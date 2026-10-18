#Requires -Version 5.1
<#
.SYNOPSIS
    Read-only Entra ID / Microsoft 365 compromise check for the ConnectWise Cloud Backup (SkyKick) /
    ConnectWise Cloud Management vendor-credential incident (Huntress advisory, October 2026).

.DESCRIPTION
    Connects to Microsoft Graph with delegated, read-only permissions and checks the tenant for the
    indicators and persistence techniques described by Huntress, plus the follow-on persistence an
    attacker holding Global Administrator could plant:

      1. ConnectWise / SkyKick service principals in the tenant, and whether they are still enabled
      2. Directory roles held by service principals: active, PIM-eligible, scoped (administrative units)
         and inherited through role-assignable groups
      3. Client secrets / certificates on ALL app registrations and service principals created since
         -StartDate, plus an inventory of federated identity credentials (FICs)
      4. High-risk application permissions (Microsoft Graph, Exchange Online, SharePoint) held by apps
      5. Entra audit log: application, role, user, group, policy and directory (domain federation,
         partner) changes; apps acting on other apps; suspicious user agents
      6. Sign-in logs: vendor app sign-ins from non-Azure IPs, any sign-in from the attacker IPs or the
         attacker ASN (AS14956 RouterHosting by default), all service-principal sign-ins from
         non-Microsoft networks, and sign-ins of apps whose credentials changed
      7. Workload identity risk (Entra ID Protection risky service principals, where licensed)
      8. Tenant configuration: Conditional Access exclusions, federated domains (Golden SAML),
         GDAP/DAP relationships (partner tenants, with -PartnerTenant)
      9. Exchange Online (optional, -IncludeExchange): Unified Audit Log for mail-flow / mailbox /
         RBAC persistence and any activity from attacker IPs, plus current forwarding, transport
         rules, connectors and Exchange RBAC for applications

    Nothing is changed unless -DisableVendorApps is used (extra permission + confirmation prompt).
    Results are written as CSV files plus an HTML report to -OutputPath.

.PARAMETER TenantId
    Tenant ID or primary domain. Optional; defaults to the home tenant of the signed-in account.

.PARAMETER StartDate
    Start of the review window, interpreted as UTC. Default 2026-10-13 00:00 UTC.

.PARAMETER EndDate
    End of the review window, interpreted as UTC. Default: now.

.PARAMETER AsnStartDate
    Start of the (longer) look-back used for the attacker-ASN sign-in hunt, interpreted as UTC.
    Default 2026-10-01 00:00 UTC. Sign-in logs are kept 30 days with Entra ID P1/P2.

.PARAMETER AttackerASNs
    Autonomous system numbers to hunt for in sign-in logs. Default: 14956 (RouterHosting / Cloudzy).

.PARAMETER AdditionalAttackerIPs
    Extra attacker IP addresses to treat as known-malicious (for indicators published after this release).

.PARAMETER AttackerCidrs
    Extra attacker IP ranges (CIDR, IPv4 or IPv6) to treat as attacker network.

.PARAMETER SkipPrefixLookup
    Do not look up the announced IP prefixes of -AttackerASNs from RIPEstat (stat.ripe.net).
    Service-principal sign-ins carry no ASN, so without prefixes the ASN hunt only covers user sign-ins.
    The lookup sends only the ASN number; nothing from the tenant leaves the machine.

.PARAMETER MaxSignIns
    Cap per sign-in query. A finding is raised when a query hits the cap. Default 50000.

.PARAMETER OutputPath
    Folder for the CSV/HTML output. Default: .\CW-SkyKick-IOC-<timestamp>

.PARAMETER SkipSignInLogs
    Skip all sign-in log queries (useful on tenants without Entra ID P1/P2, or for a fast run).

.PARAMETER SkipAsnHunt
    Skip the attacker-ASN hunt and the all-service-principal sign-in sweep (the slowest queries).

.PARAMETER IncludeExchange
    Also run the Exchange Online / Unified Audit Log checks. Requires the ExchangeOnlineManagement module
    and the View-Only Organization Management + View-Only Audit Logs roles (or equivalent).

.PARAMETER IncludeInboxRules
    With -IncludeExchange: enumerate inbox rules on every mailbox (slow on large tenants).

.PARAMETER ExchangeDelegatedOrganization
    With -IncludeExchange: customer tenant domain for partner (GDAP) access to Exchange Online.

.PARAMETER PartnerTenant
    The tenant is a CSP/MSP partner tenant: also review GDAP relationships and DAP contracts.
    Requests DelegatedAdminRelationship.Read.All.

.PARAMETER DisableVendorApps
    After the assessment, disable (NOT delete) any enabled ConnectWise/SkyKick service principals.
    Requests Application.ReadWrite.All and prompts for confirmation per app.

.PARAMETER UseDeviceCode
    Use device-code sign-in (for hosts without a browser).

.EXAMPLE
    .\Invoke-CWSkyKickIOCCheck.ps1

.EXAMPLE
    .\Invoke-CWSkyKickIOCCheck.ps1 -TenantId contoso.onmicrosoft.com -OutputPath C:\IR\contoso -IncludeExchange

.EXAMPLE
    .\Invoke-CWSkyKickIOCCheck.ps1 -AdditionalAttackerIPs 203.0.113.10 -AttackerASNs 14956,64512

.EXAMPLE
    .\Invoke-CWSkyKickIOCCheck.ps1 -DisableVendorApps

.NOTES
    Version : 1.2.0 (2026-10-18)
    Project : Community tool - not affiliated with Huntress, ConnectWise or Microsoft.
    Requires the Microsoft.Graph.Authentication module:
        Install-Module Microsoft.Graph.Authentication -Scope CurrentUser
    Optional, for -IncludeExchange:
        Install-Module ExchangeOnlineManagement -Scope CurrentUser
    Reference: https://www.huntress.com/blog/vendor-credential-enables-unauthorized-access

    A clean result does NOT prove the tenant was not accessed: Microsoft Graph reads performed by an
    application are not recorded in the Entra audit log. Only Microsoft Graph activity logs (if they were
    streamed to Log Analytics / Sentinel before the incident) record them. See hunting\sentinel-hunting.kql.
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [string]$TenantId,
    [datetime]$StartDate = [datetime]::new(2026, 10, 13, 0, 0, 0, [System.DateTimeKind]::Utc),
    [datetime]$EndDate = [datetime]::UtcNow,
    [datetime]$AsnStartDate = [datetime]::new(2026, 10, 1, 0, 0, 0, [System.DateTimeKind]::Utc),
    [int[]]$AttackerASNs = @(14956),
    [string[]]$AdditionalAttackerIPs = @(),
    [string[]]$AttackerCidrs = @(),
    [switch]$SkipPrefixLookup,
    [ValidateRange(500, 1000000)][int]$MaxSignIns = 50000,
    [string]$OutputPath = (Join-Path -Path (Get-Location).Path -ChildPath ('CW-SkyKick-IOC-' + (Get-Date -Format 'yyyyMMdd-HHmmss'))),
    [switch]$SkipSignInLogs,
    [switch]$SkipAsnHunt,
    [switch]$IncludeExchange,
    [switch]$IncludeInboxRules,
    [string]$ExchangeDelegatedOrganization,
    [switch]$PartnerTenant,
    [switch]$DisableVendorApps,
    [switch]$UseDeviceCode
)

$ScriptVersion = '1.2.0'
$TotalSteps    = 10
$ErrorActionPreference = 'Stop'
$ProgressPreference    = 'SilentlyContinue'

#region ------------------------------ Indicators (Huntress advisory) ------------------------------
$VendorApps = [ordered]@{
    '506e08f9-6e9a-4da4-942b-a099a03644ae' = 'ConnectWise Cloud Backup (formerly SkyKick Backup)'
    '2399d300-6fca-4e6a-a686-399fefe75b83' = 'ConnectWise Cloud Management'
    '24205314-2b89-4e07-a2a4-579e898a5640' = 'ConnectWise Cloud Management - MS Teams'
    'b78f6a77-d4e5-46fb-87e5-d1648bd02519' = 'ConnectWise Cloud Management - Exchange Online'
    '0de14c77-b9b0-4137-9360-34878a929827' = 'ConnectWise Cloud Management - MS Graph'
    '412dcf96-176d-4b3a-a1b0-4981ad66971e' = 'ConnectWise Cloud Management - Partner Center'
    'b2b55f5b-7758-4719-8d8f-88ae172e6bdb' = 'ConnectWise Cloud Management - SharePoint Online'
}
$VendorTenantId      = '3f9cd7a0-127a-4ed4-bf06-2f830d5616b7'   # app owner tenant seen on the vendor SP events
$AttackerIPs         = @(@('144.172.64.128') + @($AdditionalAttackerIPs) | Where-Object { $_ } | Select-Object -Unique)  # 144.172.64.128 = AS14956 RouterHosting
$SuspiciousUAs       = @('Python-urllib', 'python-requests', 'curl/')
$UlaPrefixOfInterest = 'fde4:8dba:2600:37ce:6d26:200:a76:'       # Azure-internal ULA seen on the persistence activity (also used legitimately)
$HuntressWindowStart = [datetime]::new(2026, 10, 15, 1, 0, 0, [System.DateTimeKind]::Utc)
$HuntressWindowEnd   = [datetime]::new(2026, 10, 16, 2, 0, 0, [System.DateTimeKind]::Utc)

# Microsoft-operated networks (Azure / Microsoft cloud egress). Used to separate "Microsoft" from "other public".
$MicrosoftASNs       = @(8068, 8069, 8075, 12076)
# Tenants that own Microsoft first-party applications
$MicrosoftTenantIds  = @('f8cdef31-a31e-4b4a-93e4-5f571e91255a', '72f988bf-86f1-41af-91ab-2d7cd011db47')
$GlobalAdminRoleId   = '62e90394-69f5-4237-9190-012177145e10'

$PrivilegedRoles = @(
    'Global Administrator', 'Privileged Role Administrator', 'Privileged Authentication Administrator',
    'Application Administrator', 'Cloud Application Administrator', 'Exchange Administrator',
    'SharePoint Administrator', 'Teams Administrator', 'User Administrator', 'Authentication Administrator',
    'Security Administrator', 'Conditional Access Administrator', 'Hybrid Identity Administrator',
    'Intune Administrator', 'Directory Writers', 'Partner Tier2 Support', 'Partner Tier1 Support',
    'Domain Name Administrator', 'External Identity Provider Administrator', 'Authentication Policy Administrator'
)
# Roles that are a direct path to full tenant control
$Tier0Roles = @(
    'Global Administrator', 'Privileged Role Administrator', 'Privileged Authentication Administrator',
    'Application Administrator', 'Cloud Application Administrator', 'Hybrid Identity Administrator',
    'Partner Tier2 Support', 'Domain Name Administrator', 'External Identity Provider Administrator'
)

# Well-known resource applications whose app roles (application permissions) are reviewed in step 4
$ResourceApps = [ordered]@{
    '00000003-0000-0000-c000-000000000000' = 'Microsoft Graph'
    '00000002-0000-0ff1-ce00-000000000000' = 'Office 365 Exchange Online'
    '00000003-0000-0ff1-ce00-000000000000' = 'Office 365 SharePoint Online'
}
# Application permissions that allow privilege escalation to tenant control
$Tier0Permissions = @(
    'RoleManagement.ReadWrite.Directory', 'AppRoleAssignment.ReadWrite.All', 'Application.ReadWrite.All',
    'Application.ReadWrite.OwnedBy', 'Directory.ReadWrite.All', 'Domain.ReadWrite.All',
    'Policy.ReadWrite.ConditionalAccess', 'Policy.ReadWrite.AuthenticationMethod', 'Policy.ReadWrite.PermissionGrant',
    'Policy.ReadWrite.ApplicationConfiguration', 'UserAuthenticationMethod.ReadWrite.All', 'User-PasswordProfile.ReadWrite.All',
    'RoleAssignmentSchedule.ReadWrite.Directory', 'RoleEligibilitySchedule.ReadWrite.Directory',
    'PrivilegedAccess.ReadWrite.AzureADGroup', 'PrivilegedAssignmentSchedule.ReadWrite.AzureADGroup',
    'PrivilegedEligibilitySchedule.ReadWrite.AzureADGroup', 'DelegatedPermissionGrant.ReadWrite.All',
    'EntitlementManagement.ReadWrite.All', 'Exchange.ManageAsApp', 'Organization.ReadWrite.All'
)
# Application permissions that give broad data access or broad write access
$Tier1Permissions = @(
    'Mail.Read', 'Mail.ReadWrite', 'Mail.Send', 'MailboxSettings.ReadWrite', 'full_access_as_app',
    'Files.Read.All', 'Files.ReadWrite.All', 'Sites.Read.All', 'Sites.ReadWrite.All', 'Sites.FullControl.All', 'Sites.Manage.All',
    'User.ReadWrite.All', 'Group.ReadWrite.All', 'GroupMember.ReadWrite.All', 'Chat.Read.All', 'Chat.ReadWrite.All',
    'ChannelMessage.Read.All', 'Calendars.ReadWrite', 'Contacts.ReadWrite', 'Notes.ReadWrite.All',
    'Policy.ReadWrite.CrossTenantAccess', 'Device.ReadWrite.All', 'DeviceManagementConfiguration.ReadWrite.All',
    'DeviceManagementManagedDevices.PrivilegedOperations.All', 'TeamMember.ReadWrite.All'
)

# Issuers commonly used by legitimate federated identity credentials (workload identity federation)
$KnownFicIssuers = @(
    'https://token.actions.githubusercontent.com*', 'https://login.microsoftonline.com/*', 'https://sts.windows.net/*',
    'https://*.oic.prod-aks.azure.com/*', 'https://vstoken.dev.azure.com/*', 'https://app.terraform.io*',
    'https://accounts.google.com*', 'https://oidc.eks.*.amazonaws.com/*', 'https://gitlab.com*'
)
#endregion

#region ------------------------------ Helpers ------------------------------
$script:Findings  = [System.Collections.Generic.List[object]]::new()
$script:Coverage  = [System.Collections.Generic.List[object]]::new()
$script:Truncated = [System.Collections.Generic.List[string]]::new()
$script:ObservedAttackerIPs = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
$script:AttackerPrefixes = [System.Collections.Generic.List[object]]::new()
$script:PrefixCache = @{}

# ---- Attacker network prefixes (CIDR matching, IPv4 + IPv6) ----
function Add-AttackerPrefix([string]$Cidr, [string]$Source) {
    try {
        $parts = $Cidr.Trim().Split('/')
        $ip = [System.Net.IPAddress]::Parse($parts[0])
        $len = if ($parts.Count -gt 1) { [int]$parts[1] } elseif ($ip.AddressFamily -eq 'InterNetworkV6') { 128 } else { 32 }
        $script:AttackerPrefixes.Add([pscustomobject]@{ Cidr = $Cidr.Trim(); Source = $Source; Bytes = $ip.GetAddressBytes(); Len = $len; Family = $ip.AddressFamily })
    }
    catch { Write-Warning "Ignoring invalid CIDR '$Cidr': $($_.Exception.Message)" }
}
function Find-AttackerPrefix([string]$Ip) {
    if (-not $Ip -or $script:AttackerPrefixes.Count -eq 0) { return $null }
    if ($script:PrefixCache.ContainsKey($Ip)) { return $script:PrefixCache[$Ip] }
    $hit = $null
    $addr = $null
    if ([System.Net.IPAddress]::TryParse($Ip, [ref]$addr)) {
        if ($addr.IsIPv4MappedToIPv6) { $addr = $addr.MapToIPv4() }
        $b = $addr.GetAddressBytes()
        foreach ($p in $script:AttackerPrefixes) {
            if ($p.Family -ne $addr.AddressFamily) { continue }
            $full = [math]::Floor($p.Len / 8); $rem = $p.Len % 8; $ok = $true
            for ($i = 0; $i -lt $full; $i++) { if ($b[$i] -ne $p.Bytes[$i]) { $ok = $false; break } }
            if ($ok -and $rem -gt 0) {
                $mask = (0xFF -shl (8 - $rem)) -band 0xFF
                if (($b[$full] -band $mask) -ne ($p.Bytes[$full] -band $mask)) { $ok = $false }
            }
            if ($ok) { $hit = $p; break }
        }
    }
    $script:PrefixCache[$Ip] = $hit
    return $hit
}
# Service-principal sign-ins usually report ASN 0: show that as unknown, never as 'AS0'
function Format-Asn($Asn) { $n = 0; if ([int]::TryParse([string]$Asn, [ref]$n) -and $n -gt 0) { return "AS$n" }; return 'ASN n/a' }

function Write-Step([int]$Number, [string]$Text) {
    Write-Host ''
    Write-Host ('[{0}/{1}] {2}' -f $Number, $TotalSteps, $Text) -ForegroundColor Cyan
}

function Add-Finding {
    param(
        [ValidateSet('Critical', 'High', 'Medium', 'Info')][string]$Severity,
        [string]$Category, [string]$Title, [string]$Detail, [string]$Recommendation
    )
    $script:Findings.Add([pscustomobject]@{
        Severity = $Severity; Category = $Category; Title = $Title; Detail = $Detail; Recommendation = $Recommendation
    })
    $color = switch ($Severity) { 'Critical' { 'Red' } 'High' { 'Magenta' } 'Medium' { 'Yellow' } default { 'Gray' } }
    Write-Host ('    [{0}] {1}' -f $Severity.ToUpper(), $Title) -ForegroundColor $color
}

# Records what was (and was not) checked, so a clean report can be read correctly.
function Add-Coverage {
    param([string]$Check, [ValidateSet('Done', 'Partial', 'Skipped', 'Failed', 'Unavailable')][string]$Status, [string]$Note = '')
    $script:Coverage.Add([pscustomobject]@{ Check = $Check; Status = $Status; Note = $Note })
}

function Invoke-GraphWithRetry {
    param([Parameter(Mandatory)][string]$Uri, [string]$Method = 'GET', $Body, [hashtable]$Headers)
    $attempt = 0
    while ($true) {
        try {
            $p = @{ Uri = $Uri; Method = $Method; OutputType = 'PSObject'; ErrorAction = 'Stop' }
            if ($null -ne $Body) { $p.Body = ($Body | ConvertTo-Json -Depth 10); $p.ContentType = 'application/json' }
            if ($Headers) { $p.Headers = $Headers }
            return Invoke-MgGraphRequest @p
        }
        catch {
            $attempt++
            $status = 0
            try { $status = [int]$_.Exception.Response.StatusCode } catch { }
            $msg = "$($_.Exception.Message) $($_.ErrorDetails.Message)"
            $retryable = ($status -eq 429 -or $status -ge 500 -or $msg -match 'TooManyRequests|Gateway|ServiceUnavailable')
            if ($retryable -and $attempt -le 5) {
                $wait = [math]::Min(60, [math]::Pow(2, $attempt) * 2)
                Write-Verbose "Graph throttled/unavailable ($status). Retry $attempt in $wait s."
                Start-Sleep -Seconds $wait
                continue
            }
            throw
        }
    }
}

function Invoke-GraphPaged {
    param([Parameter(Mandatory)][string]$Uri, [int]$MaxItems = 0, [string]$Label, [hashtable]$Headers)
    $results = [System.Collections.Generic.List[object]]::new()
    $next = $Uri
    while ($next) {
        $resp = Invoke-GraphWithRetry -Uri $next -Headers $Headers
        foreach ($v in @($resp.value)) { if ($null -ne $v) { $results.Add($v) } }
        if ($MaxItems -gt 0 -and $results.Count -ge $MaxItems) {
            $name = if ($Label) { $Label } else { $Uri }
            Write-Warning "Result cap of $MaxItems reached for '$name' - output truncated."
            $script:Truncated.Add(("{0} (cap {1})" -f $name, $MaxItems))
            break
        }
        $next = $resp.'@odata.nextLink'
    }
    return $results
}

# JSON batching: up to 20 GET requests per call. Returns a hashtable keyed by the caller's request id.
function Invoke-GraphBatch {
    param([Parameter(Mandatory)][hashtable]$Requests, [string]$Version = 'v1.0')
    $out = @{}
    $pending = [System.Collections.Generic.Queue[string]]::new()
    foreach ($k in $Requests.Keys) { $pending.Enqueue([string]$k) }
    $round = 0
    while ($pending.Count -gt 0 -and $round -lt 8) {
        $round++
        $retry = [System.Collections.Generic.List[string]]::new()
        $retryAfter = 0
        while ($pending.Count -gt 0) {
            $chunk = @(); while ($pending.Count -gt 0 -and $chunk.Count -lt 20) { $chunk += $pending.Dequeue() }
            $body = @{ requests = @($chunk | ForEach-Object { @{ id = $_; method = 'GET'; url = $Requests[$_] } }) }
            $resp = Invoke-GraphWithRetry -Method POST -Uri "https://graph.microsoft.com/$Version/`$batch" -Body $body
            foreach ($r in @($resp.responses)) {
                if ([int]$r.status -eq 429 -or [int]$r.status -ge 500) {
                    $retry.Add([string]$r.id)
                    $ra = 0; try { $ra = [int]$r.headers.'Retry-After' } catch { }
                    $retryAfter = [math]::Max($retryAfter, $ra)
                }
                else { $out[[string]$r.id] = $r }
            }
        }
        if ($retry.Count -gt 0) {
            Start-Sleep -Seconds ([math]::Min(60, [math]::Max(2, $retryAfter)))
            foreach ($id in $retry) { $pending.Enqueue($id) }
        }
    }
    return $out
}

function ConvertTo-Utc($Value) {
    if ($null -eq $Value -or "$Value" -eq '') { return $null }
    if ($Value -is [datetime]) { return $Value.ToUniversalTime() }
    return [datetime]::Parse([string]$Value, [Globalization.CultureInfo]::InvariantCulture,
        ([Globalization.DateTimeStyles]::AdjustToUniversal -bor [Globalization.DateTimeStyles]::AssumeUniversal))
}

function Get-IpClass([string]$Ip, $Asn) {
    if (-not $Ip) { return 'None' }
    if ($AttackerIPs -contains $Ip) { return 'KnownMalicious' }
    $asnInt = 0; [void][int]::TryParse([string]$Asn, [ref]$asnInt)
    if ($asnInt -gt 0 -and $AttackerASNs -contains $asnInt) { return 'AttackerASN' }
    if (Find-AttackerPrefix $Ip) { return 'AttackerASN' }
    if ($Ip -match '^f[cd][0-9a-f]{2}:') { return 'PrivateIPv6-ULA' }
    if ($Ip -match '^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.)') { return 'PrivateIPv4' }
    if ($asnInt -gt 0 -and $MicrosoftASNs -contains $asnInt) { return 'Microsoft' }
    return 'Public'
}

function Test-SuspiciousUA([string]$Ua) {
    if (-not $Ua) { return $false }
    foreach ($s in $SuspiciousUAs) { if ($Ua -like "*$s*") { return $true } }
    return $false
}

function Test-IsVendor([string]$AppId, [string]$SpId, [string]$OwnerTenant) {
    return ($VendorAppIdSet.Contains([string]$AppId) -or $VendorSpIdSet.Contains([string]$SpId) -or ($OwnerTenant -eq $VendorTenantId))
}

function Test-IsMicrosoftApp([string]$SpId, [string]$AppId) {
    $sp = $null
    if ($SpId -and $script:SpById.ContainsKey([string]$SpId)) { $sp = $script:SpById[[string]$SpId] }
    elseif ($AppId -and $script:SpByAppId.ContainsKey([string]$AppId)) { $sp = $script:SpByAppId[[string]$AppId] }
    if ($sp) { return ($MicrosoftTenantIds -contains [string]$sp.appOwnerOrganizationId) }
    return $false
}

function Export-Data($Data, [string]$Name) {
    $items = @($Data | Where-Object { $null -ne $_ })
    if ($items.Count -gt 0) {
        $path = Join-Path $OutputPath "$Name.csv"
        # Write timestamps as ISO 8601 UTC so the CSV is unambiguous in every locale
        $items = foreach ($o in $items) {
            $h = [ordered]@{}
            foreach ($prop in $o.PSObject.Properties) {
                $v = $prop.Value
                if ($v -is [datetime]) { $v = $v.ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", [Globalization.CultureInfo]::InvariantCulture) }
                $h[$prop.Name] = $v
            }
            [pscustomobject]$h
        }
        $items | Export-Csv -Path $path -NoTypeInformation -Encoding UTF8
        return $path
    }
}

function New-CredRow($Obj, [string]$ObjectType, [string]$CredType, $Cred) {
    $start = ConvertTo-Utc $Cred.startDateTime
    [pscustomobject]@{
        ObjectType     = $ObjectType
        SPType         = $Obj.servicePrincipalType
        DisplayName    = $Obj.displayName
        AppId          = $Obj.appId
        ObjectId       = $Obj.id
        CredentialType = $CredType
        CredentialName = $Cred.displayName
        KeyId          = $Cred.keyId
        StartUtc       = $start
        EndUtc         = (ConvertTo-Utc $Cred.endDateTime)
        AddedInWindow  = [bool]($null -ne $start -and $start -ge $StartUtc -and $start -le $EndUtc)
        IsVendorApp    = (Test-IsVendor $Obj.appId $Obj.id ([string]$Obj.appOwnerOrganizationId))
        MicrosoftManaged = (Test-MicrosoftManagedCredential $Obj $Cred)
    }
}

# Credentials that Microsoft creates and rotates automatically (not user/attacker added):
#  - Managed identity certificates (rotated by Azure, cannot be added through Graph)
#  - P2P Server 'CN=MS-Organization-P2P-Access [YYYY]' certificate (yearly rotation for Entra-joined device RDP)
function Test-MicrosoftManagedCredential($Obj, $Cred) {
    if ($Obj.servicePrincipalType -eq 'ManagedIdentity') { return $true }
    if ($Obj.displayName -eq 'P2P Server' -and [string]$Cred.displayName -like 'CN=MS-Organization-P2P-Access*') { return $true }
    return $false
}

function Get-CredentialRows($Obj, [string]$ObjectType) {
    foreach ($c in @($Obj.passwordCredentials)) { if ($c) { New-CredRow $Obj $ObjectType 'ClientSecret' $c } }
    foreach ($c in @($Obj.keyCredentials))      { if ($c) { New-CredRow $Obj $ObjectType ('Certificate/' + $c.usage) $c } }
}

function New-RoleRow($Sp, [string]$RoleName, [string]$AssignmentType, [string]$Scope = '/', [string]$Via = '') {
    if ((-not $Sp.appId) -and $script:SpById.ContainsKey([string]$Sp.id)) { $Sp = $script:SpById[[string]$Sp.id] }
    [pscustomobject]@{
        ServicePrincipal = $Sp.displayName
        AppId            = $Sp.appId
        ObjectId         = $Sp.id
        Role             = $RoleName
        AssignmentType   = $AssignmentType
        Scope            = $(if ($Scope -and $Scope -ne '/') { $Scope } else { 'Tenant' })
        ViaGroup         = $Via
        Privileged       = ($PrivilegedRoles -contains $RoleName)
        Tier0            = ($Tier0Roles -contains $RoleName)
        IsVendorApp      = (Test-IsVendor $Sp.appId $Sp.id ([string]$Sp.appOwnerOrganizationId))
        IsMicrosoftApp   = ($MicrosoftTenantIds -contains [string]$Sp.appOwnerOrganizationId)
    }
}

function ConvertTo-SignInRow($S, [string]$Query) {
    $class = Get-IpClass $S.ipAddress $S.autonomousSystemNumber
    if ($class -in @('KnownMalicious', 'AttackerASN') -and $S.ipAddress) { [void]$script:ObservedAttackerIPs.Add([string]$S.ipAddress) }
    [pscustomobject]@{
        Query                = $Query
        TimeUtc              = (ConvertTo-Utc $S.createdDateTime)
        EventTypes           = (@($S.signInEventTypes) -join ',')
        AppDisplayName       = $S.appDisplayName
        AppId                = $S.appId
        ServicePrincipalId   = $S.servicePrincipalId
        ServicePrincipalName = $S.servicePrincipalName
        UserPrincipalName    = $S.userPrincipalName
        IPAddress            = $S.ipAddress
        IPClass              = $class
        ASN                  = $S.autonomousSystemNumber
        AttackerNetwork      = $(if ($class -eq 'KnownMalicious') { 'known IP' } elseif ($class -eq 'AttackerASN') { $px = Find-AttackerPrefix $S.ipAddress; if ($px) { '{0} ({1})' -f $px.Cidr, $px.Source } else { Format-Asn $S.autonomousSystemNumber } } else { $null })
        Country              = $S.location.countryOrRegion
        Resource             = $S.resourceDisplayName
        ClientCredentialType = $S.clientCredentialType
        CredentialKeyId      = $S.servicePrincipalCredentialKeyId
        CredentialThumbprint = $S.servicePrincipalCredentialThumbprint
        UserAgent            = $S.userAgent
        ErrorCode            = $S.status.errorCode
        FailureReason        = $S.status.failureReason
        Success              = ($S.status.errorCode -eq 0)
        CorrelationId        = $S.correlationId
    }
}

$script:SignInBlocked = $false
$script:LastSignInError = $null
function Invoke-SignInQuery([string]$Filter, [string]$Label, [int]$Max = $MaxSignIns, [switch]$ExpectFailure) {
    $script:LastSignInError = $null
    if ($script:SignInBlocked) { return }
    $uri = 'https://graph.microsoft.com/beta/auditLogs/signIns?$filter=' + [uri]::EscapeDataString($Filter) + '&$top=500'
    try {
        foreach ($s in @(Invoke-GraphPaged -Uri $uri -MaxItems $Max -Label "SignIns:$Label")) { ConvertTo-SignInRow $s $Label }
    }
    catch {
        $msg = "$($_.Exception.Message) $($_.ErrorDetails.Message)"
        $script:LastSignInError = $msg
        if ($msg -match 'NonPremium|premium') {
            $script:SignInBlocked = $true
            Add-Finding -Severity Info -Category 'SignIns' -Title 'Sign-in logs not available through the API (no Entra ID P1/P2)' `
                -Detail 'The tenant has no Entra ID P1/P2 license, so sign-in logs cannot be read through Microsoft Graph.' `
                -Recommendation ('Check manually: Entra admin center > Monitoring > Sign-in logs > Service principal sign-ins, filter Application ID 506e08f9-6e9a-4da4-942b-a099a03644ae (and the other ConnectWise IDs); search all tabs for IP(s) {0} and add the "Autonomous system number" column to look for AS{1}.' -f ($AttackerIPs -join ', '), ($AttackerASNs -join ', AS'))
        }
        elseif ($msg -match 'Forbidden|Authorization_RequestDenied|403') {
            $script:SignInBlocked = $true
            Add-Finding -Severity Medium -Category 'SignIns' -Title 'Sign-in logs could not be read (access denied)' `
                -Detail $msg -Recommendation 'Run as a user holding Security Reader, Global Reader or Reports Reader, with AuditLog.Read.All consented.'
        }
        elseif ($ExpectFailure) { Write-Verbose "Sign-in query '$Label' not accepted, falling back: $msg" }
        else { Write-Warning "Sign-in query '$Label' failed: $msg" }
    }
}
#endregion

#region ------------------------------ Setup & connect ------------------------------
foreach ($n in 'StartDate', 'EndDate', 'AsnStartDate') {
    $v = Get-Variable -Name $n -ValueOnly
    if ($v.Kind -eq [System.DateTimeKind]::Unspecified) { Set-Variable -Name $n -Value ([datetime]::SpecifyKind($v, [System.DateTimeKind]::Utc)) }
}
$StartUtc = $StartDate.ToUniversalTime()
$EndUtc   = $EndDate.ToUniversalTime()
$AsnStartUtc = $AsnStartDate.ToUniversalTime()
if ($AsnStartUtc -gt $StartUtc) { $AsnStartUtc = $StartUtc }
$fmt      = "yyyy-MM-dd'T'HH:mm:ss'Z'"
$startStr = $StartUtc.ToString($fmt, [Globalization.CultureInfo]::InvariantCulture)
$endStr   = $EndUtc.ToString($fmt, [Globalization.CultureInfo]::InvariantCulture)
$asnStartStr = $AsnStartUtc.ToString($fmt, [Globalization.CultureInfo]::InvariantCulture)

if (-not (Get-Module -ListAvailable -Name Microsoft.Graph.Authentication)) {
    throw 'Module Microsoft.Graph.Authentication not found. Install it with: Install-Module Microsoft.Graph.Authentication -Scope CurrentUser'
}
Import-Module Microsoft.Graph.Authentication

$exchangeAvailable = $false
if ($IncludeExchange) {
    if (Get-Module -ListAvailable -Name ExchangeOnlineManagement) { $exchangeAvailable = $true }
    else { Write-Warning 'ExchangeOnlineManagement module not found - Exchange checks will be skipped. Install it with: Install-Module ExchangeOnlineManagement -Scope CurrentUser' }
}

$scopes = @('Application.Read.All', 'Directory.Read.All', 'RoleManagement.Read.Directory', 'AuditLog.Read.All', 'Policy.Read.All',
            'Domain.Read.All', 'IdentityRiskyServicePrincipal.Read.All')
if ($PartnerTenant)     { $scopes += 'DelegatedAdminRelationship.Read.All' }
if ($DisableVendorApps) { $scopes += 'Application.ReadWrite.All' }

Write-Host "ConnectWise / SkyKick vendor-credential IOC check v$ScriptVersion" -ForegroundColor White
Write-Host ("Review window: {0} -> {1} (UTC)" -f $startStr, $endStr)
if (-not $SkipSignInLogs -and -not $SkipAsnHunt) { Write-Host ("ASN hunt     : AS{0} from {1}" -f ($AttackerASNs -join ', AS'), $asnStartStr) }
Write-Host ("Requesting delegated scopes: {0}" -f ($scopes -join ', '))

$daysBack = ([datetime]::UtcNow - $StartUtc).TotalDays
if ($daysBack -gt 6) {
    Write-Warning ("The window starts {0:N0} days ago. Tenants without Entra ID P1/P2 keep audit logs for 7 days only - export results now." -f $daysBack)
}

$connectParams = @{ Scopes = $scopes; NoWelcome = $true; ErrorAction = 'Stop' }
if ($TenantId)      { $connectParams.TenantId = $TenantId }
if ($UseDeviceCode) { $connectParams.UseDeviceCode = $true }
Connect-MgGraph @connectParams

$ctx = Get-MgContext
$missing = @($scopes | Where-Object { $ctx.Scopes -notcontains $_ })
if ($missing.Count -gt 0) { Write-Warning ("Token is missing scopes: {0}. Related checks may fail." -f ($missing -join ', ')) }

$org = @((Invoke-GraphWithRetry -Uri 'https://graph.microsoft.com/v1.0/organization?$select=id,displayName').value)[0]
Write-Host ("Connected as {0} to tenant '{1}' ({2})" -f $ctx.Account, $org.displayName, $org.id) -ForegroundColor Green

New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null

# Attacker network prefixes. Service-principal sign-ins carry no ASN, so app sign-ins can only be matched by IP range.
foreach ($c in @($AttackerCidrs)) { if ($c) { Add-AttackerPrefix $c 'manual' } }
$prefixNote = ''
if (-not $SkipSignInLogs -and -not $SkipAsnHunt -and -not $SkipPrefixLookup) {
    try { [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12 } catch { }
    foreach ($asn in $AttackerASNs) {
        try {
            $ripe = Invoke-RestMethod -Uri ("https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS{0}&sourceapp=skykick-ioc-check" -f $asn) -TimeoutSec 30 -ErrorAction Stop
            $n = 0
            foreach ($p in @($ripe.data.prefixes)) { if ($p.prefix) { Add-AttackerPrefix ([string]$p.prefix) "AS$asn"; $n++ } }
            Write-Host ("Attacker net : AS{0} announces {1} prefix(es) (RIPEstat)" -f $asn, $n)
            if ($n -eq 0) { $prefixNote += "AS$asn returned no prefixes; " }
        }
        catch { $prefixNote += "AS$asn lookup failed ($($_.Exception.Message)); "; Write-Warning "RIPEstat prefix lookup for AS$asn failed - app sign-ins can only be matched by exact IP. Use -AttackerCidrs to supply ranges." }
    }
}
elseif ($SkipPrefixLookup) { $prefixNote = '-SkipPrefixLookup; ' }

$VendorAppIdSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
$VendorSpIdSet  = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
foreach ($k in $VendorApps.Keys) { [void]$VendorAppIdSet.Add($k) }
#endregion

#region ------------------------------ 1. Vendor service principals ------------------------------
Write-Step 1 'ConnectWise / SkyKick service principals'
$allSPs = @(Invoke-GraphPaged -Uri 'https://graph.microsoft.com/v1.0/servicePrincipals?$select=id,appId,displayName,accountEnabled,appOwnerOrganizationId,servicePrincipalType,passwordCredentials,keyCredentials&$top=999')
$script:SpById = @{}
$script:SpByAppId = @{}
foreach ($sp in $allSPs) { $script:SpById[[string]$sp.id] = $sp; if ($sp.appId) { $script:SpByAppId[[string]$sp.appId] = $sp } }
Write-Host ("    {0} service principals in tenant" -f $allSPs.Count)

$vendorSPs = @($allSPs | Where-Object {
    $VendorAppIdSet.Contains([string]$_.appId) -or
    ([string]$_.appOwnerOrganizationId -eq $VendorTenantId) -or
    ($_.displayName -match 'SkyKick|ConnectWise')
})
foreach ($sp in $vendorSPs) { [void]$VendorAppIdSet.Add([string]$sp.appId); [void]$VendorSpIdSet.Add([string]$sp.id) }

$vendorRows = foreach ($sp in $vendorSPs) {
    $matched = @()
    if ($VendorApps.Contains([string]$sp.appId))              { $matched += 'Known IOC AppId' }
    if ([string]$sp.appOwnerOrganizationId -eq $VendorTenantId) { $matched += 'Vendor owner tenant' }
    if ($sp.displayName -match 'SkyKick|ConnectWise')          { $matched += 'Display name' }
    [pscustomobject]@{
        DisplayName      = $sp.displayName
        AppId            = $sp.appId
        ObjectId         = $sp.id
        Enabled          = $sp.accountEnabled
        AppOwnerTenantId = $sp.appOwnerOrganizationId
        MatchedBy        = ($matched -join ', ')
        SecretsOnSP      = @($sp.passwordCredentials).Where({ $_ }).Count
        CertsOnSP        = @($sp.keyCredentials).Where({ $_ }).Count
    }
}

if ($vendorSPs.Count -eq 0) {
    Add-Finding -Severity Info -Category 'VendorApps' -Title 'No ConnectWise / SkyKick service principals found' `
        -Detail 'None of the known application IDs, the vendor owner tenant, or matching display names exist in this tenant.' `
        -Recommendation 'Still review the audit-log and IP results below (the second wave targeted tenants without ConnectWise products).'
}
foreach ($r in $vendorRows) {
    if ($r.Enabled) {
        Add-Finding -Severity High -Category 'VendorApps' -Title ("ConnectWise/SkyKick app is ENABLED: {0}" -f $r.DisplayName) `
            -Detail ("AppId {0}, ObjectId {1}, matched by {2}." -f $r.AppId, $r.ObjectId, $r.MatchedBy) `
            -Recommendation 'Disable it: Entra admin center > Enterprise applications > app > Properties > Enabled for users to sign-in = No. Do NOT delete. Keep disabled until ConnectWise confirms all credentials were reset. (Or rerun with -DisableVendorApps.)'
    }
    else {
        Add-Finding -Severity Info -Category 'VendorApps' -Title ("ConnectWise/SkyKick app present but disabled: {0}" -f $r.DisplayName) `
            -Detail ("AppId {0}" -f $r.AppId) -Recommendation 'Keep disabled until ConnectWise confirms credential reset.'
    }
    if (($r.SecretsOnSP + $r.CertsOnSP) -gt 0) {
        Add-Finding -Severity High -Category 'VendorApps' -Title ("Credentials exist on the vendor service principal in YOUR tenant: {0}" -f $r.DisplayName) `
            -Detail ("{0} secret(s), {1} certificate(s) on service principal {2}. Multi-tenant vendor apps normally hold credentials only in the vendor tenant." -f $r.SecretsOnSP, $r.CertsOnSP, $r.ObjectId) `
            -Recommendation 'Review the credential start dates in AppCredentials.csv and remove any you did not create.'
    }
}
Add-Coverage -Check 'Vendor service principals' -Status Done -Note ("{0} service principals scanned, {1} vendor match(es)" -f $allSPs.Count, $vendorSPs.Count)
#endregion

#region ------------------------------ 2. Directory roles held by service principals ------------------------------
Write-Step 2 'Directory roles held by service principals (active, PIM eligible, scoped, via groups)'
$roleRows = [System.Collections.Generic.List[object]]::new()
$script:PrivGroupIds   = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
$script:PrivGroupNames = @{}
$groupSpCache = @{}
$roleStatus = 'Done'; $roleNotes = [System.Collections.Generic.List[string]]::new()

$roleDefs = @{}
try {
    foreach ($d in @(Invoke-GraphPaged -Uri 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleDefinitions?$select=id,displayName,templateId')) {
        $roleDefs[[string]$d.id] = $d.displayName
        if ($d.templateId) { $roleDefs[[string]$d.templateId] = $d.displayName }
    }
}
catch { Write-Warning "Could not read role definitions: $($_.Exception.Message)"; $roleStatus = 'Partial'; $roleNotes.Add('role definitions unreadable') }

# Resolve principal IDs that are not service principals to groups (role-assignable groups can hold roles).
function Resolve-GroupIds([string[]]$Ids) {
    $found = @{}
    $ids = @($Ids | Where-Object { $_ } | Select-Object -Unique)
    for ($i = 0; $i -lt $ids.Count; $i += 1000) {
        $chunk = $ids[$i..([math]::Min($i + 999, $ids.Count - 1))]
        try {
            $resp = Invoke-GraphWithRetry -Method POST -Uri 'https://graph.microsoft.com/v1.0/directoryObjects/getByIds' -Body @{ ids = @($chunk); types = @('group') }
            foreach ($g in @($resp.value)) { if ($g) { $found[[string]$g.id] = $g } }
        }
        catch { Write-Warning "Could not resolve role principals to groups: $($_.Exception.Message)" }
    }
    return $found
}

function Get-GroupServicePrincipals([string]$GroupId) {
    if ($groupSpCache.ContainsKey($GroupId)) { return $groupSpCache[$GroupId] }
    $uri = 'https://graph.microsoft.com/v1.0/groups/{0}/transitiveMembers/microsoft.graph.servicePrincipal?$select=id,appId,displayName,appOwnerOrganizationId' -f $GroupId
    $members = @()
    try { $members = @(Invoke-GraphPaged -Uri $uri) } catch { Write-Warning "Could not read members of group ${GroupId}: $($_.Exception.Message)" }
    $groupSpCache[$GroupId] = $members
    return $members
}

function Add-RoleAssignmentRows($Assignments, [string]$AssignmentType) {
    $unknown = [System.Collections.Generic.List[object]]::new()
    foreach ($a in @($Assignments)) {
        if (-not $a) { continue }
        $roleName = $roleDefs[[string]$a.roleDefinitionId]
        if (-not $roleName) { $roleName = 'Unlisted role ' + [string]$a.roleDefinitionId }
        if ($script:SpById.ContainsKey([string]$a.principalId)) {
            $roleRows.Add((New-RoleRow -Sp $script:SpById[[string]$a.principalId] -RoleName $roleName -AssignmentType $AssignmentType -Scope $a.directoryScopeId))
        }
        else { $unknown.Add($a) }
    }
    if ($unknown.Count -eq 0) { return }
    $groups = Resolve-GroupIds @($unknown | ForEach-Object { [string]$_.principalId })
    foreach ($a in $unknown) {
        $g = $groups[[string]$a.principalId]
        if (-not $g) { continue }   # a user - not in scope of this check
        [void]$script:PrivGroupIds.Add([string]$g.id); $script:PrivGroupNames[[string]$g.id] = $g.displayName
        $roleName = $roleDefs[[string]$a.roleDefinitionId]
        if (-not $roleName) { $roleName = 'Unlisted role ' + [string]$a.roleDefinitionId }
        foreach ($m in @(Get-GroupServicePrincipals ([string]$g.id))) {
            $roleRows.Add((New-RoleRow -Sp $m -RoleName $roleName -AssignmentType $AssignmentType -Scope $a.directoryScopeId -Via $g.displayName))
        }
    }
}

# Active assignments (tenant-wide and administrative-unit scoped, direct and via groups)
$activeAssignments = $null
try {
    $activeAssignments = @(Invoke-GraphPaged -Uri 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments?$select=id,principalId,roleDefinitionId,directoryScopeId')
}
catch {
    Write-Verbose "Unfiltered roleAssignments list failed, querying per role definition: $($_.Exception.Message)"
    if ($roleDefs.Count -gt 0) {
        $activeAssignments = [System.Collections.Generic.List[object]]::new()
        foreach ($rid in @($roleDefs.Keys | Select-Object -Unique)) {
            try {
                $f = [uri]::EscapeDataString("roleDefinitionId eq '$rid'")
                foreach ($x in @(Invoke-GraphPaged -Uri ("https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments?`$filter=$f&`$select=id,principalId,roleDefinitionId,directoryScopeId"))) { $activeAssignments.Add($x) }
            }
            catch { }
        }
    }
}
if ($null -ne $activeAssignments) { Add-RoleAssignmentRows $activeAssignments 'Active' }
else {
    # Last resort: legacy directoryRoles API (tenant-wide, direct service principal members only)
    $roleStatus = 'Partial'; $roleNotes.Add('unified role assignments unreadable - fell back to directoryRoles (no scoped / group-inherited roles)')
    try {
        foreach ($role in @(Invoke-GraphPaged -Uri 'https://graph.microsoft.com/v1.0/directoryRoles?$select=id,displayName,roleTemplateId')) {
            $uri = 'https://graph.microsoft.com/v1.0/directoryRoles/{0}/members/microsoft.graph.servicePrincipal?$select=id,appId,displayName,appOwnerOrganizationId' -f $role.id
            foreach ($m in @(Invoke-GraphPaged -Uri $uri)) { $roleRows.Add((New-RoleRow -Sp $m -RoleName $role.displayName -AssignmentType 'Active')) }
        }
    }
    catch { Write-Warning "Could not enumerate active directory role members: $($_.Exception.Message)"; $roleStatus = 'Failed' }
}

# PIM-eligible assignments
try {
    $eligible = @(Invoke-GraphPaged -Uri 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleEligibilitySchedules?$select=id,principalId,roleDefinitionId,directoryScopeId')
    Add-RoleAssignmentRows $eligible 'PIM-Eligible'
}
catch {
    Write-Verbose "PIM eligibility not readable (needs Entra ID P2): $($_.Exception.Message)"
    $roleNotes.Add('PIM eligibility not readable (Entra ID P2 needed)')
}

# Role-assignable groups (membership changes to these are privileged - used by the audit-log step)
try {
    $rag = @(Invoke-GraphPaged -Uri 'https://graph.microsoft.com/v1.0/groups?$filter=isAssignableToRole%20eq%20true&$select=id,displayName&$count=true' -Headers @{ ConsistencyLevel = 'eventual' })
    foreach ($g in $rag) { [void]$script:PrivGroupIds.Add([string]$g.id); $script:PrivGroupNames[[string]$g.id] = $g.displayName }
}
catch { Write-Verbose "Could not list role-assignable groups: $($_.Exception.Message)" }

# De-duplicate (the same assignment can surface through several paths)
$roleRows = [System.Collections.Generic.List[object]]@($roleRows | Sort-Object ObjectId, Role, AssignmentType, Scope, ViaGroup -Unique)

foreach ($r in $roleRows) {
    $where = @("{0} assignment" -f $r.AssignmentType)
    if ($r.Scope -ne 'Tenant') { $where += ("scoped to {0} (administrative unit / resource scope)" -f $r.Scope) }
    if ($r.ViaGroup) { $where += ("inherited through group '{0}' - not visible on the app's own role list" -f $r.ViaGroup) }
    $whereText = ($where -join ', ')
    if ($r.IsVendorApp) {
        $sev = if ($r.Privileged) { 'Critical' } else { 'High' }
        Add-Finding -Severity $sev -Category 'Roles' -Title ("ConnectWise/SkyKick app holds directory role '{0}': {1}" -f $r.Role, $r.ServicePrincipal) `
            -Detail ("{0}. AppId {1}. Huntress observed these apps adding themselves to Exchange Administrator / Global Administrator." -f $whereText, $r.AppId) `
            -Recommendation 'After disabling the app, remove any role you did not intentionally grant. Check the audit log (AuditEvents.csv) for when it was added and by whom.'
    }
    elseif ($r.Privileged -and $r.IsMicrosoftApp) {
        Add-Finding -Severity Info -Category 'Roles' -Title ("Microsoft first-party app holds role '{0}': {1}" -f $r.Role, $r.ServicePrincipal) `
            -Detail ("{0}. AppId {1}." -f $whereText, $r.AppId) -Recommendation 'Usually expected. Listed for completeness.'
    }
    elseif ($r.Privileged) {
        Add-Finding -Severity Medium -Category 'Roles' -Title ("Service principal holds privileged role '{0}': {1}" -f $r.Role, $r.ServicePrincipal) `
            -Detail ("{0}. AppId {1}.{2}" -f $whereText, $r.AppId, $(if ($r.Tier0) { ' This role allows full tenant takeover.' } else { '' })) `
            -Recommendation 'Confirm this assignment is intentional and expected for the tool.'
    }
}
if ($roleRows.Count -eq 0) { Write-Host '    No service principals hold directory roles.' }
Add-Coverage -Check 'Directory roles held by apps' -Status $roleStatus -Note ((@("{0} app role assignment(s); {1} role-holding / role-assignable group(s)" -f $roleRows.Count, $script:PrivGroupIds.Count) + $roleNotes) -join '; ')
#endregion

#region ------------------------------ 3. Credentials on apps and service principals ------------------------------
Write-Step 3 'Client secrets, certificates and federated identity credentials on apps'
$apps = @(Invoke-GraphPaged -Uri 'https://graph.microsoft.com/v1.0/applications?$select=id,appId,displayName,createdDateTime,passwordCredentials,keyCredentials&$top=999')
$appById = @{}
foreach ($a in $apps) { $appById[[string]$a.id] = $a }
Write-Host ("    {0} app registrations in tenant" -f $apps.Count)

$credRows = [System.Collections.Generic.List[object]]::new()
foreach ($a in $apps)   { foreach ($row in @(Get-CredentialRows $a 'AppRegistration'))  { $credRows.Add($row) } }
foreach ($sp in $allSPs) { foreach ($row in @(Get-CredentialRows $sp 'ServicePrincipal')) { $credRows.Add($row) } }

$credChangedAppIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
# A signing certificate is stored as a keyCredential plus a passwordCredential with the same KeyId,
# so group by object + KeyId to report each credential once.
foreach ($grp in ($credRows | Where-Object AddedInWindow | Group-Object ObjectId, KeyId)) {
    $c = $grp.Group[0]
    $types = (@($grp.Group.CredentialType) | Sort-Object -Unique) -join ' + '
    $title = "New credential ({0}) on {1} '{2}' (start {3:yyyy-MM-dd HH:mm} UTC)" -f $types, $c.ObjectType, $c.DisplayName, $c.StartUtc
    if ($c.MicrosoftManaged) {
        Add-Finding -Severity Info -Category 'Credentials' -Title $title `
            -Detail ("Microsoft-managed credential (automatic rotation). Name '{0}', SP type {1}, KeyId {2}." -f $c.CredentialName, $c.SPType, $c.KeyId) `
            -Recommendation 'None. Listed for completeness.'
        continue
    }
    [void]$credChangedAppIds.Add([string]$c.AppId)
    $isSaml = [string]$c.CredentialName -like 'CN=Microsoft Azure Federated SSO Certificate*'
    $sev = if ($isSaml) { 'Medium' } else { 'High' }
    $lifetimeDays = if ($c.EndUtc) { [int]($c.EndUtc - $c.StartUtc).TotalDays } else { 0 }
    $detail = "AppId {0}, KeyId {1}, name '{2}', expires {3:yyyy-MM-dd} ({4} days)." -f $c.AppId, $c.KeyId, $c.CredentialName, $c.EndUtc, $lifetimeDays
    if ($isSaml) { $detail += ' Looks like a SAML signing certificate rotation.' }
    if ($c.ObjectType -eq 'ServicePrincipal' -and -not $isSaml) { $detail += ' Credentials added directly to a service principal are rare and not visible in the App registrations blade.' }
    if ($lifetimeDays -ge 540) { $detail += ' Long-lived credential (the attacker-added secrets Huntress saw expired in 2028).' }
    Add-Finding -Severity $sev -Category 'Credentials' -Title $title -Detail $detail `
        -Recommendation 'Confirm with the app owner that this credential was created on purpose. If not: remove it, review the app sign-ins (SignIns-*.csv) and its permissions, and treat the app as compromised.'
}
foreach ($a in $apps) {
    $created = ConvertTo-Utc $a.createdDateTime
    if ($created -and $created -ge $StartUtc -and $created -le $EndUtc) {
        Add-Finding -Severity Medium -Category 'Credentials' -Title ("App registration created during window: {0}" -f $a.displayName) `
            -Detail ("AppId {0}, created {1:yyyy-MM-dd HH:mm} UTC." -f $a.appId, $created) `
            -Recommendation 'Confirm who created it and what permissions it was granted.'
    }
}
if (-not ($credRows | Where-Object AddedInWindow)) { Write-Host '    No credentials with a start date inside the window.' }

# Federated identity credentials (FICs) let an external identity provider sign in as the app with no secret at all.
# FICs carry no creation timestamp, so this is an inventory; additions inside the window are caught by the audit log.
$ficRows = [System.Collections.Generic.List[object]]::new()
$ficStatus = 'Done'
if ($apps.Count -gt 0) {
    $reqs = @{}
    foreach ($a in $apps) { $reqs[[string]$a.id] = ('/applications/{0}/federatedIdentityCredentials' -f $a.id) }
    try {
        $batch = Invoke-GraphBatch -Requests $reqs
        foreach ($id in $batch.Keys) {
            $r = $batch[$id]
            if ([int]$r.status -ne 200) { $ficStatus = 'Partial'; continue }
            $a = $appById[$id]
            foreach ($f in @($r.body.value)) {
                if (-not $f) { continue }
                $known = [bool]($KnownFicIssuers | Where-Object { [string]$f.issuer -like $_ })
                $ficRows.Add([pscustomobject]@{
                    AppDisplayName = $a.displayName
                    AppId          = $a.appId
                    ObjectId       = $a.id
                    Name           = $f.name
                    Issuer         = $f.issuer
                    Subject        = $f.subject
                    Audiences      = (@($f.audiences) -join ',')
                    Description    = $f.description
                    KnownIssuer    = $known
                })
            }
        }
        if ($batch.Count -lt $reqs.Count) { $ficStatus = 'Partial' }
    }
    catch { Write-Warning "Could not read federated identity credentials: $($_.Exception.Message)"; $ficStatus = 'Failed' }
}
foreach ($f in $ficRows) {
    if (-not $f.KnownIssuer) {
        Add-Finding -Severity Medium -Category 'Credentials' -Title ("Federated identity credential with an uncommon issuer on '{0}'" -f $f.AppDisplayName) `
            -Detail ("AppId {0}. FIC '{1}', issuer {2}, subject {3}. Whoever controls this issuer can sign in as the app without a secret." -f $f.AppId, $f.Name, $f.Issuer, $f.Subject) `
            -Recommendation 'Confirm the issuer and subject belong to your own workload (CI/CD, Kubernetes, another cloud). If not, remove the FIC and treat the app as compromised.'
    }
}
if ($ficRows.Count -gt 0) { Write-Host ("    {0} federated identity credential(s) found - see FederatedIdentityCredentials.csv" -f $ficRows.Count) }
Add-Coverage -Check 'App credentials (secrets / certificates)' -Status Done -Note ("{0} credential(s) on {1} app registrations and {2} service principals" -f $credRows.Count, $apps.Count, $allSPs.Count)
Add-Coverage -Check 'Federated identity credentials' -Status $ficStatus -Note ("{0} FIC(s); no creation timestamps exist, additions are covered by the audit log" -f $ficRows.Count)
#endregion

#region ------------------------------ 4. High-risk application permissions ------------------------------
Write-Step 4 'Application permissions held by apps (Microsoft Graph, Exchange Online, SharePoint)'
# An app holding e.g. RoleManagement.ReadWrite.Directory is effectively a Global Administrator without the role.
$permRows = [System.Collections.Generic.List[object]]::new()
$permStatus = 'Done'; $permNotes = [System.Collections.Generic.List[string]]::new()
foreach ($resAppId in $ResourceApps.Keys) {
    $resSp = $script:SpByAppId[$resAppId]
    if (-not $resSp) { $permNotes.Add("$($ResourceApps[$resAppId]) not present"); continue }
    try {
        $full = Invoke-GraphWithRetry -Uri ('https://graph.microsoft.com/v1.0/servicePrincipals/{0}?$select=id,appRoles' -f $resSp.id)
        $roleValues = @{}
        foreach ($ar in @($full.appRoles)) { if ($ar) { $roleValues[[string]$ar.id] = [string]$ar.value } }
        $assigned = @(Invoke-GraphPaged -Uri ('https://graph.microsoft.com/v1.0/servicePrincipals/{0}/appRoleAssignedTo?$top=999' -f $resSp.id))
        foreach ($x in $assigned) {
            if ($x.principalType -ne 'ServicePrincipal') { continue }
            $perm = $roleValues[[string]$x.appRoleId]
            if (-not $perm) { $perm = [string]$x.appRoleId }
            $principal = $script:SpById[[string]$x.principalId]
            $tier = if ($Tier0Permissions -contains $perm) { 'Tier0' } elseif ($Tier1Permissions -contains $perm) { 'Tier1' } else { 'Other' }
            $created = ConvertTo-Utc $x.createdDateTime
            $permRows.Add([pscustomobject]@{
                Principal      = $x.principalDisplayName
                PrincipalAppId = $(if ($principal) { $principal.appId } else { $null })
                PrincipalId    = $x.principalId
                Resource       = $ResourceApps[$resAppId]
                Permission     = $perm
                Tier           = $tier
                GrantedUtc     = $created
                GrantedInWindow = [bool]($created -and $created -ge $StartUtc -and $created -le $EndUtc)
                IsVendorApp    = $(if ($principal) { Test-IsVendor $principal.appId $principal.id ([string]$principal.appOwnerOrganizationId) } else { $false })
                IsMicrosoftApp = $(if ($principal) { $MicrosoftTenantIds -contains [string]$principal.appOwnerOrganizationId } else { $false })
            })
        }
    }
    catch { Write-Warning ("Could not read app role assignments for {0}: {1}" -f $ResourceApps[$resAppId], $_.Exception.Message); $permStatus = 'Partial' }
}

$script:PrivilegedAppIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
foreach ($r in ($roleRows | Where-Object { $_.Privileged -and $_.AppId })) { [void]$script:PrivilegedAppIds.Add([string]$r.AppId) }
foreach ($r in ($permRows | Where-Object { $_.Tier -eq 'Tier0' -and $_.PrincipalAppId })) { [void]$script:PrivilegedAppIds.Add([string]$r.PrincipalAppId) }

foreach ($g in ($permRows | Where-Object { -not $_.IsMicrosoftApp } | Group-Object PrincipalId)) {
    $first = $g.Group[0]
    $t0 = @($g.Group | Where-Object Tier -eq 'Tier0')
    $t1 = @($g.Group | Where-Object Tier -eq 'Tier1')
    $newT = @($g.Group | Where-Object { $_.GrantedInWindow -and $_.Tier -in 'Tier0', 'Tier1' })
    $fmtPerms = { param($rows) (($rows | ForEach-Object { '{0} ({1})' -f $_.Permission, $_.Resource }) -join ', ') }
    if ($newT.Count -gt 0) {
        $sev = if ($first.IsVendorApp -or @($newT | Where-Object Tier -eq 'Tier0').Count -gt 0) { 'Critical' } else { 'High' }
        Add-Finding -Severity $sev -Category 'Permissions' -Title ("High-risk application permission granted during window to '{0}'" -f $first.Principal) `
            -Detail ("AppId {0}. Granted in window: {1}." -f $first.PrincipalAppId, (& $fmtPerms $newT)) `
            -Recommendation 'Confirm who granted this (AuditEvents.csv: "Add app role assignment to service principal" / "Consent to application"). If not intentional, remove the assignment and investigate the app.'
    }
    if ($first.IsVendorApp -and ($t0.Count + $t1.Count) -gt 0) {
        $sev = if ($t0.Count -gt 0) { 'High' } else { 'Medium' }
        Add-Finding -Severity $sev -Category 'Permissions' -Title ("ConnectWise/SkyKick app holds high-risk application permissions: {0}" -f $first.Principal) `
            -Detail ("AppId {0}. Tier-0 (tenant takeover): {1}. Data access: {2}. With the vendor credential compromised, these permissions are available to the attacker in this tenant." -f $first.PrincipalAppId, $(if ($t0) { & $fmtPerms $t0 } else { 'none' }), $(if ($t1) { & $fmtPerms $t1 } else { 'none' })) `
            -Recommendation 'Keep the app disabled until ConnectWise confirms credential reset. Consider whether it needs these permissions at all before re-enabling.'
    }
    elseif ($t0.Count -gt 0 -and $newT.Count -eq 0) {
        Add-Finding -Severity Medium -Category 'Permissions' -Title ("App holds tenant-takeover application permissions: {0}" -f $first.Principal) `
            -Detail ("AppId {0}. {1}. Anyone holding a credential for this app can escalate to Global Administrator." -f $first.PrincipalAppId, (& $fmtPerms $t0)) `
            -Recommendation 'Confirm the permission is required, restrict who can add credentials to this app (owners, Application Administrators), and review its credentials and sign-ins.'
    }
}
Write-Host ("    {0} application permission assignment(s) reviewed" -f $permRows.Count)
Add-Coverage -Check 'Application permissions (Graph / EXO / SPO)' -Status $permStatus -Note ((@("{0} assignment(s)" -f $permRows.Count) + $permNotes) -join '; ')
#endregion

#region ------------------------------ 5. Entra audit log ------------------------------
Write-Step 5 'Entra audit log (applications, roles, users, groups, policies, domains, partners)'
# Ordered: the first matching pattern decides the kind of change.
$auditKinds = @(
    @{ P = 'Add*member to role*';                 K = 'RoleAdd' }
    @{ P = '*Certificates and secrets*';          K = 'Cred' }
    @{ P = '*service principal credentials*';     K = 'Cred' }
    @{ P = 'Add owner to application*';           K = 'AppOwner' }
    @{ P = 'Add owner to service principal*';     K = 'AppOwner' }
    @{ P = 'Consent to application*';             K = 'Consent' }
    @{ P = 'Add app role assignment*';            K = 'Consent' }
    @{ P = 'Add delegated permission grant*';     K = 'Consent' }
    @{ P = 'Add application*';                    K = 'AppMgmt' }
    @{ P = 'Add service principal*';              K = 'AppMgmt' }
    @{ P = 'Update application*';                 K = 'AppMgmt' }
    @{ P = 'Update service principal*';           K = 'AppMgmt' }
    @{ P = 'Reset password*';                     K = 'UserAuth' }
    @{ P = 'Reset user password*';                K = 'UserAuth' }
    @{ P = 'Change user password*';               K = 'UserAuth' }
    @{ P = '*security info*';                     K = 'UserAuth' }
    @{ P = '*Temporary Access Pass*';             K = 'UserAuth' }
    @{ P = '*authentication method*';             K = 'UserAuth' }
    @{ P = 'Disable Strong Authentication*';      K = 'UserAuth' }
    @{ P = 'Add user';                            K = 'UserCreate' }
    @{ P = 'Invite external user*';               K = 'UserCreate' }
    @{ P = 'Restore user*';                       K = 'UserCreate' }
    @{ P = 'Update user';                         K = 'UserUpdate' }
    @{ P = 'Add member to group*';                K = 'GroupMember' }
    @{ P = 'Add owner to group*';                 K = 'GroupMember' }
    @{ P = '*conditional access*';                K = 'CAPolicy' }
    @{ P = '*named location*';                    K = 'CAPolicy' }
    @{ P = '*authorization policy*';              K = 'PolicyOther' }
    @{ P = '*cross*tenant*';                      K = 'PolicyOther' }
    @{ P = '*authentication methods policy*';     K = 'PolicyOther' }
    @{ P = '*authentication strength*';           K = 'PolicyOther' }
    @{ P = '*app management polic*';              K = 'PolicyOther' }
    @{ P = 'Add policy*';                         K = 'PolicyOther' }
    @{ P = 'Update policy*';                      K = 'PolicyOther' }
    @{ P = 'Delete policy*';                      K = 'PolicyOther' }
    @{ P = 'Set domain authentication*';          K = 'DomainFed' }
    @{ P = '*federation settings*';               K = 'DomainFed' }
    @{ P = '*federation configuration*';          K = 'DomainFed' }
    @{ P = 'Add domain to company*';              K = 'Domain' }
    @{ P = 'Add unverified domain*';              K = 'Domain' }
    @{ P = 'Add verified domain*';                K = 'Domain' }
    @{ P = 'Verify domain*';                      K = 'Domain' }
    @{ P = '*partner*';                           K = 'Partner' }
)
# Permission names that a consent / grant event ADDED. Entra logs the grant's full scope list, including scopes
# consented long before, either as oldValue/newValue or as "[before] => [after]" inside newValue.
$GraphCliAppId = '14d82eec-204b-4c2f-b7e8-296a70dab67e'   # Microsoft Graph Command Line Tools (Microsoft Graph PowerShell)
function Get-PermTokens([string]$Text) {
    $set = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($m in [regex]::Matches($Text, '(?<![A-Za-z0-9.\-])[A-Za-z][A-Za-z0-9\-]*\.[A-Za-z0-9\-]+(\.[A-Za-z0-9\-]+)*')) { [void]$set.Add($m.Value) }
    return ,$set
}
function Get-AddedPermissions($Targets) {
    $before = ''; $after = ''; $hasBefore = $false
    foreach ($t in @($Targets)) {
        foreach ($mp in @($t.modifiedProperties)) {
            if ([string]$mp.displayName -notmatch 'Scope|Permissions|AppRole') { continue }
            $nv = [string]$mp.newValue; $ov = [string]$mp.oldValue
            if ($nv -match '=>') { $parts = $nv -split '=>', 2; $before += ' ' + $parts[0]; $after += ' ' + $parts[1]; $hasBefore = $true }
            else { $after += ' ' + $nv }
            if ($ov -and $ov -notmatch '^\s*(\[\s*\]|"?"?|null)\s*$') { $before += ' ' + $ov; $hasBefore = $true }
        }
    }
    $a = Get-PermTokens $after; $b = Get-PermTokens $before
    $added = @($a | Where-Object { -not $b.Contains($_) })
    return [pscustomobject]@{ Added = $added; HadPrevious = $hasBefore; PreviousCount = $b.Count }
}

function Get-AuditKind([string]$Activity) {
    foreach ($k in $auditKinds) { if ($Activity -like $k.P) { return $k.K } }
    return $null
}
$sevRank = @{ Info = 0; Medium = 1; High = 2; Critical = 3 }

$auditRows = [System.Collections.Generic.List[object]]::new()
$auditCats = @('ApplicationManagement', 'RoleManagement', 'UserManagement', 'GroupManagement', 'Policy', 'DirectoryManagement')
$auditRead = 0; $auditFailed = [System.Collections.Generic.List[string]]::new()
foreach ($cat in $auditCats) {
    $filter = "activityDateTime ge $startStr and activityDateTime le $endStr and category eq '$cat'"
    $uri = 'https://graph.microsoft.com/v1.0/auditLogs/directoryAudits?$filter=' + [uri]::EscapeDataString($filter) + '&$top=500'
    try { $events = @(Invoke-GraphPaged -Uri $uri -MaxItems 50000 -Label "AuditLog:$cat"); $auditRead += $events.Count }
    catch {
        $auditFailed.Add($cat)
        Add-Finding -Severity Medium -Category 'AuditLog' -Title "Could not read audit log category $cat" -Detail $_.Exception.Message `
            -Recommendation 'Run with Security Reader / Global Reader / Reports Reader and AuditLog.Read.All.'
        continue
    }
    foreach ($e in $events) {
        $act = [string]$e.activityDisplayName
        $kind = Get-AuditKind $act
        if (-not $kind) { continue }

        $app = $e.initiatedBy.app; $user = $e.initiatedBy.user
        $initType = 'Unknown'; $initName = $null; $initAppId = $null; $initSpId = $null; $initIp = $null
        if ($app -and ($app.appId -or $app.servicePrincipalId -or $app.displayName)) {
            $initType = 'Application'; $initName = $app.displayName; $initAppId = $app.appId; $initSpId = $app.servicePrincipalId
            if (-not $initAppId -and $initSpId -and $script:SpById.ContainsKey([string]$initSpId)) { $initAppId = $script:SpById[[string]$initSpId].appId }
        }
        elseif ($user -and ($user.userPrincipalName -or $user.id)) {
            $initType = 'User'; $initName = $user.userPrincipalName; $initIp = $user.ipAddress
        }

        $ua = [string](@($e.additionalDetails) | Where-Object { $_.key -eq 'User-Agent' } | Select-Object -First 1).value
        $targets = @($e.targetResources)
        $roleName = $null; $modNames = @(); $modText = ''
        foreach ($t in $targets) {
            foreach ($mp in @($t.modifiedProperties)) {
                if ($mp.displayName) { $modNames += $mp.displayName }
                if ($mp.displayName -eq 'Role.DisplayName') { $roleName = ([string]$mp.newValue).Trim('"') }
                $modText += ' ' + [string]$mp.newValue
            }
        }
        $targetAppIds = @()
        foreach ($t in $targets) {
            if ($t.type -eq 'Application' -and $appById.ContainsKey([string]$t.id)) { $targetAppIds += $appById[[string]$t.id].appId }
            elseif ($t.type -eq 'ServicePrincipal' -and $script:SpById.ContainsKey([string]$t.id)) { $targetAppIds += $script:SpById[[string]$t.id].appId }
        }

        $isRoleAdd   = $kind -eq 'RoleAdd'
        $isCred      = ($kind -eq 'Cred') -or (($modNames -join ',') -match 'KeyDescription|FederatedIdentityCredentials|PasswordCredentials|KeyCredentials')
        $isApp       = $initType -eq 'Application'
        $isVendor    = $isApp -and (Test-IsVendor $initAppId $initSpId '')
        $isMsApp     = $isApp -and -not $isVendor -and (Test-IsMicrosoftApp $initSpId $initAppId)
        $selfAssign  = $isRoleAdd -and $initSpId -and (@($targets | ForEach-Object { [string]$_.id }) -contains [string]$initSpId)
        $suspUA      = Test-SuspiciousUA $ua
        $privGroup   = ($kind -eq 'GroupMember') -and [bool](@($targets | Where-Object { $_.type -eq 'Group' -and $script:PrivGroupIds.Contains([string]$_.id) }))
        $tier0Perm   = @()
        $consentNote = ''
        if ($kind -eq 'Consent') {
            $perm = Get-AddedPermissions $targets
            $tier0Perm = @($Tier0Permissions | Where-Object { $perm.Added -contains $_ })
            if ($perm.HadPrevious -and $perm.PreviousCount -gt 0) { $consentNote = " (newly added; {0} permission(s) were already granted before)" -f $perm.PreviousCount }
            # The tool's own consent: Graph Command Line Tools, by the account running this check, adding no tenant-takeover scope
            $graphCli = @($targets | Where-Object { $_.type -eq 'ServicePrincipal' -and $script:SpById.ContainsKey([string]$_.id) -and $script:SpById[[string]$_.id].appId -eq $GraphCliAppId })
            $byRunner = ($graphCli.Count -gt 0) -and ($initType -eq 'User') -and ([string]$initName -eq [string]$ctx.Account)
            # Without a logged "before" list, the tool's consent is recognised by the grant holding every scope this tool requests
            $allToolScopes = -not @($scopes | Where-Object { $perm.Added -notcontains $_ }).Count
            $selfConsent = $byRunner -and (($tier0Perm.Count -eq 0) -or (-not $perm.HadPrevious -and $allToolScopes))
            $preexistingT0 = if ($selfConsent -and $tier0Perm.Count -gt 0) { $tier0Perm } else { @() }
        }
        else { $selfConsent = $false; $preexistingT0 = @() }
        $tier0Role   = $roleName -and ($Tier0Roles -contains $roleName)
        $effKind     = if ($isCred) { 'Cred' } elseif ($kind -eq 'GroupMember' -and $privGroup) { 'GroupPriv' } else { $kind }

        # UserUpdate and ordinary group changes are high volume; keep them only when something else flags them.
        $reasons = [System.Collections.Generic.List[string]]::new(); $sev = $null
        $raise = { param($s, [string]$why) if ($why) { $reasons.Add($why) }; if (-not $sev -or $sevRank[$s] -gt $sevRank[$sev]) { Set-Variable -Name sev -Value $s -Scope 1 } }

        $sensitiveKinds = @('RoleAdd', 'Cred', 'AppOwner', 'UserAuth', 'UserCreate', 'GroupPriv', 'CAPolicy', 'PolicyOther', 'DomainFed', 'Domain', 'Partner')
        if ($isVendor) {
            if ($sensitiveKinds -contains $effKind -or ($effKind -eq 'Consent' -and $tier0Perm)) { & $raise 'Critical' 'initiated by a ConnectWise/SkyKick application' }
            else { & $raise 'High' 'initiated by a ConnectWise/SkyKick application' }
        }
        if ($isApp -and -not $isMsApp) {
            switch ($effKind) {
                'RoleAdd'     { if ($selfAssign) { & $raise 'High' 'application added ITSELF to a directory role' } else { & $raise 'High' 'application added a principal to a directory role' } }
                'Cred'        { & $raise 'High' 'application changed credentials of an app/service principal' }
                'AppOwner'    { & $raise 'High' 'application added an owner to an app (owners can add credentials)' }
                'UserAuth'    { & $raise 'High' 'application changed a user password / authentication method' }
                'UserCreate'  { & $raise 'High' 'application created or invited a user' }
                'GroupPriv'   { & $raise 'High' 'application changed membership of a role-assignable / role-holding group' }
                'CAPolicy'    { & $raise 'High' 'application changed Conditional Access' }
                'PolicyOther' { & $raise 'High' 'application changed a tenant policy' }
                'DomainFed'   { & $raise 'Critical' 'application changed domain federation (Golden SAML persistence)' }
                'Domain'      { & $raise 'High' 'application added or verified a domain' }
                'Partner'     { & $raise 'High' 'application changed partner relationships' }
                'Consent'     { if ($tier0Perm) { & $raise 'High' ("application granted tenant-takeover permission(s): {0}{1}" -f ($tier0Perm -join ', '), $consentNote) } }
            }
        }
        if ($isMsApp -and $effKind -eq 'DomainFed') { & $raise 'High' 'domain federation changed' }
        if (-not $isApp) {
            switch ($effKind) {
                'DomainFed'   { & $raise 'High' 'domain federation changed - verify against your AD FS / IdP change records (Golden SAML persistence)' }
                'Partner'     { & $raise 'High' 'partner (DAP/GDAP) relationship changed' }
                'Domain'      { & $raise 'Medium' 'domain added or verified' }
                'CAPolicy'    { & $raise 'Medium' 'Conditional Access changed' }
                'PolicyOther' { & $raise 'Medium' 'tenant policy changed' }
                'GroupPriv'   { & $raise 'Medium' 'membership of a role-assignable / role-holding group changed' }
                'RoleAdd'     { if ($tier0Role) { & $raise 'Medium' ("Tier-0 role '{0}' assigned" -f $roleName) } }
                'Consent'     { if ($tier0Perm) { & $raise 'Medium' ("tenant-takeover permission(s) granted: {0}{1}" -f ($tier0Perm -join ', '), $consentNote) } }
                'AppOwner'    { & $raise 'Medium' 'owner added to an app (owners can add credentials)' }
                'Cred'        { & $raise 'Medium' 'credential added/changed by a user - confirm it was intentional' }
            }
        }
        if ($suspUA) { & $raise 'High' "suspicious user agent '$ua'" }

        # Azure ESTS Service (Microsoft first-party token service) rotating the P2P Server certificate is expected.
        $isMsP2PRotation = ($initAppId -eq '00000001-0000-0000-c000-000000000000') -and
                           (@($targets | ForEach-Object { $_.displayName }) -contains 'P2P Server')
        if ($isMsP2PRotation -and -not $isVendor -and -not $suspUA) {
            $reasons.Clear(); $reasons.Add('Microsoft-managed P2P Server certificate rotation by Azure ESTS Service')
            $sev = 'Info'
        }
        if ($selfConsent -and -not $isVendor -and -not $suspUA) {
            $reasons.Clear(); $reasons.Add('consent for Microsoft Graph Command Line Tools by the account running this check - typically the consent prompt for this tool')
            if ($preexistingT0.Count -gt 0) { $reasons.Add(("the Graph PowerShell grant also holds high-privilege delegated scopes ({0}); trim them if no longer needed" -f ($preexistingT0 -join ', '))) }
            $sev = 'Info'
        }
        if ($isMsApp -and -not $sev -and $effKind -in 'RoleAdd', 'Cred') { $reasons.Add('Microsoft first-party service (e.g. PIM activation, managed rotation)') }

        if ($effKind -in 'UserUpdate', 'GroupMember' -and -not $sev) { continue }
        if ($isCred) { foreach ($id in $targetAppIds) { if ($id) { [void]$credChangedAppIds.Add([string]$id) } } }

        $targetText = ($targets | ForEach-Object { '{0} ({1}) [{2}]' -f $(if ($_.displayName) { $_.displayName } else { $_.userPrincipalName }), $_.type, $_.id }) -join '; '
        $row = [pscustomobject]@{
            TimeUtc            = (ConvertTo-Utc $e.activityDateTime)
            Category           = $cat
            Kind               = $effKind
            Activity           = $act
            Result             = $e.result
            ResultReason       = $e.resultReason
            InitiatorType      = $initType
            Initiator          = $initName
            InitiatorAppId     = $initAppId
            InitiatorSpId      = $initSpId
            InitiatorIP        = $initIp
            UserAgent          = $ua
            Role               = $roleName
            Targets            = $targetText
            ModifiedProperties = (($modNames | Select-Object -Unique) -join ',')
            Severity           = $sev
            Flags              = ($reasons -join '; ')
            CorrelationId      = $e.correlationId
        }
        $auditRows.Add($row)

        if ($sev -and -not ($isMsP2PRotation -and $sev -eq 'Info' -and $act -like 'Update service principal*')) {
            Add-Finding -Severity $sev -Category 'AuditLog' -Title ("{0} by {1} '{2}' at {3:yyyy-MM-dd HH:mm} UTC ({4})" -f $act, $initType, $initName, $row.TimeUtc, $e.result) `
                -Detail ("Why: {0}. Targets: {1}. Role: {2}. User-Agent: {3}." -f $row.Flags, $targetText, $roleName, $ua) `
                -Recommendation $(if ($sev -eq 'Info') { 'None. Expected Microsoft-managed activity, listed for completeness.' } else { switch ($effKind) {
                    'DomainFed' { 'Compare the federation issuer and signing certificate with your IdP (FederatedDomains.csv). If not yours: convert the domain back to managed, revoke all sessions, and treat the tenant as fully compromised.' }
                    'UserAuth'  { 'Confirm with the user/helpdesk. If not expected: reset the password, remove the added method, revoke sessions and review the account sign-ins.' }
                    'UserCreate' { 'Confirm the account is legitimate. If not: disable it and review what it accessed and which roles/groups it received.' }
                    'Partner'   { 'Confirm the partner relationship with your MSP/CSP. Remove any relationship you did not approve.' }
                    default     { 'Validate this change. If not expected: revert it (remove the role/credential/owner/policy change), disable the initiating app, and investigate the target as compromised.' }
                } })
        }
    }
}
Write-Host ("    {0} audit events read, {1} relevant" -f $auditRead, $auditRows.Count)
$auditStatus = if ($auditFailed.Count -eq $auditCats.Count) { 'Failed' } elseif ($auditFailed.Count -gt 0) { 'Partial' } else { 'Done' }
Add-Coverage -Check 'Entra audit log' -Status $auditStatus -Note ("categories: {0}{1}" -f ($auditCats -join ', '), $(if ($auditFailed.Count) { '; unreadable: ' + ($auditFailed -join ', ') } else { '' }))
#endregion

#region ------------------------------ 6. Sign-in logs ------------------------------
$signInVendor = [System.Collections.Generic.List[object]]::new()
$signInIp     = [System.Collections.Generic.List[object]]::new()
$signInAsn    = [System.Collections.Generic.List[object]]::new()
$signInSweep  = [System.Collections.Generic.List[object]]::new()
$signInCred   = [System.Collections.Generic.List[object]]::new()
$script:SpPullCache = $null
$script:UserPullCache = @{}

# All service-principal sign-ins from the ASN look-back start to the end of the window, fetched once and shared.
function Get-AllSpSignIns {
    if ($null -eq $script:SpPullCache) {
        $f = "createdDateTime ge $asnStartStr and createdDateTime le $endStr and signInEventTypes/any(t: t eq 'servicePrincipal')"
        $script:SpPullCache = @(Invoke-SignInQuery -Filter $f -Label 'AllServicePrincipals')
    }
    return $script:SpPullCache
}
# Client-side fallback for the ASN hunt when Graph does not accept a filter on autonomousSystemNumber.
function Get-AllUserSignIns([string]$Type) {
    if (-not $script:UserPullCache.ContainsKey($Type)) {
        $f = "createdDateTime ge $asnStartStr and createdDateTime le $endStr and signInEventTypes/any(t: t eq '$Type')"
        $script:UserPullCache[$Type] = @(Invoke-SignInQuery -Filter $f -Label "All:$Type")
    }
    return $script:UserPullCache[$Type]
}

if ($SkipSignInLogs) {
    Write-Step 6 'Sign-in logs (skipped)'
    Add-Coverage -Check 'Sign-in logs' -Status Skipped -Note '-SkipSignInLogs'
}
else {
    Write-Step 6 'Sign-in logs (beta API; can be slow on large tenants)'

    # 6a. Service principal sign-ins of the ConnectWise apps
    foreach ($appId in $VendorAppIdSet) {
        $f = "createdDateTime ge $startStr and createdDateTime le $endStr and appId eq '$appId' and signInEventTypes/any(t: t eq 'servicePrincipal')"
        foreach ($r in @(Invoke-SignInQuery -Filter $f -Label "VendorApp:$appId")) { $signInVendor.Add($r) }
    }
    foreach ($g in ($signInVendor | Group-Object AppId, IPAddress)) {
        $first = $g.Group[0]
        $ok = @($g.Group | Where-Object Success).Count
        $span = '{0:yyyy-MM-dd HH:mm} - {1:yyyy-MM-dd HH:mm} UTC' -f ($g.Group | Measure-Object TimeUtc -Minimum).Minimum, ($g.Group | Measure-Object TimeUtc -Maximum).Maximum
        $detail = "{0} sign-ins ({1} successful), {2}. App {3} ({4}). {5}, country {6}." -f $g.Count, $ok, $span, $first.AppDisplayName, $first.AppId, (Format-Asn $first.ASN), $first.Country
        switch ($first.IPClass) {
            { $_ -in 'KnownMalicious', 'AttackerASN' } {
                $what = if ($first.IPClass -eq 'KnownMalicious') { 'known attacker IP' } else { "attacker network $($first.AttackerNetwork)" }
                Add-Finding -Severity Critical -Category 'SignIns' -Title ("Vendor app signed in from {0} ({1})" -f $what, $first.IPAddress) -Detail $detail `
                    -Recommendation 'Treat the tenant as accessed. Disable the app, review all credentials/roles, and review the Purview Unified Audit Log (MailItemsAccessed, FileDownloaded) for this AppId and IP (-IncludeExchange does the IP search).'
            }
            'Public' {
                Add-Finding -Severity High -Category 'SignIns' -Title ("Vendor app signed in from public IP {0}" -f $first.IPAddress) -Detail ($detail + ' Legitimate traffic for these apps normally comes from Azure private IPv6 space.') `
                    -Recommendation 'Determine who owns this IP. If unknown, handle as unauthorized access.'
            }
            'Microsoft' {
                Add-Finding -Severity Medium -Category 'SignIns' -Title ("Vendor app signed in from a public Microsoft/Azure IP {0}" -f $first.IPAddress) -Detail ($detail + ' Legitimate traffic normally uses Azure private IPv6; a public Azure address can still be attacker-rented infrastructure.') `
                    -Recommendation 'Correlate with AuditEvents.csv and with ConnectWise. Unexplained activity from this IP should be handled as unauthorized access.'
            }
            'PrivateIPv6-ULA' {
                $inWin = @($g.Group | Where-Object { $_.TimeUtc -ge $HuntressWindowStart -and $_.TimeUtc -le $HuntressWindowEnd }).Count
                if ($first.IPAddress -like "$UlaPrefixOfInterest*" -and $inWin -gt 0) {
                    Add-Finding -Severity Medium -Category 'SignIns' -Title ("Vendor app sign-ins from Azure ULA {0} during the persistence window" -f $first.IPAddress) `
                        -Detail ($detail + " $inWin sign-in(s) between 2026-10-15 01:00 and 2026-10-16 02:00 UTC. This range carries both legitimate and malicious traffic.") `
                        -Recommendation 'Correlate with AuditEvents.csv: role assignments or credential changes by this app at the same time indicate abuse.'
                }
            }
        }
    }
    if ($signInVendor.Count -eq 0 -and -not $script:SignInBlocked) {
        Add-Finding -Severity Info -Category 'SignIns' -Title 'No ConnectWise/SkyKick service principal sign-ins in the window' `
            -Detail ("Checked {0} application IDs." -f $VendorAppIdSet.Count) -Recommendation 'None.'
    }

    # 6b. Anything from the known attacker IP(s) (password spray, user and app sign-ins) - over the longer ASN look-back
    foreach ($ip in $AttackerIPs) {
        foreach ($type in @('interactiveUser', 'nonInteractiveUser', 'servicePrincipal')) {
            $f = "createdDateTime ge $asnStartStr and createdDateTime le $endStr and ipAddress eq '$ip' and signInEventTypes/any(t: t eq '$type')"
            foreach ($r in @(Invoke-SignInQuery -Filter $f -Label "AttackerIP:$ip/$type")) { $signInIp.Add($r) }
        }
    }
    foreach ($g in ($signInIp | Group-Object { if ($_.UserPrincipalName) { $_.UserPrincipalName } else { $_.AppDisplayName } })) {
        $ok = @($g.Group | Where-Object Success).Count
        $sev = if ($ok -gt 0) { 'Critical' } else { 'High' }
        Add-Finding -Severity $sev -Category 'SignIns' -Title ("{0} sign-in(s) from attacker IP for '{1}' ({2} successful)" -f $g.Count, $g.Name, $ok) `
            -Detail ("IPs: {0}. Event types: {1}. User agents: {2}. Error codes: {3}." -f (($g.Group.IPAddress | Select-Object -Unique) -join ','), (($g.Group.EventTypes | Select-Object -Unique) -join ','), (($g.Group.UserAgent | Where-Object { $_ } | Select-Object -Unique) -join ', '), (($g.Group.ErrorCode | Select-Object -Unique) -join ',')) `
            -Recommendation $(if ($ok -gt 0) { 'Successful sign-in: reset credentials / revoke sessions (users) or disable the app and rotate credentials (apps); investigate activity after the sign-in.' } else { 'Failed attempts (likely password spray). Confirm the accounts have MFA and are not locked out; block the IP in a named location.' })
    }
    if ($signInIp.Count -eq 0 -and -not $script:SignInBlocked) {
        Add-Finding -Severity Info -Category 'SignIns' -Title ("No sign-ins from {0} since {1:yyyy-MM-dd}" -f ($AttackerIPs -join ', '), $AsnStartUtc) -Detail 'Interactive, non-interactive and service principal sign-in logs were checked.' -Recommendation 'None. A clean result does not rule out access through other infrastructure.'
    }

    # 6c. Attacker network hunt (ASN + announced prefixes): catches address rotation inside the same provider.
    #     User sign-ins carry an ASN: a server-side filter is tried and EVERY returned row is verified, because
    #     Graph can ignore the filter and return unfiltered results. Service-principal sign-ins carry no ASN
    #     (reported as 0), so they are matched client-side against the attacker prefixes instead.
    $asnMode = 'n/a'
    if (-not $SkipAsnHunt -and -not $script:SignInBlocked) {
        $asnModes = [System.Collections.Generic.List[string]]::new()
        foreach ($type in @('interactiveUser', 'nonInteractiveUser', 'servicePrincipal')) {
            $rows = [System.Collections.Generic.List[object]]::new()
            $mode = $null
            if ($type -ne 'servicePrincipal') {
                foreach ($asn in $AttackerASNs) {
                    $f = "createdDateTime ge $asnStartStr and createdDateTime le $endStr and autonomousSystemNumber eq $asn and signInEventTypes/any(t: t eq '$type')"
                    $r = @(Invoke-SignInQuery -Filter $f -Label "ASN:$asn/$type" -ExpectFailure)
                    if ($script:SignInBlocked) { break }
                    if ($script:LastSignInError) { $mode = 'client-side (server filter rejected)'; break }
                    if (@($r | Where-Object { [string]$_.ASN -ne [string]$asn }).Count -gt 0) { $mode = 'client-side (server filter ignored)'; break }
                    foreach ($x in $r) { $rows.Add($x) }
                }
                if (-not $mode) { $mode = 'server-side, verified' }
            }
            else { $mode = 'client-side prefix match (no ASN on app sign-ins)' }
            if ($mode -like 'client-side*' -and -not $script:SignInBlocked) {
                $rows.Clear()
                $pool = if ($type -eq 'servicePrincipal') { Get-AllSpSignIns } else { Get-AllUserSignIns $type }
                foreach ($x in @($pool | Where-Object { $_.IPClass -eq 'AttackerASN' })) { $rows.Add($x) }
            }
            foreach ($x in $rows) { $x.Query = "AttackerNetwork/$type"; $signInAsn.Add($x) }
            $asnModes.Add("$type=$mode")
        }
        $asnMode = ($asnModes -join '; ')
        $netLabel = ('AS{0}' -f ($AttackerASNs -join '/AS'))
        # IPs already reported by 6b are not repeated here
        $newAsnRows = @($signInAsn | Where-Object { $AttackerIPs -notcontains $_.IPAddress })
        foreach ($g in ($newAsnRows | Group-Object { if ($_.UserPrincipalName) { $_.UserPrincipalName } else { '{0} [{1}]' -f $_.AppDisplayName, $_.AppId } })) {
            $ok = @($g.Group | Where-Object Success).Count
            $sev = if ($ok -gt 0) { 'Critical' } else { 'High' }
            $isSp = [bool]($g.Group | Where-Object { $_.EventTypes -match 'servicePrincipal' })
            Add-Finding -Severity $sev -Category 'SignIns' -Title ("{0} sign-in(s) from attacker network {1} for '{2}' ({3} successful)" -f $g.Count, $netLabel, $g.Name, $ok) `
                -Detail ("Matched: {0}. IPs: {1}. Event types: {2}. User agents: {3}. Error codes: {4}. First {5:yyyy-MM-dd HH:mm}, last {6:yyyy-MM-dd HH:mm} UTC." -f (($g.Group.AttackerNetwork | Select-Object -Unique) -join ', '), (($g.Group.IPAddress | Select-Object -Unique) -join ', '), (($g.Group.EventTypes | Select-Object -Unique) -join ','), (($g.Group.UserAgent | Where-Object { $_ } | Select-Object -Unique) -join ', '), (($g.Group.ErrorCode | Select-Object -Unique) -join ','), ($g.Group | Measure-Object TimeUtc -Minimum).Minimum, ($g.Group | Measure-Object TimeUtc -Maximum).Maximum) `
                -Recommendation $(if ($isSp -and $ok -gt 0) { 'An application credential is being used from attacker infrastructure. Remove ALL credentials on this app, review its permissions and audit trail, and treat its data as accessed.' } elseif ($ok -gt 0) { 'Successful user sign-in from attacker infrastructure: reset the password, revoke sessions, review MFA methods and mailbox rules, and investigate activity after the sign-in.' } else { 'Failed attempts from attacker infrastructure (likely password spray). Confirm MFA, check for lockouts, and block the attacker ranges in a named location.' })
        }
        if ($signInAsn.Count -eq 0 -and -not $script:SignInBlocked) {
            Add-Finding -Severity Info -Category 'SignIns' -Title ("No sign-ins from attacker network {0} since {1:yyyy-MM-dd}" -f $netLabel, $AsnStartUtc) `
                -Detail ("{0}. Attacker prefixes known: {1}." -f $asnMode, $script:AttackerPrefixes.Count) -Recommendation 'None.'
        }
        foreach ($ip in $script:ObservedAttackerIPs) { if ($AttackerIPs -notcontains $ip) { Write-Host ("    New attacker-network address observed: {0}" -f $ip) -ForegroundColor Yellow } }
    }

    # 6d. Sweep: every service principal sign-in in the window from public, non-Microsoft networks.
    #     Catches planted credentials in use even when the audit event that created them has aged out.
    $sweepComplete = $false
    if (-not $SkipAsnHunt -and -not $script:SignInBlocked) {
        $pool = @(Get-AllSpSignIns | Where-Object { $_.TimeUtc -ge $StartUtc })
        $sweepComplete = -not ($script:Truncated | Where-Object { $_ -like 'SignIns:AllServicePrincipals*' })
        foreach ($r in $pool) { if (-not $VendorAppIdSet.Contains([string]$r.AppId) -and $r.IPClass -eq 'Public') { $signInSweep.Add($r) } }
        $infoApps = [System.Collections.Generic.List[string]]::new()
        foreach ($g in ($signInSweep | Group-Object AppId)) {
            $first = $g.Group[0]
            $ok = @($g.Group | Where-Object Success).Count
            $nets = ($g.Group | Group-Object { Format-Asn $_.ASN } | Sort-Object Count -Descending | Select-Object -First 8 | ForEach-Object { '{0} x{1}' -f $_.Name, $_.Count }) -join ', '
            $ips  = ($g.Group | Group-Object IPAddress | Sort-Object Count -Descending | Select-Object -First 8 | ForEach-Object { '{0} x{1}' -f $_.Name, $_.Count }) -join ', '
            $detail = "AppId {0}. {1} sign-in(s), {2} successful. Networks: {3}. Top IPs: {4}. Service-principal sign-ins often carry no ASN; 'n/a' is not a network." -f $first.AppId, $g.Count, $ok, $nets, $ips
            if ($credChangedAppIds.Contains([string]$first.AppId)) {
                Add-Finding -Severity High -Category 'SignIns' -Title ("App with a credential change in the window signs in from non-Microsoft networks: {0}" -f $first.AppDisplayName) -Detail $detail `
                    -Recommendation 'Confirm these networks belong to the app vendor or your own infrastructure. Unknown networks right after a new secret was added indicate the planted credential is in use.'
            }
            elseif ($script:PrivilegedAppIds.Contains([string]$first.AppId)) {
                Add-Finding -Severity Medium -Category 'SignIns' -Title ("Privileged app signs in from non-Microsoft networks: {0}" -f $first.AppDisplayName) -Detail $detail `
                    -Recommendation 'This app holds a privileged role or tenant-takeover permissions. Confirm every network listed belongs to its vendor; consider Conditional Access for workload identities to pin its sign-in locations.'
            }
            else { $infoApps.Add(('{0} ({1}; IPs {2})' -f $first.AppDisplayName, $nets, (($g.Group.IPAddress | Select-Object -Unique | Select-Object -First 4) -join ', '))) }
        }
        if ($infoApps.Count -gt 0) {
            Add-Finding -Severity Info -Category 'SignIns' -Title ("{0} other app(s) sign in from non-Microsoft networks" -f $infoApps.Count) `
                -Detail (($infoApps | Select-Object -First 30) -join '; ') -Recommendation 'Usually third-party SaaS hosted outside Azure. Spot-check unfamiliar networks in SignIns-AllAppsNonMicrosoft.csv.'
        }
    }

    # 6e. Sign-ins of apps whose credentials changed in the window (direct queries when the sweep is unavailable or truncated)
    $toCheck = @($credChangedAppIds | Where-Object { $_ -and -not $VendorAppIdSet.Contains($_) })
    if ($sweepComplete) {
        foreach ($r in @(Get-AllSpSignIns | Where-Object { $_.TimeUtc -ge $StartUtc -and $toCheck -contains $_.AppId })) { $signInCred.Add($r) }
    }
    else {
        foreach ($appId in ($toCheck | Select-Object -First 50)) {
            $f = "createdDateTime ge $startStr and createdDateTime le $endStr and appId eq '$appId' and signInEventTypes/any(t: t eq 'servicePrincipal')"
            $rows = @(Invoke-SignInQuery -Filter $f -Label "CredChangedApp:$appId" -Max 5000)
            foreach ($r in $rows) { $signInCred.Add($r) }
            $public = @($rows | Where-Object { $_.IPClass -in @('Public', 'KnownMalicious', 'AttackerASN') })
            if ($public.Count -gt 0) {
                $ips = ($public | Group-Object IPAddress | ForEach-Object { '{0} (x{1})' -f $_.Name, $_.Count }) -join ', '
                Add-Finding -Severity Medium -Category 'SignIns' -Title ("App with a credential change signed in from public IPs: {0}" -f $public[0].AppDisplayName) `
                    -Detail ("AppId {0}. Source IPs: {1}. Credential types used: {2}." -f $appId, $ips, (($public.ClientCredentialType | Select-Object -Unique) -join ',')) `
                    -Recommendation 'Confirm these IPs belong to the app vendor or your own infrastructure. Unknown IPs right after a new secret was added indicate the planted credential is in use.'
            }
        }
    }

    if ($script:SignInBlocked) { Add-Coverage -Check 'Sign-in logs' -Status Unavailable -Note 'No Entra ID P1/P2 or access denied - see findings for the manual check' }
    else {
        Add-Coverage -Check 'Sign-in logs: vendor apps + attacker IPs' -Status Done -Note ("IPs: {0}; IP look-back from {1:yyyy-MM-dd}" -f ($AttackerIPs -join ', '), $AsnStartUtc)
        if ($SkipAsnHunt) { Add-Coverage -Check 'Sign-in logs: attacker ASN + all-app sweep' -Status Skipped -Note '-SkipAsnHunt' }
        else {
            $trunc = @($script:Truncated | Where-Object { $_ -like 'SignIns:*' })
            $noPrefixes = $script:AttackerPrefixes.Count -eq 0
            Add-Coverage -Check 'Sign-in logs: attacker network hunt' -Status $(if ($trunc -or $noPrefixes) { 'Partial' } else { 'Done' }) -Note ("AS{0} from {1:yyyy-MM-dd}; {2} prefix(es){3}; {4}" -f ($AttackerASNs -join ', AS'), $AsnStartUtc, $script:AttackerPrefixes.Count, $(if ($noPrefixes) { ' - app sign-ins NOT covered (' + $prefixNote.TrimEnd('; ') + ')' } else { '' }), $asnMode)
            Add-Coverage -Check 'Sign-in logs: all-app non-Microsoft sweep' -Status $(if ($sweepComplete) { 'Done' } else { 'Partial' }) -Note ("{0} sign-in(s) from {1} app(s)" -f $signInSweep.Count, @($signInSweep | Select-Object -ExpandProperty AppId -Unique).Count)
        }
    }
}
#endregion

#region ------------------------------ 6b. Credential usage ------------------------------
# Service-principal sign-ins record the KeyId of the secret/certificate used. This ties sign-ins to specific
# credentials: a credential created during the window that is actually being used, and credentials on
# Microsoft first-party apps (a known persistence technique) with their real usage.
$usageByKey = @{}
$usageKnown = ($null -ne $script:SpPullCache) -and -not $script:SignInBlocked
if ($usageKnown) {
    foreach ($r in $script:SpPullCache) {
        $k = [string]$r.CredentialKeyId
        if (-not $k) { continue }
        if (-not $usageByKey.ContainsKey($k)) { $usageByKey[$k] = [System.Collections.Generic.List[object]]::new() }
        $usageByKey[$k].Add($r)
    }
}
foreach ($c in $credRows) {
    $u = if ($usageKnown -and $c.KeyId) { $usageByKey[[string]$c.KeyId] } else { $null }
    $c | Add-Member -NotePropertyName SignInsSinceLookback -NotePropertyValue $(if (-not $usageKnown) { $null } elseif ($u) { $u.Count } else { 0 }) -Force
    $c | Add-Member -NotePropertyName LastUsedUtc -NotePropertyValue $(if ($u) { ($u | Measure-Object TimeUtc -Maximum).Maximum } else { $null }) -Force
    $c | Add-Member -NotePropertyName UsedFromIPs -NotePropertyValue $(if ($u) { (($u.IPAddress | Select-Object -Unique | Select-Object -First 10) -join ', ') } else { $null }) -Force
}

if ($usageKnown) {
    # A credential created during the window that is being used
    foreach ($grp in ($credRows | Where-Object { $_.AddedInWindow -and -not $_.MicrosoftManaged -and $_.SignInsSinceLookback -gt 0 } | Group-Object ObjectId, KeyId)) {
        $c = $grp.Group[0]
        $rows = $usageByKey[[string]$c.KeyId]
        $atk = @($rows | Where-Object { $_.IPClass -in 'KnownMalicious', 'AttackerASN' })
        Add-Finding -Severity $(if ($atk.Count -gt 0) { 'Critical' } else { 'High' }) -Category 'Credentials' `
            -Title ("Credential created during the window is in use: '{0}' (KeyId {1})" -f $c.DisplayName, $c.KeyId) `
            -Detail ("Created {0:yyyy-MM-dd HH:mm} UTC; {1} sign-in(s), last {2:yyyy-MM-dd HH:mm} UTC, from {3}.{4}" -f $c.StartUtc, $c.SignInsSinceLookback, $c.LastUsedUtc, $c.UsedFromIPs, $(if ($atk.Count) { " $($atk.Count) sign-in(s) from attacker infrastructure." } else { '' })) `
            -Recommendation 'Confirm with the app owner that this credential and these source IPs are theirs. If not, remove the credential and treat everything the app can access as exposed.'
    }
}

# Credentials on Microsoft first-party service principals (excluding Microsoft-managed rotations)
$fpCreds = @($credRows | Where-Object {
    $_.ObjectType -eq 'ServicePrincipal' -and -not $_.MicrosoftManaged -and $_.EndUtc -and $_.EndUtc -gt [datetime]::UtcNow -and
    $script:SpById.ContainsKey([string]$_.ObjectId) -and ($MicrosoftTenantIds -contains [string]$script:SpById[[string]$_.ObjectId].appOwnerOrganizationId)
})
foreach ($grp in ($fpCreds | Group-Object ObjectId)) {
    $first = $grp.Group[0]
    $creds = @($grp.Group | Group-Object KeyId | ForEach-Object { $_.Group[0] } | Sort-Object StartUtc)
    $lines = foreach ($c in $creds) {
        $use = if (-not $usageKnown) { 'usage unknown' } elseif ($c.SignInsSinceLookback -gt 0) { 'used {0}x, last {1:yyyy-MM-dd}, from {2}' -f $c.SignInsSinceLookback, $c.LastUsedUtc, $c.UsedFromIPs } else { 'NOT used since {0:yyyy-MM-dd}' -f $AsnStartUtc }
        '{0} {1} (created {2:yyyy-MM-dd}, expires {3:yyyy-MM-dd}): {4}' -f $c.CredentialType, $c.KeyId, $c.StartUtc, $c.EndUtc, $use
    }
    $unused = @($creds | Where-Object { $usageKnown -and $_.SignInsSinceLookback -eq 0 }).Count
    $inWin  = @($creds | Where-Object AddedInWindow).Count
    Add-Finding -Severity $(if ($inWin -gt 0) { 'High' } else { 'Medium' }) -Category 'Credentials' `
        -Title ("{0} active credential(s) on Microsoft first-party app '{1}'{2}" -f $creds.Count, $first.DisplayName, $(if ($unused) { " - $unused unused" } else { '' })) `
        -Detail (("AppId {0}. Anyone holding one of these can sign in as this Microsoft app in your tenant. " -f $first.AppId) + ($lines -join ' | ')) `
        -Recommendation 'Legitimate uses exist (e.g. the NPS extension or AD FS adapter on Azure Multi-Factor Auth Client, some identity vendors), but this is also a known persistence technique. Map each credential to an owner; remove unused and unexplained ones (Remove-MgServicePrincipalPassword / Remove-MgServicePrincipalKey).'
}
Add-Coverage -Check 'Credential usage (sign-in KeyId correlation)' -Status $(if ($usageKnown) { 'Done' } else { 'Skipped' }) `
    -Note $(if ($usageKnown) { "{0} distinct credential KeyId(s) in {1} of {2} service-principal sign-ins since {3:yyyy-MM-dd}. Multi-tenant (vendor) apps authenticate with credentials held in the publisher's tenant, so their sign-ins carry no KeyId from this tenant - expected." -f $usageByKey.Count, @($script:SpPullCache | Where-Object { $_.CredentialKeyId }).Count, @($script:SpPullCache).Count, $AsnStartUtc } else { 'Needs sign-in logs without -SkipAsnHunt' })
#endregion

#region ------------------------------ 7. Workload identity risk ------------------------------
Write-Step 7 'Workload identity risk (Entra ID Protection)'
$riskRows = [System.Collections.Generic.List[object]]::new()
try {
    foreach ($r in @(Invoke-GraphPaged -Uri 'https://graph.microsoft.com/v1.0/identityProtection/riskyServicePrincipals?$top=500')) {
        $riskRows.Add([pscustomobject]@{
            Source = 'RiskyServicePrincipal'; DisplayName = $r.displayName; AppId = $r.appId; ServicePrincipalId = $r.id
            RiskLevel = $r.riskLevel; RiskState = $r.riskState; RiskDetail = $r.riskDetail; TimeUtc = (ConvertTo-Utc $r.riskLastUpdatedDateTime)
            DetectionType = $null; IPAddress = $null
        })
    }
    $f = [uri]::EscapeDataString("activityDateTime ge $startStr")
    foreach ($d in @(Invoke-GraphPaged -Uri "https://graph.microsoft.com/v1.0/identityProtection/servicePrincipalRiskDetections?`$filter=$f&`$top=500")) {
        $riskRows.Add([pscustomobject]@{
            Source = 'RiskDetection'; DisplayName = $d.servicePrincipalDisplayName; AppId = $d.appId; ServicePrincipalId = $d.servicePrincipalId
            RiskLevel = $d.riskLevel; RiskState = $d.riskState; RiskDetail = $d.riskDetail; TimeUtc = (ConvertTo-Utc $d.activityDateTime)
            DetectionType = $d.riskEventType; IPAddress = $d.ipAddress
        })
    }
    foreach ($r in ($riskRows | Where-Object { $_.Source -eq 'RiskyServicePrincipal' -and $_.RiskState -in 'atRisk', 'confirmedCompromised' })) {
        $sev = if (Test-IsVendor $r.AppId $r.ServicePrincipalId '') { 'Critical' } else { 'High' }
        Add-Finding -Severity $sev -Category 'Risk' -Title ("Entra ID Protection flags service principal as {0}: {1}" -f $r.RiskState, $r.DisplayName) `
            -Detail ("AppId {0}, risk level {1}, detail {2}, updated {3:yyyy-MM-dd HH:mm} UTC." -f $r.AppId, $r.RiskLevel, $r.RiskDetail, $r.TimeUtc) `
            -Recommendation 'Review the risk detections (WorkloadIdentityRisk.csv), the app credentials and its sign-ins. Confirm compromise or dismiss in Entra ID Protection.'
    }
    foreach ($g in ($riskRows | Where-Object Source -eq 'RiskDetection' | Group-Object AppId)) {
        $first = $g.Group[0]
        Add-Finding -Severity High -Category 'Risk' -Title ("{0} workload identity risk detection(s) in window: {1}" -f $g.Count, $first.DisplayName) `
            -Detail ("AppId {0}. Types: {1}. IPs: {2}." -f $first.AppId, (($g.Group.DetectionType | Select-Object -Unique) -join ', '), (($g.Group.IPAddress | Where-Object { $_ } | Select-Object -Unique) -join ', ')) `
            -Recommendation 'Investigate the detections in Entra ID Protection > Risky workload identities.'
    }
    if ($riskRows.Count -eq 0) { Write-Host '    No risky service principals or detections.' }
    Add-Coverage -Check 'Workload identity risk' -Status Done -Note ("{0} record(s)" -f $riskRows.Count)
}
catch {
    $msg = "$($_.Exception.Message) $($_.ErrorDetails.Message)"
    Write-Host '    Risky workload identities not readable (needs Workload Identities Premium and IdentityRiskyServicePrincipal.Read.All).' -ForegroundColor Gray
    Add-Coverage -Check 'Workload identity risk' -Status Unavailable -Note 'Workload Identities Premium license or IdentityRiskyServicePrincipal.Read.All consent missing'
    Write-Verbose $msg
}
#endregion

#region ------------------------------ 8. Tenant configuration ------------------------------
Write-Step 8 'Tenant configuration (Conditional Access, domain federation, partner relationships)'

# 8a. Conditional Access policies that exclude the vendor apps
$caRows = [System.Collections.Generic.List[object]]::new()
try {
    foreach ($p in @(Invoke-GraphPaged -Uri 'https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies')) {
        $hitApps = @(@($p.conditions.applications.excludeApplications) | Where-Object { $_ -and $VendorAppIdSet.Contains([string]$_) })
        $hitSPs  = @(@($p.conditions.clientApplications.excludeServicePrincipals) | Where-Object { $_ -and $VendorSpIdSet.Contains([string]$_) })
        if ($hitApps.Count + $hitSPs.Count -gt 0) {
            $caRows.Add([pscustomobject]@{ Policy = $p.displayName; State = $p.state; ExcludedAppIds = ($hitApps -join ','); ExcludedServicePrincipals = ($hitSPs -join ',') })
            Add-Finding -Severity Medium -Category 'ConditionalAccess' -Title ("CA policy '{0}' excludes ConnectWise/SkyKick apps" -f $p.displayName) `
                -Detail ("State {0}. Excluded app IDs: {1}. Excluded service principals: {2}." -f $p.state, ($hitApps -join ','), ($hitSPs -join ',')) `
                -Recommendation 'Attacker infrastructure is not blocked by this policy for these apps. Review the exclusion once the apps are disabled.'
        }
    }
    if ($caRows.Count -eq 0) { Write-Host '    No policies exclude the vendor apps.' }
    Add-Coverage -Check 'Conditional Access exclusions' -Status Done
}
catch { Write-Warning "Could not read Conditional Access policies: $($_.Exception.Message)"; Add-Coverage -Check 'Conditional Access exclusions' -Status Failed -Note $_.Exception.Message }

# 8b. Federated domains: a Global Administrator can federate a domain to an attacker IdP (Golden SAML persistence)
$fedRows = [System.Collections.Generic.List[object]]::new()
try {
    $domains = @(Invoke-GraphPaged -Uri 'https://graph.microsoft.com/v1.0/domains?$select=id,authenticationType,isVerified')
    foreach ($d in ($domains | Where-Object { $_.authenticationType -eq 'Federated' })) {
        $cfgs = @()
        try { $cfgs = @((Invoke-GraphWithRetry -Uri ('https://graph.microsoft.com/v1.0/domains/{0}/federationConfiguration' -f [uri]::EscapeDataString($d.id))).value) }
        catch { Write-Warning ("Could not read federation configuration for {0}: {1}" -f $d.id, $_.Exception.Message) }
        if ($cfgs.Count -eq 0) { $cfgs = @($null) }
        foreach ($c in $cfgs) {
            $certInfo = @()
            foreach ($slot in 'signingCertificate', 'nextSigningCertificate') {
                $b64 = if ($c) { [string]$c.$slot } else { '' }
                if (-not $b64) { continue }
                try {
                    $x = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new([Convert]::FromBase64String($b64))
                    $certInfo += [pscustomobject]@{ Slot = $slot; Thumbprint = $x.Thumbprint; Subject = $x.Subject; NotBeforeUtc = $x.NotBefore.ToUniversalTime(); NotAfterUtc = $x.NotAfter.ToUniversalTime() }
                }
                catch { $certInfo += [pscustomobject]@{ Slot = $slot; Thumbprint = 'unparseable'; Subject = $null; NotBeforeUtc = $null; NotAfterUtc = $null } }
            }
            $row = [pscustomobject]@{
                Domain            = $d.id
                IssuerUri         = $(if ($c) { $c.issuerUri } else { $null })
                PassiveSignInUri  = $(if ($c) { $c.passiveSignInUri } else { $null })
                MfaBehavior       = $(if ($c) { $c.federatedIdpMfaBehavior } else { $null })
                SigningCerts      = (($certInfo | ForEach-Object { '{0}: {1} ({2}) {3:yyyy-MM-dd} -> {4:yyyy-MM-dd}' -f $_.Slot, $_.Thumbprint, $_.Subject, $_.NotBeforeUtc, $_.NotAfterUtc }) -join ' | ')
                CertIssuedInWindow = [bool]($certInfo | Where-Object { $_.NotBeforeUtc -and $_.NotBeforeUtc -ge $StartUtc -and $_.NotBeforeUtc -le $EndUtc })
            }
            $fedRows.Add($row)
            $sev = if ($row.CertIssuedInWindow) { 'High' } else { 'Medium' }
            Add-Finding -Severity $sev -Category 'Federation' -Title ("Domain '{0}' is federated{1}" -f $d.id, $(if ($row.CertIssuedInWindow) { ' - signing certificate issued during the window' } else { '' })) `
                -Detail ("Issuer {0}. Sign-in URL {1}. MFA behavior {2}. Certificates: {3}." -f $row.IssuerUri, $row.PassiveSignInUri, $row.MfaBehavior, $row.SigningCerts) `
                -Recommendation 'Confirm the issuer, sign-in URL and certificate thumbprints match your own IdP (e.g. Get-AdfsCertificate -CertificateType Token-Signing). A mismatch means anyone holding that certificate can sign in as any user in the domain.'
        }
    }
    if ($fedRows.Count -eq 0) { Write-Host ("    All {0} domain(s) are managed (not federated)." -f $domains.Count) }
    Add-Coverage -Check 'Domain federation' -Status Done -Note ("{0} domain(s), {1} federated" -f $domains.Count, $fedRows.Count)
}
catch { Write-Warning "Could not read domains: $($_.Exception.Message)"; Add-Coverage -Check 'Domain federation' -Status Failed -Note $_.Exception.Message }

# 8c. Partner relationships (partner/MSP tenants). In customer tenants, partner changes are covered by the audit log.
$gdapRows = [System.Collections.Generic.List[object]]::new()
if ($PartnerTenant) {
    try {
        foreach ($r in @(Invoke-GraphPaged -Uri 'https://graph.microsoft.com/v1.0/tenantRelationships/delegatedAdminRelationships?$top=300')) {
            $roles = @($r.accessDetails.unifiedRoles | ForEach-Object { $rn = $roleDefs[[string]$_.roleDefinitionId]; if ($rn) { $rn } else { [string]$_.roleDefinitionId } })
            $created = ConvertTo-Utc $r.createdDateTime; $modified = ConvertTo-Utc $r.lastModifiedDateTime
            $gdapRows.Add([pscustomobject]@{
                Relationship = $r.displayName; Id = $r.id; Status = $r.status
                CustomerTenantId = $r.customer.tenantId; Customer = $r.customer.displayName
                Roles = ($roles -join ', ')
                IncludesGlobalAdmin = [bool](@($r.accessDetails.unifiedRoles) | Where-Object { [string]$_.roleDefinitionId -eq $GlobalAdminRoleId })
                CreatedUtc = $created; LastModifiedUtc = $modified
                ChangedInWindow = [bool](($created -and $created -ge $StartUtc) -or ($modified -and $modified -ge $StartUtc))
            })
        }
        foreach ($r in ($gdapRows | Where-Object ChangedInWindow)) {
            Add-Finding -Severity High -Category 'Partner' -Title ("GDAP relationship created/changed during window: {0} ({1})" -f $r.Relationship, $r.Customer) `
                -Detail ("Status {0}. Roles: {1}. Created {2:yyyy-MM-dd HH:mm}, modified {3:yyyy-MM-dd HH:mm} UTC." -f $r.Status, $r.Roles, $r.CreatedUtc, $r.LastModifiedUtc) `
                -Recommendation 'Confirm the change in Partner Center. The ConnectWise Partner Center app was on the abused-app list.'
        }
        $gaRel = @($gdapRows | Where-Object { $_.IncludesGlobalAdmin -and $_.Status -eq 'active' })
        if ($gaRel.Count -gt 0) {
            Add-Finding -Severity Medium -Category 'Partner' -Title ("{0} active GDAP relationship(s) include Global Administrator" -f $gaRel.Count) `
                -Detail (($gaRel | Select-Object -First 25 | ForEach-Object { '{0} ({1})' -f $_.Relationship, $_.Customer }) -join '; ') `
                -Recommendation 'Reduce to least-privilege roles. A compromised partner credential or app inherits these rights in every customer tenant.'
        }
        Add-Coverage -Check 'GDAP relationships (partner)' -Status Done -Note ("{0} relationship(s)" -f $gdapRows.Count)
    }
    catch { Write-Warning "Could not read GDAP relationships: $($_.Exception.Message)"; Add-Coverage -Check 'GDAP relationships (partner)' -Status Failed -Note $_.Exception.Message }
    try {
        $dap = @(Invoke-GraphPaged -Uri 'https://graph.microsoft.com/v1.0/contracts?$top=999')
        if ($dap.Count -gt 0) {
            Add-Finding -Severity Medium -Category 'Partner' -Title ("{0} legacy DAP customer contract(s) present" -f $dap.Count) `
                -Detail 'Delegated Admin Privileges (DAP) grant Global Administrator-equivalent access to every customer.' `
                -Recommendation 'Transition remaining customers to GDAP and remove DAP.'
        }
    }
    catch { Write-Verbose "Could not read DAP contracts: $($_.Exception.Message)" }
}
else { Add-Coverage -Check 'GDAP relationships (partner)' -Status Skipped -Note 'Use -PartnerTenant in MSP/CSP tenants; customer-side partner changes are covered by the audit log' }
#endregion

#region ------------------------------ 9. Exchange Online (optional) ------------------------------
$exoEvents = [System.Collections.Generic.List[object]]::new()
$exoIpHits = [System.Collections.Generic.List[object]]::new()
$exoState  = [System.Collections.Generic.List[object]]::new()

$ExoOps = @(
    'New-InboxRule', 'Set-InboxRule', 'UpdateInboxRules', 'Set-Mailbox', 'Add-MailboxPermission', 'Add-RecipientPermission',
    'Add-MailboxFolderPermission', 'New-TransportRule', 'Set-TransportRule', 'Enable-TransportRule',
    'New-ManagementRoleAssignment', 'New-ServicePrincipal', 'New-ApplicationAccessPolicy', 'Remove-ApplicationAccessPolicy',
    'New-RoleGroup', 'Add-RoleGroupMember', 'New-InboundConnector', 'Set-InboundConnector', 'New-OutboundConnector',
    'Set-OutboundConnector', 'Set-RemoteDomain', 'Set-HostedOutboundSpamFilterPolicy', 'Set-AdminAuditLogConfig',
    'Set-OrganizationConfig', 'SiteCollectionAdminAdded', 'SharingPolicyChanged'
)

function Search-UALAll([hashtable]$P, [string]$Label, [int]$Cap = 50000) {
    $sid = [guid]::NewGuid().ToString()
    $all = [System.Collections.Generic.List[object]]::new()
    for ($i = 0; $i -lt 200; $i++) {
        $batch = @(Search-UnifiedAuditLog @P -SessionId $sid -SessionCommand ReturnLargeSet -ResultSize 5000 -ErrorAction Stop)
        if ($batch.Count -eq 0) { break }
        foreach ($b in $batch) { $all.Add($b) }
        $total = [int]$batch[0].ResultCount
        if (($total -gt 0 -and $all.Count -ge $total) -or ($total -le 0 -and $batch.Count -lt 5000)) { break }
        if ($all.Count -ge $Cap) { $script:Truncated.Add(("UAL:{0} (cap {1})" -f $Label, $Cap)); break }
    }
    return $all
}

function Get-UalIp($D) {
    $ip = [string]$D.ClientIP
    if (-not $ip) { $ip = [string]$D.ClientIPAddress }
    if ($ip -match '^\[(.+)\](:\d+)?$') { return $Matches[1] }
    if ($ip -match '^(\d{1,3}(\.\d{1,3}){3}):\d+$') { return $Matches[1] }
    return $ip
}

if (-not $IncludeExchange) {
    Write-Step 9 'Exchange Online (skipped - use -IncludeExchange)'
    Add-Coverage -Check 'Exchange Online / Unified Audit Log' -Status Skipped -Note 'Use -IncludeExchange: inbox rules, forwarding, transport rules, Exchange RBAC for apps and attacker-IP activity are not covered otherwise'
}
elseif (-not $exchangeAvailable) {
    Write-Step 9 'Exchange Online (ExchangeOnlineManagement module missing)'
    Add-Coverage -Check 'Exchange Online / Unified Audit Log' -Status Unavailable -Note 'Install-Module ExchangeOnlineManagement -Scope CurrentUser'
}
else {
    Write-Step 9 'Exchange Online and Unified Audit Log'
    $exoConnected = $false
    try {
        Import-Module ExchangeOnlineManagement -ErrorAction Stop
        $exoParams = @{ ShowBanner = $false; ErrorAction = 'Stop' }
        if ($ExchangeDelegatedOrganization) { $exoParams.DelegatedOrganization = $ExchangeDelegatedOrganization }
        if ($UseDeviceCode) { $exoParams.Device = $true } elseif ($ctx.Account) { $exoParams.UserPrincipalName = $ctx.Account }
        Connect-ExchangeOnline @exoParams
        $exoConnected = $true
    }
    catch {
        Add-Finding -Severity Medium -Category 'Exchange' -Title 'Could not connect to Exchange Online' -Detail $_.Exception.Message `
            -Recommendation 'Check the ExchangeOnlineManagement module and that the account holds View-Only Organization Management and View-Only Audit Logs.'
        Add-Coverage -Check 'Exchange Online / Unified Audit Log' -Status Failed -Note $_.Exception.Message
    }

    if ($exoConnected) {
        try {
            $acceptedDomains = @()
            try { $acceptedDomains = @(Get-AcceptedDomain | ForEach-Object { [string]$_.DomainName }) } catch { }
            $isExternal = { param([string]$addr) $dom = ($addr -replace '^(smtp|SMTP):', '' -split '@')[-1]; return ($dom -and $acceptedDomains -notcontains $dom) }
            $ualStart = $StartUtc.AddDays(-1)   # one day of slack: the cmdlet's time-zone handling varies by session

            # 9a. Is the Unified Audit Log on at all?
            try {
                $alc = Get-AdminAuditLogConfig
                if ($alc.UnifiedAuditLogIngestionEnabled -eq $false) {
                    Add-Finding -Severity High -Category 'Exchange' -Title 'Unified Audit Log ingestion is DISABLED' -Detail 'Mailbox, SharePoint and admin activity is not being recorded.' `
                        -Recommendation 'Enable it now (Set-AdminAuditLogConfig -UnifiedAuditLogIngestionEnabled $true) and check the Entra audit log for who disabled it.'
                }
            }
            catch { Write-Verbose "Get-AdminAuditLogConfig failed: $($_.Exception.Message)" }

            # 9b. Persistence-relevant admin and mailbox operations in the window
            $ualStatus = 'Done'
            try {
                $records = Search-UALAll -P @{ StartDate = $ualStart; EndDate = $EndUtc; Operations = $ExoOps } -Label 'PersistenceOps'
                foreach ($rec in $records) {
                    $d = $null; try { $d = $rec.AuditData | ConvertFrom-Json } catch { continue }
                    $op = [string]$d.Operation
                    $ip = Get-UalIp $d
                    $appId = [string]$d.AppId; if (-not $appId) { $appId = [string]$d.ClientAppId }
                    $paramText = (@($d.Parameters) | Where-Object { $_ } | ForEach-Object { '{0}={1}' -f $_.Name, $_.Value }) -join '; '
                    if (-not $paramText -and $d.OperationProperties) { $paramText = (@($d.OperationProperties) | ForEach-Object { '{0}={1}' -f $_.Name, $_.Value }) -join '; ' }
                    $isAppInit = ([string]$d.UserId -like 'ServicePrincipal_*') -or ([string]$d.UserType -in '5', '6', 'Application', 'ServicePrincipal') -or ($appId -and -not $d.UserKey)
                    $isVendor  = ($appId -and $VendorAppIdSet.Contains($appId)) -or [bool]($VendorAppIdSet | Where-Object { [string]$d.UserId -like "*$_*" })
                    $fromAtk   = $ip -and ($AttackerIPs -contains $ip -or $script:ObservedAttackerIPs.Contains($ip))
                    $forwards  = $paramText -match '(ForwardTo|RedirectTo|ForwardAsAttachmentTo|ForwardingSmtpAddress|ForwardingAddress|DeliverToMailboxAndForward|BlindCopyTo|RedirectMessageTo|CopyTo|AddToRecipients)='
                    $hides     = $paramText -match 'DeleteMessage=True|MoveToFolder=.*(RSS|Archive|Conversation History|Junk)|MarkAsRead=True|SoftDeleteMessage=True'

                    $sev = $null; $why = [System.Collections.Generic.List[string]]::new()
                    $up = { param($s, $w) $why.Add($w); if (-not $sev -or $sevRank[$s] -gt $sevRank[$sev]) { Set-Variable -Name sev -Value $s -Scope 1 } }
                    if ($fromAtk)  { & $up 'Critical' "performed from attacker infrastructure ($ip)" }
                    if ($isVendor) { & $up 'Critical' 'performed by a ConnectWise/SkyKick application' }
                    switch -Wildcard ($op) {
                        '*InboxRule*'                    { if ($forwards) { & $up 'High' 'inbox rule forwards/redirects mail' }; if ($hides) { & $up 'High' 'inbox rule deletes / hides mail' } }
                        'Set-Mailbox'                    { if ($forwards) { & $up 'High' 'mailbox forwarding set' } }
                        '*TransportRule'                 { if ($forwards) { & $up 'High' 'transport rule redirects / copies mail' } else { & $up 'Medium' 'transport rule changed' } }
                        '*Connector'                     { & $up 'High' 'mail connector created/changed' }
                        'Set-AdminAuditLogConfig'        { & $up 'High' 'audit configuration changed' }
                        { $_ -in 'New-ManagementRoleAssignment', 'New-ServicePrincipal', 'New-ApplicationAccessPolicy', 'Remove-ApplicationAccessPolicy', 'New-RoleGroup', 'Add-RoleGroupMember' } {
                            if ($isAppInit) { & $up 'High' 'Exchange RBAC changed by an application' } else { & $up 'Medium' 'Exchange RBAC / app access changed' } }
                        { $_ -in 'Add-MailboxPermission', 'Add-RecipientPermission' } { if ($isAppInit) { & $up 'High' 'mailbox permission granted by an application' } else { & $up 'Medium' 'mailbox permission granted' } }
                        { $_ -in 'Set-RemoteDomain', 'Set-HostedOutboundSpamFilterPolicy' } { if ($paramText -match 'AutoForward') { & $up 'High' 'external auto-forwarding setting changed' } }
                        'SiteCollectionAdminAdded'       { if ($isAppInit) { & $up 'High' 'site collection admin added by an application' } else { & $up 'Medium' 'site collection admin added' } }
                    }
                    if ($isAppInit -and -not $sev -and $op -notin 'UpdateInboxRules') { & $up 'Medium' 'performed by an application' }

                    $row = [pscustomobject]@{
                        TimeUtc = (ConvertTo-Utc $d.CreationTime); Operation = $op; UserId = $d.UserId; AppId = $appId; ClientIP = $ip
                        ObjectId = $d.ObjectId; Result = $d.ResultStatus; Parameters = $paramText; Severity = $sev; Flags = ($why -join '; ')
                    }
                    $exoEvents.Add($row)
                    if ($sev) {
                        Add-Finding -Severity $sev -Category 'Exchange' -Title ("{0} by '{1}' on '{2}' at {3:yyyy-MM-dd HH:mm} UTC" -f $op, $d.UserId, $d.ObjectId, $row.TimeUtc) `
                            -Detail ("Why: {0}. IP {1}. AppId {2}. Parameters: {3}" -f $row.Flags, $ip, $appId, $(if ($paramText.Length -gt 600) { $paramText.Substring(0, 600) + ' ...' } else { $paramText })) `
                            -Recommendation 'Validate with the mailbox owner / Exchange admins. If not expected: remove the rule, forwarding, permission or role assignment, and review what the actor accessed (MailItemsAccessed).'
                    }
                }
                Write-Host ("    {0} persistence-relevant UAL record(s) since {1:yyyy-MM-dd}" -f $exoEvents.Count, $ualStart)
            }
            catch {
                $ualStatus = 'Failed'
                Add-Finding -Severity Medium -Category 'Exchange' -Title 'Unified Audit Log search failed' -Detail $_.Exception.Message `
                    -Recommendation 'Assign View-Only Audit Logs (Exchange) or Audit Reader (Purview) and rerun, or search in the Purview portal.'
            }

            # 9c. Everything any attacker address did, all workloads (mail read, file download, admin)
            $ipList = @(@($AttackerIPs) + @($script:ObservedAttackerIPs) | Where-Object { $_ } | Select-Object -Unique)
            if ($ualStatus -ne 'Failed' -and $ipList.Count -gt 0) {
                try {
                    for ($i = 0; $i -lt $ipList.Count; $i += 50) {
                        $chunk = $ipList[$i..([math]::Min($i + 49, $ipList.Count - 1))]
                        $since = if ($AsnStartUtc -lt $ualStart) { $AsnStartUtc } else { $ualStart }
                        foreach ($rec in (Search-UALAll -P @{ StartDate = $since; EndDate = $EndUtc; IPAddresses = $chunk } -Label 'AttackerIPs')) {
                            $d = $null; try { $d = $rec.AuditData | ConvertFrom-Json } catch { continue }
                            $exoIpHits.Add([pscustomobject]@{
                                TimeUtc = (ConvertTo-Utc $d.CreationTime); Workload = $d.Workload; Operation = $d.Operation; UserId = $d.UserId
                                AppId = $(if ($d.AppId) { $d.AppId } else { $d.ClientAppId }); ClientIP = (Get-UalIp $d); ObjectId = $d.ObjectId; Result = $d.ResultStatus
                            })
                        }
                    }
                    foreach ($g in ($exoIpHits | Group-Object UserId)) {
                        $ops = ($g.Group | Group-Object Operation | Sort-Object Count -Descending | ForEach-Object { '{0} x{1}' -f $_.Name, $_.Count }) -join ', '
                        Add-Finding -Severity Critical -Category 'Exchange' -Title ("{0} M365 audit record(s) from attacker infrastructure for '{1}'" -f $g.Count, $g.Name) `
                            -Detail ("Operations: {0}. IPs: {1}. First {2:yyyy-MM-dd HH:mm}, last {3:yyyy-MM-dd HH:mm} UTC." -f $ops, (($g.Group.ClientIP | Select-Object -Unique) -join ', '), ($g.Group | Measure-Object TimeUtc -Minimum).Minimum, ($g.Group | Measure-Object TimeUtc -Maximum).Maximum) `
                            -Recommendation 'Data access from attacker infrastructure is confirmed for this identity. Scope what was read/downloaded (UAL-AttackerIP.csv) and start breach-notification assessment.'
                    }
                    if ($exoIpHits.Count -eq 0) { Write-Host ("    No UAL activity from {0} attacker address(es)." -f $ipList.Count) }
                }
                catch { Write-Warning "UAL search by IP failed: $($_.Exception.Message)"; $ualStatus = 'Partial' }
            }

            # 9d. Current state: forwarding, transport rules, connectors, Exchange RBAC for applications
            $stateStatus = 'Done'
            try {
                foreach ($m in @(Get-EXOMailbox -ResultSize Unlimited -Properties ForwardingSmtpAddress, ForwardingAddress, DeliverToMailboxAndForward -Filter 'ForwardingSmtpAddress -ne $null -or ForwardingAddress -ne $null')) {
                    $target = if ($m.ForwardingSmtpAddress) { [string]$m.ForwardingSmtpAddress } else { [string]$m.ForwardingAddress }
                    $ext = $m.ForwardingSmtpAddress -and (& $isExternal ([string]$m.ForwardingSmtpAddress))
                    $exoState.Add([pscustomobject]@{ Type = 'MailboxForwarding'; Name = $m.UserPrincipalName; Detail = "Forwards to $target (keep copy: $($m.DeliverToMailboxAndForward))"; ChangedUtc = $null; External = $ext })
                    Add-Finding -Severity $(if ($ext) { 'High' } else { 'Medium' }) -Category 'Exchange' -Title ("Mailbox forwarding on '{0}' to {1}" -f $m.UserPrincipalName, $target) `
                        -Detail ("External: {0}. Keep a copy: {1}." -f $ext, $m.DeliverToMailboxAndForward) -Recommendation 'Confirm with the mailbox owner; remove if not expected.'
                }
            }
            catch { Write-Warning "Mailbox forwarding check failed: $($_.Exception.Message)"; $stateStatus = 'Partial' }
            try {
                foreach ($r in @(Get-TransportRule)) {
                    $redir = @($r.RedirectMessageTo) + @($r.BlindCopyTo) + @($r.CopyTo) + @($r.AddToRecipients) | Where-Object { $_ }
                    $changed = if ($r.WhenChanged) { ([datetime]$r.WhenChanged).ToUniversalTime() } else { $null }
                    $inWin = $changed -and $changed -ge $StartUtc
                    if ($redir -or $inWin) {
                        $exoState.Add([pscustomobject]@{ Type = 'TransportRule'; Name = $r.Name; Detail = ("State {0}; recipients added/redirected: {1}" -f $r.State, ($redir -join ', ')); ChangedUtc = $changed; External = $null })
                        Add-Finding -Severity $(if ($inWin) { 'High' } else { 'Medium' }) -Category 'Exchange' -Title ("Transport rule '{0}'{1}" -f $r.Name, $(if ($inWin) { ' changed during window' } else { ' copies or redirects mail' })) `
                            -Detail ("State {0}. Redirect/BCC/CC/added recipients: {1}. Last changed {2:yyyy-MM-dd HH:mm} UTC." -f $r.State, $(if ($redir) { $redir -join ', ' } else { 'none' }), $changed) `
                            -Recommendation 'Confirm the rule with the mail admins; disable it if unknown.'
                    }
                }
            }
            catch { Write-Warning "Transport rule check failed: $($_.Exception.Message)"; $stateStatus = 'Partial' }
            try {
                foreach ($c in @(@(Get-InboundConnector) + @(Get-OutboundConnector) | Where-Object { $_ })) {
                    $changed = if ($c.WhenChanged) { ([datetime]$c.WhenChanged).ToUniversalTime() } else { $null }
                    if ($changed -and $changed -ge $StartUtc) {
                        $exoState.Add([pscustomobject]@{ Type = 'Connector'; Name = $c.Name; Detail = ("Enabled {0}" -f $c.Enabled); ChangedUtc = $changed; External = $null })
                        Add-Finding -Severity High -Category 'Exchange' -Title ("Mail connector '{0}' created/changed during window" -f $c.Name) `
                            -Detail ("Changed {0:yyyy-MM-dd HH:mm} UTC. Enabled {1}." -f $changed, $c.Enabled) -Recommendation 'Confirm with the mail admins; a rogue connector can relay or intercept mail.'
                    }
                }
            }
            catch { Write-Verbose "Connector check failed: $($_.Exception.Message)" }
            try {
                foreach ($sp in @(Get-ServicePrincipal)) {
                    $assignments = @(Get-ManagementRoleAssignment -RoleAssignee ([string]$sp.Identity) -ErrorAction SilentlyContinue)
                    foreach ($a in $assignments) {
                        $created = if ($a.WhenCreated) { ([datetime]$a.WhenCreated).ToUniversalTime() } else { $null }
                        $vendor = $VendorAppIdSet.Contains([string]$sp.AppId)
                        $inWin = $created -and $created -ge $StartUtc
                        $exoState.Add([pscustomobject]@{ Type = 'ExchangeAppRBAC'; Name = $sp.DisplayName; Detail = ("AppId {0}; role {1}; scope {2}" -f $sp.AppId, $a.Role, $a.CustomResourceScope); ChangedUtc = $created; External = $null })
                        $sev = if ($vendor -and $inWin) { 'Critical' } elseif ($vendor -or $inWin) { 'High' } else { 'Medium' }
                        Add-Finding -Severity $sev -Category 'Exchange' -Title ("Exchange RBAC role '{0}' assigned to app '{1}'" -f $a.Role, $sp.DisplayName) `
                            -Detail ("AppId {0}. Scope {1}. Created {2:yyyy-MM-dd HH:mm} UTC. Exchange RBAC for applications grants mailbox access that is not visible in Entra." -f $sp.AppId, $a.CustomResourceScope, $created) `
                            -Recommendation 'Confirm the assignment is intended; remove it otherwise (Remove-ManagementRoleAssignment).'
                    }
                }
            }
            catch { Write-Verbose "Exchange RBAC for applications check failed: $($_.Exception.Message)" }
            try {
                $rd = Get-RemoteDomain -Identity Default
                $ob = @(Get-HostedOutboundSpamFilterPolicy | Where-Object { [string]$_.AutoForwardingMode -eq 'On' })
                if ($rd.AutoForwardEnabled -and $ob.Count -gt 0) {
                    Add-Finding -Severity Medium -Category 'Exchange' -Title 'External automatic forwarding is allowed' -Detail ("Outbound policies with AutoForwardingMode On: {0}." -f (($ob.Name) -join ', ')) `
                        -Recommendation 'Set AutoForwardingMode to Off (or Automatic) unless forwarding is a business requirement.'
                }
            }
            catch { Write-Verbose "Auto-forward settings check failed: $($_.Exception.Message)" }

            # 9e. Optional: inbox rules on every mailbox (no creation timestamps - review the content)
            if ($IncludeInboxRules) {
                $mbx = @(Get-EXOMailbox -ResultSize Unlimited -RecipientTypeDetails UserMailbox, SharedMailbox)
                Write-Host ("    Reading inbox rules of {0} mailbox(es)..." -f $mbx.Count)
                foreach ($m in $mbx) {
                    try {
                        foreach ($r in @(Get-InboxRule -Mailbox ([string]$m.UserPrincipalName) -ErrorAction Stop)) {
                            $fw = @(@($r.ForwardTo) + @($r.RedirectTo) + @($r.ForwardAsAttachmentTo) | Where-Object { $_ })
                            $hide = $r.DeleteMessage -or $r.SoftDeleteMessage -or ([string]$r.MoveToFolder -match 'RSS|Archive|Conversation History|Junk')
                            if (-not $fw -and -not $hide) { continue }
                            $exoState.Add([pscustomobject]@{ Type = 'InboxRule'; Name = ("{0}: {1}" -f $m.UserPrincipalName, $r.Name); Detail = ("Enabled {0}; forward {1}; move {2}; delete {3}" -f $r.Enabled, ($fw -join ', '), $r.MoveToFolder, $r.DeleteMessage); ChangedUtc = $null; External = $null })
                            Add-Finding -Severity $(if ($fw) { 'High' } else { 'Medium' }) -Category 'Exchange' -Title ("Inbox rule '{0}' on {1} {2}" -f $r.Name, $m.UserPrincipalName, $(if ($fw) { 'forwards mail' } else { 'hides mail' })) `
                                -Detail ("Enabled {0}. Forward/redirect: {1}. Move to: {2}. Delete: {3}." -f $r.Enabled, ($fw -join ', '), $r.MoveToFolder, $r.DeleteMessage) `
                                -Recommendation 'Confirm with the mailbox owner; remove the rule and reset the account if not theirs.'
                        }
                    }
                    catch { Write-Verbose ("Get-InboxRule failed for {0}: {1}" -f $m.UserPrincipalName, $_.Exception.Message) }
                }
            }

            Add-Coverage -Check 'Exchange: UAL persistence operations + attacker IPs' -Status $ualStatus -Note ("{0} event(s); {1} record(s) from {2} attacker address(es)" -f $exoEvents.Count, $exoIpHits.Count, $ipList.Count)
            Add-Coverage -Check 'Exchange: current configuration' -Status $stateStatus -Note ("forwarding, transport rules, connectors, app RBAC{0}" -f $(if ($IncludeInboxRules) { ', inbox rules' } else { ' (inbox rules: use -IncludeInboxRules)' }))
        }
        finally { try { Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue | Out-Null } catch { } }
    }
}
#endregion

#region ------------------------------ 10. Optional remediation + report ------------------------------
Write-Step 10 'Remediation (optional) and report'
$remediated = [System.Collections.Generic.List[object]]::new()
if ($DisableVendorApps) {
    foreach ($sp in ($vendorSPs | Where-Object accountEnabled)) {
        if ($PSCmdlet.ShouldProcess(("{0} [{1}]" -f $sp.displayName, $sp.appId), 'Disable service principal sign-in (accountEnabled = false)')) {
            try {
                Invoke-GraphWithRetry -Method PATCH -Uri ('https://graph.microsoft.com/v1.0/servicePrincipals/{0}' -f $sp.id) -Body @{ accountEnabled = $false } | Out-Null
                Write-Host ("    Disabled {0}" -f $sp.displayName) -ForegroundColor Green
                $remediated.Add([pscustomobject]@{ DisplayName = $sp.displayName; AppId = $sp.appId; ObjectId = $sp.id; Action = 'Disabled'; TimeUtc = [datetime]::UtcNow })
            }
            catch { Write-Warning ("Failed to disable {0}: {1}" -f $sp.displayName, $_.Exception.Message) }
        }
    }
}

# Things this script cannot see, stated explicitly so a clean report is read correctly
Add-Finding -Severity Info -Category 'Coverage' -Title 'Microsoft Graph reads by applications are not in the Entra audit log' `
    -Detail 'Directory, mail and file reads through Microsoft Graph by an app leave no trace in the audit log. Only Microsoft Graph activity logs record them, and only if they were already streamed to Log Analytics / Sentinel / a storage account before the incident.' `
    -Recommendation 'If MicrosoftGraphActivityLogs exist for this tenant, run the queries in hunting\sentinel-hunting.kql. If not, enable them now (Entra admin center > Diagnostic settings) for future visibility.'
foreach ($t in ($script:Truncated | Select-Object -Unique)) {
    Add-Finding -Severity Medium -Category 'Coverage' -Title ("Query hit its result cap - results incomplete: {0}" -f $t) `
        -Detail 'The query returned more records than the cap, so later records were not analysed.' `
        -Recommendation 'Rerun with a higher -MaxSignIns or a narrower window, or run the equivalent query in Sentinel / Log Analytics (hunting\sentinel-hunting.kql).'
}

$files = @(
    Export-Data $vendorRows   'VendorServicePrincipals'
    Export-Data $roleRows     'ServicePrincipalRoles'
    Export-Data $credRows     'AppCredentials'
    Export-Data $ficRows      'FederatedIdentityCredentials'
    Export-Data $permRows     'AppPermissions'
    Export-Data $auditRows    'AuditEvents'
    Export-Data $signInVendor 'SignIns-VendorApps'
    Export-Data $signInIp     'SignIns-AttackerIP'
    Export-Data $signInAsn    'SignIns-AttackerASN'
    Export-Data $signInSweep  'SignIns-AllAppsNonMicrosoft'
    Export-Data $signInCred   'SignIns-CredentialChangedApps'
    Export-Data $riskRows     'WorkloadIdentityRisk'
    Export-Data $caRows       'ConditionalAccessExclusions'
    Export-Data $fedRows      'FederatedDomains'
    Export-Data $gdapRows     'GDAPRelationships'
    Export-Data $exoEvents    'UAL-PersistenceOps'
    Export-Data $exoIpHits    'UAL-AttackerIP'
    Export-Data $exoState     'Exchange-Configuration'
    Export-Data $script:Coverage 'Coverage'
    Export-Data $remediated   'Remediation'
) | Where-Object { $_ }

$sevOrder = @{ Critical = 0; High = 1; Medium = 2; Info = 3 }
$sorted = @($script:Findings | Sort-Object @{ Expression = { $sevOrder[$_.Severity] } }, Category, Title)
$files += Export-Data $sorted 'Findings'
$sorted | ConvertTo-Json -Depth 4 | Set-Content -Path (Join-Path $OutputPath 'Findings.json') -Encoding UTF8

$counts = foreach ($s in 'Critical', 'High', 'Medium', 'Info') { [pscustomobject]@{ Severity = $s; Count = @($sorted | Where-Object Severity -eq $s).Count } }
$css = @'
<style>
body{font-family:Segoe UI,Arial,sans-serif;margin:24px;color:#222}
table{border-collapse:collapse;width:100%;margin-bottom:24px}
th,td{border:1px solid #ccc;padding:6px 8px;vertical-align:top;font-size:13px;text-align:left}
th{background:#1f2937;color:#fff}
</style>
'@
$pre = @"
<h1>ConnectWise / SkyKick vendor-credential IOC check (v$ScriptVersion)</h1>
<p><b>Tenant:</b> $([Net.WebUtility]::HtmlEncode($org.displayName)) ($($org.id))<br>
<b>Run by:</b> $([Net.WebUtility]::HtmlEncode($ctx.Account)) at $([datetime]::UtcNow.ToString('yyyy-MM-dd HH:mm')) UTC<br>
<b>Window:</b> $startStr to $endStr<br>
<b>Attacker IPs:</b> $([Net.WebUtility]::HtmlEncode(($AttackerIPs -join ', ')))$(if ($script:ObservedAttackerIPs.Count) { ' + observed: ' + [Net.WebUtility]::HtmlEncode((@($script:ObservedAttackerIPs) -join ', ')) })<br>
<b>Attacker ASNs:</b> AS$($AttackerASNs -join ', AS') (look-back from $asnStartStr)<br>
<b>Reference:</b> https://www.huntress.com/blog/vendor-credential-enables-unauthorized-access</p>
<p>A clean result does not prove the tenant was not accessed: Graph reads by an application are not audited.</p>
$(($counts | ConvertTo-Html -Fragment) -join "`n")
<h2>Coverage</h2>
<p>What was and was not checked in this run. Anything other than <i>Done</i> limits what a clean result means.</p>
$(($script:Coverage | ConvertTo-Html -Fragment -Property Check, Status, Note) -join "`n")
<h2>Findings</h2>
"@
$html = ($sorted | ConvertTo-Html -Head $css -PreContent $pre -Property Severity, Category, Title, Detail, Recommendation -Title 'CW/SkyKick IOC check') -join "`n"
$html = $html -replace '<td>Critical</td>', '<td style="background:#b91c1c;color:#fff;font-weight:bold">Critical</td>' `
              -replace '<td>High</td>', '<td style="background:#c2410c;color:#fff;font-weight:bold">High</td>' `
              -replace '<td>Medium</td>', '<td style="background:#facc15">Medium</td>' `
              -replace '<td>(Skipped|Unavailable|Failed|Partial)</td>', '<td style="background:#fde68a;font-weight:bold">$1</td>'
$htmlPath = Join-Path $OutputPath 'Report.html'
$html | Set-Content -Path $htmlPath -Encoding UTF8

Write-Host ''
Write-Host '==================== SUMMARY ====================' -ForegroundColor White
foreach ($c in $counts) {
    $color = switch ($c.Severity) { 'Critical' { 'Red' } 'High' { 'Magenta' } 'Medium' { 'Yellow' } default { 'Gray' } }
    Write-Host ('  {0,-9} {1}' -f $c.Severity, $c.Count) -ForegroundColor $color
}
Write-Host ("  Report: {0}" -f $htmlPath)
Write-Host ("  Output: {0}" -f $OutputPath)
if (@($sorted | Where-Object { $_.Severity -in 'Critical', 'High' }).Count -gt 0) {
    Write-Host '  Critical/High findings present - review Report.html and engage incident response.' -ForegroundColor Red
}

$gaps = @($script:Coverage | Where-Object { $_.Status -ne 'Done' })
if ($gaps.Count -gt 0) {
    Write-Host ("  Coverage gaps: {0}" -f (($gaps | ForEach-Object { '{0} ({1})' -f $_.Check, $_.Status }) -join '; ')) -ForegroundColor Yellow
}

Disconnect-MgGraph | Out-Null
#endregion
