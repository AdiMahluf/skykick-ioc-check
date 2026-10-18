#Requires -Version 5.1
<#
.SYNOPSIS
    Read-only Entra ID / Microsoft 365 compromise check for the ConnectWise Cloud Backup (SkyKick) /
    ConnectWise Cloud Management vendor-credential incident (Huntress advisory, October 2026).

.DESCRIPTION
    Connects to Microsoft Graph with delegated, read-only permissions and checks the tenant for the
    indicators and persistence techniques described by Huntress:

      1. ConnectWise / SkyKick service principals in the tenant, and whether they are still enabled
      2. Directory roles held by service principals (ConnectWise apps and any other app), active and PIM-eligible
      3. Client secrets / certificates on ALL app registrations and service principals created since -StartDate
      4. Entra audit log: apps adding themselves to roles, apps changing other apps' credentials,
         suspicious user agents (Python-urllib, python-requests, curl)
      5. Sign-in logs: ConnectWise app service-principal sign-ins from non-Azure IPs, any sign-in
         (interactive, non-interactive, service principal) from 144.172.64.128, and sign-ins of apps
         whose credentials changed during the window
      6. Conditional Access policies that exclude the ConnectWise apps

    Nothing is changed unless -DisableVendorApps is used (extra permission + confirmation prompt).
    Results are written as CSV files plus an HTML report to -OutputPath.

.PARAMETER TenantId
    Tenant ID or primary domain. Optional; defaults to the home tenant of the signed-in account.

.PARAMETER StartDate
    Start of the review window, interpreted as UTC. Default 2026-10-13 00:00 UTC.

.PARAMETER EndDate
    End of the review window, interpreted as UTC. Default: now.

.PARAMETER OutputPath
    Folder for the CSV/HTML output. Default: .\CW-SkyKick-IOC-<timestamp>

.PARAMETER SkipSignInLogs
    Skip sign-in log queries (useful on tenants without Entra ID P1/P2, or for a fast run).

.PARAMETER DisableVendorApps
    After the assessment, disable (NOT delete) any enabled ConnectWise/SkyKick service principals.
    Requests Application.ReadWrite.All and prompts for confirmation per app.

.PARAMETER UseDeviceCode
    Use device-code sign-in (for hosts without a browser).

.EXAMPLE
    .\Invoke-CWSkyKickIOCCheck.ps1

.EXAMPLE
    .\Invoke-CWSkyKickIOCCheck.ps1 -TenantId contoso.onmicrosoft.com -OutputPath C:\IR\contoso

.EXAMPLE
    .\Invoke-CWSkyKickIOCCheck.ps1 -DisableVendorApps

.NOTES
    Version : 1.1.0 (2026-10-18)
    Project : Community tool - not affiliated with Huntress, ConnectWise or Microsoft.
    Requires the Microsoft.Graph.Authentication module:
        Install-Module Microsoft.Graph.Authentication -Scope CurrentUser
    Reference: https://www.huntress.com/blog/vendor-credential-enables-unauthorized-access

    A clean result does NOT prove the tenant was not accessed: Microsoft Graph reads performed by an
    application are not recorded in the Entra audit log.
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [string]$TenantId,
    [datetime]$StartDate = [datetime]::new(2026, 10, 13, 0, 0, 0, [System.DateTimeKind]::Utc),
    [datetime]$EndDate = [datetime]::UtcNow,
    [string]$OutputPath = (Join-Path -Path (Get-Location).Path -ChildPath ('CW-SkyKick-IOC-' + (Get-Date -Format 'yyyyMMdd-HHmmss'))),
    [switch]$SkipSignInLogs,
    [switch]$DisableVendorApps,
    [switch]$UseDeviceCode
)

$ScriptVersion = '1.1.0'
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
$AttackerIPs         = @('144.172.64.128')                       # AS14956 RouterHosting
$SuspiciousUAs       = @('Python-urllib', 'python-requests', 'curl/')
$UlaPrefixOfInterest = 'fde4:8dba:2600:37ce:6d26:200:a76:'       # Azure-internal ULA seen on the persistence activity (also used legitimately)
$HuntressWindowStart = [datetime]::new(2026, 10, 15, 1, 0, 0, [System.DateTimeKind]::Utc)
$HuntressWindowEnd   = [datetime]::new(2026, 10, 16, 2, 0, 0, [System.DateTimeKind]::Utc)

$PrivilegedRoles = @(
    'Global Administrator', 'Privileged Role Administrator', 'Privileged Authentication Administrator',
    'Application Administrator', 'Cloud Application Administrator', 'Exchange Administrator',
    'SharePoint Administrator', 'Teams Administrator', 'User Administrator', 'Authentication Administrator',
    'Security Administrator', 'Conditional Access Administrator', 'Hybrid Identity Administrator',
    'Intune Administrator', 'Directory Writers', 'Partner Tier2 Support', 'Partner Tier1 Support'
)
#endregion

#region ------------------------------ Helpers ------------------------------
$script:Findings = [System.Collections.Generic.List[object]]::new()

function Write-Step([int]$Number, [string]$Text) {
    Write-Host ''
    Write-Host ('[{0}/7] {1}' -f $Number, $Text) -ForegroundColor Cyan
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

function Invoke-GraphWithRetry {
    param([Parameter(Mandatory)][string]$Uri, [string]$Method = 'GET', $Body)
    $attempt = 0
    while ($true) {
        try {
            $p = @{ Uri = $Uri; Method = $Method; OutputType = 'PSObject'; ErrorAction = 'Stop' }
            if ($null -ne $Body) { $p.Body = ($Body | ConvertTo-Json -Depth 5); $p.ContentType = 'application/json' }
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
    param([Parameter(Mandatory)][string]$Uri, [int]$MaxItems = 0)
    $results = [System.Collections.Generic.List[object]]::new()
    $next = $Uri
    while ($next) {
        $resp = Invoke-GraphWithRetry -Uri $next
        foreach ($v in @($resp.value)) { if ($null -ne $v) { $results.Add($v) } }
        if ($MaxItems -gt 0 -and $results.Count -ge $MaxItems) {
            Write-Warning "Result cap of $MaxItems reached for $Uri - output truncated."
            break
        }
        $next = $resp.'@odata.nextLink'
    }
    return $results
}

function ConvertTo-Utc($Value) {
    if ($null -eq $Value -or "$Value" -eq '') { return $null }
    if ($Value -is [datetime]) { return $Value.ToUniversalTime() }
    return [datetime]::Parse([string]$Value, [Globalization.CultureInfo]::InvariantCulture,
        ([Globalization.DateTimeStyles]::AdjustToUniversal -bor [Globalization.DateTimeStyles]::AssumeUniversal))
}

function Get-IpClass([string]$Ip) {
    if (-not $Ip) { return 'None' }
    if ($AttackerIPs -contains $Ip) { return 'KnownMalicious' }
    if ($Ip -match '^f[cd][0-9a-f]{2}:') { return 'PrivateIPv6-ULA' }
    if ($Ip -match '^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.)') { return 'PrivateIPv4' }
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

function New-RoleRow($Sp, [string]$RoleName, [string]$AssignmentType) {
    if ((-not $Sp.appId) -and $script:SpById.ContainsKey([string]$Sp.id)) { $Sp = $script:SpById[[string]$Sp.id] }
    [pscustomobject]@{
        ServicePrincipal = $Sp.displayName
        AppId            = $Sp.appId
        ObjectId         = $Sp.id
        Role             = $RoleName
        AssignmentType   = $AssignmentType
        Privileged       = ($PrivilegedRoles -contains $RoleName)
        IsVendorApp      = (Test-IsVendor $Sp.appId $Sp.id ([string]$Sp.appOwnerOrganizationId))
    }
}

function ConvertTo-SignInRow($S, [string]$Query) {
    [pscustomobject]@{
        Query                = $Query
        TimeUtc              = (ConvertTo-Utc $S.createdDateTime)
        EventTypes           = (@($S.signInEventTypes) -join ',')
        AppDisplayName       = $S.appDisplayName
        AppId                = $S.appId
        ServicePrincipalName = $S.servicePrincipalName
        UserPrincipalName    = $S.userPrincipalName
        IPAddress            = $S.ipAddress
        IPClass              = (Get-IpClass $S.ipAddress)
        ASN                  = $S.autonomousSystemNumber
        Country              = $S.location.countryOrRegion
        Resource             = $S.resourceDisplayName
        ClientCredentialType = $S.clientCredentialType
        UserAgent            = $S.userAgent
        ErrorCode            = $S.status.errorCode
        FailureReason        = $S.status.failureReason
        Success              = ($S.status.errorCode -eq 0)
        CorrelationId        = $S.correlationId
    }
}

$script:SignInBlocked = $false
function Invoke-SignInQuery([string]$Filter, [string]$Label, [int]$Max = 5000) {
    if ($script:SignInBlocked) { return }
    $uri = 'https://graph.microsoft.com/beta/auditLogs/signIns?$filter=' + [uri]::EscapeDataString($Filter) + '&$top=500'
    try {
        foreach ($s in @(Invoke-GraphPaged -Uri $uri -MaxItems $Max)) { ConvertTo-SignInRow $s $Label }
    }
    catch {
        $msg = "$($_.Exception.Message) $($_.ErrorDetails.Message)"
        if ($msg -match 'NonPremium|premium') {
            $script:SignInBlocked = $true
            Add-Finding -Severity Info -Category 'SignIns' -Title 'Sign-in logs not available through the API (no Entra ID P1/P2)' `
                -Detail 'The tenant has no Entra ID P1/P2 license, so sign-in logs cannot be read through Microsoft Graph.' `
                -Recommendation 'Check manually: Entra admin center > Monitoring > Sign-in logs > Service principal sign-ins, filter Application ID 506e08f9-6e9a-4da4-942b-a099a03644ae (and the other ConnectWise IDs); search all tabs for IP 144.172.64.128.'
        }
        elseif ($msg -match 'Forbidden|Authorization_RequestDenied|403') {
            $script:SignInBlocked = $true
            Add-Finding -Severity Medium -Category 'SignIns' -Title 'Sign-in logs could not be read (access denied)' `
                -Detail $msg -Recommendation 'Run as a user holding Security Reader, Global Reader or Reports Reader, with AuditLog.Read.All consented.'
        }
        else { Write-Warning "Sign-in query '$Label' failed: $msg" }
    }
}
#endregion

#region ------------------------------ Setup & connect ------------------------------
if ($StartDate.Kind -eq [System.DateTimeKind]::Unspecified) { $StartDate = [datetime]::SpecifyKind($StartDate, [System.DateTimeKind]::Utc) }
if ($EndDate.Kind   -eq [System.DateTimeKind]::Unspecified) { $EndDate   = [datetime]::SpecifyKind($EndDate,   [System.DateTimeKind]::Utc) }
$StartUtc = $StartDate.ToUniversalTime()
$EndUtc   = $EndDate.ToUniversalTime()
$fmt      = "yyyy-MM-dd'T'HH:mm:ss'Z'"
$startStr = $StartUtc.ToString($fmt, [Globalization.CultureInfo]::InvariantCulture)
$endStr   = $EndUtc.ToString($fmt, [Globalization.CultureInfo]::InvariantCulture)

if (-not (Get-Module -ListAvailable -Name Microsoft.Graph.Authentication)) {
    throw 'Module Microsoft.Graph.Authentication not found. Install it with: Install-Module Microsoft.Graph.Authentication -Scope CurrentUser'
}
Import-Module Microsoft.Graph.Authentication

$scopes = @('Application.Read.All', 'Directory.Read.All', 'RoleManagement.Read.Directory', 'AuditLog.Read.All', 'Policy.Read.All')
if ($DisableVendorApps) { $scopes += 'Application.ReadWrite.All' }

Write-Host "ConnectWise / SkyKick vendor-credential IOC check v$ScriptVersion" -ForegroundColor White
Write-Host ("Review window: {0} -> {1} (UTC)" -f $startStr, $endStr)
Write-Host ("Requesting delegated scopes: {0}" -f ($scopes -join ', '))

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

$VendorAppIdSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
$VendorSpIdSet  = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
foreach ($k in $VendorApps.Keys) { [void]$VendorAppIdSet.Add($k) }
#endregion

#region ------------------------------ 1. Vendor service principals ------------------------------
Write-Step 1 'ConnectWise / SkyKick service principals'
$allSPs = @(Invoke-GraphPaged -Uri 'https://graph.microsoft.com/v1.0/servicePrincipals?$select=id,appId,displayName,accountEnabled,appOwnerOrganizationId,servicePrincipalType,passwordCredentials,keyCredentials&$top=999')
$script:SpById = @{}
foreach ($sp in $allSPs) { $script:SpById[[string]$sp.id] = $sp }
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
#endregion

#region ------------------------------ 2. Directory roles held by service principals ------------------------------
Write-Step 2 'Directory roles held by service principals (active + PIM eligible)'
$roleRows = [System.Collections.Generic.List[object]]::new()
try {
    $directoryRoles = @(Invoke-GraphPaged -Uri 'https://graph.microsoft.com/v1.0/directoryRoles?$select=id,displayName,roleTemplateId')
    foreach ($role in $directoryRoles) {
        $uri = 'https://graph.microsoft.com/v1.0/directoryRoles/{0}/members/microsoft.graph.servicePrincipal?$select=id,appId,displayName,appOwnerOrganizationId' -f $role.id
        foreach ($m in @(Invoke-GraphPaged -Uri $uri)) { $roleRows.Add((New-RoleRow -Sp $m -RoleName $role.displayName -AssignmentType 'Active')) }
    }
}
catch { Write-Warning "Could not enumerate active directory role members: $($_.Exception.Message)" }

try {
    $roleDefs = @{}
    foreach ($d in @(Invoke-GraphPaged -Uri 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleDefinitions?$select=id,displayName')) { $roleDefs[[string]$d.id] = $d.displayName }
    foreach ($e in @(Invoke-GraphPaged -Uri 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleEligibilitySchedules?$expand=principal')) {
        if ($e.principal.'@odata.type' -eq '#microsoft.graph.servicePrincipal') {
            $roleRows.Add((New-RoleRow -Sp $e.principal -RoleName $roleDefs[[string]$e.roleDefinitionId] -AssignmentType 'PIM-Eligible'))
        }
    }
}
catch { Write-Verbose "PIM eligibility not readable (needs Entra ID P2): $($_.Exception.Message)" }

foreach ($r in $roleRows) {
    if ($r.IsVendorApp) {
        $sev = if ($r.Privileged) { 'Critical' } else { 'High' }
        Add-Finding -Severity $sev -Category 'Roles' -Title ("ConnectWise/SkyKick app holds directory role '{0}': {1}" -f $r.Role, $r.ServicePrincipal) `
            -Detail ("{0} assignment. AppId {1}. Huntress observed these apps adding themselves to Exchange Administrator / Global Administrator." -f $r.AssignmentType, $r.AppId) `
            -Recommendation 'After disabling the app, remove any role you did not intentionally grant. Check the audit log (AuditEvents.csv) for when it was added and by whom.'
    }
    elseif ($r.Privileged) {
        Add-Finding -Severity Medium -Category 'Roles' -Title ("Service principal holds privileged role '{0}': {1}" -f $r.Role, $r.ServicePrincipal) `
            -Detail ("{0} assignment. AppId {1}." -f $r.AssignmentType, $r.AppId) `
            -Recommendation 'Confirm this assignment is intentional and expected for the tool.'
    }
}
if ($roleRows.Count -eq 0) { Write-Host '    No service principals hold directory roles.' }
#endregion

#region ------------------------------ 3. Credentials on apps and service principals ------------------------------
Write-Step 3 'Client secrets and certificates on app registrations and service principals'
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
#endregion

#region ------------------------------ 4. Entra audit log ------------------------------
Write-Step 4 'Entra audit log (ApplicationManagement + RoleManagement)'
$interesting = @('Add*member to role*', '*Certificates and secrets*', '*service principal credentials*', 'Update application*',
                 'Update service principal*', 'Add owner to*', 'Add app role assignment*', 'Consent to application*',
                 'Add delegated permission grant*', 'Add application*', 'Add service principal*')
$auditRows = [System.Collections.Generic.List[object]]::new()
foreach ($cat in @('ApplicationManagement', 'RoleManagement')) {
    $filter = "activityDateTime ge $startStr and activityDateTime le $endStr and category eq '$cat'"
    $uri = 'https://graph.microsoft.com/v1.0/auditLogs/directoryAudits?$filter=' + [uri]::EscapeDataString($filter) + '&$top=500'
    try { $events = @(Invoke-GraphPaged -Uri $uri -MaxItems 50000) }
    catch {
        Add-Finding -Severity Medium -Category 'AuditLog' -Title "Could not read audit log category $cat" -Detail $_.Exception.Message `
            -Recommendation 'Run with Security Reader / Global Reader / Reports Reader and AuditLog.Read.All.'
        continue
    }
    foreach ($e in $events) {
        $act = [string]$e.activityDisplayName
        if (-not ($interesting | Where-Object { $act -like $_ })) { continue }

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
        $roleName = $null; $modNames = @()
        foreach ($t in $targets) {
            foreach ($mp in @($t.modifiedProperties)) {
                if ($mp.displayName) { $modNames += $mp.displayName }
                if ($mp.displayName -eq 'Role.DisplayName') { $roleName = ([string]$mp.newValue).Trim('"') }
            }
        }
        $targetAppIds = @()
        foreach ($t in $targets) {
            if ($t.type -eq 'Application' -and $appById.ContainsKey([string]$t.id)) { $targetAppIds += $appById[[string]$t.id].appId }
            elseif ($t.type -eq 'ServicePrincipal' -and $script:SpById.ContainsKey([string]$t.id)) { $targetAppIds += $script:SpById[[string]$t.id].appId }
        }

        $isRoleAdd = $act -like 'Add*member to role*'
        $isCred    = ($act -like '*Certificates and secrets*') -or ($act -like '*service principal credentials*') -or
                     (($modNames -join ',') -match 'KeyDescription|FederatedIdentityCredentials|PasswordCredentials|KeyCredentials')
        $isVendor  = ($initType -eq 'Application') -and (Test-IsVendor $initAppId $initSpId '')
        $selfAssign = $isRoleAdd -and $initSpId -and (@($targets | ForEach-Object { [string]$_.id }) -contains [string]$initSpId)
        $suspUA    = Test-SuspiciousUA $ua

        $reasons = [System.Collections.Generic.List[string]]::new(); $sev = $null
        if ($isVendor -and ($isRoleAdd -or $isCred)) { $reasons.Add('initiated by a ConnectWise/SkyKick application'); $sev = 'Critical' }
        elseif ($isVendor) { $reasons.Add('initiated by a ConnectWise/SkyKick application'); $sev = 'High' }
        if ($isRoleAdd -and $initType -eq 'Application') {
            if ($selfAssign) { $reasons.Add('application added ITSELF to a directory role') } else { $reasons.Add('application added a principal to a directory role') }
            if (-not $sev) { $sev = 'High' }
        }
        if ($isCred -and $initType -eq 'Application') { $reasons.Add('application changed credentials of an app/service principal'); if (-not $sev) { $sev = 'High' } }
        if ($suspUA) { $reasons.Add("suspicious user agent '$ua'"); if (-not $sev) { $sev = 'High' } }
        if (-not $sev -and $isCred) { $reasons.Add('credential added/changed by a user - confirm it was intentional'); $sev = 'Medium' }

        # Azure ESTS Service (Microsoft first-party token service) rotating the P2P Server certificate is expected.
        $isMsP2PRotation = ($initAppId -eq '00000001-0000-0000-c000-000000000000') -and
                           (@($targets | ForEach-Object { $_.displayName }) -contains 'P2P Server')
        if ($isMsP2PRotation -and -not $isVendor -and -not $suspUA) {
            $reasons.Clear(); $reasons.Add('Microsoft-managed P2P Server certificate rotation by Azure ESTS Service')
            $sev = 'Info'
        }

        if ($isCred) { foreach ($id in $targetAppIds) { if ($id) { [void]$credChangedAppIds.Add([string]$id) } } }

        $targetText = ($targets | ForEach-Object { '{0} ({1}) [{2}]' -f $_.displayName, $_.type, $_.id }) -join '; '
        $row = [pscustomobject]@{
            TimeUtc            = (ConvertTo-Utc $e.activityDateTime)
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
            Flags              = ($reasons -join '; ')
            CorrelationId      = $e.correlationId
        }
        $auditRows.Add($row)

        if ($sev -and -not ($isMsP2PRotation -and $sev -eq 'Info' -and $act -like 'Update service principal*')) {
            Add-Finding -Severity $sev -Category 'AuditLog' -Title ("{0} by {1} '{2}' at {3:yyyy-MM-dd HH:mm} UTC ({4})" -f $act, $initType, $initName, $row.TimeUtc, $e.result) `
                -Detail ("Why: {0}. Targets: {1}. Role: {2}. User-Agent: {3}." -f $row.Flags, $targetText, $roleName, $ua) `
                -Recommendation 'Validate this change. If not expected: remove the role/credential, disable the initiating app, and investigate the target app as compromised.'
        }
    }
}
Write-Host ("    {0} relevant audit events collected" -f $auditRows.Count)
#endregion

#region ------------------------------ 5. Sign-in logs ------------------------------
$signInVendor = [System.Collections.Generic.List[object]]::new()
$signInIp     = [System.Collections.Generic.List[object]]::new()
$signInCred   = [System.Collections.Generic.List[object]]::new()
if ($SkipSignInLogs) {
    Write-Step 5 'Sign-in logs (skipped)'
}
else {
    Write-Step 5 'Sign-in logs (beta API; can be slow on large tenants)'

    # 5a. Service principal sign-ins of the ConnectWise apps
    foreach ($appId in $VendorAppIdSet) {
        $f = "createdDateTime ge $startStr and createdDateTime le $endStr and appId eq '$appId' and signInEventTypes/any(t: t eq 'servicePrincipal')"
        foreach ($r in @(Invoke-SignInQuery -Filter $f -Label "VendorApp:$appId")) { $signInVendor.Add($r) }
    }
    foreach ($g in ($signInVendor | Group-Object AppId, IPAddress)) {
        $first = $g.Group[0]
        $ok = @($g.Group | Where-Object Success).Count
        $span = '{0:yyyy-MM-dd HH:mm} - {1:yyyy-MM-dd HH:mm} UTC' -f ($g.Group | Measure-Object TimeUtc -Minimum).Minimum, ($g.Group | Measure-Object TimeUtc -Maximum).Maximum
        $detail = "{0} sign-ins ({1} successful), {2}. App {3} ({4}). ASN {5}, country {6}." -f $g.Count, $ok, $span, $first.AppDisplayName, $first.AppId, $first.ASN, $first.Country
        switch ($first.IPClass) {
            'KnownMalicious' {
                Add-Finding -Severity Critical -Category 'SignIns' -Title ("Vendor app signed in from known attacker IP {0}" -f $first.IPAddress) -Detail $detail `
                    -Recommendation 'Treat the tenant as accessed. Disable the app, review all credentials/roles, and review Purview Unified Audit Log (MailItemsAccessed, FileDownloaded) for this AppId.'
            }
            'Public' {
                Add-Finding -Severity High -Category 'SignIns' -Title ("Vendor app signed in from public IP {0}" -f $first.IPAddress) -Detail ($detail + ' Legitimate traffic for these apps normally comes from Azure private IPv6 space.') `
                    -Recommendation 'Determine who owns this IP. If unknown, handle as unauthorized access.'
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

    # 5b. Anything from the known attacker IP (password spray, user and app sign-ins)
    foreach ($ip in $AttackerIPs) {
        foreach ($type in @('interactiveUser', 'nonInteractiveUser', 'servicePrincipal')) {
            $f = "createdDateTime ge $startStr and createdDateTime le $endStr and ipAddress eq '$ip' and signInEventTypes/any(t: t eq '$type')"
            foreach ($r in @(Invoke-SignInQuery -Filter $f -Label "AttackerIP:$ip/$type")) { $signInIp.Add($r) }
        }
    }
    foreach ($g in ($signInIp | Group-Object { if ($_.UserPrincipalName) { $_.UserPrincipalName } else { $_.AppDisplayName } })) {
        $ok = @($g.Group | Where-Object Success).Count
        $sev = if ($ok -gt 0) { 'Critical' } else { 'High' }
        Add-Finding -Severity $sev -Category 'SignIns' -Title ("{0} sign-in(s) from attacker IP for '{1}' ({2} successful)" -f $g.Count, $g.Name, $ok) `
            -Detail ("Event types: {0}. User agents: {1}. Error codes: {2}." -f (($g.Group.EventTypes | Select-Object -Unique) -join ','), (($g.Group.UserAgent | Where-Object { $_ } | Select-Object -Unique) -join ', '), (($g.Group.ErrorCode | Select-Object -Unique) -join ',')) `
            -Recommendation $(if ($ok -gt 0) { 'Successful sign-in: reset credentials / revoke sessions (users) or disable the app and rotate credentials (apps); investigate activity after the sign-in.' } else { 'Failed attempts (likely password spray). Confirm the accounts have MFA and are not locked out; block the IP in a named location.' })
    }
    if ($signInIp.Count -eq 0 -and -not $script:SignInBlocked) {
        Add-Finding -Severity Info -Category 'SignIns' -Title 'No sign-ins from 144.172.64.128 in the window' -Detail 'Interactive, non-interactive and service principal sign-in logs were checked.' -Recommendation 'None. A clean result does not rule out access through other infrastructure.'
    }

    # 5c. Sign-ins of apps whose credentials changed in the window
    $toCheck = @($credChangedAppIds | Where-Object { $_ -and -not $VendorAppIdSet.Contains($_) } | Select-Object -First 25)
    foreach ($appId in $toCheck) {
        $f = "createdDateTime ge $startStr and createdDateTime le $endStr and appId eq '$appId' and signInEventTypes/any(t: t eq 'servicePrincipal')"
        $rows = @(Invoke-SignInQuery -Filter $f -Label "CredChangedApp:$appId" -Max 2000)
        foreach ($r in $rows) { $signInCred.Add($r) }
        $public = @($rows | Where-Object { $_.IPClass -in @('Public', 'KnownMalicious') })
        if ($public.Count -gt 0) {
            $ips = ($public | Group-Object IPAddress | ForEach-Object { '{0} (x{1})' -f $_.Name, $_.Count }) -join ', '
            Add-Finding -Severity Medium -Category 'SignIns' -Title ("App with a credential change signed in from public IPs: {0}" -f $public[0].AppDisplayName) `
                -Detail ("AppId {0}. Source IPs: {1}. Credential types used: {2}." -f $appId, $ips, (($public.ClientCredentialType | Select-Object -Unique) -join ',')) `
                -Recommendation 'Confirm these IPs belong to the app vendor or your own infrastructure. Unknown IPs right after a new secret was added indicate the planted credential is in use.'
        }
    }
}
#endregion

#region ------------------------------ 6. Conditional Access ------------------------------
Write-Step 6 'Conditional Access exclusions'
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
}
catch { Write-Warning "Could not read Conditional Access policies: $($_.Exception.Message)" }
#endregion

#region ------------------------------ 7. Optional remediation + report ------------------------------
Write-Step 7 'Remediation (optional) and report'
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

$files = @(
    Export-Data $vendorRows   'VendorServicePrincipals'
    Export-Data $roleRows     'ServicePrincipalRoles'
    Export-Data $credRows     'AppCredentials'
    Export-Data $auditRows    'AuditEvents'
    Export-Data $signInVendor 'SignIns-VendorApps'
    Export-Data $signInIp     'SignIns-AttackerIP'
    Export-Data $signInCred   'SignIns-CredentialChangedApps'
    Export-Data $caRows       'ConditionalAccessExclusions'
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
<b>Reference:</b> https://www.huntress.com/blog/vendor-credential-enables-unauthorized-access</p>
<p>A clean result does not prove the tenant was not accessed: Graph reads by an application are not audited.</p>
$(($counts | ConvertTo-Html -Fragment) -join "`n")
<h2>Findings</h2>
"@
$html = ($sorted | ConvertTo-Html -Head $css -PreContent $pre -Property Severity, Category, Title, Detail, Recommendation -Title 'CW/SkyKick IOC check') -join "`n"
$html = $html -replace '<td>Critical</td>', '<td style="background:#b91c1c;color:#fff;font-weight:bold">Critical</td>' `
              -replace '<td>High</td>', '<td style="background:#c2410c;color:#fff;font-weight:bold">High</td>' `
              -replace '<td>Medium</td>', '<td style="background:#facc15">Medium</td>'
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

Disconnect-MgGraph | Out-Null
#endregion
