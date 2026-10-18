#Requires -Version 5.1
<#
.SYNOPSIS
    Runs Invoke-CWSkyKickIOCCheck.ps1 against many tenants and builds one summary (MSP / partner use).

.DESCRIPTION
    Reads a tenant list (CSV or -TenantId), runs the read-only check once per tenant into its own folder,
    and writes Summary.csv and Summary.html sorted by severity, with each tenant's coverage gaps.

    The remediation switch (-DisableVendorApps) is deliberately NOT available here: disable apps per tenant,
    after reviewing that tenant's report.

    Authentication: each tenant gets its own Connect-MgGraph -TenantId sign-in. With GDAP, sign in with your
    partner account; the token cache usually avoids repeated prompts. Exchange checks use
    Connect-ExchangeOnline -DelegatedOrganization when -PartnerDelegated is set.

.PARAMETER TenantListPath
    CSV with a TenantId column (tenant ID or primary domain). Optional columns: Name, ExchangeOrganization
    (the customer's *.onmicrosoft.com domain, used with -PartnerDelegated).

.PARAMETER TenantId
    Tenant IDs or domains, as an alternative to -TenantListPath.

.PARAMETER OutputRoot
    Root folder; one sub-folder per tenant. Default: .\CW-SkyKick-IOC-Bulk-<timestamp>

.PARAMETER PartnerDelegated
    Use partner-delegated (GDAP) access for Exchange Online: passes ExchangeOrganization (or TenantId) as
    -ExchangeDelegatedOrganization.

.EXAMPLE
    .\Invoke-CWSkyKickIOCCheckBulk.ps1 -TenantListPath .\tenants.csv -IncludeExchange -PartnerDelegated

.NOTES
    Version : 1.2.0 (2026-10-18)
#>
[CmdletBinding()]
param(
    [string]$TenantListPath,
    [string[]]$TenantId,
    [string]$OutputRoot = (Join-Path -Path (Get-Location).Path -ChildPath ('CW-SkyKick-IOC-Bulk-' + (Get-Date -Format 'yyyyMMdd-HHmmss'))),
    [datetime]$StartDate,
    [datetime]$EndDate,
    [datetime]$AsnStartDate,
    [int[]]$AttackerASNs,
    [string[]]$AdditionalAttackerIPs,
    [string[]]$AttackerCidrs,
    [switch]$SkipPrefixLookup,
    [int]$MaxSignIns,
    [switch]$SkipSignInLogs,
    [switch]$SkipAsnHunt,
    [switch]$IncludeExchange,
    [switch]$PartnerDelegated,
    [switch]$UseDeviceCode
)
$ErrorActionPreference = 'Stop'
$main = Join-Path $PSScriptRoot 'Invoke-CWSkyKickIOCCheck.ps1'
if (-not (Test-Path $main)) { throw "Invoke-CWSkyKickIOCCheck.ps1 not found next to this script ($PSScriptRoot)." }

$tenants = [System.Collections.Generic.List[object]]::new()
if ($TenantListPath) { foreach ($r in (Import-Csv -Path $TenantListPath)) { if ($r.TenantId) { $tenants.Add($r) } } }
foreach ($t in @($TenantId)) { if ($t) { $tenants.Add([pscustomobject]@{ TenantId = $t; Name = $t; ExchangeOrganization = $null }) } }
if ($tenants.Count -eq 0) { throw 'No tenants given. Use -TenantListPath (CSV with a TenantId column) or -TenantId.' }
New-Item -ItemType Directory -Path $OutputRoot -Force | Out-Null

# Parameters passed through unchanged to every run
$common = @{}
foreach ($n in 'StartDate', 'EndDate', 'AsnStartDate', 'AttackerASNs', 'AdditionalAttackerIPs', 'AttackerCidrs', 'MaxSignIns') {
    if ($PSBoundParameters.ContainsKey($n)) { $common[$n] = $PSBoundParameters[$n] }
}
foreach ($n in 'SkipSignInLogs', 'SkipAsnHunt', 'SkipPrefixLookup', 'IncludeExchange', 'UseDeviceCode') { if ($PSBoundParameters[$n]) { $common[$n] = $true } }

$summary = [System.Collections.Generic.List[object]]::new()
$i = 0
foreach ($t in $tenants) {
    $i++
    $name = if ($t.Name) { [string]$t.Name } else { [string]$t.TenantId }
    $safe = ($name -replace '[^\w\.\-]', '_')
    $out = Join-Path $OutputRoot $safe
    Write-Host ''
    Write-Host ('==== [{0}/{1}] {2} ({3}) ====' -f $i, $tenants.Count, $name, $t.TenantId) -ForegroundColor White
    $p = $common.Clone()
    $p.TenantId = [string]$t.TenantId
    $p.OutputPath = $out
    if ($PartnerDelegated -and $IncludeExchange) {
        $p.ExchangeDelegatedOrganization = if ($t.ExchangeOrganization) { [string]$t.ExchangeOrganization } else { [string]$t.TenantId }
    }
    $status = 'Completed'; $err = $null
    try { & $main @p }
    catch { $status = 'Failed'; $err = $_.Exception.Message; Write-Warning ("{0}: {1}" -f $name, $err) }
    finally { try { Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null } catch { } }

    $findings = @(); $gaps = @()
    $fj = Join-Path $out 'Findings.json'
    if (Test-Path $fj) { $findings = @(Get-Content -Path $fj -Raw | ConvertFrom-Json) }
    elseif ($status -eq 'Completed') { $status = 'NoOutput' }
    $cv = Join-Path $out 'Coverage.csv'
    if (Test-Path $cv) { $gaps = @(Import-Csv -Path $cv | Where-Object { $_.Status -ne 'Done' } | ForEach-Object { '{0} ({1})' -f $_.Check, $_.Status }) }
    $top = @($findings | Where-Object { $_.Severity -in 'Critical', 'High' } | Select-Object -First 6 | ForEach-Object { '[{0}] {1}' -f $_.Severity, $_.Title })
    $summary.Add([pscustomobject]@{
        Tenant       = $name
        TenantId     = $t.TenantId
        Status       = $status
        Critical     = @($findings | Where-Object Severity -eq 'Critical').Count
        High         = @($findings | Where-Object Severity -eq 'High').Count
        Medium       = @($findings | Where-Object Severity -eq 'Medium').Count
        Info         = @($findings | Where-Object Severity -eq 'Info').Count
        TopFindings  = ($top -join ' | ')
        CoverageGaps = ($gaps -join '; ')
        Error        = $err
        Report       = $(if (Test-Path (Join-Path $out 'Report.html')) { Join-Path $out 'Report.html' } else { $null })
    })
}

$sorted = @($summary | Sort-Object @{ Expression = { if ($_.Status -ne 'Completed') { 0 } else { 1 } } }, @{ Expression = 'Critical'; Descending = $true }, @{ Expression = 'High'; Descending = $true }, Tenant)
$sorted | Export-Csv -Path (Join-Path $OutputRoot 'Summary.csv') -NoTypeInformation -Encoding UTF8
$css = '<style>body{font-family:Segoe UI,Arial,sans-serif;margin:24px;color:#222}table{border-collapse:collapse;width:100%}th,td{border:1px solid #ccc;padding:6px 8px;vertical-align:top;font-size:13px;text-align:left}th{background:#1f2937;color:#fff}</style>'
$pre = "<h1>ConnectWise / SkyKick IOC check - multi-tenant summary</h1><p>$($tenants.Count) tenant(s), generated $([datetime]::UtcNow.ToString('yyyy-MM-dd HH:mm')) UTC. Failed runs are listed first, then tenants by Critical/High count. Open each tenant's Report.html for details.</p>"
($sorted | ConvertTo-Html -Head $css -PreContent $pre -Property Tenant, TenantId, Status, Critical, High, Medium, TopFindings, CoverageGaps, Error, Report -Title 'CW/SkyKick IOC summary') -join "`n" |
    Set-Content -Path (Join-Path $OutputRoot 'Summary.html') -Encoding UTF8

Write-Host ''
Write-Host '==================== MULTI-TENANT SUMMARY ====================' -ForegroundColor White
foreach ($s in $sorted) {
    $color = if ($s.Status -ne 'Completed') { 'DarkYellow' } elseif ($s.Critical) { 'Red' } elseif ($s.High) { 'Magenta' } else { 'Green' }
    Write-Host ('  {0,-35} {1,-9} C:{2,-3} H:{3,-3} M:{4,-3}' -f $s.Tenant, $s.Status, $s.Critical, $s.High, $s.Medium) -ForegroundColor $color
}
Write-Host ("  Summary: {0}" -f (Join-Path $OutputRoot 'Summary.html'))
