# ConnectWise / SkyKick Vendor-Credential IOC Check for Entra ID

A free, **read-only** PowerShell script that checks a Microsoft Entra ID / Microsoft 365 tenant for the indicators of compromise and persistence techniques from the ConnectWise Cloud Backup (formerly SkyKick) vendor-credential incident of October 2026.

> **Background:** On October 16, 2026, [Huntress reported](https://www.huntress.com/blog/vendor-credential-enables-unauthorized-access) that a Microsoft 365 credential belonging to ConnectWise Cloud Backup (formerly SkyKick) had been compromised and was being used to access customer tenants. In one tenant, a ConnectWise Cloud Management application assigned itself Global Administrator and added new client secrets to other applications. ConnectWise published its own advisory on its [Trust Center](https://www.connectwise.com/company/trust/advisories).
>
> **Disabling the vendor applications does not remove credentials an attacker already planted on other apps.** This script helps you find them, and the other ways back in that a Global Administrator could have left behind.

This is a community tool. It is not affiliated with or endorsed by Huntress, ConnectWise or Microsoft.

> ⏱️ **Run it now.** Tenants without Entra ID P1/P2 keep audit logs for only 7 days, so events from October 13–15 age out around October 20–22. Tenants with P1/P2 keep 30 days.

---

## What it checks

| # | Check | What gets flagged |
|---|-------|-------------------|
| 1 | ConnectWise / SkyKick service principals | Known App IDs, the vendor's owner tenant ID, or matching display names. Flags apps that are still **enabled** and any credentials on the vendor service principal in your tenant. |
| 2 | Directory roles held by service principals | Active and PIM-eligible assignments, **administrative-unit scoped** roles, and roles **inherited through role-assignable groups**. A vendor app holding a privileged role is **Critical**. |
| 3 | Credentials on all apps | Client secrets and certificates on every app registration and service principal with a start date inside the review window, plus an inventory of **federated identity credentials** (FICs) with uncommon issuers flagged. |
| 4 | Application permissions | Microsoft Graph, Exchange Online and SharePoint app roles held by apps. Tenant-takeover permissions (e.g. `RoleManagement.ReadWrite.Directory`, `Application.ReadWrite.All`) and grants made **during the window** are flagged. |
| 5 | Entra audit log | Six categories: apps adding themselves to roles or changing other apps' credentials; password resets and authentication-method changes; new users and guests; role-assignable group changes; Conditional Access and tenant policy changes; **domain federation changes** (Golden SAML); partner relationship changes; suspicious user agents. Microsoft first-party activity (PIM activations, managed rotations) is recognized. |
| 6 | Sign-in logs | Vendor app sign-ins from non-Azure IPs; all sign-in types from the known attacker IPs; an **attacker-network hunt** (AS14956 RouterHosting by default, by ASN for user sign-ins and by announced IP prefix for app sign-ins); a **sweep of every service-principal sign-in** from non-Microsoft networks; sign-ins of apps whose credentials changed. |
| 6b | Credential usage | Ties app sign-ins to the exact secret or certificate used (KeyId). Flags a credential created during the window that is **in use**, and reviews credentials on **Microsoft first-party apps** (e.g. Azure Multi-Factor Auth Client) with which ones are used and which are not. |
| 7 | Workload identity risk | Risky service principals and risk detections from Entra ID Protection (where licensed). |
| 8 | Tenant configuration | Conditional Access exclusions for the vendor apps; **federated domains** with issuer and signing-certificate details; GDAP relationships and DAP contracts (`-PartnerTenant`). |
| 9 | Exchange Online *(optional, `-IncludeExchange`)* | Unified Audit Log: inbox rules, forwarding, mailbox permissions, transport rules, connectors and Exchange RBAC changes, plus **all activity from attacker IPs**, including addresses discovered by the ASN hunt. Current state: forwarding mailboxes, transport rules, connectors, Exchange RBAC for applications, external auto-forwarding, and optionally every inbox rule. |

Microsoft-managed credential rotations (the `P2P Server` certificate, managed identity certificates) are recognized and reported as **Info**, not as findings.

Every run also produces a **coverage table**: which checks ran fully, partially, or not at all (no licence, missing permission, result cap reached). A clean result only means something next to a complete coverage table.

Output: an HTML report plus CSV files, rated **Critical / High / Medium / Info**.

### Why the ASN hunt matters

A single IP is a weak indicator: the actor can move to a neighbouring address at the same provider. The attacker IP sits in AS14956 (RouterHosting), a hosting ASN that is rarely a legitimate source of Microsoft 365 sign-ins. The script therefore hunts the whole network, reports every **new** address it finds, and feeds those addresses into the Unified Audit Log search (`-IncludeExchange`).

How it matches, and why:

- **User sign-ins** carry an ASN. The script asks Graph to filter on it and then **verifies every returned row**, because Graph can silently ignore the filter and return unfiltered results. If it does, the script falls back to filtering locally.
- **Service-principal (app) sign-ins carry no ASN**: Graph reports `0`. They are matched against the ASN's **announced IP prefixes**, looked up at run time from [RIPEstat](https://stat.ripe.net/). Only the ASN number is sent; nothing from the tenant leaves the machine. Use `-SkipPrefixLookup` to disable this and `-AttackerCidrs` to supply ranges yourself. Without prefixes, app sign-ins are matched by exact IP only and the coverage table says so.

The ASN does **not** find everything. Huntress saw the Global Administrator assignment and the planted secrets come from Azure private IPv6 space about two and a half hours *before* the first sign-ins from the attacker IP. Persistence is found by checks 2–5, not by IP or ASN matching. Use both.

---

## Requirements

- Windows PowerShell 5.1 or PowerShell 7+
- The `Microsoft.Graph.Authentication` module:

```powershell
Install-Module Microsoft.Graph.Authentication -Scope CurrentUser
```

- Optional, for `-IncludeExchange`:

```powershell
Install-Module ExchangeOnlineManagement -Scope CurrentUser
```

### Permissions

The script signs in with **delegated** permissions through the *Microsoft Graph Command Line Tools* app.

| Delegated Graph scope | Used for |
|---|---|
| `Application.Read.All` | Service principals, app registrations, credentials, FICs, app role assignments |
| `Directory.Read.All` | Directory role members, groups, tenant info |
| `RoleManagement.Read.Directory` | Role definitions, active and PIM-eligible assignments |
| `AuditLog.Read.All` | Entra audit log and sign-in logs |
| `Policy.Read.All` | Conditional Access policies |
| `Domain.Read.All` | Domain federation configuration (new in 1.2) |
| `IdentityRiskyServicePrincipal.Read.All` | Risky workload identities (new in 1.2; the check is skipped if not granted) |
| `DelegatedAdminRelationship.Read.All` | **Only** with `-PartnerTenant` |
| `Application.ReadWrite.All` | **Only** with `-DisableVendorApps` |

**Upgrading from 1.1:** version 1.2 requests two new scopes, so the first run asks for admin consent again.

**Who can run it**

- **Global Reader** is enough for all read-only Graph checks.
- `-IncludeExchange` needs **View-Only Organization Management** and **View-Only Audit Logs** in Exchange Online (or Audit Reader in Purview for the audit search).
- `-PartnerTenant` needs a Partner Center role that can read GDAP relationships.
- `-DisableVendorApps` needs **Cloud Application Administrator** or **Application Administrator**.

**One-time consent:** the first run asks for admin consent for the scopes above. A Global Administrator, Privileged Role Administrator, or Cloud Application Administrator / Application Administrator can grant it. After that, a Global Reader can run the script.

**Licensing:** reading sign-in logs through the API requires **Entra ID P1 or P2**. Without it, the script tells you how to check the portal manually (including the ASN column) and runs every other check. Risky workload identities need **Workload Identities Premium**.

---

## Quick start

```powershell
# Download the script, then:
Unblock-File .\Invoke-CWSkyKickIOCCheck.ps1

# Read-only assessment of your home tenant
.\Invoke-CWSkyKickIOCCheck.ps1

# Full assessment including Exchange Online / Unified Audit Log
.\Invoke-CWSkyKickIOCCheck.ps1 -TenantId contoso.onmicrosoft.com -OutputPath C:\IR\contoso -IncludeExchange

# Add indicators published after this release
.\Invoke-CWSkyKickIOCCheck.ps1 -AdditionalAttackerIPs 203.0.113.10 -AttackerASNs 14956,64512

# Assess, then disable (never delete) any enabled ConnectWise/SkyKick apps - prompts per app
.\Invoke-CWSkyKickIOCCheck.ps1 -DisableVendorApps
```

### Parameters

| Parameter | Description |
|---|---|
| `-TenantId` | Tenant ID or domain. Defaults to the signed-in account's home tenant. |
| `-StartDate` / `-EndDate` | Review window, treated as UTC. Default: 2026-10-13 00:00 UTC to now. |
| `-AsnStartDate` | Longer look-back for the attacker IP / ASN hunt. Default: 2026-10-01 00:00 UTC. |
| `-AttackerASNs` | ASNs to hunt. Default: `14956` (RouterHosting). |
| `-AdditionalAttackerIPs` | Extra IPs to treat as known-malicious. |
| `-AttackerCidrs` | Extra attacker IP ranges (CIDR, IPv4 or IPv6). |
| `-SkipPrefixLookup` | Do not look up the attacker ASN's prefixes from RIPEstat (offline / no outbound calls). |
| `-MaxSignIns` | Cap per sign-in query (default 50000). Hitting it raises a finding and marks coverage as Partial. |
| `-OutputPath` | Output folder. Default: `.\CW-SkyKick-IOC-<timestamp>` |
| `-SkipSignInLogs` | Skip all sign-in queries (fast run, or no P1/P2). |
| `-SkipAsnHunt` | Skip the ASN hunt and the all-app sweep (the slowest queries). |
| `-IncludeExchange` | Run the Exchange Online / Unified Audit Log checks. |
| `-IncludeInboxRules` | With `-IncludeExchange`: read inbox rules on every mailbox (slow on large tenants). |
| `-ExchangeDelegatedOrganization` | With `-IncludeExchange`: customer domain for partner (GDAP) access. |
| `-PartnerTenant` | MSP/CSP partner tenant: also review GDAP relationships and DAP contracts. |
| `-DisableVendorApps` | After the assessment, disable enabled vendor service principals. Requires extra permission and confirmation. |
| `-UseDeviceCode` | Device-code sign-in for hosts without a browser. |

**Performance:** app sign-ins are always read in full since `-AsnStartDate` (they carry no ASN), and user sign-ins are read in full if Graph rejects or ignores the ASN filter. On large tenants this is slow and can hit `-MaxSignIns`; the coverage table says so. For large tenants, run the ASN hunt in Sentinel instead (see below) and use `-SkipAsnHunt`.

---

## MSPs: many tenants at once

`Invoke-CWSkyKickIOCCheckBulk.ps1` runs the check once per tenant, each into its own folder, and writes `Summary.csv` / `Summary.html` sorted by severity, with each tenant's coverage gaps. Failed tenants are listed first.

```powershell
# tenants.csv: TenantId,Name,ExchangeOrganization
.\Invoke-CWSkyKickIOCCheckBulk.ps1 -TenantListPath .\tenants.csv -IncludeExchange -PartnerDelegated
```

`-DisableVendorApps` is intentionally not available in bulk mode. Review each tenant's report, then remediate per tenant.

---

## Sentinel / Log Analytics hunting

`hunting\sentinel-hunting.kql` covers what no API-based script can see:

- **Microsoft Graph activity logs**: the only record of what an app *read* through Graph (mail, files, directory). Only available if `MicrosoftGraphActivityLogs` were streamed before the incident.
- ASN and IP hunting at scale (no API result cap, longer retention).
- Python / curl Graph write calls by any app.
- Microsoft 365 activity from attacker IPs and ranges.

---

## Output

| File | Contents |
|---|---|
| `Report.html` | Summary, coverage table and all findings, sorted by severity |
| `Findings.csv` / `Findings.json` | All findings |
| `Coverage.csv` | What was checked and with what result (Done / Partial / Skipped / Failed / Unavailable) |
| `VendorServicePrincipals.csv` | ConnectWise/SkyKick service principals found |
| `ServicePrincipalRoles.csv` | Directory roles held by service principals, with scope and inheriting group |
| `AppCredentials.csv` | Every secret and certificate on apps and service principals, with sign-in count, last use and source IPs since `-AsnStartDate` |
| `FederatedIdentityCredentials.csv` | Every FIC with issuer and subject |
| `AppPermissions.csv` | Graph / Exchange / SharePoint application permissions held by apps, with tier and grant date |
| `AuditEvents.csv` | Relevant audit events with kind, initiator, user agent, severity and flags |
| `SignIns-*.csv` | Vendor apps, attacker IPs, attacker ASN, all-app non-Microsoft sweep, credential-changed apps |
| `WorkloadIdentityRisk.csv` | Risky service principals and detections |
| `ConditionalAccessExclusions.csv` | CA policies excluding the vendor apps |
| `FederatedDomains.csv` | Federated domains, issuer, sign-in URL and signing certificates |
| `GDAPRelationships.csv` | GDAP relationships (`-PartnerTenant`) |
| `UAL-PersistenceOps.csv` / `UAL-AttackerIP.csv` / `Exchange-Configuration.csv` | Exchange Online results (`-IncludeExchange`) |

Files are written only when there is data.

> ⚠️ **The output contains sensitive tenant data.** Do not commit it or attach it to public issues.

### Interpreting results

- **Critical:** strong indicator of compromise (vendor app with a privileged role, vendor app changing credentials, successful sign-in from attacker infrastructure, M365 activity from attacker IPs, domain federation changed by an app). Start incident response.
- **High:** needs validation (a new credential on an app, an app-initiated role or user change, a federation change, an app credential used from a non-Microsoft network right after it was added, a suspicious user agent). Confirm with the app owner.
- **Medium:** review (privileged roles or tenant-takeover permissions held by other apps, credentials on Microsoft first-party apps, CA exclusions, federated domains, uncommon FIC issuers, admin changes to CA or role-assignable groups).
- **Info:** context, clean results, and Microsoft-managed activity.

---

## Limitations

- **A clean result does not prove the tenant was not accessed.** Reads through Microsoft Graph by an application are not in the Entra audit log. Only Microsoft Graph activity logs record them, and only if they were enabled beforehand.
- **Read the coverage table.** A check that was skipped, unlicensed or truncated did not prove anything.
- **Credential start dates can be set by whoever creates the credential.** The audit-log check is the stronger evidence. FICs have no creation date at all.
- **The ASN hunt finds the access phase, not the persistence phase.** The persistence Huntress observed came from Azure private IPv6.
- **SharePoint and Teams configuration** beyond site-collection admin changes in the audit log is not covered.
- **Customer-side GDAP state** is not exposed through Graph. In customer tenants, partner changes are found through the audit log only.
- Sign-in queries use the Microsoft Graph **beta** endpoint, which is required for service-principal sign-ins.

---

## Indicators used

| Indicator | Type |
|---|---|
| `144.172.64[.]128` | Attacker IP |
| `AS14956` | Attacker ASN (RouterHosting) — hunted as a whole |
| `506e08f9-6e9a-4da4-942b-a099a03644ae` | ConnectWise Cloud Backup (formerly SkyKick) |
| `2399d300-6fca-4e6a-a686-399fefe75b83` | ConnectWise Cloud Management |
| `24205314-2b89-4e07-a2a4-579e898a5640` | ConnectWise Cloud Management - MS Teams |
| `b78f6a77-d4e5-46fb-87e5-d1648bd02519` | ConnectWise Cloud Management - Exchange Online |
| `0de14c77-b9b0-4137-9360-34878a929827` | ConnectWise Cloud Management - MS Graph |
| `412dcf96-176d-4b3a-a1b0-4981ad66971e` | ConnectWise Cloud Management - Partner Center |
| `b2b55f5b-7758-4719-8d8f-88ae172e6bdb` | ConnectWise Cloud Management - SharePoint Online |
| `3f9cd7a0-127a-4ed4-bf06-2f830d5616b7` | Vendor app owner tenant ID |
| `fde4:8dba:2600:37ce:6d26:200:a76:*` | Azure ULA seen on the persistence activity (also carries legitimate traffic; context only) |
| `Python-urllib/3.12`, `python-requests/2.31`, `curl/7.88.1` | User agents (low fidelity alone) |

Source: [Huntress advisory](https://www.huntress.com/blog/vendor-credential-enables-unauthorized-access). Check it for updates; the indicators in this script may lag behind. Add new ones with `-AdditionalAttackerIPs` and `-AttackerASNs` without waiting for a release.

---

## If you find something

Follow the vendor and Huntress guidance:

1. **Disable** (do not delete) the ConnectWise / SkyKick enterprise applications. Deleting removes the consent.
2. Remove directory roles you did not intentionally grant to those apps, including through groups.
3. Remove unexpected secrets, certificates and federated identity credentials from **all** apps, especially management and security tools.
4. Check federated domains: if the issuer or signing certificate is not yours, convert the domain back to managed and revoke all sessions.
5. Remove mailbox forwarding, inbox rules, transport rules, connectors and Exchange RBAC assignments you did not create.
6. Review Conditional Access exclusions for the vendor apps.
7. Do not re-enable the vendor apps until ConnectWise confirms all credentials were reset.

---

## Contributing

Issues and pull requests are welcome: new indicators, false-positive tuning, or extra checks. Please **never** include tenant output, IDs or logs from a real environment in an issue.

## Credits

Research and indicators: [Huntress](https://www.huntress.com/blog/vendor-credential-enables-unauthorized-access). ASN-based hunting suggested by community feedback.

## Disclaimer

Provided as-is, without warranty. Test it in a non-production tenant first. You are responsible for how you use it in your environment.

## License

[MIT](LICENSE)
