# ConnectWise / SkyKick Vendor-Credential IOC Check for Entra ID

A free, **read-only** PowerShell script that checks a Microsoft Entra ID / Microsoft 365 tenant for the indicators of compromise and persistence techniques from the ConnectWise Cloud Backup (formerly SkyKick) vendor-credential incident of October 2026.

> **Background:** On October 16, 2026, [Huntress reported](https://www.huntress.com/blog/vendor-credential-enables-unauthorized-access) that a Microsoft 365 credential belonging to ConnectWise Cloud Backup (formerly SkyKick) had been compromised and was being used to access customer tenants. In one tenant, a ConnectWise Cloud Management application assigned itself Global Administrator and added new client secrets to other applications. ConnectWise published its own advisory on its [Trust Center](https://www.connectwise.com/company/trust/advisories).
>
> **Disabling the vendor applications does not remove credentials an attacker already planted on other apps.** This script helps you find them.

This is a community tool. It is not affiliated with or endorsed by Huntress, ConnectWise or Microsoft.

---

## What it checks

| # | Check | What gets flagged |
|---|---|---|
| 1 | ConnectWise / SkyKick service principals | Known App IDs, the vendor's owner tenant ID, or matching display names. Flags apps that are still **enabled** and any credentials on the vendor service principal in your tenant. |
| 2 | Directory roles held by service principals | Active and PIM-eligible assignments. A vendor app holding a privileged role (for example Global Administrator) is **Critical**. |
| 3 | Credentials on all apps | Client secrets and certificates on every app registration and service principal with a start date inside the review window. Long-lived secrets are called out. |
| 4 | Entra audit log | Apps adding themselves (or others) to directory roles, apps changing other apps' credentials, and suspicious user agents (`Python-urllib`, `python-requests`, `curl`). |
| 5 | Sign-in logs | Vendor app service-principal sign-ins from non-Azure IPs; **all** sign-in types from the known attacker IP; sign-ins of apps whose credentials changed in the window. |
| 6 | Conditional Access | Policies that exclude the vendor apps, which would let attacker infrastructure through. |

Microsoft-managed credential rotations (the `P2P Server` certificate, managed identity certificates) are recognized and reported as **Info**, not as findings.

Output: an HTML report plus CSV files (findings, audit events, credentials, roles, sign-ins), rated **Critical / High / Medium / Info**.

---

## Requirements

- Windows PowerShell 5.1 or PowerShell 7+
- The `Microsoft.Graph.Authentication` module:

```powershell
Install-Module Microsoft.Graph.Authentication -Scope CurrentUser
```

### Permissions

The script signs in with **delegated** permissions through the *Microsoft Graph Command Line Tools* app.

| Delegated Graph scope | Used for |
|---|---|
| `Application.Read.All` | Service principals, app registrations, credentials |
| `Directory.Read.All` | Directory role members, tenant info |
| `RoleManagement.Read.Directory` | Role definitions, PIM-eligible assignments |
| `AuditLog.Read.All` | Entra audit log and sign-in logs |
| `Policy.Read.All` | Conditional Access policies |
| `Application.ReadWrite.All` | **Only** with `-DisableVendorApps` |

**Who can run it**

- **Global Reader** is enough for all read-only checks.
- `-DisableVendorApps` needs **Cloud Application Administrator** or **Application Administrator**.

**One-time consent:** the first run asks for admin consent for the scopes above. A Global Administrator, Privileged Role Administrator, or Cloud Application Administrator / Application Administrator can grant it. After that, a Global Reader can run the script.

**Licensing:** reading sign-in logs through the API requires **Entra ID P1 or P2**. Without it, the script reports how to check the portal manually and runs every other check.

> ⏱️ **Run it soon.** Tenants without P1/P2 keep audit logs for only 7 days, so events from October 13–15 will age out quickly. Tenants with P1/P2 keep 30 days.

---

## Quick start

```powershell
# Download the script, then:
Unblock-File .\Invoke-CWSkyKickIOCCheck.ps1

# Read-only assessment of your home tenant
.\Invoke-CWSkyKickIOCCheck.ps1

# A specific tenant, custom output folder
.\Invoke-CWSkyKickIOCCheck.ps1 -TenantId contoso.onmicrosoft.com -OutputPath C:\IR\contoso

# Assess, then disable (never delete) any enabled ConnectWise/SkyKick apps - prompts per app
.\Invoke-CWSkyKickIOCCheck.ps1 -DisableVendorApps
```

### Parameters

| Parameter | Description |
|---|---|
| `-TenantId` | Tenant ID or domain. Defaults to the signed-in account's home tenant. |
| `-StartDate` / `-EndDate` | Review window, treated as UTC. Default: 2026-10-13 00:00 UTC to now. |
| `-OutputPath` | Output folder. Default: `.\CW-SkyKick-IOC-<timestamp>` |
| `-SkipSignInLogs` | Skip sign-in queries (fast run, or no P1/P2). |
| `-DisableVendorApps` | After the assessment, disable enabled vendor service principals. Requires extra permission and confirmation. |
| `-UseDeviceCode` | Device-code sign-in for hosts without a browser. |

**MSPs:** the script assesses one tenant per run. Run it in each customer tenant.

---

## Output

| File | Contents |
|---|---|
| `Report.html` | Summary and all findings, sorted by severity |
| `Findings.csv` / `Findings.json` | All findings |
| `VendorServicePrincipals.csv` | ConnectWise/SkyKick service principals found |
| `ServicePrincipalRoles.csv` | Directory roles held by service principals |
| `AppCredentials.csv` | Every secret and certificate on apps and service principals |
| `AuditEvents.csv` | Relevant audit events with initiator, user agent and flags |
| `SignIns-*.csv` | Sign-in results (written only when there is data) |
| `ConditionalAccessExclusions.csv` | CA policies excluding the vendor apps |

> ⚠️ **The output contains sensitive tenant data.** Do not commit it or attach it to public issues.

### Interpreting results

- **Critical:** strong indicator of compromise (vendor app with a privileged role, vendor app changing credentials, successful sign-in from the attacker IP). Start incident response.
- **High:** needs validation (a new credential on an app, an app-initiated role change, a suspicious user agent). Confirm with the app owner.
- **Medium:** review (privileged roles held by other apps, CA exclusions, sign-ins from the Azure IPv6 range during the persistence window).
- **Info:** context, clean results, and Microsoft-managed rotations.

---

## Limitations

- **A clean result does not prove the tenant was not accessed.** Reads through Microsoft Graph by an application are not audited.
- **Credential start dates can be set by whoever creates the credential.** The audit-log check is the stronger evidence.
- **Mailbox and file access is not covered.** Use the Purview Unified Audit Log (for example `MailItemsAccessed`, `FileDownloaded`) filtered by the vendor App IDs.
- Sign-in queries use the Microsoft Graph **beta** endpoint, which is required for service-principal sign-ins.

---

## Indicators used

| Indicator | Type |
|---|---|
| `144.172.64[.]128` | Attacker IP (AS14956) |
| `506e08f9-6e9a-4da4-942b-a099a03644ae` | ConnectWise Cloud Backup (formerly SkyKick) |
| `2399d300-6fca-4e6a-a686-399fefe75b83` | ConnectWise Cloud Management |
| `24205314-2b89-4e07-a2a4-579e898a5640` | ConnectWise Cloud Management - MS Teams |
| `b78f6a77-d4e5-46fb-87e5-d1648bd02519` | ConnectWise Cloud Management - Exchange Online |
| `0de14c77-b9b0-4137-9360-34878a929827` | ConnectWise Cloud Management - MS Graph |
| `412dcf96-176d-4b3a-a1b0-4981ad66971e` | ConnectWise Cloud Management - Partner Center |
| `b2b55f5b-7758-4719-8d8f-88ae172e6bdb` | ConnectWise Cloud Management - SharePoint Online |
| `3f9cd7a0-127a-4ed4-bf06-2f830d5616b7` | Vendor app owner tenant ID |
| `Python-urllib/3.12`, `python-requests/2.31`, `curl/7.88.1` | User agents (low fidelity alone) |

Source: [Huntress advisory](https://www.huntress.com/blog/vendor-credential-enables-unauthorized-access). Check it for updates; the indicators in this script may lag behind.

---

## If you find something

Follow the vendor and Huntress guidance:

1. **Disable** (do not delete) the ConnectWise / SkyKick enterprise applications. Deleting removes the consent.
2. Remove directory roles you did not intentionally grant to those apps.
3. Remove unexpected secrets and certificates from **all** apps, especially management and security tools.
4. Review Conditional Access exclusions for the vendor apps.
5. Do not re-enable the vendor apps until ConnectWise confirms all credentials were reset.

---

## Contributing

Issues and pull requests are welcome: new indicators, false-positive tuning, or extra checks. Please **never** include tenant output, IDs or logs from a real environment in an issue.

## Credits

Research and indicators: [Huntress](https://www.huntress.com/blog/vendor-credential-enables-unauthorized-access).

## Disclaimer

Provided as-is, without warranty. Test it in a non-production tenant first. You are responsible for how you use it in your environment.

## License

[MIT](LICENSE)
