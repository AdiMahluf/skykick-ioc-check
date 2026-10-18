# Changelog

## [1.2.0] - 2026-10-18
### Added
- **Attacker-network hunt** (`-AttackerASNs`, default AS14956 RouterHosting) across interactive, non-interactive and service-principal sign-ins, with a longer look-back (`-AsnStartDate`, default 2026-10-01). User sign-ins are matched by ASN (server-side filter, every returned row verified, local fallback if Graph rejects or ignores the filter). Service-principal sign-ins carry no ASN, so they are matched against the ASN's announced IP prefixes, looked up at run time from RIPEstat (`-SkipPrefixLookup` to disable, `-AttackerCidrs` to add ranges). Newly discovered attacker addresses are reported and reused by the Exchange IP search.
- **All-app sign-in sweep**: every service-principal sign-in from non-Microsoft networks, rated by whether the app had a credential change or holds privileged access.
- **Credential usage correlation**: sign-ins are tied to the credential KeyId used. Flags a credential created during the window that is in use, and reviews active credentials on Microsoft first-party apps (e.g. Azure Multi-Factor Auth Client) with per-credential usage. `AppCredentials.csv` gains SignInsSinceLookback, LastUsedUtc and UsedFromIPs.
- **Application permission review**: Microsoft Graph, Exchange Online and SharePoint app roles held by apps; tenant-takeover permissions and grants made during the window are flagged.
- **Federated identity credential** inventory, with uncommon issuers flagged.
- **Directory roles** inherited through role-assignable groups and administrative-unit scopes.
- **Audit log** now covers UserManagement, GroupManagement, Policy and DirectoryManagement: password and authentication-method changes, new users and guests, role-assignable group membership, Conditional Access and tenant policy changes, domain federation changes and partner changes. Consents and grants are evaluated on the permissions they newly add, not on scopes the grant already held. Microsoft first-party activity (PIM activations, managed rotations) and the consent prompt for this tool are reported as Info.
- **Workload identity risk** (risky service principals and detections, where licensed).
- **Federated domain** review with issuer, sign-in URL and signing-certificate details.
- **GDAP / DAP review** for partner tenants (`-PartnerTenant`).
- **Exchange Online** (`-IncludeExchange`, `-IncludeInboxRules`, `-ExchangeDelegatedOrganization`): Unified Audit Log search for mail-flow, mailbox-permission and Exchange RBAC persistence and for all activity from attacker IPs; current forwarding, transport rules, connectors, Exchange RBAC for applications, external auto-forwarding and inbox rules.
- **Coverage table** in the report and `Coverage.csv`; queries that hit their cap raise a finding.
- `-AdditionalAttackerIPs`, `-MaxSignIns`, `-SkipAsnHunt`.
- `Invoke-CWSkyKickIOCCheckBulk.ps1` for multi-tenant (MSP) runs with a combined summary.
- `hunting/sentinel-hunting.kql`: Microsoft Graph activity log, network, audit and Microsoft 365 activity queries.

### Changed
- Two new delegated scopes (`Domain.Read.All`, `IdentityRiskyServicePrincipal.Read.All`): the first 1.2 run asks for consent again.
- Vendor app sign-ins from public Azure addresses are Medium (previously High as "public IP"); sign-ins from the attacker network are Critical.
- Sign-in queries default to a 50000-record cap (was 5000) and report when the cap is reached.
- Attacker IP sign-ins are checked from `-AsnStartDate`, not only from `-StartDate`.
- Sign-ins without an ASN are shown as "ASN n/a".

## [1.1.0] - 2026-10-18
### Changed
- Microsoft-managed credential rotations are reported as Info: the `P2P Server` certificate (rotated by Azure ESTS Service) and managed identity certificates.
- A signing certificate (keyCredential + passwordCredential with the same KeyId) is reported once instead of twice.
- CSV timestamps are written in ISO 8601 UTC, independent of the local date format.
- SAML signing-certificate rotations are rated Medium; long-lived credentials (18+ months) are called out.
- A clean ConnectWise sign-in result is reported as an explicit Info finding.
- Version shown in console output and the HTML report.

## [1.0.0] - 2026-10-18
### Added
- Initial release: vendor service principals, directory roles held by apps, credentials added in the window, Entra audit log analysis, sign-in log checks, Conditional Access exclusions, optional `-DisableVendorApps`, HTML and CSV report.
