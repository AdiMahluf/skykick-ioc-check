# Changelog

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
