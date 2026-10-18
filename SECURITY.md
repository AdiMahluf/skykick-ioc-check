# Security

## Reporting a problem with the script
If you find a bug that could cause the script to change something it should not, or to miss a known indicator, open an issue or contact the maintainer privately through GitHub.

## Do not share tenant data
The script output (CSV, JSON, HTML) contains tenant IDs, application IDs, user names, IP addresses and audit events. Never post it in issues, pull requests or discussions. Redact anything you share.

## Network connections
Besides Microsoft Graph and (with `-IncludeExchange`) Exchange Online, the script makes one outbound request per attacker ASN to RIPEstat (`stat.ripe.net`) to look up the ASN's announced IP prefixes. Only the ASN number is sent; no tenant data leaves the machine. Use `-SkipPrefixLookup` to disable it.

## Reporting the incident itself
This project does not handle incident reports. Contact ConnectWise, Huntress, Microsoft or your incident response provider.
