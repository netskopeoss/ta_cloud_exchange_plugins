# 1.2.0
## Fixed
- The pull functionality now includes an option to choose whether to extract only the domain name or use the full URL. For example, if the URL is google.com/abc/xyz, selecting Yes will extract only the domain google.com, while selecting No will retain the full URL google.com/abc/xyz. This setting is applicable only when the indicator type 'URL' is selected in the 'Type of Threat Data to Pull' configuration parameter.

# 1.1.1
## Fixed
- Fixed Bugs in Pull Functionality.

# 1.1.0
## Changed
- Renamed plugin from 'External Website' to 'Web Page IOC Scraper'.
## Added
- Added support to bifurcate the URL by types (Domain, IPv4, IPv6) starting from CE v5.0.1.

# 1.0.0
## Added
- Initial release.