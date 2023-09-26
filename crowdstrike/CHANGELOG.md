# 2.0.0
## Added
- Handled API rate limit.
- Added debug logs throughout the plugin.
- Added support of IPv4 and IPv6 in pull and push mechanisms.
- Added the capability to update the indicators as part of the "Perform Action" target action.
- Added support of "Isolate/Remediate Hosts" action in sharing configuration.
- Added the support of pulling indicators from CrowdStrike Custom IOC Management.
## Changed
- Improved error handling.
- Updated "Type of Threat data to pull" configuration parameter to allow pulling specific types of indicators.
# 1.0.3
## Fixed
- Fixed an issue with unsupported detection types.
- Updated the logic for verifying the existence of indicators in IOC Management page.

# 1.0.2
## Added
- Added pagination and timeout support in pull method's API calls.

# 1.0.1
## Changed
- Changed CrowdStrike CTE APIs in place of deprecated APIs.
## Fixed
- Fixed missing IoC types.

# 1.0.0
## Added
- Initial Release.