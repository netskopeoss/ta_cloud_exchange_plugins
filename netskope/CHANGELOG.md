# 2.6.0 (Required minimum CE version for this is 7.0.0)
## Added
- Added support for prefixing CIDR IOCs and RANGE IOCs when sharing them to the destination profile.
- Added support for ipv4 CIDR IOCs when sharing them to the private app and url list.

## Updated
- Updated the Private App sharing logger to include the count of skipped IOCs due to unsupported types.
- Updated the FQDN validation regex to support hostnames with multiple labels for Private App sharing.
- Enhanced sharing actions with skipped_iocs tracking to ensure unsupported IOCs retain the correct "Sharing Result" status after retract and un-retract cycles.
- Improved “Unshared” tagging to ensure all IOCs that fail to be shared are consistently marked as “Unshared” across sharing actions.

## Fixed
- Added unique destination key mappings for Private App and File Hash List to prevent data from being overwritten by other actions.

# 2.5.0
## Added
- Added support for DNS Profile sharing and push retraction.
- Added logic for skipping tags longer than 30 characters for Private App sharing action.

# 2.4.0
## Added
- Added support for Destination Profile sharing and delete retraction.
- Added delete retraction for URL List.
- Added resolution for error logs.
## Changed
- Updated URL List sharing to share only modified indicators.
- Updated error log to info log when duplicate file hashes are shared.
- Updated sharing behavior irrespective of selected IOC types in configuration.

# 2.3.0
## Added
- Added configuration option to enable/disable querying Retrohunt API.
## Fixed
- Fixed tagging of indicators while sharing.

# 2.2.0
## Added
- Added support for retraction of False Positive if IoC type is File Hash.
- Added support for port range in Add to Private App Target.
- Added support for severity in URL IoCs.
## Changed
- Pull only malicious file hash IoCs using Retrohunt.
- Updated URL List limit to 7 MB from 8 MB.

# 2.1.3
## Changed
- Bug fixes.

# 2.1.2
## Added
- Added support to create indicators from SHA256 and MD5 fields, along with Local SHA256 and Local MD5, from malware alerts.

# 2.1.1
## Changed
- Updated authentication for V1 token.

# 2.1.0
## Added
- Added support for retraction of retracted IoCs. It does not support fetching retracted indicators from the Netskope tenant.

# 2.0.0
## Changed
- The Netskope CTE plugin has been restructured and is now available in the Default repository.

# 1.0.0
## Added
- Initial release.