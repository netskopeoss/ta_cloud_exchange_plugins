# 1.1.0
## Added
- Added support of sharing indicators of type URL(IPv4, IPv6 and DNS).
## Changed
- Updated the API version from v6 to v7 for retrieving the indicators.
## Fixed
- Fixed an error while sharing indicators to Carbon Black.


# 1.0.5
## Added
- Added retry mechanism for the "Too many requests" (429) status code.
## Fixed
- Fixed pagination when there are more than 10k iocs.

# 1.0.4
## Fixed
- Fixed an issue where empty indicators were being created on Carbon Black.

# 1.0.0
## Added
- Initial release.