# 3.1.0
## Added
- Added support for pulling ipv4 and ipv6 and Domain for STIX/TAXII version 2.x.
- Added support to bifurcate the URL by types (Domain, IPv4, IPv6).
## Fixed
- Fixed the plugin validation method.

# 3.0.0
## Added
- Added "Pagination Method" configuration parameter.
## Changed
- In Taxii versions 2.0 and 2.1, data retrieval is divided into chunks. Each retrieval cycle restricted to fetching up to 100 bundles, each containing 1000 objects.

# 2.1.0
## Added
- Added new configuration parameter named Look Back. This can be used to backdate the start time for pulling the data.

# 2.0.3
## Added
- Added changes to make the plugin compatible with the core version 4.1.0.

# 2.0.2
## Added
- Added log statements for better understanding.

# 2.0.1-beta
## Fixed
- Fixed an issue related to the SSL verification.

# 2.0.0
## Added
- Added support for version 2.1.

# 1.0.0
## Added
- Initial Release.