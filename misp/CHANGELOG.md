# 1.5.0
## Added
- Added support for IoC(s) Retraction.
- Added support for IoC Source Labelling.
- Added support for pulling Hostname, Destination IP (ip-dst), Destination IP|Port (ip-dst|port), Domain|IP (domain|ip), Source IP|Port (ip-src|port),  and Hostname|Port (hostname|port) from MISP.

# 1.4.1
## Added
- Added support for accepting multiple events in the "Exclude IoCs from Event" parameter.

# 1.4.0
## Added
- Added support for pulling indicators on the basis of Decaying Score Threshold, Decaying Model IDs, Published Events, IDS flag and Enforce Warning List IoCs flag.
- Added support to divide the URL by types (Domain, IPv4, IPv6) starting from CE v5.0.1.
- Added "netskope-ce" tag when sharing IOCs to fix the issue creating the IoC cycle in Cloud Exchange.

# 1.3.0
## Added
- Added additional optimizations for large number of indicators.

# 1.2.0
## Added
- Added batching of 2500 in push functionality.
- Added new configuration parameters for defining the pulling mechanism (Incremental or Look Back) and the look back time in hours.

# 1.1.0
## Added
- Added new configuration parameters.

# 1.0.0
## Added
- Initial release.