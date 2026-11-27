# 1.1.0 (Requires minimum Cloud Exchange version 6.1.0)
## Added
- Added support for Netskope Alerts and Events.
- Added validation of the mapping file.
- Added the Compression configuration parameter to store blobs either gzip-compressed (`.json.gz`, default) or uncompressed (`.json`).
- Added validation for the Object Prefix, ingestion format and container connectivity.
## Changed
- Changed the Azure Connection String to a password type parameter.
- Changed blob names to carry a file extension and blobs to be written as JSON Lines, gzip-compressed (`.json.gz`) by default. Select None in the Compression parameter to store uncompressed (`.json`) blobs.
- Changed blobs to be stored in folders by Object Prefix, data type, subtype and upload hour (UTC), e.g. `netskope/alerts/feedname=dlp/year=2026/month=11/day=24/hour=9/`.
## Removed
- Removed the Maximum Duration (in Seconds) and Maximum File Size (in MBs) configuration parameters.
## Fixed
- Fixed the push failing with a type error for WebTx data received from Netskope Log Streaming.
- Fixed ingestion for selected field in JSON format.
- Fixed skipped logs handling in the plugin so that logs that could not be ingested are reported back to Cloud Exchange instead of being counted as ingested.

# 1.0.1
## Changed
- Changed plugin name to Microsoft Azure Cloud Storage.

# 1.0.0
## Added
- Initial release.
