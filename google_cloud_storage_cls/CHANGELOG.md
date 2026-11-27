# 2.0.0 (Requires minimum Cloud Exchange version 6.1.0)
## Added
- Added support for sharing Alerts and Events data.
- Added a mappings file declaring the Alert, Event and WebTx subtypes supported by the plugin. 
- Added validation of the mapping file.
- Added the Custom Region configuration parameter.
- Added the Compression configuration parameter to store objects either gzip-compressed (`.json.gz`, default) or uncompressed (`.json`).
- Added resolutions for error logs.
- Added User-Agent to the requests sent to Google Cloud Storage.

## Changed
- Updated the validation of the configuration parameters and the validation messages.
- The proxy and SSL validation settings of Cloud Exchange are now applied to all the requests.
- Updated the plugin icon.
- Changed objects to be stored in folders by Object Prefix, data type, subtype and upload hour (UTC), e.g. `netskope/alerts/feedname=dlp/year=2026/month=11/day=24/hour=9/`.

## Removed
- Removed the Maximum Duration (in Seconds) and Maximum File Size (in MBs) configuration parameters.

## Fixed
- Fixed the `a bytes-like object is required, not 'dict'` error observed while pushing WebTx data.
- Fixed the bucket verification, which needed permission to list all the buckets of the project. It now needs only the `storage.buckets.get` permission on the configured bucket, and also checks that the Service Account has the `storage.objects.create` permission on it.
- Fixed sensitive data (private key) possibly appearing in the logs.
- Fixed ingestion for selected field in JSON format.
- Fixed empty and invalid logs that were skipped being counted as ingested.

# 1.0.0
## Added
- Initial release.
