# 2.1.0 (Required minimum CE version for this is 6.1.0)
## Added
- Added `Azure Cloud` configuration parameter to support Azure US Government, Azure China (21Vianet), and Custom Cloud tenants.
- Added validation of the 'DCE URI' format and a check that it belongs to the selected 'Azure Cloud'.
## Changed
- Updated default mappings.
- Renamed the "Incident ID" field of Network events to "transaction_id" in the default mapping.
## Fixed
- Fixed AADSTS900382 (Confidential Client is not supported in Cross Cloud request) for non-public cloud tenants.
- Fixed ingestion requests exceeding the 1 MB API limit when the data contains non-ASCII characters.
- Fixed retry handling for API rate limit (429) and server errors (5xx), which were not retried.

# 2.0.0
## Added
- Added support for the content and device alert type.
- Added support for clientstatus and endpoint events.
- Added support for JA3 fields in Application events.
- Added support for invoking mapping validation separately.
- Added support for log source identifier.
- Added support for storing access token in the storage.
## Changed
- Enhanced the efficiency of database interactions.
- Updated the mappings for Network events and Audit events.
## Fixed
- Fixed CEF transformation for nested JSON fields in data.
- Fixed ingestion for selected field in JSON format.

# 1.1.0
## Added
- Added Support for the incident event type. To pull and ingest this event type update your CE version to 4.1.0.
- Added Support for the CTEP alert type. To pull and ingest this alert type update your CE version to 4.2.0.

# 1.0.0
## Added
- Initial release.
