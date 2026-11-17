# 2.2.0 (Requires minimum Cloud Exchange version 6.1.0)
## Added
- Added support for Device and Content in alerts and Endpoint and Client Status in events.
- Added configuration parameters Exclude Timestamp Field and Exclude Log Source Identifier Field for JSON-formatted data.
- Added the CEF and JSON format options.
- Added connection timeout and retry handling for data ingestion.
- Added resolutions to the error logs.
## Changed
- Renamed the plugin from Secureworks to Sophos Fusion.
- Updated the default mappings.
- Added the syslog header to JSON-formatted data.
- Changed warning logs to debug logs.
## Fixed
- Fixed TLS protocol support for Python 3.12 and later by replacing the removed ssl.wrap_socket() with SSLContext.
- Fixed data loss when ingestion to Sophos Fusion fails.
- Fixed mapping of nested fields.

# 2.1.0
## Added
- Added support for webtx JSON format to send specific fields to SIEM platform

# 2.0.0
## Added
- Added Support for the incident event type. To pull and ingest this event type update your CE version to 4.1.0
- Added Support for the CTEP alert type. To pull and ingest this alert type update your CE version to 4.2.0.
- Added support for WebTx format3.
## Changed
- Changed error logs to warning if single field is skipped.
## Fixed
- Fixed JSON format of raw data.
## Removed
- Removed priority from the syslog message for the logs that are not transformed in CEF.

# 1.0.0
## Added
- Initial release.
