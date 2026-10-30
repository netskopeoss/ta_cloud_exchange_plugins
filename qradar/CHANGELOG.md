# 4.0.0 (Requires minimum Cloud Exchange version 6.1.0)
## Added
- Added configuration parameters Exclude Timestamp Field, Exclude Log Source Identifier Field and Exclude Priority Field.
- Added support for the Device and Content alert types and the Endpoint event type, the Client Status event type and the Debug logs type, along with the Supporting Data and Details fields for the Audit events, the Activity field for the other Alerts and Events, the Publisher fields for the Network events, and the JA3 fields for the Application events and WebTx, to the default mappings.
- Added the CEF and JSON format options.
- Added connection timeout and retry handling for data ingestion.
- Added resolutions to the error logs.
## Changed
- Added the syslog header to JSON-formatted data.
- Updated the default WebTx and Logs mappings.
- Removed the QRadar Format parameter.
- Changed warning logs to debug logs.
## Fixed
- Fixed TLS support for Python 3.12 and later.
- Fixed data loss when ingestion to QRadar fails.
- Fixed mapping of nested fields.
- Fixed ingestion of logs in JSON format.

# 3.1.0
## Added
- Added support for webtx JSON format to send specific fields to SIEM platform.

# 3.0.0
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

# 2.0.1
## Added
- Added Incident ID mapping field in all alerts and events.

# 2.0.0
## Added
- Added support to sent raw data to the SIEM Platform.

# 1.2.3
## Fixed
- Fixed Severity mappings for Audit events.

# 1.2.2-beta
## Added
- Added support for Syslog service plugin for Netskope CE.

# 1.2.1
## Changed
- Updated the mapping file for timestamp related fields

# 1.2.0
## Added
- Added Log Source Identifier as configurable field.

# 1.1.1
## Added
- Updated webTx mappings.

# 1.1.0
## Changed
- Removed valid extension from plugin configuration.
- Updated mapping file with transformation fields.

# 1.0.0
## Added
- Initial release.