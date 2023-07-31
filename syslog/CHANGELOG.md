# 3.1.0
## Added
- Added support for webtx JSON format to send specific fields to SIEM platform

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

# 1.2.2
## Fixed
- Fixed Severity mappings for Audit events.

# 1.2.1
## Added
- Added support for Syslog service plugin for Netskope CE.

# 1.2.0
## Added
- Added Log Source Identifier as configurable field.

# 1.1.1
## Added
- Updated webTx mappings.

# 1.1.0
## Added
- Support for web transaction logs ingestion.
## Removed
- Valid extensions from plugin configuration.
- Transformations from the plugin.

# 1.0.0
## Added
- Initial release.
