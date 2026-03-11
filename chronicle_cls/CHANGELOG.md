# 3.0.0
## Added
- Added support for invoking mapping validation separately.
- Added resolution for error logs starting from CE v6.0.0.
## Changed
- Enhanced the efficiency of database interactions.
- Changed error logs to debug in UDM generator to prevent log pileup in CE.

# 2.2.0
## Added
- Added support for raw JSON data.

# 2.1.0
## Added
- Added support for CTEP alert type.
- Added support for incident event type.

## Fixed
- Bug fixes and improvements in transformation.

# 2.0.2

## Fixed
- Fixed transformation to convert the data into the valid UDM format.

## Removed
- Removed justification_type and justification_reason from mappings.

# 2.0.1
## Changed
- Changed plugin name to Google Chronicle.

# 2.0.0
## Added
- Added support to sent raw data to the SIEM Platform.

# 1.4.0
## Added
- Added support for region selection.

# 1.3.1
## Changed
- Mapped 'security_result.action_details' UDM field to Netskope field 'action'.

# 1.3.0
## Changed
- Removed valid extension from plugin configuration.
- Updated mapping file with transformation fields.

# 1.2.0
## Changed
- Updated Chronicle APIs to v2.

# 1.1.0
## Changed
- Added Chronicle Parser to ingest data with proper event types.

# 1.0.0
## Added
- Initial release.