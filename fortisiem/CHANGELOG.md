# 1.1.0 (Requires minimum Cloud Exchange version 6.1.0)
## Added
- Added support for Device and Content in alerts and Client Status in events.
- Added configuration parameters Exclude Timestamp Field, Exclude Log Source Identifier Field and Exclude Priority Field.
- Added the JSON format option.
- Added connection timeout and retry handling for data ingestion.
- Added resolutions to the error logs.
## Changed
- Updated the default mappings.
## Fixed
- Fixed TLS protocol support for Python 3.12 and later by replacing the removed ssl.wrap_socket() with SSLContext.
- Fixed data loss when ingestion to FortiSIEM fails.
- Fixed mapping of nested fields.

# 1.0.0
## Added
- Initial release.
- Added support for the Endpoint event type. The pull and ingestion is supported from CE version 5.1.0.
