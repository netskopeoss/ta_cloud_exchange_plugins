# 1.1.0 (Requires minimum Cloud Exchange version 6.1.0)
## Added
- Added configuration parameters Exclude Timestamp Field, Exclude Log Source Identifier Field and Exclude Priority Field for JSON-formatted data.
- Added the CEF and JSON format options.
- Added connection timeout and retry handling for data ingestion.
- Added resolutions to the error logs.
## Changed
- Updated the default mappings.
- Changed warning logs to debug logs.
## Fixed
- Fixed TLS protocol support for Python 3.12 and later by replacing the removed ssl.wrap_socket() with SSLContext.
- Fixed data loss when the Darktrace server closes the connection.
- Fixed mapping of nested fields.

# 1.0.0
## Added
- Initial release.
