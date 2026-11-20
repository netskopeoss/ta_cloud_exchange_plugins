# 1.1.0 (Requires minimum Cloud Exchange version 6.1.0)
## Added
- Added support for the Content and Device alert types, Client Status event type and WebTx v2 type in the default mappings.
- Added the JSON format option.
- Added resolutions for error logs.

## Changed
- Updated the object file name format to <epoch>_<thread_id>_<uuid>.<extension> to prevent data overwrite when data is ingested at the exact same time.

## Fixed
- Fixed the error observed while sharing WebTx data using NLS.
- Fixed temporary files not being removed when an upload fails.

# 1.0.0
## Added
- Initial release.
