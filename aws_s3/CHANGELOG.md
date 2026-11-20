# 1.3.0 (Requires minimum Cloud Exchange version 6.1.0)
## Added
- Added support for Custom Region and Externally Provisioned Bucket in the configuration parameters.
- Added resolutions for error logs.
- Added the JSON format option.

## Changed
- Updated the object file name format to <epoch>_<thread_id>_<uuid>.gz to prevent data overwrite when data is ingested at the exact same time.

## Fixed
- Fixed the error observed while sharing WebTx data using NLS.
- Fixed proxy settings not being applied to AWS IAM Roles Anywhere requests.

# 1.2.0
## Added
- Added two new authentication methods.
## Removed
- Removed secret credentials for authentication.
## Changed
- Updated object structure in push functionality.

# 1.1.0
## Changed
- Added support for few regions.
- Changed the plugin name

# 1.0.0
## Added
- Initial release.