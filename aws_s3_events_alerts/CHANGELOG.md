# 1.3.0 (Minimum required CE version 6.0.0)
## Added
- Added support for external provisioned buckets.
- Added resolutions for error logs.
## Changed
- Changed bucket existence and connectivity checks to use HeadBucket,
  which requires only the `s3:ListBucket` permission on the target
  bucket instead of the account-wide `s3:ListAllMyBuckets` permission.

# 1.2.0
## Added
- Added support for dynamic field population based on selected Authentication Method. To use the dynamic field population feature update your CE version to 6.0.0.

# 1.1.0
## Added
- Added two new authentication methods.
- Added Support for the incident event type. To pull and ingest this event type update your CE version to 4.1.0
- Added Support for the CTEP alert type. To pull and ingest this alert type update your CE version to 4.2.0.
## Removed
- Removed secret credentials for authentication.
## Changed
- Updated object structure in push functionality.

# 1.0.0
## Added
- Initial release.
