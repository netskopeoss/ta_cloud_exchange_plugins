# 1.1.0 (Requires minimum Cloud Exchange version 7.0.0)
## Added
- Added dynamic configuration field support for the Authentication Method. The 'AWS IAM Roles Anywhere' parameters (Private Key, Certificate Body, Password Phrase, Profile ARN, Role ARN and Trust Anchor ARN) are now shown only when that authentication method is selected.
## Changed
- Pulled alerts, events and webtx logs are now tagged with the format they were serialized in, so Cloud Exchange parses each batch by its declared format instead of inferring it from the content.
## Updated
- Updated configuration validation, credential handling, and AWS region validation. 

# 1.0.0
## Added
- Initial release.