# 1.1.0 (Required minimum CE version for this is 6.1.0)
## Added
- Added `Azure Cloud` configuration parameter to support Azure US Government, Azure China (21Vianet), and Custom Cloud tenants.
- Added validation of the 'DCE URI' format and a check that it belongs to the selected 'Azure Cloud'.
## Changed
- Updated default mappings.
- Updated the dynamic configuration to be conditional based on the required parameters.
## Fixed
- Fixed AADSTS900382 (Confidential Client is not supported in Cross Cloud request) for non-public cloud tenants.
- Fixed ingestion requests exceeding the 1 MB API limit when the data contains non-ASCII characters.

# 1.0.0
## Added
- Initial release
  - Log Types: Alerts, Events, WebTx
  - Transformation: CEF(only supported in 'Single Table' mode) and JSON