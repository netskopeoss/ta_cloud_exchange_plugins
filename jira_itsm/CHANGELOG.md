# 2.1.1
## Fixed
- Bug fixes.

# 2.1.0
## Changed
- Changed deprecated API '/rest/api/3/search' with new API '/rest/api/3/search/jql'.
## Fixed
- Bug fixes.

# 2.0.0
## Added
- Added support for Endpoint and Incident Events.
- Added support for storing updates of Severity and Assignee along with status.
## Changed
- Changed deprecated API '/issue/createmeta' with new API '/createmeta/{projectIdOrKey}/issuetypes/{issueTypeId}'.
- Changed the storage behavior to store old and new both the values for assignee and status.

# 1.1.0
## Added
- Added support for more Jira fields while creating tickets.
- Added retry mechanism while creating/updating tickets.

# 1.0.3
## Added
- Added support for labels while creating issues.

# 1.0.2
## Fixed
- Fixed newline error while adding summary in queue.

# 1.0.1
## Added
- Added Append metadata to original ticket.

## Changed
- Changed default mappings.

# 1.0.0
## Added
- Initial release.