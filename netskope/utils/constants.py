"""
BSD 3-Clause License

Copyright (c) 2021, Netskope OSS
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its
   contributors may be used to endorse or promote products derived from
   this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
"""

"""Netskope CTE Plugin constants."""

REGEX_FOR_MD5 = r"^[0-9a-fA-F]{32}$"
REGEX_FOR_SHA256 = r"^[0-9a-fA-F]{64}$"
REGEX_FOR_URL = r"^(\*.?)?(https?:\/\/)?[a-zA-Z0-9]+(\.[a-zA-Z0-9]+)*\.[a-zA-Z]+(\/[\w]*)*$"  # noqa
REGEX_HOST = (
    r"^(?!:\/\/)([a-z0-9-]{1,63}\.)?[a-z0-9-]{1,63}(?:\.[a-z]{2,})?$|"
    r"^(?:(?:25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\.){3}(?:25[0-5]|(?:2[0-4]|1\d|[1-9]|)\d)$"  # noqa
)
DESTINATION_PROFILE_EXACT_MATCH_PATTERN = (
    r'^'
    r'(?:'
        r'CIDR:(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)/(?:[0-9]|[12][0-9]|3[0-2])(?::[0-9]{1,5})?(?://[^\s]*|/[^\s]*|\?[^\s]*)?'  # noqa
        r'|'
        r'RANGE:(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)-(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(?::[0-9]{1,5})?(?://[^\s]*|/[^\s]*|\?[^\s]*)?'  # noqa
        r'|'
        r'(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(?::[0-9]{1,5})?(?://[^\s]*|/[^\s]*|\?[^\s]*)?'  # noqa
        r'|'
        r'\*\.(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z]{2,}(?::[0-9]{1,5})?(?://[^\s]*|/[^\s]*|\?[^\s]*)?'  # noqa
        r'|'
        r'(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}(?::[0-9]{1,5})?(?://[^\s]*|/[^\s]*|\?[^\s]*)?'  # noqa
    r')'
    r'$'
)
BATCH_SIZE = 10000
MAX_PUSH_INDICATORS = 300000
MAX_PUSH_HOSTS = 500
MAX_QUERY_INDICATORS = 500
URLS = {
    "V2_URL_LIST": "{}/api/v2/policy/urllist",
    "V2_URL_LIST_DEPLOY": "{}/api/v2/policy/urllist/deploy",
    "V1_FILEHASH_LIST": "{}/api/v1/updateFileHashList",
    "V2_URL_LIST_REPLACE": "{}/api/v2/policy/urllist/{}/replace",
    "V2_URL_LIST_APPEND": "{}/api/v2/policy/urllist/{}/append",
    "V2_DESTINATION_PROFILE": "{}/api/v2/profiles/destinations",
    "V2_DESTINATION_PROFILE_VALUES": (
        "{}/api/v2/profiles/destinations/{}/values"
    ),
    "V2_DESTINATION_PROFILE_DEPLOY": "{}/api/v2/profiles/destinations/deploy",
    "V2_PRIVATE_APP": "{}/api/v2/steering/apps/private",
    "V2_PRIVATE_APP_PATCH": "{}/api/v2/steering/apps/private/{}",
    "V2_PUBLISHER": "{}/api/v2/infrastructure/publishers",
    "V2_RETROHUNT_HASH_INFO": "{}/api/v2/nsiq/retrohunt/ioc/getinfo",
}
MODULE_NAME = "CTE"
PLUGIN_NAME = "Netskope Threat Exchange"
PLUGIN_VERSION = "2.4.0"
BYTES_TO_MB = 1024 * 1024
# Retraction Constant
RETRACTION = "Retraction"

MAX_RETRIES = 4
DEFAULT_SLEEP_TIME = 60
MAX_INITIAL_RANGE = 365
MAXIMUM_CE_VERSION = "5.1.2"
MAX_PROFILE_NAME_LENGTH = 100
MAX_PROFILE_DESC_LENGTH = 200
DESTINATION_PROFILE_BATCH_SIZE = 10

# Destination Profile Limits
DESTINATION_PROFILE_EXACT_TOTAL_LIMIT = 300000  # Total across all exact-type profiles
DESTINATION_PROFILE_EXACT_PER_PROFILE_LIMIT = 100000  # Per exact-type profile
DESTINATION_PROFILE_REGEX_TOTAL_LIMIT = 1000  # Total across all regex-type profiles

DUPLICATE_FILE_HASH_REQUEST = "Duplicate request, no change in file hashes"
PENDING_CHANGES_DETECTED = (
    "non-interactive operation on pending profile is not allowed"
)
RETRY_ERROR_MSG = (
    "Received exit code {status_code}, {error_reason} "
    "while {logger_msg}. Retrying after {wait_time} "
    "seconds. {retry_remaining} retries remaining."
)
NO_MORE_RETRIES_ERROR_MSG = (
    "Received exit code {status_code}, API rate limit "
    "exceeded while {logger_msg}. Max retries for rate "
    "limit handler exceeded hence returning status "
    "code {status_code}."
)
VALIDATION_ERROR_MSG = "Validation error occurred. "
INVALID_VALUE_ERROR_MESSAGE = " Allowed values are '{allowed_values}'"
EMPTY_ERROR_MESSAGE = "{field_name} is a required {parameter_type} parameter."
TYPE_ERROR_MESSAGE = (
    "Invalid value provided for the {parameter_type} parameter '{field_name}'."
)
ENABLE_TAGGING_OPTIONS = {
    "yes": "Yes",
    "no": "No",
}
ENABLE_POLLING_OPTIONS = {
    "Yes": "Yes",
    "No": "No",
}
TYPES_OF_THREATS_OPTIONS = {
    "MD5": "MD5",
    "SHA256": "SHA256",
    "URL": "URL",
}
URL_LIST_TYPE_OPTIONS = {
    "Exact": "Exact",
    "Regex": "Regex",
}
PROTOCOL_OPTIONS = {
    "UDP": "UDP",
    "TCP": "TCP",
}
USE_PUBLISHER_OPTIONS = {
    False: "No",
    True: "Yes",
}
MATCH_TYPE_OPTIONS = {
    "insensitive": "Exact (Case Insensitive)",
    "sensitive": "Exact (Case Sensitive)",
    "regex": "RegEx"
}
