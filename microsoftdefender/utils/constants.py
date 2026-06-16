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

CTE Microsoft Defender for Endpoint plugin constants.
"""

MODULE_NAME = "CTE"
PLUGIN_NAME = "Microsoft Defender for Endpoint"
PLUGIN_VERSION = "1.4.0"
MAX_API_CALLS = 4
DEFAULT_SLEEP_TIME = 60
MAX_WAIT_TIME = 300
MAXIMUM_CE_VERSION = "5.1.2"
RETRACTION = "Retraction"

INDICATOR_ENDPOINT = "{base_url}/api/indicators"
BATCH_DELETE_ENDPOINT = "{base_url}/api/indicators/BatchDelete"
DATE_TIME_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
IOC_SOURCE_LENGTH = 200
PAGE_SIZE = 10000
RETRACTION_FETCH_BATCH_SIZE = 20   # max values per OData filter clause
RETRACTION_DELETE_BATCH_SIZE = 500  # MDE BatchDelete API limit
DAYS_LIMIT = 365

EMPTY_ERROR_MESSAGE = "{field_name} is a required {parameter_type} parameter."
TYPE_ERROR_MESSAGE = (
    "Invalid value provided for the {parameter_type} parameter '{field_name}'."
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
VALIDATION_ERROR_MSG = "Validation error occurred."
INVALID_VALUE_ERROR_MESSAGE = " Allowed values are {allowed_values}."

CHECK_TENANT_ID_ERROR = "check your tenant name or GUID is correct"

YES_NO_PARAMETER = {
    "Yes": "Yes",
    "No": "No",
}
IOC_GENERATED_ALERT = {
    "True": True,
    "False": False,
    "Both": "Both"
}
ACTIONS = {
    "Warn": "Warn",
    "Block": "Block",
    "Audit": "Audit",
    "BlockAndRemediate": "BlockAndRemediate",
    "Allowed": "Allowed",
}
THREAT_TYPES = {
    "SHA256": "FileSha256",
    "MD5": "FileMd5",
    "Domain": "DomainName",
    "URL": "Url",
    "IPv4": "IpAddressV4",
    "IPv6": "IpAddressV6",
}
VALID_BASE_URLS = {
    "api.securitycenter.microsoft.com": "https://api.securitycenter.microsoft.com", # noqa
    "us.api.security.microsoft.com": "https://us.api.security.microsoft.com",
    "eu.api.security.microsoft.com": "https://eu.api.security.microsoft.com",
    "uk.api.security.microsoft.com": "https://uk.api.security.microsoft.com",
    "au.api.security.microsoft.com": "https://au.api.security.microsoft.com",
    "swa.api.security.microsoft.com": "https://swa.api.security.microsoft.com",
    "ina.api.security.microsoft.com": "https://ina.api.security.microsoft.com",
    "aea.api.security.microsoft.com": "https://aea.api.security.microsoft.com",
    "api-gcc.securitycenter.microsoft.us": "https://api-gcc.securitycenter.microsoft.us", # noqa
    "api-gov.securitycenter.microsoft.us": "https://api-gov.securitycenter.microsoft.us", # noqa
}
