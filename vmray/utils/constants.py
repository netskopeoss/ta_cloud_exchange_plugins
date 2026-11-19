"""
BSD 3-Clause License

Copyright (c) 2021, Netskope OSS
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice,
   this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its
   contributors may be used to endorse or promote products derived from
   this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
POSSIBILITY OF SUCH DAMAGE.

CTE VMRay plugin constants.
"""

MODULE_NAME = "CTE"
PLUGIN_NAME = "VMRay"
PLATFORM_NAME = "VMRay"
PLUGIN_VERSION = "1.0.0"
MAX_API_CALLS = 4
DEFAULT_WAIT_TIME = 60
PAGE_SIZE = 50
MAX_INTERVAL_DAYS = 100000
RETRACTION = "[Retraction]"

CE_TAG = "Netskope-CE"

DATE_FORMAT_VMRAY = "%Y-%m-%dT%H:%M:%S"

# IOC type classification regexes
FQDN_REGEX = r"^(?=.{1,253}$)((?!-)[A-Za-z0-9-]{1,63}(?<!-)\.){2,}[A-Za-z]{2,63}$"
DOMAIN_REGEX = r"^(?:\*\.)?[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}"

# VMRay API Endpoints
SUBMISSION_FINISH_TIME_ENDPOINT = (
    "/rest/submission/finish_time/{start}~{end}"
)
SAMPLE_IOC_ENDPOINT = "/rest/sample/{sample_id}/iocs"
SUBMIT_SAMPLE_ENDPOINT = "/rest/sample/submit"
SUBMISSION_SEARCH_ENDPOINT = "/rest/submission/search"
SUBMISSION_DELETE_ENDPOINT = "/rest/submission/{submission_id}"

# Verdict values
VERDICT_MALICIOUS = "malicious"
VERDICT_SUSPICIOUS = "suspicious"

ALL_RETRACTION_VERDICTS = [
    VERDICT_MALICIOUS, VERDICT_SUSPICIOUS
]

# Error message templates
EMPTY_ERROR_MESSAGE = (
    "{field_name} is a required {parameter_type} parameter."
)
TYPE_ERROR_MESSAGE = (
    "Invalid value provided for the {parameter_type}"
    " parameter '{field_name}'."
)
VALIDATION_ERROR_MESSAGE = "Validation error occurred."
INVALID_VALUE_ERROR_MESSAGE = " Allowed values are {allowed_values}."

RETRY_ERROR_MSG = (
    "Received exit code {status_code}, {error_reason}"
    " while {logger_msg}. Retrying after {wait_time}"
    " seconds. {retry_remaining} retries remaining."
)
NO_MORE_RETRIES_ERROR_MSG = (
    "Received exit code {status_code}, API rate limit"
    " exceeded while {logger_msg}. Max retries for rate"
    " limit handler exceeded hence returning status"
    " code {status_code}."
)
