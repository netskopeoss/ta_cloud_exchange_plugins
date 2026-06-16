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

CTE Darktrace plugin constants.
"""

from netskope.integrations.cte.models import IndicatorType

MODULE_NAME = "CTE"
PLUGIN_NAME = "Darktrace"
PLATFORM_NAME = "Darktrace"
PLUGIN_VERSION = "1.0.0"
MAX_API_CALLS = 4
MAXIMUM_CE_VERSION = "5.1.2"
INDICATOR_LIST_LIMIT = 100000
PUSH_BATCH_SIZE = 5000
RETRACTION = "Retraction"
SOURCE_LABEL = "Netskope CE"
DEFAULT_WAIT_TIME = 60

DATE_FORMAT = r"%Y-%m-%dT%H:%M:%S.%f%zZ"
DARKTRACE_TO_INTERNAL_TYPE = {
    "domain": getattr(IndicatorType, "DOMAIN", IndicatorType.URL),
    "fqdn": getattr(IndicatorType, "FQDN", IndicatorType.URL),
    "ipv4": getattr(IndicatorType, "IPV4", IndicatorType.URL),
    "ipv6": getattr(IndicatorType, "IPV6", IndicatorType.URL),
    "hostname": getattr(IndicatorType, "HOSTNAME", IndicatorType.URL),
    "url": IndicatorType.URL
}

INTELFEED_API_ENDPOINT = "/intelfeed"

HOSTNAME_REGEX = r"^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$"
DOMAIN_REGEX = r"^(?:\*\.)?[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}"
DOMAIN_REGEX_2 = r"(?<!-)(?<![:\/\w.])(?:\*\.[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}|(?<!\*)[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?)*\.[a-zA-Z]{2,})(?::(?:6553[0-5]|655[0-2]\d|65[0-4]\d{2}|6[0-4]\d{3}|[1-5]\d{4}|\d{1,4}))?(?:\/)?(?![:\/\w])"
FQDN_REGEX = r"^(?=.{1,253}$)((?!-)[A-Za-z0-9-]{1,63}(?<!-)\.){2,}[A-Za-z]{2,63}$"

EMPTY_ERROR_MESSAGE = "{field_name} is a required {parameter_type} parameter."
TYPE_ERROR_MESSAGE = (
    "Invalid value provided for the {parameter_type} parameter '{field_name}'."
)
VALIDATION_ERROR_MESSAGE = "Validation error occurred."
INVALID_VALUE_ERROR_MESSAGE = " Allowed values are {allowed_values}"

RETRY_ERROR_MSG = (
    "Received exit code {status_code}, {error_reason}"
    " while {logger_msg}. Retrying after {wait_time} "
    "seconds. {retry_remaining} retries remaining."
)
NO_MORE_RETRIES_ERROR_MSG = (
    "Received exit code {status_code}, API rate limit "
    "exceeded while {logger_msg}. Max retries for rate"
    " limit handler exceeded hence returning status"
    " code {status_code}."
)
