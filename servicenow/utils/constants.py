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

CTE ServiceNow plugin constants.
"""

from netskope.integrations.cte.models import IndicatorType

MODULE_NAME = "CTE"
PLUGIN_NAME = "ServiceNow Threat Intelligence"
PLATFORM_NAME = "ServiceNow"
PLUGIN_VERSION = "2.0.0"

MAX_API_CALLS = 4
DEFAULT_WAIT_TIME = 60
PAGE_SIZE = 1000
MAX_DAYS = 365
MAX_RETRACTION_INTERVAL_DAYS = 100000
RETRACTION = "[Retraction]"

DATE_FORMAT = "%Y-%m-%d %H:%M:%S"

# ServiceNow Table API endpoints (default path resolves to latest version).
OBSERVABLE_ENDPOINT = "/api/now/table/sn_ti_observable"
OBSERVABLE_FIELDS = (
    "value,type.value,sys_id,sys_created_on,sys_updated_on,notes,finding"
)
RECORD_URL_PATH = "/nav_to.do?uri=sn_ti_observable.do?sys_id="

# ServiceNow `type.value` -> CE IndicatorType map.
SERVICENOW_TO_INDICATOR_TYPE = {
    "MD5": IndicatorType.MD5,
    "SHA256": IndicatorType.SHA256,
    "URL": IndicatorType.URL,
    "ipv4-addr": IndicatorType.IPV4,
    "ipv6-addr": IndicatorType.IPV6,
    "Domain name": IndicatorType.DOMAIN,
    "FQDN": IndicatorType.FQDN,
}

ALLOWED_THREAT_TYPES = list(SERVICENOW_TO_INDICATOR_TYPE.keys())

ALLOWED_FINDINGS = ["Malicious", "Suspicious", "Unknown", "Clean"]

# Fixed prefix written into a shared observable's `notes` field. Also
# used on pull to detect and skip observables this plugin created
# itself, preventing a push -> pull -> push cycle.
SOURCE_LABEL = "Shared by Netskope Cloud Exchange"

# Error message templates.
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
    "Received exit code {status_code} while {logger_msg}."
    " Retrying after {wait_time} seconds."
    " {retry_remaining} retries remaining."
)
NO_MORE_RETRIES_ERROR_MSG = (
    "Received exit code {status_code} while {logger_msg}."
    " Max retries for rate limit/server error handler exceeded"
    " hence returning status code {status_code}."
)
