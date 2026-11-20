"""
BSD 3-Clause License

Copyright (c) 2021, Netskope OSS
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions
are met:

1. Redistributions of source code must retain the above copyright
   notice, this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright
   notice, this list of conditions and the following disclaimer in
   the documentation and/or other materials provided with the
   distribution.

3. Neither the name of the copyright holder nor the names of its
   contributors may be used to endorse or promote products derived
   from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
POSSIBILITY OF SUCH DAMAGE.

CTE GreyNoise plugin constants.
"""

MODULE_NAME = "CTE"
PLATFORM_NAME = "GreyNoise"
PLUGIN_NAME = "GreyNoise"
PLUGIN_VERSION = "1.0.0"
MAX_API_CALLS = 4
DEFAULT_WAIT_TIME = 60
PAGE_SIZE = 10000
CALLBACK_PAGE_SIZE = 100
REQUEST_TIMEOUT = 300
RETRACTION = "[Retraction]"
TAG_COLOR = "#FF0000"

GNQL_ENDPOINT = "/v3/gnql"
CALLBACK_LIST_ENDPOINT = "/v1/callback/ips"
CALLBACK_IP_ENDPOINT = "/v1/callback/ip"

VALID_IOC_TYPES = ["ip", "callback_ip", "md5", "sha256"]
EXCLUDE_FIELDS = (
    "tag_volumes,spoofable,cves,callback_ips,vpn,vpn_service,tor,"
    "last_seen_malicious,last_seen_suspicious,last_seen_benign,"
    "raw_data,"
    "metadata.asn,metadata.source_country_code,metadata.rdns_parent,"
    "metadata.rdns_validated,metadata.category,metadata.rdns,"
    "metadata.destination_countries,metadata.destination_country_codes,"
    "metadata.destination_asns,metadata.destination_cities,"
    "metadata.carrier,metadata.datacenter,metadata.longitude,"
    "metadata.latitude,metadata.sensor_count,metadata.sensor_hits,"
    "metadata.mobile,metadata.single_destination,"
    "metadata.domain,metadata.region,metadata.os"
)

DATE_FORMAT_FIRST_SEEN = "%Y-%m-%d"
DATE_FORMAT_LAST_SEEN = "%Y-%m-%d %H:%M:%S"

VALID_CLASSIFICATIONS = ["malicious", "suspicious", "unknown", "benign"]
VALID_RANGES = ["today", "1d", "1w", "1m", "1y", "custom"]
RANGE_TO_DAYS = {"today": 0, "1d": 1, "1w": 7, "1m": 30, "1y": 365}
GREYNOISE_URL = "https://viz.greynoise.io/"
EMPTY_ERROR_MESSAGE = (
    "{field_name} is a required {parameter_type} parameter."
)
TYPE_ERROR_MESSAGE = (
    "Invalid value provided for the {parameter_type}"
    " parameter '{field_name}'."
)
INVALID_VALUE_ERROR_MESSAGE = " Allowed values: {allowed_values}."
VALIDATION_ERROR_MESSAGE = "Validation error occurred."
RETRY_ERROR_MSG = (
    "Received exit code {status_code}, {error_reason}"
    " while {logger_msg}. Retrying after {wait_time}"
    " seconds. {retry_remaining} retries remaining."
)
NO_MORE_RETRIES_ERROR_MSG = (
    "Received exit code {status_code} while {logger_msg}."
    " Max retries exceeded."
)
