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

TrendAI Vision One Plugin to push and pull data from the TrendAI Vision One
Platform.
"""

from netskope.integrations.cte.models import (
    IndicatorType,
    SeverityType,
)


TRENDMICRO_TO_INTERNAL_TYPE = {
    "url": IndicatorType.URL,
    "domain": IndicatorType.DOMAIN,
    "fileSha256": IndicatorType.SHA256,
    # "ip" is intentionally absent: it resolves to IndicatorType.IPV4 or
    # IndicatorType.IPV6 based on the value itself (see
    # TrendMicroPlugin._detect_indicator_type), not a fixed mapping.
}

INTERNAL_SEVERITY_TO_TRENDMICRO = {
    SeverityType.UNKNOWN: "",
    SeverityType.LOW: "low",
    SeverityType.MEDIUM: "medium",
    SeverityType.HIGH: "high",
    SeverityType.CRITICAL: "high",
}

TRENDMICRO_TO_INTERNAL_SEVERITY = {
    "high": SeverityType.HIGH,
    "medium": SeverityType.MEDIUM,
    "low": SeverityType.LOW,
}

# Fixed Data Region API hosts - matches the v1.0.2 convention where the
# Data Region choice's VALUE is the API host URL itself and the UI shows
# "<Region name> (<host>)", e.g. "Australia (api.au.xdr.trendmicro.com)"
# (see manifest.json's "data_region" choices, which this list must stay in
# sync with), extended with the 5 new regions and the updated Japan host.
# The Japan host changes from v1.0.2's api.xdr.trendmicro.co.jp to
# api.jp.xdr.trendmicro.com to match the naming scheme every other region
# already follows - see TDD_CTE_TrendVisionOne.md section 5.1 / section 16
# for confirmation status of new/changed hosts.
FIXED_REGION_URLS = [
    "https://api.au.xdr.trendmicro.com",
    "https://api.ca.xdr.trendmicro.com",
    "https://api.eu.xdr.trendmicro.com",
    "https://api.in.xdr.trendmicro.com",
    "https://api.id.xdr.trendmicro.com",
    "https://api.jp.xdr.trendmicro.com",
    "https://api.mea.xdr.trendmicro.com",
    "https://api.sg.xdr.trendmicro.com",
    "https://api.za.xdr.trendmicro.com",
    "https://api.uk.xdr.trendmicro.com",
    "https://api.xdr.trendmicro.com",
]

# Sentinel Data Region value that switches Base URL from a fixed host to a
# user-provided one. The Base URL field itself is not in manifest.json's
# static configuration - it is returned by get_dynamic_fields() only when
# this value is selected (has_api_call/payload_fields on data_region).
CUSTOM_REGION = "Custom Region"

DATA_REGIONS = FIXED_REGION_URLS + [CUSTOM_REGION]

# Base URL field definition - schema matches manifest.json configuration
# entries exactly (label/key/type/default/mandatory/description), returned
# by TrendMicroPlugin.get_dynamic_fields() only for Custom Region. Kept as
# a constant so main.py and this file share one definition, matching the
# pattern other dynamic-config CTE plugins use (e.g. stix_taxii).
BASE_URL_FIELD = {
    "label": "Base URL",
    "key": "base_url",
    "type": "text",
    "default": "",
    "mandatory": True,
    "description": (
        "Base URL of your TrendAI Vision One API host, for example"
        " https://api.xdr.trendmicro.com."
    ),
}

# Every other configuration field is dynamic too - not just Base URL -
# so Data Region is the ONLY static manifest.json entry (matching
# stix_taxii's pattern) and get_dynamic_fields() controls the order
# these render in, placing Base URL immediately after Data Region
# instead of wherever the platform would otherwise append it (dynamic
# fields always render after the trigger field, so with a mix of
# static and dynamic fields the trigger has to be last - keeping every
# field dynamic avoids that constraint entirely).
TOKEN_FIELD = {
    "label": "Authentication Token",
    "key": "token",
    "type": "password",
    "default": "",
    "mandatory": True,
    "description": (
        "Authentication Token to access TrendAI Vision One APIs."
        " Authentication Token can be generated from the 'Trend"
        " Vision One Portal > Administration > API Keys' page."
    ),
}

IS_PULL_REQUIRED_FIELD = {
    "label": "Enable Polling",
    "key": "is_pull_required",
    "type": "choice",
    "choices": [
        {"key": "Yes", "value": "Yes"},
        {"key": "No", "value": "No"},
    ],
    "default": "Yes",
    "mandatory": True,
    "description": (
        "Enable/Disable polling data from TrendAI Vision One. "
        "Disable if you only need to push indicators to TrendAI Vision One."
    ),
}

ENABLE_PUSH_RETRACTION_FIELD = {
    "label": "Enable Push Retraction",
    "key": "enable_push_retraction",
    "type": "choice",
    "choices": [
        {"key": "Yes", "value": "Yes"},
        {"key": "No", "value": "No"},
    ],
    "default": "No",
    "mandatory": True,
    "description": (
        "Enable/Disable push retraction of indicator(s) for Trend"
        " Vision One. When enabled, indicator(s) marked as retracted"
        " in Netskope Cloud Exchange that were previously shared to"
        " TrendAI Vision One will be deleted from both the Suspicious"
        " Object List and the Exception List."
    ),
}

RETRACTION_INTERVAL_FIELD = {
    "label": "Retraction Interval (in days)",
    "key": "retraction_interval",
    "type": "number",
    "mandatory": False,
    "description": (
        "Number of days to use as the retraction interval for Trend"
        " Vision One indicator(s) pull retraction. This parameter"
        " applies only when IoC(s) Retraction is enabled in Threat"
        " Exchange Settings. Value must be between 1 and 365."
    ),
}

INITIAL_RANGE_FIELD = {
    "label": "Initial Range (in days)",
    "key": "initial_range",
    "type": "number",
    "mandatory": True,
    "default": 7,
    "description": (
        "Number of days to pull the data for the initial run. Value"
        " must be between 1 and 365."
    ),
}

INDICATOR_TYPES = ["domain", "fileSha256", "ip", "url"]
MODULE_NAME = "CTE"
PLUGIN_NAME = "TrendAI Vision One"
PLUGIN_VERSION = "2.0.0"
PLATFORM_NAME = "TrendAI Vision One"

MAX_RETRIES = 4
DEFAULT_WAIT_TIME = 60
# TrendAI Vision One documents a 60s server-side request timeout (a slower
# response gets its own 504 from the server); this is the client-side
# requests() timeout, set to match rather than cut a request off early.
REQUEST_TIMEOUT = 60

DATE_FORMAT_FOR_IOCS = r"%Y-%m-%dT%H:%M:%SZ"

# Label written into every NEW shared object's description, matching the
# current best-practice wording used across the CTE plugin suite (e.g.
# servicenow). TrendAI Vision One's delete endpoints take only a type/value
# pair (no notes/description field), so - unlike a plugin whose delete API
# supports a lookup step - this label cannot be used to verify object
# ownership before a retraction delete call; it is for push/pull
# traceability only.
SOURCE_LABEL = "Shared by Netskope Cloud Exchange"

# The label every object pushed by v1.0.2-2.0.0-pre versions of this
# plugin carries. Objects already shared to TrendAI Vision One by existing
# customers before this label change still carry this text, not
# SOURCE_LABEL - pull's echo-suppression check must match EITHER label,
# or those pre-existing objects would stop being recognized as
# CE-originated and get pulled back in as if they were external IOCs.
LEGACY_SOURCE_LABEL = "(Created from Netskope CTE)"

RETRACTION = "[Retraction]"

# Push/retraction batch size per target - TrendAI Vision One documents a
# separate, smaller cap for the Exception List than the Suspicious Object
# List.
SUSPICIOUS_OBJECT_BATCH_SIZE = 1000
SUSPICIOUS_OBJECT_EXCEPTION_BATCH_SIZE = 100

# How many indicators CE hands to retract_indicators() per generator
# iteration; the plugin then re-chunks per action/endpoint using the two
# batch sizes above for the actual delete API calls.
RETRACTION_BATCH = 10000

# Request body size cap from TrendAI Vision One is 1MB; chunks are kept under
# this with headroom for JSON structural overhead before a chunk is sent.
MAX_PAYLOAD_BYTES = 900_000

# Per-field length limits from the TrendAI Vision One suspiciousObjects /
# suspiciousObjectExceptions API schema (atl-v3-url, atl-v3-domain,
# atl-v3-ip, atl-v3-sha256, atl-v3-description). An IOC value outside its
# bound is skipped rather than sent; an oversized description is truncated
# since it is metadata, not the IOC identity.
MAX_URL_LENGTH = 2048
MAX_DOMAIN_LENGTH = 253
MAX_IP_LENGTH = 39
SHA256_LENGTH = 64
MAX_DESCRIPTION_LENGTH = 1000

# Retraction Interval bounds PULL retraction only (get_modified_indicators)
# - the number of days to re-query the Suspicious Object List for the
# active-value set used to diff against what CE has stored. It has no role
# in PUSH retraction (retract_indicators): CE already hands that method
# exactly the indicators to delete, and TrendAI Vision One's delete
# endpoints take a raw IOC value directly with no re-query step to bound.
# Matches MAX_INITIAL_RANGE_DAYS since both bound a "how many days back"
# re-query against the same endpoint - not a hard API-documented limit.
MAX_RETRACTION_INTERVAL_DAYS = 365
MAX_INITIAL_RANGE_DAYS = 365

# Shared message templates for the common _validate_configuration_
# parameters() validator - matches the wording/format used by other
# CTE plugins (e.g. servicenow) so a common validation helper can be
# reused for every configuration parameter instead of one bespoke
# error message per field.
EMPTY_ERROR_MESSAGE = (
    "{field_name} is a required {parameter_type} parameter."
)
TYPE_ERROR_MESSAGE = (
    "Invalid value provided for the {parameter_type}"
    " parameter '{field_name}'."
)
VALIDATION_ERROR_MESSAGE = "Validation error occurred."
INVALID_VALUE_ERROR_MESSAGE = " Allowed values are {allowed_values}."
