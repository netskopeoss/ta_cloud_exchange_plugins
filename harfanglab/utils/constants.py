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

CTE HarfangLab plugin constants.
"""
# ─────────────────────────── Plugin identity ────────────────────────────────
MODULE_NAME = "CTE"
PLUGIN_NAME = "HarfangLab"
PLATFORM_NAME = "HarfangLab"
PLUGIN_VERSION = "2.0.0"

# ─────────────────────────── Retry / rate-limit ─────────────────────────────
MAX_API_CALLS = 3
DEFAULT_WAIT_TIME = 60    # seconds between retries
MAX_WAIT_TIME = 300       # cap for Retry-After header (5 min)

# ─────────────────────────── Pagination ─────────────────────────────────────
PAGE_LIMIT = 500

# ─────────────────────────── Retraction ─────────────────────────────────────
RETRACTION = "Retraction"

# Maximum days allowed for Initial Range and Retraction Interval fields.
MAX_DAYS = 100000

# ─────────────────────────── Tag constants ──────────────────────────────────
DRIVER_BLOCK_LIST_TAG = "HarfangLab-Driver-Block-List"
TAG_COLOR = "#FF0000"

# ─────────────────────────── IOC source filtering ───────────────────────────
# Prefix used to identify indicators and lists pushed by Netskope CE.
CE_TAG = "Netskope CE"

# Description stamped on IOC Source lists created by Netskope CE (informational).
NETSKOPE_CE_LIST_DESCRIPTION = "IOC List created from Netskope CE"


# ─────────────────────────── Date format ────────────────────────────────────
DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
DATE_FORMAT_WITH_MS = "%Y-%m-%dT%H:%M:%S.%fZ"
# HarfangLab API filter parameters require space-separated datetime (no T/Z).
DATE_FORMAT_FOR_FILTER = "%Y-%m-%d %H:%M:%S"

# ─────────────────────────── API endpoint paths ─────────────────────────────
IOC_SOURCE_ENDPOINT = "/api/data/threat_intelligence/IOCSource/"
IOC_RULE_ENDPOINT = "/api/data/threat_intelligence/IOCRule/"
DRIVER_BLOCKLIST_ENDPOINT = (
    "/api/data/threat_intelligence/DriverBlocklist/"
)

# Filter parameters for incremental IOC Source pulls.
# Both are sent together to define a [gte, lte] time window per sync.
IOC_RULE_FILTER_PARAM     = "last_update__gte"   # start of window
IOC_RULE_FILTER_END_PARAM = "last_update__lte"   # end of window (now)
# Response field tracked as the per-sync checkpoint value.
IOC_RULE_CHECKPOINT_FIELD = "last_update"

# ─────────────────────────── Allowed threat_data_type values ────────────────
ALLOWED_THREAT_DATA_TYPES = {
    "sha256", "md5", "domain", "fqdn", "hostname",
    "ipv4", "ipv6", "ipv4_cidr", "ipv6_cidr", "url"
}

# ─────────────────────────── Validation helpers ─────────────────────────────
VALIDATION_ERROR_MSG = "Validation error occurred. "

# ─────────────────────────── Source type constants ───────────────────────────
SOURCE_TYPE_IOC_SOURCE = "ioc_sources"
SOURCE_TYPE_DRIVER_BLOCK_LIST = "driver_block_list"
ALLOWED_SOURCE_TYPES = {SOURCE_TYPE_IOC_SOURCE, SOURCE_TYPE_DRIVER_BLOCK_LIST}

# Indicator types supported by Driver Block List (hash-only).
DBL_SUPPORTED_TYPES = {"sha256", "md5"}

# ─────────────────────────── Push action field allowed values ────────────────
# Sentinel used in choice fields to mean "do not send this field to the API".
NO_OVERRIDE_VALUE = "null"

# global_state — valid API values for the Action field.
ALLOWED_GLOBAL_STATES = {
    "disabled", "backend_alert", "alert", "block", "quarantine"
}

# hl_status — valid API values for the Maturity field.
ALLOWED_HL_STATUSES = {"stable", "testing", "experimental"}
