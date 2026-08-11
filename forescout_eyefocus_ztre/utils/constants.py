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

CRE Forescout eyeFocus REM plugin constants.
"""

MODULE_NAME = "CRE"
PLUGIN_NAME = "Forescout eyeFocus"
PLATFORM_NAME = "Forescout"
PLUGIN_VERSION = "1.0.0"

# Entity
SUPPORTED_ENTITY = "Assets"

# Actions. This is a data-only plugin: the single "No actions" entry exists
# because the CRE framework requires at least one action to be offered.
ACTION_NO_ACTION = "generate"
SUPPORTED_ACTIONS = [ACTION_NO_ACTION]

# --------------------------------------------------------------------------- #
# API
# --------------------------------------------------------------------------- #
# The working REM Asset Search endpoint (validated against the demo instance).
# NOTE: the Swagger reference lists the path as "/api/risk-sharing/v3/..." but
# that path returns HTTP 400 on the demo instance; "data-exchange/v3" is the
# path used by the working cURL samples and is what the plugin calls.
REM_ASSET_SEARCH_ENDPOINT = "/api/data-exchange/v3/rem-asset-search"

# The REM Asset Search API caps every response at this many entities and does
# NOT honour `limit` / `offset` / `page` query parameters (verified against the
# demo instance). The ONLY way to get more than this many results is to
# narrow the `from`/`to` window. When `total_hits` for a window exceeds
# the number of entities returned, the window is "truncated" and must be split.
RESPONSE_HARD_CAP = 1000

# Ordering used for every pull. Ordering ascending by `last_seen` makes each
# window's results deterministic (oldest first) which is helpful for debugging
# and for the date-window bisection logic.
ORDER_BY_FIELD = "last_seen"
SORT_ORDER = "ASCENDING"

# Ordering used for the unfiltered first pass of a window. Sending either risk
# bound makes the API drop assets scored exactly 0, and those assets cannot
# be recovered by any later banded query - so the one call that carries no
# bound is ordered by risk_score ASCENDING, which guarantees its (possibly
# capped) page starts at the bottom of the scale and therefore contains every
# zero-score asset. Verified live: last_seen ordering surfaced 0 of them over
# a 14-day window, risk_score ordering surfaced all 8.
ZERO_SCORE_PROBE_ORDER_BY = "risk_score"

# --------------------------------------------------------------------------- #
# Date-window pagination / checkpointing
# --------------------------------------------------------------------------- #
# Default size of a single pull window (in days). A run's [from, to] range is
# swept one window at a time. If a window comes back truncated it is bisected
# down to as small as MIN_WINDOW_SECONDS before the (rare) capped result is
# accepted with an explicit log line.
DEFAULT_PULL_WINDOW_DAYS = 1
MIN_PULL_WINDOW_DAYS = 1
MAX_PULL_WINDOW_DAYS = 30

# Smallest window the bisection will shrink to before giving up and accepting a
# capped (potentially incomplete) page.
#
# NOTE: narrowing the datetime window is NOT sufficient on its own. The demo
# tenant stamps assets in bursts - e.g. 1072 assets sharing a 19-second
# `last_seen` span - so `total_hits` plateaus just above the cap however far
# the window is narrowed, and then drops straight to 0. That is why the pull
# paginates primarily on `risk_score` (see below) and only falls back to time
# splitting inside a single score band.
MIN_WINDOW_SECONDS = 300

# The API renders datetimes to millisecond precision and answers HTTP 400 when
# `from` equals `to`, so no time split may ever produce a step finer than this.
# (Observed live: repeated bisection produced a
# `from == to == 2026-07-29T07:51:35.294Z` request that failed the whole pull.)
MIN_WINDOW_STEP_MILLISECONDS = 1

# When a window is truncated it is split into enough equal sub-windows to bring
# each under this fraction of RESPONSE_HARD_CAP (proportional split, so most
# dense windows resolve in a single split instead of repeated halving).
WINDOW_FILL_TARGET = 0.8

# Hard backstop on bisection recursion depth (duration halving already bounds
# this well below the cap; a guard against pathological data density).
MAX_BISECT_DEPTH = 25

# --------------------------------------------------------------------------- #
# Risk-score pagination (the primary way past the 1000-entity cap)
# --------------------------------------------------------------------------- #
# `risk_score` is orthogonal to the `last_seen` bursts described above, so a
# window the datetime split cannot break up is instead sliced into risk-score
# bands. Measured on the demo instance: a 6-minute burst window that time
# splitting could only ever return 1000 of 1072 assets for was resolved
# completely - all 1072 - by 8 score bands.
#
# Forescout reports `risk_score` to one decimal place, so score bands are
# tracked in TENTHS of a point as integers (0..100). This keeps the band
# arithmetic exact and lets adjacent bands be built without overlapping, even
# though the API's bounds are inclusive on both ends.
RISK_SCORE_TENTHS_MIN = 0
RISK_SCORE_TENTHS_MAX = 100
RISK_SCORE_TENTHS_PER_POINT = 10

# Backstop on how many times a score band may be subdivided. A band narrows to
# a single score value long before this.
MAX_SCORE_SPLIT_DEPTH = 12

# Look-back window applied on the first pull (Incremental strategy) or on
# EVERY pull (Full strategy).
DEFAULT_INITIAL_RANGE_DAYS = 7
MIN_INITIAL_RANGE_DAYS = 1
MAX_INITIAL_RANGE_DAYS = 365

# Key under which the resumable pull checkpoint is stored in ``self.storage``.
STORAGE_CHECKPOINT_KEY = "pull_checkpoint"

# --------------------------------------------------------------------------- #
# Pull strategy
# --------------------------------------------------------------------------- #
# "incremental": the first pull covers [now - Initial Range, now]; every later
#     pull covers [last successful run, now] - only assets seen since the
#     previous run are fetched.
# "full": EVERY pull covers [now - Initial Range, now] - the complete Initial
#     Range is re-fetched on each cycle, so assets are refreshed even when
#     they were not seen again since the previous run.
# Both strategies use the same window slicing, de-duplication and resumable
# checkpointing; only the [from, to] range differs.
PULL_STRATEGY_INCREMENTAL = "incremental"
PULL_STRATEGY_FULL = "full"
ALL_PULL_STRATEGIES = [PULL_STRATEGY_INCREMENTAL, PULL_STRATEGY_FULL]
DEFAULT_PULL_STRATEGY = PULL_STRATEGY_INCREMENTAL

# --------------------------------------------------------------------------- #
# Retry / networking
# --------------------------------------------------------------------------- #
MAX_API_RETRIES = 4
DEFAULT_WAIT_TIME = 30
MAX_WAIT_TIME = 300  # hard cap (seconds) on any single Retry-After back-off

# Base for the exponential back-off applied to transient connection errors
# (5s, 10s, 20s ...), capped by MAX_WAIT_TIME. Shorter than the rate-limit
# wait because a dropped connection usually recovers immediately.
CONNECTION_RETRY_BACKOFF_SECONDS = 5
DEFAULT_REQUEST_TIMEOUT = 60

# --------------------------------------------------------------------------- #
# Date handling
# --------------------------------------------------------------------------- #
# Forescout REM timestamps look like: 2026-05-06T08:55:23.777Z
DATE_FORMAT_WITH_MS = "%Y-%m-%dT%H:%M:%S.%fZ"
DATE_FORMAT_NO_MS = "%Y-%m-%dT%H:%M:%SZ"

# --------------------------------------------------------------------------- #
# Advanced filters (server-side risk-score range)
# --------------------------------------------------------------------------- #
# Forescout `risk_score` is on a 0-10 scale (higher = more risk). Used to bound
# the optional "Minimum / Maximum Risk Score" advanced filters.
RISK_SCORE_SCALE_MIN = 0
RISK_SCORE_SCALE_MAX = 10

# Values of the "Advanced Filters" toggle that drives ``get_dynamic_fields``.
ADVANCED_FILTERS_YES = "yes"
ADVANCED_FILTERS_NO = "no"
ALL_ADVANCED_FILTER_CHOICES = [ADVANCED_FILTERS_YES, ADVANCED_FILTERS_NO]
DEFAULT_ADVANCED_FILTERS = ADVANCED_FILTERS_NO

# Query parameter names accepted by the REM Asset Search API. Both bounds are
# INCLUSIVE server-side; sending either one additionally drops assets whose
# risk_score is exactly 0 (verified against the live demo instance).
# Accepted shape for a risk-score bound typed into the text field: an
# optionally signed plain decimal such as "1.2", "3", ".5" or "2.".
# Exponent notation and nan/inf are intentionally NOT accepted.
RISK_SCORE_REGEX = r"^[+-]?(\d+\.?\d*|\.\d+)$"

RISK_SCORE_MIN_PARAM = "risk_score_min"
RISK_SCORE_MAX_PARAM = "risk_score_max"

# Configuration fields revealed by ``get_dynamic_fields`` when the "Advanced
# Filters" toggle is set to Yes. Both are optional so a one-sided bound can be
# configured; ``validate`` enforces that at least one of them is provided and
# that min <= max.
ADVANCED_FILTER_DYNAMIC_FIELDS = [
    {
        "label": "Minimum Risk Score",
        "key": RISK_SCORE_MIN_PARAM,
        # Deliberately "text", not "number": the CE number widget strips the
        # decimal separator, turning 1.2 into 12. The value is parsed and
        # range-checked by validate() before it reaches the API, which itself
        # expects these bounds as strings.
        "type": "text",
        "default": "0",
        "placeholder": "0",
        "mandatory": False,
        "description": (
            "Only fetch assets whose Forescout risk score is greater than or "
            "equal to this value (0-10 scale, decimals allowed e.g. 1.2). "
            "Applied server-side by the REM Asset Search API. Leave blank for "
            "no lower bound. Note: setting any risk bound makes the API "
            "exclude assets whose risk score is exactly 0."
        ),
    },
    {
        "label": "Maximum Risk Score",
        "key": RISK_SCORE_MAX_PARAM,
        # See the note on "Minimum Risk Score" above.
        "type": "text",
        "default": "10",
        "placeholder": "10",
        "mandatory": False,
        "description": (
            "Only fetch assets whose Forescout risk score is less than or "
            "equal to this value (0-10 scale, decimals allowed e.g. 3). "
            "Applied server-side by the REM Asset Search API. Leave blank for "
            "no upper bound."
        ),
    },
]

# --------------------------------------------------------------------------- #
# Asset categories
# --------------------------------------------------------------------------- #
# Values mirror the Forescout UI "Category" filter exactly (see docs/README).
# NOTE: these are Forescout's own category strings, so "Network Device" and
# "Medical Device" keep the vendor's spelling and are compared verbatim against
# the raw ``rem_category`` field - they are not plugin-facing wording.
CATEGORY_NETWORK = "Network Device"
CATEGORY_UNKNOWN = "Unknown"
CATEGORY_MEDICAL = "Medical Device"
CATEGORY_IOT = "IoT"
CATEGORY_OT = "OT"
CATEGORY_IT = "IT"

ALL_CATEGORY_CHOICES = [
    CATEGORY_NETWORK,
    CATEGORY_UNKNOWN,
    CATEGORY_MEDICAL,
    CATEGORY_IOT,
    CATEGORY_OT,
    CATEGORY_IT,
]

# The non-host / headless preset: every category except "IT"
# (Netskope-Client-compatible hosts) per the customer scope.
#
# NOTE: this is a reference preset, NOT the shipped default - the field's
# default comes from manifest.json, which currently pre-selects all six
# categories (including "IT").
NON_HOST_CATEGORIES = [
    CATEGORY_NETWORK,
    CATEGORY_UNKNOWN,
    CATEGORY_MEDICAL,
    CATEGORY_IOT,
    CATEGORY_OT,
]

# --------------------------------------------------------------------------- #
# Entity field mapping: entity field name -> source spec.
#   key            : dot-notation path into the raw Forescout entity
#   default        : value used when the key is absent
#   transformation : one of {None, "string", "list", "datetime", "float"}
# --------------------------------------------------------------------------- #
ASSET_FIELD_MAPPING = {
    "Asset ID": {
        "key": "id",
        "default": None,
        "transformation": "string"
    },
    "Hostname": {
        "key": "hostname",
        "default": None,
        "transformation": "string",
    },
    "IP Addresses": {
        "key": "ip_addresses",
        "default": [],
        "transformation": "list",
    },
    "MAC Addresses": {
        "key": "mac_addresses",
        "default": [],
        "transformation": "list",
    },
    "Category": {
        "key": "rem_category",
        "default": None,
        "transformation": "string",
    },
    "Function": {
        "key": "rem_function",
        "default": None,
        "transformation": "string",
    },
    "Vendor": {
        "key": "rem_vendor",
        "default": None,
        "transformation": "string",
    },
    "OS": {
        "key": "rem_os",
        "default": None,
        "transformation": "string"
    },
    "Model": {
        "key": "rem_model",
        "default": None,
        "transformation": "string"
    },
    "Firmware": {
        "key": "rem_firmware",
        "default": None,
        "transformation": "string",
    },
    "Risk Score": {
        "key": "risk_score",
        "default": None,
        "transformation": "float",
    },
    "Risk Severity": {
        "key": "risk_severity",
        "default": None,
        "transformation": "string",
    },
    "Asset Criticality": {
        "key": "risk_device_criticality",
        "default": None,
        "transformation": "string",
    },
    "Last Seen": {
        "key": "last_seen",
        "default": None,
        "transformation": "datetime",
    },
    "Last Seen Online": {
        "key": "last_seen_online",
        "default": None,
        "transformation": "datetime",
    },
}

# --------------------------------------------------------------------------- #
# Validation
# --------------------------------------------------------------------------- #
CONFIGURATION = "configuration"
ACTION = "action"

VALIDATION_ERROR_MESSAGE = "Validation error occurred."
EMPTY_ERROR_MESSAGE = (
    "'{field_name}' is a required {parameter_type} parameter."
)
TYPE_ERROR_MESSAGE = (
    "Invalid value provided for the {parameter_type} parameter "
    "'{field_name}'."
)

# Suffixes appended to TYPE_ERROR_MESSAGE so the message always states what a
# valid value looks like instead of only reporting that the value was rejected.
INVALID_VALUE_ERROR_MESSAGE = " Allowed values are {allowed_values}."
INTEGER_ERROR_MESSAGE = " Valid value should be an integer."
# ``value_kind`` is either empty or INTEGER_VALUE_KIND, so the bound and the
# whole-number requirement are stated in one sentence rather than two.
INTEGER_VALUE_KIND = "an integer "
RANGE_ERROR_MESSAGE = (
    " Valid value should be {value_kind}in range {min_value} to {max_value}."
)
MIN_VALUE_ERROR_MESSAGE = (
    " Valid value should be {value_kind}greater than or equal to {min_value}."
)
MAX_VALUE_ERROR_MESSAGE = (
    " Valid value should be {value_kind}less than or equal to {max_value}."
)
# Appended when the Base URL fails the URL-shape check.
# Appended when a risk-score bound is not a plain decimal number. The bounds
# are text fields (the CE number widget drops the decimal separator), so a
# free-text value has to be reported clearly.
RISK_SCORE_EXAMPLE = "1.2"
RISK_SCORE_FORMAT_ERROR_MESSAGE = (
    " Valid value should be a number between 0-10."
)

URL_ERROR_MESSAGE = (
    " Valid value should be a URL including the scheme, "
    "e.g. https://<instance>.cloud.forescout.com."
)

# --------------------------------------------------------------------------- #
# Error message templates
# --------------------------------------------------------------------------- #
RETRY_ERROR_MSG = (
    "Received exit code {status_code}, {error_reason} while {logger_msg}. "
    "Retrying after {wait_time} second(s). {retry_remaining} retries left."
)
NO_MORE_RETRIES_ERROR_MSG = (
    "Received exit code {status_code} while {logger_msg}. "
    "Maximum retry limit reached."
)
