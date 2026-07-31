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

Tenant Netskope constants.
"""

from netskope_api.iterator.const import Const
import os

MODULE_NAME = "TENANT"
PLUGIN_VERSION = "1.6.2"
PLATFORM_NAME = "Netskope"
MAX_API_CALLS = 4
DATE_FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"
DOCS_URL = "https://docs.netskope.com/en/netskope-help/integrations-439794/netskope-cloud-exchange/get-started-with-cloud-exchange/configure-netskope-tenants/#v2-rest-api-scopes"  # NOQA
CLIENT_STATUS_ITERATOR_NAME = "netskope_ce_cs_iterator"
DB_LOOKUP_INTERVAL = 120
ALERTS = {
    "Compromised Credential": Const.ALERT_TYPE_COMPROMISEDC_CREDENTIALS,
    "policy": Const.ALERT_TYPE_POLICY,
    "malsite": Const.ALERT_TYPE_MALSITE,
    "Malware": Const.ALERT_TYPE_MALWARE,
    "DLP": Const.ALERT_TYPE_DLP,
    "Security Assessment": Const.ALERT_TYPE_SECURITY_ASSESSMENT,
    "watchlist": Const.ALERT_TYPE_WATCHLIST,
    "quarantine": Const.ALERT_TYPE_QUARANTINE,
    "Remediation": Const.ALERT_TYPE_REMEDIATION,
    "uba": Const.ALERT_TYPE_UBA,
    "ctep": Const.ALERT_TYPE_CTEP,
    "Device": "device",
    "Content": "content",
}
EVENTS = {
    "page": Const.EVENT_TYPE_PAGE,
    "infrastructure": Const.EVENT_TYPE_INFRASTRUCTURE,
    "network": Const.EVENT_TYPE_NETWORK,
    "audit": Const.EVENT_TYPE_AUDIT,
    "application": Const.EVENT_TYPE_APPLICATION,
    "incident": Const.EVENT_TYPE_INCIDENT,
    "endpoint": "endpoint",
    "clientstatus": "clientstatus"
}

ITERATORS = {
    key.lower(): list({x.strip() for x in value.split(',') if x.strip() != ""})
    for key, value in os.environ.items()
    if key.lower().startswith("iterator_")
}

RESOURCES = {"alert": ALERTS, "event": EVENTS}

DATA_TYPE = {"alert": "alerts", "event": "events"}
CLIENT_STATUS_CSV = "{}/api/v2/events/dataexport/iterator/{}/events"
OK_PATTERN = rb"\"ok\"\s*:\s*(\d+)"
TIMESTAMP_HWM_PATTERN = rb"\"timestamp_hwm\"\s*:\s*(\d+)"
WAIT_TIME_PATTERN = rb"\"wait_time\"\s*:\s*(\d+)"
ID_PATTERN = rb'\"_id"\s*:'
RESULT = "result"
TIMESTAMP_HWM = "timestamp_hwm"
QUEUE_SIZE = 10
DEFAULT_WAIT_TIME = 30
WAIT_TIME = "wait_time"


def _get_env_int(name, default, minimum=1):
    """Read a positive integer override from the environment."""
    value = os.environ.get(name)
    if isinstance(value, str) and value.isnumeric() and int(value) >= minimum:
        return int(value)
    return default


# ---------------------------------------------------------------------------
# Unified pull retry mechanism (see iterator_helper.PullRetryController).
#
# Every transient failure while pulling is retried in place with exponential
# backoff: delays grow 30s -> 60s -> 120s -> 240s -> 480s (~15 min), then
# stay flat at 15 min. Two bounds stop the retries:
#   * maintenance pulling never retries past its scheduled pull window
#     (MAINTENANCE_PULL_WINDOW_SECONDS after the task started);
#   * any pull retries a single failure episode for at most
#     BACKOFF_MAX_TOTAL seconds (this is the only bound for the one-shot
#     historical pulls).
#
# Retry policy: retry EVERY HTTP error status except authentication (401)
# and permission (403) failures, plus every network/stream/unexpected
# exception. 401/403 are the only non-retryable statuses -- repeating the
# request cannot succeed until the token or its scopes are fixed, and they
# keep their banner/storage side effects. Every other 4xx and 5xx (including
# 400/404 and 501/505) is retried within the bounds above; a request that
# truly cannot succeed simply exhausts the episode budget and reports an
# actionable failure.
# ---------------------------------------------------------------------------
NON_RETRYABLE_HTTP_STATUS_CODES = {401, 403}
RETRYABLE_HTTP_STATUS_CODES = (
    set(range(400, 600)) - NON_RETRYABLE_HTTP_STATUS_CODES
)
BACKOFF_INITIAL_DELAY = _get_env_int("PULL_BACKOFF_INITIAL_DELAY", 30)
BACKOFF_FACTOR = 2
BACKOFF_MAX_DELAY = _get_env_int("PULL_BACKOFF_MAX_DELAY", 900)
# Upper bound of a single failure episode; the only bound for historical.
BACKOFF_MAX_TOTAL = _get_env_int("PULL_BACKOFF_MAX_TOTAL", 3600)
BACKOFF_JITTER_RATIO = 0.1
BACKOFF_SLEEP_TICK = 30
# Scheduled length of one maintenance pull cycle: load() stops pulling and
# pull() stops retrying once this much time has passed since the cycle
# started. The env override exists for testing only.
MAINTENANCE_PULL_WINDOW_SECONDS = _get_env_int(
    "PULL_MAINTENANCE_WINDOW_SECONDS", 3600
)
# ID fields converted to string so large 64-bit identifiers keep their
# precision downstream (see alert_id_fields_syslog_mapping.md). A set is used
# for O(1) membership checks since this lookup runs for every field on every
# log record.
ID_STRING_FIELDS = {
    "app_session_id",
    "browser_session_id",
    "connection_id",
    "dlp_incident_id",
    "dlp_parent_id",
    "incident_id",
    "latest_incident_id",
    "request_id",
    "signature_id",
    "transaction_id",
}
DLP_INCIDENT_FORENSICS_ENDPOINT = "{base_url}/api/v2/incidents/dlpincidents/{dlp_incident_id}/forensics"
DLP_INCIDENT_ORIGINAL_FILE_ENDPOINT = "{base_url}/api/v2/incidents/dlpincidents/{dlp_incident_id}/originalfile"
DLP_INCIDENT_SUB_FILE_ENDPOINT = "{base_url}/api/v2/incidents/dlpincidents/{dlp_incident_id}/subfile"
# Rate limit remaining
RATELIMIT_REMAINING = "ratelimit-remaining"
# Rate limit RESET value is in seconds
RATELIMIT_RESET = "ratelimit-reset"

ALERT_EVENT_ID_FIELD_MAPPING = {
    "alert": {
        "c2": [
            "signature_id",
            "transaction_id"
        ],
        "content": [
            "dlp_incident_id",
            "incident_id"
        ],
        "ctep": [
            "signature_id",
            "transaction_id"
        ],
        "dlp": [
            "app_session_id",
            "browser_session_id",
            "connection_id",
            "dlp_incident_id",
            "dlp_parent_id",
            "incident_id",
            "request_id",
            "transaction_id"
        ],
        "ips": [
            "signature_id",
            "transaction_id"
        ],
        "malsite": [
            "app_session_id",
            "browser_session_id",
            "connection_id",
            "incident_id",
            "request_id",
            "transaction_id"
        ],
        "malware": [
            "app_session_id",
            "browser_session_id",
            "connection_id",
            "incident_id",
            "request_id",
            "transaction_id"
        ],
        "policy": [
            "app_session_id",
            "browser_session_id",
            "connection_id",
            "incident_id",
            "request_id",
            "transaction_id"
        ],
        "remediation": [
            "app_session_id",
            "browser_session_id",
            "connection_id",
            "incident_id",
            "request_id",
            "transaction_id"
        ],
        "uba": [
            "app_session_id",
            "browser_session_id",
            "connection_id",
            "incident_id",
            "request_id",
            "transaction_id"
        ],
        "watchlist": [
            "app_session_id",
            "browser_session_id",
            "connection_id",
            "dlp_incident_id",
            "dlp_parent_id",
            "incident_id",
            "request_id",
            "transaction_id"
        ]
    },
    "event": {
        "application": [
            "app_session_id",
            "browser_session_id",
            "connection_id",
            "dlp_incident_id",
            "dlp_parent_id",
            "request_id",
            "transaction_id"
        ],
        "endpoint": [
            "dlp_incident_id",
            "incident_id"
        ],
        "incident": [
            "app_session_id",
            "connection_id",
            "dlp_incident_id",
            "dlp_parent_id",
            "latest_incident_id"
        ],
        "page": [
            "app_session_id",
            "browser_session_id",
            "connection_id",
            "request_id",
            "transaction_id"
        ]
    }
}
