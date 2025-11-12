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
PLUGIN_VERSION = "1.5.3"
MAXIMUM_CE_VERSION = "5.1.2"
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
EXPONENTIAL_WAIT_TIME = 180
WAIT_TIME = "wait_time"
DEFAULT_RETRY_COUNT = 3
RETRY_COUNT_FOR_PULLING = os.environ.get("RETRY_COUNT_FOR_PULLING")
if isinstance(RETRY_COUNT_FOR_PULLING, str) and RETRY_COUNT_FOR_PULLING.isnumeric():
    RETRY_COUNT_FOR_PULLING = int(RETRY_COUNT_FOR_PULLING)
    if RETRY_COUNT_FOR_PULLING < 1:
        RETRY_COUNT_FOR_PULLING = DEFAULT_RETRY_COUNT
else:
    RETRY_COUNT_FOR_PULLING = DEFAULT_RETRY_COUNT
STRING_FIELDS = ['dlp_incident_id', 'connection_id', 'app_session_id', 'dlp_parent_id', 'browser_session_id']
DLP_INCIDENT_FORENSICS_ENDPOINT = "{base_url}/api/v2/incidents/dlpincidents/{dlp_incident_id}/forensics"
DLP_INCIDENT_ORIGINAL_FILE_ENDPOINT = "{base_url}/api/v2/incidents/dlpincidents/{dlp_incident_id}/originalfile"
DLP_INCIDENT_SUB_FILE_ENDPOINT = "{base_url}/api/v2/incidents/dlpincidents/{dlp_incident_id}/subfile"
# Rate limit remaining
RATELIMIT_REMAINING = "ratelimit-remaining"
# Rate limit RESET value is in seconds
RATELIMIT_RESET = "ratelimit-reset"
