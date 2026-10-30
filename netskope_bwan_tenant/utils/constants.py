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

Tenant Netskope Borderless WAN.
"""

MODULE_NAME = "TENANT"
PLUGIN_VERSION = "1.2.0"
PLATFORM_NAME = "Netskope Borderless WAN"
MAX_API_CALLS = 4
DEFAULT_WAIT_TIME = 60
MAINTENANCE_PULL = "maintenance_pulling"
HISTORICAL_PULL = "historical_pulling"
DEFAULT_WAIT_TIME = 30
DATE_FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"
AUDIT_RECORDS_ENDPOINT = "/v2/auditevents"
NETWORK_EVENTS_ENDPOINT = "/v2/networkevents"
ALERTS_ENDPOINT = "/v2/alerts"
# CRE entity endpoints. The entities (Clients, Gateways) are pulled by this
# tenant provider so the netskope CRE flow (common.pull -> cre.fetch_records)
# can drive the CRE Borderless WAN plugin, which then only transforms the data.
CLIENTS_ENDPOINT = "/v2/clients"
GATEWAYS_ENDPOINT = "/v2/gateways"
# Custom CRE entity subtypes (free-form; not a framework data_type). They ride
# under the 'events' data_type, so the scheduled task is tenant.<name>.events.
CRE_ENTITY_CLIENT_SUBTYPE = "cre_entity_client"
CRE_ENTITY_GATEWAY_SUBTYPE = "cre_entity_gateway"
# Per-entity high water marks kept on this tenant's (provider) storage. The
# CRE Borderless WAN plugin clears them on delete (cleanup) so that a later
# re-configure treats its first pull as new and pulls the entity in full.
CRE_ENTITY_CLIENT_CHECKPOINT = "cre_entity_client_checkpoint"
CRE_ENTITY_GATEWAY_CHECKPOINT = "cre_entity_gateway_checkpoint"
# Per-subtype high water marks for the other dedicated endpoints, so that a
# failed subtype re-pulls only its own window instead of losing it when the
# shared checkpoint advances. The audit subtypes share one /v2/auditevents
# call (one 'event_time' window) and keep the per-data-type checkpoint.
NETWORK_EVENT_CHECKPOINT = "bwan_network_event_checkpoint"
ALERT_V2_CHECKPOINT = "bwan_alert_v2_checkpoint"
ENTITY_PULL_SORT_FIELD = "modified_at"
TYPE_EVENT = "events"
TYPE_ALERT = "alerts"
BACK_PRESSURE_WAIT_TIME = 300
# Netskope Borderless WAN caps 'first' at 100 records per API call (O-1).
PAGE_SIZE = 100
# Pages accumulated into one yielded batch so a high-volume subtype (e.g.
# flows) produces fewer, larger CE batches instead of one per 100 records
# (O-2). On an error mid-accumulation the pages buffered so far are yielded
# before the error propagates.
BATCH_PAGE_COUNT = 10
SUBTYPE_LIST_MAPPING = {
    "bwan_audit": "audit",
    "bwan_authentication": "authentication",
    "bwan_client": "client",
    "bwan_gateway": "gateway",
    "bwan_system": "system",
    "bwan_network_event": "network_event",
    "bwan_alert_v2": "alert",
    CRE_ENTITY_CLIENT_SUBTYPE: CRE_ENTITY_CLIENT_SUBTYPE,
    CRE_ENTITY_GATEWAY_SUBTYPE: CRE_ENTITY_GATEWAY_SUBTYPE,
}
# Reverse of SUBTYPE_LIST_MAPPING (internal short name -> CE subtype), built
# once at import time instead of on every pull window (O-6). Used to map a
# pulled audit subtype back to its display subtype in the zero-pull logs.
REVERSE_SUBTYPE_LIST_MAPPING = {
    mapped: display for display, mapped in SUBTYPE_LIST_MAPPING.items()
}
# Display names for the CRE entity subtypes in the pull logs. These are
# entities (records), not events, so they are logged as "Client"/"Gateway
# record(s)" rather than as events.
ENTITY_SUBTYPE_DISPLAY = {
    CRE_ENTITY_CLIENT_SUBTYPE: "Client",
    CRE_ENTITY_GATEWAY_SUBTYPE: "Gateway",
}
SUBTYPE_RESPONSE_MAPPING = {
    "AUDIT": "bwan_audit",
    "AUTHENTICATION": "bwan_authentication",
    "CLIENT": "bwan_client",
    "SYSTEM": "bwan_system",
    "GATEWAY": "bwan_gateway",
}

# Filter strategies for the dedicated-endpoint subtypes.
#   FILTER_RANGE - bound a single field, e.g. ended_at.
#   FILTER_ALERT - bound opened_at OR closed_at. An alert can close long
#                  after it opens, so a window bounded only on opened_at
#                  silently drops closure events.
FILTER_RANGE = "range"
FILTER_ALERT = "alert"
#   FILTER_NONE - no time filter; pull the endpoint in full each cycle.
FILTER_NONE = "none"
#   FILTER_ENTITY - incremental on 'modified_at' using a per-entity high
#                   water mark stored on the tenant. The first run (no
#                   stored checkpoint) pulls the entity in full, then every
#                   cycle pulls only the records modified since the last.
FILTER_ENTITY = "entity"

# Subtypes served by their own endpoint. Unlike the audit subtypes, these
# endpoints return one subtype each and their records carry no "type" field,
# so the response is never bifurcated. Keyed by the SUBTYPE_LIST_MAPPING
# value, which is what paginate() receives.
DEDICATED_ENDPOINT_CONFIG = {
    "network_event": {
        "endpoint": NETWORK_EVENTS_ENDPOINT,
        "sub_type": "bwan_network_event",
        "filter_type": FILTER_RANGE,
        "time_field": "ended_at",
        "checkpoint_key": NETWORK_EVENT_CHECKPOINT,
    },
    "alert": {
        "endpoint": ALERTS_ENDPOINT,
        "sub_type": "bwan_alert_v2",
        "filter_type": FILTER_ALERT,
        "checkpoint_key": ALERT_V2_CHECKPOINT,
    },
    CRE_ENTITY_CLIENT_SUBTYPE: {
        "endpoint": CLIENTS_ENDPOINT,
        "sub_type": CRE_ENTITY_CLIENT_SUBTYPE,
        "filter_type": FILTER_ENTITY,
        "time_field": ENTITY_PULL_SORT_FIELD,
        "checkpoint_key": CRE_ENTITY_CLIENT_CHECKPOINT,
    },
    CRE_ENTITY_GATEWAY_SUBTYPE: {
        "endpoint": GATEWAYS_ENDPOINT,
        "sub_type": CRE_ENTITY_GATEWAY_SUBTYPE,
        "filter_type": FILTER_ENTITY,
        "time_field": ENTITY_PULL_SORT_FIELD,
        "checkpoint_key": CRE_ENTITY_GATEWAY_CHECKPOINT,
    },
}
