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

CRE HPE Mist Plugin constants.
"""

from netskope.integrations.crev2.plugin_base import EntityFieldType

MODULE_NAME = "CRE"
PLATFORM_NAME = "HPE Mist"
PLUGIN_NAME = "HPE Mist Access Assurance"
PLUGIN_VERSION = "1.0.0"

# --------------------------------------------------------------------------- #
# Retry / networking
# --------------------------------------------------------------------------- #
# Maximum number of retry attempts on a 429/5xx response before the API
# call is given up on.
MAX_API_CALLS = 4
# Flat wait (in seconds) used for every retry attempt when a response
# carries no 'Retry-After' header - the same value for both the Mist
# and NAC APIs, on every retry_counter (no exponential doubling).
DEFAULT_WAIT_TIME = 60
# Hard ceiling (in seconds) on a single computed wait, whether it comes
# from a 'Retry-After' header or from DEFAULT_WAIT_TIME above. Per
# the TDD, once the computed wait would exceed this value the retry loop
# is ABORTED immediately (the error is raised) instead of sleeping for a
# capped duration and trying again — do not turn this into a
# min(wait, MAX_RETRY_AFTER) capped-sleep pattern.
MAX_RETRY_AFTER = 300
# HPE Mist's documented API quota (calls per rolling hour, per API
# token/account). Not enforced by call-counting in this plugin — the
# quota is bounded by CE's own pull-interval configuration, and quota
# exhaustion surfaces as a 429 the same as any other rate-limit response,
# handled by the retry/abort logic above. Referenced only in log
# resolution text so an operator knows what a persistent 429 likely
# means and that the next scheduled pull will retry once the quota
# resets, rather than the plugin waiting out the hour in-process (which
# would exceed the platform's own request timeout).
MIST_HOURLY_RATE_LIMIT = 5000
# Per-request timeout (in seconds) passed to requests.request.
DEFAULT_REQUEST_TIMEOUT = 120

# --------------------------------------------------------------------------- #
# Pagination
# --------------------------------------------------------------------------- #
# Page size used for both the 'devices' pull and the 'inventory/search'
# site-discovery pull (page/limit query params, page incrementing from 1,
# stop when a page returns fewer rows than PAGE_SIZE). The TDD confirms
# limit=100 for 'devices'; the same page/limit shape is assumed for
# 'inventory/search' since its own pagination parameter names are not
# documented (TDD assumption, carried forward here).
PAGE_SIZE = 100

# --------------------------------------------------------------------------- #
# Authentication
# --------------------------------------------------------------------------- #
# Token Authentication is the only supported method for pulling Device
# (Access Point) records from the HPE Mist API.
#
# Values below MUST match the manifest.json 'fetch_access_points' choice
# 'key' display strings exactly, since
# self.configuration["fetch_access_points"] holds whichever display
# string the user selected.
FETCH_ACCESS_POINTS_YES = "Yes"
FETCH_ACCESS_POINTS_NO = "No"
FETCH_ACCESS_POINTS_CHOICES = [
    FETCH_ACCESS_POINTS_YES,
    FETCH_ACCESS_POINTS_NO,
]
DEFAULT_FETCH_ACCESS_POINTS = FETCH_ACCESS_POINTS_NO

# Label-enrichment toggle values. Match the 'key' display strings of the
# FETCH_LABELS_DYNAMIC_FIELDS choice field below exactly (also rendered
# dynamically, not declared in manifest.json).
FETCH_LABELS_YES = "Yes"
FETCH_LABELS_NO = "No"
FETCH_LABELS_CHOICES = [FETCH_LABELS_YES, FETCH_LABELS_NO]
DEFAULT_FETCH_LABELS = FETCH_LABELS_NO

# 'Fetch Access Points' master switch (replaces the old standalone
# 'fetch_access_points' boolean field, and later the three-way
# 'auth_method' choice that also offered Basic Authentication — Basic
# Authentication is no longer supported and has been removed). It
# selects which of the plugin's two workflows a configuration uses:
#   FETCH_ACCESS_POINTS_YES - pull Device (Access Point) records from
#                     the HPE Mist API using Token Authentication. Its
#                     credentials (and Base URL / Organization ID) are
#                     then required; the NAC block is optional.
#   FETCH_ACCESS_POINTS_NO  - do not pull any devices from Mist (the
#                     default). Only the NAC workflow is used, so the
#                     five NAC configuration fields become mandatory
#                     instead and the Mist connection fields are not
#                     required.
# The requirement is enforced in validate() and
# is_fetch_access_points_enabled() (not via field visibility). This
# could not be a second, independent field/trigger - the plugin already
# has exactly one has_api_call trigger (Fetch Access Points) and cannot
# add a second (see the "Dynamic configuration fields" section comment
# below).

# --------------------------------------------------------------------------- #
# User-Agent
# --------------------------------------------------------------------------- #
# The TDD specifies an exact User-Agent shape that deviates from the usual
# "{ce_agent}-{module}-{plugin_name}-{version}" pattern: the module
# segment is lowercase 'cre' (not 'CRE') and the vendor segment is the
# hyphenated 'hpe-mist-access-assurance' (not the space-to-hyphen
# conversion of PLUGIN_NAME, which would also yield
# 'HPE-Mist-Access-Assurance' with capitals).
# e.g.:
# netskope-ce-v<ce_version>-cre-hpe-mist-access-assurance-v<plugin_version>
USER_AGENT_MODULE_SEGMENT = "cre"
USER_AGENT_VENDOR_SEGMENT = "hpe-mist-access-assurance"

# --------------------------------------------------------------------------- #
# API endpoints
# --------------------------------------------------------------------------- #
# All endpoint constants are full format strings (including {base_url}),
# so a helper only ever does ENDPOINT.format(...) with the placeholders it
# has on hand — no separate URL-joining step is required.
SELF_ENDPOINT = "{base_url}/api/v1/self"
ORG_INVENTORY_SEARCH_ENDPOINT = (
    "{base_url}/api/v1/orgs/{org_id}/inventory/search"
)
# Returns every Site under the Organization, each carrying "id" and
# "name" - the source of truth for resolving the configured "Site
# Names" to the site_id values the other Mist endpoints need. Replaces
# inventory/search as the site-discovery source (inventory/search is
# now used only for its mac -> status map).
ORG_SITES_ENDPOINT = "{base_url}/api/v1/orgs/{org_id}/sites"
SITE_DEVICES_ENDPOINT = "{base_url}/api/v1/sites/{site_id}/devices"
# Used for both GET (list WX Tags / label enrichment source) and POST
# (Create Label action) — same URL, different HTTP method.
SITE_WXTAGS_ENDPOINT = "{base_url}/api/v1/sites/{site_id}/wxtags"
# DELETE — Delete Label action.
SITE_WXTAG_ENDPOINT = (
    "{base_url}/api/v1/sites/{site_id}/wxtags/{wxtag_id}"
)

# --------------------------------------------------------------------------- #
# Entities
# --------------------------------------------------------------------------- #
DEVICES_ENTITY = "Devices"
SUPPORTED_ENTITIES = [DEVICES_ENTITY]

# --------------------------------------------------------------------------- #
# Entity field mapping: CE field name -> source spec.
#   key            : flat field name in the 'GET /sites/{site_id}/devices'
#                    response (no dot-notation needed, the payload is flat).
#   transformation : dispatched by _extract_field_from_event() —
#                    "string"/"integer"/"float" use the built-in casts;
#                    "boolean", "epoch_datetime", "json_string" and "list"
#                    are custom transformations implemented in the helper.
# 'Labels' and 'Status' are intentionally NOT here: both are derived
# fields sourced from a DIFFERENT endpoint than the one this mapping
# reads. 'Labels' comes from 'GET /sites/{site_id}/wxtags'
# (device_id -> [tag.name, ...]); 'Status' comes from
# 'GET /orgs/{org_id}/inventory/search' (mac -> status, e.g.
# 'connected') — the devices endpoint itself never returns a status
# field at all. Both are populated separately in fetch_records()
# after this mapping is applied.
# --------------------------------------------------------------------------- #
FIELD_MAPPING = {
    "Unique ID": {"key": "id", "transformation": "string"},
    "Name": {"key": "name", "transformation": "string"},
    "MAC Address": {"key": "mac", "transformation": "string"},
    "Serial Number": {"key": "serial", "transformation": "string"},
    "Model": {"key": "model", "transformation": "string"},
    "Hardware Revision": {"key": "hw_rev", "transformation": "string"},
    "Device Type": {"key": "type", "transformation": "string"},
    "Adopted": {"key": "adopted", "transformation": "boolean"},
    "Notes": {"key": "notes", "transformation": "string"},
    "Radio Config": {
        "key": "radio_config",
        "transformation": "json_string",
    },
    "Locating": {"key": "locating", "transformation": "boolean"},
    "Tags": {"key": "tags", "transformation": "list"},
    "Site ID": {"key": "site_id", "transformation": "string"},
    "Organization ID": {"key": "org_id", "transformation": "string"},
    "Created Time": {
        "key": "created_time",
        "transformation": "epoch_datetime",
    },
    "Modified Time": {
        "key": "modified_time",
        "transformation": "epoch_datetime",
    },
    "Map ID": {"key": "map_id", "transformation": "string"},
    "Tag UUID": {"key": "tag_uuid", "transformation": "string"},
    "Tag ID": {"key": "tag_id", "transformation": "integer"},
    "EVPN Scope": {"key": "evpn_scope", "transformation": "string"},
    "EVPN Topology ID": {
        "key": "evpntopo_id",
        "transformation": "string",
    },
    "Static IP Base": {"key": "st_ip_base", "transformation": "string"},
    "Device Profile ID": {
        "key": "deviceprofile_id",
        "transformation": "string",
    },
    "Bundled MAC": {"key": "bundled_mac", "transformation": "string"},
    "Mist Configured": {
        "key": "mist_configured",
        "transformation": "boolean",
    },
}
# Name of the derived Labels field, populated outside FIELD_MAPPING.
LABELS_FIELD = "Labels"
# Name of the derived Status field, populated outside FIELD_MAPPING
# from GET /orgs/{org_id}/inventory/search (mac -> status), since the
# devices endpoint itself never returns a status field.
STATUS_FIELD = "Status"
# CE field name -> EntityFieldType override for FIELD_MAPPING keys whose
# type is not the STRING default.
ENTITY_FIELD_TYPE_OVERRIDES = {
    "Adopted": EntityFieldType.BOOLEAN,
    "Locating": EntityFieldType.BOOLEAN,
    "Mist Configured": EntityFieldType.BOOLEAN,
    "Created Time": EntityFieldType.DATETIME,
    "Modified Time": EntityFieldType.DATETIME,
    "Tag ID": EntityFieldType.NUMBER,
    "Tags": EntityFieldType.LIST,
}
# CE field name -> short description, used for both FIELD_MAPPING keys
# and the derived "Labels" field.
ENTITY_FIELD_DESCRIPTIONS = {
    "Unique ID": "Unique identifier of the device in HPE Mist.",
    "Name": "Name of the device.",
    "MAC Address": "MAC address of the device.",
    "Serial Number": "Serial number of the device.",
    "Model": "Hardware model of the device.",
    "Hardware Revision": "Hardware revision of the device.",
    "Device Type": "Type of the device, e.g. ap, switch, gateway.",
    "Adopted": "Whether the device has been adopted into the site.",
    "Notes": "Free-text notes recorded against the device.",
    "Radio Config": "Radio configuration of the device (JSON string).",
    "Locating": "Whether locating is enabled for the device.",
    "Tags": "Device-level tags set by Mist administrators.",
    "Site ID": "Mist Site ID the device belongs to.",
    "Organization ID": "Mist Organization ID the device belongs to.",
    "Created Time": "Timestamp the device record was created.",
    "Modified Time": "Timestamp the device record was last modified.",
    "Map ID": "Floor plan map ID the device is placed on, if any.",
    "Tag UUID": "Opaque tag UUID identifier for the device.",
    "Tag ID": "Opaque numeric tag identifier for the device.",
    "EVPN Scope": "EVPN topology scope of the device, if any.",
    "EVPN Topology ID": "EVPN topology ID of the device, if any.",
    "Static IP Base": "Static IP base configured for the device.",
    "Device Profile ID": (
        "Device profile ID assigned to the device, if any."
    ),
    "Bundled MAC": "Bundled/stacked unit MAC address, if any.",
    "Mist Configured": "Whether the device is fully configured by Mist.",
    LABELS_FIELD: (
        "WX Tag label names the device belongs to, derived from the "
        "site's WX Tags. Empty when Fetch Labels is 'No'."
    ),
    STATUS_FIELD: (
        "Connectivity status of the device (e.g. 'connected'), from "
        "GET /orgs/{org_id}/inventory/search during this pull. Not "
        "available from the devices endpoint itself; null if the "
        "device's MAC address was not found in that inventory "
        "snapshot."
    ),
}
# CE field names used to resolve a record's own identity for actions that
# target the acted-on record itself (Update Device Notes and Tags has no
# manual device selector — site_id/device_id come from the record).
UNIQUE_ID_FIELD = "Unique ID"
SITE_ID_FIELD = "Site ID"
MAC_ADDRESS_FIELD = "MAC Address"

# --------------------------------------------------------------------------- #
# Dynamic configuration fields (get_dynamic_fields())
# --------------------------------------------------------------------------- #
# manifest.json's static 'configuration' array intentionally contains only
# 'Base URL' and 'Fetch Access Points' (config key 'fetch_access_points')
# — the ONLY has_api_call trigger in this plugin. CE renders
# get_dynamic_fields()'s entire return as one block directly after
# 'Fetch Access Points' and fully replaces it (not appends) every time
# the trigger changes, so this method must
# always return the complete, freshly recomputed set for the current
# configuration, in display order: Token Authentication's credential
# field, Organization ID, Site Names, then Fetch Labels.
#
# Two designs were tried and rejected before landing on exactly ONE
# has_api_call trigger for this plugin, full stop:
#   1. Nesting a second has_api_call field INSIDE this method's return
#      (instead of the static manifest), to get live reactivity on it
#      too. This produced unbounded recursion in CE's dependent-field
#      diff walker (routers/repos.py:_get_config_diff) — it treats any
#      has_api_call field it finds in the output as needing its own
#      dependents resolved too, calls get_dynamic_fields() again, gets
#      the identical field back (self.configuration hasn't changed),
#      and never terminates. Not hypothetical: ~900+ real recursion
#      frames, crashing plugin upload with a downstream
#      'bson.errors.InvalidBSON: maximum recursion depth exceeded'.
#   2. Making a second field a SECOND static has_api_call trigger, a
#      sibling of 'Fetch Access Points' in manifest.json (not nested —
#      this avoided the recursion crash). This produced a different,
#      also-unacceptable bug: switching Fetch Access Points started
#      appending a duplicate set of fields instead of replacing them,
#      once two independent has_api_call triggers existed in the same
#      manifest — CE's per-trigger full-replace guarantee apparently
#      only holds for a single trigger.
#
# Every confirmed-working has_api_call example elsewhere in this repo
# (amazon_security_lake, aws_inspector_ztre, forescout_eyefocus_ztre)
# also has exactly ONE such trigger — never two, never nested.
#
# The five NAC fields are declared as plain STATIC fields in
# manifest.json (before Base URL) — not returned by this method — so
# they render by default without depending on the trigger. They are
# "mandatory": False at the manifest level; validate() enforces all five
# when Fetch Access Points is 'No' (otherwise all-or-nothing once at
# least one is filled in), and the two NAC actions refuse to be saved
# until all five are present.
#
# Always rendered first in the dynamic block (before the Token
# Authentication credential field). Base URL is part of the Mist
# device-pull connection, so it belongs with the auth fields rather
# than the static manifest. mandatory:False at the field level; the real
# requirement is conditional on 'Fetch Access Points' being 'Yes' and
# is enforced in validate() (see the FETCH_ACCESS_POINTS_NO comment
# above). None of the fields below this point are returned at all when
# fetch_access_points == FETCH_ACCESS_POINTS_NO - get_dynamic_fields()
# returns [] in that case.
BASE_URL_DYNAMIC_FIELDS = [
    {
        "label": "Base URL",
        "key": "base_url",
        "type": "text",
        "default": "",
        "placeholder": "https://api.mist.com",
        "mandatory": False,
        "description": (
            "Base URL of your HPE Mist API endpoint.e.g. "
            "https://api.mist.com"
        ),
    },
]
# Revealed when fetch_access_points == FETCH_ACCESS_POINTS_YES. Token
# Authentication is the only supported method.
TOKEN_AUTH_DYNAMIC_FIELDS = [
    {
        "label": "API Token",
        "key": "api_key",
        "type": "password",
        "default": "",
        # Conditionally required, enforced in validate() only when
        # 'Fetch Access Points' is 'Yes' (see the FETCH_ACCESS_POINTS_NO
        # comment above).
        "mandatory": False,
        "description": (
            "API token generated from the HPE Mist dashboard. Navigate"
            " to 'My Account > API Token' to generate the API token."
        ),
    },
]
# Always revealed (unconditionally returned by get_dynamic_fields(), right
# after the Token Authentication field above), since it does not itself
# depend on any other field's value.
ORG_ID_DYNAMIC_FIELDS = [
    {
        "label": "Organization ID",
        "key": "org_id",
        "type": "text",
        "default": "",
        # Conditionally required, enforced in validate() only when
        # 'Fetch Access Points' is 'Yes' (see the FETCH_ACCESS_POINTS_NO
        # comment above).
        "mandatory": False,
        "description": (
            "HPE Mist Organization ID to pull Devices from. Navigate to"
            " 'Organizations > Settings' page to obtain the Organization ID"
            " for your Mist Instance."
        ),
    },
]
# Always revealed, immediately after Organization ID. Plain entry —
# deliberately does NOT carry 'has_api_call'/'payload_fields' (see the
# "Dynamic configuration fields" section-header comment above for why
# a second trigger, nested or sibling, is not safe/stable here).
# Optional and self-gating: an empty value means "pull Devices from
# every Site under the configured Organization ID"; a non-empty,
# comma-separated value means "pull Devices only from the named
# Site(s)" — there is no separate Yes/No toggle. Names are resolved to
# site_id via GET /orgs/{org_id}/sites (see ORG_SITES_ENDPOINT); a
# configured name not found under the Organization is skipped (logged
# in aggregate, not per-name), and it is a hard failure only when NONE
# of the configured names resolve to a Site.
SITE_NAME_DYNAMIC_FIELDS = [
    {
        "label": "Site Names",
        "key": "site_name",
        "type": "text",
        "default": "",
        "mandatory": False,
        "description": (
            "Comma-separated list of HPE Mist Site Names to fetch "
            "Devices from. Leave blank to fetch Devices from all the "
            "Site under the configured Organization ID. Navigate to"
            " 'Organization > Site Configuration' to obtain the Site"
            " Names."
        ),
    },
]
# Always revealed, last in the dynamic block (after Site Names).
FETCH_LABELS_DYNAMIC_FIELDS = [
    {
        "label": "Fetch Labels",
        "key": "fetch_labels",
        "type": "choice",
        "choices": [
            {"key": FETCH_LABELS_YES, "value": FETCH_LABELS_YES},
            {"key": FETCH_LABELS_NO, "value": FETCH_LABELS_NO},
        ],
        "default": DEFAULT_FETCH_LABELS,
        "mandatory": True,
        "description": (
            "Select 'Yes' to update each Device record with its WX "
            "Tag labels. Select 'No' to skip pulling labels."
        ),
    },
]

# --------------------------------------------------------------------------- #
# NAC (Juniper NAC / EDR API) - connection, endpoints, storage
# --------------------------------------------------------------------------- #
# The NAC / EDR API is a DIFFERENT service from the Mist API this plugin
# already talks to: different host, different credentials, and its own
# client-credentials token flow. Its five connection fields are plugin
# configuration (not action parameters) so the Client Secret can be a
# 'password' field and the credentials are entered once per
# configuration.
NAC_PLATFORM_NAME = "HPE Mist NAC"

# Endpoint format strings. 'nac_base_url' contributes ONLY the host part -
# '/v1' and the org/account segments belong here, not to the configured
# base URL. The token endpoint really does sit under
# {org_id}/{account_id}; that is confirmed correct, unusual as it is for
# a client-credentials endpoint.
NAC_TOKEN_ENDPOINT = (
    "{base_url}/v1/{org_id}/{account_id}/netskope/edr/token"
)
NAC_DEVICES_ENDPOINT = (
    "{base_url}/v1/{org_id}/{account_id}/netskope/edr/devices"
)
NAC_DELETE_DEVICE_ENDPOINT = (
    "{base_url}/v1/{org_id}/{account_id}/netskope/edr/devices/{uuid}"
)

# Max device objects sent in one POST to NAC_DEVICES_ENDPOINT (Add
# Devices to NAC only). Tunable here without touching the action logic.
NAC_DEVICE_BATCH_SIZE = 100

# self.storage keys. Prefixed with 'nac_' to keep the key scoped and
# unambiguous within the shared storage dict.
NAC_STORAGE_TOKEN_KEY = "nac_access_token"
NAC_STORAGE_CONFIG_HASH_KEY = "nac_config_hash"

# Configuration keys of the five NAC fields, in the exact order their
# values are concatenated (NO delimiter) before sha256-hashing for the
# token cache key. Order is fixed by the TDD: Base URL, Client ID,
# Client Secret, Mist Org ID, Netskope Account ID. Also used to check
# the NAC block is fully filled in before a NAC action may be saved.
NAC_BASE_URL_KEY = "nac_base_url"
NAC_CLIENT_ID_KEY = "nac_client_id"
NAC_CLIENT_SECRET_KEY = "nac_client_secret"
NAC_MIST_ORG_ID_KEY = "nac_mist_org_id"
NAC_NETSKOPE_ACCOUNT_ID_KEY = "nac_netskope_account_id"
# (config key, display label) pairs in hash/validation order.
NAC_CONFIG_FIELDS = [
    (NAC_BASE_URL_KEY, "NAC API Base URL"),
    (NAC_CLIENT_ID_KEY, "Client ID"),
    (NAC_CLIENT_SECRET_KEY, "Client Secret"),
    (NAC_MIST_ORG_ID_KEY, "Mist Org ID"),
    (NAC_NETSKOPE_ACCOUNT_ID_KEY, "Netskope Account ID"),
]

# --------------------------------------------------------------------------- #
# NAC device object - action parameter key == request body key
# --------------------------------------------------------------------------- #
# Every field uses the same string for both the CE action-parameter key
# and the NAC request-body key.
NAC_DEVICE_UUID_FIELD = "netskope_device_uuid"
NAC_MAC_ADDRESSES_FIELD = "mac_addresses"
# CE action-parameter key for the 'Labels' field, and the NAC
# request-body key its values (a list of strings) are sent under.
NAC_LABELS_FIELD = "labels"
# CE action-parameter key ('Connection Type' in the UI) AND NAC
# request-body key for the device's connection type. A static choice of
# 'wired' / 'wireless' (the exact values sent to the NAC API).
NAC_ETHER_TYPE_FIELD = "ether_type"
NAC_ETHER_TYPE_WIRED = "wired"
NAC_ETHER_TYPE_WIRELESS = "wireless"
# The two accepted values. The field is optional: when it is left blank
# the key is omitted and the NAC API defaults it to 'wireless'.
NAC_ETHER_TYPE_CHOICES = [NAC_ETHER_TYPE_WIRED, NAC_ETHER_TYPE_WIRELESS]
# Plain string fields: copied straight across when non-empty, key
# omitted entirely when empty (never sent as null or ""). Order matches
# the request body order in the TDD.
NAC_DEVICE_STRING_FIELDS = [
    "hostname",
    "username",
    "os",
    "os_version",
    "device_make",
    "device_model",
]

# --------------------------------------------------------------------------- #
# NAC configuration fields
# --------------------------------------------------------------------------- #
# The five NAC connection fields are declared as PLAIN STATIC fields in
# manifest.json (before Base URL), NOT returned by get_dynamic_fields().
# They therefore render by default, independently of the single
# 'Fetch Access Points' has_api_call trigger, so they no longer depend
# on that trigger firing to appear. Their keys/labels/types are the
# manifest source of truth; the (key, label) pairs used for validation
# and token-cache hashing live in NAC_CONFIG_FIELDS above. Their real
# requirement is enforced in validate() (all five when Fetch Access
# Points is disabled, otherwise all-or-nothing once any one is filled in)
# and in validate_action() (all five before either NAC action may run).

# --------------------------------------------------------------------------- #
# Actions
# --------------------------------------------------------------------------- #
ACTION_GENERATE = "generate"
# Add Label / Remove Label are consolidated into ONE action value with
# an internal "Label Action" choice parameter (LABEL_ACTION_ADD /
# LABEL_ACTION_REMOVE), mirroring this repo's orca_security_ztre
# ("Add/Remove Tag") and crowdstrike_ztre ("Add/Remove Tag(s)")
# pattern — a single ActionWithoutParams entry, not two.
ACTION_ADD_REMOVE_LABEL = "add_remove_label"
# The two NAC / EDR API actions. Labels: 'Add/Update NAC Devices' and
# 'Delete NAC Devices'.
ACTION_ADD_DEVICES_TO_NAC = "add_devices_to_nac"
ACTION_DELETE_DEVICE_FROM_NAC = "delete_device_from_nac"
# Actions that talk to the NAC / EDR API instead of the Mist API. They
# do not need a Mist auth header at all, so execute_actions() dispatches
# them before it generates one.
NAC_ACTIONS = [
    ACTION_ADD_DEVICES_TO_NAC,
    ACTION_DELETE_DEVICE_FROM_NAC,
]
SUPPORTED_ACTIONS = [
    ACTION_GENERATE,
    ACTION_ADD_REMOVE_LABEL,
    ACTION_ADD_DEVICES_TO_NAC,
    ACTION_DELETE_DEVICE_FROM_NAC,
]
# Choice values for the "Label Action" parameter of ACTION_ADD_REMOVE_LABEL.
LABEL_ACTION_ADD = "add"
LABEL_ACTION_REMOVE = "remove"
LABEL_ACTION_CHOICES = [LABEL_ACTION_ADD, LABEL_ACTION_REMOVE]
DEFAULT_LABEL_ACTION = LABEL_ACTION_ADD
# Choice values for the "Operation" parameter of ACTION_ADD_REMOVE_LABEL,
# corresponding 1:1 to a WX Tag's own "op" field. Must match an existing
# label's "op" exactly to be considered the same label (see
# HPEMistAccessAssurancePluginHelper.match_wxtag()); used as-is (with
# WXTAG_MATCH_TYPE) when a new label is created.
LABEL_OPERATION_IN = "in"
LABEL_OPERATION_NOT_IN = "not_in"
LABEL_OPERATION_CHOICES = [LABEL_OPERATION_IN, LABEL_OPERATION_NOT_IN]
DEFAULT_LABEL_OPERATION = LABEL_OPERATION_IN
# The WX Tag "match" type this plugin always creates/looks for. A
# same-named WX Tag with any other "match" value (e.g. Mist's built-in
# "mac"/"sdkclient_uuid" client-tag types) is never treated as a
# candidate for ACTION_ADD_REMOVE_LABEL - only as "not found".
WXTAG_MATCH_TYPE = "ap_id"
# Number of device ids batched into a single WX Tag create/update call
# for ACTION_ADD_REMOVE_LABEL, grouped by (Site, Label Name, Label
# Action, Operation).
LABEL_DEVICE_BATCH_SIZE = 100
# Actions that aggregate device identifiers across records and batch
# them: ACTION_ADD_REMOVE_LABEL by Device Unique ID in groups of
# LABEL_DEVICE_BATCH_SIZE (see _collect_label_targets()/
# _execute_add_remove_label() in main.py).
BULK_DEVICE_ACTIONS = [
    ACTION_ADD_REMOVE_LABEL,
]

# --------------------------------------------------------------------------- #
# Validation
# --------------------------------------------------------------------------- #
CONFIGURATION = "configuration"
ACTION = "action"

VALIDATION_ERROR_MESSAGE = "Error occurred during validation."
EMPTY_ERROR_MESSAGE = (
    "'{field_name}' is a required {parameter_type} parameter."
)
TYPE_ERROR_MESSAGE = (
    "Invalid value provided for the {parameter_type} parameter "
    "'{field_name}'."
)
INVALID_VALUE_ERROR_MESSAGE = " Allowed values are {allowed_values}."
INVALID_URL_ERROR_MESSAGE = (
    " Provide a valid URL, for example 'https://api.mist.com'."
)
EMPTY_CSV_ERROR_MESSAGE = (
    " Comma-separated values must not contain an empty value."
)
WHITESPACE_ONLY_ERROR_MESSAGE = " The field must not contain only whitespace."
# HPE Mist trims a WX Tag name beyond this length rather than
# rejecting it outright. A Static "Label Name" value is hard-rejected
# at validate_action() time when any comma-separated label name
# exceeds this (see _validate_label_name_lengths() on the plugin
# class); a Source Field value is only warned about, after grouping,
# at execute_actions() time (see _collect_label_targets()), since the
# platform will silently trim it rather than fail.
LABEL_NAME_CHARACTER_LIMIT = 64
INVALID_LABEL_NAME_LENGTH_ERROR_MESSAGE = (
    " Each comma-separated label name must be {limit} characters or "
    "less."
)
STATIC_FIELD_ERROR_MESSAGE = (
    "{field_name} contains the Source Field. Please select {field_name} "
    "from the Static Field dropdown only."
)
SOURCE_FIELD_ERROR_MESSAGE = (
    "{field_name} does not contain the Source Field. Please select "
    "{field_name} from the Source Field dropdown only."
)
# Raised by validate_action() when a NAC action is being saved but the
# NAC configuration block is not fully filled in. The NAC fields are
# 'mandatory': False in get_dynamic_fields(), so this is where the real
# requirement is enforced.
NAC_CONFIG_INCOMPLETE_ERROR_MESSAGE = (
    "'{field_name}' is required in the configuration parameters to use "
    "the '{action_label}' action."
)

# --------------------------------------------------------------------------- #
# Error message templates (API / retry)
# --------------------------------------------------------------------------- #
RETRY_ERROR_MSG = (
    "Received exit code {status_code}, {error_reason} while {logger_msg}. "
    "Retrying after {wait_time} second(s). {retry_remaining} retries left."
)
NO_MORE_RETRIES_ERROR_MSG = (
    "Received exit code {status_code} while {logger_msg}. "
    "Maximum retry limit reached."
)
RETRY_ABORTED_ERROR_MSG = (
    "Received exit code {status_code} while {logger_msg}. Computed "
    "retry wait of {wait_time} second(s) exceeds the maximum allowed "
    "wait of {max_wait} second(s). Aborting retries."
)
