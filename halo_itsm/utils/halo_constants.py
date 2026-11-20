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

3. Neither the name of the copyright holder nor the names of its contributors
   may be used to endorse or promote products derived from this software
   without specific prior written permission.

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

HaloITSM Plugin constants.
"""

from netskope.integrations.itsm.models import Severity

PLATFORM_NAME = "HaloITSM"
MODULE_NAME = "CTO"
PLUGIN_VERSION = "2.0.0"
MAX_RETRIES = 4
DEFAULT_WAIT_TIME = 60
PAGE_SIZE = 100  # Max page_size supported by GET /api/Team
BASE_URL = "https://{}.haloitsm.com"

# Endpoints
AUTH_TOKEN_ENDPOINT = "/auth/token"
TICKETS_ENDPOINT = "/api/tickets"
ACTIONS_ENDPOINT = "/api/Actions"
TEAM_ENDPOINT = "/api/Team"
TICKET_TYPE_ENDPOINT = "/api/TicketType"
STATUS_ENDPOINT = "/api/Status"
USERS_ENDPOINT = "/api/Users"

# HaloITSM Actions API requires a mandatory outcome label
CREATE_NOTE_OUTCOME = "Note"

# Token storage keys
ACCESS_TOKEN_KEY = "access_token"
TOKEN_EXPIRY_KEY = "token_expiry"
CONFIG_HASH_KEY = "config_hash"
TOKEN_EXPIRY_BUFFER = 60  # Seconds before expiry to trigger refresh

# Agent email → linked_agent_id cache key in CE persistent storage
AGENT_CACHE_KEY = "agent_email_cache"

# Translates fieldinfo.name values (returned by GET /api/TicketType/{id})
# to the actual field keys accepted by POST /api/tickets.
# HaloITSM uses internal ITSM names in the TicketType API that differ
# from the REST field names used in ticket creation/update payloads.
FIELD_NAME_MAP = {
    # Incident / common fields
    "symptom": "summary",
    "symptom2": "details",
    "seriousness": "priority_id",
    "dateoccured": "dateoccurred",
    "fisdowntime": "is_downtime",
    "fserviceid": "serviceid",
    "assignedtoint": "agent_id",
    "sectio_": "team",
    "supplier": "supplier_id",
    # Category fields
    "category2": "category_1",
    "category5": "category_4",
    # Source / template
    "frequestsource": "source",
    "ftemplateparentid": "template_id",
    # Change fields
    "frisklevel": "risklevel",
    "fchangeinformationhtml": "changeinformation_html",
    "ftestplan": "testplan",
    "fbackoutplan": "backoutplan",
    "fcommunicationplan": "communicationplan",
    # Date fields
    "FProjectStartDate": "startdate",
    "FOppTargetDate": "targetdate",
    # Project fields
    "FProjectTimeBudget": "projecttimebudget",
    # Financial / inventory
    "fcost": "cost",
    "fquantity": "quantity",
    "fDeliveryAddress": "delivery_address",
    # Knowledge article fields
    "FArticleDescription": "article_description",
    "FArticleResolution": "article_resolution",
    "FArticleNotes": "article_notes",
}

# Fields that require a dict in the POST payload.
DICT_FIELD_WRAPPERS = {
    "delivery_address": "line2",
}

# Any mapping field NOT in this set is treated as a HaloITSM custom field
# and sent inside customfields[] in the POST payload.
STANDARD_POST_FIELDS = set(FIELD_NAME_MAP.values()) | {
    "impact",
    "urgency",
    "notepad",
}

# Field names used by different ticket types for impact and urgency.
# Both 'impact'/'urgency' (label fields) and 'impact_id'/'urgency_id'
# (ID fields) may appear depending on the ticket type definition.
IMPACT_FIELD_NAMES = {"impact", "impact_id"}
URGENCY_FIELD_NAMES = {"urgency", "urgency_id"}

# Maps human-readable impact labels to the integer IDs expected by the
# HaloITSM POST /api/tickets endpoint.
# Keys are lowercase for case-insensitive lookup.
# Numeric input (e.g. "1", "2", "3") is handled as a direct int fallback.
IMPACT_LABEL_TO_ID = {
    "company wide": 1,
    "multiple users affected": 2,
    "single user affected": 3,
}

# Maps human-readable urgency labels to the integer IDs expected by the
# HaloITSM POST /api/tickets endpoint.
# Keys are lowercase for case-insensitive lookup.
# Numeric input (e.g. "1", "2", "3") is handled as a direct int fallback.
URGENCY_LABEL_TO_ID = {
    "high": 1,
    "medium": 2,
    "low": 3,
}

# Mapping from HaloITSM priority_id to CE Severity
SEVERITY_MAPPINGS = {
    1: Severity.CRITICAL,
    2: Severity.HIGH,
    3: Severity.MEDIUM,
    4: Severity.LOW,
}
