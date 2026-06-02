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

CTE Proofpoint plugin constants.
"""


PLUGIN_NAME = "Proofpoint"
MODULE_NAME = "CTE"
PLUGIN_VERSION = "2.0.0"

SIEM_ALL_ENDPOINT = "/v2/siem/all"
DEFAULT_RESPONSE_FORMAT = "JSON"

RETRACTION = "Retraction"

MAX_HOURS = 168
MIN_QUERY_INTERVAL_SECONDS = 30
BOUNDARY_SAFETY_SECONDS = 5
PAGINATION_INTERVAL_HOURS = 1
NON_OVERLAPPING_OFFSET_SECONDS = 1
SECONDS_PER_HOUR = 3600

MAX_API_CALLS = 4
DEFAULT_WAIT_TIME = 60

MAXIMUM_CE_VERSION = "5.1.2"

EVENT_CLICKS_PERMITTED = "clicksPermitted"
EVENT_CLICKS_BLOCKED = "clicksBlocked"
EVENT_MESSAGES_DELIVERED = "messagesDelivered"
EVENT_MESSAGES_BLOCKED = "messagesBlocked"

VALID_EVENT_TYPES = [
    EVENT_CLICKS_PERMITTED,
    EVENT_CLICKS_BLOCKED,
    EVENT_MESSAGES_DELIVERED,
    EVENT_MESSAGES_BLOCKED,
]

TAG_CLICK_PERMITTED = "Click Permitted"
TAG_CLICK_BLOCKED = "Click Blocked"
TAG_MESSAGE_DELIVERED = "Message Delivered"
TAG_MESSAGE_BLOCKED = "Message Blocked"
DEFAULT_TAG_COLOR = "#FF0000"

EVENT_TYPE_TAG_MAP = {
    EVENT_CLICKS_PERMITTED: TAG_CLICK_PERMITTED,
    EVENT_CLICKS_BLOCKED: TAG_CLICK_BLOCKED,
    EVENT_MESSAGES_DELIVERED: TAG_MESSAGE_DELIVERED,
    EVENT_MESSAGES_BLOCKED: TAG_MESSAGE_BLOCKED,
}

VALIDATION_ERROR_MSG = "Validation error occurred. "
AUTH_SUCCESS_MSG = "Authentication Successful."
AUTH_UNEXPECTED_ERROR_MSG = (
    "Error occurred while validating account credentials. Check Logs."
)

DOMAIN_REGEX = (
    r"^(?:\*\.)?[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?"
    r"(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?)*"
    r"\.[a-zA-Z]{2,}"
)
DOMAIN_REGEX_2 = (
    r"(?<!-)(?<![:\/\w.])(?:\*\.[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?"
    r"(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}|"
    r"(?<!\*)[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?(?:\.[a-zA-Z0-9]"
    r"(?:[a-zA-Z0-9-]*[a-zA-Z0-9])?)*\.[a-zA-Z]{2,})"
    r"(?::(?:6553[0-5]|655[0-2]\d|65[0-4]\d{2}|"
    r"6[0-4]\d{3}|[1-5]\d{4}|\d{1,4}))?"
    r"(?:\/)?(?![:\/\w])"
)
FQDN_REGEX = (
    r"^(?=.{1,253}$)((?!-)[A-Za-z0-9-]{1,63}(?<!-)\.){2,}"
    r"[A-Za-z]{2,63}$"
)
