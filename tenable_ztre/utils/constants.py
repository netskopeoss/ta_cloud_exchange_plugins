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

CRE Tenable Plugin Constants module.
"""

ASSET_PAGE_SIZE = 1000
VULN_PAGE_SIZE = 50
PLATFORM_NAME = "Tenable"
PLUGIN_VERSION = "1.0.0"
MODULE_NAME = "CRE"
MAX_RETRIES = 4
DEFAULT_SLEEP_TIME = 60
INTEGER_THRESHOLD = 4611686018427387904
MAXIMUM_CE_VERSION = "5.1.2"

CONFIGURATION = "configuration"
ACTION = "action"

RETRY_ERROR_MSG = (
    "Received exit code {status_code}, {error_reason} "
    "while {logger_msg}. Retrying after {wait_time} "
    "seconds. {retry_remaining} retries remaining."
)
NO_MORE_RETRIES_ERROR_MSG = (
    "Received exit code {status_code}, API rate limit "
    "exceeded while {logger_msg}. Max retries for rate "
    "limit handler exceeded hence returning status "
    "code {status_code}."
)
VALIDATION_ERROR_MSG = "Validation error occurred. "

BASE_URL = "https://cloud.tenable.com"

# Tags API endpoints
TAGS_CATEGORIES_ENDPOINT = "{base_url}/tags/categories"
TAGS_VALUES_ENDPOINT = "{base_url}/tags/values"
TAGS_ASSIGNMENTS_ENDPOINT = "{base_url}/tags/assets/assignments"

# Tags API limits
TAGS_API_LIMIT = 5000
TAG_VALUE_MAX_LENGTH = 50
TAG_ASSIGNMENT_BATCH_SIZE = 100

# Assets API endpoints
ASSETS_EXPORT_ENDPOINT = "{base_url}/assets/v2/export"
ASSETS_STATUS_ENDPOINT = "{base_url}/assets/export/{export_uuid}/status"
ASSETS_CHUNK_DOWNLOAD_ENDPOINT = (
    "{base_url}/assets/export/{export_uuid}/chunks/{chunk_id}"
)

# Findings API endpoints
FINDINGS_EXPORT_ENDPOINT = "{base_url}/vulns/export"
FINDINGS_STATUS_ENDPOINT = "{base_url}/vulns/export/{export_uuid}/status"
FINDINGS_CHUNK_DOWNLOAD_ENDPOINT = (
    "{base_url}/vulns/export/{export_uuid}/chunks/{chunk_id}"
)

# Export API status
EXPORT_STATUS_FINISHED = "FINISHED"
EXPORT_STATUS_QUEUED = "QUEUED"
EXPORT_STATUS_PROCESSING = "PROCESSING"
EXPORT_STATUS_CANCELLED = "CANCELLED"
EXPORT_STATUS_ERROR = "ERROR"

STATUS_CHECK_SLEEP_TIME = 60

ASSET_FIELD_MAPPING = {
    "Asset ID": {"key": "id"},
    "Agent UUID": {"key": "agent_uuid"},
    "Asset Types": {"key": "types"},
    "Agent Names": {"key": "agent_names"},
    "Operating Systems": {"key": "operating_systems"},
    "System Types": {"key": "system_types"},
    "Installed Software": {"key": "installed_software"},
    "Serial Number": {"key": "serial_number"},
    "Sources Name": {"key": "sources"},
    "Tags": {"key": "tags", "transformation": "_extract_tags"},
    "IPv4 Addresses": {"key": "network.ipv4s"},
    "IPv6 Addresses": {"key": "network.ipv6s"},
    "FQDNs": {"key": "network.fqdns"},
    "MAC Addresses": {"key": "network.mac_addresses"},
    "Hostnames": {"key": "network.hostnames"},
    "First Seen": {
        "key": "timestamps.first_seen",
        "transformation": "_parse_datetime"
    },
    "Last Seen": {
        "key": "timestamps.last_seen",
        "transformation": "_parse_datetime"
    },
    "Asset Criticality Rating": {"key": "ratings.acr.score"},
    "Asset Exposure Score": {"key": "ratings.aes.score"},
    "Cloud Resource Tags": {
        "key": "resource_tags",
        "transformation": "_extract_tags"
    },
}

FINDINGS_FIELD_MAPPING = {
    "Asset ID": {"key": "asset.uuid"},
    "CVSSv3 Base Score": {"key": "plugin.cvss3_base_score"},
    "CVSSv3 Temporal Score": {"key": "plugin.cvss3_temporal_score"},
    "VPR Score": {"key": "plugin.vpr.score"},
    "EPSS Score": {"key": "plugin.epss_score"},
    "Risk Factor": {"key": "plugin.risk_factor"},
    "Severity": {"key": "severity"},
    "State": {"key": "state"},
    "CVEs": {"key": "plugin.cve"},
}
