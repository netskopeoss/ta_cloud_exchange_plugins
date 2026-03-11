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

CRE CrowdStrike Falcon Spotlight Plugin Constants module.
"""

PAGE_SIZE = 5000
PLUGIN_NAME = "CrowdStrike Falcon Spotlight"
PLATFORM_NAME = "CrowdStrike Falcon Spotlight"
PLUGIN_VERSION = "1.0.0"
MODULE_NAME = "CRE"
MAX_RETRIES = 4
DEFAULT_SLEEP_TIME = 60
INTEGER_THRESHOLD = 4611686018427387904
DATETIME_FORMAT = r"%Y-%m-%dT%H:%M:%SZ"
BASE_URLS = {
    "https://api.crowdstrike.com": "Commercial cloud (api.crowdstrike.com)",
    "https://api.us-2.crowdstrike.com": "US 2 (api.us-2.crowdstrike.com)",
    "https://api.laggar.gcw.crowdstrike.com": "Falcon on GovCloud (api.laggar."
    "gcw.crowdstrike.com)",
    "https://api.eu-1.crowdstrike.com": "EU cloud (api.eu-1.crowdstrike.com)",
}
MAXIMUM_CE_VERSION = "5.1.2"
RETRY_ERROR_MSG = (
    "Received exit code {status_code}, {error_reason}"
    " while {logger_msg}. Retrying after {wait_time} "
    "seconds. {retry_remaining} retries remaining."
)
NO_MORE_RETRIES_ERROR_MSG = (
    "Received exit code {status_code}, API rate limit "
    "exceeded while {logger_msg}. Max retries for rate"
    " limit handler exceeded hence returning status"
    " code {status_code}."
)
VALIDATION_ERROR_MSG = "Validation error occurred. "

OAUTH_URL = "{base_url}/oauth2/token"
FETCH_VULNERABILITIES_API_ENDPOINT = (
    "{base_url}/spotlight/combined/vulnerabilities/v1"
)
VULNERABILITY_FIELD_MAPPING = {
    "ID": {"key": "id"},
    "AID": {"key": "aid"},
    "Status": {"key": "status"},
    "Confidence": {"key": "confidence"},
    "Hostname": {"key": "host_info.hostname"},
    "Local IP": {"key": "host_info.local_ip"},
    "Machine Domain": {"key": "host_info.machine_domain"},
    "Site name": {"key": "host_info.site_name"},
    "Tags": {"key": "host_info.tags"},
    "Asset Criticality": {"key": "host_info.asset_criticality"},
    "Internet Exposure": {"key": "host_info.internet_exposure"},
    "Instance ID": {"key": "host_info.instance_id"},
    "Service Provider Account ID": {
        "key": "host_info.service_provider_account_id"
    },
    "Service Provider": {"key": "host_info.service_provider"},
    "Managed By": {"key": "host_info.managed_by"},
    "Host Confidence": {"key": "host_info.confidence_label"},
    "CVE ID": {"key": "cve.id"},
    "CVE Base Score": {"key": "cve.base_score"},
    "CVE Severity": {"key": "cve.severity"},
    "CVE Exploit Status": {"key": "cve.exploit_status"},
    "CVE ExPRT Rating": {"key": "cve.exprt_rating"},
    "CVE Name": {"key": "cve.name"},
    "CVE Types": {"key": "cve.types"},
    "CVE Actors": {"key": "cve.actors"},
    "CVE Description": {"key": "cve.description"},
    "CVE Exploitability Score": {"key": "cve.exploitability_score"},
    "CVE Impact Score": {"key": "cve.impact_score"},
    "CVE Vector": {"key": "cve.vector"},
}

CVE_EXPLOIT_STATUS_MAPPING = {
    0: "UNPROVEN",
    30: "AVAILABLE",
    60: "EASILY_ACCESSIBLE",
    90: "ACTIVELY_USED",
}
