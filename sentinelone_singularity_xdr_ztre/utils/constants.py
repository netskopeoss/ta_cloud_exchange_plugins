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

3. Neither the name of the copyright holder nor the names of its
   contributors may be used to endorse or promote products derived from
   this software without specific prior written permission.

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

CRE SentinelOne Singularity XDR Constants module.
"""

PLATFORM_NAME = "SentinelOne Singularity XDR"
PLUGIN_VERSION = "1.0.0"
MODULE_NAME = "CRE"
MAX_RETRIES = 4
DEFAULT_WAIT_TIME = 60
PAGE_SIZE = 1000
GROUP_PAGE_SIZE = 300
BATCH_SIZE = 5000

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

# API Endpoints
SITES_ENDPOINT = "/web/api/v2.1/sites"
ENDPOINT_PULL_ENDPOINT = (
    "/web/api/v2.1/xdr/assets/surface/endpoint"
)
IDENTITY_PULL_ENDPOINT = (
    "/web/api/v2.1/xdr/assets/surface/identity"
)
APPLICATION_ENDPOINT = (
    "/web/api/v2.1/application-management/risks/applications"
)
APPLICATION_VULNERABILITY_ENDPOINT = (
    "/web/api/v2.1/application-management/risks"
)
GROUPS_ENDPOINT = "/web/api/v2.1/groups"
TAGS_ENDPOINT = "/web/api/v2.1/agents/tags"
TAG_MANAGER_ENDPOINT = "/web/api/v2.1/tag-manager"
MANAGE_TAGS_ENDPOINT = "/web/api/v2.1/agents/actions/manage-tags"
MOVE_AGENTS_ENDPOINT = "/web/api/v2.1/groups/{group_id}/move-agents"
NETWORK_DISCONNECT_ENDPOINT = (
    "/web/api/v2.1/agents/actions/disconnect"
)
NETWORK_CONNECT_ENDPOINT = (
    "/web/api/v2.1/agents/actions/connect"
)
ASSET_ACTION_ENDPOINT = (
    "/web/api/v2.1/xdr/assets/action"
)
SCAN_ENDPOINT = "/web/api/v2.1/agents/actions/initiate-scan"
VULN_SCAN_ENDPOINT = (
    "/web/api/v2.1/application-management/scan"
)
REBOOT_ENDPOINT = (
    "/web/api/v2.1/agents/actions/restart-machine"
)

# Asset Criticality action values
ASSET_CRITICALITY_MAP = {
    "low": "mark_asset_criticality_low",
    "medium": "mark_asset_criticality_medium",
    "high": "mark_asset_criticality_high",
    "critical": "mark_asset_criticality_critical",
    "clear": "clear_asset_criticality"
}


# --- Field Mappings ---

DEVICE_ENTITY_MAPPING = {
    "Agent ID": {"key": "agent.id"},
    "Asset ID": {"key": "id"},
    "Asset Name": {"key": "name"},
    "Serial Number": {"key": "serialNumber"},
    "Network Status": {"key": "agent.networkStatus"},
    "IP Address (Public)": {"key": "ipAddress"},
    "Internal IPv4 Addresses": {"key": "internalIps"},
    "Internal IPv6 Addresses": {"key": "internalIpsV6"},
    "MAC Addresses": {"key": "macAddresses"},
    "Domain": {"key": "domain"},
    "Asset Criticality": {"key": "assetCriticality"},
    "Device Review Status": {"key": "deviceReview"},
    "Infection Status": {"key": "infectionStatus"},
    "Risk Factors": {"key": "riskFactors"},
    "Asset Status": {"key": "assetStatus"},
    "Tags": {"key": "tags"},
    "Last Logged In User": {"key": "agent.lastLoggedInUser"},
    "OS Username": {"key": "osUsername"},
    "AD User DN": {"key": "identity.adUserDistinguishedName"},
    "Asset Contact Email": {"key": "assetContactEmail"},
    "Operating System": {"key": "os"},
    "OS Family": {"key": "osFamily"},
    "Site Name": {"key": "s1SiteName"},
    "Member Of": {"key": "s1GroupName"},
}

USER_ENTITY_MAPPING = {
    "Asset ID": {"key": "id"},
    "Distinguished Name": {"key": "distinguishedName"},
    "User Principal Name": {"key": "userPrincipalName"},
    "Domain": {"key": "domain"},
    "Risk Factors": {"key": "riskFactors"},
    "Infection Status": {"key": "infectionStatus"},
    "Asset Status": {"key": "assetStatus"},
    "Privileged Account": {"key": "privileged"},
    "Account Enabled": {"key": "enabled"},
    "Service Account": {"key": "serviceAccount"},
    "Asset Criticality": {"key": "assetCriticality"},
    "Member Of Groups": {"key": "memberOf"},
    "Bad Password Count": {"key": "badPasswordCount"},
    "Deleted": {"key": "deleted"},
    "Tags": {"key": "tags"},
    "Asset Contact Email": {"key": "assetContactEmail"},
    "Email": {"key": "mail"},
    "Site Name": {"key": "s1SiteName"},
    "Display Name": {"key": "displayName"},
    "Sam Account Name": {"key": "samAccountName"},
    "Last Logon Time": {
        "key": "lastLogonTime",
        "transformation": "_parse_datetime",
    },
}


APPLICATION_VULNERABILITY_MAPPING = {
    "Application Vulnerability ID": {"key": "id"},
    "CVE ID": {"key": "cveId"},
    "Application Name": {"key": "applicationName"},
    "Application Vendor": {"key": "applicationVendor"},
    "Endpoint ID": {"key": "endpointId"},
    "Endpoint Name": {"key": "endpointName"},
    "Application Version": {"key": "applicationVersion"},
    "NVD Base Score": {"key": "nvdBaseScore"},
    "Severity": {"key": "severity"},
    "Risk Score": {"key": "riskScore"},
    "Exploit Maturity": {"key": "exploitCodeMaturity"},
    "Remediation Availability": {"key": "remediationLevel"},
    "Confidence Level": {"key": "reportConfidence"},
    "Vulnerability Status": {"key": "status"},
    "Mitigation Status": {"key": "mitigationStatus"},
    "Detection Date": {
        "key": "detectionDate",
        "transformation": "_parse_datetime",
    },
    "Published Date": {
        "key": "publishedDate",
        "transformation": "_parse_datetime",
    },
    "OS Type": {"key": "osType"},
}
