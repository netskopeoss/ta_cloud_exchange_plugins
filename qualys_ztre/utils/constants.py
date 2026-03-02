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

CRE Qualys plugin constants.
"""

DEVICE_PAGE_SIZE = 300
WEB_APPLICATION_PAGE_SIZE = 1000
ASSET_VULN_ID_BATCH_SIZE = 1000
WEB_APP_FINDING_ID_BATCH_SIZE = 1000
FINDING_OR_VULN_BATCH_SIZE = 1000
FETCH_TAGS_PAGE_SIZE = 1000
PLUGIN_NAME = "Qualys"
PLATFORM_NAME = "Qualys"
PLUGIN_VERSION = "1.0.0"
MODULE_NAME = "CRE"
MAX_RETRIES = 4
DEFAULT_SLEEP_TIME = 60
INTEGER_THRESHOLD = 4611686018427387904
DATETIME_FORMAT = r"%Y-%m-%dT%H:%M:%SZ"
MAXIMUM_CE_VERSION = "5.1.2"

TAG_NAME_LENGTH = 1024
TAG_ASSET_BATCH_SIZE = 1000
SCAN_ASSET_BATCH_SIZE = 1000
TAG_WEB_APP_BATCH_SIZE = 1000

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
EMPTY_ERROR_MESSAGE = "{field_name} is a required {parameter_type} parameter."
TYPE_ERROR_MESSAGE = (
    "Invalid value provided for the {parameter_type} parameter '{field_name}'."
)
VALIDATION_ERROR_MESSAGE = "Validation error occurred."
INVALID_VALUE_ERROR_MESSAGE = " Allowed values are '{allowed_values}'"

QUALYS_API_SERVER_TO_API_GATEWAY_URL_MAPPING = {
    "https://qualysapi.qualys.com": (
        "https://gateway.qg1.apps.qualys.com"
    ),
    "https://qualysapi.qg2.apps.qualys.com": (
        "https://gateway.qg2.apps.qualys.com"
    ),
    "https://qualysapi.qg3.apps.qualys.com": (
        "https://gateway.qg3.apps.qualys.com"
    ),
    "https://qualysapi.qg4.apps.qualys.com": (
        "https://gateway.qg4.apps.qualys.com"
    ),
    "https://qualysapi.qualys.eu": (
        "https://gateway.qg1.apps.qualys.eu"
    ),
    "https://qualysapi.qg2.apps.qualys.eu": (
        "https://gateway.qg2.apps.qualys.eu"
    ),
    "https://qualysapi.qg3.apps.qualys.it": (
        "https://gateway.qg3.apps.qualys.it"
    ),
    "https://qualysapi.qg1.apps.qualys.in": (
        "https://gateway.qg1.apps.qualys.in"
    ),
    "https://qualysapi.qg1.apps.qualys.ca": (
        "https://gateway.qg1.apps.qualys.ca"
    ),
    "https://qualysapi.qg1.apps.qualys.ae": (
        "https://gateway.qg1.apps.qualys.ae"
    ),
    "https://qualysapi.qg1.apps.qualys.co.uk": (
        "https://gateway.qg1.apps.qualys.co.uk"
    ),
    "https://qualysapi.qg1.apps.qualys.com.au": (
        "https://gateway.qg1.apps.qualys.com.au"
    ),
    "https://qualysapi.qg1.apps.qualysksa.com": (
        "https://gateway.qg1.apps.qualysksa.com"
    ),
    # "https://qualysapi.<customer_base_url>": (
    #     "https://qualysgateway.<customer_base_url>"
    # ),
}

FETCH_ASSETS_API_ENDPOINT = "{api_gateway_url}/rest/2.0/search/am/asset"
FETCH_WEB_APPLICATIONS_API_ENDPOINT = (
    "{api_server_url}/qps/rest/3.0/search/was/webapp"
)
FETCH_ASSET_VULNERABILITY_IDS_API_ENDPOINT = (
    "{api_server_url}/api/5.0/fo/asset/host/vm/detection/"
)
FETCH_VULNERABILITY_DETAILS_API_ENDPOINT = (
    "{api_server_url}/api/4.0/fo/knowledge_base/vuln/"
)
FETCH_WEB_APPLICATION_FINDING_IDS_API_ENDPOINT = (
    "{api_server_url}/qps/rest/3.0/search/was/finding"
)

# Need to add the fields query parameter in the URL itself because adding it
# in the params argument is not working since requests library encodes comma
# (,) to %2C which causes Qualys to send only the pagination parameters in
# the response and not the actual tags data.
FETCH_TAGS_API_ENDPOINT = (
    "{api_server_url}/qps/rest/2.0/search/am/tag?fields=id,name"
)
CREATE_TAG_API_ENDPOINT = "{api_server_url}/qps/rest/2.0/create/am/tag"
TAG_ASSET_API_ENDPOINT = "{api_server_url}/qps/rest/2.0/update/am/hostasset"
SCAN_ASSET_API_ENDPOINT = "{api_server_url}/qps/rest/1.0/ods/ca/agentasset"
TAG_WEBAPP_API_ENDPOINT = (
    "{api_server_url}/qps/rest/3.0/update/was/webapp/{web_app_id}"
)

ASSET_FIELD_MAPPING = {
    "Asset ID": {"key": "assetId", "transformation": "string"},
    "Host ID": {"key": "hostId", "transformation": "string"},
    "Serial Number": {"key": "biosSerialNumber"},
    "Risk Score": {"key": "riskScore"},
    "Criticality Score": {"key": "criticality.score"},
    "Tags": {"key": "tagList.tag"},
    "Asset Type": {"key": "assetType"},
    "IP Address": {"key": "address"},
    "DNS Name": {"key": "dnsName"},
    "Asset Name": {"key": "assetName"},
    "BIOS Asset Tag": {"key": "biosAssetTag"},
    "Users": {
        "key": "userAccountListData.userAccount",
    },
    "Open Ports": {
        "key": "openPortListData.openPort",
    },
    "Network Interfaces": {
        "key": "networkInterfaceListData.networkInterface",
    },
    "Domain": {"key": "domain"},
    "Sub Domain": {"key": "subdomain"},
    "OS": {"key": "operatingSystem.osName"},
}
ASSET_VULNERABILITY_BASIC_INFO_FIELD_MAPPING = {
    "Vulnerability QID": {"key": "QID"},
    "Unique Vulnerability ID": {"key": "UNIQUE_VULN_ID"},
    "Vulnerability Type": {"key": "TYPE"},
    "Vulnerability Severity": {"key": "SEVERITY"},
    "Is SSL": {"key": "SSL"},
    "Vulnerability Status": {"key": "STATUS"},
    "Vulnerability QDS Score": {"key": "QDS.severity"},
}
ASSET_VULNERABILITY_EXTRA_INFO_FIELD_MAPPING = {
    "Vulnerability Category": {"key": "CATEGORY"},
    "Is Patchable": {"key": "PATCHABLE"},
    "Product": {"key": "SOFTWARE_LIST.SOFTWARE.PRODUCT"},
    "Vendor": {"key": "SOFTWARE_LIST.SOFTWARE.VENDOR"},
    "CVE ID": {"key": "CVE_LIST.CVE.ID"},
    "Base CVSS Score": {"key": "CVSS.BASE"},
    "Temporal CVSS Score": {"key": "CVSS.TEMPORAL"},
}
WEB_APPS_FIELD_MAPPING = {
    "Web Application ID": {"key": "id", "transformation": "string"},
    "Web Application Name": {"key": "name"},
    "Web Application URL": {"key": "url"},
    "Risk Score": {"key": "riskScore"},
    "Tags": {"key": "tags.list"},
}

WEB_APPLICATION_FINDING_BASIC_INFO_FIELD_MAPPING = {
    "Finding QID": {"key": "qid"},
    "Finding Type": {"key": "type"},
    "Potential": {"key": "potential"},
    "Finding Detection Score": {"key": "detectionScore"},
    "Finding Severity": {"key": "severity"},
    "Finding Status": {"key": "status"},
}
WEB_APPLICATION_FINDING_EXTRA_INFO_FIELD_MAPPING = {
    "Is Patchable": {"key": "PATCHABLE"},
    "Base CVSS Score": {"key": "CVSS.BASE"},
    "Temporal CVSS Score": {"key": "CVSS.TEMPORAL"},
    "Base CVSS3 Score": {"key": "CVSS_V3.BASE"},
    "Temporal CVSS3 Score": {"key": "CVSS_V3.TEMPORAL"},
}
IS_PATCHABLE_MAPPING = {
    "1": "Yes",
    "0": "No",
}

SCAN_TYPE_OPTIONS = {
    "Inventory_Scan": "Inventory Scan",
    "Vulnerability_Scan": "Vulnerability Scan",
    "PolicyCompliance_Scan": "Policy Audit Scan",
    "UDC_Scan": "UDC Scan",
    "SCA_Scan": "SCA Scan",
    "SWCA_scan": "SWCA Scan",
}
OVERRIDE_CONFIG_CPU_OPTIONS = {
    "True": "Yes",
    "False": "No",
}
YES_NO_OPTIONS = {
    "Yes": "Yes",
    "No": "No",
}
TAG_ACTION_OPTIONS = {
    "add": "Add",
    "remove": "Remove",
}

STORAGE_KEYS = {
    "assets": {
        "fetch": "asset_last_run_at",
        "update": "asset_vulnerability_last_run_at"
    },
    "web applications": {
        "fetch": "web_app_last_run_at",
        "update": "web_app_finding_last_run_at"
    }
}
