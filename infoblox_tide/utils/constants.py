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

CTE Infoblox Plugin constants.
"""

DATETIME_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
MODULE_NAME = "CTE"
PLATFORM_NAME = "Infoblox"
PLUGIN_VERSION = "2.0.0"
DEFAULT_WAIT_TIME = 60
MAX_API_CALLS = 4
RETRACTION = "Retraction"
DEFAULT_SLEEP_TIME = 60
INDICATOR_TYPES = {
    "Domain": "domain",
    "Hash": "hash",
    "Host": "host",
    "IPv4": "ipv4",
    "IPv6": "ipv6",
    "URL": "url",
}
HASH_TYPES = ["sha256", "md5"]
IP_TYPES = ["ipv4", "ipv6"]
DEFAULT_SLEEP_TIME = 60
INTEGER_THRESHOLD = 4611686018427387904
MAX_API_CALLS = 4
TIME_PAGINATION_INTERVAL_1_DAY = 24  # 24 hours
TIME_PAGINATION_INTERVAL_1_HOUR = 1  # 1 hour
IOC_UI_ENDPOINT = "{base_url}/#/security_research/search/auto/{value}/summary"
DEFAULT_PUSH_BATCH = 100000
ACTIVE_INDICATORS_RESPONSE_LIMIT = 50000
SOC_INSIGHTS_PULL_LIMIT = 10000
ACTIVE_INDICATORS = "Active Indicators"
LOOKALIKE_DOMAINS = "Lookalike Domains"
SOC_INSIGHTS = "SOC Insights"
PULL = "pull"
PUSH = "push"
INDICATOR_SOURCE_PAGES = {
    ACTIVE_INDICATORS: "active_indicators",
    LOOKALIKE_DOMAINS: "lookalike_domains",
    SOC_INSIGHTS: "soc_insights",
}
SOC_INSIGHT_IOC_ACTION_TYPES = {
    "Blocked": "blocked",
    "Not Blocked": "not blocked",
}
CONFIGURATION_BOOLEAN_VALUES = {"Yes": "yes", "No": "no"}
INFOBLOX_LOOKALIKE_DOMAINS_PULL_LIMIT = 1000
BASE_PULL_LOGGER_MESSAGE = (
    " {fetch_type} for page {page_number} from"
    " {indicator_source_page} page of {platform_name} server"
)
IOC_TYPE_REGEX = {
    "domain": r"^((?=[a-z0-9-]{1,63}\.)(xn--)?[a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,63}$",
    "hostname": r"^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$",
    "fqdn": r"^(?=.{1,255}$)(?:(?!-)[A-Za-z0-9-]{1,63}(?<!-)\.)+(?:[A-Za-z]{2,})\.?$",
    "sha256": r"^[a-fA-F0-9]{64}$",
    "md5": r"^[a-fA-F0-9]{32}$",
}
INFOBLOX_PAGE_TO_SERVICE_MAPPING = {
    ACTIVE_INDICATORS: "TIDE",
    LOOKALIKE_DOMAINS: "Lookalike Domains",
    SOC_INSIGHTS: "SOC Insights",
}
FETCH_PROPERTIES_ENDPOINT = "{base_url}/tide/api/data/properties"
DATA_PROFILES_ENDPOINT = "{base_url}/tide/admin/v1/resources/dataprofiles"
FETCH_ACTIVE_INDICATORS_ENDPOINT = "{base_url}/tide/api/data/threats"
FETCH_LOOKALIKE_DOMAINS_ENDPOINT = "{base_url}/api/tdlad/v1/lookalike_domains"
FETCH_INSIGHTS_ENDPOINT = "{base_url}/api/v1/insights"
FETCH_INSIGHTS_INDICATORS_ENDPOINT = (
    "{base_url}/api/v1/insights/{insight_id}/indicators"
)
PUSH_ACTIVE_INDICATORS_ENDPOINT = "{base_url}/tide/api/data/batches"
