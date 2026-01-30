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

CRE Wiz Plugin constants.
"""
PAGE_SIZE = 500
PLATFORM_NAME = "Wiz"
MODULE_NAME = "CRE"
PLUGIN_VERSION = "2.0.0"
MAX_API_CALLS = 4
DEFAULT_WAIT_TIME = 60
MAX_RETRY_AFTER_IN_MIN = 5
INTEGER_THRESHOLD = 4611686018427387904
MAXIMUM_CE_VERSION = "5.1.2"
DATE_TIME_FORMAT = "%Y-%m-%dT%H:%M:%SZ"

GRAPHQL_ENDPOINT = "{api_endpoint_url}/graphql"
AUTH_ENDPOINT = "{token_url}/oauth/token"

# Application
APPLICATION_ENTITY_NAME = "Applications"
GRAPHQL_QUERY = {
   "query": "query Table($first: Int, $after: String, \
   $filterBy: CloudResourceV2Filters) {    cloudResourcesV2(      \
   first: $first      after: $after      filterBy: $filterBy    ) \
   {      nodes {        id        name             type         \
   cloudAccount {            externalId            id        }    \
   graphEntity {            properties            firstSeen        \
   lastSeen        }      }      pageInfo {        hasNextPage      \
   endCursor      }    }  }"
}
APPLICATION_FIELDS = {
   "Application ID": {"key": "id"},
   "Subscription External ID": {"key": "cloudAccount.externalId"},
   "Subscription ID": {"key": "cloudAccount.id"},
   "Application Name": {"key": "name"},
   "Cloud Platform": {"key": "graphEntity.properties.cloudPlatform"},
   "Cloud Provider URL": {"key": "graphEntity.properties.cloudProviderURL"},
   "Creation Date": {"key": "graphEntity.properties.creationDate"},
   "First Seen": {"key": "graphEntity.firstSeen"},
   "Last Seen": {"key": "graphEntity.lastSeen"},
}

# Workloads
WORKLOADS_ENTITY_NAME = "Workloads"
WORKLOADS_QUERY = {
   "query": "query VulnerabilityFindingsPage($filterBy: VulnerabilityFindingFilters, \
   $first: Int, $after: String) \
   {    vulnerabilityFindings(        filterBy: $filterBy      \
   first: $first        after: $after    ) \
   {        nodes {            id            name           score            \
   exploitabilityScore            severity            impactScore            \
   status            cnaScore                \
   epssSeverity            epssPercentile            epssProbability         \
   CVSSSeverity            vulnerableAsset \
   {                ... on VulnerableAssetBase {                    \
   id                    type                    name                    \
   region                    cloudProviderURL                    \
   cloudPlatform                    status                    \
   subscriptionName           subscriptionExternalId           \
   subscriptionId                  tags                }                \
   ... on VulnerableAssetVirtualMachine {                    \
   operatingSystem                    \
   ipAddresses                }            }        }        \
   pageInfo {            hasNextPage            endCursor        }    }}"
}
WORKLOADS_FIELDS = {
   "Workload ID": {"key": "vulnerableAsset.id"},
   "IP Addresses": {"key": "vulnerableAsset.ipAddresses"},
   "Type": {"key": "vulnerableAsset.type"},
   "Name": {"key": "vulnerableAsset.name"},
   "Region": {"key": "vulnerableAsset.region"},
   "Cloud Platform": {"key": "vulnerableAsset.cloudPlatform"},
   "Cloud Provider URL": {"key": "vulnerableAsset.cloudProviderURL"},
   "Status": {"key": "vulnerableAsset.status"},
   "Subscription Name": {"key": "vulnerableAsset.subscriptionName"},
   "Subscription External ID": {"key": "vulnerableAsset.subscriptionExternalId"},
   "Subscription ID": {"key": "vulnerableAsset.subscriptionId"},
   "OS": {"key": "vulnerableAsset.operatingSystem"},
   "Tags": {"key": "vulnerableAsset.tags"},
   "Vulnerability Name": {"key": "name"},
   "CVSS Severity": {"key": "CVSSSeverity"},
   "Vulnerability Score": {"key": "score"},
   "Exploitability Score": {"key": "exploitabilityScore"},
   "Severity": {"key": "severity"},
   "Impact Score": {"key": "impactScore"},
   "Vulnerability Status": {"key": "status"},
   "EPSS Severity": {"key": "epssSeverity"},
   "EPSS Percentile": {"key": "epssPercentile"},
   "EPSS Probability": {"key": "epssProbability"},
   "CNA Score": {"key": "cnaScore"},
}
