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

CTE Rubrik plugin constants.
"""

MODULE_NAME = "CTE"
PLUGIN_NAME = "Rubrik"
PLATFORM_NAME = "Rubrik"
PLUGIN_VERSION = "1.0.0"
MAX_API_CALLS = 4
DEFAULT_WAIT_TIME = 60
DEFAULT_BATCH_SIZE = 200
MAX_WAIT_TIME = 300
BATCH_SIZE = 15000
DATE_FORMAT = r"%Y-%m-%dT%H:%M:%S.%f%zZ"
DATE_FORMAT_FOR_IOCS = r"%Y-%m-%dT%H:%M:%SZ"
DEFAULT_NETSKOPE_TAG = "netskope-ce"
THREAT_TYPES = ["sha256", "md5"]
HUNT_SOURCE_TAG = "(Created from Netskope CE)"
FILE_SIZE_LIMIT = 15000
MAX_IOC_MATCHES = 1000
MAX_RETRY_AFTER_IN_MIN = 5

INCLUDE_FILE_LIST = [
    "*.acm",
    "*.ax",
    "*.cpl",
    "*.dll",
    "*.drv",
    "*.efi",
    "*.exe",
    "*.mui",
    "*.ocx",
    "*.scr",
    "*.sys",
    "*.tsp",
]

GET_CLUSTER_UUID_AND_LIST_QUERY = """
      query ClusterPickerQuery($first: Int, $after: String, $filter: ClusterFilterInput, $sortBy: ClusterSortByEnum, $sortOrder: SortOrder) {
      clusterConnection(filter: $filter, sortBy: $sortBy, sortOrder: $sortOrder, first: $first, after: $after) {
         edges {
         cursor
         node {
            id
            status
            ...ClusterIconNameFragment
            ...ClusterVersionColumnFragment
            ...ClusterTypeColumnFragment
            ...ClusterCapacityColumnFragment
            ...ClusterProtectedCountColumnFragment
            ...ClusterGeoLocationColumnFragment
            ...ClusterNameColumnFragment
            __typename
         }
         __typename
         }
         pageInfo {
         startCursor
         endCursor
         hasNextPage
         hasPreviousPage
         __typename
         }
         __typename
      }
      }

      fragment ClusterIconNameFragment on Cluster {
      id
      name
      status
      pauseStatus
      state {
         clusterRemovalState
         __typename
      }
      defaultAddress
      passesConnectivityCheck
      connectivityLastUpdated
      ...ClusterNodeConnectionFragment
      globalManagerConnectivityStatus {
         urls {
         url
         isReachable
         __typename
         }
         __typename
      }
      systemStatus
      ccprovisionInfo {
         jobStatus
         jobType
         progress
         vendor
         __typename
      }
      __typename
      }

      fragment ClusterNodeConnectionFragment on Cluster {
      clusterNodeConnection {
         nodes {
         id
         status
         ipAddress
         __typename
         }
         __typename
      }
      __typename
      }

      fragment ClusterVersionColumnFragment on Cluster {
      version
      eosDate
      eosStatus
      __typename
      }

      fragment ClusterTypeColumnFragment on Cluster {
      name
      productType
      type
      clusterNodeConnection {
         nodes {
         id
         __typename
         }
         __typename
      }
      __typename
      }

      fragment ClusterCapacityColumnFragment on Cluster {
      metric {
         usedCapacity
         availableCapacity
         totalCapacity
         __typename
      }
      __typename
      }

      fragment ClusterProtectedCountColumnFragment on Cluster {
      productType
      noSqlWorkloadCount
      ...ClusterProtectedSnappablesFragment
      __typename
      }

      fragment ClusterProtectedSnappablesFragment on Cluster {
      protectedSnappables: snappableConnection(filter: {protectionStatus: Protected}) {
         count
         __typename
      }
      __typename
      }

      fragment ClusterGeoLocationColumnFragment on Cluster {
      geoLocation {
         address
         __typename
      }
      __typename
      }

      fragment ClusterNameColumnFragment on Cluster {
      name
      __typename
      }
      """

GET_TOTAL_OBJECT_FIDS_QUERY = """
                query SnappableQuery($first: Int, $after: String, $typeFilter: [HierarchyObjectTypeEnum!], $filter: [Filter!], $sortBy: HierarchySortByField, $sortOrder: SortOrder) {
                inventoryRoot {
                    descendantConnection(first: $first, after: $after, typeFilter: $typeFilter, filter: $filter, sortBy: $sortBy, sortOrder: $sortOrder) {
                    edges {
                        cursor
                        node {
                        id
                        ... on WindowsFileset {
                            isPassThrough
                            __typename
                        }
                        ... on ShareFileset {
                            isPassThrough
                            __typename
                        }
                        ... on LinuxFileset {
                            isPassThrough
                            __typename
                        }
                        ... on O365Onedrive {
                            userPrincipalName
                            __typename
                        }
                        ...EffectiveSlaColumnFragment
                        ...HierarchyObjectClusterColumnFragment
                        ...HierarchyObjectLocationColumnFragment
                        ...HierarchyObjectNameColumnFragment
                        ...HierarchyObjectTypeFragment
                        ... on AzureNativeVirtualMachine {
                            region
                            isAdeEnabled
                            resourceGroup {
                            subscription {
                                name
                                __typename
                            }
                            __typename
                            }
                            effectiveSlaDomain {
                            ...ArchivalSpecFragment
                            __typename
                            }
                            __typename
                        }
                        ... on AzureNativeManagedDisk {
                            region
                            isAdeEnabled
                            resourceGroup {
                            subscription {
                                name
                                __typename
                            }
                            __typename
                            }
                            effectiveSlaDomain {
                            ...ArchivalSpecFragment
                            __typename
                            }
                            __typename
                        }
                        ... on CloudDirectNasExport {
                            exportPath
                            __typename
                        }
                        __typename
                        }
                        __typename
                    }
                    pageInfo {
                        endCursor
                        hasNextPage
                        hasPreviousPage
                        __typename
                    }
                    __typename
                    }
                    __typename
                }
                }

                fragment EffectiveSlaColumnFragment on HierarchyObject {
                id
                effectiveSlaDomain {
                    ...EffectiveSlaDomainFragment
                    ... on GlobalSlaReply {
                    description
                    __typename
                    }
                    __typename
                }
                ... on CdmHierarchyObject {
                    pendingSla {
                    ...SLADomainFragment
                    __typename
                    }
                    __typename
                }
                __typename
                }

                fragment EffectiveSlaDomainFragment on SlaDomain {
                id
                name
                ... on GlobalSlaReply {
                    isRetentionLockedSla
                    retentionLockMode
                    __typename
                }
                ... on ClusterSlaDomain {
                    fid
                    cluster {
                    id
                    name
                    __typename
                    }
                    isRetentionLockedSla
                    retentionLockMode
                    __typename
                }
                __typename
                }

                fragment SLADomainFragment on SlaDomain {
                id
                name
                ... on ClusterSlaDomain {
                    fid
                    cluster {
                    id
                    name
                    __typename
                    }
                    __typename
                }
                __typename
                }

                fragment HierarchyObjectClusterColumnFragment on HierarchyObject {
                ...CdmClusterLabelFragment
                ... on CloudDirectHierarchyObject {
                    cluster {
                    id
                    name
                    __typename
                    }
                    __typename
                }
                __typename
                }

                fragment CdmClusterLabelFragment on CdmHierarchyObject {
                cluster {
                    id
                    name
                    version
                    __typename
                }
                primaryClusterLocation {
                    id
                    __typename
                }
                __typename
                }

                fragment HierarchyObjectLocationColumnFragment on HierarchyObject {
                logicalPath {
                    name
                    objectType
                    __typename
                }
                physicalPath {
                    name
                    objectType
                    __typename
                }
                __typename
                }

                fragment HierarchyObjectNameColumnFragment on HierarchyObject {
                name
                __typename
                }

                fragment HierarchyObjectTypeFragment on HierarchyObject {
                objectType
                __typename
                }

                fragment ArchivalSpecFragment on GlobalSlaReply {
                archivalSpec {
                    storageSetting {
                    targetType
                    __typename
                    }
                    __typename
                }
                archivalSpecs {
                    storageSetting {
                    targetType
                    __typename
                    }
                    __typename
                }
                __typename
                }
                """

START_THREAT_HUNT_QUERY = """
                mutation StartThreatHuntMutation($input:StartThreatHuntInput!) 
                { startThreatHunt(input: $input)
                    {
                        huntId isSyncSuccessful __typename
                    }
                }
                """

BIFURCATE_INDICATOR_TYPES = {
    "url",
    "domain",
    "hostname",
    "ipv4",
    "ipv6",
    "fqdn",
}
