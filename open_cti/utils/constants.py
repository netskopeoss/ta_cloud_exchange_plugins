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

CTE OpenCTI Plugin costants module.
"""

from netskope.integrations.cte.models import IndicatorType

OBSERVABLE_REGEXES = [
    {
        "regex": (
            (
                r"file:hashes\.(?:'SHA-256'|\"SHA-256\")\s*=\s*"
                r"('[a-z0-9]*'|\"[a-z0-9]*\")"
            )
        ),
        "type": getattr(
            IndicatorType,
            "SHA256",
            IndicatorType.SHA256,
        ),
    },
    {
        "regex": (
            r"file:hashes\.(?:MD5|'MD5'|\"MD5\")\s*=\s*"
            r"('[a-z0-9]*'|\"[a-z0-9]*\")"
        ),
        "type": getattr(
            IndicatorType,
            "MD5",
            IndicatorType.MD5,
        ),
    },
    {
        "regex": (
            r"url:value\s*=\s*(?:\"((?:[^\"\\]|\\.)*)\"|'((?:[^'\\]|\\.)*)')"
        ),
        "type": getattr(
            IndicatorType,
            "URL",
            IndicatorType.URL,
        ),
    },
    {
        "regex": (
            r"domain-name:value\s*=\s*"
            r"(?:\"((?:[^\"\\]|\\.)*)\"|'((?:[^'\\]|\\.)*)')"
        ),
        "type": getattr(
            IndicatorType,
            "DOMAIN",
            IndicatorType.URL,
        ),
    },
    {
        "regex": (
            r"ipv4-addr:value\s*=\s*(?:\"((?:[0-9]{1,3}\.){3}[0-9]{1,3})\"|'"
            r"((?:[0-9]{1,3}\.){3}[0-9]{1,3})')"
        ),
        "type": getattr(
            IndicatorType,
            "IPV4",
            IndicatorType.URL,
        ),
    },
    {
        "regex": (
            r"ipv4-addr:value\s*=\s*"
            r"(?:\"((?:[0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2})\""
            r"|'((?:[0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2})')"
        ),
        "type": getattr(
            IndicatorType,
            "URL",
            IndicatorType.URL,
        ),
    },
    {
        "regex": (
            r"ipv6-addr:value\s*=\s*(?:\"([0-9a-fA-F:]+)\"|'([0-9a-fA-F:]+)')"
        ),
        "type": getattr(
            IndicatorType,
            "IPV6",
            IndicatorType.URL,
        ),
    },
]
GRAPHQL_API = "{}/graphql"
INDICATOR_TYPES = ["StixFile", "Domain-Name", "Url", "IPv4-Addr", "IPv6-Addr"]
INTEGER_THRESHOLD = 4611686018427387904
RETRACTION = "Retraction"
DEFAULT_REPUTATION = 5
DEFAULT_WAIT_TIME = 60
MAX_API_CALLS = 4
LIMIT = 1000
MODULE_NAME = "CTE"
PLUGIN_VERSION = "1.0.0"
PLATFORM_NAME = "OpenCTI"
TAG_NAME = "netskope-ce"

INDICATOR_PAGINATION = {
    "query": """
    query Indicators(
      $filters: FilterGroup,
      $search: String,
      $first: Int,
      $after: ID,
      $orderBy: IndicatorsOrdering,
      $orderMode: OrderingMode
    ) {
      indicators(
        filters: $filters,
        search: $search,
        first: $first,
        after: $after,
        orderBy: $orderBy,
        orderMode: $orderMode
      ) {
        edges {
          node {
            id
            objectLabel {
              id
              value
              color
            }
            revoked
            confidence
            created
            modified
            pattern_type
            pattern
            description
            indicator_types
            valid_from
            valid_until
            x_opencti_score
            x_opencti_main_observable_type
          }
        }
        pageInfo {
          startCursor
          endCursor
          hasNextPage
          hasPreviousPage
          globalCount
        }
      }
    }
    """
}

PAGINATION_VARIABLES = {
    "first": 1000,
    "after": None,
    "orderBy": "modified",
    "orderMode": "desc",
    "filters": {
        "mode": "and",
        "filters": [
            {
                "key": "entity_type",
                "values": ["Indicator"],
                "operator": "eq",
                "mode": "or",
            },
            {
                "key": "pattern_type",
                "values": ["stix"],
                "operator": "eq",
                "mode": "or",
            },
        ],
        "filterGroups": [{"mode": "and", "filters": [], "filterGroups": []}],
    },
}

TAGS_ID_QUERY = {
    "query": """
    query LabelsQuerySearchQuery(
      $search: String
    ) {
      labels(search: $search) {
        edges {
          node {
            id
            value
            color
          }
        }
      }
    }
    """
}

INDICATOR_MUTATION = """
    mutation IndicatorCreationMutation($input: IndicatorAddInput!) {
      indicatorAdd(input: $input) {
        id
        standard_id
        name
        description
        entity_type
        parent_types
        pattern_type
        valid_from
        valid_until
        x_opencti_score
        x_opencti_main_observable_type
        created
        confidence
        x_opencti_detection
        createdBy {
          id
          name
          entity_type
        }
        objectMarking {
          id
          definition_type
          definition
          x_opencti_order
          x_opencti_color
        }
        objectLabel {
          id
          value
          color
        }
        creators {
          id
          name
        }
      }
    }
    """

SHARING_TAG_CONSTANT = "Netskope CE"
DEFAULT_IOC_TAG = "netskope-ce"
