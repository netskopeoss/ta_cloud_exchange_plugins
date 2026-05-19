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

CRE AWS Inspector Plugin constants.
"""

PLATFORM_NAME = "AWS Inspector"
MODULE_NAME = "CRE"
PLUGIN_VERSION = "1.0.0"
MAXIMUM_CE_VERSION = "5.1.2"
MAX_INITIAL_RANGE_DAYS = 20000

# AWS Inspector v2 list_findings allows up to 100 results per page.
BATCH_SIZE = 100
ENRICHMENT_BATCH_SIZE = 10

# Inspector v2 enforces a strict ARN format on BatchGetFindingDetails.
# The API rejects the ENTIRE batch if any single ARN does not match this
# pattern, so we pre-validate locally and skip non-conforming ARNs rather
# than letting one malformed record poison enrichment for the whole chunk.
INSPECTOR_FINDING_ARN_PATTERN = (
    r"^arn:(aws[a-zA-Z-]*)?:inspector2:"
    r"[a-z]{2}(-gov)?-[a-z]+-\d{1}:\d{12}:finding/[a-f0-9]{32}$"
)

DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"

AUTHENTICATION_METHODS = [
    "aws_iam_roles_anywhere",
    "deployed_on_aws",
]

RETRY_ATTEMPTS = 3
RETRY_MODE = "standard"

USER_AGENT = "APN/1.1 (ahq9d89xj9gspapczzdb59goq)"

# Inspector EC2 resource type filter (only EC2 findings are pulled).
EC2_RESOURCE_TYPE = "AWS_EC2_INSTANCE"

REGIONS = [
    "us-east-2",
    "us-east-1",
    "us-west-1",
    "us-west-2",
    "af-south-1",
    "ap-east-1",
    "ap-south-1",
    "ap-northeast-3",
    "ap-northeast-2",
    "ap-southeast-1",
    "ap-southeast-2",
    "ap-northeast-1",
    "ca-central-1",
    "cn-north-1",
    "cn-northwest-1",
    "eu-central-1",
    "eu-west-1",
    "eu-west-2",
    "eu-south-1",
    "eu-west-3",
    "eu-north-1",
    "me-south-1",
    "sa-east-1",
    "ap-south-2",
    "ap-southeast-3",
    "eu-south-2",
    "eu-central-2",
    "me-central-1",
    "ca-west-1",
    "ap-southeast-4",
    "il-central-1",
    "ap-southeast-7",
    "ap-southeast-5",
    "mx-central-1"
]

DEVICE_FIELD_MAPPING = {
    # Core identity
    "Finding ID": {"key": "findingArn", "context": "event"},
    "Resource ID": {"key": "id", "context": "resource"},
    "Resource Name": {"key": "Name", "context": "tags"},
    "Region": {"key": "region", "context": "resource"},

    # Network / workload context
    "VPC ID": {"key": "vpcId", "context": "ec2_details"},
    "Subnet ID": {"key": "subnetId", "context": "ec2_details"},
    "Resource Tags": {"key": "tags", "context": "resource"},

    # Severity / risk (initial, pre-enrichment)
    "Severity": {"key": "severity", "context": "event"},
    "Inspector Score": {"key": "inspectorScore", "context": "event"},
    "Exploit Available": {"key": "exploitAvailable", "context": "event"},

    # Finding metadata
    "Finding Type": {"key": "type", "context": "event"},
    "Title": {"key": "title", "context": "event"},
    "Description": {"key": "description", "context": "event"},
    "First Seen": {"key": "firstObservedAt", "context": "event"},
    "Last Seen": {"key": "lastObservedAt", "context": "event"},

    "Vulnerability ID": {
        "key": "packageVulnerabilityDetails.vulnerabilityId",
        "context": "event",
    },

    # Network reachability (only populated for NETWORK_REACHABILITY type)
    "Port": {
        "key": "openPortRange.begin", "context": "network_reach"
    },
    "Protocol": {"key": "protocol", "context": "network_reach"},
}

EC2_IPV4_KEY = "ipV4Addresses"

ENRICHMENT_FIELD_MAPPING = {
    "Risk Score": {"key": "riskScore"},
    "EPSS Score": {"key": "epssScore"},
}

ENTITY_NAME = "Workloads"

ACTION_NO_OP = "generate"
ACTION_CREATE_SUPPRESSION_RULE = "create_suppression_rule"

SUPPRESSION_ACTION_VALUES = {ACTION_CREATE_SUPPRESSION_RULE}

# AWS Inspector v2 quotas for filterCriteria and list_filters.
LIST_FILTERS_MAX_RESULTS = 100

DEFAULT_SUPPRESSION_RULE_NAME = "CE-Inspector-Suppression-Rule"
DEFAULT_SUPPRESSION_REASON = "Suppressed by Netskope Cloud Exchange"

MAX_SUPPRESSION_RULE_NAME_LENGTH = 128

SOURCE_FIELD_PREFIX = "$"

REGION_CHOICES = [
    {
        "key": "US East (N. Virginia) [us-east-1]",
        "value": "us-east-1",
    },
    {"key": "US East (Ohio) [us-east-2]", "value": "us-east-2"},
    {
        "key": "US West (N. California) [us-west-1]",
        "value": "us-west-1",
    },
    {
        "key": "US West (Oregon) [us-west-2]",
        "value": "us-west-2",
    },
    {
        "key": "Africa (Cape Town) [af-south-1]",
        "value": "af-south-1",
    },
    {
        "key": "Asia Pacific (Hong Kong) [ap-east-1]",
        "value": "ap-east-1",
    },
    {
        "key": "Asia Pacific (Mumbai) [ap-south-1]",
        "value": "ap-south-1",
    },
    {
        "key": "Asia Pacific (Hyderabad) [ap-south-2]",
        "value": "ap-south-2",
    },
    {
        "key": "Asia Pacific (Tokyo) [ap-northeast-1]",
        "value": "ap-northeast-1",
    },
    {
        "key": "Asia Pacific (Seoul) [ap-northeast-2]",
        "value": "ap-northeast-2",
    },
    {
        "key": "Asia Pacific (Osaka) [ap-northeast-3]",
        "value": "ap-northeast-3",
    },
    {
        "key": "Asia Pacific (Singapore) [ap-southeast-1]",
        "value": "ap-southeast-1",
    },
    {
        "key": "Asia Pacific (Sydney) [ap-southeast-2]",
        "value": "ap-southeast-2",
    },
    {
        "key": "Asia Pacific (Jakarta) [ap-southeast-3]",
        "value": "ap-southeast-3",
    },
    {
        "key": "Asia Pacific (Melbourne) [ap-southeast-4]",
        "value": "ap-southeast-4",
    },
    {
        "key": "Asia Pacific (Malaysia) [ap-southeast-5]",
        "value": "ap-southeast-5",
    },
    {
        "key": "Asia Pacific (Thailand) [ap-southeast-7]",
        "value": "ap-southeast-7",
    },
    {
        "key": "Canada (Central) [ca-central-1]",
        "value": "ca-central-1",
    },
    {
        "key": "Canada (Calgary) [ca-west-1]",
        "value": "ca-west-1",
    },
    {
        "key": "China (Beijing) [cn-north-1]",
        "value": "cn-north-1",
    },
    {
        "key": "China (Ningxia) [cn-northwest-1]",
        "value": "cn-northwest-1",
    },
    {
        "key": "Europe (Frankfurt) [eu-central-1]",
        "value": "eu-central-1",
    },
    {
        "key": "Europe (Zurich) [eu-central-2]",
        "value": "eu-central-2",
    },
    {
        "key": "Europe (Ireland) [eu-west-1]",
        "value": "eu-west-1",
    },
    {
        "key": "Europe (London) [eu-west-2]",
        "value": "eu-west-2",
    },
    {"key": "Europe (Paris) [eu-west-3]", "value": "eu-west-3"},
    {"key": "Europe (Milan) [eu-south-1]", "value": "eu-south-1"},
    {"key": "Europe (Spain) [eu-south-2]", "value": "eu-south-2"},
    {
        "key": "Europe (Stockholm) [eu-north-1]",
        "value": "eu-north-1",
    },
    {
        "key": "Israel (Tel Aviv) [il-central-1]",
        "value": "il-central-1",
    },
    {
        "key": "Mexico (Central) [mx-central-1]",
        "value": "mx-central-1",
    },
    {
        "key": "Middle East (Bahrain) [me-south-1]",
        "value": "me-south-1",
    },
    {
        "key": "Middle East (UAE) [me-central-1]",
        "value": "me-central-1",
    },
    {
        "key": "South America (São Paulo) [sa-east-1]",
        "value": "sa-east-1",
    },
]

SUPPRESSION_FILTER_FIELD_CHOICES = [
    {"key": "Finding ARN", "value": "finding_arn"},
    {"key": "Resource ID", "value": "resource_id"},
    {"key": "VPC ID", "value": "vpc_id"},
    {"key": "Subnet ID", "value": "subnet_id"},
    {"key": "Resource Tag", "value": "resource_tag"},
    {"key": "Severity", "value": "severity"},
    {"key": "Inspector Score", "value": "inspector_score"},
    {"key": "Exploit Available", "value": "exploit_available"},
    {"key": "Vulnerability ID", "value": "vulnerability_id"},
    {"key": "Title", "value": "title"},
    {"key": "Open Port", "value": "open_port"},
    {"key": "Protocol", "value": "protocol"},
]

SUPPRESSION_FILTER_FIELD_MAP = {
    "finding_arn":      {"key": "findingArn",        "type": "string"},
    "resource_id":      {"key": "resourceId",         "type": "string"},
    "vpc_id":           {"key": "ec2InstanceVpcId",   "type": "string"},
    "subnet_id":        {"key": "ec2InstanceSubnetId", "type": "string"},
    "resource_tag":     {"key": "resourceTags",       "type": "map"},
    "severity":         {"key": "severity",           "type": "string"},
    "inspector_score":  {"key": "inspectorScore",     "type": "number"},
    "exploit_available": {"key": "exploitAvailable",  "type": "string"},
    "vulnerability_id": {"key": "vulnerabilityId",    "type": "string"},
    "title":            {"key": "title",              "type": "string"},
    "open_port":        {"key": "portRange",          "type": "port"},
    "protocol":         {"key": "networkProtocol",    "type": "string"},
}

SUPPRESSION_FILTER_FIELD_VALUES = {
    c["value"] for c in SUPPRESSION_FILTER_FIELD_CHOICES
}
