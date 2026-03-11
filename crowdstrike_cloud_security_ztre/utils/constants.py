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

CRE CrowdStrike Cloud Security Constants module.
"""

PAGE_SIZE = 1000
IOM_PAGE_SIZE = 500
IOA_RESOURCES_PAGE_SIZE = 1000
PLUGIN_NAME = "CrowdStrike Falcon Cloud Security"
PLATFORM_NAME = "CrowdStrike Falcon Cloud Security"
PLUGIN_VERSION = "1.0.1"
MODULE_NAME = "CRE"
IOM_ENTITY_NAME = "Cloud Workloads (Applications)"
MAX_API_CALLS = 4
NORMALIZATION_MULTIPLIER = 10
DEFAULT_WAIT_TIME = 60
MAX_RETRY_AFTER_IN_MIN = 5
CROWDSTRIKE_DATE_FORMAT = r"%Y-%m-%dT%H:%M:%SZ"
INTEGER_THRESHOLD = 4611686018427387904
BASE_URLS = [
    "https://api.crowdstrike.com",
    "https://api.us-2.crowdstrike.com",
    "https://api.laggar.gcw.crowdstrike.com",
    "https://api.eu-1.crowdstrike.com",
]
IOA_CLOUD_PROVIDERS = ["aws", "azure"]
IOM_CLOUD_PROVIDERS = ["aws", "azure", "gcp"]
CLOUD_SERVICES = [
    "ACM",
    "ACR",
    "Any",
    "App Engine",
    "AppService",
    "BigQuery",
    "Cloud Load Balancing",
    "Cloud Logging",
    "Cloud SQL",
    "Cloud Storage",
    "CloudFormation",
    "CloudTrail",
    "CloudWatch Logs",
    "Cloudfront",
    "Compute Engine",
    "Config",
    "Disk",
    "DynamoDB",
    "EBS",
    "EC2",
    "ECR",
    "EFS",
    "EKS",
    "ELB",
    "EMR",
    "Elasticache",
    "GuardDuty",
    "IAM",
    "Identity",
    "KMS",
    "KeyVault",
    "Kinesis",
    "Kubernetes",
    "Lambda",
    "LoadBalancer",
    "Monitor",
    "NLB/ALB",
    "NetworkSecurityGroup",
    "PostgreSQL",
    "RDS",
    "Redshift",
    "S3",
    "SES",
    "SNS",
    "SQLDatabase",
    "SQLServer",
    "SQS",
    "SSM",
    "Serverless Application Repository",
    "StorageAccount",
    "Subscriptions",
    "VPC",
    "VirtualMachine",
    "VirtualNetwork",
]
IOM_FIELD_MAPPING = {
    "Instance ID": {"key": "resource_attributes.Instance Id"},
    "Instance Name": {"key": "resource_attributes.Instance Name"},
    "Instance Type": {"key": "resource_attributes.Instance Type"},
    "Instance State": {"key": "resource_attributes.Instance State"},
    "Instance Public IP Address": {
        "key": "resource_attributes.Instance Public IP Address"
    },
    "Instance Private IP Address": {
        "key": "resource_attributes.Instance Private IP Address"
    },
    "Instance Public DNS Name": {
        "key": "resource_attributes.Instance Public DNS Name"
    },
    "Instance Private DNS Name": {
        "key": "resource_attributes.Instance Private DNS Name"
    },
    "Instance VPC ID": {"key": "resource_attributes.Instance VPC Id"},
    "Instance Subnet ID": {"key": "resource_attributes.Instance Subnet Id"},
    "Instance Platform": {"key": "resource_attributes.Instance Platform"},
    "Instance Architecture": {
        "key": "resource_attributes.Instance Architecture"
    },
    "IOM Event ID": {"key": "id"},
    "Resource ID": {"key": "resource_id"},
    "Resource ID Type": {"key": "resource_id_type"},
    "Resource URL": {"key": "resource_url"},
    "Resource UUID": {"key": "resource_uuid"},
    "Cloud Provider": {"key": "cloud_provider"},
    "Cloud Service": {"key": "service"},
    "Security Group": {"key": "finding.Security Group"},
    "NACL ID": {"key": "finding.NACL Id"},
    "Port(s)": {"key": "finding.Port(s)"},
    "Region": {"key": "region"},
    "Severity": {"key": "severity"},
    "Status": {"key": "status"},
    "Policy Statement": {"key": "policy_statement"},
    "Is Managed": {"key": "is_managed", "transformation": "string"},
}

IOA_FIELD_MAPPING = {
    "User Name": {"key": "user_identity.user_name"},
    "Display Name": {"key": "user_identity.display_name"},
    "Event ID": {"key": "event_id"},
    "Event State": {"key": "state"},
    "Event Category": {"key": "event_category"},
    "Event Name": {"key": "event_name"},
    "Event Source": {"key": "event_source"},
    "Event Type": {"key": "event_type"},
    "Management Event": {
        "key": "management_event",
        "transformation": "string",
    },
    "Request ID": {"key": "request_id"},
    "Source IP Address": {"key": "source_ip_address"},
    "User ARN": {"key": "user_identity.arn"},
    "AWS Access Key ID": {"key": "user_identity.aws_access_key_id"},
    "Principal ID": {"key": "user_identity.principal_id"},
    "Confidence": {"key": "aggregate.confidence"},
    "Join Keys": {"key": "aggregate.join_keys", "default": []},
    "Score": {"key": "aggregate.score"},
    "AWS Account ID": {"key": "cloud_account_id.aws_account_id"},
    "Azure Account ID": {"key": "cloud_account_id.azure_account_id"},
    "Policy ID": {"key": "policy_id"},
    "Policy Statement": {"key": "policy_statement"},
    "Severity": {"key": "severity"},
    "Cloud Provider": {"key": "cloud_provider"},
    "Cloud Service": {"key": "service"},
    "Cloud Region": {"key": "cloud_region"},
    "Vertex ID": {"key": "vertex_id"},
    "Vertex Type": {"key": "vertex_type"},
}

# The maximum CE version that does not support resolution message
MAXIMUM_CE_VERSION = "5.1.2"

CONFIGURATION = "configuration"
ACTION = "action"

EMPTY_ERROR_MESSAGE = "{field_name} is a required configuration parameter."
TYPE_ERROR_MESSAGE = (
    "Invalid value provided for the configuration parameter '{field_name}'."
)
VALIDATION_ERROR_MESSAGE = "Validation error occurred. "
ALLOWED_VALUE_MESSAGE = "Allowed values are '{allowed_values}'"
VALUE_OUT_OF_RANGE_ERROR_MESSAGE = (
    " Value should be between 0 and {max_value}."
)

PULL_IOA_EVENTS_ENDPOINT = "{base_url}/detects/entities/ioa/v1"
PULL_IOM_EVENT_IDS_ENDPOINT = "{base_url}/detects/queries/iom/v2"
PULL_IOM_EVENT_DETAILS_ENDPOINT = "{base_url}/detects/entities/iom/v2"
