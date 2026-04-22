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

Amazon Security Lake Contstants."""

MODULE_NAME = "CLS"
PLUGIN_NAME = "Amazon Security Lake"
PLUGIN_VERSION = "2.0.0"
USER_AGENT = "APN/1.1 (ahq9d89xj9gspapczzdb59goq)"
STAGING_DIR = "/opt/netskope/plugins/security_lake_staging/"
MAX_FILE_SIZE_BYTES = 256 * 1024 * 1024  # Staging threshold for upload
MAX_FILE_AGE_MINUTES = 5  # Staging age threshold

# Pending file constants
PENDING_FILE_PREFIX = "pending_"
MIN_UPLOAD_SIZE_BYTES = 256 * 1024 * 1024  # AWS minimum for frequent uploads
MAX_BATCH_SIZE_BYTES = 512 * 1024 * 1024  # Max batch size (Python memory limit)

# Corrupted file suffix (for quarantining files with JSONDecodeError)
INVALID_FILE_SUFFIX = ".invalid"

# Regex for sanitizing file suffixes
# matches any character that is
# NOT alphanumeric, underscore, or hyphen
FILE_SUFFIX_UNSAFE_CHARS_PATTERN = r"[^a-zA-Z0-9_\-]"
CUSTOM_SOURCE_NAME_PATTERN = r"^[\w\-\_\:\.]*$"
AUTHENTICATION_METHODS = [
    "aws_iam_roles_anywhere",
    "deployed_on_aws",
]
IAM_ROLES_ANYWHERE_REQUIRED_ACTIONS = [
    "sts:AssumeRole",
    "sts:SetSourceIdentity",
    "sts:TagSession",
]
IAM_ROLES_ANYWHERE_TRUST_POLICY_TEMPLATE = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            # Principal will be created with account_id
            "Principal": {"AWS": "placeholder"},
            "Action": IAM_ROLES_ANYWHERE_REQUIRED_ACTIONS,
        }
    ],
}
MAX_RETRIES = 3
S3_UPLOAD_RETRY_DELAY_SECONDS = 30
READ_TIMEOUT = 300
VALIDATION_MAX_RETRIES = 0
DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
TRANSFORM_DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
LOCK_FILE_NAME = "json_writer.lock"
# S3 partitioning pattern: region=region/accountId=accountID/eventDay=YYYYMMDD/filename.parquet
S3_PARTITION_PATH = "region={}/accountId={}/{}/{}.parquet"
OCSF_SCHEMA_FILENAME = "ocsf_schema_v130.json"
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


AWS_IAM_ROLES_ANYWHERE_CONFIG = [
    {
        "label": "Private Key",
        "key": "private_key_file",
        "type": "textarea",
        "default": "",
        "mandatory": True,
        "description": "Private Key for decrypting the AWS Private CA Certificate. Required for 'AWS IAM Roles Anywhere' authentication type."
    },
    {
        "label": "Certificate Body",
        "key": "public_certificate_file",
        "type": "textarea",
        "default": "",
        "mandatory": True,
        "description": "Certificate Body for AWS Public/Private CA Certificate. Required for 'AWS IAM Roles Anywhere' authentication type."
    },
    {
        "label": "Password Phrase",
        "key": "pass_phrase",
        "type": "password",
        "default": "",
        "mandatory": True,
        "description": "Password Phrase for decrypting the CA Certificate. Required for 'AWS IAM Roles Anywhere' authentication type."
    },
    {
        "label": "Profile ARN",
        "key": "profile_arn",
        "type": "text",
        "default": "",
        "mandatory": True,
        "description": "AWS Profile ARN for AWS client authentication. Required for 'AWS IAM Roles Anywhere' authentication type."
    },
    {
        "label": "Role ARN",
        "key": "role_arn",
        "type": "text",
        "default": "",
        "mandatory": True,
        "description": "AWS Role ARN for AWS client authentication. Required for 'AWS IAM Roles Anywhere' authentication type."
    },
    {
        "label": "Trust Anchor ARN",
        "key": "trust_anchor_arn",
        "type": "text",
        "default": "",
        "mandatory": True,
        "description": "AWS Trust Anchor ARN for AWS client authentication. Required for 'AWS IAM Roles Anywhere' authentication type."
    },
    {
        "label": "Auto-update Provider Role Trust Policy",
        "key": "auto_update_trust_policy",
        "type": "choice",
        "choices": [
            {
                "key": "Yes",
                "value": "yes"
            },
            {
                "key": "No",
                "value": "no"
            },
        ],
        "default": "yes",
        "mandatory": True,
        "description": (
            "When enabled, the plugin will ensure the Provider Role trust policy allows "
            "principal arn:aws:iam::account_id:root with actions sts:AssumeRole, "
            "sts:SetSourceIdentity, and sts:TagSession. This allows the plugin to "
            "assume the Provider Role when uploading parquets to S3. "
            "Please be careful as the plugin will replace the existing trust policy "
            "with the above mentioned actions. If No is selected, each event type's Provider Role "
            "will have to be manually updated to include these actions."
        ),
    },
]

COMMON_CONFIG = [
    {
        "label": "AWS S3 Bucket Region Name",
        "key": "region_name",
        "type": "choice",
        "choices": [
            {
                "key": "US East (N. Virginia) [us-east-1]",
                "value": "us-east-1"
            },
            {
                "key": "US East (Ohio) [us-east-2]",
                "value": "us-east-2"
            },
            {
                "key": "US West (N. California) [us-west-1]",
                "value": "us-west-1"
            },
            {
                "key": "US West (Oregon) [us-west-2]",
                "value": "us-west-2"
            },
            {
                "key": "Africa (Cape Town) [af-south-1]",
                "value": "af-south-1"
            },
            {
                "key": "Asia Pacific (Hong Kong) [ap-east-1]",
                "value": "ap-east-1"
            },
            {
                "key": "Asia Pacific (Mumbai) [ap-south-1]",
                "value": "ap-south-1"
            },
            {
                "key": "Asia Pacific (Tokyo) [ap-northeast-1]",
                "value": "ap-northeast-1"
            },
            {
                "key": "Asia Pacific (Seoul) [ap-northeast-2]",
                "value": "ap-northeast-2"
            },
            {
                "key": "Asia Pacific (Melbourne) [ap-southeast-4]",
                "value": "ap-southeast-4"
            },
            {
                "key": "Asia Pacific (Thailand) [ap-southeast-7]",
                "value": "ap-southeast-7"
            },
            {
                "key": "Canada (Calgary) [ca-west-1]",
                "value": "ca-west-1"
            },
            {
                "key": "Asia Pacific (Osaka) [ap-northeast-3]",
                "value": "ap-northeast-3"
            },
            {
                "key": "Asia Pacific (Singapore) [ap-southeast-1]",
                "value": "ap-southeast-1"
            },
            {
                "key": "Asia Pacific (Sydney) [ap-southeast-2]",
                "value": "ap-southeast-2"
            },
            {
                "key": "Canada (Central) [ca-central-1]",
                "value": "ca-central-1"
            },
            {
                "key": "China (Beijing) [cn-north-1]",
                "value": "cn-north-1"
            },
            {
                "key": "China (Ningxia) [cn-northwest-1]",
                "value": "cn-northwest-1"
            },
            {
                "key": "Europe (Frankfurt) [eu-central-1]",
                "value": "eu-central-1"
            },
            {
                "key": "Europe (Ireland) [eu-west-1]",
                "value": "eu-west-1"
            },
            {
                "key": "Europe (London) [eu-west-2]",
                "value": "eu-west-2"
            },
            {
                "key": "Europe (Paris) [eu-west-3]",
                "value": "eu-west-3"
            },
            {
                "key": "Europe (Milan) [eu-south-1]",
                "value": "eu-south-1"
            },
            {
                "key": "Europe (Stockholm) [eu-north-1]",
                "value": "eu-north-1"
            },
            {
                "key": "Israel (Tel Aviv) [il-central-1]",
                "value": "il-central-1"
            },
            {
                "key": "Middle East (Bahrain) [me-south-1]",
                "value": "me-south-1"
            },
            {
                "key": "South America (São Paulo) [sa-east-1]",
                "value": "sa-east-1"
            },
            {
                "key": "Asia Pacific (Hyderabad) [ap-south-2]",
                "value": "ap-south-2"
            },
            {
                "key": "Asia Pacific (Jakarta) [ap-southeast-3]",
                "value": "ap-southeast-3"
            },
            {
                "key": "Asia Pacific (Malaysia) [ap-southeast-5]",
                "value": "ap-southeast-5"
            },
            {
                "key": "Europe (Spain) [eu-south-2]",
                "value": "eu-south-2"
            },
            {
                "key": "Europe (Zurich) [eu-central-2]",
                "value": "eu-central-2"
            },
            {
                "key": "Mexico (Central) mx-central-1",
                "value": "mx-central-1"
            },
            {
                "key": "Middle East (UAE) [me-central-1]",
                "value": "me-central-1"
            }
        ],
        "default": "us-east-1",
        "mandatory": True,
        "description": "AWS S3 Bucket Region Name from where to get the AWS S3 Bucket. Make sure that the region name matches the region in the Profile ARN and Trust Anchor ARN."
    },
    {
        "label": "AWS Account ID",
        "key": "account_id",
        "type": "text",
        "default": "",
        "mandatory": True,
        "description": "AWS AccountID in which the AWS Security Lake Custom Source Bucket is created."
    },
    {
        "label": "Parquet File Name Prefix",
        "key": "prefix",
        "type": "text",
        "default": "",
        "mandatory": False,
        "description": "Parquet File Name Prefix for the AWS Security Lake Custom Source Bucket."
    },
    {
        "label": "AWS Crawler Role ARN",
        "key": "crawler_role_arn",
        "type": "text",
        "default": "",
        "mandatory": True,
        "description": (
            "The Amazon Resource Name (ARN) of the IAM role that the AWS Glue crawler will use to access your data. "
            "This role must have permissions for accessing Security Lake, S3 buckets, Glue Data Catalog and Lake Formation. "
            "Please refer to the guide for detailed steps on configuring the Glue Crawler role."
        )
    },
    {
        "label": "Provider External ID",
        "key": "provider_external_id",
        "type": "text",
        "default": "",
        "mandatory": True,
        "description": "An external ID used to establish a trust relationship with the log provider (for security best practices against 'confused deputy' attacks)."
    },
    {
        "label": "Provider Principal",
        "key": "provider_principal",
        "type": "text",
        "default": "",
        "mandatory": True,
        "description": "The AWS principal (usually an IAM Role ARN or Account ID) of the entity that will be writing logs to the S3 bucket."
    },
]

SUBTYPE_MAPPING = {
    # Alert subtypes
    "compromisedcredential": {
        "config_key": "custom_source_name_compromisedcredential",
        "event_classes": ["DATA_SECURITY_FINDING"]
    },
    "content": {
        "config_key": "custom_source_name_content",
        "event_classes": ["DATA_SECURITY_FINDING"]
    },
    "ctep": {
        "config_key": "custom_source_name_ctep",
        "event_classes": ["DETECTION_FINDING"]
    },
    "device": {
        "config_key": "custom_source_name_device",
        "event_classes": ["DETECTION_FINDING"]
    },
    "dlp": {
        "config_key": "custom_source_name_dlp",
        "event_classes": ["DATA_SECURITY_FINDING"]
    },
    "malsite": {
        "config_key": "custom_source_name_malsite",
        "event_classes": ["DETECTION_FINDING"]
    },
    "malware": {
        "config_key": "custom_source_name_malware",
        "event_classes": ["DETECTION_FINDING"]
    },
    "policy": {
        "config_key": "custom_source_name_policy",
        "event_classes": ["DETECTION_FINDING"]
    },
    "quarantine": {
        "config_key": "custom_source_name_quarantine",
        "event_classes": ["DETECTION_FINDING"]
    },
    "remediation": {
        "config_key": "custom_source_name_remediation",
        "event_classes": ["DETECTION_FINDING"]
    },
    "securityassessment": {
        "config_key": "custom_source_name_securityassessment",
        "event_classes": ["DATA_SECURITY_FINDING"]
    },
    "uba": {
        "config_key": "custom_source_name_uba",
        "event_classes": ["DETECTION_FINDING"]
    },
    "watchlist": {
        "config_key": "custom_source_name_watchlist",
        "event_classes": ["DETECTION_FINDING"]
    },
    # Event subtypes
    "application": {
        "config_key": "custom_source_name_application",
        "event_classes": ["APPLICATION_LIFECYCLE"]
    },
    "audit": {
        "config_key": "custom_source_name_audit",
        "event_classes": ["EVENT_LOG_ACTIVITY"]
    },
    "clientstatus": {
        "config_key": "custom_source_name_clientstatus",
        "event_classes": ["DETECTION_FINDING"]
    },
    "endpoint": {
        "config_key": "custom_source_name_endpoint",
        "event_classes": ["DETECTION_FINDING"]
    },
    "incident": {
        "config_key": "custom_source_name_incident",
        "event_classes": ["DETECTION_FINDING"]
    },
    "infrastructure": {
        "config_key": "custom_source_name_infrastructure",
        "event_classes": ["APPLICATION_LIFECYCLE"]
    },
    "network": {
        "config_key": "custom_source_name_network",
        "event_classes": ["NETWORK_ACTIVITY"]
    },
    "page": {
        "config_key": "custom_source_name_page",
        "event_classes": ["DETECTION_FINDING"]
    },
    # Webtx
    "v2": {
        "config_key": "custom_source_name_v2",
        "event_classes": ["NETWORK_ACTIVITY"]
    },
}

CUSTOM_SOURCE_DETAILS_CONFIG = [
    {
        "label": "Name of Custom Data Source for Compromised Credential",
        "key": "custom_source_name_compromisedcredential",
        "type": "text",
        "default": "ns_comp_credential",
        "mandatory": False,
        "description": "Custom Source Bucket of this name will be created in AWS Security Lake for Compromised Credential Alert type. By default this type will be mapped to Data Security Finding [2006] OCSF class."
    },
    {
        "label": "Name of Custom Data Source for Content",
        "key": "custom_source_name_content",
        "type": "text",
        "default": "ns_content",
        "mandatory": False,
        "description": "Custom Source Bucket of this name will be created in AWS Security Lake for Content Alert type. By default this type will be mapped to Data Security Finding [2006] OCSF class."
    },
    {
        "label": "Name of Custom Data Source for CTEP",
        "key": "custom_source_name_ctep",
        "type": "text",
        "default": "ns_ctep",
        "mandatory": False,
        "description": "Custom Source Bucket of this name will be created in AWS Security Lake for CTEP Alert type. By default this type will be mapped to Detection Finding [2004] OCSF class."
    },
    {
        "label": "Name of Custom Data Source for Device",
        "key": "custom_source_name_device",
        "type": "text",
        "default": "ns_device",
        "mandatory": False,
        "description": "Custom Source Bucket of this name will be created in AWS Security Lake for Device Alert type. By default this type will be mapped to Detection Finding [2004] OCSF class."
    },
    {
        "label": "Name of Custom Data Source for DLP",
        "key": "custom_source_name_dlp",
        "type": "text",
        "default": "ns_dlp",
        "mandatory": False,
        "description": "Custom Source Bucket of this name will be created in AWS Security Lake for DLP Alert type. By default this type will be mapped to Data Security Finding [2006] OCSF class."
    },
    {
        "label": "Name of Custom Data Source for Malsite",
        "key": "custom_source_name_malsite",
        "type": "text",
        "default": "ns_malsite",
        "mandatory": False,
        "description": "Custom Source Bucket of this name will be created in AWS Security Lake for Malsite Alert type. By default this type will be mapped to Detection Finding [2004] OCSF class."
    },
    {
        "label": "Name of Custom Data Source for Malware",
        "key": "custom_source_name_malware",
        "type": "text",
        "default": "ns_malware",
        "mandatory": False,
        "description": "Custom Source Bucket of this name will be created in AWS Security Lake for Malware Alert type. By default this type will be mapped to Detection Finding [2004] OCSF class."
    },
    {
        "label": "Name of Custom Data Source for Policy",
        "key": "custom_source_name_policy",
        "type": "text",
        "default": "ns_policy",
        "mandatory": False,
        "description": "Custom Source Bucket of this name will be created in AWS Security Lake for Policy Alert type. By default this type will be mapped to Detection Finding [2004] OCSF class."
    },
    {
        "label": "Name of Custom Data Source for Quarantine",
        "key": "custom_source_name_quarantine",
        "type": "text",
        "default": "ns_quarantine",
        "mandatory": False,
        "description": "Custom Source Bucket of this name will be created in AWS Security Lake for Quarantine Alert type. By default this type will be mapped to Detection Finding [2004] OCSF class."
    },
    {
        "label": "Name of Custom Data Source for Remediation",
        "key": "custom_source_name_remediation",
        "type": "text",
        "default": "ns_remediation",
        "mandatory": False,
        "description": "Custom Source Bucket of this name will be created in AWS Security Lake for Remediation Alert type. By default this type will be mapped to Detection Finding [2004] OCSF class."
    },
    {
        "label": "Name of Custom Data Source for Security Assessment",
        "key": "custom_source_name_securityassessment",
        "type": "text",
        "default": "ns_sec_assessment",
        "mandatory": False,
        "description": "Custom Source Bucket of this name will be created in AWS Security Lake for Security Assessment Alert type. By default this type will be mapped to Data Security Finding [2006] OCSF class."
    },
    {
        "label": "Name of Custom Data Source for UBA",
        "key": "custom_source_name_uba",
        "type": "text",
        "default": "ns_uba",
        "mandatory": False,
        "description": "Custom Source Bucket of this name will be created in AWS Security Lake for UBA Alert type. By default this type will be mapped to Detection Finding [2004] OCSF class."
    },
    {
        "label": "Name of Custom Data Source for Watchlist",
        "key": "custom_source_name_watchlist",
        "type": "text",
        "default": "ns_watchlist",
        "mandatory": False,
        "description": "Custom Source Bucket of this name will be created in AWS Security Lake for Watchlist Alert type. By default this type will be mapped to Detection Finding [2004] OCSF class."
    },
    {
        "label": "Name of Custom Data Source for Application",
        "key": "custom_source_name_application",
        "type": "text",
        "default": "ns_application",
        "mandatory": False,
        "description": "Custom Source Bucket of this name will be created in AWS Security Lake for Application Event type. By default this type will be mapped to Application Lifecycle [6002] OCSF class."
    },
    {
        "label": "Name of Custom Data Source for Audit",
        "key": "custom_source_name_audit",
        "type": "text",
        "default": "ns_audit",
        "mandatory": False,
        "description": "Custom Source Bucket of this name will be created in AWS Security Lake for Audit Event type. By default this type will be mapped to Event Log Activity [1008] OCSF class."
    },
    {
        "label": "Name of Custom Data Source for Client Status",
        "key": "custom_source_name_clientstatus",
        "type": "text",
        "default": "ns_client_status",
        "mandatory": False,
        "description": "Custom Source Bucket of this name will be created in AWS Security Lake for Client Status Event type. By default this type will be mapped to Detection Finding [2004] OCSF class."
    },
    {
        "label": "Name of Custom Data Source for Endpoint",
        "key": "custom_source_name_endpoint",
        "type": "text",
        "default": "ns_endpoint",
        "mandatory": False,
        "description": "Custom Source Bucket of this name will be created in AWS Security Lake for Endpoint Event type. By default this type will be mapped to Detection Finding [2004] OCSF class."
    },
    {
        "label": "Name of Custom Data Source for Incident",
        "key": "custom_source_name_incident",
        "type": "text",
        "default": "ns_incident",
        "mandatory": False,
        "description": "Custom Source Bucket of this name will be created in AWS Security Lake for Incident Event type. By default this type will be mapped to Detection Finding [2004] OCSF class."
    },
    {
        "label": "Name of Custom Data Source for Infrastructure",
        "key": "custom_source_name_infrastructure",
        "type": "text",
        "default": "ns_infrastructure",
        "mandatory": False,
        "description": "Custom Source Bucket of this name will be created in AWS Security Lake for Infrastructure Event type. By default this type will be mapped to Application Lifecycle [6002] OCSF class."
    },
    {
        "label": "Name of Custom Data Source for Network",
        "key": "custom_source_name_network",
        "type": "text",
        "default": "ns_network",
        "mandatory": False,
        "description": "Custom Source Bucket of this name will be created in AWS Security Lake for Network Event type. By default this type will be mapped to Network Activity [4001] OCSF class."
    },
    {
        "label": "Name of Custom Data Source for Page",
        "key": "custom_source_name_page",
        "type": "text",
        "default": "ns_page",
        "mandatory": False,
        "description": "Custom Source Bucket of this name will be created in AWS Security Lake for Page Event type. By default this type will be mapped to Detection Finding [2004] OCSF class."
    },
    {
        "label": "Name of Custom Data Source for Web Transaction",
        "key": "custom_source_name_v2",
        "type": "text",
        "default": "ns_webtx",
        "mandatory": False,
        "description": "Custom Source Bucket of this name will be created in AWS Security Lake for Webtx type. By default this type will be mapped to Network Activity [4001] OCSF class."
    },
]

