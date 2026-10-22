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

AWS CloudWatch CLS Plugin constants.
"""

MODULE_NAME = "CLS"
PLATFORM_NAME = "AWS CloudWatch"
PLUGIN_NAME = "AWS CloudWatch"
PLUGIN_VERSION = "1.0.0"

# CE version at or below which transformData is sent as a boolean.
MAXIMUM_CE_VERSION = "5.1.2"

VALIDATION_ERROR_MESSAGE = "Validation error occurred."

AUTHENTICATION_METHODS = ["deployed_on_aws", "aws_iam_roles_anywhere"]
AWS_IAM_ROLES_ANYWHERE = "aws_iam_roles_anywhere"

# Records per push() call. Cloud Exchange 6.1.0 and 7.0.0 core do not
# call chunk_size(), so this is only a hint for future core versions.
# The syslog plugin keeps the method for the same reason.
CHUNK_SIZE = 2000

# ---------------------------------------------------------------------------
# AWS client settings
# ---------------------------------------------------------------------------

# AWS Partner Network user agent. Every AWS plugin in Cloud Exchange
# sends this so AWS can attribute the API calls to Netskope. The Cloud
# Exchange user agent rides along in Config(user_agent_extra=...).
USER_AGENT = "APN/1.1 (ahq9d89xj9gspapczzdb59goq)"

# The IAM Roles Anywhere credential lifetime (900 seconds) lives inside
# the ported auth module. Refresh this many minutes before expiry, and
# give the CreateSession call a timeout. Both mirror aws_s3_edm.
CREDENTIAL_REFRESH_MINUTES = 3
# (connect, read) for the CreateSession request. A black holed endpoint
# or proxy must never hang a Cloud Exchange worker.
ROLES_ANYWHERE_TIMEOUT = (10, 60)

# botocore retry budget for throttling and 5xx responses.
MAX_RETRIES = 3
# No retries while validating, so the user gets the error straight away.
VALIDATION_MAX_RETRIES = 0
# Time to establish the TCP connection to the CloudWatch Logs endpoint.
CONNECT_TIMEOUT = 30
# Time to wait for a response once connected. PutLogEvents can carry a
# full 1 MB batch, so this is generous.
READ_TIMEOUT = 300

# ---------------------------------------------------------------------------
# PutLogEvents hard limits
# ---------------------------------------------------------------------------

# Maximum number of log events in one PutLogEvents request.
MAX_EVENTS_PER_BATCH = 10000
# Maximum size of one PutLogEvents request, in bytes.
MAX_BATCH_SIZE_BYTES = 1048576
# Maximum size of a single log event, in bytes, including the overhead below.
# AWS raised this from 256 KB to 1 MB in April 2025. The cap is measured as the
# message plus PER_EVENT_OVERHEAD_BYTES, so the message itself may be up to
# 1 MB - 26 = 1,048,550 bytes.
MAX_EVENT_SIZE_BYTES = 1048576
# Bytes AWS adds to every log event when it measures the request size.
PER_EVENT_OVERHEAD_BYTES = 26

# ---------------------------------------------------------------------------
# Log group and log stream naming rules
# ---------------------------------------------------------------------------

LOG_GROUP_NAME_PATTERN = r"^[\.\-_/#A-Za-z0-9]+$"
LOG_NAME_MIN_LENGTH = 1
LOG_NAME_MAX_LENGTH = 512
LOG_STREAM_FORBIDDEN_CHARS = [":", "*"]

# ---------------------------------------------------------------------------
# AWS partitions
# ---------------------------------------------------------------------------

# Ported from aws_s3_edm. IAM Roles Anywhere lives on a different domain
# in the China partition, so the host cannot be hard coded.
PARTITION_AWS = "aws"
PARTITION_AWS_CN = "aws-cn"
PARTITION_AWS_US_GOV = "aws-us-gov"
ROLES_ANYWHERE_DOMAIN = {
    PARTITION_AWS: "amazonaws.com",
    PARTITION_AWS_US_GOV: "amazonaws.com",
    PARTITION_AWS_CN: "amazonaws.com.cn",
}
# Custom region: the dropdown value that selects the free text region.
CUSTOM_REGION_VALUE = "custom"
# Safety guard for the custom region: it is placed into manually built
# URLs (the Roles Anywhere host and the SigV4 scope), so it must be a
# valid DNS host label. Identical to the region name rule of botocore
# (validate_region_name), used with re.fullmatch. Nothing else about the
# region shape is assumed; AWS validates it at the connection check.
REGION_NAME_REGEX = r"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$"
# Prefix of the AWS European Sovereign Cloud regions (partition aws-eusc).
UNSUPPORTED_REGION_PREFIXES = ("eusc-",)
UNSUPPORTED_REGION_MARKERS = ("-iso",)

# ---------------------------------------------------------------------------
# IAM
# ---------------------------------------------------------------------------

# Access denied guidance, one per failing call. The region, log group
# and log stream are filled in from the configuration at run time, so
# the operator can copy the ARN straight into a policy. The account id
# is the only placeholder left: AWS echoes the caller ARN in the error
# details, and resolving it would mean an extra STS call in an error
# path.
IAM_RESOLUTION_PUT = (
    "Grant logs:PutLogEvents to the IAM role on"
    " arn:{partition}:logs:{region}:<account-id>:log-group:{group}"
    ":log-stream:{stream}."
)
IAM_RESOLUTION_CREATE = (
    "Grant logs:CreateLogGroup and logs:CreateLogStream to the IAM role"
    " on both arn:{partition}:logs:{region}:<account-id>:log-group:"
    "{group} and arn:{partition}:logs:{region}:<account-id>:log-group:"
    "{group}:*, or create the log group and log stream in the AWS"
    " console so the plugin does not need to create them."
)
IAM_RESOLUTION_DESCRIBE_GROUPS = (
    "Grant logs:DescribeLogGroups to the IAM role on"
    " arn:{partition}:logs:{region}:<account-id>:log-group:*. This"
    " action lists the log groups in the account and cannot be scoped"
    " to a single log group."
)
IAM_RESOLUTION_VALIDATION = (
    "Grant logs:DescribeLogStreams to the IAM role on"
    " arn:{partition}:logs:{region}:<account-id>:log-group:{group}:*."
    " If the plugin should create the log group and log stream, also"
    " grant logs:CreateLogGroup and logs:CreateLogStream on"
    " arn:{partition}:logs:{region}:<account-id>:log-group:{group} and"
    " arn:{partition}:logs:{region}:<account-id>:log-group:{group}:*;"
    " otherwise create them in the AWS console."
)

INVALID_CREDENTIALS_ERROR_CODES = [
    "UnrecognizedClientException",
    "InvalidSignatureException",
    "InvalidClientTokenId",
    "SignatureDoesNotMatch",
    "ExpiredTokenException",
    "InvalidAccessKeyId",
]
ACCESS_DENIED_ERROR_CODES = [
    "AccessDeniedException",
    "AccessDenied",
    "AuthorizationError",
]
RESOURCE_NOT_FOUND_ERROR_CODE = "ResourceNotFoundException"
RESOURCE_ALREADY_EXISTS_ERROR_CODE = "ResourceAlreadyExistsException"

# ---------------------------------------------------------------------------
# CEF severity maps
# ---------------------------------------------------------------------------

SEVERITY_LOW = "Low"
SEVERITY_MEDIUM = "Medium"
SEVERITY_HIGH = "High"
SEVERITY_VERY_HIGH = "Very-High"
SEVERITY_UNKNOWN = "Unknown"
SEVERITY_INFO = "Info"

SEVERITY_MAP = {
    "low": SEVERITY_LOW,
    "med": SEVERITY_MEDIUM,
    "medium": SEVERITY_MEDIUM,
    "high": SEVERITY_HIGH,
    "very-high": SEVERITY_VERY_HIGH,
    "critical": SEVERITY_VERY_HIGH,
    "0": SEVERITY_LOW,
    "1": SEVERITY_LOW,
    "2": SEVERITY_LOW,
    "3": SEVERITY_LOW,
    "4": SEVERITY_MEDIUM,
    "5": SEVERITY_MEDIUM,
    "6": SEVERITY_MEDIUM,
    "7": SEVERITY_HIGH,
    "8": SEVERITY_HIGH,
    "9": SEVERITY_VERY_HIGH,
    "10": SEVERITY_VERY_HIGH,
}

AUDIT_SEVERITY_MAP = {
    "low": SEVERITY_LOW,
    "med": SEVERITY_MEDIUM,
    "medium": SEVERITY_MEDIUM,
    "high": SEVERITY_HIGH,
    "very-high": SEVERITY_HIGH,
    "critical": SEVERITY_HIGH,
    "0": SEVERITY_UNKNOWN,
    "1": SEVERITY_HIGH,
    "2": SEVERITY_MEDIUM,
    "3": SEVERITY_UNKNOWN,
    "4": SEVERITY_LOW,
    "5": SEVERITY_UNKNOWN,
    "6": SEVERITY_INFO,
    "7": SEVERITY_UNKNOWN,
    "8": SEVERITY_UNKNOWN,
    "9": SEVERITY_UNKNOWN,
    "10": SEVERITY_UNKNOWN,
}

# ---------------------------------------------------------------------------
# AWS regions
# ---------------------------------------------------------------------------

REGION_CHOICES = [
    {"key": "US East (N. Virginia) [us-east-1]", "value": "us-east-1"},
    {"key": "US East (Ohio) [us-east-2]", "value": "us-east-2"},
    {"key": "US West (N. California) [us-west-1]", "value": "us-west-1"},
    {"key": "US West (Oregon) [us-west-2]", "value": "us-west-2"},
    {"key": "Africa (Cape Town) [af-south-1]", "value": "af-south-1"},
    {"key": "Asia Pacific (Hong Kong) [ap-east-1]", "value": "ap-east-1"},
    {"key": "Asia Pacific (Mumbai) [ap-south-1]", "value": "ap-south-1"},
    {
        "key": "Asia Pacific (Tokyo) [ap-northeast-1]",
        "value": "ap-northeast-1",
    },
    {
        "key": "Asia Pacific (Seoul) [ap-northeast-2]",
        "value": "ap-northeast-2",
    },
    {
        "key": "Asia Pacific (Melbourne) [ap-southeast-4]",
        "value": "ap-southeast-4",
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
    {"key": "Canada (Central) [ca-central-1]", "value": "ca-central-1"},
    {"key": "Canada (Calgary) [ca-west-1]", "value": "ca-west-1"},
    {"key": "China (Beijing) [cn-north-1]", "value": "cn-north-1"},
    {"key": "China (Ningxia) [cn-northwest-1]", "value": "cn-northwest-1"},
    {"key": "Europe (Frankfurt) [eu-central-1]", "value": "eu-central-1"},
    {"key": "Europe (Ireland) [eu-west-1]", "value": "eu-west-1"},
    {"key": "Europe (London) [eu-west-2]", "value": "eu-west-2"},
    {"key": "Europe (Paris) [eu-west-3]", "value": "eu-west-3"},
    {"key": "Europe (Milan) [eu-south-1]", "value": "eu-south-1"},
    {"key": "Europe (Stockholm) [eu-north-1]", "value": "eu-north-1"},
    {"key": "Israel (Tel Aviv) [il-central-1]", "value": "il-central-1"},
    {"key": "Middle East (Bahrain) [me-south-1]", "value": "me-south-1"},
    {"key": "South America (São Paulo) [sa-east-1]", "value": "sa-east-1"},
    {"key": "Asia Pacific (Hyderabad) [ap-south-2]", "value": "ap-south-2"},
    {
        "key": "Asia Pacific (Jakarta) [ap-southeast-3]",
        "value": "ap-southeast-3",
    },
    {"key": "Europe (Spain) [eu-south-2]", "value": "eu-south-2"},
    {"key": "Europe (Zurich) [eu-central-2]", "value": "eu-central-2"},
    {"key": "Middle East (UAE) [me-central-1]", "value": "me-central-1"},
    {
        "key": "Asia Pacific (Malaysia) [ap-southeast-5]",
        "value": "ap-southeast-5",
    },
    {
        "key": "Asia Pacific (Thailand) [ap-southeast-7]",
        "value": "ap-southeast-7",
    },
    {"key": "Mexico (Central) [mx-central-1]", "value": "mx-central-1"},
]

REGIONS = [region["value"] for region in REGION_CHOICES]

# ---------------------------------------------------------------------------
# Dynamic configuration fields
# ---------------------------------------------------------------------------

AWS_IAM_ROLES_ANYWHERE_CONFIG = [
    {
        "label": "Private Key",
        "key": "private_key_file",
        "type": "textarea",
        "default": "",
        "mandatory": True,
        "description": (
            "PEM-encoded private key that matches the Certificate Body."
            " It signs the IAM Roles Anywhere CreateSession request."
            " Required for 'AWS IAM Roles Anywhere' authentication."
        ),
    },
    {
        "label": "Certificate Body",
        "key": "public_certificate_file",
        "type": "textarea",
        "default": "",
        "mandatory": True,
        "description": (
            "PEM-encoded X.509 end-entity certificate issued by the CA"
            " configured in the Trust Anchor. Required for 'AWS IAM"
            " Roles Anywhere' authentication."
        ),
    },
    {
        "label": "Password Phrase",
        "key": "pass_phrase",
        "type": "password",
        "default": "",
        "mandatory": True,
        "description": (
            "Passphrase of the Private Key, if the key is encrypted."
            " Required for 'AWS IAM Roles Anywhere' authentication."
        ),
    },
    {
        "label": "Profile ARN",
        "key": "profile_arn",
        "type": "text",
        "default": "",
        "mandatory": True,
        "description": (
            "ARN of the IAM Roles Anywhere profile. Format:"
            " arn:aws:rolesanywhere:{region}:{account-id}:profile/"
            "{profile-id}. Required for 'AWS IAM Roles Anywhere'"
            " authentication."
        ),
    },
    {
        "label": "Role ARN",
        "key": "role_arn",
        "type": "text",
        "default": "",
        "mandatory": True,
        "description": (
            "ARN of the IAM role to be assumed. Format:"
            " arn:aws:iam::{account-id}:role/{role-name}. The role needs"
            " logs:PutLogEvents on the target log stream, and"
            " logs:CreateLogGroup and logs:CreateLogStream if the plugin"
            " should create them. Required for 'AWS IAM Roles Anywhere'"
            " authentication."
        ),
    },
    {
        "label": "Trust Anchor ARN",
        "key": "trust_anchor_arn",
        "type": "text",
        "default": "",
        "mandatory": True,
        "description": (
            "ARN of the IAM Roles Anywhere trust anchor. Format:"
            " arn:aws:rolesanywhere:{region}:{account-id}:trust-anchor/"
            "{anchor-id}. Required for 'AWS IAM Roles Anywhere'"
            " authentication."
        ),
    },
]

COMMON_CONFIG = [
    {
        "label": "AWS CloudWatch Region Name",
        "key": "region_name",
        "type": "choice",
        "choices": REGION_CHOICES
        + [{"key": "Custom Region", "value": CUSTOM_REGION_VALUE}],
        "default": "us-east-1",
        "mandatory": True,
        "description": (
            "AWS region that holds the target CloudWatch log group. When"
            " 'AWS IAM Roles Anywhere' is used, this region must match the"
            " region in the Profile ARN and the Trust Anchor ARN. Select"
            " 'Custom Region' to enter a region that is not in the list."
        ),
    },
    {
        "label": "AWS CloudWatch Custom Region",
        "key": "custom_region_name",
        "type": "text",
        "default": "",
        "mandatory": False,
        "description": (
            "Only used when 'AWS CloudWatch Region Name' is set to"
            " 'Custom Region'; leave it empty otherwise. Any valid AWS"
            " region code of the log group, for a region that is not in"
            " the list, for example us-west-1. AWS IAM Roles Anywhere"
            " supports the aws, aws-cn and aws-us-gov partitions only,"
            " not the ISO or eusc- regions."
        ),
    },
    {
        "label": "Log Group Name",
        "key": "log_group_name",
        "type": "text",
        "default": "",
        "mandatory": True,
        "description": (
            "Name of the CloudWatch log group the data is written to. The"
            " plugin creates the log group if it does not exist. It can be"
            " 1 to 512 characters long and can contain letters, digits and"
            " the characters . - _ / #"
        ),
    },
    {
        "label": "Log Stream Name",
        "key": "log_stream_name",
        "type": "text",
        "default": "",
        "mandatory": True,
        "description": (
            "Name of the log stream inside the log group. The plugin"
            " creates the log stream if it does not exist. It can be 1 to"
            " 512 characters long and must not contain : or *"
        ),
    },
]
