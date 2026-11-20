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

AWS S3 WebTx plugin constants.
"""

MODULE_NAME = "CLS"
PLATFORM_NAME = "AWS S3"
PLUGIN_NAME = "AWS S3 WebTx"
PLUGIN_VERSION = "1.3.0"
# AWS Partner Network user agent, as in the other AWS plugins.
USER_AGENT = "APN/1.1 (ahq9d89xj9gspapczzdb59goq)"
WEBTX_DATA_TYPE = "webtx"
MANIFEST_NAME_KEY = "name"
MANIFEST_VERSION_KEY = "version"

# Configuration parameter keys.
AUTHENTICATION_METHOD_KEY = "authentication_method"
PRIVATE_KEY_FILE_KEY = "private_key_file"
PUBLIC_CERTIFICATE_FILE_KEY = "public_certificate_file"
PASS_PHRASE_KEY = "pass_phrase"
PROFILE_ARN_KEY = "profile_arn"
ROLE_ARN_KEY = "role_arn"
TRUST_ANCHOR_ARN_KEY = "trust_anchor_arn"
EXTERNALLY_PROVISIONED_BUCKET_KEY = "externally_provisioned_bucket"
REGION_NAME_KEY = "region_name"
CUSTOM_REGION_NAME_KEY = "custom_region_name"
BUCKET_NAME_KEY = "bucket_name"

# Configuration parameter labels.
AUTHENTICATION_METHOD_LABEL = "Authentication Method"
PRIVATE_KEY_LABEL = "Private Key"
CERTIFICATE_BODY_LABEL = "Certificate Body"
PASS_PHRASE_LABEL = "Password Phrase"
PROFILE_ARN_LABEL = "Profile ARN"
ROLE_ARN_LABEL = "Role ARN"
TRUST_ANCHOR_ARN_LABEL = "Trust Anchor ARN"
EXTERNALLY_PROVISIONED_BUCKET_LABEL = "Externally Provisioned Bucket"
REGION_NAME_LABEL = "AWS S3 Bucket Region Name"
CUSTOM_REGION_NAME_LABEL = "AWS Custom Region"
BUCKET_NAME_LABEL = "AWS S3 Bucket Name"

# Authentication methods.
AUTH_DEPLOYED_ON_AWS = "deployed_on_aws"
AUTH_ROLES_ANYWHERE = "aws_iam_roles_anywhere"
AUTH_METHODS = (AUTH_DEPLOYED_ON_AWS, AUTH_ROLES_ANYWHERE)

# Externally Provisioned Bucket values.
EP_YES = "yes"
EP_NO = "no"
EP_VALUES = (EP_YES, EP_NO)
EP_DEFAULT = EP_NO

# S3 bucket naming rules (3 to 63 characters, no IP address format).
BUCKET_NAME_REGEX = (
    r"^(?!xn--)(?!.*\.\.)(?!\d+\.\d+\.\d+\.\d+$)"
    r"[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$"
)
# Suffixes AWS reserves for access point and Object Lambda aliases.
BUCKET_RESERVED_SUFFIXES = ("-s3alias", "--ol-s3")

# Region settings.
DEFAULT_REGION = "us-east-1"
CUSTOM_REGION_VALUE = "custom"
# The custom region is placed into a manually built URL (Roles Anywhere
# host) and the SigV4 scope, so it must be a valid DNS host label. Same
# rule as botocore validate_region_name, used with re.fullmatch.
REGION_NAME_REGEX = r"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$"
# Domain of the IAM Roles Anywhere endpoint (China regions use their own).
ROLES_ANYWHERE_DOMAIN = "amazonaws.com"
ROLES_ANYWHERE_CN_DOMAIN = "amazonaws.com.cn"

# IAM Roles Anywhere temporary credentials.
# 900 seconds is the shortest session AWS allows. Short sessions limit the
# exposure of the credentials and need no change of the role's maximum
# session duration; the credentials are renewed when 3 minutes remain.
ROLES_ANYWHERE_SESSION_SECONDS = 900
ROLES_ANYWHERE_SESSION_NAME = "Session"
ROLES_ANYWHERE_TIMEOUT = 60
CREDENTIAL_REFRESH_MINUTES = 3
SIGNING_ALGORITHM = "AWS4-X509-RSA-SHA256"
SIGNED_HEADERS = "content-type;host;x-amz-date;x-amz-x509"
CANONICAL_URI = "/sessions"
CONTENT_TYPE = "application/json"
ROLES_ANYWHERE_SUCCESS_CODES = (200, 201)
# Keys of the temporary credentials block of a CreateSession response.
CREDENTIAL_SET_KEY = "credentialSet"
CREDENTIALS_KEY = "credentials"
ACCESS_KEY_ID_KEY = "accessKeyId"
SECRET_ACCESS_KEY_KEY = "secretAccessKey"
SESSION_TOKEN_KEY = "sessionToken"
EXPIRATION_KEY = "expiration"
# Every key must be present (non-empty) in usable temporary credentials.
REQUIRED_CREDENTIAL_KEYS = (
    ACCESS_KEY_ID_KEY,
    SECRET_ACCESS_KEY_KEY,
    SESSION_TOKEN_KEY,
    EXPIRATION_KEY,
)
# Key under which the plugin storage keeps a fingerprint of the
# configuration the cached credentials were created for.
CREDENTIALS_FINGERPRINT_KEY = "credentials_fingerprint"
FINGERPRINT_SEPARATOR = "|"
ISO_UTC_SUFFIX = "Z"
ISO_UTC_OFFSET = "+00:00"

# CreateSession request body keys.
DURATION_SECONDS_KEY = "durationSeconds"
PROFILE_ARN_BODY_KEY = "profileArn"
ROLE_ARN_BODY_KEY = "roleArn"
SESSION_NAME_KEY = "sessionName"
TRUST_ANCHOR_ARN_BODY_KEY = "trustAnchorArn"

# CreateSession request signing (AWS SigV4 with an X.509 certificate).
HTTP_METHOD = "POST"
ROLES_ANYWHERE_SERVICE = "rolesanywhere"
SIGNING_TERMINATOR = "aws4_request"
AMZ_DATE_FORMAT = "%Y%m%dT%H%M%SZ"
DATE_STAMP_FORMAT = "%Y%m%d"
CREDENTIAL_SCOPE_FORMAT = "{date_stamp}/{region}/{service}/{terminator}"
CANONICAL_HEADERS_FORMAT = (
    "content-type:{content_type}\n"
    "host:{host}\n"
    "x-amz-date:{amz_date}\n"
    "x-amz-x509:{amz_x509}\n"
)
CANONICAL_REQUEST_FORMAT = (
    "{method}\n{uri}\n\n{canonical_headers}\n{signed_headers}\n"
    "{payload_hash}"
)
STRING_TO_SIGN_FORMAT = (
    "{algorithm}\n{amz_date}\n{credential_scope}\n{request_hash}"
)
AUTHORIZATION_FORMAT = (
    "{algorithm} Credential={serial_number}/{credential_scope}, "
    "SignedHeaders={signed_headers}, Signature={signature}"
)
ROLES_ANYWHERE_HOST_FORMAT = "rolesanywhere.{region}.{domain}"
ROLES_ANYWHERE_URL_FORMAT = "https://{host}{uri}"

# HTTP header names.
HEADER_CONTENT_TYPE = "Content-Type"
HEADER_AMZ_DATE = "X-Amz-Date"
HEADER_AMZ_X509 = "X-Amz-X509"
HEADER_AUTHORIZATION = "Authorization"
HEADER_USER_AGENT = "User-Agent"

# AWS service names, response keys and region prefixes.
S3_SERVICE = "s3"
STS_SERVICE = "sts"
ERROR_KEY = "Error"
ERROR_CODE_KEY = "Code"
ERROR_MESSAGE_KEY = "Message"
ROLES_ANYWHERE_MESSAGE_KEY = "message"
ACCOUNT_KEY = "Account"
LOCATION_CONSTRAINT_KEY = "LocationConstraint"
ARN_PREFIX = "arn"
ARN_MIN_FIELDS = 6
ARN_REGION_INDEX = 3
CN_REGION_PREFIX = "cn-"

# boto3 client settings.
BOTO_MAX_ATTEMPTS = 3
BOTO_RETRY_MODE = "standard"
BOTO_CONNECT_TIMEOUT = 30
BOTO_READ_TIMEOUT = 120

# AWS error codes. A HEAD response has no body, so botocore uses the HTTP
# status as the error code ("403", "404").
ACCESS_DENIED_CODES = ("403", "AccessDenied")
NOT_FOUND_CODES = ("404", "NoSuchBucket", "NotFound")
BUCKET_OWNED_CODES = ("BucketAlreadyOwnedByYou",)

# Object and serialization settings.
OBJECT_EXTENSION = ".gz"
OBJECT_KEY_PREFIX = "webtx"
OBJECT_NAME_FORMAT = "{epoch}_{thread_id}_{uuid}{extension}"
OBJECT_FOLDERS_FORMAT = "year={year}/month={month}/day={day}/hour={hour}"
OBJECT_KEY_FORMAT = "{prefix}/feedname={subtype}/{folders}/{name}"
TEMP_FILE_SUFFIX = ".gz"
TEXT_ENCODING = "utf-8"

# Logging.
ERROR_MESSAGE_LEAD = "Error occurred while"
VALIDATION_ACTION = "validating configuration parameters"
ROLES_ANYWHERE_ACTION = "generating temporary credentials"
MAX_ERROR_TEXT_LENGTH = 500

# Resolutions and message parts shared by the modules.
ENCRYPTED_KEY_CAUSE = (
    "Private Key is encrypted and no Password Phrase was provided, or the "
    "Password Phrase is incorrect."
)
ROLES_ANYWHERE_RESOLUTION = (
    "Ensure that the AWS IAM Roles Anywhere configuration parameters are "
    "correct."
)
ARN_RESOLUTION = (
    "Ensure that the Profile ARN, Role ARN, Trust Anchor ARN, the "
    "certificate and the policies attached to the role are correct."
)
ENDPOINT_REACHABLE_RESOLUTION = (
    "Ensure that the AWS IAM Roles Anywhere endpoint is reachable directly "
    "or through the configured proxy."
)
BUCKET_CHECK_RESOLUTION = (
    "Ensure that the AWS S3 Bucket configuration and network connectivity "
    "to AWS are correct."
)
ROLES_ANYWHERE_SUFFIX = (
    " when 'AWS IAM Roles Anywhere' is selected as Authentication Method"
)
SENSITIVE_TEXT_PATTERNS = (
    (r"-----BEGIN [A-Z ]+-----.*?-----END [A-Z ]+-----", "<redacted>"),
    (r"(?i)(authorization)\s*[:=]\s*[^;\n]+", r"\1=<redacted>"),
    (
        r"(?i)(x-amz-[\w-]+|[\w-]*secret[\w-]*|signature|"
        r"[\w-]*session[\w-]*token|password|pass_phrase|"
        r"private[\w-]*key|[\w-]*access[\w-]*key[\w-]*)"
        r"[\"']?\s*[:=]\s*[\"']?[^\s,;\"'}]+",
        r"\1=<redacted>",
    ),
    # An AWS access key id on its own (20 characters, fixed prefix).
    (r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA|ANVA|AIPA)[A-Z0-9]{16}\b",
     "<redacted>"),
    (r"(//)[^/@\s]+@", r"\1<redacted>@"),
    (r"\?[^\s'\")]*", ""),
)


REGION_CHOICES = [
    {"key": "US East (N. Virginia) [us-east-1]", "value": "us-east-1"},
    {"key": "US East (Ohio) [us-east-2]", "value": "us-east-2"},
    {"key": "US West (N. California) [us-west-1]", "value": "us-west-1"},
    {"key": "US West (Oregon) [us-west-2]", "value": "us-west-2"},
    {"key": "Africa (Cape Town) [af-south-1]", "value": "af-south-1"},
    {"key": "Asia Pacific (Hong Kong) [ap-east-1]", "value": "ap-east-1"},
    {"key": "Asia Pacific (Hyderabad) [ap-south-2]", "value": "ap-south-2"},
    {
        "key": "Asia Pacific (Jakarta) [ap-southeast-3]",
        "value": "ap-southeast-3",
    },
    {
        "key": "Asia Pacific (Malaysia) [ap-southeast-5]",
        "value": "ap-southeast-5",
    },
    {
        "key": "Asia Pacific (Melbourne) [ap-southeast-4]",
        "value": "ap-southeast-4",
    },
    {"key": "Asia Pacific (Mumbai) [ap-south-1]", "value": "ap-south-1"},
    {
        "key": "Asia Pacific (Osaka) [ap-northeast-3]",
        "value": "ap-northeast-3",
    },
    {
        "key": "Asia Pacific (Seoul) [ap-northeast-2]",
        "value": "ap-northeast-2",
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
        "key": "Asia Pacific (Thailand) [ap-southeast-7]",
        "value": "ap-southeast-7",
    },
    {
        "key": "Asia Pacific (Tokyo) [ap-northeast-1]",
        "value": "ap-northeast-1",
    },
    {"key": "Canada (Calgary) [ca-west-1]", "value": "ca-west-1"},
    {"key": "Canada (Central) [ca-central-1]", "value": "ca-central-1"},
    {"key": "China (Beijing) [cn-north-1]", "value": "cn-north-1"},
    {"key": "China (Ningxia) [cn-northwest-1]", "value": "cn-northwest-1"},
    {"key": "Europe (Frankfurt) [eu-central-1]", "value": "eu-central-1"},
    {"key": "Europe (Ireland) [eu-west-1]", "value": "eu-west-1"},
    {"key": "Europe (London) [eu-west-2]", "value": "eu-west-2"},
    {"key": "Europe (Milan) [eu-south-1]", "value": "eu-south-1"},
    {"key": "Europe (Paris) [eu-west-3]", "value": "eu-west-3"},
    {"key": "Europe (Spain) [eu-south-2]", "value": "eu-south-2"},
    {"key": "Europe (Stockholm) [eu-north-1]", "value": "eu-north-1"},
    {"key": "Europe (Zurich) [eu-central-2]", "value": "eu-central-2"},
    {"key": "Israel (Tel Aviv) [il-central-1]", "value": "il-central-1"},
    {"key": "Mexico (Central) [mx-central-1]", "value": "mx-central-1"},
    {"key": "Middle East (Bahrain) [me-south-1]", "value": "me-south-1"},
    {"key": "Middle East (UAE) [me-central-1]", "value": "me-central-1"},
    {"key": "South America (São Paulo) [sa-east-1]", "value": "sa-east-1"},
]

REGIONS = [choice["value"] for choice in REGION_CHOICES]

# Dynamic configuration fields (returned by get_dynamic_fields).
ROLES_ANYWHERE_FIELDS = [
    {
        "label": PRIVATE_KEY_LABEL,
        "key": PRIVATE_KEY_FILE_KEY,
        "type": "textarea",
        "default": "",
        "mandatory": True,
        "description": (
            "PEM-encoded private key used to decrypt the AWS Private CA "
            "Certificate. Required for 'AWS IAM Roles Anywhere' "
            "authentication."
        ),
    },
    {
        "label": CERTIFICATE_BODY_LABEL,
        "key": PUBLIC_CERTIFICATE_FILE_KEY,
        "type": "textarea",
        "default": "",
        "mandatory": True,
        "description": (
            "PEM-encoded X.509 certificate body issued by your AWS Private "
            "or Public CA. Required for 'AWS IAM Roles Anywhere' "
            "authentication."
        ),
    },
    {
        "label": PASS_PHRASE_LABEL,
        "key": PASS_PHRASE_KEY,
        "type": "password",
        "default": "",
        "mandatory": False,
        "description": (
            "Passphrase used to decrypt the Private Key. Required only if "
            "the Private Key is encrypted."
        ),
    },
    {
        "label": PROFILE_ARN_LABEL,
        "key": PROFILE_ARN_KEY,
        "type": "text",
        "default": "",
        "mandatory": True,
        "placeholder": (
            "e.g. arn:aws:rolesanywhere:us-east-1:123456789012:"
            "profile/profile-id"
        ),
        "description": (
            "ARN of the IAM Roles Anywhere profile. Required for 'AWS IAM "
            "Roles Anywhere' authentication."
        ),
    },
    {
        "label": ROLE_ARN_LABEL,
        "key": ROLE_ARN_KEY,
        "type": "text",
        "default": "",
        "mandatory": True,
        "placeholder": "e.g. arn:aws:iam::123456789012:role/role-name",
        "description": (
            "ARN of the IAM role to be assumed. Required for 'AWS IAM "
            "Roles Anywhere' authentication."
        ),
    },
    {
        "label": TRUST_ANCHOR_ARN_LABEL,
        "key": TRUST_ANCHOR_ARN_KEY,
        "type": "text",
        "default": "",
        "mandatory": True,
        "placeholder": (
            "e.g. arn:aws:rolesanywhere:us-east-1:123456789012:"
            "trust-anchor/anchor-id"
        ),
        "description": (
            "ARN of the IAM Roles Anywhere trust anchor. Required for "
            "'AWS IAM Roles Anywhere' authentication."
        ),
    },
]

EP_FIELD = {
    "label": EXTERNALLY_PROVISIONED_BUCKET_LABEL,
    "key": EXTERNALLY_PROVISIONED_BUCKET_KEY,
    "type": "choice",
    "choices": [
        {"key": "Yes", "value": EP_YES},
        {"key": "No", "value": EP_NO},
    ],
    "default": EP_DEFAULT,
    "mandatory": True,
    "description": (
        "Select 'Yes' if the S3 bucket is located in an external AWS "
        "account. Select 'No' if the bucket is in your own AWS account. If "
        "'No' is selected and the bucket does not already exist, the plugin "
        "will create it. If 'Yes' is selected, the bucket must already "
        "exist, as the plugin will not create it."
    ),
}

REGION_FIELD = {
    "label": REGION_NAME_LABEL,
    "key": REGION_NAME_KEY,
    "type": "choice",
    "choices": REGION_CHOICES
    + [{"key": "Custom Region", "value": CUSTOM_REGION_VALUE}],
    "default": DEFAULT_REGION,
    "mandatory": True,
    "description": (
        "AWS region where the AWS S3 Bucket resides. Make sure that the "
        "region matches the region in the Profile ARN and Trust Anchor ARN "
        "when 'AWS IAM Roles Anywhere' is used. Select 'Custom Region' to "
        "provide a region that is not in the list."
    ),
}

CUSTOM_REGION_FIELD = {
    "label": CUSTOM_REGION_NAME_LABEL,
    "key": CUSTOM_REGION_NAME_KEY,
    "type": "text",
    "default": "",
    "mandatory": False,
    "placeholder": "e.g. us-gov-west-1",
    "condition": {"key": REGION_NAME_KEY, "values": [CUSTOM_REGION_VALUE]},
    "description": (
        "AWS region code of the bucket. Required when 'Custom Region' is "
        "selected in AWS S3 Bucket Region Name."
    ),
}

BUCKET_FIELD = {
    "label": BUCKET_NAME_LABEL,
    "key": BUCKET_NAME_KEY,
    "type": "text",
    "default": "",
    "mandatory": True,
    "description": (
        "AWS S3 Bucket Name in which the WebTx data objects will be stored."
    ),
}

COMMON_FIELDS = [
    EP_FIELD,
    REGION_FIELD,
    CUSTOM_REGION_FIELD,
    BUCKET_FIELD,
]
