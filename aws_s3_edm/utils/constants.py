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

AWS S3 EDM plugin constants file.
"""

import gzip
import zipfile
import zlib

MODULE_NAME = "EDM"
PLATFORM_NAME = "AWS S3"
PLUGIN_NAME = "AWS S3"
PLUGIN_VERSION = "1.0.0"
USER_AGENT = "APN/1.1 (ahq9d89xj9gspapczzdb59goq)"
SAMPLE_DATA_RECORD_COUNT = 20
SAMPLE_CSV_FILE_NAME = "sample.txt"
MAX_COLUMNS = 25

# Authentication methods.
AUTH_DEPLOYED_ON_AWS = "deployed_on_aws"
AUTH_ROLES_ANYWHERE = "aws_iam_roles_anywhere"
AUTH_METHODS = [AUTH_DEPLOYED_ON_AWS, AUTH_ROLES_ANYWHERE]

# Roles Anywhere temporary credentials.
ROLES_ANYWHERE_SESSION_SECONDS = 900
ROLES_ANYWHERE_SESSION_NAME = "Session"
ROLES_ANYWHERE_TIMEOUT = 60
CREDENTIAL_REFRESH_MINUTES = 3

# boto3 client settings.
BOTO_MAX_ATTEMPTS = 3
BOTO_CONNECT_TIMEOUT = 30
BOTO_READ_TIMEOUT = 120

# S3 error codes used to map botocore errors to user messages.
AUTH_ERROR_CODES = (
    "InvalidAccessKeyId",
    "ExpiredToken",
    "ExpiredTokenException",
    "InvalidToken",
    "SignatureDoesNotMatch",
    "RequestTimeTooSkewed",
    "UnrecognizedClientException",
    "AuthFailure",
)
# The numeric codes are real: a HEAD response has no body, so botocore uses
# the HTTP status as the error Code ("400", "403", "404", "301").
ACCESS_DENIED_CODES = ("403", "AccessDenied")
NOT_FOUND_CODES = ("404", "NoSuchKey")
CHANGED_OBJECT_CODES = ("PreconditionFailed", "412", "InvalidRange", "416")
REGION_ERROR_CODES = (
    "301",
    "PermanentRedirect",
    "AuthorizationHeaderMalformed",
    "IllegalLocationConstraintException",
)

# Errors raised when reading a corrupt or unsupported gzip/zip archive.
ARCHIVE_READ_ERRORS = (
    gzip.BadGzipFile,
    zipfile.BadZipFile,
    zipfile.LargeZipFile,
    EOFError,
    zlib.error,
    NotImplementedError,
    RuntimeError,
)

# IAM Roles Anywhere request signing.
SIGNING_ALGORITHM = "AWS4-X509-RSA-SHA256"
SIGNED_HEADERS = "content-type;host;x-amz-date;x-amz-x509"
CANONICAL_URI = "/sessions"
CONTENT_TYPE = "application/json"

# Object key rules.
GZIP_EXTENSION = ".gz"
ZIP_EXTENSION = ".zip"
DATA_EXTENSIONS = (".csv", ".txt")
SUPPORTED_EXTENSIONS = (
    ".csv",
    ".txt",
    ".csv.gz",
    ".txt.gz",
    ".zip",
)
NESTED_ARCHIVE_EXTENSIONS = (
    ".zip",
    ".gz",
    ".tar",
    ".tgz",
    ".bz2",
    ".7z",
    ".xz",
)
MAX_KEY_LENGTH_BYTES = 1024
INVALID_DELIMITERS = ('"', "\n", "\r")

# File format markers (magic bytes).
GZIP_MAGIC = b"\x1f\x8b"
ZIP_MAGIC = b"PK\x03\x04"
UTF8_BOM = b"\xef\xbb\xbf"
FORMAT_PLAIN = "plain"
FORMAT_GZIP = "gzip"
FORMAT_ZIP = "zip"

# Zip entries that are ignored (OS metadata).
IGNORED_ZIP_PREFIXES = ("__MACOSX/",)
IGNORED_ZIP_NAMES = (".DS_Store",)
ZIP_ENCRYPTED_FLAG = 0x1

# S3 storage classes / archive tiers that cannot be read directly.
GLACIER_STORAGE_CLASSES = ("GLACIER", "DEEP_ARCHIVE")
ARCHIVE_ACCESS_TIERS = ("ARCHIVE_ACCESS", "DEEP_ARCHIVE_ACCESS")

# Size limits.
# Plain .csv/.txt files have no size limit (like linux_file_share_edm).
# The limits below are the current limits for compressed files (.gz/.zip),
# chosen for the expected Cloud Exchange host disk; they can be changed here.
MAX_COMPRESSED_SIZE = 1024 * 1024 * 1024  # 1 GiB (.gz / .zip objects)
MAX_DECOMPRESSED_SIZE = 5 * 1024 * 1024 * 1024  # 5 GiB (extracted data)
MAX_COMPRESSION_RATIO = 200  # Decompressed : compressed
MIN_BYTES_BEFORE_RATIO_CHECK = 10 * 1024 * 1024  # 10 MiB

# Streaming settings.
CHUNK_SIZE = 1024 * 1024  # 1 MiB
STREAM_BUFFER_SIZE = 64 * 1024  # Buffer for streamed S3 bodies
DOWNLOAD_RANGE_SIZE = 64 * 1024 * 1024  # 64 MiB per ranged GetObject
MAX_LINE_BYTES = 1024 * 1024  # Longest supported line while sampling
DOWNLOAD_MAX_ATTEMPTS = 2  # Initial attempt + one retry (risk R4)
RANGE_MAX_ATTEMPTS = 2  # One retry of a range on a streaming error
ARCHIVE_TEMP_FILE_NAME = "aws_s3_edm_download.tmp"

# Custom region: the dropdown value that selects the free text region.
CUSTOM_REGION_VALUE = "custom"
# Safety guard for the custom region: it is placed into manually built URLs
# (Roles Anywhere host, SigV4 scope), so it must be a valid DNS host label.
# Identical to the region name rule of botocore (validate_region_name), used
# with re.fullmatch. Nothing else about the region shape is assumed; AWS
# validates the region at the connection check.
REGION_NAME_REGEX = r"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$"
# Prefix of the AWS European Sovereign Cloud regions (partition aws-eusc).
UNSUPPORTED_REGION_PREFIXES = ("eusc-",)
UNSUPPORTED_REGION_MARKERS = ("-iso",)
# Original error texts shown to the user are sanitized and truncated.
MAX_ERROR_TEXT_LENGTH = 500
SENSITIVE_TEXT_PATTERNS = (
    (r"-----BEGIN [A-Z ]+-----.*?-----END [A-Z ]+-----", "<redacted>"),
    (r"(?i)(authorization)\s*[:=]\s*[^;\n]+", r"\1=<redacted>"),
    (
        r"(?i)(x-amz-[\w-]+|[\w-]*secret[\w-]*|signature|"
        r"[\w-]*session[\w-]*token|password|pass_phrase|"
        r"private[\w-]*key)[\"']?\s*[:=]\s*[\"']?[^\s,;\"'}]+",
        r"\1=<redacted>",
    ),
    (r"(//)[^/@\s]+@", r"\1<redacted>@"),
    (r"\?[^\s'\")]*", ""),
)
PARTITION_AWS = "aws"
PARTITION_AWS_CN = "aws-cn"
PARTITION_AWS_US_GOV = "aws-us-gov"
ROLES_ANYWHERE_DOMAIN = {
    PARTITION_AWS: "amazonaws.com",
    PARTITION_AWS_US_GOV: "amazonaws.com",
    PARTITION_AWS_CN: "amazonaws.com.cn",
}


# Fields that must never be whitespace stripped.
NO_STRIP_FIELDS = ("password", "pass_phrase", "delimiter")

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
    "mx-central-1",
]

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
    {"key": "US West (Oregon) [us-west-2]", "value": "us-west-2"},
    {"key": "Africa (Cape Town) [af-south-1]", "value": "af-south-1"},
    {
        "key": "Asia Pacific (Hong Kong) [ap-east-1]",
        "value": "ap-east-1",
    },
    {
        "key": "Asia Pacific (Mumbai) [ap-south-1]",
        "value": "ap-south-1",
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
        "key": "Asia Pacific (Melbourne) [ap-southeast-4]",
        "value": "ap-southeast-4",
    },
    {
        "key": "Asia Pacific (Thailand) [ap-southeast-7]",
        "value": "ap-southeast-7",
    },
    {"key": "Canada (Calgary) [ca-west-1]", "value": "ca-west-1"},
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
        "key": "Canada (Central) [ca-central-1]",
        "value": "ca-central-1",
    },
    {"key": "China (Beijing) [cn-north-1]", "value": "cn-north-1"},
    {
        "key": "China (Ningxia) [cn-northwest-1]",
        "value": "cn-northwest-1",
    },
    {
        "key": "Europe (Frankfurt) [eu-central-1]",
        "value": "eu-central-1",
    },
    {"key": "Europe (Ireland) [eu-west-1]", "value": "eu-west-1"},
    {"key": "Europe (London) [eu-west-2]", "value": "eu-west-2"},
    {"key": "Europe (Paris) [eu-west-3]", "value": "eu-west-3"},
    {"key": "Europe (Milan) [eu-south-1]", "value": "eu-south-1"},
    {
        "key": "Europe (Stockholm) [eu-north-1]",
        "value": "eu-north-1",
    },
    {
        "key": "Israel (Tel Aviv) [il-central-1]",
        "value": "il-central-1",
    },
    {
        "key": "Middle East (Bahrain) [me-south-1]",
        "value": "me-south-1",
    },
    {
        "key": "South America (São Paulo) [sa-east-1]",
        "value": "sa-east-1",
    },
    {
        "key": "Asia Pacific (Hyderabad) [ap-south-2]",
        "value": "ap-south-2",
    },
    {
        "key": "Asia Pacific (Jakarta) [ap-southeast-3]",
        "value": "ap-southeast-3",
    },
    {
        "key": "Asia Pacific (Malaysia) [ap-southeast-5]",
        "value": "ap-southeast-5",
    },
    {"key": "Europe (Spain) [eu-south-2]", "value": "eu-south-2"},
    {
        "key": "Europe (Zurich) [eu-central-2]",
        "value": "eu-central-2",
    },
    {
        "key": "Mexico (Central) [mx-central-1]",
        "value": "mx-central-1",
    },
    {
        "key": "Middle East (UAE) [me-central-1]",
        "value": "me-central-1",
    },
]


AUTH_METHOD_FIELD = {
    "label": "Authentication Method",
    "key": "authentication_method",
    "type": "choice",
    "choices": [
        {"key": "Deployed on AWS", "value": AUTH_DEPLOYED_ON_AWS},
        {"key": "AWS IAM Roles Anywhere", "value": AUTH_ROLES_ANYWHERE},
    ],
    "default": AUTH_DEPLOYED_ON_AWS,
    "mandatory": True,
    "description": (
        "Select the method to be used for AWS client authentication."
    ),
}

# The Roles Anywhere fields are returned by get_fields for every method and
# shown only for that method. Shape as used by PluginDynamicForm.jsx
# (filterFields) and repos.py (_is_field_visible):
# {"key": <field key>, "values": [<values>]}. The diagnose redactor ignores
# the condition, so the fields are always enumerated.
ROLES_ANYWHERE_CONDITION = {
    "key": "authentication_method",
    "values": [AUTH_ROLES_ANYWHERE],
}

ROLES_ANYWHERE_FIELDS = [
    {
        "label": "Private Key",
        "key": "private_key_file",
        "type": "textarea",
        "default": "",
        "mandatory": True,
        "condition": ROLES_ANYWHERE_CONDITION,
        "description": (
            "PEM-encoded private key used to decrypt the AWS Private CA "
            "Certificate. Required for 'AWS IAM Roles Anywhere' "
            "authentication."
        ),
    },
    {
        "label": "Certificate Body",
        "key": "public_certificate_file",
        "type": "textarea",
        "default": "",
        "mandatory": True,
        "condition": ROLES_ANYWHERE_CONDITION,
        "description": (
            "PEM-encoded X.509 certificate body issued by your AWS "
            "Private or Public CA. Required for 'AWS IAM Roles Anywhere' "
            "authentication."
        ),
    },
    {
        "label": "Password Phrase",
        "key": "pass_phrase",
        "type": "password",
        "default": "",
        "mandatory": False,
        "condition": ROLES_ANYWHERE_CONDITION,
        "description": (
            "Passphrase used to decrypt the Private Key if it is "
            "encrypted. Required for 'AWS IAM Roles Anywhere' "
            "authentication only if the Private Key is encrypted."
        ),
    },
    {
        "label": "Profile ARN",
        "key": "profile_arn",
        "type": "text",
        "default": "",
        "mandatory": True,
        "condition": ROLES_ANYWHERE_CONDITION,
        "placeholder": (
            "e.g. arn:aws:rolesanywhere:us-east-1:123456789012:"
            "profile/profile-id"
        ),
        "description": (
            "AWS Profile ARN for AWS client authentication. Required for "
            "'AWS IAM Roles Anywhere' authentication type."
        ),
    },
    {
        "label": "Role ARN",
        "key": "role_arn",
        "type": "text",
        "default": "",
        "mandatory": True,
        "condition": ROLES_ANYWHERE_CONDITION,
        "placeholder": (
            "e.g. arn:aws:iam::123456789012:role/role-name"
        ),
        "description": (
            "AWS Role ARN for AWS client authentication. Required for "
            "'AWS IAM Roles Anywhere' authentication type."
        ),
    },
    {
        "label": "Trust Anchor ARN",
        "key": "trust_anchor_arn",
        "type": "text",
        "default": "",
        "mandatory": True,
        "condition": ROLES_ANYWHERE_CONDITION,
        "placeholder": (
            "e.g. arn:aws:rolesanywhere:us-east-1:123456789012:"
            "trust-anchor/anchor-id"
        ),
        "description": (
            "AWS Trust Anchor ARN for AWS client authentication. Required "
            "for 'AWS IAM Roles Anywhere' authentication type."
        ),
    },
]

# Fields shown for every authentication method (returned after the
# Roles Anywhere fields).
S3_LOCATION_FIELDS = [
    {
        "label": "AWS S3 Bucket Region",
        "key": "region_name",
        "type": "choice",
        "choices": REGION_CHOICES
        + [{"key": "Custom Region", "value": CUSTOM_REGION_VALUE}],
        "default": "us-east-1",
        "mandatory": True,
        "description": (
            "AWS region where the S3 bucket resides. Make sure the region "
            "matches the region in the Profile ARN and Trust Anchor ARN "
            "when using IAM Roles Anywhere. Select Custom Region to enter "
            "a region that is not in the list."
        ),
    },
    {
        "label": "AWS Custom Region",
        "key": "custom_region_name",
        "type": "text",
        "default": "",
        "mandatory": True,
        "placeholder": "e.g. us-west-1",
        "condition": {"key": "region_name", "values": [CUSTOM_REGION_VALUE]},
        "description": (
            "Any valid AWS region code of the bucket, for a region that is "
            "not in the AWS S3 Bucket Region list. IAM Roles Anywhere "
            "supports the aws, aws-cn and aws-us-gov partitions only (not "
            "ISO or eusc- regions)."
        ),
    },
    {
        "label": "AWS S3 Bucket Name",
        "key": "bucket_name",
        "type": "text",
        "default": "",
        "mandatory": True,
        "placeholder": "e.g. my-edm-data-bucket",
        "description": (
            "Name of the AWS S3 bucket that contains the file to be "
            "pulled. Example: my-edm-data-bucket."
        ),
    },
    {
        "label": "File Path",
        "key": "filepath",
        "type": "text",
        "default": "",
        "mandatory": True,
        "placeholder": "e.g. exports/customers/data.csv",
        "description": (
            "File path (path of the file inside the bucket) to be "
            "pulled. Do not include the bucket name or the s3:// "
            "prefix."
        ),
        "helperText": (
            "Only .csv, .txt, .csv.gz, .txt.gz and .zip (containing "
            "one .csv/.txt) UTF-8 encoded files with max 25 columns are "
            "supported. "
            "A zip must contain exactly one unencrypted .csv/.txt "
            "file and no nested archive."
        ),
    },
    {
        "label": "Delimiter",
        "key": "delimiter",
        "type": "text",
        "default": ",",
        "mandatory": True,
        "placeholder": "e.g. , or | or ;",
        "description": (
            "Single character delimiter used in the CSV/TXT file "
            "(e.g. comma, pipe, semicolon)."
        ),
    },
    {
        "label": "Remove Quotes",
        "key": "remove_quotes",
        "type": "boolean",
        "default": False,
        "mandatory": False,
        "description": (
            "Enable this if your CSV encloses fields in double quotes, "
            "especially when values contain commas. Quoted fields will be "
            "parsed as single columns. Improper quote placement may cause "
            "rows to be skipped."
        ),
        "helperText": (
            "Example: \"123 Main St, Apt 4B\" stays in one column "
            "instead of splitting. Turn this on if your CSV encloses "
            "fields in double quotes, especially when values contain "
            "commas."
        ),
    },
]

AWS_S3_EDM_FIELDS = {
    # All fields are returned for every authentication method (no
    # branching): the diagnose redactor only removes the keys it can
    # enumerate from get_fields, and the UI hides the conditional fields.
    "configuration": (
        [AUTH_METHOD_FIELD] + ROLES_ANYWHERE_FIELDS + S3_LOCATION_FIELDS
    ),
    "sanity_inputs": [
        {
            "label": "Sanitization Parameters",
            "key": "sanitization_input",
            "type": "sanitization_input",
            "default": {},
            "mandatory": False,
            "description": (
                "Parameters required for sanitization and EDM hashing."
            ),
        },
        {
            "label": "Remove Stopwords",
            "key": "exclude_stopwords",
            "type": "boolean",
            "default": False,
            "mandatory": False,
            "description": (
                "By default, stopwords are included during data sanitization "
                "for all the columns. To reflect the changes in sanitization "
                "for any given column, make sure that column is selected as "
                "'Name Column' and 'Proceed without sanitization' is unchecked"
                " in the next step."
            ),
            "helperText": (
                "Stopwords are common words (e.g., 'is', 'the', 'and') that "
                "are often removed to improve accuracy."
            ),
        },
    ],
    "sanity_results": [
        {
            "label": "Preview Files",
            "key": "sanity_preview",
            "type": "sanitization_preview",
            "default": "",
            "mandatory": False,
            "description": (
                "Preview options for viewing sanitized results. "
                "This provides a way to see the data before "
                "further processing. "
                "It includes both 'good' and 'bad' files, "
                "indicating data that passed and data that "
                "didn't meet the sanitization criteria."
            ),
            "readonly": True,
        },
        {
            "label": "Proceed Without Sanitization",
            "key": "is_unsanitized_data",
            "type": "boolean",
            "default": True,
            "mandatory": True,
            "description": (
                "When on, every row is hashed as pulled. When off, only "
                "the rows in the Good file are hashed."
            ),
        },
    ],
}

# Error messages start with this lead, resolutions with "Ensure that".
ERROR_MESSAGE_LEAD = "Error occurred while"
# What was being done for each S3 operation (error message lead).
OPERATION_ACTIONS = {
    "head_bucket": "validating the AWS S3 bucket",
    "get_bucket_location": "validating the AWS S3 bucket region",
    "head_object": "validating the file path",
    "get_object": "downloading the file",
}
