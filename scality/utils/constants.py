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


Scality Constants.
"""

MODULE_NAME = "CLS"
PLATFORM_NAME = "Scality"
PLUGIN_NAME = "Scality"
PLUGIN_VERSION = "1.1.0"
VALIDATION_ERROR_MESSAGE = "Validation error occurred."

# Data types handled by the plugin.
WEBTX_DATA_TYPE = "webtx"

# Object file properties.
GZIP_EXTENSION = ".gz"
# Kept as ".txt" so objects stay compatible with version 1.0.0.
ALERTS_EVENTS_EXTENSION = ".txt"
TEXT_ENCODING = "utf-8"

# boto3 client settings.
VALIDATION_MAX_RETRIES = 0
MAX_RETRIES = 3
READ_TIMEOUT = 300

# Only an AWS style endpoint URL carries a region; a Scality endpoint
# does not match this pattern and the client is then created without a
# region, exactly as in version 1.0.0.
EXTRACT_AWS_REGION_REGEX = r"https?://s3\.([a-zA-Z0-9-]+)\.amazonaws\.com"
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
]

# --- Configuration keys (the keys of manifest.json) ---
CONFIG_ENDPOINT_URL = "endpoint_url"
CONFIG_ACCESS_KEY = "access_key"
CONFIG_SECRET_ACCESS_KEY = "secret_access_key"
CONFIG_BUCKET_NAME = "bucket_name"
# The output format Cloud Exchange passes to the plugin. Version 5.1.2
# and older pass a boolean, newer versions pass the format name.
TRANSFORM_DATA_KEY = "transformData"
JSON_FORMAT = "json"

# --- Mappings ---
MAPPINGS_JSON_DATA_KEY = "jsonData"
TAXONOMY_KEY = "taxonomy"
MAPPINGS_SCHEMA = {
    "type": "object",
    "properties": {
        TAXONOMY_KEY: {
            "type": "object",
            "properties": {
                JSON_FORMAT: {
                    "type": "object",
                    "patternProperties": {
                        ".*": {
                            "type": "object",
                            "patternProperties": {".*": {"type": "array"}},
                        }
                    },
                }
            },
            "required": [JSON_FORMAT],
        }
    },
    "required": [TAXONOMY_KEY],
}

# --- boto3 and the S3 API ---
S3_SERVICE_NAME = "s3"
RETRY_MODE = "standard"
DEFAULT_REGION = "us-east-1"
BUCKETS_KEY = "Buckets"
BUCKET_NAME_KEY = "Name"
LOCATION_CONSTRAINT_KEY = "LocationConstraint"

# --- Object key layout ---
# <data type>/feedname=<subtype>/year=Y/month=M/day=D/hour=H/<name>
PARTITION_TEMPLATE = "year={year}/month={month}/day={day}/hour={hour}"
FEEDNAME_TEMPLATE = "feedname={subtype}"
# The same file name as the other S3 style plugins.
OBJECT_NAME_TEMPLATE = "{epoch}_{thread_id}_{uuid}{extension}"
JSON_SEPARATORS = (",", ":")

# --- User agent ---
USER_AGENT_HEADER = "User-Agent"
DEFAULT_USER_AGENT = "netskope-ce"
USER_AGENT_TEMPLATE = "{ce_agent}-{module}-{plugin}-v{version}"

# --- Error messages ---
ERROR_MESSAGE_LEAD = "Error occurred while"

# Resolutions used when a boto3 error says what actually went wrong.
ENDPOINT_RESOLUTION = (
    f"Ensure that the {PLATFORM_NAME} Endpoint URL provided in the"
    " configuration parameters is correct and that the Cloud Exchange"
    " host can reach it, directly or through the configured proxy."
)
PROXY_RESOLUTION = (
    "Ensure that the proxy configured for Cloud Exchange is reachable"
    f" and allows connections to the {PLATFORM_NAME} Endpoint URL."
)
SSL_RESOLUTION = (
    f"Ensure that the SSL certificate of the {PLATFORM_NAME} instance"
    " is valid and trusted by the Cloud Exchange host."
)
TIMEOUT_RESOLUTION = (
    f"Ensure that the {PLATFORM_NAME} Endpoint URL is reachable from"
    " Cloud Exchange and that the instance responds within the"
    " configured timeout."
)
CREDENTIALS_RESOLUTION = (
    "Ensure that the Access Key and Secret Access Key provided in the"
    " configuration parameters are correct."
)
PERMISSION_RESOLUTION = (
    "Ensure that the user of the provided Access Key has the required"
    f" permissions on the {PLATFORM_NAME} bucket."
)
BUCKET_RESOLUTION = (
    f"Ensure that the {PLATFORM_NAME} Bucket Name provided in the"
    f" configuration parameters exists on {PLATFORM_NAME}."
)

# Error codes returned by Scality in a botocore ClientError.
CREDENTIAL_ERROR_CODES = frozenset(
    {
        "AuthFailure",
        "ExpiredToken",
        "InvalidAccessKeyId",
        "InvalidClientTokenId",
        "InvalidToken",
        "SignatureDoesNotMatch",
        "UnrecognizedClientException",
    }
)
PERMISSION_ERROR_CODES = frozenset(
    {"403", "AccessDenied", "AllAccessDisabled"}
)
BUCKET_ERROR_CODES = frozenset({"404", "NoSuchBucket", "PermanentRedirect"})

# --- Masking ---
# Replaces the credentials when a ScalityConfig is printed.
MASK = "***"
