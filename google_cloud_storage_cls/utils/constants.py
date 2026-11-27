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
Google Cloud Storage plugin constants.
"""

MODULE_NAME = "CLS"
PLATFORM_NAME = "Google Cloud Storage"
PLUGIN_NAME = "Google Cloud Storage"
PLUGIN_VERSION = "2.0.0"
ALERTS_DATA_TYPE = "alerts"
EVENTS_DATA_TYPE = "events"
WEBTX_DATA_TYPE = "webtx"
SUPPORTED_DATA_TYPES = (
    ALERTS_DATA_TYPE,
    EVENTS_DATA_TYPE,
    WEBTX_DATA_TYPE,
)
# Mapping file.
MAPPING_JSON_DATA = "jsonData"
MAPPING_TAXONOMY = "taxonomy"
MAPPING_JSON = "json"
NESTED_FIELD_SEPARATOR = "."
FORMAT_JSON = "json"
MAPPING_INVALID_JSON_MESSAGE = (
    "Invalid mapping file. The mapping must be a valid JSON object."
)
MAPPING_INVALID_JSON_RESOLUTION = (
    "Ensure that the mapping file is a valid JSON object."
)
MAPPING_MISSING_TAXONOMY_MESSAGE = (
    "Invalid mapping file. 'taxonomy.json' must be an object."
)
MAPPING_TYPE_INVALID_MESSAGE = (
    "Invalid mapping file. 'taxonomy.json.{data_type}' must be an object "
    "of subtype and list of field names."
)
MAPPING_SUBTYPE_INVALID_MESSAGE = (
    "Invalid mapping file. 'taxonomy.json.{data_type}.{subtype}' must be a "
    "list of field names (strings)."
)
MAPPING_VALIDATION_RESOLUTION = (
    "Ensure that the mapping file follows the structure of the default "
    "mapping 'Google Cloud Storage Default Mappings'."
)
MAPPING_VALIDATION_SUCCESS = "Mapping validation successful."
UNSUPPORTED_FORMAT_MESSAGE = (
    "Google Cloud Storage plugin supports only the JSON format."
)
MANIFEST_NAME_KEY = "name"
MANIFEST_VERSION_KEY = "version"

# Configuration parameter keys.
KEY_FILE_KEY = "key_file"
BUCKET_NAME_KEY = "bucket_name"
LOCATION_KEY = "location"
CUSTOM_LOCATION_KEY = "custom_location"
STORAGE_CLASS_KEY = "storage_class"
OBJECT_PREFIX_KEY = "obj_prefix"

# Configuration parameter labels.
KEY_FILE_LABEL = "Key File"
BUCKET_NAME_LABEL = "Bucket Name"
LOCATION_LABEL = "Region Name"
CUSTOM_LOCATION_LABEL = "Custom Region"
STORAGE_CLASS_LABEL = "Storage Class"
OBJECT_PREFIX_LABEL = "Object Prefix"

CUSTOM_LOCATION_VALUE = "custom"
STORAGE_CLASSES = ("STANDARD", "NEARLINE", "COLDLINE", "ARCHIVE")
LOCATIONS = (
    "US",
    "EU",
    "ASIA",
    "ASIA1",
    "EUR4",
    "NAM4",
    "NORTHAMERICA-NORTHEAST1",
    "NORTHAMERICA-NORTHEAST2",
    "US-CENTRAL1",
    "US-EAST1",
    "US-EAST4",
    "US-WEST1",
    "US-WEST2",
    "US-WEST3",
    "US-WEST4",
    "SOUTHAMERICA-EAST1",
    "EUROPE-CENTRAL2",
    "EUROPE-NORTH1",
    "EUROPE-WEST1",
    "EUROPE-WEST2",
    "EUROPE-WEST3",
    "EUROPE-WEST4",
    "EUROPE-WEST6",
    "ASIA-EAST1",
    "ASIA-EAST2",
    "ASIA-NORTHEAST1",
    "ASIA-NORTHEAST2",
    "ASIA-NORTHEAST3",
    "ASIA-SOUTH1",
    "ASIA-SOUTH2",
    "ASIA-SOUTHEAST1",
    "ASIA-SOUTHEAST2",
    "AUSTRALIA-SOUTHEAST1",
    "AUSTRALIA-SOUTHEAST2",
)
# Location of a bucket: letters, digits and dashes (e.g. ME-CENTRAL2).
LOCATION_REGEX = r"^[A-Za-z0-9][A-Za-z0-9-]{1,62}$"
# Bucket naming rules: 3 to 63 characters (dots allowed), no IP address.
BUCKET_NAME_REGEX = r"^[a-z0-9][a-z0-9._-]{1,61}[a-z0-9]$"
IP_ADDRESS_REGEX = r"^\d{1,3}(\.\d{1,3}){3}$"
BUCKET_RESERVED_PREFIX = "goog"
BUCKET_RESERVED_WORD = "google"
OBJECT_PREFIX_MAX_LENGTH = 200

# Service account key file.
SERVICE_ACCOUNT_TYPE = "service_account"
REQUIRED_KEY_FILE_FIELDS = (
    "type",
    "project_id",
    "private_key",
    "client_email",
)
UPLOAD_PERMISSION = "storage.objects.create"
STORAGE_SCOPE = "https://www.googleapis.com/auth/devstorage.read_write"


# Object settings.
# Objects are grouped in folders by Object Prefix, data type, subtype and the
# UTC hour of the upload, e.g.
# netskope/alerts/feedname=dlp/year=2026/month=11/day=24/hour=9/<name>.
OBJECT_FOLDER_FORMAT = (
    "{prefix}/{data_type}/feedname={subtype}"
    "/year={year}/month={month}/day={day}/hour={hour}"
)
OBJECT_NAME_FORMAT = "{epoch}_{thread_id}_{uuid}{extension}"
COMPRESSION_KEY = "compression"
COMPRESSION_LABEL = "Compression"
COMPRESSION_GZIP = "gzip"
COMPRESSION_NONE = "none"
COMPRESSION_OPTIONS = (COMPRESSION_GZIP, COMPRESSION_NONE)
OBJECT_EXTENSION_GZIP = ".json.gz"
OBJECT_EXTENSION_JSON = ".json"
OBJECT_CONTENT_TYPE_GZIP = "application/gzip"
OBJECT_CONTENT_TYPE_JSON = "application/x-ndjson"
TEXT_ENCODING = "utf-8"
# Objects have unique names; 0 makes the upload create-only, so an upload
# never overwrites an object. A 412 response to a retried upload means the
# object was already created, and is treated as success.
IF_GENERATION_MATCH = 0

# Text limits and redaction of secrets in logs.
MAX_ERROR_TEXT_LENGTH = 500
ERROR_MESSAGE_LEAD = "Error occurred while"
VALIDATION_ACTION = "validating configuration parameters"
SENSITIVE_TEXT_PATTERNS = (
    (
        r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY"
        r"-----",
        "[REDACTED]",
    ),
    (r"(?i)(private_key(?:_id)?\"?\s*[:=]\s*)\"[^\"]*\"", r"\1[REDACTED]"),
    (r"(?i)(bearer\s+)[A-Za-z0-9._~+/=-]+", r"\1[REDACTED]"),
    (r"(?i)(access_token|refresh_token|assertion)=[^&\s]+", r"\1=[REDACTED]"),
)

# Fields rendered after the Region Name (see get_dynamic_fields).
CUSTOM_LOCATION_FIELD = {
    "label": "Custom Region",
    "key": "custom_location",
    "type": "text",
    "default": "",
    "mandatory": False,
    "placeholder": "e.g. me-central2",
    "description": (
        "Location used while creating the bucket. Required when "
        "'Custom Region' is selected in Region Name."
    ),
}

COMMON_FIELDS = [
    {
        "label": "Storage Class",
        "key": "storage_class",
        "type": "choice",
        "choices": [
            {
                "key": "STANDARD",
                "value": "STANDARD"
            },
            {
                "key": "NEARLINE",
                "value": "NEARLINE"
            },
            {
                "key": "COLDLINE",
                "value": "COLDLINE"
            },
            {
                "key": "ARCHIVE",
                "value": "ARCHIVE"
            }
        ],
        "default": "STANDARD",
        "mandatory": True,
        "description": (
            "Storage class used while creating the bucket. It determines "
            "the costs for storing, retrieving, and performing operations"
            " on the objects. It is ignored if the bucket already exists."
        ),
    },
    {
        "label": "Object Prefix",
        "key": "obj_prefix",
        "type": "text",
        "default": "",
        "mandatory": True,
        "placeholder": "e.g. netskope",
        "description": (
            "Name of the top-level folder in the bucket under which the "
            "objects of this plugin configuration are stored. Objects are "
            "stored as <prefix>/<data_type>/feedname=<subtype>/"
            "year=<YYYY>/month=<M>/day=<D>/hour=<H>/"
            "<epoch>_<thread_id>_<uuid> (UTC) followed by the .json.gz "
            "(Gzip) or .json (None) extension. The prefix can be at most "
            "200 characters, may contain '/' for nested folders, and "
            "cannot have empty, '.' or '..' folder names or control "
            "characters."
        ),
    },
    {
        "label": "Compression",
        "key": "compression",
        "type": "choice",
        "choices": [
            {
                "key": "Gzip (Compressed)",
                "value": "gzip"
            },
            {
                "key": "None (Uncompressed)",
                "value": "none"
            }
        ],
        "default": "gzip",
        "mandatory": True,
        "description": (
            "Whether the objects are gzip-compressed before being stored "
            "in the bucket. Compressed objects are named with the "
            "'.json.gz' extension and uncompressed objects with the "
            "'.json' extension. Both contain one JSON log per line."
        ),
    }
]
