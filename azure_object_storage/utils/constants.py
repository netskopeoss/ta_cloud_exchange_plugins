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

Microsoft Azure Cloud Storage plugin constants.
"""

MODULE_NAME = "CLS"
PLATFORM_NAME = "Microsoft Azure"
PLUGIN_NAME = "Microsoft Azure Cloud Storage"
PLUGIN_VERSION = "1.1.0"

VALIDATION_ERROR_MSG = "Validation error occurred."

# Data types handled by this plugin. Logs reach push() as dicts.
TYPE_ALERTS = "alerts"
TYPE_EVENTS = "events"
TYPE_WEBTX = "webtx"

# Azure Blob Storage container naming rules. The pattern only accepts
# lowercase characters, so a purely numeric container name - which Azure
# permits - is no longer rejected the way a str.islower() check would.
MIN_CONTAINER_NAME_LENGTH = 3
MAX_CONTAINER_NAME_LENGTH = 63
# The Object Prefix is the top-level folder of the blob name. The limit keeps
# the full blob name (prefix + folders + file name) well inside the 1,024
# character limit of Azure.
MAX_OBJECT_PREFIX_LENGTH = 200
REGEX_FOR_CONTAINER = r"^(?!-)(?!.*--)[a-z0-9-]+(?<!-)$"

# Blob compression options. Compressed blobs are gzip streams whose
# decompressed content is JSON Lines; uncompressed blobs are plain JSON
# Lines.
# Mapping file.
MAPPING_JSON_DATA = "jsonData"
MAPPING_TAXONOMY = "taxonomy"
MAPPING_JSON = "json"
NESTED_FIELD_SEPARATOR = "."
SUPPORTED_DATA_TYPES = ("alerts", "events", "webtx")
MAPPING_VALIDATION_RESOLUTION = (
    "Ensure that the mapping file follows the structure of the default "
    "mapping 'Microsoft Azure Cloud Storage Default Mappings'."
)

COMPRESSION_KEY = "compression"
COMPRESSION_GZIP = "gzip"
COMPRESSION_NONE = "none"
BLOB_EXTENSION_JSON_GZIP = ".json.gz"
BLOB_EXTENSION_JSON = ".json"

# Retry settings handed to the Azure SDK pipeline. The SDK already retries
# throttling (429) and server (5xx) responses with an exponential backoff,
# so no retry loop is hand-rolled in this plugin.
MAX_RETRIES = 4

# Socket timeouts, set explicitly so the values are visible here rather
# than inherited. They match the Azure SDK's own defaults, which
# _shared/base_client.py applies when the caller passes none. CE Core
# does not impose a request timeout of its own; the only ceiling is the
# Celery soft time limit on the task, so a request that never times out
# would hold a worker until that limit is reached.
CONNECTION_TIMEOUT = 20
READ_TIMEOUT = 60
