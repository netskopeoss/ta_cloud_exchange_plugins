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
"""

"""Provides constants for Azure Monitor plugin."""


GENERATE_TOKEN_BASE_URL = (
   "https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
)
API_SCOPE = "https://monitor.azure.com/.default"
GRANT_TYPE = "client_credentials"
PUSH_DATA_ENDPOINT = (
   "{dce_uri}/dataCollectionRules/{dcr_immutable_id}/streams/"
   "Custom-{custom_log_table_name}?api-version=2023-01-01"
)

MAX_RETRIES = 3
RETRY_SLEEP_TIME = 60
MAX_WAIT_TIME = 120
MODULE_NAME = "CLS"
PLUGIN_NAME = "Microsoft Azure Monitor"
PLUGIN_VERSION = "2.0.0"
MAXIMUM_CE_VERSION = "5.1.2"

RETRY_ERROR_MSG = (
   "Received exit code {status_code}, {error_reason} "
   "while {logger_msg}. Retrying after {wait_time} "
   "seconds. {retry_remaining} retries remaining."
)
NO_MORE_RETRIES_ERROR_MSG = (
   "Received exit code {status_code}, API rate limit "
   "exceeded while {logger_msg}. Max retries for rate "
   "limit handler exceeded hence returning status "
   "code {status_code}."
)
VALIDATION_ERROR_MSG = "Validation error occurred. "
