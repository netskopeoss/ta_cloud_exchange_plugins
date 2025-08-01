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

"""Netskope CTE Plugin constants."""

from netskope.integrations.cte.models import SeverityType

REGEX_FOR_MD5 = r"^[0-9a-fA-F]{32}$"
REGEX_FOR_SHA256 = r"^[0-9a-fA-F]{64}$"
REGEX_FOR_URL = r"^(\*.?)?(https?:\/\/)?[a-zA-Z0-9]+(\.[a-zA-Z0-9]+)*\.[a-zA-Z]+(\/[\w]*)*$"
REGEX_HOST = (
    r"^(?!:\/\/)([a-z0-9-]{1,63}\.)?[a-z0-9-]{1,63}(?:\.[a-z]{2,})?$|"
    r"^(?:(?:25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\.){3}(?:25[0-5]|(?:2[0-4]|1\d|[1-9]|)\d)$"
)
BATCH_SIZE = 10000
MAX_PUSH_INDICATORS = 300000
MAX_PUSH_HOSTS = 500
MAX_QUERY_INDICATORS = 500
# MAX_PUSH_INDICATORS = 300
JSON_DATA_OFFSET = 35
URLS = {
    "V2_URL_LIST": "{}/api/v2/policy/urllist",
    "V2_URL_LIST_DEPLOY": "{}/api/v2/policy/urllist/deploy",
    "V1_FILEHASH_LIST": "{}/api/v1/updateFileHashList",
    "V2_URL_LIST_REPLACE": "{}/api/v2/policy/urllist/{}/replace",
    "V2_PRIVATE_APP": "{}/api/v2/steering/apps/private",
    "V2_PRIVATE_APP_PATCH": "{}/api/v2/steering/apps/private/{}",
    "V2_PUBLISHER": "{}/api/v2/infrastructure/publishers",
    "V2_RETROHUNT_HASH_INFO": "{}/api/v2/nsiq/retrohunt/ioc/getinfo",
}
MODULE_NAME = "CTE"
PLUGIN_NAME = "Netskope CTE"
PLUGIN_VERSION = "2.2.0"
RETROHUNT_FP_SEVERITY_MAPPING = {
    "1": SeverityType.LOW,
    "2": SeverityType.MEDIUM,
    "3": SeverityType.HIGH,
}
BYTES_TO_MB = 1024 * 1024
# Retraction Constant
RETRACTION = "Retraction"
