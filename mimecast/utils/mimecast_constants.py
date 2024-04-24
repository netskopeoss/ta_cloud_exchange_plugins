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

CTE Mimecast plugin constants.
"""

MAX_REQUEST_URL = 25
MAX_CREATE_URL = 20
PLUGIN_NAME = "Mimecast"
MODULE_NAME = "CTE"
PLUGIN_VERSION = "1.2.0"
DEFAULT_WAIT_TIME = 60
MAX_API_CALLS = 4
PUSH_HASH_BATCH_SIZE = 1000
PULL_URL_BATCH_SIZE = 500

GET_ACCOUNT_ENDPOINT = "/api/account/get-account"
FETCH_HASHES_ENDPOINT = "/api/ttp/threat-intel/get-feed"
FETCH_URL_ENDPOINT = "/api/ttp/url/get-logs"
PUSH_HASH_ENDPOINT = "/api/byo-threat-intelligence/create-batch"
DECODE_URL_ENDPOINT = "/api/ttp/url/decode-url"
PUSH_URL_ENDPOINT = "/api/ttp/url/create-managed-url"




GET_TYPE_FROM_MAPPING = {
    "text": str,
    "password": str,
    "number": int,
    "choice": str,
    "multichoice": list,
    "teaxtarea": str,
}

HASH_OPERATION_TYPE = {
    "ALLOW": "ALLOW",
    "BLOCK": "BLOCK",
    "DELETE": "DELETE",
}

URL_OPERATION_TYPE = {
    "BLOCK": "block",
    "PERMIT": "permit",
}

MALWARE_TYPE = {
    "Malware Customer": "malware_customer",
    "Malware Grid": "malware_grid"
}

FEED_TYPES = {
    "malware_customer": "Malware Customer",
    "malware_grid": "Malware Grid",
    "malsite": "Malsite"
}

MALWARE_TYPES = [
    "MD5",
    "SHA256"
]
