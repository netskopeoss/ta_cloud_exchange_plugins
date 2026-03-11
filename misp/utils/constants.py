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

CTE MISP Constants module.
"""

ATTRIBUTE_TYPES = [
    "md5",
    "sha256",
    "ip-src",
    "ip-src|port",
    "ip-dst",
    "ip-dst|port",
    "url",
    "domain",
    "domain|ip",
    "hostname",
    "hostname|port",
]


ATTRIBUTE_CATEGORIES = [
    "Internal reference",
    "Targeting data",
    "Antivirus detection",
    "Payload delivery",
    "Artifacts dropped",
    "Payload installation",
    "Persistence mechanism",
    "Network activity",
    "Payload type",
    "Attribution",
    "External analysis",
    "Financial fraud",
    "Support Tool",
    "Social network",
    "Person",
    "Other",
]
PLATFORM_NAME = "MISP"
PLUGIN_NAME = "MISP"
MODULE_NAME = "CTE"
PLUGIN_VERSION = "1.5.1"
BATCH_SIZE = 2500
MAX_API_CALLS = 4
DEFAULT_WAIT_TIME = 60
INTEGER_THRESHOLD = 4611686018427387904
MAX_LOOK_BACK = 8760
BIFURCATE_INDICATOR_TYPES = {
    "url",
    "ipv4",
    "ipv6",
}
RETRACTION = "Retraction"
DEFAULT_IOC_TAG = "netskope-ce"
SHARING_TAG_CONSTANT = "Netskope CE"
PULL_PAGE_SIZE = 1000
RETRACTION_BATCH = 10000
MAXIMUM_CE_VERSION = "5.1.2"
