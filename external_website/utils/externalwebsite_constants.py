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

CTE Web Page IOC Scraper Plugin constants.
"""

MODULE_NAME = "CTE"
PLATFORM_NAME = "Web Page IOC Scraper"
MAXIMUM_CORE_VERSION = "5.1.2"
PLUGIN_VERSION = "2.0.0"
MAX_API_CALLS = 4
DEFAULT_WAIT_TIME = 60
DEFAULT_BATCH_SIZE = 5000
THREAT_TYPES = ["sha256", "md5", "url", "domain", "ipv4", "ipv6"]
THREAT_TYPES_LABELS = ["SHA256", "MD5", "URL", "Domain", "IPv4", "IPv6"]
RETRACTION_IOC_TAG = "IOC(s) Retraction"
RETRACTION = "[Retraction]"
FILE_TYPES = ["plain_text", "json", "xml", "html"]
FILE_TYPES_LABELS = ["Plain Text", "JSON", "XML", "HTML"]
VALIDATION_ERROR_MESSAGE = "Validation error occurred."

SHA256_REGEX = r"\b[a-fA-F0-9]{64}\b"
MD5_REGEX = r"\b[a-fA-F\d]{32}\b"
IPV4_REGEX = r"(?<![:\/\.\d])\b(?:\d{1,3}\.){3}\d{1,3}\b\/*?(?![:\/\.\dA-Za-z])"  # noqa: E501
IPV6_REGEX = (  # noqa: E501
    r"^(([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}"
    r"|([0-9a-fA-F]{1,4}:){1,7}:"
    r"|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}"
    r"|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}"
    r"|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}"
    r"|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}"
    r"|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}"
    r"|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})"
    r"|:((:[0-9a-fA-F]{1,4}){1,7}|:)"
    r"|([0-9a-fA-F]{1,4}:){1,7}:)(\/*)?$"
)
RESPONSE_LIST_REGEX = r"[^\s]+"
DOMAIN_REGEX = (  # noqa: E501
    r"^(?:\*\.)?[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?"
    r"(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}"
)
DOMAIN_REGEX_2 = (  # noqa: E501
    r"(?<!-)(?<![:\/\w.])(?:\*\.[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?"
    r"(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}"
    r"|(?<!\*)[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?"
    r"(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?)*\.[a-zA-Z]{2,})"
    r"(?::(?:6553[0-5]|655[0-2]\d|65[0-4]\d{2}|6[0-4]\d{3}"
    r"|[1-5]\d{4}|\d{1,4}))?(?:\/)?(?![:\/\w])"
)
