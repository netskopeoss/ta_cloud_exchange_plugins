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

"""CLS Google Chronicle Plugin constants."""

MODULE_NAME = "CLS"
PLUGIN_NAME = "Google Chronicle"
PLUGIN_VERSION = "3.0.0"
MAXIMUM_CORE_VERSION = "5.1.2"

DEFAULT_URL = {
    "usa": "https://malachiteingestion-pa.googleapis.com",
    "europe": "https://europe-malachiteingestion-pa.googleapis.com",
    "asia": "https://asia-southeast1-malachiteingestion-pa.googleapis.com",
}
SCOPES = ["https://www.googleapis.com/auth/malachite-ingestion"]

SEVERITY_LOW = "Low"
SEVERITY_MEDIUM = "Medium"
SEVERITY_HIGH = "High"
SEVERITY_VERY_HIGH = "High"
SEVERITY_UNKNOWN = "UNKNOWN_SEVERITY"

SEVERITY_MAP = {
    "low": SEVERITY_LOW,
    "med": SEVERITY_MEDIUM,
    "medium": SEVERITY_MEDIUM,
    "high": SEVERITY_HIGH,
    "very-high": SEVERITY_VERY_HIGH,
    "critical": SEVERITY_VERY_HIGH,
    "0": SEVERITY_LOW,
    "1": SEVERITY_LOW,
    "2": SEVERITY_LOW,
    "3": SEVERITY_LOW,
    "4": SEVERITY_MEDIUM,
    "5": SEVERITY_MEDIUM,
    "6": SEVERITY_MEDIUM,
    "7": SEVERITY_HIGH,
    "8": SEVERITY_HIGH,
    "9": SEVERITY_VERY_HIGH,
    "10": SEVERITY_VERY_HIGH,
}

DUMMY_DATA = [
    {
        "metadata": {
            "event_timestamp": "2022-07-04T06:39:49Z",
            "product_name": "Netskope Alert",
            "product_version": "NULL",
            "product_event_type": "[test] - test",
            "event_type": "GENERIC_EVENT",
            "product_log_id": "111111111111111111111111",
            "vendor_name": "Netskope",
            "description": "test",
        },
        "security_result": {"severity": "Low", "action_details": "no action"},
        "principal": {
            "user": {
                "user_display_name": "testurl@xyz.com",
                "userid": "testurl@xyz.com",
                "email_addresses": "testurl@xyz.com",
            }
        },
    }
]
LOG_TYPE = "NETSKOPE_ALERT_V2"
DUMMY_DATA_JSON = [
    {
        "log_text": (
            "26-Feb-2019 13:35:02.187 client 10.120.20.32#4238: "
            "query: altostrat.com IN A + (203.0.113.102)"
        ),
        "ts_epoch_microseconds": 1551188102187000,
    }
]
LOG_SOURCE_IDENTIFIER = "netskopece"
BATCH_SIZE = 800000
