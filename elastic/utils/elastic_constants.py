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

"""Elastic Plugin constants."""


SEVERITY_LOW = "Low"
SEVERITY_MEDIUM = "Medium"
SEVERITY_HIGH = "High"
SEVERITY_VERY_HIGH = "Very-High"
SEVERITY_UNKNOWN = "Unknown"
MODULE_NAME = "CLS"
PLATFORM_NAME = "Elastic"
PLUGIN_NAME = "Elastic"
BATCH_SIZE = 100
PLUGIN_VERSION = "2.1.0"
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

BOOLEAN_FIELDS = [
    "netskope.alerts.ml_detection",
    "netskope.alerts.obfuscate",
    "netskope.alerts.is_web_universal_connector",
    "netskope.events.obfuscate",
]
