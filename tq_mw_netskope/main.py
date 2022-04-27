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

"""ThreatQuotient CTE plugin."""


###########################################################################################################
# ThreatQuotient Proprietary and Confidential
# Copyright (c)2020 ThreatQuotient, Inc. All rights reserved.
#
# NOTICE: All information contained herein, is, and remains the property of ThreatQuotient, Inc.
# The intellectual and technical concepts contained herein are proprietary to ThreatQuotient, Inc.
# and its suppliers and may be covered by U.S. and Foreign Patents, patents in process, and are
# protected by trade secret or copyright law.
#
# Dissemination of this information or reproduction of this material is strictly forbidden unless prior
# written permission is obtained from ThreatQuotient, Inc.
###########################################################################################################
import sys

from netskope.integrations.cte.plugin_base import PluginBase, ValidationResult
from netskope.integrations.cte.models import Indicator, IndicatorType
from .lib.threatqsdk import Threatq, ThreatLibrary
from .lib.threatqsdk.exceptions import AuthenticationError
from netskope.integrations.cte.models.business_rule import Action

string_types = (str,)
if sys.version_info < (3,):
    string_types += (str, unicode)  # noqa: F821

supported_types = ["URL", "MD5", "SHA-256", "IP Address", "FQDN"]


class ThreatQ(PluginBase):
    """ThreatQ Plugin."""

    def pull(self):
        """Pull indicators from ThreatQ."""
        host = self.configuration.get("tq_host")
        client_id = self.configuration.get("tq_client_id")
        client_secret = self.configuration.get("tq_client_secret")

        proxy_info = (
            self.proxy["https"]
            if self.proxy and "https" in self.proxy
            else None
        )
        proxy_info = (
            self.proxy["http"] if self.proxy and "http" in self.proxy else None
        )
        verify = self.ssl_validation

        fields = ["id", "value", "type", "score", "status"]
        tq = None
        indicators = []

        try:
            tq = Threatq(
                host,
                (client_id, client_secret),
                private=True,
                verify=verify,
                proxy=proxy_info,
            )
        except AuthenticationError:
            message = "[ThreatQ Plugin Pull]: Failed to Authenticate with ThreatQ [{}]".format(
                host
            )
            self.notifier.error(message)
            self.logger.error(message)
            return ValidationResult(success=False, message=message)

        tlsearch = ThreatLibrary(tq, fields=fields)
        search_list = list(
            filter(
                lambda i: len(i) > 0,
                map(
                    lambda i: i.strip(),
                    self.configuration.get("tq_searches").split(","),
                ),
            )
        )

        # Give us all the TL Search results ordered by ID
        for search_name in search_list:
            for ind in tlsearch.get_saved_search(search_name).execute(
                "indicators"
            ):
                score = ind.get("score") if ind.get("score") <= 10 else 10
                typename = ind.get("type")
                value = ind.get("value")
                score = score if score > 0 else 1
                tq_url = "{0}/indicators/{1}/details".format(
                    host, ind.get("id")
                )
                if not typename or typename not in supported_types:
                    continue

                new_ind = Indicator(
                    value=value,
                    type=self.get_ns_type(typename),
                    reputation=score,
                    extendedInformation=tq_url,
                    active=ind.get("status") != "Expired",
                )

                indicators.append(new_ind)

        return indicators

    def validate(self, data):
        """Validate configuration."""
        fields = {
            "tq_host": "ThreatQ URL",
            "tq_client_id": "ThreatQ Client ID",
            "tq_client_secret": "ThreatQ Client Secret",
            "tq_searches": "ThreatQ Search Names",
        }

        validation_msg = "[ThreatQ Plugin Validation]: The value provided for field [{}] was invalid"

        # Validate that our fields were filled out properly.
        for k, v in fields.items():
            if k not in data or not data[k] or type(data[k]) != str:
                self.logger.error(validation_msg.format(v))
                self.notifier.error(validation_msg)
                return ValidationResult(
                    success=False, message=validation_msg.format(v)
                )

        # Check for connectivity to ThreatQ
        host = data.get("tq_host")
        client_id = data.get("tq_client_id")
        client_secret = data.get("tq_client_secret")

        proxy_info = (
            self.proxy["https"]
            if self.proxy and "https" in self.proxy
            else None
        )
        proxy_info = (
            self.proxy["http"] if self.proxy and "http" in self.proxy else None
        )
        verify = self.ssl_validation

        # Verify that our host has https://
        if host.startswith("http://"):
            host = "https://{}".format(host[7:])
        elif not host.startswith("https://"):
            host = "https://{}".format(host)

        try:
            Threatq(
                host,
                (client_id, client_secret),
                private=True,
                verify=verify,
                proxy=proxy_info,
            )
        except AuthenticationError:
            message = "[ThreatQ Plugin Validation]: Failed to Authenticate with ThreatQ [{}]".format(
                host
            )
            self.notifier.error(message)
            self.logger.error(message)
            return ValidationResult(success=False, message=message)
        except Exception as ex:
            self.logger.error(f"[ThreatQ Plugin Validation]: {repr(ex)}")
            return ValidationResult(
                success=False,
                message="Error occurred while validation configuration. Check logs for more detail.",
            )

        return ValidationResult(
            success=True,
            message="Successfully Validated ThreatQ Plugin Configuration",
        )

    def get_ns_type(self, itype):
        """Get type enumeration from string."""
        if itype == "URL":
            return IndicatorType.URL
        elif itype == "MD5":
            return IndicatorType.MD5
        elif itype == "SHA-256":
            return IndicatorType.SHA256
        elif itype == "IP Address":
            return IndicatorType.URL
        elif itype == "FQDN":
            return IndicatorType.URL

    def get_actions(self):
        """Get available actions."""
        return []

    def validate_action(self, action: Action):
        """Validate ThreatQ configuration."""
        return ValidationResult(success=True, message="Validation successful.")

    def get_action_fields(self, action: Action):
        """Get fields required for an action."""
        return []
