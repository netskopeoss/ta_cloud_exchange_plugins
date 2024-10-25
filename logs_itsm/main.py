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

"""CE Logs ITSM plugin."""


from typing import List

from netskope.common.utils import DBConnector, Collections
from netskope.integrations.itsm.plugin_base import PluginBase, ValidationResult
from netskope.integrations.itsm.models import Alert


connector = DBConnector()


class CELogsPlugin(PluginBase):
    """CE Logs plugin implementation."""

    def _validate_params(self, configuration):
        params = configuration["params"]
        if len(params["logs_type"]) == 0:
            return ValidationResult(
                success=False,
                message="Log Type(s) should not be empty."
            )
        return ValidationResult(success=True, message="Validation successful.")

    def validate_step(self, name, configuration):
        """Validate a given step."""
        if name == "params":
            return self._validate_params(configuration)
        else:
            return ValidationResult(
                success=True,
                message="Validation successful."
            )

    def pull_alerts(self) -> List[Alert]:
        """Pull alerts from the Netskope platform."""
        alerts = []
        query = {}
        query["$and"] = [
            {"type": {"$in": self.configuration["params"]["logs_type"]}}
        ]
        if self.last_run_at is not None:
            query["$and"].append({"createdAt": {"$gte": self.last_run_at}})
        logs = connector.collection(Collections.LOGS).find(query)
        for log in logs:
            try:
                alerts.append(
                    Alert(
                        id=str(log["_id"]),
                        alertName="CE Log",
                        alertType="Log",
                        app="Cloud Exchange",
                        appCategory="CE",
                        type=log["type"],
                        user="",
                        timestamp=log["createdAt"],
                        rawData={"message": log["message"], "errorCode": log["errorCode"]},
                    )
                )
            except KeyError as ex:
                self.logger.error(
                    f"Error occurred while getting fields from "
                    f"alert with id={str(log.get('_id'))}. {repr(ex)}"
                )
        return alerts
