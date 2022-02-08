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

"""ServiceNow plugin implementation.

This is a ServiceNow implementation of base PluginBase class.
Which explains the concrete implemetation of the base class.
"""


from typing import Dict, List
from datetime import datetime, timedelta, timezone
import requests

from netskope.common.utils import add_user_agent

from netskope.integrations.cte.plugin_base import (
    PluginBase,
    ValidationResult,
    PushResult,
)
from netskope.integrations.cte.models import Indicator, IndicatorType
from netskope.integrations.cte.models.business_rule import (
    Action,
    ActionWithoutParams,
)

# SerivceNow types
SERVICENOW_TYPE_MAPPINGS = {
    IndicatorType.MD5: "MD5",
    IndicatorType.SHA256: "SHA256",
    IndicatorType.URL: "URL",
}
MAX_PER_PAGE = 1000
SERVICENOW_TO_INTERNAL_TYPE = {
    "MD5": IndicatorType.MD5,
    "SHA256": IndicatorType.SHA256,
    "URL": IndicatorType.URL,
}


class ServiceNowPlugin(PluginBase):
    """Plugin implementation for ServiceNow."""

    def pull(self):
        """Pull the Observables based on timestamp.

        For initial data fetch, pull last N days of data.

        Returns:
            List[cte.models.Indicators]: List of indicator objects received from the ServiceNow Observables table.
        """
        config = self.configuration
        logger = self.logger
        logger.info(
            "ServiceNow Plugin: Starting to fetch data from ServiceNow Threat Intelligence plugin's Observables table."
        )
        indicator_list = self.fetch_observables(config, logger)
        logger.info("ServiceNow Plugin: Finished fetching data.")
        return indicator_list

    def datetime_to_str(self, date: datetime) -> str:
        """Get string representation of datetime.

        Args:
            date (datetime): The datetime object.

        Returns:
            str: String representation.
        """
        return date.strftime("%Y-%m-%d %H:%M:%S")

    def str_to_datetime(self, string: str) -> datetime:
        """Convert string to datetime object.

        Args:
            string (str): String to be converted.

        Returns:
            datetime: The converted datetime object.
        """
        return datetime.strptime(string, "%Y-%m-%d %H:%M:%S").replace(
            tzinfo=timezone.utc
        )

    def fetch_observables(self, config, logger):
        """Actual Pull implementation.

        This method pulls the data from 3rd party APIs, proccesses it and returns the list of
        Indicator objects on success. It will raise an error/Exception on failure.
        Args:
            config: Plugin configuration dict object.
            logger: Logger object to persist logs to mongodb.
        Returns:
            List[cte.models.Indicators]: List of indicator objects received from the 3rd party Threat Intel Systems.
        """
        start_time = self.last_run_at  # datetime.datetime object.
        end_time = datetime.now()
        if not start_time:
            logger.info(
                f"ServiceNow Plugin: This is initial data fetch since "
                f"checkpoint is empty. Querying observables for last {config['days']} days."
            )
            start_time = datetime.now() - timedelta(days=int(config["days"]))
        indicators = []
        # Make API Call
        params = {
            "sysparm_query": (
                f"sys_updated_on>{self.datetime_to_str(start_time)}^sys_updated_on<{self.datetime_to_str(end_time)}^"
                f"type.value=MD5^ORtype.value=SHA256^ORtype.value=URL"
            ),
            "sysparm_limit": MAX_PER_PAGE,
            "sysparm_offset": 0,
            "sysparm_fields": "value,type.value,sys_id,sys_created_on,sys_updated_on,notes",
        }
        while True:
            response = requests.get(
                f"{config['url'].strip('/')}/api/now/table/sn_ti_observable",
                params=params,
                auth=(config["username"], config["password"]),
                verify=self.ssl_validation,
                proxies=self.proxy,
                headers=add_user_agent(),
            )
            response.raise_for_status()
            for i in response.json()["result"]:
                indicators.append(
                    Indicator(
                        value=i["value"],
                        type=SERVICENOW_TO_INTERNAL_TYPE[i["type.value"]],
                        comments=i["notes"],
                        firstSeen=self.str_to_datetime(i["sys_created_on"]),
                        lastSeen=self.str_to_datetime(i["sys_updated_on"]),
                    )
                )
            params["sysparm_offset"] += MAX_PER_PAGE
            if len(indicators) >= int(response.headers["X-Total-Count"]):
                break
        return indicators

    def push(self, indicators: List[Indicator], action_dict: Dict):
        """Push the Indicator list to the 3rd party Threat Intel systems.

        Implement the logic of spliting the indicators list according to their type and push the data
        to the 3rd party APIs. This method will be invoked while sharing the Threat information with 3rd party.
        Args:
            indicators (List[cte.models.Indicators]): List of Indicator objects to be pushed.
        Returns:
            cte.plugin_base.PushResult: PushResult object with success flag and Push result message.
        """
        # Load all the configured plugin parameters as python dict object.
        # Use the key name provided in the manifest.json file for the configuration parameters to
        # get the value of that perticular parameter.
        config = self.configuration
        # Get the logger object for logging purpose. This logger object logs all the logs to mongodb
        # under the cte database logs collection. Log timestamp is automatically recorded by the logger library.
        # Supported logging levels are info, warn and error.
        logger = self.logger
        logger.info(
            "ServiceNow Plugin: Starting Pushing data for ServiceNow plugin."
        )
        push_result = self.create_observables(config, logger, indicators)
        logger.info(
            "ServiceNow Plugin: Finished Pushing data for ServiceNow plugin."
        )
        return push_result

    def create_observables(self, config, logger, indicators):
        """Actual Pull implementation.

        This method pulls the data from 3rd party APIs, proccesses it and returns the list of
        Indicator objects on success. It will raise an error/Exception on failure.
        Args:
            config: Plugin configuration dict object.
            logger: Logger object to persist logs to mongodb.
            indicators: List of cte.models.Indicator objects.
        Returns:
            cte.plugin_base.PushResult: PushResult object with success flag and message.
        """
        for indicator in indicators:
            try:
                url = (
                    config["url"].strip("/")
                    + "/api/now/table/sn_ti_observable"
                )
                query_params = {"sysparm_query": f"value={indicator.value}"}
                auth = (config["username"], config["password"])

                query_indicator_res = requests.get(
                    url=url,
                    auth=auth,
                    params=query_params,
                    timeout=60,
                    verify=self.ssl_validation,
                    proxies=self.proxy,
                    headers=add_user_agent(),
                )
                query_indicator_res.raise_for_status()
                if query_indicator_res.json().get("result", []):
                    self.logger.info(
                        "ServiceNow Plugin: Indicator {} already exists".format(
                            indicator.value
                        )
                    )
                    continue

                # Make API Call
                response = requests.post(
                    url=url,
                    auth=auth,
                    timeout=60,
                    json={"value": indicator.value},
                    verify=self.ssl_validation,
                    proxies=self.proxy,
                    headers=add_user_agent(),
                )
                response.raise_for_status()
            except Exception as e:
                self.logger.error(
                    "ServiceNow Plugin: Error while submitting indicator {}. Error {}".format(
                        indicator.value, str(e)
                    )
                )

        return PushResult(
            success=True, message="Successfully pushed data to 3rd party."
        )

    def validate(self, data):
        """Validate the Plugin configuration parameters.

        Validation for all the parameters mentioned in the manifest.json for the existence and
        data type. Method returns the cte.plugin_base.ValidationResult object with success = True in the case
        of successful validation and success = False and a error message in the case of failure.
        Args:
            data (dict): Dict object having all the Plugin configuration parameters.
        Returns:
            cte.plugin_base.ValidateResult: ValidateResult object with success flag and message.
        """
        self.logger.info(
            "ServiceNow Plugin: Executing validate method for ServiceNow plugin"
        )
        if "url" not in data or not data["url"] or type(data["url"]) != str:
            self.logger.error(
                "ServiceNow Plugin: Validation error occured Error: Invalid ServiceNow instance URL provided."
            )
            return ValidationResult(
                success=False,
                message="Invalid ServiceNow Instance URL provided.",
            )

        if (
            "username" not in data
            or not data["username"]
            or type(data["username"]) != str
        ):
            self.logger.error(
                "ServiceNow Plugin: Validation error occured Error: Invalid Username provided."
            )
            return ValidationResult(
                success=False,
                message="Invalid Username provided.",
            )

        if (
            "password" not in data
            or not data["password"]
            or type(data["password"]) != str
        ):
            self.logger.error(
                "ServiceNow Plugin: Validation error occured Error: Invalid Password provided."
            )
            return ValidationResult(
                success=False,
                message="Invalid Password provided.",
            )

        try:
            if (
                "days" not in data
                or not data["days"]
                or int(data["days"]) <= 0
            ):
                self.logger.error(
                    "ServiceNow Plugin: Validation error occured Error: Invalid 'Initial Range' provided."
                )
                return ValidationResult(
                    success=False,
                    message="Invalid 'Initial Range' provided.",
                )
        except ValueError:
            return ValidationResult(
                success=False,
                message="Invalid 'Initial Range' provided.",
            )

        try:
            response = requests.get(
                f"{data['url'].strip('/')}/api/now/table/sn_ti_observable",
                params={"sysparm_limit": 1},
                auth=(data["username"], data["password"]),
                verify=self.ssl_validation,
                proxies=self.proxy,
                headers=add_user_agent(),
            )
            if response.status_code in [401, 403]:
                self.logger.error(
                    f"ServiceNow Plugin: HTTP request returned with status code {response.status_code}"
                )
                return ValidationResult(
                    success=False,
                    message="Invalid username/password provided.",
                )
            elif response.status_code != 200:
                self.logger.error(
                    f"ServiceNow Plugin: HTTP request returned with status code {response.status_code}"
                )
                return ValidationResult(
                    success=False,
                    message="Could not validate username/password.",
                )
        except Exception as e:
            self.logger.error(
                "ServiceNow Plugin: Error while fetching data from ServiceNow"
                + repr(e)
            )
            return ValidationResult(
                success=False,
                message="Validation failed. Check the input configuration.",
            )

        return ValidationResult(
            success=True,
            message="Validation successfull for ServiceNow plugin",
        )

    def get_actions(self):
        """Get available actions."""
        return [
            ActionWithoutParams(label="Share Indicators", value="share"),
        ]

    def validate_action(self, action: Action):
        """Validate ServiceNow configuration."""
        if action.value not in ["share"]:
            return ValidationResult(
                success=False, message="Unsupported action provided."
            )

        return ValidationResult(success=True, message="Validation successful.")

    def get_action_fields(self, action: Action):
        """Get fields required for an action."""
        return []
