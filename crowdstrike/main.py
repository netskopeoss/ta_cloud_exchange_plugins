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

"""CrowdStrike Plugin implementation to push and pull the data from CrowdStrike Platform."""


import requests
import datetime
import re
from typing import Dict, List
from netskope.integrations.cte.plugin_base import (
    PluginBase,
    ValidationResult,
    PushResult,
)
from netskope.integrations.cte.models.business_rule import (
    ActionWithoutParams,
    Action,
)
from netskope.integrations.cte.models import (
    Indicator,
    IndicatorType,
    SeverityType,
)
from netskope.common.utils import add_user_agent

CROWDSTRIKE_TO_INTERNAL_TYPE = {
    "hash_md5": IndicatorType.MD5,
    "hash_sha256": IndicatorType.SHA256,
    "domain": IndicatorType.URL,
    "sha256": IndicatorType.SHA256,
    "md5": IndicatorType.MD5,
}

INTERNAL_TYPES_TO_CROWDSTRIKE = {
    IndicatorType.MD5: "md5",
    IndicatorType.SHA256: "sha256",
    IndicatorType.URL: "domain",
}


PAGE_SIZE = 1000


class CrowdStrikePlugin(PluginBase):
    """CrowdStrikePlugin class having concrete implementation for pulling and pushing threat information."""

    def handle_error(self, resp):
        """Handle the different HTTP response code.

        Args:
            resp (requests.models.Response): Response object returned from API call.
        Returns:
            dict: Returns the dictionary of response JSON when the response code is 200.
        Raises:
            HTTPError: When the response code is not 200.
        """
        if resp.status_code == 200 or resp.status_code == 201:
            try:
                return resp.json()
            except ValueError:
                self.notifier.error(
                    "Plugin: CrowdStrike,"
                    "Exception occurred while parsing JSON response."
                )
                self.logger.error(
                    "Plugin: CrowdStrike, "
                    "Exception occurred while parsing JSON response."
                )
        elif resp.status_code == 401:
            self.notifier.error(
                "Plugin: CrowdStrike, "
                "Received exit code 401, Authentication Error"
            )
            self.logger.error(
                "Plugin: CrowdStrike, "
                "Received exit code 401, Authentication Error"
            )
        elif resp.status_code == 403:
            self.notifier.error(
                "Plugin: CrowdStrike, "
                "Received exit code 403, Forbidden User"
            )
            self.logger.error(
                "Plugin: CrowdStrike, "
                "Received exit code 403, Forbidden User"
            )
        elif resp.status_code >= 400 and resp.status_code < 500:
            self.notifier.error(
                f"Plugin: CrowdStrike, "
                f"Received exit code {resp.status_code}, HTTP client Error"
            )
            self.logger.error(
                f"Plugin: CrowdStrike, "
                f"Received exit code {resp.status_code}, HTTP client Error"
            )
        elif resp.status_code >= 500 and resp.status_code < 600:
            self.notifier.error(
                f"Plugin: CrowdStrike, "
                f"Received exit code {resp.status_code}, HTTP server Error"
            )
            self.logger.error(
                f"Plugin: CrowdStrike, "
                f"Received exit code {resp.status_code}, HTTP server Error"
            )
        else:
            self.notifier.error(
                f"Plugin: CrowdStrike, "
                f"Received exit code {resp.status_code}, HTTP Error"
            )
            self.logger.error(
                f"Plugin: CrowdStrike, "
                f"Received exit code {resp.status_code}, HTTP Error"
            )
        resp.raise_for_status()

    def get_severity_from_int(self, severity):
        """Get severity from score.

        None (0)
        Low (10-39)
        Medium (40-69)
        High (70-89)
        Critical (90-100)
        """
        if type(severity) is not int or severity == 0:
            return SeverityType.UNKNOWN
        if 10 <= severity <= 39:
            return SeverityType.LOW
        if 40 <= severity <= 69:
            return SeverityType.MEDIUM
        if 70 <= severity <= 89:
            return SeverityType.HIGH
        if 90 <= severity <= 100:
            return SeverityType.CRITICAL
        return SeverityType.UNKNOWN

    def get_indicators_detailed(self, ioc_ids, headers):
        """Get detailed information by Detection IDs.

        Args:
            ioc_ids (dict): Python dict object having Indicators IDs received from Query endpoint.
            headers (dict): Header dict having Auth token as bearer header.
        Returns:
            List[cte.models.Indicators]: List of indicator objects received from the CrowdStrike platform.
        """
        # Indicator endpoint, this will return detailed information about Indicator.
        indicator_endpoint = f"{self.configuration['base_url']}/detects/entities/summaries/GET/v1"
        indicator_list = []
        json_payload = {}
        skip_count = 0
        for ioc_chunks in self.divide_in_chunks(ioc_ids, 1000):
            json_payload["ids"] = list(ioc_chunks)
            headers = self.reload_auth_token(headers)
            ioc_resp = requests.post(
                indicator_endpoint,
                headers=add_user_agent(headers),
                json=json_payload,
                verify=self.ssl_validation,
                proxies=self.proxy,
                timeout=60,
            )
            resp_json = self.handle_error(ioc_resp)
            if resp_json.get("errors"):
                err_msg = resp_json.get("errors")[0].get("message")
                self.notifier.error(
                    f"Plugin: CrowdStrike Unable to Fetch Indicator Details, "
                    f"Error: {err_msg}"
                )
                self.logger.error(
                    f"Plugin: CrowdStrike Unable to Fetch Indicator Details, "
                    f"Error: {err_msg}"
                )
            indicators_json_list = resp_json.get("resources", [])

            for indicator_json in indicators_json_list:
                behaviors = indicator_json.get("behaviors", [])
                if behaviors:
                    for behavior_info in behaviors:
                        if (
                            len(behavior_info.get("ioc_value", "")) > 0
                            and len(behavior_info.get("ioc_type", "")) > 0
                            and behavior_info.get("ioc_type")
                            in CROWDSTRIKE_TO_INTERNAL_TYPE
                        ):
                            indicator_list.append(
                                Indicator(
                                    value=behavior_info.get("ioc_value"),
                                    type=CROWDSTRIKE_TO_INTERNAL_TYPE.get(
                                        behavior_info.get("ioc_type")
                                    ),
                                    comments=behavior_info.get(
                                        "ioc_description", ""
                                    ),
                                    firstSeen=datetime.datetime.strptime(
                                        behavior_info.get("timestamp"),
                                        "%Y-%m-%dT%H:%M:%SZ",
                                    ),
                                    lastSeen=datetime.datetime.strptime(
                                        behavior_info.get("timestamp"),
                                        "%Y-%m-%dT%H:%M:%SZ",
                                    ),
                                    severity=self.get_severity_from_int(
                                        behavior_info.get("severity", 0)
                                    ),
                                )
                            )
                        else:
                            skip_count += 1
        if skip_count > 0:
            self.logger.warn(
                f"Plugin CrowdStrike: Skipping {skip_count} record(s) as IOC value and/or IOC type not compatible."
            )
        return indicator_list

    def get_ioc_ids(self, threat_type, headers):
        """Get the all the IOC ID list from the Indicator Query Endpoint.

        Args:
            threat_type (string): Type of threat data to pull.
            headers (dict): Header dict object having OAUTH2 access token.
        Returns:
            dict: JSON response dict received from query Indicator endpoint.
        """
        # Query endpoint, this will return all the indicator IDs.
        query_endpoint = (
            f"{self.configuration['base_url']}/iocs/combined/indicator/v1"
        )
        query_params = {}
        if threat_type == "Both":
            query_params["types"] = ["md5", "sha256", "domain"]
        elif threat_type == "Malware":
            query_params["types"] = ["md5", "sha256"]
        elif threat_type == "URL":
            query_params["types"] = "domain"
        query_params["limit"] = 2000
        ioc_ids = []
        while True:
            headers = self.reload_auth_token(headers)
            all_ioc_resp = requests.get(
                query_endpoint,
                headers=add_user_agent(headers),
                params=query_params,
                verify=self.ssl_validation,
                proxies=self.proxy,
            )
            ioc_resp_json = self.handle_error(all_ioc_resp)
            errors = ioc_resp_json.get("errors")
            if errors:
                err_msg = errors[0].get("message", "")
                self.notifier.error(
                    "Plugin: CrowdStrike Unable to Fetch Indicators, "
                    f"Error: {err_msg}"
                )
                self.logger.error(
                    "Plugin: CrowdStrike Unable to Fetch Indicators, "
                    f"Error: {err_msg}"
                )
                raise requests.HTTPError(
                    f"Plugin: CrowdStrike Unable to Fetch Indicators, "
                    f"Error: {err_msg}"
                )
            meta = ioc_resp_json.get("meta")
            after = meta.get("pagination", {}).get("after")
            query_params["after"] = after
            total = meta.get("pagination", {}).get("total")
            resources = ioc_resp_json.get("resources", [])
            for resource in resources:
                ioc_ids.append(
                    f"{resource.get('type', '')}"
                    ":"
                    f"{resource.get('value', '')}"
                )
            total_received_iocs = len(ioc_ids)
            if total_received_iocs == total:
                break
        return ioc_ids

    def get_detection_ids(self, threat_type, headers):
        """Get the all the Detection ID list from the Detection Endpoint.

        Args:
            threat_type (string): Type of threat data to pull.
            headers (dict): Header dict object having OAUTH2 access token.
        Returns:
            dict: JSON response dict received from Detection endpoint.
        """
        # Query endpoint, this will return all the indicator IDs.
        query_endpoint = (
            f"{self.configuration['base_url']}/detects/queries/detects/v1"
        )
        if self.last_run_at:
            last_run_time = self.last_run_at
        else:
            last_run_time = datetime.datetime.now() - datetime.timedelta(
                days=self.configuration["days"]
            )
        last_run_time = last_run_time.strftime("%Y-%m-%dT%H:%M:%SZ")
        query_params = {}
        ioc_types = []
        if threat_type == "Both":
            ioc_types = ["hash_md5", "md5", "hash_sha256", "sha256", "domain"]
        elif threat_type == "Malware":
            ioc_types = [
                "hash_md5",
                "md5",
                "hash_sha256",
                "sha256",
            ]
        elif threat_type == "URL":
            ioc_types = ["domain"]
        ioc_ids = []
        for ioc_type in ioc_types:
            offset = 0
            while True:
                filter_query = (
                    f"last_behavior:>'{last_run_time}'"
                    f"+behaviors.ioc_type:'{ioc_type}'"
                )
                query_params["limit"] = PAGE_SIZE
                query_params["filter"] = filter_query
                query_params["offset"] = offset
                headers = self.reload_auth_token(headers)
                all_ioc_resp = requests.get(
                    query_endpoint,
                    headers=add_user_agent(headers),
                    params=query_params,
                    verify=self.ssl_validation,
                    proxies=self.proxy,
                    timeout=60,
                )
                ioc_resp_json = self.handle_error(all_ioc_resp)
                errors = ioc_resp_json.get("errors")
                if errors:
                    err_msg = errors[0].get("message", "")
                    self.notifier.error(
                        "Plugin: CrowdStrike Unable to Fetch Indicators, "
                        f"Error: {err_msg}"
                    )
                    self.logger.error(
                        "Plugin: CrowdStrike Unable to Fetch Indicators, "
                        f"Error: {err_msg}"
                    )
                    raise requests.HTTPError(
                        f"Plugin: CrowdStrike Unable to Fetch Indicators, "
                        f"Error: {err_msg}"
                    )
                resources = ioc_resp_json.get("resources", [])
                offset += PAGE_SIZE
                ioc_ids.extend(resources)
                if len(resources) < PAGE_SIZE:
                    break
        return ioc_ids

    def pull(self):
        """Pull the Threat information from CrowdStrike platform.

        Returns:
            List[cte.models.Indicators]: List of indicator objects received from the CrowdStrike platform.
        """
        # Let's trip the spaces from the OAUTH2 secrets.
        self.configuration["client_id"] = self.configuration[
            "client_id"
        ].replace(" ", "")
        self.configuration["client_secret"] = self.configuration[
            "client_secret"
        ].replace(" ", "")
        config = self.configuration
        if config["is_pull_required"] == "Yes":
            self.logger.info("Plugin: CrowdStrike Polling is enabled.")
            threat_type = config["threat_data_type"]
            try:
                auth_json = self.get_auth_json(
                    self.configuration.get("client_id"),
                    self.configuration.get("client_secret"),
                    self.configuration.get("base_url"),
                )
                auth_token = auth_json.get("access_token")
                headers = {"Authorization": f"Bearer {auth_token}"}
                ioc_ids = self.get_detection_ids(threat_type, headers)
                return self.get_indicators_detailed(ioc_ids, headers)

            except requests.exceptions.ProxyError:
                self.notifier.error(
                    "Plugin: CrowdStrike Invalid proxy configuration."
                )
                self.logger.error(
                    "Plugin: CrowdStrike Invalid proxy configuration."
                )
                raise requests.HTTPError(
                    "Plugin: CrowdStrike Invalid proxy configuration."
                )
            except requests.exceptions.ConnectionError:
                self.notifier.error(
                    "Plugin: CrowdStrike Unable to establish connection with CrowdStrike platform. "
                    "Proxy server or CrowdStrike API is not reachable."
                )
                self.logger.error(
                    "Plugin: CrowdStrike Unable to establish connection with CrowdStrike platform. "
                    "Proxy server or CrowdStrike API is not reachable."
                )
                raise requests.HTTPError(
                    "Plugin: CrowdStrike Unable to establish connection with CrowdStrike platform. "
                    "Proxy server or CrowdStrike API is not reachable."
                )
            except requests.exceptions.RequestException as e:
                self.logger.error(
                    "Plugin: CrowdStrike "
                    "Exception occurred while making an API call to CrowdStrike platform"
                )
                raise e
        else:
            self.logger.info(
                "Plugin: CrowdStrike Polling is disabled, skipping."
            )
            return []

    def push(self, indicators: List[Indicator], action_dict: Dict):
        """Push the Indicator list to CrowdStrike.

        Args:
            indicators (List[cte.models.Indicators]): List of Indicator objects to be pushed.
        Returns:
            cte.plugin_base.PushResult: PushResult object with success flag and Push result message.
        """
        self.logger.info("Plugin: CrowdStrike Executing push method")
        action_dict = action_dict.get("parameters")
        # Let's trip the spaces from the OAUTH2 secrets.
        self.configuration["client_id"] = self.configuration[
            "client_id"
        ].replace(" ", "")
        self.configuration["client_secret"] = self.configuration[
            "client_secret"
        ].replace(" ", "")
        try:
            auth_json = self.get_auth_json(
                self.configuration.get("client_id"),
                self.configuration.get("client_secret"),
                self.configuration.get("base_url"),
            )
            auth_token = auth_json.get("access_token")
            headers = {"Authorization": f"Bearer {auth_token}"}
            ioc_ids = self.get_ioc_ids("Both", headers)
            payload_list = self.prepare_payload(
                ioc_ids, indicators, action_dict
            )
            for chunked_list in self.divide_in_chunks(
                payload_list, self.configuration["batch_size"]
            ):
                headers = self.reload_auth_token(headers)
                self.push_indicators_to_crowdstrike(headers, chunked_list)
            self.logger.info(
                "Plugin: CrowdStrike "
                f"Successfully Pushed {len(payload_list)} Indicators to CrowdStrike"
            )
            return PushResult(
                success=True,
                message=f"Successfully Pushed {len(payload_list)} Indicators to CrowdStrike",
            )
        except requests.exceptions.ProxyError:
            self.notifier.error(
                "Plugin: CrowdStrike Invalid proxy configuration."
            )
            self.logger.error(
                "Plugin: CrowdStrike Invalid proxy configuration."
            )
            return PushResult(
                success=False,
                message=(
                    "Failed to push indicators to CrowdStrike "
                    "Invalid proxy configuration"
                ),
            )
        except requests.exceptions.ConnectionError:
            self.notifier.error(
                "Plugin: CrowdStrike Unable to establish connection with CrowdStrike platform. "
                "Proxy server or CrowdStrike API is not reachable."
            )
            self.logger.error(
                "Plugin: CrowdStrike Unable to establish connection with CrowdStrike platform. "
                "Proxy server or CrowdStrike API is not reachable."
            )
            return PushResult(
                success=False,
                message=(
                    "Failed to push indicators to CrowdStrike "
                    "Unable to establish connection with CrowdStrike platform."
                ),
            )
        except requests.exceptions.RequestException as e:
            self.logger.error(
                "Plugin: CrowdStrike "
                "Exception occurred while making an API call to CrowdStrike platform"
            )
            return PushResult(
                success=False,
                message=(
                    "Exception occurred while making an API call to CrowdStrike platform "
                    f"Error :{repr(e)}"
                ),
            )

    def reload_auth_token(self, headers):
        """Reload the OAUTH2 token after Expiry."""
        if self.storage["token_expiry"] < datetime.datetime.now():
            self.logger.info(
                "Plugin: Crowdstrike OAUTH2 token expired generating new token"
            )
            auth_json = self.get_auth_json(
                self.configuration.get("client_id"),
                self.configuration.get("client_secret"),
                self.configuration.get("base_url"),
            )
            auth_token = auth_json.get("access_token")
            headers = {"Authorization": f"Bearer {auth_token}"}
            return headers
        else:
            return headers

    def divide_in_chunks(self, indicators, chunk_size):
        """Return Fixed size chunks from list."""
        for i in range(0, len(indicators), chunk_size):
            yield indicators[i : i + chunk_size]  # noqa

    def push_indicators_to_crowdstrike(self, headers, json_payload):
        """Push the indicator to the CrowdStrike endpoint.

        Args:
            headers (dict): Header dict object having OAUTH2 access token
            json_payload (List[dict]): List of python dict object of JSON response model as per CrowdStrike API.)
        Returns:
            dict: JSON response dict received after successfull Push.
        """
        push_endpoint = (
            f"{self.configuration['base_url']}/iocs/entities/indicators/v1"
        )
        json_body = {}
        json_body["indicators"] = json_payload
        try:
            post_resp = requests.post(
                push_endpoint,
                headers=add_user_agent(headers),
                json=json_body,
                verify=self.ssl_validation,
                proxies=self.proxy,
            )
        except requests.exceptions.RequestException as e:
            self.notifier.error(
                "Plugin: CrowdStrike "
                f"Exception occurred while making an API call to CrowdStrike platform {repr(e)}"
            )
            self.logger.error(
                "Plugin: CrowdStrike "
                f"Exception occurred while making an API call to CrowdStrike platform {repr(e)}"
            )
            return {}
        json_resp = post_resp.json()
        resources = json_resp.get("resources", [])
        if post_resp.status_code == 400 and resources:
            err_msg = resources[0].get("message", "")
            self.notifier.error(
                "Plugin: CrowdStrike Unable to Push Indicators, "
                f"Error: {err_msg}"
            )
            self.logger.error(
                "Plugin: CrowdStrike Unable to Push Indicators, "
                f"Error: {err_msg}"
            )
            raise requests.HTTPError(
                f"Plugin: CrowdStrike Unable to Push Indicators, "
                f"Error: {err_msg}"
            )
        json_resp = self.handle_error(post_resp)
        errors = json_resp.get("errors")
        if errors:
            err_msg = errors[0].get("message", "")
            self.notifier.error(
                "Plugin: CrowdStrike Unable to Push Indicators, "
                f"Error: {err_msg}"
            )
            self.logger.error(
                "Plugin: CrowdStrike Unable to Push Indicators, "
                f"Error: {err_msg}"
            )
            raise requests.HTTPError(
                f"Plugin: CrowdStrike Unable to Push Indicators, "
                f"Error: {err_msg}"
            )
        return json_resp

    def _extract_host(self, url):
        try:
            host_regex = r"^(?:[a-zA-Z]*:\/\/)?([\w\-\.]+)(?:\/)?"
            host = re.findall(host_regex, url).pop()
            if host:
                return host
            else:
                raise ValueError("Could not extract host name")
        except Exception:
            return url

    def validate_domain(self, value):
        """Validate domain name.

        Args:
            value (str): Domain name.

        Returns:
            bool: Whether the name is valid or not.
        """
        if re.match(
            r"^((?=[a-z0-9-]{1,63}\.)(xn--)?[a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,63}$",
            value,
        ):
            return True
        else:
            return False

    def prepare_payload(self, ioc_ids, indicators, action_dict):
        """Prepare the JSON payload for Push.

        Args:
            ioc_ids (List[str]):
            indicators (List[cte.models.Indicators]): List of Indicator objects to be pushed.
            action_dict (Dict) : Dictionary contains the action and plateforms for sharing.
        Returns:
            List[dict]: List of python dict object of JSON response model as per CrowdStrike API.
        """
        payload_list = []
        ioc = set()
        source = self.configuration.get("source", "")
        action = action_dict.get("action", "")
        platforms = action_dict.get("platforms", ["windows", "mac", "linux"])
        for indicator in indicators:
            if indicator.severity == SeverityType.UNKNOWN:
                indicator.severity = "informational"
            json_body = {
                "source": source,
                "action": action,
                "platforms": platforms,
                "applied_globally": True,
                "severity": indicator.severity,
            }
            if (
                f"{INTERNAL_TYPES_TO_CROWDSTRIKE[indicator.type]}:{indicator.value}"
                not in ioc_ids
            ):
                json_body["type"] = INTERNAL_TYPES_TO_CROWDSTRIKE[
                    indicator.type
                ]
                if indicator.type == IndicatorType.URL:
                    value = self._extract_host(indicator.value)
                    if (
                        f"{INTERNAL_TYPES_TO_CROWDSTRIKE[indicator.type]}:{value}"
                        in ioc_ids
                        or value in ioc
                        or not self.validate_domain(value)
                    ):
                        continue
                    else:
                        ioc.add(value)
                        json_body["value"] = value
                else:
                    json_body["value"] = indicator.value
                payload_list.append(json_body.copy())
        return payload_list

    def validate(self, data):
        """Validate the Plugin configuration parameters.

        Args:
            data (dict): Dict object having all the Plugin configuration parameters.
        Returns:
            cte.plugin_base.ValidateResult: ValidateResult object with success flag and message.
        """
        self.logger.info(
            "Plugin: CrowdStrike Executing validate method for CrowdStrike plugin"
        )
        if "base_url" not in data or data["base_url"] not in [
            "https://api.crowdstrike.com",
            "https://api.us-2.crowdstrike.com",
            "https://api.laggar.gcw.crowdstrike.com",
            "https://api.eu-1.crowdstrike.com",
        ]:
            self.logger.error(
                "Plugin: CrowdStrike Validation error occurred "
                "Error: Type of Pulling configured should be non-empty string."
            )
            return ValidationResult(
                success=False,
                message="Invalid value for 'Enable Polling' provided. Allowed values are 'Yes', or 'No'.",
            )

        if (
            "client_id" not in data
            or not data["client_id"]
            or type(data["client_id"]) != str
        ):
            self.logger.error(
                "Plugin: CrowdStrike Validation error occurred"
                "Error: Type of Client ID should be non-empty string."
            )
            return ValidationResult(
                success=False,
                message="Invalid Client ID provided.",
            )

        if (
            "client_secret" not in data
            or not data["client_secret"]
            or type(data["client_secret"]) != str
        ):
            self.logger.error(
                "Plugin: CrowdStrike Validation error occurred"
                "Error: Type of Client Secret should be non-empty string."
            )
            return ValidationResult(
                success=False,
                message="Invalid Client Secret provided.",
            )

        if "is_pull_required" not in data or data["is_pull_required"] not in [
            "Yes",
            "No",
        ]:
            self.logger.error(
                "Plugin: CrowdStrike Validation error occurred "
                "Error: Type of Pulling configured should be non-empty string."
            )
            return ValidationResult(
                success=False,
                message="Invalid value for 'Enable Polling' provided. Allowed values are 'Yes', or 'No'.",
            )

        if "threat_data_type" not in data or data["threat_data_type"] not in [
            "Both",
            "Malware",
            "URL",
        ]:
            self.logger.error(
                "Plugin: CrowdStrike Invalid value for 'Type of Threat data to pull' provided. "
                "Allowed values are Both, Malware or URL."
            )
            return ValidationResult(
                success=False,
                message=(
                    "Invalid value for 'Type of Threat data to pull' provided. "
                    "Allowed values are 'Both', 'Malware' or 'URL'."
                ),
            )
        if (
            "days" not in data
            or not data["days"]
            or type(data["days"]) != int
            or data["days"] < 0
        ):
            self.logger.error(
                "Plugin: CrowdStrike Validation error occurred "
                "Error: Type of Initial Range (in days) should be non-zero positive integer."
            )
            return ValidationResult(
                success=False,
                message="Error: Type of Initial Range (in days) should be non-zero positive integer.",
            )
        if (
            "batch_size" not in data
            or not data["batch_size"]
            or type(data["batch_size"]) != int
            or data["batch_size"] < 0
        ):
            self.logger.error(
                "Plugin: CrowdStrike Validation error occurred "
                "Error: Type of Indicate Batch Size Range should be non-zero positive integer."
            )
            return ValidationResult(
                success=False,
                message="Error: Type of Indicate Batch Size Range should be non-zero positive integer.",
            )
        if "source" in data and (
            type(data["source"]) != str or len(data["source"]) > 200
        ):
            self.logger.error(
                "Plugin: CrowdStrike Validation error occurred "
                "Error: Invalid Type of IOC source provided."
            )
            return ValidationResult(
                success=False,
                message=(
                    "Invalid Type of IOC source provided. "
                    "Size of source string should be less than 200 Characters"
                ),
            )
        return self.validate_auth_params(
            data["client_id"], data["client_secret"], data["base_url"]
        )

    def validate_auth_params(self, client_id, client_secret, base_url):
        """Validate the authentication params with CrowdStrike platform.

        Args:
            client_id (str): Client ID required to generate OAUTH2 token.
            client_secret (str): Client Secret required to generate OAUTH2 token.
            base_url (str): Base url of crowd strike
        Returns:
            ValidationResult: ValidationResult object having validation results after making
            an API call.
        """
        try:
            self.get_auth_json(client_id, client_secret, base_url)
            return ValidationResult(
                success=True,
                message="Validation successfull for CrowdStrike Plugin",
            )
        except requests.exceptions.ProxyError:
            self.logger.error(
                "Plugin: CrowdStrike Validation Error, "
                "Invalid proxy configuration."
            )
            return ValidationResult(
                success=False,
                message="Validation Error, Invalid proxy configuration.",
            )
        except requests.exceptions.ConnectionError:
            self.logger.error(
                "Plugin: CrowdStrike Validation Error, "
                "Unable to establish connection with CrowdStrike Platform API"
            )
            return ValidationResult(
                success=False,
                message="Validation Error, Unable to establish connection with CrowdStrike Platform API",
            )
        except requests.HTTPError as err:
            self.logger.error(
                f"Plugin: CrowdStrike Validation Error, "
                f"Error in validating Credentials {repr(err)}"
            )
            return ValidationResult(
                success=False,
                message=f"Validation Error, Error in validating Credentials {repr(err)}",
            )

    def get_auth_json(self, client_id, client_secret, base_url):
        """Get the OAUTH2 Json object with access token from CrowdStrike platform.

        Args:
            client_id (str): Client ID required to generate OAUTH2 token.
            client_secret (str): Client Secret required to generate OAUTH2 token.
            base_url (str): Base URL of crowdstrike.
        Returns:
            json: JSON response data in case of Success.
        """
        client_id = client_id.replace(" ", "")
        client_secret = client_secret.replace(" ", "")
        auth_endpoint = f"{base_url}/oauth2/token"

        auth_params = {
            "grant_type": "client_credentials",
            "client_id": client_id,
            "client_secret": client_secret,
        }
        resp = requests.post(
            auth_endpoint,
            data=auth_params,
            verify=self.ssl_validation,
            proxies=self.proxy,
            headers=add_user_agent(),
            timeout=60,
        )
        auth_json = self.handle_error(resp)
        auth_errors = auth_json.get("errors")
        if auth_errors:
            err_msg = auth_errors[0].get("message", "")
            self.notifier.error(
                "Plugin: CrowdStrike Unable to generate Auth token. "
                f"Error: {err_msg}"
            )
            self.logger.error(
                "Plugin: CrowdStrike Unable to generate Auth token. "
                f"Error: {err_msg}"
            )
            raise requests.HTTPError(
                f"Plugin: CrowdStrike Unable to generate Auth token. "
                f"Error: {err_msg}"
            )
        if self.storage is not None:
            self.storage[
                "token_expiry"
            ] = datetime.datetime.now() + datetime.timedelta(
                seconds=int(auth_json.get("expires_in", 1799))
            )
        return auth_json

    def get_actions(self):
        """Get available actions."""
        return [
            ActionWithoutParams(label="Perform Action", value="action"),
        ]

    def validate_action(self, action: Action):
        """Validate crowdstrike configuration."""
        if action.value not in ["action"]:
            return ValidationResult(
                success=False, message="Unsupported action provided."
            )

        if action.parameters.get("action") not in [
            "no_action",
            "prevent",
            "detect",
            "prevent_no_ui",
            "allow",
        ]:
            return ValidationResult(
                success=False, message="Unsupported action provided."
            )

        if action.parameters.get("platforms", []) is None:
            return ValidationResult(
                success=False, message="platforms should not be empty."
            )

        return ValidationResult(success=True, message="Validation successful.")

    def get_action_fields(self, action: Action):
        """Get fields required for an action."""
        if action.value == "action":
            return [
                {
                    "label": "Action",
                    "key": "action",
                    "type": "choice",
                    "choices": [
                        {"key": "No Action", "value": "no_action"},
                        {"key": "Allow", "value": "allow"},
                        {"key": "Prevent No UI", "value": "prevent_no_ui"},
                        {"key": "Prevent", "value": "prevent"},
                        {"key": "Detect", "value": "detect"},
                    ],
                    "default": "no_action",
                    "mandatory": True,
                    "description": "Action to take when a host observes the custom IOC.",
                },
                {
                    "label": "Platforms",
                    "key": "platforms",
                    "type": "multichoice",
                    "choices": [
                        {"key": "windows", "value": "windows"},
                        {"key": "mac", "value": "mac"},
                        {"key": "linux", "value": "linux"},
                    ],
                    "default": ["windows", "mac", "linux"],
                    "mandatory": True,
                    "description": "The platforms that the indicator applies to. \
                    You can choose multiple platform names.",
                },
            ]
