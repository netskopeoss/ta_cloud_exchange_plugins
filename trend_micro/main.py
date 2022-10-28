"""Trend Micro Vision One Plugin to push and pull the data from Trend Micro Vision One Platform."""

from time import sleep
from typing import List
from urllib.error import HTTPError
import requests
import datetime
from datetime import timedelta
import re
import ipaddress

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

USER_AGENT = "Netskope-TMV1-1.0.1"

TRENDMICRO_TO_INTERNAL_TYPE = {
    "url": IndicatorType.URL,
    "domain": IndicatorType.URL,
    "ip": IndicatorType.URL,
    "fileSha256": IndicatorType.SHA256,
}

INTERNAL_TYPES_TO_TRENDMICRO = {
    IndicatorType.SHA256: "fileSha256",
    IndicatorType.URL: "domain",
}

TRENDMICRO_TO_INTERNAL_SEVERITY = {
    "high": SeverityType.HIGH,
    "medium": SeverityType.MEDIUM,
    "low": SeverityType.LOW,
}

INTERNAL_SEVERITY_TO_TRENDMICRO = {
    SeverityType.UNKNOWN: "",
    SeverityType.LOW: "low",
    SeverityType.MEDIUM: "medium",
    SeverityType.HIGH: "high",
    SeverityType.CRITICAL: "high",
}


def check_url_domain_ip(type):
    """Categorize UTL as Domain, IP or URL."""
    regex_domain = (
        "^((?!-)[A-Za-z0-9-]" + "{1,63}(?<!-)\\.)" + "+[A-Za-z]{2,6}"
    )
    try:
        ipaddress.ip_address(type)
        return "ip"
    except Exception:
        if re.search(regex_domain, type):
            return "domain"
        else:
            return "url"


class TrendMicroPlugin(PluginBase):
    """Trend Micro Vision One Plugin class for pulling and pushing threat indicators."""

    def handle_error(self, resp):
        """Handle the different HTTP response code.

        Args:
            resp (requests.models.Response):
            Response object returned from API call.
        Returns:
            dict: Returns the dictionary of response JSON
            when the response code is 200.
        Raises:
            HTTPError: When the response code is not 200.
        """
        if resp.status_code == 200:
            try:
                return resp.json()
            except ValueError:
                self.notifier.error(
                    "Plugin: Trend Micro Vision One,"
                    "Exception occurred while parsing JSON response."
                )
                self.logger.error(
                    "Plugin: Trend Micro Vision One, "
                    "Exception occurred while parsing JSON response."
                )
        elif resp.status_code == 400:
            err_resp = resp.json()
            err_msg = err_resp.get("message")
            self.notifier.error(
                "Plugin: Trend Micro Vision One, "
                "Received exit code 400, Bad Request. "
                f"Error: {err_msg}"
            )
            self.logger.error(
                "Plugin: Trend Micro Vision One, "
                "Received exit code 400, Bad Request. "
                f"Error: {err_msg}"
            )
        elif resp.status_code == 401:
            err_resp = resp.json()
            err_msg = err_resp.get("message")
            self.notifier.error(
                "Plugin: Trend Micro Vision One, "
                "Received exit code 401, Unauthorized. "
                f"Error: {err_msg}"
            )
            self.logger.error(
                "Plugin: Trend Micro Vision One, "
                "Received exit code 401, Unauthorized. "
                f"Error: {err_msg}"
            )
        elif resp.status_code == 403:
            err_resp = resp.json()
            err_msg = err_resp.get("message")
            self.notifier.error(
                "Plugin: Trend Micro Vision One, "
                "Received exit code 403, Access Denied. "
                f"Error: {err_msg}"
            )
            self.logger.error(
                "Plugin: Trend Micro Vision One, "
                "Received exit code 403, Access Denied. "
                f"Error: {err_msg}"
            )
        elif resp.status_code == 429:
            err_resp = resp.json()
            err_msg = err_resp.get("message")
            self.notifier.error(
                "Plugin: Trend Micro Vision One, "
                "Received exit code 429, Too Many Requests. "
                f"Error: {err_msg}"
            )
            self.logger.error(
                "Plugin: Trend Micro Vision One, "
                "Received exit code 429, Too Many Requests. "
                f"Error: {err_msg}"
            )
        elif resp.status_code == 500:
            err_resp = resp.json()
            err_msg = err_resp.get("message")
            self.notifier.error(
                "Plugin: Trend Micro Vision One, "
                "Received exit code 500, Internal server Error. "
                f"Error: {err_msg}"
            )
            self.logger.error(
                "Plugin: Trend Micro Vision One, "
                "Received exit code 500, Internal server Error. "
                f"Error: {err_msg}"
            )
        elif resp.status_code == 413:
            self.notifier.error(
                "Plugin: Trend Micro Vision One, "
                "Received exit code 413, Payload Too Large. "
            )
            self.notifier.error(
                "Plugin: Trend Micro Vision One, "
                "Received exit code 413, Payload Too Large. "
            )
        else:
            self.notifier.error(
                "Plugin: Trend Micro Vision One, "
                f"Received exit code {resp.status_code}, HTTP Error"
            )
            self.logger.error(
                "Plugin: Trend Micro Vision One, "
                f"Received exit code {resp.status_code}, HTTP Error"
            )
        resp.raise_for_status()

    def get_indicators(self, headers):
        """Get indicators from Trend Micro Vision One.

        Args:
            headers (dict): Header dict object having authentication token.
        Returns:
            List[dict]: List of python dict object of JSON response model
            as per Trend Micro Vision One API.
        """
        skip_count = 0
        indicator_list = []
        query_endpoint = (
            f"{self.configuration['base_url']}/v3.0"
            "/threatintel/suspiciousObjects"
        )
        if not self.last_run_at:
            start_time = datetime.datetime.now() - timedelta(
                days=int(self.configuration["initial_range"])
            )
        else:
            start_time = self.last_run_at

        query_params = {
            "startDateTime": start_time,
            "endDateTime": datetime.datetime.now(),
            "top": 200,
        }

        while True:
            retry_time = 15
            for _ in range(3):
                ioc_response = requests.get(
                    query_endpoint,
                    params=query_params,
                    headers=headers,
                    proxies=self.proxy,
                )
                if ioc_response.status_code == 429:
                    retry_after = ioc_response.headers.get("Retry-After", 60)
                    self.logger.info(
                        "Plugin: Trend Micro Vision One, 429 Client Error - "
                        "Too Many Requests, Retrying after "
                        f"{retry_after} seconds"
                    )
                    sleep(int(retry_after))
                    continue
                if ioc_response.status_code == 500:
                    self.logger.info(
                        "Plugin: Trend Micro Vision One, 500 Internal Server Error - "
                        f"Retrying after {retry_time} seconds."
                    )
                    sleep(retry_time)
                    retry_time = retry_time * 2
                    continue
                else:
                    break
            resp_json = self.handle_error(ioc_response)
            if resp_json.get("errors"):
                err_msg = resp_json.get("errors")[0].get("message")
                message = (
                    f"Plugin: Trend Micro Vision One, "
                    f"Unable to Fetch Indicator Details, "
                    f"Error: {err_msg}"
                )
                self.notifier.error(message)
                self.logger.error(message)
                raise HTTPError(message)
            indicators_json_list = resp_json.get("items", [])
            for indicator in indicators_json_list:
                if (
                    len(indicator.get("type")) > 0
                    and str("(Created from Netskope CTE)")
                    not in indicator.get("description", "")
                    and indicator.get("type")
                    in ["domain", "fileSha256", "ip", "url"]
                ):
                    value = indicator.get("type")
                    indicator_list.append(
                        Indicator(
                            value=indicator.get(value),
                            type=TRENDMICRO_TO_INTERNAL_TYPE.get(
                                indicator.get("type")
                            ),
                            comments=indicator.get("description", ""),
                            lastSeen=datetime.datetime.strptime(
                                indicator.get("lastModifiedDateTime"),
                                "%Y-%m-%dT%H:%M:%SZ",
                            ),
                            severity=TRENDMICRO_TO_INTERNAL_SEVERITY.get(
                                indicator.get("riskLevel")
                            ),
                        )
                    )
                elif indicator.get("type") not in [
                    "domain",
                    "fileSha256",
                    "ip",
                    "url",
                ]:
                    skip_count += 1

            if "nextLink" not in resp_json or "nextLink" == "":
                break
            else:
                query_params.clear()
                query_endpoint = resp_json["nextLink"]
        if skip_count > 0:
            self.logger.warn(
                f"Plugin: Trend Micro Vision One: {skip_count} indicator(s) were "
                f"skipped due to unsupported indicator type."
            )

        return indicator_list

    def pull(self):
        """Pull the Threat information from Trend Micro Vision One platform.

        Returns : List[cte.models.Indicators] :
        List of indicator objects received from the Trend Micro Vision One platform.
        """
        if self.configuration["is_pull_required"] == "Yes":
            headers = {
                "Authorization": "Bearer "
                f"{self.configuration['token'].strip()}",
                "User-Agent": USER_AGENT,
            }
            try:
                return self.get_indicators(headers)
            except requests.exceptions.ProxyError:
                self.logger.error(
                    "Plugin: Trend Micro Vision One, Invalid proxy configuration."
                )
                raise requests.HTTPError(
                    "Plugin: Trend Micro Vision One, Invalid proxy configuration."
                )
            except requests.exceptions.ConnectionError:
                self.logger.error(
                    "Plugin: Trend Micro Vision One, Unable to establish "
                    "connection with Trend Micro Vision One platform. Proxy server or "
                    "Trend Micro Vision One API is not reachable."
                )
                raise requests.HTTPError(
                    "Plugin: Trend Micro Vision One, Unable to establish "
                    "connection with Trend Micro Vision One platform. Proxy server or "
                    "Trend Micro Vision One API is not reachable."
                )
            except requests.exceptions.RequestException as e:
                self.logger.error(
                    "Plugin: Trend Micro Vision One, "
                    "Exception occurred while making an API call to "
                    "Trend Micro Vision One platform"
                )
                raise e
        else:
            self.logger.info(
                "Trend Micro Vision One Plugin: Polling is disabled, skipping."
            )
            return []

    def push_indicators_to_trendmicro(self, json_payload, action_value):
        """Push Indicators to Trend Micro Vision One's selected Target List."""
        if action_value == "suspicious_object":
            push_endpoint = (
                f"{self.configuration['base_url']}/v3.0"
                "/threatintel/suspiciousObjects"
            )
        else:
            push_endpoint = (
                f"{self.configuration['base_url']}/v3.0"
                "/threatintel/suspiciousObjectExceptions"
            )
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.configuration['token']}",
            "User-Agent": USER_AGENT,
        }
        try:
            retry_time = 15
            for _ in range(3):
                response = requests.post(
                    push_endpoint,
                    headers=headers,
                    json=json_payload,
                    proxies=self.proxy,
                )
                if response.status_code == 429:
                    retry_after = response.headers.get("Retry-After", 60)
                    self.logger.info(
                        "Plugin: Trend Micro Vision One, 429 Client Error - "
                        "Too Many Requests, Retrying after "
                        f"{retry_after} seconds"
                    )
                    sleep(int(retry_after))
                    continue
                if response.status_code == 500:
                    self.logger.info(
                        "Plugin: Trend Micro Vision One, 500 Internal Server Error - "
                        f"Retrying after {retry_time} seconds."
                    )
                    sleep(retry_time)
                    retry_time = retry_time * 2
                    continue
                else:
                    break
            return response

        except requests.exceptions.RequestException as e:
            self.notifier.error(
                "Plugin: Trend Micro Vision One "
                "Exception occurred "
                f"while making an API call to Trend Micro Vision One platform {repr(e)}"
            )
            self.logger.error(
                "Plugin: Trend Micro Vision One "
                "Exception occurred "
                f"while making an API call to Trend Micro Vision One platform {repr(e)}"
            )
            return {}

    def push(self, indicators: List[Indicator], action_dict: Action):
        """Push indicators to Trend Micro Vision One."""
        action_value = action_dict.get("value")
        action_params = action_dict.get("parameters", {})
        invalid_indicator_count = 0
        shared_indicators = 0
        try:
            payload_list = self.prepare_payload(indicators, action_params)
            for chunked_list in self.divide_in_chunks(payload_list):
                response = self.push_indicators_to_trendmicro(
                    chunked_list, action_value
                )
                result = response.json()
                if (
                    response.status_code == 400
                    and "(Error code: 4000018)" in result.get("message")
                ):
                    self.logger.info(
                        f"Shared {shared_indicators} indicator(s) to "
                        "Trend Micro Vision One. Remaining indicators were not "
                        "shared because the number of objects exceeded "
                        "the maximum limit. Remove objects and try again."
                    )
                    return PushResult(
                        success=False,
                        message="Failed to push indicators to Trend Micro Vision One. "
                        "Number of objects exceeded the maximum limit.",
                    )
                if response.status_code != 207:
                    self.handle_error(response)
                else:
                    response_code = [
                        status["status"] for status in response.json()
                    ]
                    for status in response_code:
                        if status == 201:
                            shared_indicators += 1
                            continue
                        else:
                            invalid_indicator_count += 1

            if invalid_indicator_count > 0:
                self.logger.info(
                    f"{shared_indicators} indicator(s) were shared to Trend Micro Vision One, "
                    f"{invalid_indicator_count} indicator(s) were not shared "
                    "due to invalid Indicator value or type."
                )

            return PushResult(
                success=True,
                message="Pushed all the indicators successfully.",
            )

        except requests.exceptions.ProxyError:
            self.notifier.error(
                "Plugin: Trend Micro Vision One Invalid proxy configuration."
            )
            self.logger.error(
                "Plugin: Trend Micro Vision One Invalid proxy configuration."
            )
            return PushResult(
                success=False,
                message=(
                    "Failed to push indicators to Trend Micro Vision One "
                    "Invalid proxy configuration"
                ),
            )

        except requests.exceptions.ConnectionError:
            self.notifier.error(
                "Plugin: Trend Micro Vision One "
                "Unable to establish connection with Trend Micro Vision One platform. "
                "Proxy server or Trend Micro Vision One API is not reachable."
            )
            self.logger.error(
                "Plugin: Trend Micro Vision One "
                "Unable to establish connection with Trend Micro Vision One platform. "
                "Proxy server or Trend Micro Vision One API is not reachable."
            )
            return PushResult(
                success=False,
                message=(
                    "Failed to push indicators to Trend Micro Vision One "
                    "Unable to establish connection with Trend Micro Vision One platform."
                ),
            )

        except requests.exceptions.RequestException as e:
            self.logger.error(
                "Plugin: Trend Micro Vision One Exception occurred "
                "while making an API call to Trend Micro Vision One platform"
            )
            return PushResult(
                success=False,
                message=(
                    "Exception occurred "
                    "while making an API call to Trend Micro Vision One platform "
                    f"Error :{repr(e)}"
                ),
            )
        except Exception as err:
            self.logger.error(
                "Plugin: Trend Micro Vision One Exception occurred "
                f"while pushing Indicators : {err}"
            )
            return PushResult(
                success=False,
                message=(
                    "Exception occurred "
                    "while making an API call to Trend Micro Vision One platform "
                    f"Error :{repr(err)}"
                ),
            )

    def prepare_payload(self, indicators, action_dict):
        """Prepare the JSON payload for Push.

        Args:
            indicators (List[cte.models.Indicators]):
            List of Indicator objects to be pushed.
            action_dict (Dict) : Dictionary contains the action
            and plateforms for sharing.
        Returns:
            List[dict]: List of python dict object of JSON response model
            as per Trend Micro Vision One API.
        """
        md5 = 0
        payload_list = []
        for indicator in indicators:
            if indicator.type in [IndicatorType.URL, IndicatorType.SHA256]:
                difference = indicator.expiresAt - datetime.datetime.now()
                hours = difference.seconds / 3600
                days_to_expire = difference.days + (hours / 24)
                if indicator.type == IndicatorType.URL:
                    type_of_url = check_url_domain_ip(indicator.value)
                    payload = {
                        f"{type_of_url}": indicator.value,
                        "description": (
                            f"{action_dict['desc']} "
                            "(Created from Netskope CTE)"
                        ),
                        "riskLevel": INTERNAL_SEVERITY_TO_TRENDMICRO[
                            indicator.severity
                        ],
                        "daysToExpiration": days_to_expire,
                    }
                else:
                    payload = {
                        "fileSha256": indicator.value,
                        "description": (
                            f"{action_dict['desc']}"
                            "(Created from Netskope CTE)"
                        ),
                        "riskLevel": INTERNAL_SEVERITY_TO_TRENDMICRO[
                            indicator.severity
                        ],
                        "daysToExpiration": days_to_expire,
                    }
                payload_list.append(payload)
            else:
                md5 += 1
        if md5 > 0:
            self.logger.warn(
                "Plugin: Trend Micro Vision One "
                f"Skipping {md5} md5 indicators."
            )
        return payload_list

    def divide_in_chunks(self, indicators):
        """Divide the json payload into chunks of size less than 1MB."""
        chunk_size = 1000
        for i in range(0, len(indicators), chunk_size):
            yield indicators[i : i + chunk_size]

    def get_actions(self):
        """Get available actions."""
        return [
            ActionWithoutParams(
                label="Add to Suspicious Object List",
                value="suspicious_object",
            ),
            ActionWithoutParams(
                label="Add to Suspicious Object Exception List",
                value="suspicious_object_exception",
            ),
        ]

    def validate_action(self, action: Action):
        """Validate Netskope configuration."""
        if action.value not in [
            "suspicious_object",
            "suspicious_object_exception",
        ]:
            return ValidationResult(
                success=False, message="Unsupported action provided."
            )
        if action.parameters.get("desc") is None:
            return ValidationResult(
                success=False, message="Invalid Event Name Provided."
            )

        return ValidationResult(success=True, message="Validation successful.")

    def get_action_fields(self, action: Action):
        """Get fields required for an action."""
        if action.value in [
            "suspicious_object",
            "suspicious_object_exception",
        ]:
            return [
                {
                    "label": "Description",
                    "key": "desc",
                    "type": "text",
                    "default": "",
                    "mandatory": False,
                    "description": "Description to be sent with the threats.",
                },
            ]

    def validate(self, data):
        """Validate the Plugin configuration parameters.

        Args:
            data (dict): Dict object having all the Plugin
            configuration parameters.
        Returns:
            cte.plugin_base.ValidateResult: ValidateResult object
            with success flag and message.
        """
        self.logger.info(
            "Plugin: Trend Micro Vision One"
            "Executing validate method for Trend Micro Vision One plugin"
        )
        if "base_url" not in data or not data["base_url"]:
            self.logger.error(
                "Plugin: Trend Micro Vision One Validation error occurred "
                "Error: Empty value for data region provided."
            )
            return ValidationResult(
                success=False,
                message="Data Region is a Required Field.",
            )
        elif data["base_url"] not in [
            "https://api.au.xdr.trendmicro.com",
            "https://api.eu.xdr.trendmicro.com",
            "https://api.in.xdr.trendmicro.com",
            "https://api.xdr.trendmicro.co.jp",
            "https://api.sg.xdr.trendmicro.com",
            "https://api.xdr.trendmicro.com",
        ]:
            self.logger.error(
                "Plugin: Trend Micro Vision One Validation error occurred "
                "Error: Type of Base URL should be non-empty string."
            )
            return ValidationResult(
                success=False,
                message="Invalid value for 'Base URL' provided. "
                "Select value from the given options only.",
            )

        if "token" not in data or not data["token"]:
            self.logger.error(
                "Plugin: Trend Micro Vision One Validation error occurred"
                "Error: Authentication String is Empty."
            )
            return ValidationResult(
                success=False,
                message="Authentication Token is a required field.",
            )

        elif not isinstance(data["token"], str):
            self.logger.error(
                "Plugin: Trend Micro Vision One Validation error occurred"
                "Error: Type of authentication Token should be "
                "non-empty string."
            )
            return ValidationResult(
                success=False,
                message="Type of authentication Token should be String.",
            )

        if "is_pull_required" not in data or not data["is_pull_required"]:
            self.logger.error(
                "Plugin: Trend Micro Vision One, Validation error occurred. "
                "Error: Enable Polling field cannot be empty."
            )
            return ValidationResult(
                success=False,
                message="Enable Polling is a Required Field",
            )

        elif data["is_pull_required"] not in [
            "Yes",
            "No",
        ]:
            self.logger.error(
                "Plugin: Trend Micro Vision One, Validation error occurred. "
                "Error: Invalid value for 'Enable Polling' provided."
                "Allowed values are 'Yes', or 'No'."
            )
            return ValidationResult(
                success=False,
                message="Invalid value for 'Enable Polling' provided. "
                "Allowed values are 'Yes', or 'No'.",
            )

        if "initial_range" not in data or not data["initial_range"]:
            self.logger.error(
                "Plugin: Trend Micro Vision One Validation error occurred "
                "Error: Type of Initial Range (in days) should be "
                "non-zero positive integer."
            )
            return ValidationResult(
                success=False,
                message="Initial Range (in days) is a Required Field.",
            )
        elif not isinstance(data["initial_range"], int):
            self.logger.error(
                "Plugin: Trend Micro Vision One Validation error occurred "
                "Initial Range should be an Integer value."
            )
            return ValidationResult(
                success=False,
                message="Initial Range should be an Integer value",
            )

        elif data["initial_range"] < 0:
            self.logger.error(
                "Plugin: Trend Micro Vision One Validation error occurred "
                "Initia Range should be a positive integer."
            )
            return ValidationResult(
                success=False,
                message=(
                    "Initia Range (in days) should be a positive integer only."
                ),
            )

        return self.validate_auth_params(data["token"], data["base_url"])

    def validate_auth_params(self, auth_token, base_url):
        """Validate the authentication params with Trend Micro Vision One platform.

        Args:
            auth_token (str): Authentication Token
            base_url (str): Base url of crowd strike
        Returns:
            ValidationResult: ValidationResult object having
            validation results after making an API call.
        """
        try:
            query_endpoint = f"{base_url}/v3.0/threatintel/suspiciousObjects"
            query_params = {
                "top": 1,
            }
            headers = {
                "Authorization": f"Bearer {auth_token.strip()}",
                "User-Agent": USER_AGENT,
            }
            retry_time = 15
            for _ in range(3):
                ioc_response = requests.get(
                    query_endpoint,
                    params=query_params,
                    headers=headers,
                    proxies=self.proxy,
                )
                if ioc_response.status_code == 429:
                    if "Retry-After" in ioc_response.headers:
                        retry_after = ioc_response.headers["Retry-After"]
                        self.logger.info(
                            "Plugin: Trend Micro Vision One, 429 Client Error - "
                            "Too Many Requests, Retrying after "
                            f"{retry_after} seconds"
                        )
                        sleep(int(retry_after))
                        continue
                if ioc_response.status_code == 500:
                    self.logger.info(
                        "Plugin: Trend Micro Vision One, 500 Internal Server Error - "
                        f"Retrying after {retry_time} seconds."
                    )
                    sleep(retry_time)
                    retry_time = retry_time * 2
                    continue
                else:
                    break

            if ioc_response.status_code == 200:
                return ValidationResult(
                    success=True,
                    message="Validation successfull for Trend Micro Vision One Plugin",
                )
            elif ioc_response.status_code == 429:
                err_resp = ioc_response.json()
                err_msg = err_resp.get("error").get("message")
                self.notifier.error(
                    f"Plugin: Trend Micro Vision One, "
                    f"Received exit code 429, TooManyRequests. "
                    f"Error: {err_msg}"
                )
                self.logger.error(
                    f"Plugin: Trend Micro Vision One, "
                    f"Received exit code 429, TooManyRequests. "
                    f"Error: {err_msg}"
                )
                return ValidationResult(
                    success=False,
                    message="Received exit code 429, TooManyRequests.",
                )
            else:
                return ValidationResult(
                    success=False,
                    message="Invalid Authentication token "
                    "or Data Region provided.",
                )

        except requests.exceptions.ProxyError:
            self.logger.error(
                "Plugin: Trend Micro Vision One Validation Error, "
                "Invalid proxy configuration."
            )
            return ValidationResult(
                success=False,
                message="Validation Error, Invalid proxy configuration.",
            )
        except requests.exceptions.ConnectionError:
            self.logger.error(
                "Plugin: Trend Micro Vision One Validation Error, "
                "Unable to establish connection with Trend Micro Vision One Platform API"
            )
            return ValidationResult(
                success=False,
                message="Validation Error, "
                "Unable to establish connection with Trend Micro Vision One Platform API",
            )
        except requests.HTTPError as err:
            self.logger.error(
                f"Plugin: Trend Micro Vision One Validation Error, "
                f"Error in validating Credentials {repr(err)}"
            )
            return ValidationResult(
                success=False,
                message="Validation Error, "
                f"Error in validating Credentials {repr(err)}",
            )
