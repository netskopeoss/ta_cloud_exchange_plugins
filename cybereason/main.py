"""Cybereason Plugin implementation to push and pull the data from Cybereason Platform."""

import re
import json
from typing import Dict, List

import requests

from netskope.integrations.cte.plugin_base import PluginBase, ValidationResult, PushResult
from netskope.integrations.cte.models import Indicator, IndicatorType
from netskope.integrations.cte.models.business_rule import Action, ActionWithoutParams
from netskope.common.utils import add_user_agent

Cybereason_TO_INTERNAL_TYPE = {
    "hash_md5": IndicatorType.MD5,
    "hash_sha256": IndicatorType.SHA256,
    "domain": IndicatorType.URL,
    "sha256": IndicatorType.SHA256,
    "md5": IndicatorType.MD5,
    "ipv4": IndicatorType.URL,
}

INTERNAL_TYPES_TO_Cybereason = {
    IndicatorType.MD5: "md5",
    IndicatorType.SHA256: "sha256",
    IndicatorType.URL: "domain",
}


class CybereasonPlugin(PluginBase):
    """CybereasonPlugin class having concrete implementation for pulling and pushing threat information."""

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
                self.logger.warn(
                    "Plugin:Cybereason-, "
                    "Exception occurred while parsing JSON response."
                )
                return resp
        elif resp.status_code == 401:
            self.notifier.error(
                "Plugin:Cybereason-, "
                "Received exit code 401, Authentication Error"
            )
            self.logger.error(
                "Plugin:Cybereason-, "
                "Received exit code 401, Authentication Error"
            )
        elif resp.status_code == 403:
            self.notifier.error(
                "Plugin:Cybereason-, "
                "Received exit code 403, Forbidden User"
            )
            self.logger.error(
                "Plugin:Cybereason-, "
                "Received exit code 403, Forbidden User"
            )
        elif resp.status_code >= 400 and resp.status_code < 500:
            self.notifier.error(
                f"Plugin:Cybereason-, "
                f"Received exit code {resp.status_code}, HTTP client Error"
            )
            self.logger.error(
                f"Plugin:Cybereason-, "
                f"Received exit code {resp.status_code}, HTTP client Error"
            )
        elif resp.status_code >= 500 and resp.status_code < 600:
            self.notifier.error(
                f"Plugin:Cybereason-, "
                f"Received exit code {resp.status_code}, HTTP server Error"
            )
            self.logger.error(
                f"Plugin:Cybereason-, "
                f"Received exit code {resp.status_code}, HTTP server Error"
            )
        else:
            self.notifier.error(
                f"Plugin:Cybereason-, "
                f"Received exit code {resp.status_code}, HTTP Error"
            )
            self.logger.error(
                f"Plugin:Cybereason-, "
                f"Received exit code {resp.status_code}, HTTP Error"
            )
        resp.raise_for_status()

    def get_indicators(self, session, headers):
        """Get detailed information by Detection IDs.

        Args:
            headers (dict): Header dict needed for the Cybereason API call.
        Returns:
            List[cte.models.Indicators]: List of indicator objects received from the Cybereason platform.
        """
        # Indicator endpoint, this will return detailed information about Indicator.
        indicator_endpoint = f"{self.configuration['base_url']}/rest/classification/download"

        indicator_list = []
        ioc_resp = session.request(
            "GET",
            indicator_endpoint,
            headers=add_user_agent(headers),
            verify=self.ssl_validation,
            proxies=self.proxy
        )

        if ioc_resp.status_code == 200 or ioc_resp.status_code == 201:
            lines = ioc_resp.content.splitlines()
            skipped_count, removed_count = 0, 0
            for row in lines:
                indicator, skipped, removed = self.prepare_indicator_from_row(row)
                if indicator:
                    indicator_list.append(indicator)
                elif skipped:
                    skipped_count += 1
                elif removed:
                    removed_count += 1
            if skipped_count > 0:
                self.logger.info(f"Plugin:Cybereason- Skipping {skipped_count} unsupported/unrecognized IoC(s).")
            if removed_count > 0:
                self.logger.info(f"Plugin:Cybereason- {removed_count} reputation(s) to be removed, skipping.")
        else:
            self.handle_error(ioc_resp)
        return indicator_list

    def prepare_indicator_from_row(self, row):
        """Prepare indicator object from row indicator."""
        indicator = None
        skipped, removed = False, False
        new_row = str(row, 'utf-8')
        ioc_elements = new_row.split(",")
        if len(ioc_elements) == 5:
            if ioc_elements[1].lower() == "blacklist" and ioc_elements[4].lower() == "false":
                # Add the blacklisted and which is not suppose to be removed IoC to Netskope
                ioc_type = self.get_indicator_type(ioc_elements[0])
                if ioc_type:
                    indicator = Indicator(
                        value=ioc_elements[0],
                        type=ioc_type,
                        comments="" if str(ioc_elements[3]).lower().strip() == "null" else ioc_elements[3]
                    )
                else:
                    skipped = True
            if ioc_elements[4].lower() == "true":
                removed = True
        else:
            self.logger.error("Plugin:Cybereason- Could not split Reputation: {}".format(new_row))
        return indicator, skipped, removed

    def get_indicator_type(self, ioc_key):
        """Get indicator type from given IOC key."""
        ioc_type = None
        if re.match(r"^((?=[a-z0-9-]{1,63}\.)(xn--)?[a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,63}$", ioc_key):
            # URL
            ioc_type = IndicatorType.URL
        elif re.match(r"^[A-Fa-f0-9]{32}$", ioc_key):
            # MD5
            ioc_type = IndicatorType.MD5
        elif re.match(r"^[A-Fa-f0-9]{64}$", ioc_key):
            # SHA256
            ioc_type = IndicatorType.SHA256
        return ioc_type

    def pull(self):
        """Pull the Threat information from Cybereason platform.

        Returns:
            List[cte.models.Indicators]: List of indicator objects received from the Cybereason platform.
        """
        # Let's trip the spaces from the OAUTH2 secrets.
        self.configuration['username'] = self.configuration['username'].replace(" ", "")
        self.configuration['password'] = self.configuration['password'].replace(" ", "")
        config = self.configuration
        if config["is_pull_required"] == "Yes":
            self.logger.info("Plugin:Cybereason- Polling is enabled.")
            try:
                session = self.get_session(
                    self.configuration.get('username'),
                    self.configuration.get('password'),
                    self.configuration.get('base_url')
                )

                headers = {"Content-Type": "application/json"}

                if session.cookies.get_dict().get("JSESSIONID") is None:
                    self.notifier.error(
                        "Plugin:Cybereason- Unable to establish session with the Cybereason console."
                    )
                else:
                    return self.get_indicators(session, headers)

            except requests.exceptions.ProxyError:
                self.notifier.error(
                    "Plugin:Cybereason- Invalid proxy configuration."
                )
                self.logger.error(
                    "Plugin:Cybereason- Invalid proxy configuration."
                )
                raise requests.HTTPError(
                    "Plugin:Cybereason- Invalid proxy configuration."
                )
            except requests.exceptions.ConnectionError:
                self.notifier.error(
                    "Plugin:Cybereason- Unable to establish connection with Cybereason platform. "
                    "Proxy server or Cybereason API is not reachable."
                )
                self.logger.error(
                    "Plugin:Cybereason- Unable to establish connection with Cybereason platform. "
                    "Proxy server or Cybereason API is not reachable."
                )
                raise requests.HTTPError(
                    "Plugin:Cybereason- Unable to establish connection with Cybereason platform. "
                    "Proxy server or Cybereason API is not reachable."
                )
            except requests.exceptions.RequestException as e:
                self.logger.error(
                    "Plugin:Cybereason- "
                    "Exception occurred while making an API call to Cybereason platform"
                )
                raise e
        else:
            self.logger.info(
                "Plugin:Cybereason- Polling is disabled, skipping."
            )
            return []

    def push(self, indicators: List[Indicator], action_dict: Dict):
        """Push the Indicator list to Cybereason.

        Args:
            indicators (List[cte.models.Indicators]): List of Indicator objects to be pushed.
        Returns:
            cte.plugin_base.PushResult: PushResult object with success flag and Push result message.
        """
        self.logger.info(
            "Plugin:Cybereason- Executing push method"
        )
        try:
            session = self.get_session(
                self.configuration.get('username'),
                self.configuration.get('password'),
                self.configuration.get('base_url')
            )
            headers = {"Content-Type": "application/json"}

            if session.cookies.get_dict().get("JSESSIONID") is None:
                self.notifier.error(
                    "Plugin:Cybereason-: Error: Unable to establish session with the Cybereason console."
                )
            else:
                payload_list = self.prepare_payload(indicators)

                self.push_indicators_to_cybereason(session, headers, payload_list[0])
                self.logger.info(
                    "Plugin:Cybereason- "
                    f"Successfully Pushed {payload_list[1]} Indicators to Cybereason"
                )
                return PushResult(
                    success=True,
                    message=f"Successfully Pushed {payload_list[1]} Indicators to Cybereason"
                )
        except requests.exceptions.ProxyError:
            self.notifier.error(
                "Plugin:Cybereason- Invalid proxy configuration."
            )
            self.logger.error(
                "Plugin:Cybereason- Invalid proxy configuration."
            )
            return PushResult(
                success=False,
                message=("Failed to push indicators to Cybereason "
                         "Invalid proxy configuration")
            )
        except requests.exceptions.ConnectionError:
            self.notifier.error(
                "Plugin:Cybereason- Unable to establish connection with Cybereason platform. "
                "Proxy server or Cybereason API is not reachable."
            )
            self.logger.error(
                "Plugin:Cybereason- Unable to establish connection with Cybereason platform. "
                "Proxy server or Cybereason API is not reachable."
            )
            return PushResult(
                success=False,
                message=("Failed to push indicators to Cybereason "
                         "Unable to establish connection with Cybereason platform.")
            )
        except requests.exceptions.RequestException as e:
            self.logger.error(
                "Plugin:Cybereason- "
                "Exception occurred while making an API call to Cybereason platform"
            )
            return PushResult(
                success=False,
                message=("Exception occurred while making an API call to Cybereason platform "
                         f"Error :{repr(e)}")
            )

    def push_indicators_to_cybereason(self, session, headers, json_payload):
        """Push the indicator to the Cybereason endpoint.

        Args:
            session: Request session object
            headers (dict): Header dict object needed to make the Cybereason API call
            json_payload (List[dict]): List of python dict object of JSON reputation model as per Cybereason API.)
        Returns:
            dict: JSON response dict received after successfull Push.
        """
        push_endpoint = f"{self.configuration['base_url']}/rest/classification/update"
        try:
            post_resp = session.request(
                "POST",
                push_endpoint,
                headers=add_user_agent(headers),
                data=json_payload,
                verify=self.ssl_validation,
                proxies=self.proxy
            )
        except requests.exceptions.RequestException as e:
            self.notifier.error(
                "Plugin:Cybereason- "
                f"Exception occurred while making an API call to Cybereason platform {repr(e)}"
            )
            self.logger.error(
                "Plugin:Cybereason- "
                f"Exception occurred while making an API call to Cybereason platform {repr(e)}"
            )
            return {}
        json_resp = self.handle_error(post_resp)
        outcome = json_resp.get('outcome')

        if outcome == 'failed':
            err_msg = json_resp.get('data', '')
            self.notifier.error(
                "Plugin:Cybereason- Unable to Push Indicators,"
                f"Error: {err_msg}"
            )
            self.logger.error(
                "Plugin:Cybereason- Unable to Push Indicators,"
                f"Error: {err_msg}"
            )
            raise requests.HTTPError(
                f"Plugin:Cybereason- Unable to Push Indicators,"
                f"Error: {err_msg}"
            )
        return json_resp

    def prepare_payload(self, indicators):
        """Prepare the JSON payload for Push.

        Args:
            indicators (List[cte.models.Indicators]): List of Indicator objects to be pushed.
        Returns:
            List[dict]: List of python dict object of JSON reputation model as per Cybereason API.
        """
        payload_list = []
        for indicator in indicators:
            if (
                f"{INTERNAL_TYPES_TO_Cybereason[indicator.type]}:{indicator.value}"
                and (re.match(r"^[A-Fa-f0-9]{64}$", indicator.value))
            ):
                self.logger.info("Cybereason skipping SHA256 indicator")
            else:
                payload_list.append(indicator.value)

        custom_reputation = "blacklist"
        payload = json.dumps(
            [{"keys": payload_list, "maliciousType": custom_reputation, "prevent": False, "remove": False}]
        )
        return [payload, len(payload_list)]

    def validate(self, data):
        """Validate the Plugin configuration parameters.

        Args:
            data (dict): Dict object having all the Plugin configuration parameters.
        Returns:
            cte.plugin_base.ValidateResult: ValidateResult object with success flag and message.
        """
        self.logger.info(
            "Plugin:Cybereason- Executing validate method for Cybereason plugin"
        )
        if "base_url" not in data:
            self.logger.error(
                "Plugin:Cybereason- Validation error occurred "
                "Error: Type of Pulling configured should be non-empty string."
            )
            return ValidationResult(
                success=False,
                message="Invalid value for 'Enable Polling' provided. Allowed values are 'Yes', or 'No'.",
            )

        if (
            "username" not in data
            or not data["username"]
            or type(data["username"]) != str
        ):
            self.logger.error(
                "Plugin:Cybereason- Validation error occurred"
                "Error: Type of Username should be non-empty string."
            )
            return ValidationResult(
                success=False, message="Invalid Username provided.",
            )

        if (
            "password" not in data
            or not data["password"]
            or type(data["password"]) != str
        ):
            self.logger.error(
                "Plugin:Cybereason- Validation error occurred"
                "Error: Type of Password should be non-empty string."
            )
            return ValidationResult(
                success=False, message="Invalid Password provided.",
            )

        if "is_pull_required" not in data or data["is_pull_required"] not in [
            "Yes",
            "No",
        ]:
            self.logger.error(
                "Plugin:Cybereason- Validation error occurred "
                "Error: Type of Pulling configured should be non-empty string."
            )
            return ValidationResult(
                success=False,
                message="Invalid value for 'Enable Polling' provided. Allowed values are 'Yes', or 'No'.",
            )

        return self.validate_auth_params(data["username"], data["password"], data["base_url"])

    def validate_auth_params(self, username, password, base_url):
        """Validate the authentication params with Cybereason platform.

        Args:
            username (str): Username required to login to Cybereason console.
            password (str): Password required to login to Cybereason console.
            base_url (str): Base url of Cybereason console.
        Returns:
            ValidationResult: ValidationResult object having validation results after making
            an API call.
        """
        try:
            session = self.get_session(username, password, base_url)
            if session.cookies.get_dict().get("JSESSIONID") is None:
                self.logger.error(
                    "Plugin:Cybereason- Validation Error, "
                    "Error in validating Credentials"
                )
                return ValidationResult(
                    success=False,
                    message="Validation Error, Error in validating Credentials. Please put the correct credentials."
                )
            return ValidationResult(
                success=True,
                message="Validation successful for Cybereason Plugin"
            )
        except requests.exceptions.ProxyError:
            self.logger.error(
                "Plugin:Cybereason- Validation Error, "
                "Invalid proxy configuration."
            )
            return ValidationResult(
                success=False,
                message="Validation Error, Invalid proxy configuration."
            )
        except requests.exceptions.ConnectionError:
            self.logger.error(
                "Plugin:Cybereason- Validation Error, "
                "Unable to establish connection with Cybereason Platform API"
            )
            return ValidationResult(
                success=False,
                message="Validation Error, Unable to establish connection with Cybereason Platform API"
            )
        except requests.HTTPError as err:
            self.logger.error(
                f"Plugin:Cybereason- Validation Error, "
                f"Error in validating Credentials {repr(err)}"
            )
            return ValidationResult(
                success=False,
                message=f"Validation Error, Error in validating Credentials {repr(err)}"
            )

    def get_session(self, username, password, base_url):
        """Get the session object after authentication from Cybereason platform.

        Args:
            username (str): Username required to login to Cybereason console.
            password (str): Password required to login to Cybereason console.
            base_url (str): Base url of Cybereason console.
        Returns:
            session: session object in case of Success.
        """
        username = username.replace(" ", "")
        password = password.replace(" ", "")
        auth_endpoint = f"{base_url}/login.html"
        session = requests.Session()
        auth_params = {
            'username': username,
            'password': password,
        }
        session.post(
            auth_endpoint,
            data=auth_params,
            verify=self.ssl_validation,
            proxies=self.proxy,
            headers=add_user_agent()
        )
        return session

    def get_actions(self):
        """Get available actions."""
        return [
            ActionWithoutParams(label="Share Indicators", value="share"),
        ]

    def validate_action(self, action: Action):
        """Validate Cybereason configuration."""
        if action.value not in ["share"]:
            return ValidationResult(
                success=False, message="Unsupported action provided."
            )

        return ValidationResult(success=True, message="Validation successful.")

    def get_action_fields(self, action: Action):
        """Get fields required for an action."""
        return []
