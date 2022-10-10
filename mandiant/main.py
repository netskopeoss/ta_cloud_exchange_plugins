"""Mandiant Plugin implementation to pull data from Mandiant Platform."""

import requests
import datetime
import time
from datetime import timedelta
from requests.auth import HTTPBasicAuth
import json
from typing import List


from netskope.integrations.cte.plugin_base import (
    PluginBase,
    ValidationResult,
)

from netskope.integrations.cte.utils import TagUtils

from netskope.integrations.cte.models import (
    Indicator,
    IndicatorType,
    SeverityType,
    TagIn,
)
from netskope.common.utils import add_user_agent

MANDIANT_TO_INTERNAL_TYPE = {
    "md5": IndicatorType.MD5,
    "url": IndicatorType.URL,
    "fqdn": IndicatorType.URL,
    "ipv4": IndicatorType.URL,
    "ipv6": IndicatorType.URL,
}


class AuthenticationException(Exception):
    pass


class MandiantPlugin(PluginBase):
    """MandiantPlugin class for pulling threat information."""

    def handle_error(self, resp):
        """Handle the different HTTP response code.

        Args:
            resp (requests.models.Response): Response object
            returned from API call.
        Returns:
            dict: Returns the dictionary of response JSON
            when the response code is 200.
        Raises:
            HTTPError: When the response code is not 200.
        """
        if resp.status_code == 200 or resp.status_code == 201:
            try:
                return resp.json()
            except ValueError:
                self.notifier.error(
                    "Plugin: Mandiant, "
                    "Exception occurred while parsing JSON response."
                )
                self.logger.error(
                    "Plugin: Mandiant, "
                    "Exception occurred while parsing JSON response."
                )
        if resp.status_code == 204:
            return {}
        elif resp.status_code == 400:
            auth_reponse = resp.text
            result_dict = json.loads(auth_reponse)
            err_msg = result_dict["error"]
            if(
                "errorMessage" in result_dict
                and err_msg == "invalid_basic_auth"
            ):
                raise AuthenticationException(
                    "Invalid Key ID or Key Secret Provided."
                )
            else:
                self.notifier.error(
                        "Plugin: Mandiant, "
                        "Received exit code 400, Bad Request."
                    )
                self.logger.error(
                        "Plugin: Mandiant, "
                        "Received exit code 400, Bad Request"
                )
        elif resp.status_code == 403:
            self.notifier.error(
                "Plugin: Mandiant, "
                "Received exit code 403, Forbidden User"
            )
            self.logger.error(
                "Plugin: Mandiant, "
                "Received exit code 403, Forbidden User"
            )
        elif resp.status_code >= 500 and resp.status_code < 600:
            self.notifier.error(
                f"Plugin: Mandiant, "
                f"Received exit code {resp.status_code}, HTTP server Error"
            )
            self.logger.error(
                f"Plugin: Mandiant, "
                f"Received exit code {resp.status_code}, HTTP server Error"
            )
        else:
            self.notifier.error(
                f"Plugin: Mandiant, "
                f"Received exit code {resp.status_code}, HTTP Error"
            )
            self.logger.error(
                f"Plugin: Mandiant, "
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
        if isinstance(severity, int) is False or severity == 0:
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

    def _create_tags(
        self, utils: TagUtils, tags: List,
    ) -> (List[str]):
        """Create new tag(s) in database if required."""
        tag_names = []
        for tag in tags:
            try:
                if not utils.exists(tag.strip()):
                    utils.create_tag(
                        TagIn(
                            name=tag.strip(),
                            color="#ED3347",
                        )
                    )
            except ValueError as e:
                self.logger.error(f"Mandiant Error: {e}")
            else:
                tag_names.append(tag.strip())
        tag_names = set(tag_names)
        return list(tag_names)

    def get_indicators(self, headers):
        indicator_list = []
        query_endpoint = "https://api.intelligence.fireeye.com/v4/indicator"
        if self.configuration.get("exclude_osint") == "Yes":
            self.configuration["exclude_osint"] = True
        else:
            self.configuration["exclude_osint"] = False
        if not self.last_run_at:
            start_time = datetime.datetime.now() - timedelta(
                hours=int(self.configuration["hours"])
            )
            epoch_time = datetime.datetime.timestamp(start_time)
        else:
            start_time = self.last_run_at
            epoch_time = datetime.datetime.timestamp(start_time)
        current_time = time.time()
        query_params = {
            "start_epoch": int(epoch_time),
            "end_epoch": int(current_time),
            "limit": 1000,
            "gte_mscore": self.configuration.get("mscore", 50),
            "exclude_osint": self.configuration["exclude_osint"]
        }
        while True:
            try:
                headers = self.reload_auth_token(headers)
                ioc_response = requests.get(
                    query_endpoint,
                    headers=add_user_agent(headers),
                    params=query_params,
                    verify=self.ssl_validation,
                    proxies=self.proxy,
                )
                resp_json = self.handle_error(ioc_response)
                if resp_json.get("errors"):
                    err_msg = resp_json.get("errors")[0].get("message")
                    self.notifier.error(
                        f"Plugin: Mandiant, "
                        f"Unable to Fetch Indicator Details, "
                        f"Error: {err_msg}"
                    )
                    self.logger.error(
                        f"Plugin: Mandiant, "
                        f"Unable to Fetch Indicator Details, "
                        f"Error: {err_msg}"
                    )
                indicators_json_list = resp_json.get("indicators", [])
                if indicators_json_list:
                    for indicator in indicators_json_list:
                        categories = []
                        if self.configuration["enable_tagging"] == "Yes":
                            for source in indicator.get("sources", []):
                                categories += source.get("category", [])
                            for attributed_association in indicator.get(
                                "attributed_associations", []
                            ):
                                if attributed_association.get(
                                    "type"
                                ) in ["malware", "threat-actor"]:
                                    categories.append(
                                        attributed_association.get("name")
                                    )
                        if (
                            len(indicator.get("value")) > 0
                            and len(indicator.get("type")) > 0
                            and indicator.get("type")
                            in ["md5", "url", "fqdn", "ipv4", "ipv6"]
                        ):
                            indicator_list.append(
                                Indicator(
                                    value=indicator.get("value").lower(),
                                    type=MANDIANT_TO_INTERNAL_TYPE.get(
                                        indicator.get("type")
                                    ),
                                    firstSeen=datetime.datetime.strptime(
                                        indicator.get("first_seen"),
                                        "%Y-%m-%dT%H:%M:%S.%f%z",
                                    ),
                                    lastSeen=datetime.datetime.strptime(
                                        indicator.get("last_seen"),
                                        "%Y-%m-%dT%H:%M:%S.%f%z",
                                    ),
                                    severity=self.get_severity_from_int(
                                        indicator.get("mscore", 0)
                                    ),
                                    tags=self._create_tags(
                                        TagUtils(), categories
                                    ),
                                )
                            )
                            categories.clear()
                        else:
                            self.logger.warn(
                                "Plugin: Mandiant: Skipping the record as "
                                "IOC value and/or IOC type not found or "
                                "IOC type not in [md5, fqdn, url]."
                            )

                if "next" not in resp_json or "next" == "":
                    break
                else:
                    if "start_epoch" and "end_epoch" in query_params.keys():
                        del query_params["start_epoch"]
                        del query_params["end_epoch"]
                    query_params["next"] = resp_json["next"]

            except requests.ConnectionError:
                raise requests.ConnectionError(
                    "Cannot make connection to the API endpoint"
                )

            except Exception as e:
                self.logger.error(
                    "Something went wrong"
                )
                raise e
        return indicator_list

    def pull(self):
        """Pull the Threat information from Mandiant platform.

        Returns : List[cte.models.Indicators] :
        List of indicator objects received from the Mandiant platform.
        """
        self.configuration["key_id"] = self.configuration[
            "key_id"
            ].replace(
            " ", "")
        self.configuration["key_secret"] = self.configuration[
            "key_secret"
            ].replace(
            " ", ""
        )
        try:
            auth_json = self.get_auth_json(
                self.configuration.get("key_id"),
                self.configuration.get("key_secret"),
            )
            auth_token = auth_json.get("access_token")
            headers = {
                "accept": "application/json",
                "Authorization": f"Bearer {auth_token}",
                "Content-Type": "application/x-www-form-urlencoded"
            }
            return self.get_indicators(headers)

        except requests.exceptions.ProxyError:
            self.notifier.error(
                "Plugin: Mandiant, Invalid proxy configuration."
            )
            self.logger.error(
                "Plugin: Mandiant, Invalid proxy configuration."
            )
            raise requests.HTTPError(
                "Plugin: Mandiant, Invalid proxy configuration."
            )
        except requests.exceptions.ConnectionError:
            self.notifier.error(
                "Plugin: Mandiant, "
                "Unable to establish connection with Mandiant platform. "
                "Proxy server or Mandiant API is not reachable."
            )
            self.logger.error(
                "Plugin: Mandiant, "
                "Unable to establish connection with Mandiant platform. "
                "Proxy server or Mandiant API is not reachable."
            )
            raise requests.HTTPError(
                "Plugin: Mandiant, "
                "Unable to establish connection with Mandiant platform. "
                "Proxy server or Mandiant API is not reachable."
            )
        except requests.exceptions.RequestException as e:
            self.logger.error(
                "Plugin: Mandiant, "
                "Exception occurred while making an API call to "
                "Mandiant platform"
            )
            raise e
        except AuthenticationException as e:
            raise e

    def reload_auth_token(self, headers):
        """Reload the access token after Expiry."""
        if self.storage.get(
            "token_expiry", datetime.datetime.now()
        ) < datetime.datetime.now():
            self.logger.info(
                "Plugin: Mandiant, access token expired generating new token"
            )
            auth_json = self.get_auth_json(
                self.configuration.get("key_id"),
                self.configuration.get("key_secret"),
            )
            auth_token = auth_json.get("access_token")
            headers["Authorization"] = f"Bearer {auth_token}"
        return headers

    def validate(self, data):
        """Validate the Plugin configuration parameters.

        Args:
            data (dict): Dict object having all
            the Plugin configuration parameters.
        Returns:
            cte.plugin_base.ValidateResult:
            ValidateResult object with success flag and message.
        """
        self.logger.info(
            "Plugin: Mandiant, Executing validate method for Mandiant plugin"
        )

        if "key_id" not in data or not data["key_id"] or type(
            data["key_id"]
        ) != str:
            self.logger.error(
                "Plugin: Mandiant, Validation error occurred. "
                "Error: Type of Key ID should be non-empty string."
            )
            return ValidationResult(
                success=False,
                message="Invalid Key ID provided.",
            )

        if (
            "key_secret" not in data
            or not data["key_secret"]
            or type(data["key_secret"]) != str
        ):
            self.logger.error(
                "Plugin: Mandiant, Validation error occurred. "
                "Error: Type of Key Secret should be non-empty string."
            )
            return ValidationResult(
                success=False,
                message="Invalid Key Secret provided.",
            )
        if (
            "hours" not in data
            or not data["hours"]
            or type(data["hours"]) != int
            or not (0 < data["hours"] <= 24)
        ):
            self.logger.error(
                "Plugin: Mandiant, Validation error occurred. "
                "Error: Type of Initial Range (in hours) "
                "should be non-zero positive integer less than or equal to 24."
            )
            return ValidationResult(
                success=False,
                message="Error: Type of Initial Range should be "
                        "non-zero positive integer less than or equal to 24.",
            )
        if (
            "mscore" not in data
            or not isinstance(data["mscore"], int)
            or not (0 <= data["mscore"] <= 100)
        ):
            self.logger.error(
                "Plugin: Mandiant, Validation error occurred. "
                "Error: Value of Minimum Indicator Confidential Score (IC-Score) "
                "should be in range of 0 to 100."
            )
            return ValidationResult(
                success=False,
                message="Invalid IC-Score value provided.",
            )
        if "exclude_osint" not in data or data[
            "exclude_osint"
        ] not in ["Yes", "No"]:
            self.logger.error(
                "Mandiant Plugin: "
                "Value of Exclude Open Source indicators should be 'Yes' or 'No'."
            )
            return ValidationResult(
                success=False,
                message="Invalid value for 'Exclude Open Source indicators' provided."
                "Allowed values are 'Yes', or 'No'.",
            )
        if "enable_tagging" not in data or data[
            "enable_tagging"
        ] not in ["Yes", "No"]:
            self.logger.error(
                "Mandiant Plugin: "
                "Value of Enable Tagging should be 'Yes' or 'No'."
            )
            return ValidationResult(
                success=False,
                message="Invalid value for 'Enable Tagging' provided."
                "Allowed values are 'Yes', or 'No'.",
            )

        return self.validate_auth_params(data["key_id"], data["key_secret"])

    def validate_auth_params(self, key_id, key_secret):
        """Validate the authentication params with Mandiant platform.

        Args:
            key_id (str): Client ID required to generate access token.
            key_secret (str): Client Secret required to generate access token.
        Returns:
            ValidationResult: ValidationResult object having
            validation results after making an API call.
        """
        try:
            self.get_auth_json(key_id, key_secret)
            return ValidationResult(
                success=True,
                message="Validation successfull for Mandiant Plugin",
            )
        except requests.exceptions.ProxyError:
            self.logger.error(
                "Plugin: Mandiant, Validation Error, "
                "Invalid proxy configuration."
            )
            return ValidationResult(
                success=False,
                message="Validation Error, Invalid proxy configuration.",
            )
        except requests.exceptions.ConnectionError:
            self.logger.error(
                "Plugin: Mandiant, Validation Error, "
                "Unable to establish connection with Mandiant Platform API"
            )
            return ValidationResult(
                success=False,
                message="Validation Error, "
                "Unable to establish connection with Mandiant Platform API",
            )
        except requests.HTTPError as err:
            self.logger.error(
                f"Plugin: Mandiant, Validation Error, "
                f"Error in validating Credentials {repr(err)}"
            )
            return ValidationResult(
                success=False,
                message=f"Plugin: Mandiant, Validation Error, "
                        f"Error in validating Credentials {repr(err)}"
            )
        except AuthenticationException as e:
            return ValidationResult(
                success=False,
                message=f"Validation Error: {e}",
            )

    def get_auth_json(self, client_key, key_secret):
        """Get the access token from Mandiant platform.

        Args:
            key_id (str): Client ID required to generate access token.
            key_secret (str): Client Secret required to generate access token.
        Returns:
            json: JSON response data in case of Success.
        """
        client_key = client_key.strip()
        key_secret = key_secret.strip()
        auth_endpoint = "https://api.intelligence.fireeye.com/token"

        headers = {"grant_type": "client_credentials",
                   'Content-Type': 'application/x-www-form-urlencoded',
                   'accept': 'application/json', }
        try:
            resp = requests.post(
                auth_endpoint, auth=HTTPBasicAuth(
                    client_key, key_secret
                ),
                data=headers
            )
            auth_json = self.handle_error(resp)
            auth_errors = auth_json.get("errors")
            if auth_errors:
                err_msg = auth_errors[0].get("message", "")
                self.notifier.error(
                    "Plugin: Mandiant, Unable to generate Auth token. "
                    f"Error: {err_msg}"
                )
                self.logger.error(
                    "Plugin: Mandiant, Unable to generate Auth token. "
                    f"Error: {err_msg}"
                )
                raise requests.HTTPError(
                    f"Plugin: Mandiant, Unable to generate Auth token. "
                    f"Error: {err_msg}"
                )
            if self.storage is not None:
                self.storage[
                    "token_expiry"
                ] = datetime.datetime.now() + datetime.timedelta(
                    seconds=int(auth_json.get("expires_in", 1799))
                )
            return auth_json
        except requests.ConnectionError:
            raise requests.ConnectionError(
                "Cannot make connection to the API endpoint"
            )
        except AuthenticationException:
            raise
        except Exception as e:
            raise e
