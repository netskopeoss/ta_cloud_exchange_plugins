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

"""Microsoft Defender for Endpoint implementation pull/push the data."""

from time import sleep
import jwt
import re
import ipaddress
import urllib.parse
from .lib import msal
from datetime import datetime, timedelta
from dateutil import parser
from operator import attrgetter

from typing import Dict, List
import requests.exceptions
from netskope.integrations.cte.plugin_base import (
    PluginBase,
    ValidationResult,
    PushResult,
)
from netskope.integrations.cte.models import (
    Indicator,
    IndicatorType,
    SeverityType,
)
from netskope.integrations.cte.models.business_rule import (
    Action,
    ActionWithoutParams
)
from netskope.common.utils import add_user_agent
from .utils.constant import actions, allow_deletion

BASE_URL = "https://api.securitycenter.microsoft.com/api/indicators"


def check_url_domain_ip(type):
    """Categorize URL as Domain, IP or URL."""
    regex_domain = (
        "^((?!-)[A-Za-z0-9-]" +
        "{1,63}(?<!-)\\.)" +
        "+[A-Za-z]{2,6}"
    )
    try:
        ipaddress.ip_address(type)
        return "IpAddress"
    except Exception:
        if re.search(regex_domain, type):
            return "DomainName"
        else:
            return "Url"


class MicrosoftDefenderEndpointPluginV2(PluginBase):

    def get_actions(self):
        """Get availabel actions."""
        return [
            ActionWithoutParams(label="Perform Action", value="action"),
        ]

    def get_action_fields(self, action: Action):
        """Get fields required for an action.

        Args:
            action (Action): Action object which is selected as Target.
        Return:
            List[Dict]: List of configurable fields based on selected action.
        """

        if action.value == "action":
            return [
                {
                    "label": "Action",
                    "key": "action",
                    "type": "choice",
                    "choices": [
                        {"key": action, "value": action} for action in actions
                    ],
                    "default": "Audit",
                    "mandatory": True,
                    "description": "The action to apply if the indicator is matched from within the targetProduct security tool.",
                },
                {
                    "label": "Allow Existing Indicators to be deleted?",
                    "key": "allow_deletion",
                    "type": "choice",
                    "choices": [
                        {"key": ad, "value": ad} for ad in allow_deletion
                    ],
                    "default": "No",
                    "mandatory": True,
                    "description": "Whether or not to delete the existing Indicators on Defender to insert new Indicators",
                },
            ]

    def validate_action(self, action: Action):
        """Validate Action Parameters

        This method validations the action and their parameters.
        Makes sure mandatory parameters have a valid value,
        and unsupport values are rejected.
        """

        if action.value not in ["action"]:
            return ValidationResult(
                success=False, message="Unsupported action provided."
            )
        if action.parameters.get("action") not in actions:
            return ValidationResult(
                success=False,
                message="Invalid action provided."
            )
        return ValidationResult(
            success=True,
            message="Validation successful."
        )

    def get_authorization_json(self, tenantid, appid, appsecret):
        """Get authorization token from Azure AD"""
        authority = "https://login.microsoftonline.com/{0}".format(tenantid)
        scope = ["https://api.securitycenter.microsoft.com/.default"]

        app = msal.ConfidentialClientApplication(
            appid, authority=authority, client_credential=appsecret
        )

        auth_json = app.acquire_token_for_client(scopes=scope)

        return auth_json

    def create_indicator(self, indicator, indicator_type):
        """Create Indicator according to type."""
        type_conversion = {
            "url": IndicatorType.URL,
            "md5": IndicatorType.MD5,
            "sha256": IndicatorType.SHA256,
        }
        severity_conversion = {
            "Low": SeverityType.LOW,
            "Medium": SeverityType.MEDIUM,
            "High": SeverityType.HIGH,
        }
        first_seen = parser.parse(
            indicator.get("creationTimeDateTimeUtc", datetime.utcnow())
        )
        last_seen = parser.parse(
            indicator.get("lastUpdateTime", datetime.utcnow())
        )
        comments = indicator["title"] + " | " + indicator["description"]

        return Indicator(
            value=indicator["indicatorValue"],
            type=type_conversion.get(indicator_type),
            firstSeen=first_seen,
            lastSeen=last_seen,
            comments=comments,
            severity=severity_conversion.get(
                indicator["severity"], SeverityType.UNKNOWN
            ),
        )

    def pull(self):
        """Pull tiIndicator data stored on the user's tenant"""
        auth_json = self.get_authorization_json(
            self.configuration["tenantid"].strip(),
            self.configuration["appid"].strip(),
            self.configuration["appsecret"].strip(),
        )
        indicators = []
        auth_token = auth_json.get("access_token")
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Authorization": f"Bearer {auth_token}",
        }

        last_pull_dt = self.last_run_at
        if self.last_run_at is None:
            last_pull_dt = datetime.utcnow() - timedelta(
                days=self.configuration["initial_range"]
            )
        url = BASE_URL
        params = {
            "$filter": "creationTimeDateTimeUtc+ge+" +
            f"{last_pull_dt.strftime('%Y-%m-%dT%H:%M:%SZ')}"
        }
        while True:
            response = self.call_pull_api(url, headers, params)
            resp_json = response.json()
            if response.status_code != 200:
                error_message = resp_json.get("error", {}).get("message", "")
                self.logger.error(
                    f"Plugin: Microsoft Defender for Endpoint, "
                    f"Unable to Pull indicators from Defender, "
                    f"Recieved status code: {response.status_code}, "
                    f"Message: {error_message}"
                )
                return []
            for indicator in resp_json.get("value", []):
                if "Netskope-CTE" not in indicator.get("description", ""):
                    if indicator["indicatorType"] in [
                        "Url", "IpAddress", "DomainName"
                    ]:
                        indicators.append(
                            self.create_indicator(indicator, "url")
                        )
                    if indicator["indicatorType"] == "FileMd5":
                        indicators.append(
                            self.create_indicator(indicator, "md5")
                        )
                    if indicator["indicatorType"] == "FileSha256":
                        indicators.append(
                            self.create_indicator(indicator, "sha256")
                        )
            if resp_json.get("@odata.nextLink", []):
                url = resp_json["@odata.nextLink"]
                params = {}
            else:
                break
        return indicators

    def push(self, indicators: List[Indicator], action_dict: Dict):
        """Push the Indicator list to Microsoft Defender for Endpoint
        Args:
            indicators (List[cte.models.Indicators]):
            List of Indicators to be pushed.

        Returns:
            cte.plugin_base.PushResult: PushResults object with success
            flag and Push result message.
        """
        action_dict = action_dict.get("parameters")
        # strip the whitespace from the authentication parameters
        try:
            auth_json = self.get_authorization_json(
                self.configuration["tenantid"].strip(),
                self.configuration["appid"].strip(),
                self.configuration["appsecret"].strip(),
            )
            auth_token = auth_json.get("access_token")
            headers = {
                "Authorization": f"Bearer {auth_token}",
                "Content-Type": "application/json",
            }
            payload_list = self.prepare_payload(indicators, action_dict)
            resp = self.push_indicators_to_defender(
                headers, payload_list, action_dict
            )
            return resp
        except requests.exceptions.ProxyError:
            self.notifier.error(
                "Plugin: Microsoft Defender for Endpoint, "
                "Invalid proxy configuration."
            )
            self.logger.error(
                "Plugin: Microsoft Defender for Endpoint, "
                "Invalid proxy configuration."
            )
            return PushResult(
                success=False,
                message=(
                    "Plugin: Microsoft Defender for Endpoint, "
                    "Failed to push indicators to Defender "
                    "Invalid proxy configuration"
                ),
            )
        except requests.exceptions.ConnectionError:
            self.notifier.error(
                "Plugin: Microsoft Defender for Endpoint, "
                "Unable to establish connection with Defender platform. "
                "Proxy server or Defender API is not reachable."
            )
            self.logger.error(
                "Plugin: Microsoft Defender for Endpoint, "
                "Unable to establish connection with Defender platform. "
                "Proxy server or Defender API is not reachable."
            )
            return PushResult(
                success=False,
                message=(
                    "Plugin: Microsoft Defender for Endpoint, "
                    "Failed to push indicators to Defender "
                    "Unable to establish connection with Defender platform."
                ),
            )
        except requests.exceptions.RequestException as e:
            self.logger.error(
                "Plugin: Microsoft Defender for Endpoint, "
                "Exception occurred while making an API call "
                "to Defender platform"
            )
            return PushResult(
                success=False,
                message=(
                    "Plugin: Microsoft Defender for Endpoint, "
                    "Exception occurred while making an API call to Defender. "
                    f"Error : {repr(e)}"
                ),
            )

    def call_push_api(self, indicator, headers, retry_count = 1, retry_val = 15):
        post_resp = requests.post(
            BASE_URL,
            headers=add_user_agent(headers),
            json=indicator,
            verify=self.ssl_validation,
            proxies=self.proxy,
        )
        if post_resp.status_code in [500, 504] and retry_count <= 3:
                self.logger.error(
                    f"Plugin Microsoft Defender for Endpoint, "
                    f"Recieved error code {post_resp.status_code}, "
                    f"Retrying in {retry_val} seconds."
                )
                sleep(retry_val)
                retry_val = retry_val * 2
                return self.call_push_api(indicator, headers, retry_count+1, retry_val)
        return post_resp

    def call_del_api(self, indicator, headers, retry_count = 1, retry_val = 15):
        url = (
                f"{BASE_URL}/{indicator.get('id')}"
            )
        del_resp = requests.delete(url, headers=headers)
        if del_resp.status_code in [500, 504] and retry_count <= 3:
                self.logger.error(
                    f"Plugin Microsoft Defender for Endpoint, "
                    f"Recieved error code {del_resp.status_code}, "
                    f"Retrying in {retry_val} seconds."
                )
                sleep(retry_val)
                retry_val = retry_val * 2
                return self.call_del_api(indicator, headers, retry_count+1, retry_val)
        return del_resp

    def call_pull_api(self, url, headers, params = {}, retry_count = 1, retry_val = 15):
        get_resp = requests.get(
            url,
            headers=add_user_agent(headers),
            params = urllib.parse.urlencode(params, safe=':+'),
            verify=self.ssl_validation,
            proxies=self.proxy,
        )
        if get_resp.status_code in [500, 504] and retry_count <= 3:
                self.logger.error(
                    f"Plugin Microsoft Defender for Endpoint, "
                    f"Recieved error code {get_resp.status_code}, "
                    f"Retrying in {retry_val} seconds."
                )
                sleep(retry_val)
                retry_val = retry_val * 2
                return self.call_pull_api(url, headers, params, retry_count+1, retry_val)
        return get_resp


    def push_indicators_to_defender(self, headers, json_payload, action_dict):
        """Push the indicator to the Microsoft Defender for Endpoint."""
        try:
            url = BASE_URL
            ioc_in_defender = []
            while True:
                get_resp = self.call_pull_api(url, headers)
                resp_json = get_resp.json()
                if get_resp.status_code != 200:
                    error_message = resp_json.get("error", {}).get(
                        "message", ""
                    )
                    return PushResult(
                        success=False,
                        message=(
                            "Plugin: Microsoft Defender for Endpoint, "
                            "Unable to push indicators to Defender, "
                            f"Recieved status code: {get_resp.status_code}, "
                            f"Message: {error_message}"
                        )
                    )
                for ioc in resp_json["value"]:
                    ioc_in_defender.append(
                        {
                            "id": ioc.get("id"),
                            "creationTimeDateTimeUtc": ioc.get(
                                "creationTimeDateTimeUtc"
                            ),
                        }
                    )
                if resp_json.get("@odata.nextLink", []):
                    url = resp_json["@odata.nextLink"]
                else:
                    break
            sorted_defender_ioc_list = sorted(
                ioc_in_defender, key=lambda i: i["creationTimeDateTimeUtc"],
                reverse=True
            )  # in decscending order earliest creation time at the end
            for ioc in json_payload:
                push_resp = self.call_push_api(ioc, headers)
                if push_resp.status_code == 200:
                    continue
                if(
                    push_resp.status_code == 400 and
                    "Max capacity exceeded" in
                    push_resp.json().get("error",{}).get("message", "")
                ):
                    if(action_dict.get("allow_deletion", "No") == "Yes"):
                        del_resp = self.call_del_api(
                            sorted_defender_ioc_list.pop(),
                            headers
                        )
                        if del_resp.status_code != 204:
                            del_resp_json = del_resp.json()
                            error_message = del_resp_json.get("error", {}).get(
                                "message", ""
                            )
                            self.logger.info(
                                "Plugin: Microsoft Defender for Endpoint, "
                                "Unable to push indicator "
                                f"{ioc['indicatorValue']}, "
                                "Recieved status code: "
                                f"{del_resp.status_code}, "
                                f"Message: {error_message}"
                            )
                            continue
                        push_resp = self.call_push_api(ioc, headers)
                        if push_resp.status_code != 200:
                            push_resp_json = push_resp.json()
                            error_message = push_resp_json.get(
                                "error", {}
                            ).get("message", "")
                            self.logger.info(
                                "Plugin: Microsoft Defender for Endpoint, "
                                "Unable to push indicator "
                                f"{ioc['indicatorValue']}, "
                                "Recieved status code: "
                                f"{push_resp.status_code}, "
                                f"Message: {error_message}"
                            )
                    else:
                        self.logger.info(
                            "Plugin: Microsoft Defender for Endpoint, "
                            "Unable to push more "
                            "indicators to Defender as Maximum "
                            "capacity is exceeded."
                        )
                        return PushResult(
                            success=False,
                            message=(
                                "Plugin: Microsoft Defender for Endpoint, "
                                "Unable to push more "
                                "indicators to Defender as Maximum "
                                "capacity is exceeded."
                            )
                        )
                elif push_resp.status_code == 400:
                    push_resp_json = push_resp.json()
                    error_message = push_resp_json.get("error", {}).get(
                        "message", ""
                    )
                    self.logger.info(
                        "Plugin: Microsoft Defender for Endpoint, "
                        "Unable to push indicator "
                        f"{ioc['indicatorValue']}, "
                        f"Recieved status code: {push_resp.status_code}, "
                        f"Message: {error_message}"
                    )
                else:
                    push_resp_json = push_resp.json()
                    error_message = push_resp_json.get("error", {}).get(
                        "message", ""
                    )
                    return PushResult(
                        success=False,
                        message=(
                            "Plugin: Microsoft Defender for Endpoint, "
                            "Unable to push Indicator to Defender , "
                            f"Recieved status code: {push_resp.status_code}, "
                            f"Message: {error_message}"
                        )
                    )
            return PushResult(
                success=True,
                message=(
                    "Plgin: Microsoft Defender for Endpoint, "
                    f"Successfully Pushed {len(json_payload)} "
                    "Indicator(s) to Microsoft Defender for Endpoint"
                )
            )
        except Exception as e:
            self.logger.error(
                "Plugin: Microsoft Defender for Endpoint, "
                "Exception Occured while executing push method."
                f"Error: {e}"
            )
            return PushResult(
                success=False,
                message=(
                    "Plugin: Microsoft Defender for Endpoint, "
                    f"Error occured while sharing indicators to Defender, "
                    f"Error: {e}"
                )
            )

    def prepare_payload(self, indicators, action_dict):
        """Prepare the JSON payload for Push.

        Args:
            ioc_ids (List[str]):
            indicators (List[cte.models.Indicators]): List of Indicator
            objects to be pushed.
        Returns:
            List[dict]: List of python dict object of JSON response model
            as per Defender API
        """
        type_conversion = {
            IndicatorType.URL: "Url",
            IndicatorType.MD5: "FileMd5",
            IndicatorType.SHA256: "FileSha256",
        }
        severity_conversion = {
            SeverityType.LOW: "Low",
            SeverityType.MEDIUM: "Medium",
            SeverityType.HIGH: "High",
            SeverityType.CRITICAL: "High"
        }
        action_conversion = {
            "unknown": "Audit",
            "allow": "Allowed",
            "block": "Block",
            "alert": "Alert"
        }
        payload_list = []
        source = self.configuration.get("source", "")
        action = action_dict.get("action", "Audit")
        if action in action_conversion.keys():
            action = action_conversion.get(action)
        sorted_indicators = sorted(
            indicators, key=attrgetter("firstSeen")
        )  # in ascendng order on the basis of firstseen
        for indicator in sorted_indicators:
            json_body = {
                "indicatorValue": indicator.value,
                "action": action,
                "title": f"Indicator {indicator.value} of type {type_conversion.get(indicator.type)}",
                "description": f" Netskope-CTE | {source} | {indicator.comments}",
            }
            if indicator.expiresAt is not None:
                json_body["expirationTime"] = indicator.expiresAt.strftime(
                    "%Y-%m-%dT%H:%M:%SZ"
                )
            if severity_conversion.get(indicator.severity, None):
                json_body["severity"] = severity_conversion.get(
                    indicator.severity
                )
            if action == "Audit":
                json_body["generateAlert"] = True
            if type_conversion.get(indicator.type) == "Url":
                json_body["indicatorType"] = check_url_domain_ip(
                    indicator.value
                )
                json_body["title"] = (
                    f"Indicator {indicator.value} of type {check_url_domain_ip(indicator.value)}"
                )
            else:
                json_body["indicatorType"] = type_conversion.get(
                    indicator.type
                )

            payload_list.append(json_body.copy())
        return payload_list

    def _validate_credentials(
        self,
        tenantid: str,
        appid: str,
        appsecret: str,
    ):
        """Validate Azure AD Application Credentials"""
        try:
            isValid = False
            auth_json = self.get_authorization_json(
                tenantid.strip(),
                appid.strip(),
                appsecret.strip(),
            )
            auth_token = auth_json.get("access_token")
            alg = jwt.get_unverified_header(auth_token)["alg"]
            decoded_auth_token = jwt.decode(
                auth_json["access_token"],
                algorithms=alg,
                options={"verify_signature": False},
            )
            roles = set(decoded_auth_token.get("roles", []))
            if "Ti.ReadWrite" in roles or "Ti.ReadWrite.All" in roles:
                isValid = True
            if isValid:
                return ValidationResult(
                    success=True,
                    message="Pugin: Microsoft Defender for Endpoint, "
                    "Validation successful."
                )
            else:
                self.logger.error(
                    "Plugin: Microsoft Defender for Endpoint, "
                    "required roles not defined"
                )
                return ValidationResult(
                    success=False,
                    message="Plugin: Microsoft Defender for Endpoint, "
                    "Couldn't find required API permissions."
                )
        except Exception as ex:
            self.logger.error(
                f"Plugin: Microsoft Defender for Endpoint, "
                f"{repr(ex)}"
            )
            return ValidationResult(
                success=False,
                message="Plugin: Microsoft Defender for Endpoint, "
                "Could not verify credentials."
            )

    def validate(self, configuration):
        """Validate the configuration"""
        if(
            "tenantid" not in configuration or not
            configuration["tenantid"].strip()
        ):
            self.logger.error(
                "Plugin: Microsoft Defender for Endpoint, "
                "No Tenant ID found in the configuration parameters."
            )
            return ValidationResult(
                success=False,
                message="Plugin: Microsoft Defender for Endpoint, "
                "Invalid Tenant ID provided."
            )

        if "appid" not in configuration or not configuration["appid"].strip():
            self.logger.error(
                "Plugin, Microsoft Defender for Endpoint, "
                "No App ID found in the configuration parameters."
            )
            return ValidationResult(
                success=False,
                message="Plugin: Microsoft Defender for Endpoint, "
                "Invalid App ID provided."
            )

        if(
            "appsecret" not in configuration or not
            configuration["appsecret"].strip()
        ):
            self.logger.error(
                "Plugin: Microsoft Defender for Endpoint, "
                "App Secret not found in the configuration parameters."
            )
            return ValidationResult(
                succes=False,
                message="Plugin: Microsoft Defender for Endpoint, "
                "Invalid App Secret Provided."
            )
        if (
            "source" not in configuration
            or type(configuration["source"]) != str
            or len(configuration["source"]) > 200
        ):
            self.logger.error(
                "Plugin: Microsoft Defender for Endpoint, "
                "Validation error occurred "
                "Error: Length of IOC Source cannot be more than 200 characters."
            )
            return ValidationResult(
                success=False,
                message="Error:  "
                "Length of IOC Source cannot be more than 200 characters.",
            )
        if (
            "initial_range" not in configuration
            or not configuration["initial_range"]
            or type(configuration["initial_range"]) != int
            or configuration["initial_range"] < 0
        ):
            self.logger.error(
                "Plugin: Microsoft Defender for Endpoint, "
                "Validation error occurred "
                "Error: Type of Initial Range (in days) "
                "should be non-zero positive integer."
            )
            return ValidationResult(
                success=False,
                message="Error: Type of Initial Range (in days) "
                "should be non-zero positive integer.",
            )


        # this is where the data comes in from manifest.json
        return self._validate_credentials(
            configuration["tenantid"].strip(),
            configuration["appid"].strip(),
            configuration["appsecret"].strip(),
        )
