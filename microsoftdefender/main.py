import requests
from .lib import msal
from datetime import datetime

from typing import Dict, List
import requests.exceptions
from netskope.integrations.cte.plugin_base import (
    PluginBase,
    ValidationResult,
    PushResult
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
from .utils.constant import actions, target_products, tlp_levels
from netskope.common.utils import add_user_agent



# Stores configuration data from parameters.json to the config object

# Variables needed for authentication and API access
# AUTHORITY = "https://login.microsoftonline.com/{0}".format(config["tenantid"])
# SCOPE = ["https://graph.microsoft.com/.default"]
# ENDPOINT = "https://graph.microsoft.com/beta/security/tiIndicators"

DEFENDER_GRAPH_TO_SEVERITY = {
    # include this information in the tooltip
    # might be able to include a line here if there is a null severity
    None: SeverityType.UNKNOWN,
    0: SeverityType.LOW,
    1: SeverityType.LOW,
    2: SeverityType.MEDIUM,
    3: SeverityType.MEDIUM,
    4: SeverityType.HIGH,
    5: SeverityType.CRITICAL,
}

SEVERITY_TO_DEFENDER_GRAPH = {
    SeverityType.UNKNOWN: None,
    SeverityType.LOW: "1",
    SeverityType.MEDIUM: "3",
    SeverityType.HIGH: "4",
    SeverityType.CRITICAL: "5"
}

INTERNAL_TYPES_TO_DEFENDER_GRAPH = {
    IndicatorType.MD5: "md5",
    IndicatorType.SHA256: "sha256",
    IndicatorType.URL: "domain",
}


class MicrosoftDefenderEndpointPluginV2(PluginBase):

    def _str_to_datetime(self, string: str) -> datetime:
        """Convert ISO formatted string to datetime object."""

        try:
            return datetime.strptime(
                string.replace(".", ""), "%Y-%m-%dT%H:%M:%S%fZ"  # taken from carbon black (I think) plugin
            )
        except Exception:
            return datetime.now()

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
            return[
                {
                    "label": "Action",
                    "key": "action",
                    "type": "choice",
                    "choices": [
                        {"key": action, "value": action} for action in actions
                    ],
                    "default": "unknown",
                    "mandatory": True,
                    "description": "The action to apply if the indicator is matched from within the targetProduct security tool."
                },
                {
                    "label": "Target Product",
                    "key": "targetProduct",
                    "type": "choice",
                    "choices": [
                        {"key": tp, "value": tp} for tp in target_products] +
                        [{"key": "Both", "value": "both"}
                    ],
                    "default": "Azure Sentinel",
                    "mandatory": True,
                    "description": "A string value representing a single security product to which the indicator should be applied."
                },
                {
                    "label": "TLP Level",
                    "key": "tlpLevel",
                    "type": "choice",
                    "choices": [
                        {"key": tlp_level, "value": tlp_level} for tlp_level in tlp_levels
                    ],
                    "default": "unknown",
                    "mandatory": True,
                    "description": "Traffic Light Protocol value for the indicator. For more details check https://docs.microsoft.com/en-us/graph/api/resources/tiindicator?view=graph-rest-beta"
                }
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
                    success=False, message="Invalid action provided."
                )
        if action.parameters.get("targetProduct") not in target_products + ["both"]:
                return ValidationResult(
                    success=False, message="Invalid target product provided."
                )
        if action.parameters.get("tlpLevel") not in tlp_levels:
                return ValidationResult(
                    success=False, message="Invalid tlp level provided."
                )
        return ValidationResult(
            success=True, message="Validation successful."
        )

    def get_authorization_json(self, tenantid, appid, appsecret):
        """Get authorization token from Azure AD"""
        authority = "https://login.microsoftonline.com/{0}".format(tenantid)
        scope = ["https://graph.microsoft.com/.default"]
        
        app = msal.ConfidentialClientApplication(
            appid, authority=authority,
            client_credential=appsecret
        )

        auth_json = app.acquire_token_for_client(scopes=scope)  # json data containing the token and a few other fields

        # might be able to do a 'if "access_token" in result:' statement for logging errors

        return auth_json

    def create_indicator(self, indicator, indicator_type):
        """Create Indicator according to type."""
        type_conversion = {
            "url": IndicatorType.URL,
            "md5": IndicatorType.MD5,
            "sha256": IndicatorType.SHA256,
        }

        # TiIndicators are not required to have a firstSeen (or equivalent) value filled out
        # so we make sure the Netskope Indicators are given one
        if indicator["ingestedDateTime"] is None:
            first_seen = datetime.now()
        else:
            first_seen = self._str_to_datetime(indicator["ingestedDateTime"])

        # concatting the fileName and description to the Indicator comments
        if (indicator_type == "md5" or indicator_type == "sha256") and indicator["fileName"]:
            comments = indicator["fileName"] + " | " + indicator["description"]
        else:
            comments = indicator["description"]

        return Indicator(
            value=indicator[indicator_type] if indicator_type == "url" else indicator["fileHashValue"],
            type=type_conversion.get(indicator_type),
            firstSeen=first_seen,
            lastSeen=self._str_to_datetime(indicator["lastReportedDateTime"]),
            comments=comments,
            severity=DEFENDER_GRAPH_TO_SEVERITY[indicator["severity"]],
            # extendedInformation=indicator["LinkToWDATP"]
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

        url = "https://graph.microsoft.com/beta/security/tiIndicators"
        while True:
            response = requests.get(
                url,
                headers=add_user_agent(headers),
            )
            response.raise_for_status()  # check back later to see what this actually does
            res = response.json()
            for indicator in res.get('value', []):
                if indicator["isActive"]:
                    if indicator["targetProduct"] == "Microsoft Defender ATP":
                        if indicator["url"] != "" and indicator["url"] is not None:
                            indicators.append(self.create_indicator(indicator, "url"))
                        if indicator["fileHashType"] == "md5":
                            indicators.append(self.create_indicator(indicator, "md5"))
                        if indicator["fileHashType"] == "sha256":
                            indicators.append(self.create_indicator(indicator, "sha256"))
                # can add additional rules here to account for errors (i.e. an incompatible hash type is produced)

            if res.get("@odata.nextLink", []):
                url = res["@odata.nextLink"]
            else:
                break
        return indicators

    def push(self, indicators: List[Indicator], action_dict: Dict):
        """Push the Indicator list to Microsoft Defender
        Args:
            indicators (List[cte.models.Indicators]): List of Indicators to be pushed.

        Returns:
            cte.plugin_base.PushResult: PushResults object with success flag and Push result message.
        """
        self.logger.info("Plugin: Microsoft Defender for Endpoint Executing push method")
        action_dict = action_dict.get("parameters")
        # strip the whitespace from the authentication parameters
        try:
            auth_json = self.get_authorization_json(
                self.configuration["tenantid"].strip(),
                self.configuration["appid"].strip(),
                self.configuration["appsecret"].strip(),
            )
            auth_token = auth_json.get("access_token")
            headers = {"Authorization": f"Bearer {auth_token}", "Content-Type": "application/json"}
            payload_list = self.prepare_payload(indicators, action_dict)

            for chunked_list in self.divide_in_chunks(
                payload_list, 100  # maximum indicators per submitIndicators reuqest is 100
            ):
                self.push_indicators_to_defender(headers, chunked_list)
            self.logger.info(
                "Plugin: Microsoft Defender for Endpoint "
                f"Successfully Pushed {len(payload_list)} Indicators to Microsoft Defender for Endpoint"
            )
            return PushResult(
                success=True,
                message=f"Successfully Pushed {len(payload_list)} Indicators to Microsoft Defender for Endpoint",
            )
        except requests.exceptions.ProxyError:
            self.notifier.error(
                "Plugin: Defender Invalid proxy configuration."
            )
            self.logger.error(
                "Plugin: Defender Invalid proxy configuration."
            )
            return PushResult(
                success=False,
                message=(
                    "Failed to push indicators to Defender "
                    "Invalid proxy configuration"
                ),
            )
        except requests.exceptions.ConnectionError:
            self.notifier.error(
                "Plugin: Defender Unable to establish connection with Defender platform. "
                "Proxy server or Defender API is not reachable."
            )
            self.logger.error(
                "Plugin: Defender UNable to establish connection with Defender platform. "
                "Proxy server or Defender API is not reachable."
            )
            return PushResult(
                success=False,
                message=("Failed to push indicators to Defender "
                         "Unable to establish connection with Defender platform."
                         ),
            )
        except requests.exceptions.RequestException as e:
            self.logger.error(
                "Plugin: Defender "
                "Exception occurred while making an API call to Defender platform"
            )
            return PushResult(
                success=False,
                message=(
                    "Exception occurred while making an API call to Defender. "
                    f"Error : {repr(e)}"
                ),
            )

    def divide_in_chunks(self, indicators, chunk_size):
        """Return Fixed size chunks from List"""
        for i in range(0, len(indicators), chunk_size):
            yield indicators[i : i + chunk_size]  # noqa

    def push_indicators_to_defender(self, headers, json_payload):
        """Push the indicator to the Defender endpoint.

        Args:
            headers (dict): Header dict object having OAUTH2 access token
            json_payload (List[dict]): List of python dict object of JSON response model as per Defender API.)
        Returns:
            dict: JSON response dict received after successful Push.
        """

        push_endpoint = "https://graph.microsoft.com/beta/security/tiIndicators/submitTiIndicators"
        json_body = {}
        json_body["value"] = json_payload
        try:
            post_resp = requests.post(
                push_endpoint,
                headers=add_user_agent(headers),
                json=json_body,
                verify=self.ssl_validation,
                proxies=self.proxy
            )
        except requests.exceptions.RequestException as e:
            self.notifier.error(
                "Plugin: Defender "
                f"Exception occurred while making an API call to Defender platform {repr(e)}"
            )
            self.logger.error(
                "Plugin: Defender"
                f"Exception occurred while making an API call to Defnder paltform {repr(e)}"
            )
            return {}
        json_resp = post_resp.json()
        error = json_resp.get("error", {})
        if error:
            err_msg = error.get("message", "")
            self.notifier.error(
                "Plugin: Defender Unable to Push Indicators, "
                f"Error: {err_msg}"
            )
            self.logger.error(
                "Plugin: Defender Unable to Push Indicatos, "
                f"Error: {err_msg}"
            )
            raise requests.HTTPError(
                f"Plugin: Defender Unable to Push Indicators, "
                f"Error: {err_msg}"
            )
        return json_resp

    def prepare_payload(self, indicators, action_dict):
        """Prepare the JSON payload for Push.

        Args:
            ioc_ids (List[str]):
            indicators (List[cte.models.Indicators]): List of Indicator objects to be pushed.
        Returns:
            List[dict]: List of python dict object of JSON response model as per Defender API
        """
        payload_list = []
        # ioc = set()
        source = self.configuration.get("source", "")
        action = action_dict.get("action", "")
        threat_type = action_dict.get("threatType", "")
        tlp_level = action_dict.get("tlpLevel", "")
        target_product = action_dict.get("targetProduct", "Azure Senitinel")
        # probably need to convert to correct datetime format for values in json_body
        for indicator in indicators:
            json_body = {
                "description": f"{source} | {indicator.comments}",
                "action": action,
                "severity": SEVERITY_TO_DEFENDER_GRAPH[indicator.severity],
                "ingestedDateTime": str(indicator.firstSeen),
                "lastReportedDateTime": str(indicator.lastSeen),
                "additionalInformation": f"For more info: {indicator.extendedInformation}",
                "tlpLevel": tlp_level,
                "expirationDateTime": str(indicator.expiresAt)
            }
            # the below if statement deviates from the example in the Crowdstrike plugin
            if indicator.type == IndicatorType.MD5:
                json_body["fileHashType"] = "md5"
                json_body["fileHashValue"] = indicator.value
                json_body["threatType"] = "Malware"
            elif indicator.type == IndicatorType.SHA256:
                json_body["fileHashType"] = "sha256"
                json_body["fileHashValue"] = indicator.value
                json_body["threatType"] = "Malware"
            # Netskope Indicators can be hostnames or URLs
            # if errors show up with hostnames/domains on Defender or Azure, check here
            # might be able to do an resolution to a URL
            # also consider changing to else OR changing to error out unsupported indicator types ("future proofing")
            elif indicator.type == IndicatorType.URL:
                json_body["url"] = indicator.value
                json_body["threatType"] = "MaliciousUrl"
            if target_product == "both":
                for target in target_products:
                    json_body["targetProduct"] = target
                    payload_list.append(json_body.copy())
            else:
                json_body["targetProduct"] = target
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
            response = requests.post(
                f"https://login.windows.net/{tenantid.strip()}/oauth2/token",
                data={
                    "resource": "https://graph.windows.net",
                    "client_id": appid,
                    "client_secret": appsecret,
                    "grant_type": "client_credentials",
                },
            )
            if response.status_code == 200:
                return ValidationResult(
                    success=True, message="Validation successful."
                )
            else:
                return ValidationResult(
                    success=False, message="Could not verify credentials."
                )
        except Exception as ex:
            self.logger.error(
                f"Microsoft Defender for Endpoint Plugin v2: {repr(ex)}"
            )
            return ValidationResult(
                success=False, message="Could not verify credentials."
            )

    def validate(self, configuration):
        """Validate the configuration"""
        if (
            "tenantid" not in configuration
            or not configuration["tenantid"].strip()
        ):
            self.logger.error(
                "Microsoft Defender for Endpoint Plugin v2: "
                "No Tenant ID found in the configuration parameters."
            )

        if (
            "appid" not in configuration
            or not configuration["appid"].strip()
        ):
            self.logger.error(
                "Microsoft Defender for Endpoing Plugin v2: "
                "No App ID found in the configuration parameters."
            )
            return ValidationResult(
                success=False, message="Invalid App ID provided."
            )

        if (
            "appsecret" not in configuration
            or not configuration["appsecret"]
        ):
            self.logger.error(
                "Microsoft Defender for Endpoint Plugin: "
                "App Secret not found in the configuration parameters."
            )
            return ValidationResult(
                succes=False, message="Invalid App Secret Provided."
            )

        # this is where the data comes in from manifest.json
        return self._validate_credentials(
            configuration["tenantid"].strip(),
            configuration["appid"].strip(),
            configuration["appsecret"],
        )
