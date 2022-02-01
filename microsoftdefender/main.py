"""Microsoft Defender for Endpoint implementation pull the data."""

import requests
from datetime import datetime, timedelta

from netskope.integrations.cte.plugin_base import PluginBase, ValidationResult
from netskope.integrations.cte.models import (
    Indicator,
    IndicatorType,
    SeverityType,
)
from netskope.integrations.cte.models.business_rule import Action
from netskope.common.utils import add_user_agent

HOST = "https://login.windows.net"
RESOURCEAPPIDURI = "https://graph.windows.net"
ALERT_URL = {
    "eu": "https://wdatp-alertexporter-eu.windows.com/api/alerts",
    "us": "https://wdatp-alertexporter-us.windows.com/api/alerts",
    "uk": "https://wdatp-alertexporter-uk.windows.com/api/alerts",
}
MICROSOFTDEFENDER_TO_INTERNAL_TYPE = {
    "UnSpecified": SeverityType.UNKNOWN,
    "Informational": SeverityType.LOW,
    "Low": SeverityType.MEDIUM,
    "Medium": SeverityType.HIGH,
    "High": SeverityType.CRITICAL,
}


class MicrosoftdefenderPlugin(PluginBase):
    """MCASB implementation to push and pull the data."""

    def datetime_to_str(self, date) -> str:
        """Get string representation of datetime.

        Args:
            date (datetime): The datetime object.

        Returns:
            str: String representation.
        """
        # remove 3 digit of microsecond in case of error
        return date.strftime("%Y-%m-%dT%H:%M:%S.%f")

    def _str_to_datetime(self, string: str) -> datetime:
        """Convert ISO formatted string to datetime object.

        Args:
            string(str): ISO formatted string.

        Returns:
            datetime: Converted datetime object.
        """
        try:
            return datetime.strptime(string.split(".")[0], "%Y-%m-%dT%H:%M:%S")
        except Exception:
            return datetime.now()

    def get_authorization_json(self, tenantid, appid, appsecret):
        """Get authorization json from Microsoft Defender for Endpoint."""
        authurl = f"{HOST}/{tenantid.strip()}/oauth2/token"
        data = {
            "resource": RESOURCEAPPIDURI,
            "client_id": appid,
            "client_secret": appsecret,
            "grant_type": "client_credentials",
        }
        response = requests.post(
            authurl,
            data=data,
            headers=add_user_agent(),
            verify=self.ssl_validation,
            proxies=self.proxy,
        )
        if response.status_code != 200:
            self.logger.error(
                "Microsoft Defender for Endpoint Plugin: Could not authorized."
            )
        return response.json()

    def create_machinegroup_list(self):
        """Create list of Device groups."""
        mgparams = self.configuration["machinegroup"]
        mgparams = [x.strip() for x in mgparams.split(",")]
        mgparams = list(filter(lambda x: len(x) > 0, mgparams))
        return mgparams

    def create_indicator(self, indicator, indicator_type):
        """Create Indicator according to type."""
        type_conversion = {
            "Url": IndicatorType.URL,
            "Md5": IndicatorType.MD5,
            "Sha256": IndicatorType.SHA256,
        }
        return Indicator(
            value=indicator[indicator_type],
            severity=MICROSOFTDEFENDER_TO_INTERNAL_TYPE[indicator["Severity"]],
            type=type_conversion.get(indicator_type),
            firstSeen=self._str_to_datetime(indicator["AlertTime"]),
            lastSeen=self._str_to_datetime(indicator["LastProcessedTimeUtc"]),
            extendedInformation=indicator["LinkToWDATP"],
        )

    def pull(self):
        """Pull data from Microsoft Defender for Endpoint."""
        auth_json = self.get_authorization_json(
            self.configuration["tenantid"].strip(),
            self.configuration["appid"].strip(),
            self.configuration["appsecret"],
        )
        indicators = []
        auth_token = auth_json.get("access_token")
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Authorization": f"Bearer {auth_token}",
        }
        if not self.last_run_at:
            start_time = datetime.now() - timedelta(
                days=int(self.configuration["days"])
            )
        else:
            start_time = self.last_run_at
        start_time = self.datetime_to_str(start_time)
        payload = {
            "sinceTimeUtc": start_time,
            "machinegroups": self.create_machinegroup_list(),
        }
        url = ALERT_URL.get(self.configuration["region"])
        response = requests.get(
            url,
            headers=add_user_agent(headers),
            params=payload,
            verify=self.ssl_validation,
            proxies=self.proxy,
        )
        response.raise_for_status()
        for indicator in response.json():
            if indicator["Url"] != "":
                indicators.append(self.create_indicator(indicator, "Url"))
            if indicator["Md5"] != "":
                indicators.append(self.create_indicator(indicator, "Md5"))
            if indicator["Sha256"] != "":
                indicators.append(self.create_indicator(indicator, "Sha256"))
        return indicators

    def _validate_credentials(
        self,
        tenantid: str,
        appid: str,
        appsecret: str,
        devicegroup: str,
        region: str,
    ):
        """Validate API credentials."""
        try:
            response = requests.post(
                f"https://login.windows.net/{tenantid.strip()}/oauth2/token",
                data={
                    "resource": "https://graph.windows.net",
                    "client_id": appid,
                    "client_secret": appsecret,
                    "grant_type": "client_credentials",
                },
                headers=add_user_agent(),
                verify=self.ssl_validation,
                proxies=self.proxy,
            )
            devicegroup = [x.strip() for x in devicegroup.split(",")]
            mgparams = list(filter(lambda x: len(x) > 0, devicegroup))
            if response.status_code == 200 and len(mgparams) == 0:
                return ValidationResult(
                    success=True, message="Validation successful."
                )
            elif response.status_code == 200 and len(mgparams) > 0:
                try:
                    auth_token = response.json().get("access_token")
                    headers = {
                        "Content-Type": "application/json",
                        "Accept": "application/json",
                        "Authorization": f"Bearer {auth_token}",
                    }
                    start_time = datetime.now() - timedelta(days=int(1))
                    payload = {
                        "sinceTimeUtc": start_time,
                        "machinegroups": mgparams,
                    }
                    url = ALERT_URL.get(region)
                    response2 = requests.get(
                        url,
                        headers=add_user_agent(headers),
                        params=payload,
                        verify=self.ssl_validation,
                        proxies=self.proxy,
                    )
                    if response2.status_code == 200:
                        return ValidationResult(
                            success=True, message="Validation successful."
                        )
                    else:
                        return ValidationResult(
                            success=False,
                            message="Could not verify Device Groups.",
                        )
                except Exception as ex:
                    self.logger.error(
                        f"Microsoft Defender for Endpoint Plugin: {repr(ex)}"
                    )
                    return ValidationResult(
                        success=False,
                        message="Could not verify Device Groups.",
                    )
            else:
                return ValidationResult(
                    success=False, message="Could not verify credentials."
                )
        except Exception as ex:
            self.logger.error(
                f"Microsoft Defender for Endpoint Plugin: {repr(ex)}"
            )
            return ValidationResult(
                success=False, message="Could not verify credentials."
            )

    def validate(self, configuration):
        """Validate the configuration."""
        if (
            "tenantid" not in configuration
            or not configuration["tenantid"].strip()
        ):
            self.logger.error(
                "Microsoft Defender for Endpoint Plugin: "
                "No Tenant ID found in the configuration parameters."
            )
            return ValidationResult(
                success=False, message="Invalid Tenant ID provided."
            )

        if "appid" not in configuration or not configuration["appid"].strip():
            self.logger.error(
                "Microsoft Defender for Endpoint Plugin: "
                "No App ID found in the configuration parameters."
            )
            return ValidationResult(
                success=False, message="Invalid App ID provided."
            )

        if "appsecret" not in configuration or not configuration["appsecret"]:
            self.logger.error(
                "Microsoft Defender for Endpoint Plugin: "
                "App Secret not found in the configuration parameters."
            )
            return ValidationResult(
                success=False, message="Invalid App Secret Provided."
            )

        if "region" not in configuration or configuration["region"] not in [
            "us",
            "uk",
            "eu",
        ]:
            self.logger.error(
                "Microsoft Defender for Endpoint Plugin: Value of region should be "
                "'European Union', or 'United States', or 'United Kingdom'."
            )
            return ValidationResult(
                success=False,
                message=(
                    "Invalid value for 'region' provided. Allowed values are "
                    "'European Union', or 'United States', or 'United Kingdom'."
                ),
            )

        if (
            "days" not in configuration
            or not configuration["days"]
            or int(configuration["days"]) < 0
        ):
            self.logger.error(
                "Microsoft Defender for Endpoint Plugin: "
                "Type of Initial Range (in days) should be non-zero positive integer."
            )
            return ValidationResult(
                success=False,
                message="Type of Initial Range (in days) should be non-zero positive integer.",
            )

        return self._validate_credentials(
            configuration["tenantid"].strip(),
            configuration["appid"].strip(),
            configuration["appsecret"],
            configuration["machinegroup"],
            configuration["region"],
        )

    def get_actions(self):
        """Get available actions."""
        return []

    def validate_action(self, action: Action):
        """Validate microsoftdefender configuration."""
        return ValidationResult(success=True, message="Validation successful.")

    def get_action_fields(self, action: Action):
        """Get fields required for an action."""
        return []
