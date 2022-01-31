"""Mimecast Plugin implementation to push and pull the data from Netskope Tenant."""

import re
import csv
import base64
import hashlib
import hmac
import uuid
import requests
from typing import Dict, List
from datetime import datetime, timedelta

from netskope.integrations.cte.models import Indicator, IndicatorType
from netskope.integrations.cte.plugin_base import (
    PluginBase,
    ValidationResult,
    PushResult,
)
from netskope.integrations.cte.models.business_rule import (
    Action,
    ActionWithoutParams,
)
from netskope.common.utils import add_user_agent


class MimecastPlugin(PluginBase):
    """The Mimecast plugin implementation."""

    def _parse_errors(self, failures):
        """Parse the error messages from Mimecast response."""
        messages = []
        for failure in failures:
            for error in failure.get("errors", []):
                messages.append(error.get("message"))
        return messages

    def _parse_csv(
        self, raw_csv: str, indicator_key: str = "MD5"
    ) -> List[Indicator]:
        """Parse given raw CSV string based on given feed type."""
        indicators = []
        raw_csv = raw_csv.split("\n")

        # This means no indicator data is returned
        if len(raw_csv) == 1:
            return indicators

        reader = csv.DictReader(raw_csv, delimiter="|")
        for row in reader:
            indicator = row.get(indicator_key)
            if indicator:
                indicators.append(
                    Indicator(
                        value=indicator,
                        type=IndicatorType[indicator_key],
                        comments=f"Sent from {row.get('SenderAddress')}"
                        if row.get("SenderAddress")
                        else "",
                    )
                )
        return indicators

    def pull(self) -> List[Indicator]:
        """Pull the indicators from Mimecast."""
        url, headers = self._get_auth_headers(
            self.configuration, "/api/ttp/threat-intel/get-feed"
        )
        # Get start time based on checkpoint
        if not self.last_run_at:
            self.logger.info(
                f"Mimecast Plugin: This is initial data fetch for indicator feed since "
                f"checkpoint is empty. Querying indicators for last {self.configuration['days']} day(s)."
            )
            start_time = datetime.now() - timedelta(
                days=int(self.configuration["days"])
            )
        else:
            start_time = self.last_run_at

        body = {
            "data": [
                {
                    "fileType": "csv",
                    "start": f"{start_time.replace(microsecond=0).astimezone().isoformat()}",
                    "feedType": self.configuration["feed_type"],
                }
            ]
        }

        response = requests.post(
            url,
            json=body,
            headers=add_user_agent(headers),
            proxies=self.proxy,
            verify=self.ssl_validation,
        )
        response.raise_for_status()

        indicators = []
        if response.status_code == 200:
            try:
                indicators = self._parse_csv(response.text)
            except Exception as ex:
                self.logger.error(
                    f"Mimecast Plugin: Error occurred while parsing CSV response: {repr(ex)}"
                )
        return indicators

    def push(
        self, indicators: List[Indicator], action_dict: Dict
    ) -> PushResult:
        """Push the given list of indicators to Mimecast."""
        # First check if push is enabled
        action_dict = action_dict.get("parameters")
        if self.configuration["push_enabled"] != "yes":
            return PushResult(
                success=False,
                message="Push is disabled for Mimecast plugin. Skipping.",
            )

        # Prepare list of only file hashes
        hashes = []
        for indicator in indicators:
            if indicator.type in [IndicatorType.MD5, IndicatorType.SHA256]:
                hashes.append(
                    {
                        "hash": indicator.value,
                        # Length of description is required to be <= 20 on Mimecast.
                        "description": indicator.comments
                        if len(indicator.comments) <= 20
                        else "",
                    }
                )

        # If all the indicators are of type other than file hash, skip.
        if len(hashes) == 0:
            return PushResult(
                success=False,
                message="Found no indicators eligible for pushing to Mimecast. Only file hashes are supported. "
                "Skipping.",
            )

        body = {
            "data": [
                {
                    "hashList": [],
                    "operationType": action_dict.get("operation_type"),
                }
            ]
        }

        # Mimecast only supports "push" in batch of 1000 indicators at a time
        batch_size = 1000
        for pos in range(0, len(hashes), batch_size):
            url, headers = self._get_auth_headers(
                self.configuration, "/api/byo-threat-intelligence/create-batch"
            )
            body["data"][0]["hashList"] = hashes[
                pos : pos + batch_size  # noqa
            ]

            response = requests.post(
                url,
                json=body,
                headers=add_user_agent(headers),
                proxies=self.proxy,
                verify=self.ssl_validation,
            )
            response.raise_for_status()
            failures = response.json().get("fail", [])
            if failures:
                return PushResult(
                    success=False,
                    message=", ".join(self._parse_errors(failures)),
                )

        return PushResult(
            success=True, message="Pushed all the indicators successfully."
        )

    def _get_auth_headers(
        self, configuration: dict, endpoint: str
    ) -> (str, dict):
        """Generate the Mimecast authentication headers."""
        request_url = configuration.get("url").strip("/") + endpoint
        request_id = str(uuid.uuid4())
        request_datetime = (
            datetime.utcnow().strftime("%a, %d %b %Y %H:%M:%S") + " UTC"
        )

        # Create the HMAC SHA1 of the Base64 decoded secret key for the Authorization header
        hmac_sha1 = hmac.new(
            base64.b64decode(configuration.get("secret_key")),
            ":".join(
                [
                    request_datetime,
                    request_id,
                    endpoint,
                    configuration.get("app_key"),
                ]
            ).encode("utf-8"),
            digestmod=hashlib.sha1,
        ).digest()

        # Use the HMAC SHA1 value to sign hmac_sha1
        sig = base64.b64encode(hmac_sha1).rstrip()

        # Create request headers
        headers = {
            "Authorization": "MC "
            + configuration.get("access_key")
            + ":"
            + sig.decode("utf-8"),
            "x-mc-app-id": configuration.get("app_id"),
            "x-mc-date": request_datetime,
            "x-mc-req-id": request_id,
            "Content-Type": "application/json",
        }
        return request_url, headers

    def _validate_credentials(
        self, configuration: dict
    ) -> (ValidationResult, List[str]):
        """Validate credentials by making REST API call."""
        try:
            url, headers = self._get_auth_headers(
                configuration, "/api/account/get-account"
            )
            response = requests.post(
                url,
                json={"data": []},
                headers=add_user_agent(headers),
                proxies=self.proxy,
                verify=self.ssl_validation,
            )

            if response.status_code == 200:
                failures = response.json().get("fail", [])
                if not failures:
                    return ValidationResult(
                        success=True, message="Validation successful."
                    ), response.json().get("data", [{}])[0].get("packages", [])
                return (
                    ValidationResult(
                        success=False,
                        message=", ".join(self._parse_errors(failures)),
                    ),
                    None,
                )

            elif response.status_code == 401:
                return (
                    ValidationResult(
                        success=False,
                        message="Incorrect access key or secret key or application key provided.",
                    ),
                    None,
                )
            else:
                return (
                    ValidationResult(
                        success=False,
                        message=(
                            f"An HTTP error occurred while validating configuration "
                            f"parameters. Status code {response.status_code}."
                        ),
                    ),
                    None,
                )
        except requests.ConnectionError as ex:
            self.logger.error(repr(ex))
            return (
                ValidationResult(
                    success=False,
                    message="Incorrect Mimecast base URL provided.",
                ),
                None,
            )
        except Exception as ex:
            self.logger.error(repr(ex))
            return (
                ValidationResult(
                    success=False,
                    message="Error occurred while validating configuration parameters. Check logs for more detail.",
                ),
                None,
            )

    def validate(self, configuration: dict) -> ValidationResult:
        """Validate the plugin configurations."""
        if (
            "url" not in configuration
            or not configuration["url"].strip()
            or type(configuration["url"]) != str
        ):
            self.logger.error(
                "Mimecast Plugin: Mimecast base URL must be a valid non-empty string."
            )
            return ValidationResult(
                success=False,
                message="Mimecast base URL must be a valid non-empty string.",
            )

        if (
            "app_id" not in configuration
            or not configuration["app_id"].strip()
            or type(configuration["app_id"]) != str
        ):
            self.logger.error(
                "Mimecast Plugin: Application ID must be a valid non-empty string."
            )
            return ValidationResult(
                success=False,
                message="Application ID must be a valid non-empty string.",
            )

        if (
            "app_key" not in configuration
            or not configuration["app_key"].strip()
            or type(configuration["app_key"]) != str
        ):
            self.logger.error(
                "Mimecast Plugin: Application Key must be a valid non-empty string."
            )
            return ValidationResult(
                success=False,
                message="Application Key must be a valid non-empty string.",
            )

        if (
            "access_key" not in configuration
            or not configuration["access_key"].strip()
            or type(configuration["access_key"]) != str
        ):
            self.logger.error(
                "Mimecast Plugin: Access Key must be a valid non-empty string."
            )
            return ValidationResult(
                success=False,
                message="Access Key must be a valid non-empty string.",
            )

        if (
            "secret_key" not in configuration
            or not configuration["secret_key"].strip()
            or type(configuration["secret_key"]) != str
            or
            # Base 64 check
            not re.match(
                r"^([A-Za-z0-9+/]{4})*([A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{2}==)?$",
                configuration["secret_key"],
            )
        ):
            self.logger.error(
                "Mimecast Plugin: Access Secret must be a valid non-empty string."
            )
            return ValidationResult(
                success=False,
                message="Access Secret must be a valid non-empty string.",
            )

        try:
            if (
                "days" not in configuration
                or not configuration["days"]
                or int(configuration["days"]) <= 0
            ):
                self.logger.error(
                    "Mimecast Plugin: Invalid number of initial days provided."
                )
                return ValidationResult(
                    success=False,
                    message="Invalid number of initial days provided.",
                )
        except ValueError:
            return ValidationResult(
                success=False,
                message="Invalid number of initial days provided.",
            )

        if "feed_type" not in configuration or configuration[
            "feed_type"
        ] not in [
            "malware_customer",
            "malware_grid",
        ]:
            self.logger.error(
                "Mimecast Plugin: Value of Feed Type must be either 'malware_customer' or 'malware_grid'."
            )
            return ValidationResult(
                success=False,
                message="Invalid value for 'Feed Type' provided. Allowed values "
                "are 'malware_customer' or 'malware_grid'.",
            )

        if "push_enabled" not in configuration or configuration[
            "push_enabled"
        ] not in [
            "yes",
            "no",
        ]:
            self.logger.error(
                "Mimecast Plugin: Invalid value provided for 'Push Enabled'."
                " Allowed value is one of 'yes' or 'no'."
            )
            return ValidationResult(
                success=False,
                message="Invalid value provided for 'Push Enabled'."
                " Allowed value is one of 'yes' or 'no'.",
            )

        validation_result, packages = self._validate_credentials(configuration)

        # If credentials are invalid
        if not validation_result.success:
            return validation_result

        # If credentials are valid but package is not enabled and push is configured
        if (
            configuration["push_enabled"] == "yes"
            and "BYO: Threat Intelligence [1089]" not in packages
        ):
            self.logger.error(
                "Mimecast Plugin: 'Bring Your Own Threat Intel' package is not enabled in "
                "configured account and hence push is not supported. Disable push and try again."
            )
            return ValidationResult(
                success=False,
                message="'Bring Your Own Threat Intel' package is not enabled in configured "
                "account and hence push is not supported. Disable push and try again.",
            )

        return validation_result

    def get_actions(self):
        """Get available actions."""
        return [
            ActionWithoutParams(label="Perform Operation", value="operation"),
        ]

    def validate_action(self, action: Action):
        """Validate Mimecast configuration."""
        if action.value not in ["operation"]:
            return ValidationResult(
                success=False, message="Unsupported target provided."
            )

        if action.parameters.get("operation_type") not in [
            "ALLOW",
            "BLOCK",
            "DELETE",
        ]:
            return ValidationResult(
                success=False,
                message="Invalid value of Operation Type provided.",
            )

        return ValidationResult(success=True, message="Validation successful.")

    def get_action_fields(self, action: Action):
        """Get fields required for an action."""
        if action.value == "operation":
            return [
                {
                    "label": "Operation Type",
                    "key": "operation_type",
                    "type": "choice",
                    "choices": [
                        {"key": "ALLOW", "value": "ALLOW"},
                        {"key": "BLOCK", "value": "BLOCK"},
                        {"key": "DELETE", "value": "DELETE"},
                    ],
                    "mandatory": True,
                    "default": "ALLOW",
                    "description": "The action to take based on the batch of indicators. \
                    For example, a file-hash can be added with a BLOCK action to prevent the delivery \
                    of a message with an attachment matching that file-hash.",
                }
            ]
