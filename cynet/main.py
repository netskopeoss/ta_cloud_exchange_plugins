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

CTE Cynet Plugin's main file which contains the implementation of all the
plugin's methods.
"""

import datetime
import traceback


from urllib.parse import urlparse
from typing import Dict, List, Tuple

from netskope.integrations.cte.models.business_rule import (
    Action,
    ActionWithoutParams,
)
from netskope.integrations.cte.models import (
    Indicator,
    SeverityType,
    IndicatorType,
)
from netskope.integrations.cte.plugin_base import (
    PluginBase,
    PushResult,
    ValidationResult,
)


from .utils.cynet_helper import CynetPluginHelper, CynetPluginException
from .utils.cynet_constants import (
    SEVERITY_TYPES,
    NETSKOPE_SEVERITY_TYPES,
    DEFAULT_BATCH_SIZE,
    CYNET_URLS,
    DATE_FORMAT_FOR_IOCS,
    MODULE_NAME,
    PLUGIN_NAME,
    PLUGIN_VERSION,
    THREAT_TYPES_TO_INTERNAL_TYPE,
    CYNET_ALERT_VALUE,
    NETSKOPE_DATE_FORMAT_FOR_IOCS,
    PLATFORM_NAME,
    THREAT_TYPES,
    GET_ACTION_LABEL,
    GET_URLS_FROM_LABEL,
    INTEGER_THRESHOLD,
)


class CynetPlugin(PluginBase):
    """Cynet Plugin class having implementation of all plugin's methods."""

    def __init__(self, name, *args, **kwargs):
        """Cynet plugin initializer
        Args:
           name (str): Plugin configuration name.
        """
        super().__init__(name, *args, **kwargs)
        self.plugin_name, self.plugin_version = self._get_plugin_info()
        self.log_prefix = f"{MODULE_NAME} {self.plugin_name}"

        if name:
            self.log_prefix = f"{self.log_prefix} [{name}]"

        self.cynet_helper = CynetPluginHelper(
            logger=self.logger,
            log_prefix=self.log_prefix,
            plugin_name=self.plugin_name,
            plugin_version=self.plugin_version,
            ssl_validation=self.ssl_validation,
            proxy=self.proxy,
        )

    def _get_plugin_info(self) -> Tuple:
        """Get plugin name and version from manifest.

        Returns:
            tuple: Tuple of plugin's name and version pulled from manifest.
        """
        try:
            manifest_json = CynetPlugin.metadata
            plugin_name = manifest_json.get("name", PLUGIN_NAME)
            plugin_version = manifest_json.get("version", PLUGIN_VERSION)
            return plugin_name, plugin_version
        except Exception as exp:
            self.logger.error(
                message=(
                    f"{MODULE_NAME} {PLUGIN_NAME}: Error occurred while"
                    f" getting plugin details. Error: {exp}"
                ),
                details=str(traceback.format_exc()),
            )
        return PLUGIN_NAME, PLUGIN_VERSION

    def _get_credentials(self, configuration: Dict) -> Tuple:
        """Get API Credentials.

        Args:
            configuration (Dict): Configuration dictionary.

        Returns:
            Tuple: Tuple containing Base URL, Client ID and Client Secret.
        """
        return (
            configuration.get("base_url", "").strip().strip("/"),
            configuration.get("client_id"),
            configuration.get("user_name", "").strip(),
            configuration.get("password", ""),
        )

    def validate(self, configuration) -> ValidationResult:
        """Validate the Plugin configuration parameters.
        Args:
           configuration (dict): Dict object having all the Plugin
           configuration parameters.
        Returns:
           cte.plugin_base.ValidateResult: ValidateResult object with
           success flag and message.
        """
        (base_url, client_id, user_name, password) = self._get_credentials(
            configuration
        )
        initial_range = configuration.get("initial_range")
        validation_err_message = "Validation error occurred."

        # Validate base_url
        if not base_url:
            err_msg = "Base URL is a required configuration parameter."
            self.logger.error(
                f"{self.log_prefix}: {validation_err_message} {err_msg}"
            )
            return ValidationResult(success=False, message=err_msg)
        elif not self._validate_url(base_url):
            err_msg = (
                "Invalid Base URL provided in the configuration parameters."
            )
            self.logger.error(
                f"{self.log_prefix}: {validation_err_message} {err_msg}"
            )
            return ValidationResult(success=False, message=err_msg)

        # Validate client_id
        if client_id is None:
            err_msg = "Client ID is a required configuration parameter."
            self.logger.error(
                f"{self.log_prefix}: {validation_err_message} {err_msg}"
            )
            return ValidationResult(success=False, message=err_msg)
        elif (
            not isinstance(client_id, int)
            or client_id < 0
            or client_id > INTEGER_THRESHOLD
        ):
            err_msg = (
                "Invalid Client ID provided in the configuration parameters."
            )
            self.logger.error(
                f"{self.log_prefix}: {validation_err_message} {err_msg}"
            )
            return ValidationResult(success=False, message=err_msg)

        # Validate user_name
        if not user_name:
            err_msg = "Username is a required configuration parameter."
            self.logger.error(
                f"{self.log_prefix}: {validation_err_message} {err_msg}"
            )
            return ValidationResult(success=False, message=err_msg)
        elif not isinstance(user_name, str):
            err_msg = (
                "Invalid Username provided in the configuration parameters."
            )
            self.logger.error(
                f"{self.log_prefix}: {validation_err_message} {err_msg}"
            )
            return ValidationResult(success=False, message=err_msg)

        # Validate password
        if not password:
            err_msg = "Password is a required configuration parameter."
            self.logger.error(
                f"{self.log_prefix}: {validation_err_message} {err_msg}"
            )
            return ValidationResult(success=False, message=err_msg)
        elif not isinstance(password, str):
            err_msg = (
                "Invalid Password provided in the configuration parameters."
            )
            self.logger.error(
                f"{self.log_prefix}: {validation_err_message} {err_msg}"
            )
            return ValidationResult(success=False, message=err_msg)

        # Validate Enable Pooling.
        is_pull_required = configuration.get("is_pull_required", "").strip()
        if not is_pull_required:
            err_msg = "Enable Polling is a required configuration parameter."
            self.logger.error(
                f"{self.log_prefix}: {validation_err_message} {err_msg}"
            )
            return ValidationResult(success=False, message=err_msg)

        elif is_pull_required not in [
            "Yes",
            "No",
        ]:
            err_msg = (
                "Invalid value provided in Enable Polling configuration"
                " parameter. Allowed values are Yes and No."
            )
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )

        # Validate initial_range
        if initial_range is None:
            err_msg = "Initial Range is a required configuration parameters."
            self.logger.error(
                f"{self.log_prefix}: {validation_err_message} {err_msg}"
            )
            return ValidationResult(success=False, message=err_msg)
        elif not isinstance(initial_range, int):
            err_msg = (
                "Invalid Initial Range provided in the "
                "configuration parameters."
            )
            self.logger.error(
                f"{self.log_prefix}: {validation_err_message} {err_msg}"
            )
            return ValidationResult(success=False, message=err_msg)
        elif initial_range < 0 or initial_range > INTEGER_THRESHOLD:
            err_msg = (
                "Invalid Initial Range provided in configuration"
                " parameters. Valid value should be in range 0 to 2^62."
            )
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )

        return self._validate_auth_params(base_url, user_name, password)

    def _validate_url(self, url: str) -> bool:
        """Validate the URL using parsing.

        Args:
            url (str): Given URL.

        Returns:
            bool: True or False { Valid or not Valid URL }.
        """
        parsed = urlparse(url)
        return (
            parsed.scheme.strip() != ""
            and parsed.netloc.strip() != ""
            and (parsed.path.strip() == "/" or parsed.path.strip() == "")
        )

    def _validate_auth_params(
        self, base_url, user_name, password
    ) -> ValidationResult:
        """Validate Cynet Authentication Parameters.
        Args:
           - base_url (str): Cynet API Domain.
           - user_name (str): Login Credentials.
           - password (str): Login Credentials.
        Returns:
           cte.plugin_base.ValidationResult: ValidationResult object with
           success flag and message.
        """
        try:
            access_token = self._generate_access_token(
                base_url, user_name, password, is_validation=True
            )
            if access_token:
                msg = (
                    "Successfully validated configuration"
                    f" for {PLUGIN_NAME} plugin."
                )
                self.logger.info(f"{self.log_prefix}: {msg}")
                return ValidationResult(
                    success=True,
                    message=msg,
                )
        except CynetPluginException as cynet_err:
            return ValidationResult(success=False, message=str(cynet_err))
        except Exception as exp:
            err_msg = "Unexpected validation error occurred."
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}, Error: {str(exp)}",
                details=str(traceback.format_exc()),
            )
            return ValidationResult(
                success=False,
                message=f"{err_msg}, Check logs for more details.",
            )

    def _generate_access_token(
        self, base_url, user_name, password, is_validation=False
    ) -> Dict:
        """Generate Access Token via Cynet Authentication API.
        Args:
           - base_url (str): Cynet API Domain.
           - user_name (str): Login Credentials.
           - password (str): Login Credentials.
        Returns:
           A dict containing access_token.
        """
        auth_payload = {"user_name": user_name, "password": password}
        auth_url = CYNET_URLS["AUTHENTICATION"].format(base_url=base_url)
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
        }
        auth_resp = self.cynet_helper.api_helper(
            logger_msg=f"validating {PLATFORM_NAME} Authentication Parameters.",  # noqa
            url=auth_url,
            method="POST",
            json=auth_payload,
            headers=headers,
            is_handle_error_required=False,
            is_validation=is_validation,
        )

        if auth_resp.ok:
            resp_json = self.cynet_helper.parse_response(
                auth_resp, is_validation
            )
            access_token = resp_json.get("access_token")
            if not access_token:
                err_msg = (
                    "No access token or OAuth2 token found in"
                    " the API Response."
                )
            else:
                self.logger.debug(
                    f"{self.log_prefix}: Successfully pulled OAuth2 "
                    f"token from {PLATFORM_NAME}."
                )
                if self.storage is not None:
                    self.storage[
                        "token_expiry"
                    ] = datetime.datetime.now() + datetime.timedelta(
                        seconds=int(resp_json.get("expires_in", 3600))
                    )
                return access_token
        elif auth_resp.status_code == 400:
            err_msg = (
                "Received exit code 400, Verify Base URL "
                "provided in the configuration parameters."
            )
        elif auth_resp.status_code == 401:
            err_msg = (
                "Received exit code 401, Unauthorized access. "
                "Verify Username/Password or API Key provided in the"
                " configuration parameters."
            )
        elif auth_resp.status_code == 403:
            err_msg = (
                "Received exit code 403, Forbidden access. "
                "Verify API Scope assigned to the user "
                "or API Key provided in the configuration parameters."
            )
        elif auth_resp.status_code == 404:
            err_msg = (
                "Received exit code 400, Verify Base URL "
                "provided in the configuration parameters."
            )
        else:
            err_msg = (
                f"Received exit code {str(auth_resp.status_code)}"
                f"Error occurred while pulling OAuth2 token."
            )
        self.logger.error(
            message=f"{self.log_prefix}: {err_msg}",
            details=(
                f"{PLATFORM_NAME} Authentication API Response:"
                f" {auth_resp.text}"
            ),
        )
        raise CynetPluginException(err_msg)

    def _reload_auth_token(self, headers: Dict) -> Dict:
        """Reload the OAUTH2 token after Expiry.

        Args:
            headers (Dict): Headers

        Returns:
            Dict: Dictionary containing auth token.
        """
        base_url, client_id, username, password = self._get_credentials(
            self.configuration
        )
        if self.storage is None or self.storage.get("token_expiry") < (
            datetime.datetime.now() + datetime.timedelta(seconds=5)
        ):
            # If storage is None then generate the auth token.
            auth_token = self._generate_access_token(
                base_url=base_url,
                user_name=username,
                password=password,
            )
            headers.update({"access_token": auth_token})
        return headers

    def get_cynet_severity(self, severity: int) -> List[Dict]:
        """Get cynet severity from constants mappings.
        And, convert it to Netskope CE severity level.
        """
        try:
            return NETSKOPE_SEVERITY_TYPES[SEVERITY_TYPES[severity]]
        except KeyError:
            self.logger.error(
                f"{self.log_prefix}: Received Unknown {PLATFORM_NAME} "
                f"severity type {severity}."
            )
            return SeverityType.UNKNOWN

    def _get_cynet_last_seen(self) -> str:
        """Get Cynet LastSeen Or DateChanged parameter.
        Returns:
            LastSeen/DateChanged (str):
                A datetime object as string representation.
        """
        if not self.last_run_at:
            self.last_run_at = datetime.datetime.now() - datetime.timedelta(
                days=int(self.configuration.get("initial_range"))
            )
        return self.last_run_at.strftime(DATE_FORMAT_FOR_IOCS)

    def _get_headers(self, access_token: str, client_id: int) -> Dict:
        return {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "access_token": access_token,
            "client_id": str(client_id),
        }

    def pull(self) -> List[Indicator]:
        """Pull indicators from Cynet.

        Returns:
            List[Indicator]: List of indictors fetched from Cynet.
        """
        is_pull_required = self.configuration.get(
            "is_pull_required", "Yes"
        ).strip()
        if is_pull_required == "No":
            self.logger.info(
                f"{self.log_prefix}: Polling is disabled in configuration "
                "parameter hence skipping pulling of indicators from "
                f"{PLATFORM_NAME}."
            )
            return []
        if hasattr(self, "sub_checkpoint"):

            def wrapper(self):
                yield from self._pull()

            return wrapper(self)

        else:
            indicators = []
            for batch in self._pull():
                indicators.extend(batch)

            total_counts_msg = (
                f"Successfully fetched {len(indicators)} indicator(s) "
                f"from {PLATFORM_NAME}."
            )
            self.logger.info(f"{self.log_prefix}: {total_counts_msg}")
            return indicators

    def _pull(self):
        """Retrieves all the alerts that were triggered since the specified
          time,
        with pagination options. Every listing includes alert properties.

        Returns:
            List[cte.models.Indicators]: List of indicator objects pulled
            from the Cynet platform.
        """
        (base_url, client_id, user_name, password) = self._get_credentials(
            self.configuration
        )

        # Get a last_seen datetime as string representations.
        # For retrieving indicators
        sub_checkpoint = getattr(self, "sub_checkpoint", None)
        if sub_checkpoint:
            checkpoint = sub_checkpoint.get("checkpoint")
        else:
            checkpoint = self._get_cynet_last_seen()
        limit = DEFAULT_BATCH_SIZE  # Default to 100 records per page.
        cynet_paginated_alerts = CYNET_URLS["GET_ALERTS_PAGINATION"].format(
            base_url=base_url
        )

        # Refresh Access Token
        access_token = self._generate_access_token(
            base_url=base_url, user_name=user_name, password=password
        )

        self.logger.info(
            f"{self.log_prefix}: Pulling indicators from {PLATFORM_NAME}"
            f" platform using checkpoint: {checkpoint}"
        )
        headers = self._get_headers(access_token, client_id)

        query_params = {"LastSeen": checkpoint, "Limit": limit, "Offset": 0}

        next_page = True
        page_count = 1
        alerts_checkpoint = checkpoint
        total_indicators = 0
        try:
            while next_page:
                logger_msg = (
                    f"pulling alerts for page {page_count} "
                    f"from {PLATFORM_NAME}"
                )
                headers = self._reload_auth_token(headers)
                indicators_resp = self.cynet_helper.api_helper(
                    logger_msg=logger_msg,
                    url=cynet_paginated_alerts,
                    method="GET",
                    params=query_params,
                    headers=headers,
                    is_handle_error_required=True,
                )
                entities = indicators_resp.get("Entities", [])

                # if the response contains less indicators then
                # page limit (DEFAULT_BATCH_SIZE),
                # that there are no more indicators to pull from cynet.
                if not entities or len(entities) < limit:
                    next_page = False

                (parsed_indicators, indicators_per_page, alerts_checkpoint) = (
                    self._parse_cynet_indicators_response(entities=entities)
                )
                page_iocs = len(parsed_indicators)
                total_indicators += page_iocs
                count_per_page_msg = (
                    "Successfully fetched {total} indicator(s) and skipped "
                    "{skipped} indicator(s) in page {page}. Pull Stats: "
                    "SHA256={sha256}, Domain={domain}, IP={ip}, URL={url},"
                    " Total indicator(s) fetched: {total_indicators}".format(
                        total=indicators_per_page["total"],
                        skipped=indicators_per_page["skipped"],
                        page=page_count,
                        sha256=indicators_per_page["sha256"],
                        domain=indicators_per_page["domain"],
                        ip=indicators_per_page["ip"],
                        url=indicators_per_page["url"],
                        total_indicators=total_indicators,
                    )
                )
                self.logger.info(f"{self.log_prefix}: {count_per_page_msg}")

                # Set offset += limit
                query_params["Offset"] += limit
                if hasattr(self, "sub_checkpoint"):
                    yield parsed_indicators, {"checkpoint": alerts_checkpoint}
                else:
                    yield parsed_indicators

                # Set page Number
                page_count += 1
        except CynetPluginException as cynet_err:
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Error Occurred while pulling "
                    f"indicators from {PLATFORM_NAME}. Error: {cynet_err}"
                ),
                details=traceback.format_exc(),
            )
            raise CynetPluginException(str(cynet_err))
        except Exception as exp:
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Unexpected error "
                    f"occurred while pulling/parsing indicators "
                    f"from {PLATFORM_NAME}. Error: {exp}"
                ),
                details=traceback.format_exc(),
            )

    def _parse_cynet_indicators_response(
        self, entities: List[Dict]
    ) -> Tuple[List[Indicator], Dict]:
        """Parse cynet alerts with pagination API response.
        And, create an objects Indicator class.
        Along with that return the pulling stats of alert types.
        Args:
            - entities (List[Dict]): A nested structure containing list
              of alert.
        Returns:
            - List[cte.models.Indicators]: List of indicator objects pulled
            from the Cynet platform.
            - indicators_per_page (Dict): Containing the pull stats of counts.
        """
        parsed_indicators = []
        indicators_per_page = {
            "total": 0,
            "sha256": 0,
            "domain": 0,
            "url": 0,
            "ip": 0,
            "skipped": 0,
        }
        alerts_checkpoint = None
        for alert in entities:

            try:
                alerts_checkpoint = alert.get(
                    "LastSeen",
                    str(
                        datetime.datetime.now().strftime(DATE_FORMAT_FOR_IOCS)
                    ),
                )
                alert_type = str(alert.get("AlertType"))

                parsed_alert_type = THREAT_TYPES_TO_INTERNAL_TYPE.get(
                    alert_type
                )
                if not parsed_alert_type:
                    # Alert Types are not supported by Netskope.
                    # E.g., User, Host, System
                    indicators_per_page["skipped"] += 1
                    continue

                value = alert.get(CYNET_ALERT_VALUE.get(alert_type, ""), "")
                # validate Threat and increase threat counter
                indicator_type, skipped = self._detect_alert_type(alert_type)
                if skipped:
                    indicators_per_page["skipped"] += 1
                    continue

                utc_now = datetime.datetime.utcnow().strftime(
                    NETSKOPE_DATE_FORMAT_FOR_IOCS
                )
                first_seen = alert.get("FirstSeenUtc", utc_now)
                last_seen = alert.get("LastSeenUtc", utc_now)
                parsed_indicators.append(
                    Indicator(
                        value=value,
                        type=parsed_alert_type,
                        firstSeen=first_seen,
                        lastSeen=last_seen,
                        severity=NETSKOPE_SEVERITY_TYPES[
                            alert.get("Severity", "99")
                        ],  # Default to UNKNOWN
                        comments=alert.get("IncidentDescription", ""),
                        extendedInformation=alert.get("AlertUrl", ""),
                    )
                )
                indicators_per_page[indicator_type] += 1
                indicators_per_page["total"] += 1
            except Exception as exp:
                err_msg = "Error occurred while creating the indicator from "
                f"alert having alert ID {alert['ClientDbId']} hence this "
                "record will be skipped."
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg} Error: {exp}",
                    details=traceback.format_exc(),
                )
                indicators_per_page["skipped"] += 1
                continue
        return parsed_indicators, indicators_per_page, alerts_checkpoint

    def _detect_alert_type(self, alert_type: str) -> Tuple[str, bool]:
        detected = THREAT_TYPES.get(alert_type)
        if not detected:
            return "skipped", True
        return detected, False

    def get_actions(self):
        """Get available actions."""
        return [
            ActionWithoutParams(
                label="Perform Remediation Action",
                value="perform_remediation_action",
            ),
        ]

    def get_action_fields(self, action: Action):
        """Get fields required for an action."""
        action_value = action.value
        choices = [
            {"key": "Delete File", "value": "delete_file"},
            {
                "key": "Quarantine",
                "value": "quarantine",
            },
            {"key": "Unquarantine", "value": "unquarantine"},
            {"key": "Verify File", "value": "verify_file"},
            {"key": "Kill Process", "value": "kill_process"},
        ]
        sorted_choices = sorted(choices, key=lambda x: x["key"])
        if action_value == "perform_remediation_action":
            return [
                {
                    "label": "Remediation Action",
                    "key": "remediation_action",
                    "type": "choice",
                    "choices": sorted_choices,
                    "default": "delete_file",
                    "mandatory": True,
                    "description": (
                        "Select the Remediation Action to perform"
                        " on file having SHA256 value."
                    ),
                }
            ]

    def validate_action(self, action: Action) -> ValidationResult:
        """Validate Cynet Push action configuration.

        Args:
            action (Action): Action to perform on IoCs.

        Returns:
            ValidationResult: Validation result.
        """
        action_value = action.value
        if action_value not in ["perform_remediation_action"]:
            return ValidationResult(
                success=False, message="Unsupported action provided."
            )

        if action_value == "perform_remediation_action":
            if action.parameters.get("remediation_action") not in [
                "delete_file",
                "quarantine",
                "unquarantine",
                "verify_file",
                "kill_process",
            ]:
                err_msg = (
                    "Invalid action selected. Allowed values are "
                    "Delete File, Quarantine, Unquarantine, "
                    "Verify File and Kill Process."
                )
                self.logger.error(f"{self.log_prefix}: {err_msg}")
                return ValidationResult(success=False, message=err_msg)

        return ValidationResult(success=True, message="Validation successful.")

    def push(self, indicators: List[Indicator], action_dict: Dict):
        """Push the Indicator list to Cynet.

        Args:
            indicators (List[cte.models.Indicators]): List of Indicator
            objects to be pushed.
        Returns:
            cte.plugin_base.PushResult: PushResult object with success
            flag and Push result message.
        """
        action_label = action_dict.get("label")
        self.logger.info(
            f"{self.log_prefix}: Executing push method for "
            f'"{action_label}" target action.'
        )
        action_value = action_dict.get("value")
        if action_value == "perform_remediation_action":
            remediation_action = action_dict.get("parameters", {}).get(
                "remediation_action"
            )
            filtered_sha256, skip_count = self._filter_indicators(indicators)
            action_label = GET_ACTION_LABEL[remediation_action]
            if not filtered_sha256:
                log_msg = (
                    "No SHA256 found in the indicators hence "
                    f"{action_label} Remediation Action will not perform."
                )
                self.logger.info(f"{self.log_prefix}: {log_msg}")
                return PushResult(success=True, message=log_msg)
            self.logger.info(
                f"{self.log_prefix}: {action_label} "
                f"action will be performed on {len(filtered_sha256)} "
                f"indicators and skipped {skip_count} indicator(s) as "
                "they were not of type SHA256."
            )
            try:
                return self._perform_action(
                    filtered_sha256, remediation_action
                )
            except Exception as exp:
                err_msg = (
                    "Error occurred while executing Remediation Action"
                    f" on {PLATFORM_NAME}."
                )
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg} Error: {exp}",
                    details=traceback.format_exc(),
                )
                raise CynetPluginException(err_msg)
        else:
            err_msg = (
                "Unsupported action selected, Allowed value"
                " is Remediation Actions."
            )
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            raise CynetPluginException(err_msg)

    def _filter_indicators(
        self, indicators: List[Indicator]
    ) -> List[Indicator]:
        """Filter indicators list. Remove indicators with empty SHA256."""
        sha256, skip_count = [], 0
        for indicator in indicators:
            if indicator.type == IndicatorType.SHA256:
                sha256.append(indicator.value)
            else:
                skip_count += 1
        return sha256, skip_count

    def _perform_action(self, sha256_values, remediation_action):
        """Perform Action.

        Args:
            sha256_values (List[str]): List of sha256 values.
            remediation_action (str): Remediation Action.
        Returns:
            cte.plugin_base.PushResult: PushResult object with success
            flag and Push result message.
        """
        action_label = GET_ACTION_LABEL[remediation_action]
        base_url, client_id, username, password = self._get_credentials(
            self.configuration
        )
        url = CYNET_URLS[GET_URLS_FROM_LABEL[remediation_action]].format(
            base_url=base_url
        )
        access_token = self._generate_access_token(
            base_url, username, password
        )
        headers = self._get_headers(access_token, client_id)
        fail_count = 0
        success_count = 0
        for sha256 in sha256_values:
            payload = {"sha256": sha256, "host": None}
            headers = self._reload_auth_token(headers)
            try:
                self.cynet_helper.api_helper(
                    url=url,
                    method="POST",
                    headers=headers,
                    json=payload,
                    logger_msg=(
                        f"executing {action_label} remediation action "
                        f"for SHA256 value {sha256}"
                    ),
                )
                success_count += 1
                self.logger.info(
                    f"{self.log_prefix}: Successfully executed {action_label}"
                    f" remediation action for SHA256 value {sha256}."
                    f" Total executed: {success_count}."
                )
            except CynetPluginException:
                fail_count += 1
            except Exception as exp:
                err_msg = (
                    f"Error occurred while executing {action_label} "
                    f"remediation action. Error: {exp}"
                )
                self.logger.error(
                    message=err_msg, details=str(traceback.format_exc())
                )
                fail_count += 1

        log_msg = (
            f"Successfully executed {action_label} remediation"
            f" action on {len(sha256_values) - fail_count} SHA256 values"
        )
        if fail_count > 0:
            log_msg += f" and failed to execute on {fail_count} SHA256 values"

        self.logger.info(f"{self.log_prefix}: {log_msg}.")
        return PushResult(success=True, message=f"{log_msg}.")
