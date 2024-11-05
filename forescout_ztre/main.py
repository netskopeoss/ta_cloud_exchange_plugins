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

CRE CrowdStrike Cloud Security plugin.
"""

import traceback
from urllib.parse import urlparse

from netskope.integrations.crev2.models import Action, ActionWithoutParams
from netskope.integrations.crev2.plugin_base import (
    Entity,
    EntityField,
    EntityFieldType,
    PluginBase,
    ValidationResult,
)

from .utils.constants import (
    HOST_MAPPING,
    MODULE_NAME,
    PLATFORM_NAME,
    PLUGIN_NAME,
    PLUGIN_VERSION,
)
from .utils.helper import ForescoutPluginException, ForescoutPluginHelper


class ForescoutPlugin(PluginBase):
    """Forescout Cloud Security plugin Class."""

    def __init__(
        self,
        name,
        *args,
        **kwargs,
    ):
        """Forescout Cloud Security plugin initializer.

        Args:
            name (str): Plugin configuration name.
        """
        super().__init__(
            name,
            *args,
            **kwargs,
        )
        self.plugin_name, self.plugin_version = self._get_plugin_info()
        self.log_prefix = f"{MODULE_NAME} {self.plugin_name}"
        if name:
            self.log_prefix = f"{self.log_prefix} [{name}]"
        self.forescout_helper = ForescoutPluginHelper(
            logger=self.logger,
            plugin_name=self.plugin_name,
            plugin_version=self.plugin_version,
            log_prefix=self.log_prefix,
            configuration=self.configuration,
        )

    def _get_plugin_info(self) -> tuple:
        """Get plugin name and version from manifest.

        Returns:
            tuple: tuple of plugin's name and version fetched from manifest.
        """
        try:
            manifest_json = ForescoutPlugin.metadata
            plugin_name = manifest_json.get("name", PLUGIN_NAME)
            plugin_version = manifest_json.get("version", PLUGIN_VERSION)
            return plugin_name, plugin_version
        except Exception as exp:
            self.logger.error(
                message=(
                    "{} {}: Error occurred while"
                    " getting plugin details. Error: {}".format(
                        MODULE_NAME, PLUGIN_NAME, exp
                    )
                ),
                details=traceback.format_exc(),
            )
        return (PLUGIN_NAME, PLUGIN_VERSION)

    def get_entities(self) -> list[Entity]:
        """Get available entities."""
        return [
            Entity(
                name="Hosts",
                fields=[
                    EntityField(
                        name="Host ID",
                        type=EntityFieldType.STRING,
                        required=True,
                    ),
                    EntityField(
                        name="Classification Score",
                        type=EntityFieldType.NUMBER,
                    ),
                    EntityField(
                        name="CYSIV Risk Device Criticality",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="CYSIV Risk Score",
                        type=EntityFieldType.NUMBER,
                    ),
                    EntityField(
                        name="CYSIV Risk Severity",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="Discovery Score",
                        type=EntityFieldType.NUMBER,
                    ),
                    EntityField(
                        name="Firmware Classification Score",
                        type=EntityFieldType.NUMBER,
                    ),
                    EntityField(
                        name="Host Mac Address",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="Model Classification Score",
                        type=EntityFieldType.NUMBER,
                    ),
                    EntityField(
                        name="OS Discovery Score",
                        type=EntityFieldType.NUMBER,
                    ),
                    EntityField(
                        name="OT Criticality",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="OT Operational Risk",
                        type=EntityFieldType.NUMBER,
                    ),
                    EntityField(
                        name="OT Security Risk",
                        type=EntityFieldType.NUMBER,
                    ),
                    EntityField(
                        name="Prim Discovery Score",
                        type=EntityFieldType.NUMBER,
                    ),
                    EntityField(
                        name="Vendor Classification Score",
                        type=EntityFieldType.NUMBER,
                    ),
                    EntityField(
                        name="Netskope Normalized Score",
                        type=EntityFieldType.NUMBER,
                    ),
                ],
            ),
        ]

    def _extract_field_from_event(
        self, key: str, event: dict, default, transformation=None
    ):
        """Extract field from event.

        Args:
            key (str): Key to fetch.
            event (dict): Event dictionary.
            default (str,None): Default value to set.
            transformation (str, None, optional): Transformation
                to perform on key. Defaults to None.

        Returns:
            Any: Value of the key from event.
        """
        keys = key.split(".")
        while keys:
            k = keys.pop(0)
            if k not in event and default is not None:
                return default
            event = event.get(k, {})
        if transformation and transformation == "string":
            return str(event)
        elif transformation and transformation == "integer":
            return int(event)
        elif transformation and transformation == "float":
            return float(event)
        return event

    def add_field(self, fields_dict: dict, field_name: str, value):
        """Function to add field to the extracted_fields dictionary.

        Args:
            fields_dict (dict): Field dictionary to update.
            field_name (str): Field name to add.
            value: Field to add.
        """
        if isinstance(value, int):
            fields_dict[field_name] = value
            return
        if value:
            fields_dict[field_name] = value

    def normalize_security_risk_score(self, forescout_score):
        """
        Normalize the Forescout OT Security Risk score and Forescout Data
        Exchange Security Risk Score to the Netskope Risk score range.

        Forescout Risk Score Ranges:
        - Low: 0 - 3.9
        - Medium: 4.0 - 6.9
        - High: 7.0 - 8.9
        - Critical: 9.0 - 10.0

        Netskope Risk Score Ranges:
        - Critical: 0 - 250
        - High: 251 - 500
        - Medium: 501 - 750
        - Low: 751 - 1000

        Args:
            forescout_score: The OT Security Risk score from
            Forescout (0.0 - 10.0)
        Returns:
            The normalized risk score for Netskope (0 - 1000)
        """
        forescout_score = float(forescout_score)
        if forescout_score < 0 or forescout_score > 10:
            self.logger.error(
                f"{self.log_prefix}: Invalid {PLATFORM_NAME} score"
                f" received from API. Score: {forescout_score}. "
                "Valid value should be between 0 and 10. Skipping this score."
            )
            return

        if forescout_score <= 3.9:
            # Low Risk (Forescout) -> Low (Netskope: 751 - 1000)
            return int((forescout_score / 3.9) * (1000 - 751) + 751)
        elif forescout_score <= 6.9:
            # Medium Risk (Forescout) -> Medium (Netskope: 501 - 750)
            return int(((forescout_score - 4.0) / 2.9) * (750 - 501) + 501)
        elif forescout_score <= 8.9:
            # High Risk (Forescout) -> High (Netskope: 251 - 500)
            return int(((forescout_score - 7.0) / 1.9) * (500 - 251) + 251)
        else:
            # Critical Risk (Forescout) -> Critical (Netskope: 0 - 250)
            return int(((forescout_score - 9.0) / 1.0) * 250)

    def extract_host_fields(
        self,
        host: dict,
        normalization_field: str,
        include_normalization: bool = True,
    ) -> dict:
        """Extract Host Fields.

        Args:
            host (dict): Host dictionary.
            normalization_field (tr): Normalization Field.
            include_normalization (bool, optional): Include Normalization
              or not. Defaults to True.

        Returns:
            Dict: Dictionary of extracted fields.
        """
        extracted_fields = {}
        for (
            field_name,
            field_value,
        ) in HOST_MAPPING.items():
            key, default, transformation = (
                field_value.get("key"),
                field_value.get("default"),
                field_value.get("transformation"),
            )
            self.add_field(
                extracted_fields,
                field_name,
                self._extract_field_from_event(
                    key, host, default, transformation
                ),
            )

        if include_normalization:

            if normalization_field == "otsm_details_security_risk":
                otsm_details_security_risk = (
                    host.get("host", {})
                    .get("fields", {})
                    .get("otsm_details_security_risk", {})
                    .get("value")
                )

                if otsm_details_security_risk:
                    extracted_fields["Netskope Normalized Score"] = (
                        self.normalize_security_risk_score(
                            otsm_details_security_risk
                        )
                    )
            elif normalization_field == "cysiv_risk_score":
                cysiv_risk_score = (
                    host.get("host", {})
                    .get("fields", {})
                    .get("cysiv_risk_score", {})
                    .get("value")
                )
                if cysiv_risk_score:
                    extracted_fields["Netskope Normalized Score"] = (
                        self.normalize_security_risk_score(cysiv_risk_score)
                    )
        return extracted_fields

    def get_hosts(self, normalization_field) -> list[dict]:
        """Get hosts from Forescout platform.

        Returns:
            list[dict]: List of hosts.
        """
        records = []
        skip_count = 0
        page_count = 1
        etag = None
        base_url, username, password = self.forescout_helper.get_credentials(
            self.configuration
        )

        headers = self.forescout_helper.get_auth_header(
            username,
            password,
            base_url,
            self.ssl_validation,
            self.proxy,
        )
        api_endpoint = f"{base_url}/api/hosts"
        try:
            while True:
                page_hosts = 0
                if etag:
                    headers["If-None-Match"] = etag
                response = self.forescout_helper.api_helper(
                    method="GET",
                    url=api_endpoint,
                    headers=headers,
                    proxies=self.proxy,
                    verify=self.ssl_validation,
                    logger_msg=(
                        f"fetching hosts for page {page_count} "
                        f"from {PLATFORM_NAME}"
                    ),
                    is_handle_error_required=False,
                )
                if response.status_code == 304:
                    self.logger.debug(
                        f"{self.log_prefix}: No additional hosts remaining"
                        " to fetch."
                    )
                    break
                elif response.status_code != 200:
                    resp_json = self.forescout_helper.handle_error(
                        resp=response,
                        logger_msg=(
                            f"fetching hosts for page {page_count} "
                            f"from {PLATFORM_NAME}"
                        ),
                    )

                resp_json = self.forescout_helper.parse_response(
                    response=response
                )

                for host in resp_json.get("hosts", []):
                    host_id = host.get("hostId")
                    if host_id:
                        resp_json = self.forescout_helper.api_helper(
                            method="GET",
                            url=f"{base_url}/api/hosts/{host_id}",
                            headers=headers,
                            proxies=self.proxy,
                            verify=self.ssl_validation,
                            logger_msg=(
                                "fetching host details for "
                                f"{host_id} from {PLATFORM_NAME}"
                            ),
                        )
                        if resp_json.get("host", {}).get("id"):
                            records.append(
                                self.extract_host_fields(
                                    resp_json, normalization_field, False
                                )
                            )
                            page_hosts += 1
                        else:
                            skip_count += 1
                            continue
                    else:
                        skip_count += 1
                        continue

                if not resp_json.get("hosts", []):
                    break

                etag = response.headers.get("ETag")

                self.logger.info(
                    f"{self.log_prefix}: Successfully fetched {page_hosts}"
                    f"host(s) in page {page_count}. Total hosts fetched: "
                    f"{len(records)}."
                )

                page_count += 1

            if skip_count > 0:
                self.logger.info(
                    f"{self.log_prefix}: Skipped {skip_count} host(s) "
                    f"because they might not contain hostId in their "
                    "response or fields could not be extracted from them."
                )
            self.logger.info(
                f"{self.log_prefix}: Successfully fetched {len(records)} "
                f"host(s) from {PLATFORM_NAME}."
            )
            return records
        except ForescoutPluginException:
            raise
        except Exception as exp:
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Error occurred while getting "
                    f"hosts. Error: {exp}"
                ),
                details=traceback.format_exc(),
            )

    def fetch_records(self, entity: Entity) -> list:
        """Get the all the Agent ID list from the Query Endpoint.

        Args:
            headers (dict): Header dict object having OAUTH2 access token.

        Returns:
            list[Record]: list of hosts fetched from CrowdStrike.
        """
        entity_name = entity.lower()
        self.logger.info(
            f"{self.log_prefix}: Fetching {entity_name} records from "
            f"{PLATFORM_NAME} platform."
        )
        records = []
        normalization_field = self.configuration.get(
            "netskope_normalization_field"
        )
        try:
            if entity == "Hosts":
                records = self.get_hosts(normalization_field)
            else:
                err_msg = (
                    f"Invalid entity found, {PLUGIN_NAME} only supports "
                    "Hosts entity."
                )
                self.logger.error(f"{self.log_prefix}: {err_msg}")
                raise ForescoutPluginException(err_msg)
            return records
        except ForescoutPluginException:
            raise
        except Exception as exp:
            err_msg = (
                f"Unexpected error occurred while pulling {entity_name} "
                f"records from {PLATFORM_NAME}."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {exp}",
                details=str(traceback.format_exc()),
            )
            raise ForescoutPluginException(err_msg)

    def update_records(self, entity: str, records: list[dict]) -> list[dict]:
        """
        Updating records from Forescout platform.

        Args:
            entity (str): Entity name.
            records (list[dict]): List of records to update.

        Returns:
            list[Record]: list of records with updated fields.
        """
        self.logger.info(
            f"{self.log_prefix}: Updating {entity.lower()}"
            f" records from {PLATFORM_NAME}."
        )
        if entity != "Hosts":
            err_msg = (
                "Invalid entity found. Forescout supports only"
                " Hosts entity."
            )
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            raise ForescoutPluginException(err_msg)

        updated_records = []
        skip_count = 0
        base_url, username, password = self.forescout_helper.get_credentials(
            self.configuration
        )
        normalization_field = self.configuration.get(
            "netskope_normalization_field"
        )

        hosts = [
            record.get("Host ID")
            for record in records
            if record.get("Host ID")
        ]
        log_msg = (
            f"{len(hosts)} host record(s) will be updated out"
            f" of {len(records)} records."
        )

        if len(records) - len(hosts) > 0:
            log_msg += (
                f" Skipped {len(records) - len(hosts)} host(s) as they"
                " do not have Host ID field in them."
            )

        self.logger.info(f"{self.log_prefix}: {log_msg}")
        headers = self.forescout_helper.get_auth_header(
            username,
            password,
            base_url,
            self.ssl_validation,
            self.proxy,
        )
        for host in hosts:
            try:
                resp_json = self.forescout_helper.api_helper(
                    method="GET",
                    url=f"{base_url}/api/hosts/{host}",
                    headers=headers,
                    proxies=self.proxy,
                    verify=self.ssl_validation,
                    logger_msg=(
                        f"fetching details for host with Host ID {host} "
                        f"from {PLATFORM_NAME}"
                    ),
                )
                if resp_json.get("host", {}).get("id"):
                    updated_records.append(
                        self.extract_host_fields(
                            resp_json, normalization_field
                        )
                    )
                else:
                    skip_count += 1
                    continue

            except ForescoutPluginException:
                skip_count += 1
            except Exception as exp:
                err_msg = (
                    f"Unexpected error occurred while updating "
                    f"{host} host record from {PLATFORM_NAME}."
                )
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg} Error: {exp}",
                    details=str(traceback.format_exc()),
                )
                skip_count += 1

        if skip_count > 0:
            self.logger.info(
                f"{self.log_prefix}: Skipped {skip_count} host(s) "
                f"because they might not contain hostId in their "
                "response or fields could not be extracted from them."
            )
        self.logger.info(
            f"{self.log_prefix}: Updated {len(updated_records)} "
            f"{entity.lower()} record(s) from {PLATFORM_NAME}."
        )
        return updated_records

    def get_actions(self):
        """Get available actions."""
        return [
            ActionWithoutParams(label="No action", value="generate"),
        ]

    def validate_action(self, action: Action):
        """Validate Netskope configuration."""
        if action.value not in ["generate"]:
            return ValidationResult(
                success=False, message="Unsupported action provided."
            )
        return ValidationResult(success=True, message="Validation successful.")

    def get_action_params(self, action: Action):
        """Get action params."""
        return []

    def execute_action(self, action: Action):
        """Execute action on the record."""
        if action.value == "generate":
            pass

    def _validate_url(self, url: str) -> bool:
        """Validate the URL using parsing.

        Args:
            - url (str): Given URL.

        Returns:
            - bool: True or False { Valid or not Valid URL }.
        """
        parsed = urlparse(url.strip())
        return (
            parsed.scheme.strip() != ""
            and parsed.netloc.strip() != ""
            and (parsed.path.strip() == "/" or parsed.path.strip() == "")
        )

    def validate(self, configuration: dict) -> ValidationResult:
        """Validate the Plugin configuration parameters.

        Args:
            configuration (dict): dict object having all the Plugin
            configuration parameters.
        Returns:
            cte.plugin_base.ValidateResult: ValidateResult object with success
            flag and message.
        """
        validation_err_msg = "Validation error occurred."
        # Validate Base URL
        base_url = configuration.get("base_url", "").strip().strip("/")
        if not base_url:
            err_msg = "Base URL is a required configuration parameter."
            self.logger.error(
                f"{self.log_prefix}: {validation_err_msg} {err_msg}"
            )
            return ValidationResult(success=False, message=err_msg)
        elif not isinstance(base_url, str) or not self._validate_url(base_url):
            err_msg = "Invalid Base URL provided in configuration parameter."
            self.logger.error(
                f"{self.log_prefix}: {validation_err_msg} {err_msg}"
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )

        # Validate Username
        username = configuration.get("username", "").strip()
        if not username:
            err_msg = "Username is a required configuration parameter."
            self.logger.error(
                f"{self.log_prefix}: {validation_err_msg} {err_msg}"
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        elif not isinstance(username, str):
            err_msg = "Invalid Username provided in configuration parameters."
            self.logger.error(
                f"{self.log_prefix}: {validation_err_msg} {err_msg}"
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )

        # Validate Password
        password = configuration.get("password")
        if not password:
            err_msg = "Password is a required configuration parameter."
            self.logger.error(
                f"{self.log_prefix}: {validation_err_msg} {err_msg}"
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        elif not isinstance(password, str):
            err_msg = "Invalid Password provided in configuration parameters."
            self.logger.error(
                f"{self.log_prefix}: {validation_err_msg} "
                f"{err_msg} Password should be an non-empty string."
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )

        # Validate Netskope Normalization Field
        field = configuration.get("netskope_normalization_field", "").strip()
        if not field:
            err_msg = (
                "Netskope Normalization Field is a required configuration"
                " parameter."
            )
            self.logger.error(
                f"{self.log_prefix}: {validation_err_msg} {err_msg}"
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        elif field not in ["cysiv_risk_score", "otsm_details_security_risk"]:
            err_msg = (
                "Invalid Netskope Normalization Field provided in"
                " configuration parameters."
            )
            self.logger.error(
                f"{self.log_prefix}: {validation_err_msg} {err_msg}"
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )

        # Validate Auth Credentials
        return self.validate_auth_params(base_url, username, password)

    def validate_auth_params(
        self, base_url, username, password
    ) -> ValidationResult:
        """Validate the authentication params with Forescout platform.

        Args:
            username (str): Username required to generate OAUTH2 token.
            password (str): Password required to generate OAUTH2
            token.
            base_url (str): Base url of Forescout platform.

        Returns:
            ValidationResult: ValidationResult object having validation
            results after making an API call.
        """
        try:

            headers = self.forescout_helper.get_auth_header(
                username,
                password,
                base_url,
                self.ssl_validation,
                self.proxy,
                is_validation=True,
            )
            api_endpoint = f"{base_url}/api/hosts"
            self.forescout_helper.api_helper(
                method="GET",
                url=api_endpoint,
                headers=headers,
                is_validation=True,
                proxies=self.proxy,
                verify=self.ssl_validation,
                logger_msg=(
                    f"validating connectivity with {PLATFORM_NAME} platform"
                ),
            )
            log_msg = f"Validation successful for {PLUGIN_NAME} plugin."
            self.logger.debug(f"{self.log_prefix}: {log_msg}")
            return ValidationResult(message=log_msg, success=True)
        except ForescoutPluginException as exp:
            return ValidationResult(success=False, message=str(exp))
        except Exception as exp:
            err_msg = "Unexpected validation error occurred."
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {exp}",
                details=traceback.format_exc(),
            )
            return ValidationResult(
                success=False,
                message=f"{err_msg} Check logs for more details.",
            )
