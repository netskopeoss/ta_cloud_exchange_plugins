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
OF THIS SOFTWARE, EVEN IF IDVISED OF THE POSSIBILITY OF SUCH DAMAGE.

CRE Illumio Plugin.
"""

import json
import traceback
from typing import List, Tuple, Dict, Union
from urllib.parse import urlparse

from netskope.common.utils import add_user_agent
from netskope.integrations.crev2.models import Action, ActionWithoutParams
from netskope.integrations.crev2.plugin_base import (
    PluginBase,
    ValidationResult,
    Entity,
    EntityField,
    EntityFieldType,
)

from illumio import PolicyComputeEngine

from .utils.functions import IllumioPluginHelper
from .utils.exceptions import IllumioPluginException

from .utils.constants import (
    MODULE_NAME,
    PLUGIN_NAME,
    PLUGIN_VERSION,
    MAX_PORT_NUMBER,
    MIN_PORT_NUMBER,
    HOST_FIELD_MAPPING,
)


class IllumioPlugin(PluginBase):
    """Illumio CRE plugin implementation."""

    def __init__(
        self,
        name,
        *args,
        **kwargs,
    ):
        """Init method.

        Args:
            name (str): Configuration name.
        """
        super().__init__(
            name,
            *args,
            **kwargs,
        )
        self.pce: PolicyComputeEngine = None
        self.plugin_name, self.plugin_version = self._get_plugin_info()
        self.log_prefix = f"{MODULE_NAME} {self.plugin_name}"
        if name:
            self.log_prefix = f"{self.log_prefix} [{name}]"
        self.illumio_helper = IllumioPluginHelper(
            logger=self.logger,
            log_prefix=self.log_prefix,
            plugin_name=self.plugin_name,
            plugin_version=self.plugin_version,
        )

    def _get_plugin_info(self) -> Tuple:
        """Get plugin name and version from manifest.

        Returns:
            tuple: Tuple of plugin's name and version fetched from manifest.
        """
        try:
            manifest_json = IllumioPlugin.metadata
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

    def get_actions(self) -> List[ActionWithoutParams]:
        """Get available actions.

        Args:
            None

        Returns:
            [...] list of ActionWithoutParams: List of ActionWithoutParams
                which has label and value defined

        """
        return [
            ActionWithoutParams(label="No actions", value="generate"),
        ]

    def get_action_params(self, action: Action) -> List:
        """Get fields required for an action.

        Args:
            action (Action): The type of action

        Returns:
            [...] (list): Returns a list of details for UI to display group

        """
        if action.value == "generate":
            return []

    def execute_action(self, action: Action):
        """Execute action on the devices.

        Args:
            action (Action): Action that needs to be perform on devices.
        """

        if action.value == "generate":
            pass

    def validate_action(self, action: Action) -> ValidationResult:
        """Validate illumio action configuration."""
        if action.value not in ["generate"]:
            return ValidationResult(
                success=False, message="Unsupported action provided."
            )
        self.logger.debug(
            f"{self.log_prefix}: "
            f"Successfully validated action '{action.label}'."
        )
        return ValidationResult(success=True, message="Validation successful.")

    def _add_user_agent(self, headers: Union[Dict, None] = None) -> Dict:
        """Add User-Agent in the headers of any request.

        Args:
            header: Headers needed to pass to the Third Party Platform.

        Returns:
            Dict: Dictionary containing the User-Agent.
        """
        if headers and "User-Agent" in headers:
            return headers

        headers = add_user_agent(header=headers)
        ce_added_agent = headers.get("User-Agent", "netskope-ce")
        user_agent = "{}-{}-{}-v{}".format(
            ce_added_agent,
            MODULE_NAME.lower(),
            self.plugin_name.lower().replace(" ", "-"),
            self.plugin_version,
        )
        headers.update({"User-Agent": user_agent})
        return headers

    def _validate_url(self, url: str) -> bool:
        """Validate the given URL."""
        parsed = urlparse(url.strip())
        return parsed.scheme.strip() != "" and parsed.netloc.strip() != ""

    def _get_credentials(self, configuration):
        """Get credentials from the configuration."""
        base_url = configuration.get("pce_url", "").strip().strip("/")
        pce_port = configuration.get("pce_port")
        org_id = configuration.get("org_id")
        api_username = configuration.get("api_username", "").strip()
        api_secret = configuration.get("api_secret")
        label_scope = configuration.get("label_scope", "").strip()

        return (
            base_url,
            pce_port,
            org_id,
            api_username,
            api_secret,
            label_scope,
        )

    def validate(self, configuration: dict) -> ValidationResult:
        """Validate the plugin configuration parameters.

        Args:
            configuration (dict): Plugin configuration parameter map.

        Returns:
            ValidationResult: Validation result with success flag and message.
        """

        (
            base_url,
            pce_port,
            org_id,
            api_username,
            api_secret,
            label_scope,
        ) = self._get_credentials(configuration)

        validation_msg = "Validation error occurred."

        # BASE URL
        if not base_url:
            error_message = "PCE URL is a required configuration parameter."
            self.logger.error(f"{validation_msg} {error_message}")
            return ValidationResult(success=False, message=error_message)
        elif not (isinstance(base_url, str) and self._validate_url(base_url)):
            error_message = (
                "Invalid PCE URL provided in the configuration parameters."
            )
            self.logger.error(f"{validation_msg} {error_message}")
            return ValidationResult(success=False, message=error_message)

        # PCE PORT
        if not pce_port:
            error_message = (
                "PCE Port Number is a required configuration parameter."
            )
            self.logger.error(f"{validation_msg} {error_message}")
            return ValidationResult(success=False, message=error_message)
        elif not isinstance(pce_port, int) or not (
            MIN_PORT_NUMBER <= pce_port <= MAX_PORT_NUMBER
        ):
            error_message = (
                "Invalid PCE Port Number found in the configuration "
                "parameters. PCE Port Number should be between"
                f" {MIN_PORT_NUMBER} to {MAX_PORT_NUMBER}."
            )
            self.logger.error(f"{validation_msg} {error_message}")
            return ValidationResult(success=False, message=error_message)

        # Organization ID
        if not org_id:
            error_message = (
                "PCE Organization ID is a required configuration parameter."
            )
            self.logger.error(f"{validation_msg} {error_message}")
            return ValidationResult(success=False, message=error_message)
        elif not isinstance(org_id, int) or org_id <= 0:
            error_message = (
                "Invalid PCE Organization ID found in the configuration "
                "parameters. PCE Organization ID should "
                "an integer greater than 0."
            )
            self.logger.error(f"{validation_msg} {error_message}")
            return ValidationResult(success=False, message=error_message)

        # API Username
        if not api_username:
            error_message = (
                "API Authentication Username is a required "
                "configuration parameter."
            )
            self.logger.error(f"{validation_msg} {error_message}")
            return ValidationResult(success=False, message=error_message)
        elif not isinstance(api_username, str):
            error_message = (
                "Invalid API Authentication Username found in the "
                "configuration parameters."
            )
            self.logger.error(f"{validation_msg} {error_message}")
            return ValidationResult(success=False, message=error_message)

        # API Secret
        if not api_secret:
            error_message = "API Secret is a required configuration parameter."
            self.logger.error(f"{validation_msg} {error_message}")
            return ValidationResult(success=False, message=error_message)
        elif not isinstance(api_secret, str):
            error_message = (
                "Invalid API Secret found in the configuration parameters."
            )
            self.logger.error(f"{validation_msg} {error_message}")
            return ValidationResult(success=False, message=error_message)

        # Label Scope
        if not label_scope:
            error_message = (
                "Label Scope is a required configuration parameter."
            )
            self.logger.error(f"{validation_msg} {error_message}")
            return ValidationResult(success=False, message=error_message)
        elif not isinstance(label_scope, str):
            error_message = (
                "Invalid Label Scope found in the configuration parameters."
            )
            self.logger.error(f"{validation_msg} {error_message}")
            return ValidationResult(success=False, message=error_message)
        else:
            try:
                logger_message = "parsing label references for validation"
                self.illumio_helper.parse_label_scope(
                    logger_message, label_scope, is_validation=True
                )
            except IllumioPluginException as err:
                return ValidationResult(success=False, message=str(err))
            except Exception as e:
                return ValidationResult(success=False, message=str(e))

        return self.validate_auth_params(configuration)

    def validate_auth_params(self, configuration):
        """Validate the authentication params with illumio platform.

        Args: configuration (dict).

        Returns:
            ValidationResult: ValidationResult object having validation
            results after making an API call.
        """
        # only try to connect if the configuration is valid
        try:
            logger_msg = "connecting to PCE for validating credentials"
            self.illumio_helper.connect_to_pce(
                logger_msg,
                configuration,
                verify=self.ssl_validation,
                proxies=self.proxy,
                headers=self._add_user_agent(),
                # fail quickly if PCE connection params are invalid
                retry_count=1,
                request_timeout=5,
            )
        except IllumioPluginException as err:
            return ValidationResult(success=False, message=str(err))
        except Exception as err:
            err_msg = (
                "Error occurred while Connecting to PCE."
                "Validate the provided configuration parameters."
            )

            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {err}",
                details=str(traceback.format_exc()),
            )
            return ValidationResult(success=False, message=f"{err_msg}")
        return ValidationResult(success=True, message="Validation successful")

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

    def _extract_field_from_event(
        self, key: str, workload, default=None, transformation=None
    ):
        """Extract field from event.

        Args:
            key (str): Key to fetch.
            workload (dict): Workload.
            default (str,None): Default value to set.
            transformation (str, None, optional): Transformation
                to perform on key. Defaults to None.

        Returns:
            Any: Value of the key from event.
        """
        value = getattr(workload, key, None)
        if key == "href" and value:
            value = value.split("/")[-1]

        if isinstance(value, str):
            return value

        return default

    def _extract_each_workload_fields(
        self,
        hostname=None,
        workload=None,
        include_tags=False,
    ) -> dict:
        """Extract each workload fields.

        Args:
            workload_id (str, optional): Workload id.
            hostname (str, optional): Workload hostname.
            workload (Workload, optional): Workload object.
            include_tags (bool, optional): Include tags or not ? Defaults to False.

        Returns:
            dict: Extracted fields dictionary.
        """
        extracted_fields = {}
        skipped_tags = []
        label_list = []
        for field_name, field_value in HOST_FIELD_MAPPING.items():
            key, default, transformation = (
                field_value.get("key"),
                field_value.get("default"),
                field_value.get("transformation"),
            )
            self.add_field(
                extracted_fields,
                field_name,
                self._extract_field_from_event(
                    key, workload, default, transformation
                ),
            )
        self.add_field(
            extracted_fields,
            "Host",
            hostname,
        )
        if include_tags and workload.labels:
            labels = workload.labels
            label_list = list(
                {
                    f"{label.key}:{label.value}"
                    for label in labels
                    if label.key and label.value
                }
            )
            skipped_tags = list(
                {
                    f"{label.key}:{label.value}"
                    for label in labels
                    if not label.key and label.value
                }
            )
            self.add_field(
                extracted_fields,
                "Labels",
                label_list,
            )

        return extracted_fields, len(skipped_tags)

    def fetch_records(self, entity: str) -> List:
        """Fetch Records from illumio.

        Returns:
            List: List of records.
        """
        try:
            total_records = []
            if entity == "Hosts":
                entity_name = entity.lower()
                self.logger.info(
                    f"{self.log_prefix}: Fetching {entity_name} from "
                    f"{PLUGIN_NAME} platform."
                )
                label_scope = self.configuration.get("label_scope").strip()
                logger_msg = f"connecting to PCE for fetching {entity_name}"
                self.pce = self.illumio_helper.connect_to_pce(
                    logger_msg,
                    self.configuration,
                    verify=self.ssl_validation,
                    proxies=self.proxy,
                    headers=self._add_user_agent(),
                )
                logger_msg = "parsing label scopes"
                label = self.illumio_helper.parse_label_scope(
                    logger_msg, label_scope
                )
                logger_msg = "get label reference"
                refs = self._get_label_refs(label)
                workloads = self.pce.workloads.get_async(
                    # the labels query param takes a JSON-formatted
                    # nested list of
                    # label HREFs - each inner list represents a separate scope
                    params={
                        "labels": json.dumps(refs),
                        # include label keys/values in the response data
                        "representation": "workload_labels",
                    }
                )
                if not workloads:
                    self.logger.info(
                        f"No Workloads found containing the Label Scope(s) - "
                        f"'{label_scope}'."
                    )
                    return total_records

                self.logger.debug(
                    f"{self.log_prefix}: Total {len(workloads)} Workload(s) "
                    "fetched containing the Label Scope(s) - "
                    f"'{label_scope}'. These Workloads will be used to "
                    "check for updates."
                )
                skip_records = 0
                successfully_fetched_record_count = 0
                address_count = 0
                total_hostname_count = 0
                total_address_fetched_count = 0
                for workload in workloads:
                    workload_id = workload.href.split("/")[-1]
                    self.logger.debug(
                        f"{self.log_prefix}: Extracting records(s) "
                        f"from workload with ID '{workload_id}'."
                    )
                    hosts_list = [
                        str(intf.address) for intf in workload.interfaces
                    ]
                    if workload.hostname:
                        try:
                            extracted_fields, _ = (
                                self._extract_each_workload_fields(
                                    hostname=workload.hostname,
                                    workload=workload,
                                    include_tags=False,
                                )
                            )
                            if extracted_fields:
                                total_records.append(extracted_fields)
                                total_hostname_count += 1
                            else:
                                skip_records += 1
                        except IllumioPluginException:
                            skip_records += 1
                        except Exception as err:
                            hostname = workload.hostname
                            err_msg = (
                                "Unable to extract fields from host "
                                f"{hostname} having Workload "
                                f'ID "{workload_id}".'
                            )
                            self.logger.error(
                                message=(
                                    f"{self.log_prefix}: {err_msg}"
                                    f" Error: {err}"
                                ),
                                details=str(traceback.format_exc()),
                            )
                            skip_records += 1

                    address_count = 0
                    for host in hosts_list:
                        try:
                            extracted_fields, _ = (
                                self._extract_each_workload_fields(
                                    hostname=host,
                                    workload=workload,
                                    include_tags=False,
                                )
                            )
                            if extracted_fields:
                                total_records.append(extracted_fields)
                                address_count += 1
                            else:
                                skip_records += 1
                        except IllumioPluginException:
                            skip_records += 1
                        except Exception as err:
                            hostname = workload.hostname
                            err_msg = (
                                "Unable to extract fields from host "
                                f"{host} having Workload "
                                f'ID "{workload_id}".'
                            )
                            self.logger.error(
                                message=(
                                    f"{self.log_prefix}: {err_msg}"
                                    f" Error: {err}"
                                ),
                                details=str(traceback.format_exc()),
                            )
                            skip_records += 1

                    total_address_fetched_count += address_count
                    self.logger.info(
                        f"{self.log_prefix}: Successfully fetched "
                        f"{address_count} addresses with hostname "
                        f"{workload.hostname} and workload ID '{workload_id}'."
                        " Total addresses fetched till now - "
                        f"{total_address_fetched_count}."
                        "Total hostnames fetches till now - "
                        f"{total_hostname_count}"
                    )

                successfully_fetched_record_count = (
                    total_address_fetched_count + total_hostname_count
                )
                info_msg = (
                    f"Successfully fetched {successfully_fetched_record_count}"
                    f" record(s) from {PLUGIN_NAME} platform."
                )
                if skip_records > 0:
                    info_msg += f" Skipped {skip_records} record(s)."
                self.logger.info(f"{self.log_prefix}: {info_msg}")
            else:
                err_msg = (
                    f"Invalid entity found. {PLUGIN_NAME}"
                    " only supports Hosts entity."
                )
                self.logger.error(f"{self.log_prefix}: {err_msg}")
                raise IllumioPluginException(err_msg)
            return total_records

        except IllumioPluginException as err:
            raise err
        except Exception as err:
            error_msg = f"Error occurred while {logger_msg}."
            self.logger.error(
                message=f"{self.log_prefix}: {error_msg} Error: {err}",
                details=str(traceback.format_exc()),
            )
            raise IllumioPluginException(error_msg)

    def update_records(self, entity: str, records: list[dict]) -> list[dict]:
        """Update host from illumio.

        Args:
            users (List): List of users.

        Returns:
            List: List of users with scores assigned.
        """
        try:
            updated_records = []
            entity_name = entity.lower()

            if entity == "Hosts":
                self.logger.info(
                    f"{self.log_prefix}: Updating {len(records)}"
                    f" {entity.lower()} records from {PLUGIN_NAME}."
                )
                label_scope = self.configuration.get("label_scope").strip()
                id_list = []
                for record in records:
                    if record.get("Workload ID") and record.get("Host"):
                        unique_id = (
                            f'{record.get("Workload ID")}_{record.get("Host")}'
                        )
                        id_list.append(unique_id)

                log_msg = (
                    f"{len(id_list)} host record(s) will be updated out"
                    f" of {len(records)} records."
                )

                if len(records) - len(id_list) > 0:
                    log_msg += (
                        f" Skipped {len(records) - len(id_list)} host(s) as"
                        " they do not have Workload ID or Host field in them."
                    )

                self.logger.info(f"{self.log_prefix}: {log_msg}")

                logger_msg = f"connecting to PCE for fetching {entity_name}"
                self.pce = self.illumio_helper.connect_to_pce(
                    logger_msg,
                    self.configuration,
                    verify=self.ssl_validation,
                    proxies=self.proxy,
                    headers=self._add_user_agent(),
                )
                logger_msg = "parsing label scopes"
                label = self.illumio_helper.parse_label_scope(
                    logger_msg, label_scope
                )
                logger_msg = "get label reference"
                refs = self._get_label_refs(label)
                workloads = self.pce.workloads.get_async(
                    # the labels query param takes a JSON-formatted nested
                    # list of
                    # label HREFs - each inner list represents a separate scope
                    params={
                        "labels": json.dumps(refs),
                        # include label keys/values in the response data
                        "representation": "workload_labels",
                    }
                )
                if not workloads:
                    self.logger.info(
                        f"No Workloads found containing the Label Scope(s) - "
                        f"'{label_scope}'."
                    )
                    return updated_records

                self.logger.debug(
                    f"{self.log_prefix}: Total {len(workloads)} Workload(s) "
                    "fetched containing the Label Scope(s) - "
                    f"'{label_scope}'. These Workloads will be used to "
                    "check for updates."
                )
                skip_records = 0
                total_skipped_tags = 0
                successfully_updated_record_count = 0
                total_address_update_count = 0
                address_count = 0
                total_hostname_update_count = 0
                for workload in workloads:
                    workload_id = workload.href.split("/")[-1]
                    self.logger.debug(
                        f"{self.log_prefix}: Extracting records(s) "
                        f"from workload with ID '{workload_id}'."
                    )
                    hosts_list = [
                        str(intf.address) for intf in workload.interfaces
                    ]
                    if workload.hostname:
                        try:
                            extracted_fields, skipped_tags = (
                                self._extract_each_workload_fields(
                                    hostname=workload.hostname,
                                    workload=workload,
                                    include_tags=True,
                                )
                            )
                            total_skipped_tags += skipped_tags
                            if extracted_fields:
                                updated_records.append(extracted_fields)
                                total_hostname_update_count += 1
                            else:
                                skip_records += 1
                        except IllumioPluginException:
                            skip_records += 1
                        except Exception as err:
                            hostname = workload.hostname
                            err_msg = (
                                "Unable to extract fields from host "
                                f"{hostname} having Workload "
                                f'ID "{workload_id}".'
                            )
                            self.logger.error(
                                message=(
                                    f"{self.log_prefix}: {err_msg}"
                                    f" Error: {err}"
                                ),
                                details=str(traceback.format_exc()),
                            )
                            skip_records += 1

                    address_count = 0
                    for host in hosts_list:
                        try:
                            extracted_fields, skipped_tags = (
                                self._extract_each_workload_fields(
                                    hostname=host,
                                    workload=workload,
                                    include_tags=True,
                                )
                            )
                            total_skipped_tags += skipped_tags
                            if extracted_fields:
                                updated_records.append(extracted_fields)
                                address_count += 1
                            else:
                                skip_records += 1
                        except IllumioPluginException:
                            skip_records += 1
                        except Exception as err:
                            hostname = workload.hostname
                            err_msg = (
                                "Unable to extract fields from host "
                                f"{host} having Workload "
                                f'ID "{workload_id}".'
                            )
                            self.logger.error(
                                message=(
                                    f"{self.log_prefix}: {err_msg}"
                                    f" Error: {err}"
                                ),
                                details=str(traceback.format_exc()),
                            )
                            skip_records += 1

                    total_address_update_count += address_count
                    self.logger.info(
                        f"{self.log_prefix}: Successfully updated "
                        f"{address_count} addresses with hostname "
                        f"{workload.hostname} and workload ID '{workload_id}'."
                        " Total addresses updated till now - "
                        f"{total_address_update_count}."
                        "Total hostnames updated till now - "
                        f"{total_hostname_update_count}"
                    )

                if total_skipped_tags > 0:
                    self.logger.info(
                        f"{self.log_prefix}: {total_skipped_tags} tag(s) "
                        "skipped due to some other exceptions that"
                        " occurred while updating them."
                    )
                successfully_updated_record_count = (
                    total_address_update_count + total_hostname_update_count
                )
                info_msg = (
                    f"Successfully updated {successfully_updated_record_count}"
                    f" record(s) out of {len(records)} record(s)"
                    f" from {PLUGIN_NAME}."
                )
                if skip_records > 0:
                    info_msg += (
                        f" Skipped {skip_records} record(s) as they"
                        " might not contain Worload ID or Host field in them."
                    )
                self.logger.info(f"{self.log_prefix}: {info_msg}")
            else:
                err_msg = (
                    f"Invalid entity found. {PLUGIN_NAME}"
                    " only supports Hosts entity."
                )
                self.logger.error(f"{self.log_prefix}: {err_msg}")
                raise IllumioPluginException(err_msg)

            return updated_records
        except IllumioPluginException as err:
            raise err
        except Exception as err:
            error_msg = f"Error occurred while {logger_msg}."
            self.logger.error(
                message=f"{self.log_prefix}: {error_msg} Error: {err}",
                details=str(traceback.format_exc()),
            )
            raise IllumioPluginException(error_msg)

    def get_entities(self) -> list[Entity]:
        """Get available entities."""
        return [
            Entity(
                name="Hosts",
                fields=[
                    EntityField(
                        name="Workload ID",
                        type=EntityFieldType.STRING,
                        required=True,
                    ),
                    EntityField(
                        name="Host",
                        type=EntityFieldType.STRING,
                        required=True,
                    ),
                    EntityField(name="Labels", type=EntityFieldType.LIST),
                    EntityField(name="OS ID", type=EntityFieldType.STRING),
                    EntityField(
                        name="OS Detail",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="OS Type",
                        type=EntityFieldType.STRING,
                    ),
                ],
            )
        ]

    def _get_label_refs(self, labels: dict) -> List[str]:
        """Retrieve Label object HREFs from the PCE.

        Args:
            labels (dict): label key:value pairs to look up.

        Returns:
            List[str]: List of HREFs.

        Raises:
            ValueError: if a label with the given key:value can't be found.
        """
        refs = []
        try:
            for key, value in labels.items():
                labels = self.pce.labels.get(
                    params={"key": key, "value": value}
                )
                if labels and labels[0].value == value:
                    # only expect to match a single label for each k:v pair
                    refs.append([labels[0].href])
                else:
                    # if we don't raise an error, we risk pulling workloads
                    # outside the expected scope and blocking legitimate access
                    msg = (
                        f"Failed to find label Href for {key}:{value} - "
                        "Verify that the provided Label Scope is "
                        f"present on the {PLUGIN_NAME} platform."
                    )
                    self.logger.error(f"{self.log_prefix}: {msg}")
                    raise IllumioPluginException(msg)
            return refs
        except IllumioPluginException:
            raise
        except Exception as err:
            err_msg = "Error occurred while fetching label reference."
            self.logger.error(f"{self.log_prefix}: {err_msg}. Error: {err}")
            raise IllumioPluginException(err_msg)
