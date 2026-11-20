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

CRE Illumio Plugin.
"""

import traceback
from typing import List, Tuple

from netskope.integrations.crev2.models import Action, ActionWithoutParams
from netskope.integrations.crev2.plugin_base import (
    Entity,
    EntityField,
    EntityFieldType,
    PluginBase,
    ValidationResult,
)

from illumio import PolicyComputeEngine
from illumio.exceptions import IllumioApiException

from .utils.constants import MODULE_NAME, PLUGIN_NAME, PLUGIN_VERSION
from .utils.exceptions import IllumioPluginException
from .utils.helper import IllumioPluginHelper

SUPPORTED_ENTITY = "Hosts"


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
        ) = self.illumio_helper.get_credentials(configuration)

        if validation_result := self.illumio_helper.validate_parameters(
            field_name="PCE URL",
            field_value=base_url,
            field_type=str,
            custom_validation_func=self.illumio_helper._validate_url,
        ):
            return validation_result

        if validation_result := self.illumio_helper.validate_parameters(
            field_name="PCE Port Number",
            field_value=pce_port,
            field_type=int,
            custom_validation_func=self.illumio_helper.validate_port_number,
        ):
            return validation_result

        if validation_result := self.illumio_helper.validate_parameters(
            field_name="PCE Organization ID",
            field_value=org_id,
            field_type=int,
            custom_validation_func=self.illumio_helper.validate_org_id,
        ):
            return validation_result

        if validation_result := self.illumio_helper.validate_parameters(
            field_name="API Authentication Username",
            field_value=api_username,
            field_type=str,
        ):
            return validation_result

        if validation_result := self.illumio_helper.validate_parameters(
            field_name="API Secret",
            field_value=api_secret,
            field_type=str,
        ):
            return validation_result

        if validation_result := self.illumio_helper.validate_parameters(
            field_name="Label Scope",
            field_value=label_scope,
            field_type=str,
            custom_validation_func=(
                self.illumio_helper.validate_label_scope_format
            ),
        ):
            return validation_result

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
                headers=self.illumio_helper._add_user_agent(),
                # fail quickly if PCE connection params are invalid
                retry_count=1,
                request_timeout=5,
            )
        except IllumioPluginException as err:
            return ValidationResult(success=False, message=str(err))
        except Exception as err:
            err_msg = (
                "Error occurred while connecting to PCE. "
                "Validate the provided configuration parameters."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {err}",
                details=str(traceback.format_exc()),
                resolution=(
                    "Ensure that the configuration parameters provided are"
                    " correct and that the PCE server is reachable."
                ),
            )
            return ValidationResult(success=False, message=f"{err_msg}")
        return ValidationResult(
            success=True, message="Validation successful."
        )

    def fetch_records(self, entity: str) -> List:
        """Fetch Records from illumio.

        Returns:
            List: List of records.
        """
        try:
            self.illumio_helper.validate_entity(entity, SUPPORTED_ENTITY)
            self.logger.info(
                f"{self.log_prefix}: Fetching {entity.lower()} records from"
                f" {PLUGIN_NAME} platform."
            )
            label_scope = self.configuration.get("label_scope").strip()
            self.pce, workloads = (
                self.illumio_helper.connect_and_fetch_workloads(
                    self.configuration,
                    self.ssl_validation,
                    self.proxy,
                    label_scope,
                )
            )
            if not workloads:
                return []

            records, stats = (
                self.illumio_helper.extract_records_from_workloads(
                    workloads, include_tags=False
                )
            )
            fetched_count = stats["hostname_count"] + stats["address_count"]
            info_msg = (
                f"Successfully fetched {fetched_count} record(s) from"
                f" {PLUGIN_NAME} platform."
            )
            if stats["skipped_records"] > 0:
                info_msg += f" Skipped {stats['skipped_records']} record(s)."
            self.logger.info(f"{self.log_prefix}: {info_msg}")
            return records
        except IllumioPluginException:
            raise
        except Exception as err:
            error_msg = (
                f"Unexpected error occurred while fetching {entity} records."
            )
            if isinstance(
                err, IllumioApiException
            ) and self.illumio_helper.is_duplicate_async_job_error(err):
                err = (
                    "A previous Workloads fetch job is still running on"
                    " the PCE. Skipping this fetch cycle."
                )
            log_message = f"{self.log_prefix}: {error_msg}"
            if err:
                log_message += f" Error: {err}"
            self.logger.error(
                message=log_message,
                details=str(traceback.format_exc()),
            )
            raise IllumioPluginException(error_msg)

    def update_records(self, entity: str, records: list[dict]) -> list[dict]:
        """Update host from illumio.

        Args:
            entity (str): Entity name.
            records (list[dict]): List of records to update.

        Returns:
            List: List of updated records.
        """
        try:
            self.illumio_helper.validate_entity(entity, SUPPORTED_ENTITY)
            self.logger.info(
                f"{self.log_prefix}: Updating {len(records)}"
                f" {entity.lower()} records from {PLUGIN_NAME}."
            )
            updatable_count = self.illumio_helper.count_matchable_records(
                records
            )
            skipped_input_count = len(records) - updatable_count
            log_msg = (
                f"{updatable_count} host record(s) will be updated out of"
                f" {len(records)} records."
            )
            if skipped_input_count > 0:
                log_msg += (
                    f" Skipped {skipped_input_count} host(s) as they do not"
                    " have Workload ID or Host field in them."
                )
            self.logger.info(f"{self.log_prefix}: {log_msg}")

            label_scope = self.configuration.get("label_scope").strip()
            self.pce, workloads = (
                self.illumio_helper.connect_and_fetch_workloads(
                    self.configuration,
                    self.ssl_validation,
                    self.proxy,
                    label_scope,
                )
            )
            if not workloads:
                return []

            updated_records, stats = (
                self.illumio_helper.extract_records_from_workloads(
                    workloads, include_tags=True
                )
            )
            if stats["skipped_tags"] > 0:
                self.logger.info(
                    f"{self.log_prefix}: {stats['skipped_tags']} tag(s) "
                    "skipped due to some other exceptions that"
                    " occurred while updating them."
                )
            updated_count = (
                stats["hostname_count"] + stats["address_count"]
            )
            info_msg = (
                f"Successfully updated {updated_count} record(s) out of"
                f" {len(records)} record(s) from {PLUGIN_NAME}."
            )
            if stats["skipped_records"] > 0:
                info_msg += (
                    f" Skipped {stats['skipped_records']} record(s) as they"
                    " might not contain Workload ID or Host field in them."
                )
            self.logger.info(f"{self.log_prefix}: {info_msg}")
            return updated_records
        except IllumioPluginException:
            raise
        except Exception as err:
            error_msg = (
                f"Unexpected error occurred while updating {entity} records."
            )
            if isinstance(
                err, IllumioApiException
            ) and self.illumio_helper.is_duplicate_async_job_error(err):
                err = (
                    "A previous Workloads fetch job is still running on"
                    " the PCE. Skipping this update cycle."
                )
            log_message = f"{self.log_prefix}: {error_msg}"
            if err:
                log_message += f" Error: {err}"
            self.logger.error(
                message=log_message,
                details=str(traceback.format_exc()),
            )
            raise IllumioPluginException(error_msg)

    def get_entities(self) -> List[Entity]:
        """Get available entities.

        Returns:
            List[Entity]: List of Entity objects.
        """
        return [
            Entity(
                name="Hosts",
                fields=[
                    EntityField(
                        name="Workload ID",
                        type=EntityFieldType.STRING,
                        description=(
                            "Unique identifier of the Illumio Workload."
                        ),
                        required=True,
                    ),
                    EntityField(
                        name="Host",
                        type=EntityFieldType.STRING,
                        description=(
                            "Hostname or interface IP address of the"
                            " Workload."
                        ),
                        required=True,
                    ),
                    EntityField(
                        name="Public IP",
                        type=EntityFieldType.STRING,
                        description=(
                            "The public IP address of the"
                            " Workload."
                        ),
                    ),
                    EntityField(
                        name="Agent Mode",
                        type=EntityFieldType.STRING,
                        description=(
                            "Operating mode configured on the Workload's"
                            " VEN agent."
                        ),
                    ),
                    EntityField(
                        name="Agent Status",
                        type=EntityFieldType.STRING,
                        description=(
                            "Current health/connectivity status reported by"
                            " the VEN agent."
                        ),
                    ),
                    EntityField(
                        name="Agent Version",
                        type=EntityFieldType.STRING,
                        description="Version of the Workload's VEN agent.",
                    ),
                    EntityField(
                        name="Online",
                        type=EntityFieldType.BOOLEAN,
                        description=(
                            "Whether the Workload is currently online."
                        ),
                    ),
                    EntityField(
                        name="Deleted",
                        type=EntityFieldType.BOOLEAN,
                        description="Whether the Workload has been deleted.",
                    ),
                    EntityField(
                        name="Labels",
                        type=EntityFieldType.LIST,
                        description=(
                            "Illumio labels assigned to the Workload in the"
                            " 'key:value' format."
                        ),
                    ),
                    EntityField(
                        name="Enforcement Mode",
                        type=EntityFieldType.STRING,
                        description=(
                            "Illumio segmentation enforcement state."
                        ),
                    ),
                    EntityField(
                        name="OS ID",
                        type=EntityFieldType.STRING,
                        description=(
                            "Operating system identifier of the Workload"
                        ),
                    ),
                    EntityField(
                        name="OS Detail",
                        type=EntityFieldType.STRING,
                        description=(
                            "Detailed operating system information reported"
                            " for the Workload."
                        ),
                    ),
                    EntityField(
                        name="OS Type",
                        type=EntityFieldType.STRING,
                        description=(
                            "Operating system of the Workload"
                        ),
                    ),
                ],
            )
        ]
