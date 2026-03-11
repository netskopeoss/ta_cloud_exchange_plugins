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

CRE Microsoft Intune Plugin
"""

import traceback
from copy import deepcopy
from typing import Any, Callable, Dict, List, Literal, Tuple, Type, Union

from netskope.common.api import __version__ as CE_VERSION
from netskope.integrations.crev2.models import Action, ActionWithoutParams
from netskope.integrations.crev2.plugin_base import (
    Entity,
    EntityField,
    EntityFieldType,
    PluginBase,
    ValidationResult,
)
from packaging import version

from .utils.constants import (
    ACTION,
    ACTION_API_ENDPOINT_MAPPING,
    ACTION_BATCH_SIZE,
    BATCHED_API_ENDPOINT,
    CONFIGURATION,
    DEVICE_ENTITY_MAPPING,
    DEVICE_HEALTH_SCORE_MAPPING,
    EMPTY_ERROR_MESSAGE,
    GET_DEVICE_HEALTH_SCORE_API_ENDPOINT,
    GET_GROUP_TAGS,
    INVALID_VALUE_ERROR_MESSAGE,
    MAXIMUM_CE_VERSION,
    MODULE_NAME,
    PAGE_SIZE,
    PLATFORM_NAME,
    PLUGIN_VERSION,
    PULL_DEVICES_API_ENDPOINT,
    TYPE_ERROR_MESSAGE,
    VALIDATION_ERROR_MESSAGE,
)
from .utils.exceptions import MicrosoftIntunePluginException, exception_handler
from .utils.helper import MicrosoftIntuneHelper
from .utils.parser import MicrosoftIntuneParser


class MicrosoftIntunePlugin(PluginBase):
    def __init__(self, name, *args, **kwargs):
        """Microsoft Intune plugin initializer.

        Args:
            name (str): Plugin configuration name.
        """
        super().__init__(
            name,
            *args,
            **kwargs,
        )
        # Flag to check if CE version is more than v5.1.2
        self._is_ce_post_v512 = self._check_ce_version()
        # Method to decide which logger to use with or without
        # resolutions based on the CE version
        self._patch_error_logger()
        self.plugin_name, self.plugin_version = self._get_plugin_info()
        self.log_prefix = f"{MODULE_NAME} {self.plugin_name} [{name}]"
        self.parser = MicrosoftIntuneParser(
            logger=self.logger,
            log_prefix=self.log_prefix,
            is_ce_post_v512=self._is_ce_post_v512,
        )
        self.microsoftintunehelper = MicrosoftIntuneHelper(
            logger=self.logger,
            log_prefix=self.log_prefix,
            plugin_name=self.plugin_name,
            plugin_version=self.plugin_version,
            parser=self.parser,
        )
        self.provide_action_id = self._is_ce_post_v512

    def _get_plugin_info(self) -> Tuple[str, str]:
        """Get plugin name and version from manifest.

        Returns:
            tuple: Tuple of plugin's name and version fetched from manifest.
        """
        try:
            manifest_json = MicrosoftIntunePlugin.metadata
            plugin_name = manifest_json.get("name", PLATFORM_NAME)
            plugin_version = manifest_json.get("version", PLUGIN_VERSION)
            return plugin_name, plugin_version
        except Exception as exp:
            self.logger.error(
                message=(
                    f"{MODULE_NAME} {PLATFORM_NAME}: Error occurred while "
                    f"getting plugin details. Error: {exp}"
                ),
                details=traceback.format_exc(),
            )
        return (PLATFORM_NAME, PLUGIN_VERSION)

    def _check_ce_version(self):
        """Check if CE version is greater than v5.1.2.

        Returns:
            bool: True if CE version is greater than v5.1.2, False otherwise.
        """
        return version.parse(CE_VERSION) > version.parse(MAXIMUM_CE_VERSION)

    def _patch_error_logger(self):
        """Monkey patch logger methods to handle resolution parameter
        compatibility.
        """
        # Store original methods
        original_error = self.logger.error

        def patched_error(
            message=None,
            details=None,
            resolution=None,
            **kwargs,
        ):
            """Patched error method that handles resolution compatibility."""
            log_kwargs = {"message": message}
            if details:
                log_kwargs["details"] = details
            if resolution and self._is_ce_post_v512:
                log_kwargs["resolution"] = resolution
            log_kwargs.update(kwargs)
            return original_error(**log_kwargs)

        # Replace logger methods with patched versions
        self.logger.error = patched_error

    def _get_storage(self) -> Dict:
        """Get storage object.

        Returns:
            Dict: Storage object.
        """
        storage = self.storage if self.storage is not None else {}
        return storage

    @exception_handler
    def get_access_token_and_storage(
        self, configuration: Dict, is_validation: bool = False
    ) -> Tuple[str, Dict]:
        """
        Get access token and storage.

        Args:
            configuration (Dict): Configuration.
            is_validation (bool, optional): Is validation. Defaults to False.

        Returns:
            Tuple[str, Dict]: Access token and storage.
        """
        storage = self._get_storage()
        stored_access_token = storage.get("access_token")
        stored_config_hash = storage.get("config_hash")
        tenant_id, client_id, client_secret = (
            self.microsoftintunehelper.get_configuration_parameters(
                configuration=configuration
            )
        )
        current_config_hash = self.microsoftintunehelper.hash_string(
            string=f"{tenant_id}{client_id}{client_secret}"
        )
        if stored_access_token and stored_config_hash == current_config_hash:
            return stored_access_token, storage
        else:
            access_token = self.microsoftintunehelper.generate_access_token(
                client_id=client_id,
                client_secret=client_secret,
                tenant_id=tenant_id,
                verify=self.ssl_validation,
                proxies=self.proxy,
                is_validation=is_validation,
                context={},
            )
            storage.update(
                {
                    "access_token": access_token,
                    "config_hash": current_config_hash,
                }
            )
            return access_token, storage

    def _validate_parameters(
        self,
        parameter_type: Literal["configuration", "action"],
        field_name: str,
        field_value: Union[str, int, List],
        field_type: Type,
        check_dollar: bool = False,
        allowed_values: List = None,
        custom_validation_func: Callable = None,
    ):
        """Validate the plugin parameters.

        Args:
            parameter_type (Literal["configuration", "action"]): Type of
                parameter.
            field_name (str): Name of the field.
            field_value (Union[str, int, List]): Value of the field.
            field_type (Type): Type of the field.
            check_dollar (bool, optional): Check for $ in the field value.
                Defaults to False.
            allowed_values (List, optional): List of allowed values. Defaults
                to None.
            custom_validation_func (Callable, optional): Custom validation
                function. Defaults to None.

        Returns:
            ValidationResult: ValidationResult object.
        """
        if field_type is str:
            field_value = field_value.strip()
        if check_dollar and "$" in field_value:
            info_msg = (
                f"'{field_name}' contains the Source Field"
                " hence validation for this field will be performed"
                " while executing the action."
            )
            self.logger.info(
                message=f"{self.log_prefix}: {info_msg}",
            )
            return
        if not field_value:
            err_msg = EMPTY_ERROR_MESSAGE.format(
                field_name=field_name, parameter_type=parameter_type
            )
            self.logger.error(
                message=(
                    f"{self.log_prefix}: {VALIDATION_ERROR_MESSAGE} {err_msg}"
                ),
                resolution=(
                    f"Please provide some value for field {field_name}."
                ),
            )
            return ValidationResult(success=False, message=err_msg)
        if not isinstance(field_value, field_type) or (
            custom_validation_func and not custom_validation_func(field_value)
        ):
            err_msg = TYPE_ERROR_MESSAGE.format(
                field_name=field_name,
                parameter_type=parameter_type,
            )
            self.logger.error(
                message=(
                    f"{self.log_prefix}: {VALIDATION_ERROR_MESSAGE} {err_msg}"
                ),
                resolution=(
                    f"Please provide a valid value for {field_name} field."
                ),
            )
            return ValidationResult(success=False, message=err_msg)
        if allowed_values and field_value not in allowed_values:
            err_msg = TYPE_ERROR_MESSAGE.format(
                field_name=field_name,
                parameter_type=parameter_type,
            )
            err_msg += INVALID_VALUE_ERROR_MESSAGE.format(
                allowed_values=[
                    allowed_value.capitalize() for allowed_value in allowed_values
                ]
            )
            self.logger.error(
                message=(
                    f"{self.log_prefix}: {VALIDATION_ERROR_MESSAGE} {err_msg}"
                ),
                resolution=(
                    "Please provide a valid value from the allowed values."
                ),
            )
            return ValidationResult(success=False, message=err_msg)

    def validate(self, configuration: Dict) -> ValidationResult:
        """Validate the plugin configuration parameters."""
        tenant_id, client_id, client_secret = (
            self.microsoftintunehelper.get_configuration_parameters(
                configuration=configuration
            )
        )
        if validation_failure := self._validate_parameters(
            parameter_type=CONFIGURATION,
            field_name="Tenant ID",
            field_value=tenant_id,
            field_type=str,
        ):
            return validation_failure
        if validation_failure := self._validate_parameters(
            parameter_type=CONFIGURATION,
            field_name="Client ID",
            field_value=client_id,
            field_type=str,
        ):
            return validation_failure
        if validation_failure := self._validate_parameters(
            parameter_type=CONFIGURATION,
            field_name="Client Secret",
            field_value=client_secret,
            field_type=str,
        ):
            return validation_failure

        return self._validate_connectivity(configuration=configuration)

    def _validate_connectivity(self, configuration: Dict):
        """
        Validate connectivity with Microsoft Intune.

        Args:
            configuration (Dict): Configuration.

        Returns:
            ValidationResult: Validation result.
        """
        logger_msg = f"validating connectivity with {PLATFORM_NAME} platform"
        try:
            access_token, storage = self.get_access_token_and_storage(
                configuration=configuration,
                is_validation=True,
            )
            self.microsoftintunehelper.api_helper(
                logger_msg=logger_msg,
                url=PULL_DEVICES_API_ENDPOINT,
                method="GET",
                headers=self.microsoftintunehelper.get_headers(
                    access_token=access_token,
                ),
                params={"$top": 0},
                verify=self.ssl_validation,
                proxies=self.proxy,
                configuration=configuration,
                storage=storage,
                is_validation=True,
                is_handle_error_required=True,
                regenerate_access_token=True,
            )
            success_msg = (
                f"Successfully validated connectivity with"
                f" {PLATFORM_NAME} platform."
            )
            self.logger.debug(f"{self.log_prefix}: {success_msg}")
            return ValidationResult(
                success=True,
                message=success_msg,
            )
        except MicrosoftIntunePluginException as err:
            return ValidationResult(
                success=False,
                message=str(err),
            )
        except Exception as err:
            err_msg = (
                f"Unexpected error occurred while {logger_msg}. Error: {err}."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=traceback.format_exc(),
            )
            return ValidationResult(
                success=False,
                message=f"{err_msg} Check logs for more details.",
            )

    def get_entities(self) -> List[Entity]:
        """Get available entities."""
        return [
            Entity(
                name="Devices",
                fields=[
                    EntityField(
                        name="Device ID",
                        type=EntityFieldType.STRING,
                        required=True,
                    ),
                    EntityField(
                        name="Azure AD Device ID",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="Serial Number",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="Group Tag",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="Ethernet MAC Address",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="Wifi MAC Address",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="IMEI",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="Compliance State",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="User Email",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="User Principal Name",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="User Display name",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="User ID",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="MEID",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(name="UDID", type=EntityFieldType.STRING),
                    EntityField(
                        name="EAS Device ID",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="Managed Device Name", type=EntityFieldType.STRING
                    ),
                    EntityField(
                        name="Device Name",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="Model",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="Manufacturer",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="OS",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="OS Version",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="Jail Broken",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="Management State",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="Device Registration State",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="Device Enrollment State",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="Endpoint Analytics Score",
                        type=EntityFieldType.NUMBER,
                    ),
                    EntityField(
                        name="Startup Performance Score",
                        type=EntityFieldType.NUMBER,
                    ),
                    EntityField(
                        name="App Reliability Score",
                        type=EntityFieldType.NUMBER,
                    ),
                    EntityField(
                        name="Work From Anywhere Score",
                        type=EntityFieldType.NUMBER,
                    ),
                    EntityField(
                        name="Battery Health Score",
                        type=EntityFieldType.NUMBER,
                    ),
                    EntityField(
                        name="Health Status",
                        type=EntityFieldType.STRING,
                    ),
                ],
            )
        ]

    def fetch_records(self, entity: str) -> List[Dict]:
        """Fetch entity records into Cloud Exchange.

        Args:
            entity (str): Entity to be fetched.

        Returns:
            List: List of records to be stored on the platform.
        """
        records = []
        entity_name = entity.lower()
        self.logger.info(
            f"{self.log_prefix}: Fetching {entity_name} records from "
            f"{PLATFORM_NAME} platform."
        )
        records = []
        if entity_name == "devices":
            device_records = self._fetch_devices(context={})
            records.extend(device_records)
        else:
            err_msg = (
                f"Invalid entity found. {PLATFORM_NAME} plugin "
                "only supports 'Devices' Entity."
            )
            self.logger.error(message=f"{self.log_prefix}: {err_msg}")
            raise MicrosoftIntunePluginException(err_msg)
        return records

    def update_records(self, entity: str, records: List[Dict]):
        """Update records present in Cloud Exchange.

        Args:
            entity (str): Entity to be updated.
            records (list): List of records to be updated.

        Returns:
            List: List of updated records.
        """
        if entity.lower() == "devices":
            self.logger.info(
                f"{self.log_prefix}: Updating {len(records)}"
                f" Devices records from {PLATFORM_NAME} platform."
            )
            updated_devices = []
            devices_with_group_tags = self._update_devices_with_group_tag(
                devices=records,
                context={}
            )
            devices_with_health_scores = self._update_devices_with_health_score(
                devices=records,
                context={}
            )
            updated_devices = self._update_records(
                devices_with_group_tags=devices_with_group_tags,
                devices_with_health_scores=devices_with_health_scores
            )
            return updated_devices
        else:
            err_msg = (
                f"Invalid entity found. {PLATFORM_NAME} plugin "
                "only supports 'Devices' Entity."
            )
            self.logger.error(message=f"{self.log_prefix}: {err_msg}")
            raise MicrosoftIntunePluginException(err_msg)

    @exception_handler
    def _fetch_devices(self, context: Dict = {}) -> List[Dict]:
        """
        Fetch devices from Microsoft Intune.

        Args:
            context (Dict, optional): Context. Defaults to {}.

        Returns:
            List[Dict]: List of devices.
        """
        access_token, storage = self.get_access_token_and_storage(
            configuration=self.configuration,
            is_validation=False,
        )
        headers = self.microsoftintunehelper.get_headers(
            access_token=access_token
        )
        self.logger.info(
            f"{self.log_prefix}: Fetching devices seen after"
            f" '{self.last_run_at}' time from {PLATFORM_NAME} platform.",
        )
        query_params = {
            "$top": PAGE_SIZE
        }
        query_params = self.microsoftintunehelper.get_time_filter_parameter(
            query_params=query_params,
            datetime_object=self.last_run_at,
        )
        device_records = []
        page_number = 1
        total_success = 0
        total_skip = 0
        while True:
            success = 0
            skip = 0
            logger_msg = (
                f"fetching devices for page {page_number} from"
                f" {PLATFORM_NAME} platform"
            )
            context["logger_msg"] = logger_msg
            response = self.microsoftintunehelper.api_helper(
                logger_msg=logger_msg,
                url=PULL_DEVICES_API_ENDPOINT,
                method="GET",
                headers=headers,
                params=query_params,
                verify=self.ssl_validation,
                proxies=self.proxy,
                configuration=self.configuration,
                storage=storage,
                is_validation=False,
                is_handle_error_required=True,
                regenerate_access_token=True,
            )
            devices_data = response.get("value", [])
            if not devices_data:
                break
            for device in devices_data:
                extracted_fields = self.parser.extract_entity_fields(
                    event=device,
                    entity_field_mapping=DEVICE_ENTITY_MAPPING,
                )
                if extracted_fields:
                    device_records.append(extracted_fields)
                    success += 1
                else:
                    skip += 1
            total_success += success
            total_skip += skip
            fetch_msg = f"Successfully fetched {success} device record(s)"
            if skip > 0:
                fetch_msg += (
                    f" , Skipped {skip} device record(s)"
                )
            self.logger.info(
                f"{self.log_prefix}: {fetch_msg} for page {page_number}."
                f" Total devices fetched: {total_success}."
            )
            next_link = response.get("@odata.nextLink")
            if next_link:
                query_params = (
                    self.microsoftintunehelper._update_query_param_with_next_link(
                        query_params=query_params, next_link=next_link
                    )
                )
                page_number += 1
            else:
                break
        self.logger.info(
            f"{self.log_prefix}: Successfully fetched {total_success}"
            f" device record(s) from {PLATFORM_NAME} platform."
        )
        if total_skip > 0:
            self.logger.info(
                f"{self.log_prefix}: Skipped {total_skip} "
                f"device record(s) from {PLATFORM_NAME} platform."
            )
        return device_records

    def _fetch_device_group_tags(self, context: Dict = {}) -> Dict:
        """
        Fetch device group tags from Microsoft Intune Windows Autopilot.

        This method retrieves group tags for Windows Autopilot devices from
        the Microsoft Intune platform. It handles pagination to fetch all
        available devices and includes error handling for API failures.
        The method fetches devices seen after the last run time.

        Args:
            context (Dict, optional): Context dictionary for logging and
                tracking purposes. Defaults to empty dict.

        Returns:
            Dict: Dictionary mapping managed device IDs to device information
                containing Device ID, Group Tag, and Serial Number.

        Raises:
            MicrosoftIntunePluginException: When API errors occur during
                data retrieval.
            Exception: For unexpected errors during the fetch operation.
        """
        access_token, storage = self.get_access_token_and_storage(
            configuration=self.configuration,
            is_validation=False,
        )
        headers = self.microsoftintunehelper.get_headers(
            access_token=access_token
        )
        self.logger.info(
            f"{self.log_prefix}: Fetching group tags for Devices"
            f" from {PLATFORM_NAME} platform.",
        )
        query_params = {
            "$top": PAGE_SIZE
        }
        page_number = 1
        windows_autopilot_devices = {}
        total_success_count = 0
        total_skip_count = 0
        while True:
            page_success_count = 0
            page_skip_count = 0
            try:
                logger_msg = (
                    "fetching group tags from windows autopilot"
                    f" for page {page_number}"
                )
                context["logger_msg"] = logger_msg
                response = self.microsoftintunehelper.api_helper(
                    logger_msg=logger_msg,
                    url=GET_GROUP_TAGS,
                    method="GET",
                    headers=headers,
                    params=query_params,
                    verify=self.ssl_validation,
                    proxies=self.proxy,
                    configuration=self.configuration,
                    storage=storage,
                    is_validation=False,
                    is_handle_error_required=True,
                    regenerate_access_token=True,
                )
                devices_data = response.get("value", [])
                if not devices_data:
                    break
                for device in devices_data:
                    managed_device_id = device.get("managedDeviceId")
                    if not managed_device_id:
                        page_skip_count += 1
                    windows_autopilot_devices[managed_device_id] = {
                        "Device ID": managed_device_id,
                        "Group Tag": device.get("groupTag", ""),
                        "Serial Number": device.get("serialNumber"),
                    }
                    page_success_count += 1
                fetch_msg = (
                    f"Successfully fetched group tags for {page_success_count}"
                    f" device(s)"
                )
                if page_skip_count > 0:
                    fetch_msg += (
                        f" and skipped fetching group tags for"
                        f" {page_skip_count} device(s)"
                    )
                self.logger.info(
                    f"{self.log_prefix}: {fetch_msg} for page {page_number}."
                )
                total_success_count += page_success_count
                total_skip_count += page_skip_count
                next_link = response.get("@odata.nextLink")
                if next_link:
                    query_params = self.microsoftintunehelper._update_query_param_with_next_link(
                        query_params=query_params,
                        next_link=next_link,
                    )
                    page_number += 1
                else:
                    break
            except MicrosoftIntunePluginException as err:
                self.logger.error(
                    f"{self.log_prefix}: Error occurred while fetching device"
                    f" group tags, hence skipping records for page"
                    f" {page_number}. Error: {err}"
                )
                # This condition checks if the error occurred was during
                # processing of the API response or during the API response
                # If the error occurred during API response there will be no
                # nextLink in the response
                # If the error occurred during processing of the API response
                # there might be nextLink in the response and if there is no
                # nextLink it indicates last page
                if isinstance(response, Dict):
                    next_link = response.get("@odata.nextLink")
                    if next_link:
                        query_params = self.microsoftintunehelper._update_query_param_with_next_link(
                            query_params=query_params,
                            next_link=next_link,
                        )
                        page_number += 1
                        continue
                    else:
                        break
                else:
                    break
            except Exception as err:
                self.logger.error(
                    f"{self.log_prefix}: Unexpected error occurred while"
                    " fetching device group tags, hence skipping records"
                    f" for page {page_number}. Error: {err}"
                )
                # Same as above
                if isinstance(response, Dict):
                    next_link = response.get("@odata.nextLink")
                    if next_link:
                        query_params = self.microsoftintunehelper._update_query_param_with_next_link(
                            query_params=query_params,
                            next_link=next_link,
                        )
                        page_number += 1
                        continue
                    else:
                        break
                else:
                    break
        self.logger.info(
            f"{self.log_prefix}: Successfully fetched group tags for"
            f" {total_success_count} device(s) from {PLATFORM_NAME}"
            f" platform."
        )
        if total_skip_count > 0:
            self.logger.info(
                f"{self.log_prefix}: Failed to fetch group tags for"
                f" {total_skip_count} device(s) as ID field was empty."
            )
        return windows_autopilot_devices

    @exception_handler
    def _update_devices_with_group_tag(
        self, devices: Dict, context: Dict = {}
    ) -> Dict[str, Dict]:
        """
        Update device records with group tags from Windows Autopilot.

        This method enriches device records by fetching and matching group
        tags from Windows Autopilot devices. It matches devices by their
        Device ID and creates a dictionary of updated device records that
        include group tag information.

        Args:
            devices (Dict): Collection of device records to be updated with
                group tags.
            context (Dict, optional): Context dictionary for logging and
                tracking purposes. Defaults to empty dict.

        Returns:
            Dict[str, Dict]: Dictionary mapping device IDs to updated device
                records containing Device ID, Group Tag, and Serial Number
                for devices that were successfully matched with Windows
                Autopilot data.

        Note:
            Only devices that exist in both the input devices collection and
            the Windows Autopilot devices will be included in the result.
            Devices not found in Windows Autopilot are logged as skipped.
        """
        context["logger_msg"] = "updating devices with group tags"
        updated_devices = {}
        success = 0
        skip = 0
        windows_autopilot_devices = self._fetch_device_group_tags()
        for device in devices:
            device_id = device.get("Device ID")
            if device_id in windows_autopilot_devices:
                updated_devices[
                    device_id
                ] = windows_autopilot_devices[device_id]
                success += 1
            else:
                skip += 1
        self.logger.info(
            f"{self.log_prefix}: Successfully updated {success}"
            f" device(s) with group tags. Skipped updating"
            f" {skip} device(s) with group tags as they were"
            f" not found on {PLATFORM_NAME} platform."
        )
        return updated_devices

    def _fetch_device_health_scores(self) -> Dict[str, Dict[str, Any]]:
        """
        Fetch device health scores from Microsoft Intune.

        Returns:
            Dict[str, Dict[str, Any]]: Device health scores.
        """
        access_token, storage = self.get_access_token_and_storage(
            configuration=self.configuration,
            is_validation=False,
        )
        headers = self.microsoftintunehelper.get_headers(
            access_token=access_token,
        )
        device_health_scores = {}
        page_number = 1
        query_params = {
            "$top": PAGE_SIZE
        }
        total_success_count = 0
        total_skip_count = 0
        while True:
            page_success_count = 0
            page_skip_count = 0
            try:
                logger_msg = (
                    f"fetching device health score for page {page_number}"
                    f" from {PLATFORM_NAME} platform"
                )
                response = None
                response = self.microsoftintunehelper.api_helper(
                    logger_msg=logger_msg,
                    url=GET_DEVICE_HEALTH_SCORE_API_ENDPOINT,
                    method="GET",
                    headers=headers,
                    params=query_params,
                    verify=self.ssl_validation,
                    proxies=self.proxy,
                    configuration=self.configuration,
                    storage=storage,
                    is_validation=False,
                    is_handle_error_required=True,
                    regenerate_access_token=True,
                )
                health_score_data = response.get("value", [])
                if not health_score_data:
                    break
                for health_data in health_score_data:
                    extracted_fields = self.parser.extract_entity_fields(
                        event=health_data,
                        entity_field_mapping=DEVICE_HEALTH_SCORE_MAPPING,
                    )
                    device_id = health_data.get("id")
                    if extracted_fields and device_id:
                        device_health_scores[device_id] = extracted_fields
                        page_success_count += 1
                    else:
                        page_skip_count += 1
                fetch_msg = (
                    "Successfully fetched health scores for"
                    f" {page_success_count} device(s)"
                )
                if page_skip_count > 0:
                    fetch_msg += (
                        f" and skipped fetching health scores for"
                        f" {page_skip_count} device(s)"
                    )
                self.logger.info(
                    f"{self.log_prefix}: {fetch_msg} for page {page_number}."
                )
                total_success_count += page_success_count
                total_skip_count += page_skip_count
                next_link = response.get("@odata.nextLink")
                if next_link:
                    query_params = (
                        self.microsoftintunehelper._update_query_param_with_next_link(
                            query_params=query_params, next_link=next_link
                        )
                    )
                    page_number += 1
                else:
                    break
            except MicrosoftIntunePluginException as err:
                self.logger.error(
                    f"{self.log_prefix}: Error occurred while fetching device"
                    f" health scores, hence skipping records for page"
                    f" {page_number}. Error: {err}"
                )
                # This condition checks if the error occurred was during
                # processing of the API response or during the API response
                # If the error occurred during API response there will be no
                # nextLink in the response
                # If the error occurred during processing of the API response
                # there might be nextLink in the response and if there is no
                # nextLink it indicates last page
                if isinstance(response, Dict):
                    next_link = response.get("@odata.nextLink")
                    if next_link:
                        query_params = self.microsoftintunehelper._update_query_param_with_next_link(
                            query_params=query_params,
                            next_link=next_link,
                        )
                        page_number += 1
                        continue
                    else:
                        break
                else:
                    break
            except Exception as err:
                err_msg = (
                    f"{self.log_prefix}: Unexpected error occurred while"
                    f" {logger_msg}. Error: {err}."
                )
                self.logger.error(
                    message=err_msg,
                    details=traceback.format_exc(),
                )
                self.logger.error(
                    f"{self.log_prefix}: Unexpected error occurred while"
                    f" fetching device health scores, hence skipping records"
                    f" for page {page_number}. Error: {err}"
                )
                # Same as above
                if isinstance(response, Dict):
                    next_link = response.get("@odata.nextLink")
                    if next_link:
                        query_params = self.microsoftintunehelper._update_query_param_with_next_link(
                            query_params=query_params,
                            next_link=next_link,
                        )
                        page_number += 1
                        continue
                    else:
                        break
                else:
                    break
        self.logger.info(
            f"{self.log_prefix}: Successfully fetched health score for"
            f" {total_success_count} device(s) from {PLATFORM_NAME}"
            f" platform."
        )
        if page_skip_count > 0:
            self.logger.info(
                f"{self.log_prefix}: Failed to fetch health scores for"
                f" {page_skip_count} device(s) as ID field was empty."
            )
        return device_health_scores

    @exception_handler
    def _update_devices_with_health_score(
        self,
        devices: List[Dict],
        context: Dict = {},
    ) -> Dict[str, Dict]:
        """
        Update devices with health scores.

        Args:
            devices (List[Dict]): List of devices.
            context (Dict, optional): Context. Defaults to {}.

        Returns:
            Dict[str, Dict]: Dict of updated devices.
        """
        context["logger_msg"] = "updating devices with health scores"
        device_health_scores = self._fetch_device_health_scores()
        updated_devices = {}
        success = 0
        skip = 0
        for device in devices:
            device_id = device.get("Device ID")
            if device_id in device_health_scores:
                updated_devices[device_id] = device_health_scores[device_id]
                success += 1
            else:
                skip += 1
        self.logger.info(
            f"{self.log_prefix}: Successfully updated {success}"
            f" device(s) with health scores. Skipped updating"
            f" {skip} device(s) with health scores as they were"
            f" not found on {PLATFORM_NAME} platform."
        )
        return updated_devices

    def _update_records(
        self,
        devices_with_group_tags: Dict[str, Dict],
        devices_with_health_scores: Dict[str, Dict],
    ) -> List[Dict]:
        """
        Merge device records with group tags and health scores.

        This method combines device data from two sources: devices with group
        tags and devices with health scores. For devices that exist in both
        dictionaries, it merges their data. Devices that exist in only one
        dictionary are included as-is in the final result.

        The method modifies the input dictionaries by removing processed
        entries to avoid duplication in the final result.

        Args:
            devices_with_group_tags (Dict[str, Dict]): Dictionary mapping
                device IDs to device data containing group tags.
            devices_with_health_scores (Dict[str, Dict]): Dictionary mapping
                device IDs to device data containing health scores.

        Returns:
            List[Dict]: List of merged device records containing combined data
                from both sources where available, plus individual records
                from devices that exist in only one source.
        """
        updated_devices = []
        iterator_dict = deepcopy(devices_with_group_tags)
        search_dict = deepcopy(devices_with_health_scores)
        # Combine the records that have both group tags and device health score
        for device_id, data in iterator_dict.items():
            if device_id in search_dict:
                data.update(search_dict[device_id])
                updated_devices.append(data)
                devices_with_group_tags.pop(device_id)
                devices_with_health_scores.pop(device_id)
        # Add the remaining values
        updated_devices.extend(devices_with_group_tags.values())
        updated_devices.extend(devices_with_health_scores.values())
        return updated_devices

    def get_actions(self) -> List[ActionWithoutParams]:
        """Get available actions.

        Args:
            None

        Returns:
            [...] list of ActionWithoutParams: List of ActionWithoutParams
                which has label and value defined

        """
        return [
            ActionWithoutParams(label="Reboot Device", value="reboot"),
            ActionWithoutParams(label="Sync Device", value="sync"),
            ActionWithoutParams(
                label="Run Windows Defender Scan", value="run"
            ),
            ActionWithoutParams(
                label="Update Windows Defender Signatures", value="update"
            ),
            ActionWithoutParams(label="No action", value="generate"),
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
        if action.value == "reboot":
            return [
                {
                    "label": "Device ID",
                    "key": "device_id",
                    "type": "text",
                    "default": "",
                    "mandatory": True,
                    "description": "ID of device to be rebooted.",
                }
            ]
        if action.value == "sync":
            return [
                {
                    "label": "Device ID",
                    "key": "device_id",
                    "type": "text",
                    "default": "",
                    "mandatory": True,
                    "description": "ID of device to be synced.",
                }
            ]
        if action.value == "run":
            return [
                {
                    "label": "Device ID",
                    "key": "device_id",
                    "type": "text",
                    "default": "",
                    "mandatory": True,
                    "description": (
                        "ID of device for which Windows Defender"
                        " scan is to be run."
                    )
                },
                {
                    "label": "Scan Type",
                    "key": "scan_type",
                    "type": "choice",
                    "choices": [
                        {
                            "key": "Quick Scan",
                            "value": "quick scan",
                        },
                        {
                            "key": "Full Scan",
                            "value": "full scan",
                        }
                    ],
                    "mandatory": True,
                    "default": "quick scan",
                    "description": (
                        "Indicates whether to run a quick scan"
                        " or a full scan."
                    )
                }
            ]
        if action.value == "update":
            return [
                {
                    "label": "Device ID",
                    "key": "device_id",
                    "type": "text",
                    "default": "",
                    "mandatory": True,
                    "description": (
                        "ID of device for which Windows Defender Signatures"
                        " are to be updated."
                    )
                }
            ]

    def validate_action(self, action: Action) -> ValidationResult:
        """Validate plugin action configuration.

        Args:
            action (Action): The type of action

        Returns:
            ValidationResult: validation result true or false with message
        """
        action_value = action.value
        if action_value == "generate":
            log_msg = (
                "Successfully validated action configuration"
                f" for '{action.label}'."
            )
            self.logger.debug(f"{self.log_prefix}: {log_msg}")
            return ValidationResult(success=True, message=log_msg)
        if action_value not in ["generate", "reboot", "sync", "run", "update"]:
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Unsupported action '{action_value}'"
                    f" provided in the action configuration. Supported actions"
                    " are - 'No Action', 'Reboot Device', 'Sync Device', 'Run"
                    " Windows Defender Scan', 'Update Windows Defender"
                    " Signatures'."
                ),
                resolution=(
                    "Please select any one of the supported actions. "
                    "Supported actions are - 'No Action', 'Reboot Device',"
                    " 'Sync Device', 'Run Windows Defender Scan', 'Update"
                    " Windows Defender Signatures'."
                )
            )
            return ValidationResult(
                success=False, message="Unsupported action provided."
            )
        device_id = action.parameters.get("device_id", "")
        if action_value in ["reboot", "sync", "run", "update"]:
            if validation_failure := self._validate_parameters(
                parameter_type=ACTION,
                field_name="Device ID",
                field_value=device_id,
                field_type=str,
                check_dollar=True,
            ):
                return validation_failure
        if action_value == "run":
            scan_type = action.parameters.get("scan_type", "")
            if validation_failure := self._validate_parameters(
                parameter_type=ACTION,
                field_name="Scan Type",
                field_value=scan_type,
                field_type=str,
                allowed_values=["quick scan", "full scan"],
            ):
                return validation_failure

        return ValidationResult(
            success=True, message="Successfully validated action parameters."
        )

    def execute_actions(self, actions: List[Action]):
        """
        Execute Microsoft Intune action.

        Args:
            actions (List[Action]): List of actions.

        Returns:
            None
        """
        first_action = (
            actions[0].get("params", {})
            if self._is_ce_post_v512
            else actions[0]
        )
        action_label = first_action.label
        action_value = first_action.value
        if action_value == "generate":
            self.logger.info(
                f"{self.log_prefix}: Successfully executed '{action_label}"
                "' action. Note: No processing will be done from plugin"
                f" for the '{action_label}' action."
            )
            return
        if action_url := ACTION_API_ENDPOINT_MAPPING.get(action_value, ""):
            action_batches = self.parser.create_batches_for_action(
                actions=actions,
                api_endpoint=action_url,
                batch_size=ACTION_BATCH_SIZE,
            )
            total_success, total_fail, failed_action_ids = (
                self._execute_msintune_action(
                    batched_action=action_batches, action_name=action_label
                )
            )
            self.logger.info(
                message=(
                    f"{self.log_prefix}: Successfully executed action "
                    f"'{action_label}'. Expand the log to view action stats."
                ),
                details=f"Success: {total_success}, Fail: {total_fail}"
            )
            # If CE supports partial action failure return ActionResult
            # model
            if self._is_ce_post_v512:
                from netskope.integrations.crev2.plugin_base import \
                    ActionResult
                return ActionResult(
                    success=True,
                    message=(
                        f"Successfully executed {action_label} action."
                    ),
                    failed_action_ids=failed_action_ids,
                )
            return
        else:
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Unsupported action '{action_value}'"
                    f" provided in the action configuration. Supported actions"
                    " are - 'No Action', 'Reboot Device', 'Sync Device', 'Run"
                    " Windows Defender Scan', 'Update Windows Defender"
                    " Signatures'."
                ),
                resolution=(
                    "Please select any one of the supported actions. "
                    "Supported actions are - 'No Action', 'Reboot Device',"
                    " 'Sync Device', 'Run Windows Defender Scan', 'Update"
                    " Windows Defender Signatures'."
                ),
            )

    def _execute_msintune_action(
        self,
        batched_action: Dict[int, List[Dict[str, Any]]],
        action_name: str
    ) -> Tuple[int, int, List]:
        """
        Execute Microsoft Intune action.

        Args:
            batched_action (Dict[int, List[Dict[str, Any]]]): Batched action.
            action_name (str): Action name.

        Returns:
            Tuple[int, int, List]: Total success, total failed, and failed
                action IDs.
        """
        access_token, storage = self.get_access_token_and_storage(
            configuration=self.configuration,
            is_validation=False,
        )
        headers = self.microsoftintunehelper.get_headers(
            access_token=access_token
        )
        total_success = 0
        total_failed = 0
        total_failed_action_ids = set()
        for batch_number, batched_requests in batched_action.items():
            logger_msg = (
                f"Executing '{action_name}' action for batch number"
                f" {batch_number} on {PLATFORM_NAME} platform"
            )
            self.logger.info(
                f"{self.log_prefix}: {logger_msg}"
            )
            try:
                response = self.microsoftintunehelper.api_helper(
                    logger_msg=logger_msg,
                    method="POST",
                    headers=headers,
                    url=BATCHED_API_ENDPOINT,
                    json={"requests": batched_requests},
                    verify=self.ssl_validation,
                    proxies=self.proxy,
                    configuration=self.configuration,
                    storage=storage,
                    is_validation=False,
                    is_handle_error_required=True,
                    regenerate_access_token=True,
                )
                (
                    success,
                    failed,
                    failure_reason,
                    failed_action_ids
                ) = self.parser.parse_batched_response(
                    batched_response=response,
                )
                self.logger.info(
                    f"{self.log_prefix}: Successfully executed '{action_name}'"
                    f" on {success} device(s) for batch {batch_number}."
                )
                if failed:
                    self.logger.error(
                        message=(
                            f"{self.log_prefix}: Failed to execute "
                            f"'{action_name}' action on {failed} device(s)"
                            f" for batch {batch_number}."
                        ),
                        details=(
                            "Failed device ID(s):"
                            f" {', '.join(failure_reason.keys())}"
                            f"\nFailure Reason(s): {failure_reason}"
                        ),
                    )
                total_success += success
                total_failed += failed
                total_failed_action_ids.update(failed_action_ids)
            except MicrosoftIntunePluginException as err:
                failed_action_ids = (
                    self.parser.parse_failed_batched_request(
                        batched_request=batched_requests,
                    )
                )
                total_failed_action_ids.update(failed_action_ids)
                err_msg = (
                    f"Failed to execute '{action_name}' on"
                    f" {len(failed_action_ids)} device(s) for"
                    f" batch {batch_number}"
                )
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg}. Error: {err}",
                )
                continue
            except Exception as err:
                failed_action_ids = (
                    self.parser.parse_failed_batched_request(
                        batched_request=batched_requests,
                    )
                )
                total_failed_action_ids.update(failed_action_ids)
                err_msg = (
                    f"Unexpected error occurred while executing"
                    f" '{action_name}' on {len(failed_action_ids)}"
                    f" device(s) for batch {batch_number}"
                )
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg}. Error: {err}",
                    details=traceback.format_exc(),
                )
                continue
        return total_success, total_failed, total_failed_action_ids
