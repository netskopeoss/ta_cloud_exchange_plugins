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

CRE Omnissa Workspace One UEM
"""

import traceback
from typing import Callable, Dict, List, Literal, Set, Tuple, Type, Union
from urllib.parse import urlparse

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
    ACTION_BATCH_SIZE,
    CONFIGURATION,
    CONFIGURATION_BOOLEAN_VALUES,
    CREATE_TAG_ENDPOINT,
    CUSTOM_SEPARATOR,
    DEVICE_ENTITY_MAPPING,
    EMPTY_ERROR_MESSAGE,
    FETCH_TAGS_ENDPOINT,
    GET,
    INVALID_VALUE_ERROR_MESSAGE,
    MAXIMUM_CE_VERSION,
    MODULE_NAME,
    NO,
    OAUTH_URLS,
    ONE,
    PAGE_SIZE,
    PLATFORM_NAME,
    PLUGIN_VERSION,
    POST,
    PULL_DEVICE_NETWORK_ENDPOINT,
    PULL_DEVICE_TAGS_ENDPOINT,
    PULL_DEVICES_ENDPOINT,
    TAG_CHARACTER_LENGTH_LIMIT,
    TAG_DEVICE_ENDPOINT,
    TWO,
    TYPE_ERROR_MESSAGE,
    UNTAG_DEVICE_ENDPOINT,
    VALIDATE_CONNECTIVITY_ENDPOINT,
    VALIDATION_ERROR_MESSAGE,
)
from .utils.exceptions import OmnissaWorkspaceOneUEMPluginException
from .utils.helper import OmnissaWorkspaceOneUEMHelper
from .utils.parser import OmnissaWorkspaceOneUEMParser


class OmnissaWorkspaceOneUEMPlugin(PluginBase):
    def __init__(self, name, *args, **kwargs):
        """OmnissaWorkspaceOneUEM plugin initializer.

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
        self.parser = OmnissaWorkspaceOneUEMParser(
            logger=self.logger,
            log_prefix=self.log_prefix,
            is_ce_post_v512=self._is_ce_post_v512
        )
        self.omnissa_workspace_one_uem_helper = OmnissaWorkspaceOneUEMHelper(
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
            manifest_json = OmnissaWorkspaceOneUEMPlugin.metadata
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
        return version.parse(CE_VERSION) > version.parse(MAXIMUM_CE_VERSION)

    def _patch_error_logger(self):
        """Monkey patch logger methods to handle resolution parameter
        compatibility.
        """
        # Store original methods
        original_error = self.logger.error

        def patched_error(
            message=None, details=None, resolution=None, **kwargs
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
        """Get storage object."""
        storage = self.storage if self.storage is not None else {}
        return storage

    def get_access_token_and_storage(self, configuration: Dict) -> str:
        """
        Get access token and storage object.
        """
        storage = self._get_storage()
        stored_config_hash = storage.get("config_hash", "")
        api_base_url, oauth_url, client_id, client_secret, _ = (
            self.omnissa_workspace_one_uem_helper.get_configuration_parameters(
                configuration=configuration
            )
        )
        generated_config_hash = (
            self.omnissa_workspace_one_uem_helper.generate_config_hash(
                config_string=(
                    f"{api_base_url}{oauth_url}{client_id}{client_secret}"
                )
            )
        )
        if storage.get("access_token") and (
            stored_config_hash == generated_config_hash
        ):
            return storage.get("access_token"), storage
        else:
            access_token = self.omnissa_workspace_one_uem_helper.generate_access_token_and_update_storage(
                oauth_url=oauth_url,
                client_id=client_id,
                client_secret=client_secret,
                verify=self.ssl_validation,
                proxies=self.proxy,
                storage=storage,
            )
            storage.update(
                {"config_hash": generated_config_hash}
            )
            return access_token, storage

    def _validate_url(self, url: str) -> bool:
        """Validate the URL using parsing.

        Args:
            url (str): Given URL.

        Returns:
            bool: True or False { Valid or not Valid URL }.
        """
        parsed = urlparse(url)
        return parsed.scheme.strip() != "" and parsed.netloc.strip() != ""

    def validate(self, configuration: Dict) -> ValidationResult:
        """Validate the plugin configuration parameters."""
        base_url, oauth_url, client_id, client_secret, pull_device_tags = (
            self.omnissa_workspace_one_uem_helper.get_configuration_parameters(
                configuration=configuration
            )
        )
        if validation_failure := self._validate_parameters(
            parameter_type=CONFIGURATION,
            field_name="API Base URL",
            field_value=base_url,
            field_type=str,
            custom_validation_func=self._validate_url
        ):
            return validation_failure
        if validation_failure := self._validate_parameters(
            parameter_type=CONFIGURATION,
            field_name="OAuth URL",
            field_value=oauth_url,
            field_type=str,
            allowed_values=OAUTH_URLS,
            custom_validation_func=self._validate_url
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

        if validation_failure := self._validate_parameters(
            parameter_type=CONFIGURATION,
            field_name="Pull Device Tags",
            field_value=pull_device_tags,
            field_type=str,
            allowed_values=CONFIGURATION_BOOLEAN_VALUES,
        ):
            return validation_failure
        return self._validate_connectivity(
            base_url=base_url, configuration=configuration
        )

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
        """
        Validate the plugin parameters.

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
                )
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
                )
            )
            return ValidationResult(success=False, message=err_msg)

    def _validate_connectivity(
        self,
        base_url: str,
        configuration: Dict,
    ) -> ValidationResult:
        """Validate connectivity with the platform."""
        logger_msg = f"Validating connectivity with {PLATFORM_NAME} platform"
        try:
            access_token, storage = self.get_access_token_and_storage(
                configuration=configuration
            )
            headers = self.omnissa_workspace_one_uem_helper.get_auth_headers(
                access_token,
                api_version=ONE,
            )
            url = VALIDATE_CONNECTIVITY_ENDPOINT.format(
                base_url=base_url,
            )
            self.omnissa_workspace_one_uem_helper.api_helper(
                logger_msg=logger_msg,
                url=url,
                method=GET,
                headers=headers,
                verify=self.ssl_validation,
                proxies=self.proxy,
                storage=storage,
                configuration=configuration,
                is_validation=True,
                is_handle_error_required=True,
                regenerate_access_token=True,
            )
            self.logger.debug(
                f"{self.log_prefix}: Successfully validated connectivity with"
                f" {PLATFORM_NAME} platform."
            )
            return ValidationResult(
                success=True,
                message=f"Successfully validated connectivity with"
                f" {PLATFORM_NAME} platform.",
            )
        except OmnissaWorkspaceOneUEMPluginException as err:
            return ValidationResult(
                success=False,
                message=str(err),
            )
        except Exception as err:
            err_msg = (
                f"Unexpected error occurred while {logger_msg}."
                f" Error: {err}"
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
                        name="Device UUID",
                        type=EntityFieldType.STRING,
                        required=True,
                    ),
                    EntityField(
                        name="Device ID",
                        type=EntityFieldType.STRING,
                        required=True,
                    ),
                    EntityField(
                        name="Organization ID",
                        type=EntityFieldType.STRING,
                        required=True,
                    ),
                    EntityField(
                        name="Device Serial Number",
                        type=EntityFieldType.STRING,
                        required=True,
                    ),
                    # The network API sometimes provides multiple Mac
                    # and IP addresses hence making these fields a list
                    EntityField(
                        name="Mac Address",
                        type=EntityFieldType.LIST,
                    ),
                    EntityField(
                        name="IP Address",
                        type=EntityFieldType.LIST,
                    ),
                    EntityField(
                        name="Tags",
                        type=EntityFieldType.LIST,
                    ),
                    EntityField(
                        name="IMEI",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="Asset Number",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="Hostname",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="Local Hostname",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="User Name",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="User Email Address",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="Compliance Status",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="Compromised Status",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="Enrollment Status",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="UDID",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="Eas ID",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="Device Friendly Name",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="Device Reported Name",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="Organization Name",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="Platform",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="Model",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="Operating System",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="Last Seen",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="OS Build Version",
                        type=EntityFieldType.STRING,
                    ),
                ],
            ),
        ]

    def fetch_records(self, entity: str) -> List[Dict]:
        """Fetch users and endpoints records from Palo Alto Cortex XDR.

        Args:
            entity (str): Entity to be fetched.

        Returns:
            List: List of records to be stored on the platform.
        """
        records = []
        entity_name = entity.lower()
        base_url, *_ = (
            self.omnissa_workspace_one_uem_helper.get_configuration_parameters(
                self.configuration
            )
        )
        self.logger.info(
            f"{self.log_prefix}: Fetching {entity_name} records from "
            f"{PLATFORM_NAME} platform."
        )
        records = []
        if entity_name == "devices":
            device_records = self._fetch_devices(
                base_url=base_url,
            )
            records.extend(device_records)
        else:
            err_msg = (
                f"Invalid entity found. {PLATFORM_NAME} plugin "
                "only supports 'Devices' Entity."
            )
            self.logger.error(message=f"{self.log_prefix}: {err_msg}")
            raise OmnissaWorkspaceOneUEMPluginException(err_msg)
        return records

    def _fetch_devices(self, base_url: str) -> List[Dict]:
        """Fetch devices.

        Args:
            base_url (str): Base URL.

        Returns:
            List: List of devices.
        """
        access_token, storage = self.get_access_token_and_storage(
            self.configuration
        )
        url = PULL_DEVICES_ENDPOINT.format(
            base_url=base_url
        )
        headers = self.omnissa_workspace_one_uem_helper.get_auth_headers(
            access_token,
            api_version=TWO,
        )
        query_params = {
            "page": 0,
            "page_size": PAGE_SIZE,
            "sort": "last_seen",
            "sort_order": "ASC",
        }
        devices_records = []
        total_skip_count = 0
        total_device_fetched = 0
        page_number = 0
        try:
            while True:
                device_fetch_count = 0
                device_skip_count = 0
                query_params["page"] = page_number
                logger_msg = (
                    f"fetching devices for page {page_number + 1} from"
                    f" {PLATFORM_NAME} platform"
                )
                response = self.omnissa_workspace_one_uem_helper.api_helper(
                    logger_msg=logger_msg,
                    url=url,
                    method=GET,
                    params=query_params,
                    headers=headers,
                    verify=self.ssl_validation,
                    proxies=self.proxy,
                    configuration=self.configuration,
                    storage=storage,
                    is_validation=False,
                    is_handle_error_required=True,
                    regenerate_access_token=True,
                )
                if not response:
                    break
                # Fetching devices
                for device in response.get("Devices", []):
                    extracted_data = self.parser.extract_entity_fields(
                        event=device,
                        entity_field_mapping=DEVICE_ENTITY_MAPPING,
                    )
                    if extracted_data:
                        devices_records.append(extracted_data)
                        device_fetch_count += 1
                    else:
                        device_skip_count += 1
                total_device_fetched += device_fetch_count
                total_skip_count += device_skip_count
                self.logger.info(
                    f"{self.log_prefix}: Successfully fetched "
                    f"{device_fetch_count} device record(s),"
                    f" Skipped {device_skip_count} device record(s) "
                    f"for page {page_number + 1}. Total devices fetched"
                    f": {total_device_fetched}."
                )
                if response.get("Total") < PAGE_SIZE:
                    break
                page_number += 1
        except OmnissaWorkspaceOneUEMPluginException:
            raise
        except Exception as err:
            err_msg = (
                f"Unexpected error occurred while {logger_msg}."
                f" Error: {err}"
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=traceback.format_exc(),
            )
            raise OmnissaWorkspaceOneUEMPluginException(err_msg)
        self.logger.info(
            f"{self.log_prefix}: Successfully fetched "
            f"{total_device_fetched} device record(s)"
            f" from {PLATFORM_NAME} platform."
        )
        if total_skip_count > 0:
            self.logger.info(
                f"{self.log_prefix}: Skipped {total_skip_count} "
                f"device record(s) from {PLATFORM_NAME} platform."
            )
        return devices_records

    def _fetch_device_tags(
        self,
        base_url: str,
        headers: Dict,
        device_uuid: str,
        logger_msg: str,
        storage: Dict,
    ) -> List[str]:
        """
        Fetch device tags

        Args:
            base_url (str): Platform base URL.
            headers (Dict): Headers.
            device_uuid (str): UUID of device to fetch tags.
            logger_msg (str): Logger message.
            storage (Dict): Plugin storage object.

        Returns:
            List[str]: List of device tags
        """
        device_tags = []
        try:
            response = self.omnissa_workspace_one_uem_helper.api_helper(
                logger_msg=logger_msg,
                url=PULL_DEVICE_TAGS_ENDPOINT.format(
                    base_url=base_url,
                    device_uuid=device_uuid
                ),
                method=GET,
                headers=headers,
                verify=self.ssl_validation,
                proxies=self.proxy,
                configuration=self.configuration,
                storage=storage,
                is_validation=False,
                is_handle_error_required=True,
                regenerate_access_token=True,
            )
            for tag in response.get("tags", []):
                if tag_name := tag.get("name"):
                    device_tags.append(tag_name)
            return device_tags
        except OmnissaWorkspaceOneUEMPluginException as err:
            err_msg = (
                f"Failed to fetch tags for Device {device_uuid}"
                f" from {PLATFORM_NAME} platform. Error: {err}"
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}"
            )
            raise OmnissaWorkspaceOneUEMPluginException(err_msg)
        except Exception as err:
            err_msg = (
                f"Unexpected error occurred while {logger_msg}"
                f" Error: {err}"
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=traceback.format_exc(),
            )
            raise OmnissaWorkspaceOneUEMPluginException(err_msg)

    def _update_devices_with_tags(
        self,
        base_url: str,
        devices: List[Dict],
        access_token: str,
        storage: Dict
    ) -> List[str]:
        """
        Update devices with tags

        Args:
            base_url (str): Platform base URL.
            devices (List[Dict]): List of devices to update.
            access_token (str): Access token.
            storage (Dict): Plugin storage object.

        Returns:
            List[str]: List of updated devices.
        """
        headers = self.omnissa_workspace_one_uem_helper.get_auth_headers(
            access_token=access_token,
            api_version=ONE,
        )
        logger_msg_base = (
            "fetching tags for Device {device_uuid} from"
            " {platform_name} platform"
        )
        success = 0
        skip = 0
        skipped_devices = []
        empty_id_skip = 0
        updated_devices = []
        for device in devices:
            try:
                device_uuid = device.get("Device UUID")
                if not device_uuid:
                    skip += 1
                    empty_id_skip += 1
                    continue
                logger_msg = logger_msg_base.format(
                    device_uuid=device_uuid,
                    platform_name=PLATFORM_NAME,
                )
                device_tags = self._fetch_device_tags(
                    base_url=base_url,
                    headers=headers,
                    device_uuid=device_uuid,
                    logger_msg=logger_msg,
                    storage=storage,
                )
                device.update({"Tags": device_tags})
                updated_devices.append(device)
                success += 1
            except OmnissaWorkspaceOneUEMPluginException:
                skip += 1
                skipped_devices.append(device_uuid)
                continue
            except Exception as err:
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: Unexpected error occurred"
                        f" while {logger_msg}. Error: {err}"
                    ),
                    details=traceback.format_exc(),
                )
                skip += 1
                skipped_devices.append(device_uuid)
                continue
        self.logger.info(
            f"{self.log_prefix}: Successfully fetched tags"
            f" for {success} Device(s)."
        )
        if skip > 0:
            self.logger.info(
                message=(
                    f"{self.log_prefix}: Skipped fetching tags"
                    f" for {skip} Device(s)."
                ),
                details=f"Skipped Devices: {', '.join(skipped_devices)}",
            )
        if empty_id_skip > 0:
            self.logger.info(
                f"{self.log_prefix}: Skipped fetching tags for"
                f" {empty_id_skip} Device(s) since 'Device ID'"
                " is empty."
            )
        return updated_devices

    def _fetch_device_network_details(
        self,
        base_url: str,
        headers: Dict,
        device_id: str,
        logger_msg: str,
        storage: Dict,
    ) -> Tuple[List[str], List[str]]:
        """
        Fetch network details (IP and MAC addresses) for a specific device.

        This method retrieves network information for a device from the
        Workspace ONE UEM platform, including IP addresses and MAC addresses.
        It parses the response and extracts relevant network information.

        Args:
            base_url: Base URL of the Workspace ONE UEM API
            headers: HTTP headers with authentication information
            device_id: ID of the device to fetch network details for
            logger_msg: Message template for logging
            storage: Dictionary for storing session information

        Returns:
            Tuple[List[str], List[str]]: A tuple containing:
                - List of IP addresses associated with the device
                - List of MAC addresses associated with the device

        Raises:
            OmnissaWorkspaceOneUEMPluginException: If an error occurs during
                the API request or while processing the response
        """
        device_ip_address = []
        device_mac_address = []
        try:
            response = self.omnissa_workspace_one_uem_helper.api_helper(
                logger_msg=logger_msg,
                url=PULL_DEVICE_NETWORK_ENDPOINT.format(
                    base_url=base_url,
                    device_id=device_id
                ),
                method=GET,
                headers=headers,
                verify=self.ssl_validation,
                proxies=self.proxy,
                configuration=self.configuration,
                storage=storage,
                is_validation=False,
                is_handle_error_required=True,
                regenerate_access_token=True,
            )
            ip_address_details = response.get("IPAddress", {})
            mac_address_details = response.get("DeviceNetworkInfo", [])
            for _, ip_address in ip_address_details.items():
                if ip_address:
                    device_ip_address.append(ip_address)
            for mac_address_data in mac_address_details:
                if mac_address := mac_address_data.get("MACAddress"):
                    device_mac_address.append(mac_address)
            return device_ip_address, device_mac_address
        except OmnissaWorkspaceOneUEMPluginException as err:
            err_msg = (
                f"Failed to fetch network info for Device {device_id}"
                f" from {PLATFORM_NAME} platform. Error: {err}"
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
            )
            raise OmnissaWorkspaceOneUEMPluginException(err_msg)
        except Exception as err:
            err_msg = (
                f"Unexpected error occurred while {logger_msg}"
                f" Error: {err}"
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=traceback.format_exc(),
            )
            raise OmnissaWorkspaceOneUEMPluginException(err_msg)

    def _update_devices_with_network_info(
        self,
        base_url: str,
        devices: List[Dict],
        access_token: str,
        storage: Dict,
    ):
        """
        Update device records with network information (IP and MAC addresses).

        This method processes a list of device records and enriches each
        record with network information by fetching IP addresses and MAC
        addresses from the Workspace ONE UEM platform. It handles
        authentication, API requests, and error conditions while tracking
        successful and failed operations.

        Args:
            base_url: Base URL of the Workspace ONE UEM API
            devices: List of device records to be updated with network
                information
            access_token: Access token for authentication
            storage: Plugin storage object

        Returns:
            List[Dict]: List of device records enriched with IP and MAC
                address information

        Note:
            - Devices with missing Device IDs are skipped
            - Exceptions during network info retrieval are logged and the
                device is skipped
            - Each device record is updated with "IP Address" and
                "Mac Address" fields
        """
        headers = self.omnissa_workspace_one_uem_helper.get_auth_headers(
            access_token=access_token,
            api_version=ONE,
        )
        logger_msg_base = (
            "fetching network info for Device {device_id}"
            " from {platform_name} platform"
        )
        success = 0
        skip = 0
        skipped_devices = []
        empty_id_skip = 0
        updated_devices = []
        for device in devices:
            try:
                device_id = device.get("Device ID")
                if not isinstance(device_id, int) and not device_id:
                    empty_id_skip += 1
                    continue
                logger_msg = logger_msg_base.format(
                    device_id=device_id,
                    platform_name=PLATFORM_NAME,
                )
                device_ip_address, device_mac_address = (
                    self._fetch_device_network_details(
                        base_url=base_url,
                        headers=headers,
                        device_id=device_id,
                        logger_msg=logger_msg,
                        storage=storage,
                    )
                )
                device.update(
                    {
                        "IP Address": device_ip_address,
                        "Mac Address": device_mac_address,
                    }
                )
                updated_devices.append(device)
                success += 1
            except OmnissaWorkspaceOneUEMPluginException:
                skip += 1
                skipped_devices.append(device_id)
                continue
            except Exception as err:
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: Unexpected error occurred"
                        f" while {logger_msg}. Error: {err}"
                    ),
                    details=traceback.format_exc(),
                )
                skip += 1
                skipped_devices.append(device_id)
                continue
        self.logger.info(
            f"{self.log_prefix}: Successfully fetched network"
            f" info for {success} Device(s)."
        )
        if skip > 0:
            self.logger.info(
                message=(
                    f"{self.log_prefix}: Skipped fetching network"
                    f" info for {skip} Device(s)."
                ),
                details=f"Skipped Devices: {', '.join(skipped_devices)}",
            )
        if empty_id_skip > 0:
            self.logger.info(
                f"{self.log_prefix}: Skipped fetching network info for"
                f" {empty_id_skip} Device(s) since 'Device ID'"
                " is empty."
            )
        return updated_devices

    def update_records(self, entity: str, records: list[dict]) -> List[Dict]:
        """Update records.

        Args:
            entity (str): Entity to be updated.
            records (list): Records to be updated.

        Returns:
            List: List of updated records.
        """
        if entity.lower() == "devices":
            access_token, storage = self.get_access_token_and_storage(
                self.configuration
            )
            base_url, *_, pull_device_tags = (
                self.omnissa_workspace_one_uem_helper.get_configuration_parameters(
                    configuration=self.configuration
                )
            )
            devices = self.parser.get_required_fields(
                data=records,
                required_fields=[
                    "Device UUID",
                    "Device ID",
                    "Organization ID",
                    "Device Serial Number",
                ]
            )
            self.logger.info(
                f"{self.log_prefix}: Updating {len(records)}"
                f" Devices records from {PLATFORM_NAME} platform."
            )
            devices = self._update_devices_with_network_info(
                base_url=base_url,
                devices=devices,
                access_token=access_token,
                storage=storage,
            )
            if pull_device_tags == NO:
                self.logger.info(
                    f"{self.log_prefix}: Skipped pulling device tags"
                    f" from {PLATFORM_NAME} platform. Enable 'Pull"
                    " Device Tags' configuration parameter to enable"
                    " pulling of device tags."
                )
                return devices
            devices = self._update_devices_with_tags(
                base_url=base_url,
                devices=devices,
                access_token=access_token,
                storage=storage,
            )
            return devices
        else:
            err_msg = (
                f"Invalid entity found. {PLATFORM_NAME} plugin "
                "only supports 'Devices' Entity."
            )
            self.logger.error(message=f"{self.log_prefix}: {err_msg}")
            raise OmnissaWorkspaceOneUEMPluginException(err_msg)

    def get_actions(self) -> List[ActionWithoutParams]:
        """Get available actions.

        Args:
            None

        Returns:
            [...] list of ActionWithoutParams: List of ActionWithoutParams
                which has label and value defined

        """
        return [
            ActionWithoutParams(label="No action", value="generate"),
            ActionWithoutParams(label="Tag Device", value="tag"),
            ActionWithoutParams(label="Untag Device", value="untag"),
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
        if action.value == "tag":
            return [
                {
                    "label": "Device ID",
                    "key": "device_id",
                    "type": "text",
                    "default": "",
                    "mandatory": True,
                    "description": "ID of device to be tagged.",
                },
                {
                    "label": "Tag",
                    "key": "tags",
                    "type": "text",
                    "default": "",
                    "mandatory": True,
                    "description": (
                        "Tag to be applied to the device. Provide "
                        "multiple tag names in comma separated format."
                    ),
                },
                {
                    "label": "Organization ID",
                    "key": "organization_id",
                    "type": "text",
                    "default": "",
                    "mandatory": True,
                    "description": (
                        "ID of organization to which device belongs."
                    ),
                }
            ]
        if action.value == "untag":
            return [
                {
                    "label": "Device ID",
                    "key": "device_id",
                    "type": "text",
                    "default": "",
                    "mandatory": True,
                    "description": "ID of device to be untagged.",
                },
                {
                    "label": "Tag",
                    "key": "tags",
                    "type": "text",
                    "default": "",
                    "mandatory": True,
                    "description": (
                        "Tag to be removed from the device. Provide "
                        "multiple tag names in comma separated format."
                    ),
                },
                {
                    "label": "Organization ID",
                    "key": "organization_id",
                    "type": "text",
                    "default": "",
                    "mandatory": True,
                    "description": (
                        "ID of organization to which device belongs."
                    ),
                }
            ]

    def _validate_tags_string(self, tags: str) -> bool:
        """
        Validate if the tags string contains at least one non-empty tag.

        This method checks if the comma-separated tags string contains
        at least one non-empty tag after stripping whitespace. It returns
        True if at least one valid tag is found, otherwise False.

        Args:
            tags: A comma-separated string of tag names

        Returns:
            bool: True if at least one non-empty tag is found, False otherwise
        """
        for tag in tags.split(","):
            if tag.strip():
                return True
        return False

    def validate_action(self, action: Action) -> ValidationResult:
        """Validate HPE Central action configuration.

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
        if action_value not in ["generate", "tag", "untag"]:
            self.logger.error(
                message=(
                    f'{self.log_prefix}: Unsupported action "'
                    f'{action_value}" provided in the action '
                    "configuration. Supported Actions are - "
                    "'Tag Device', 'Untag Device'."
                ),
                resolution=(
                    "Please select any one of the supported actions. "
                    "Supported actions are - 'No Action', 'Tag Device',"
                    " 'Untag Device'."
                )
            )
            return ValidationResult(
                success=False, message="Unsupported action provided."
            )
        device_id = action.parameters.get("device_id", "")
        organization_id = action.parameters.get("organization_id", "")
        tags = action.parameters.get("tags", "")
        if action_value == "tag" or action_value == "untag":
            if validation_failure := self._validate_parameters(
                parameter_type=ACTION,
                field_name="Device ID",
                field_value=device_id,
                field_type=str,
                check_dollar=True,
            ):
                return validation_failure
            if validation_failure := self._validate_parameters(
                parameter_type=ACTION,
                field_name="Tags",
                field_value=tags,
                field_type=str,
                check_dollar=True,
                custom_validation_func=self._validate_tags_string
            ):
                return validation_failure
            if not self.parser.validate_tags(tags=tags):
                return ValidationResult(
                    success=False,
                    message=(
                        "Invalid tag provided. Ensure the tag length is less"
                        " than 50 characters."
                    )
                )
            if validation_failure := self._validate_parameters(
                parameter_type=ACTION,
                field_name="Organization ID",
                field_value=organization_id,
                field_type=str,
                check_dollar=True,
            ):
                return validation_failure

        return ValidationResult(
            success=True, message="Validation successful."
        )

    def execute_actions(self, actions: List[Action]):
        """Execute action on the devices.

        Args:
            action (List[Action]): Action that needs to be perform on devices.

        Returns:
            None
        """
        try:
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

            tags = first_action.parameters.get("tags")
            if isinstance(tags, str):
                parse_tags = True
            if isinstance(tags, List):
                parse_tags = False

            skipped_action_ids = []
            (
                action_by_organization,
                skipped_action_ids,
                device_id_to_action_id,
            ) = self.parser.group_action_by_organization_id(
                actions=actions,
                parse_tags=parse_tags,
                skipped_action_ids=skipped_action_ids,
            )

            tags_by_organization = self.parser.group_tags_by_organization(
                action_by_organization
            )

            access_token, storage = self.get_access_token_and_storage(
                self.configuration
            )
            upserted_tags = {}
            for organization_id, org_tags_list in tags_by_organization.items():
                upserted_tags[organization_id] = self._upsert_tags(
                    action_tag_list=org_tags_list,
                    organization_id=organization_id,
                    access_token=access_token,
                    storage=storage,
                    action_value=action_value,
                )

            devices_by_tags = self.parser.group_devices_by_tags(
                action_by_organization=action_by_organization,
                upserted_tags=upserted_tags
            )

            devices_by_tags = self.parser.create_batch_for_action_execution(
                devices_by_tags=devices_by_tags,
                batch_size=ACTION_BATCH_SIZE,
            )

            if action_value in ["tag", "untag"]:
                final_action_result = {}
                for key, action_data in devices_by_tags.items():
                    key = key.split(CUSTOM_SEPARATOR)
                    organization_id = key[0]
                    tag_name = key[1]
                    batch_number = key[2]
                    batched_action_result, failed_action_ids = (
                        self._tag_untag_devices_action(
                            device_id_to_action_id=device_id_to_action_id,
                            device_ids=action_data.get("device_ids", []),
                            tag_name=tag_name,
                            tag_id=action_data.get("tag_id", ""),
                            action_name=action_value,
                            batch_number=batch_number,
                            access_token=access_token,
                            storage=storage,
                        )
                    )
                    final_action_result = self.parser.update_final_action_result_dict(
                        batched_action_result=batched_action_result,
                        final_action_result=final_action_result,
                    )
                    skipped_action_ids.extend(failed_action_ids)
                self.logger.info(
                    message=(
                        f"{self.log_prefix}: Successfully executed action"
                        f" '{action_label}'. Expand the log to view action"
                        " stats."
                    ),
                    details=f"Action stats: {final_action_result}",
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
                        failed_action_ids=list(set(skipped_action_ids)),
                    )
                return
            else:
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: Unsupported action '{action_value}"
                        "' provided in the action configuration. Supported"
                        " actions are 'Tag Device' and 'Untag Device'."
                    ),
                    resolution=(
                        "Please select any one of the supported actions. "
                        "Supported actions are - 'No Action', 'Tag Device',"
                        " 'Untag Device'."
                    ),
                )
        except Exception:
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Error while executing action"
                    f" '{action_label}'."
                ),
                details=traceback.format_exc(),
            )

    def _upsert_tags(
        self,
        action_tag_list: Set[str],
        organization_id: str,
        access_token: str,
        storage: Dict,
        action_value: Literal["tag", "untag"] = "tag",
    ) -> Dict[str, str]:
        """
        Manage tags for tagging or un-tagging operations.

        This method fetches existing tags from the platform, determines
        which tags need to be created (for tag operations), and prepares
        a dictionary mapping tag names to their IDs for use in device
        tagging operations.

        Args:
            action_tag_list: List of tag names to be processed
            organization_id: ID of the organization to which the tags belong
            access_token: Access token for authentication
            storage: Storage dictionary
            action_value: The action to perform - either "tag" or "untag"

        Returns:
            Dict[str, str]: A dictionary mapping tag names to their IDs for
                existing tags

        Note:
            - For "tag" operations, tags not found on the platform will
                be created
            - For "untag" operations, tags not found on the platform will
                be skipped
        """
        # Fetch the already existing tags
        fetched_tags_dict = self._fetch_tags(
            organization_id=organization_id,
            access_token=access_token,
            storage=storage,
        )

        # Get the tags to be created and tags not to create based on the
        # ones already present on the platform
        tags_to_create, tags_not_to_create = (
            self.parser.get_list_of_tags_to_create(
                action_tags=action_tag_list,
                existing_tags=fetched_tags_dict.keys(),
            )
        )

        # Create a tag dictionary of format {tag_name: tag_id} for
        # tags already present on the platform
        final_tag_dict = self.parser.create_tag_name_to_id_dict(
            tags_name=tags_not_to_create,
            tags_id_dict=fetched_tags_dict,
        )
        self.logger.info(
            message=(
                f"{self.log_prefix}: Found {len(tags_not_to_create)}"
                f" tag(s) out of {len(action_tag_list)} tag(s) provided in"
                f" action parameters for Organization '{organization_id}'"
                f" on the {PLATFORM_NAME} platform."
            ),
            details=(
                "Tags already present on the platform:"
                f" {', '.join(tags_not_to_create)}"
            ),
        )
        if tags_to_create:
            if action_value == "untag":
                self.logger.info(
                    message=(
                        f"{self.log_prefix}: Skipped un-tagging device with"
                        f" {len(tags_to_create)} tags as they do not exist"
                        f" for Organization '{organization_id}' on"
                        f" {PLATFORM_NAME} platform."
                    ),
                    details=(
                        "Tags not present on platform: "
                        f"{', '.join(tags_to_create)}"
                    ),
                )
                return final_tag_dict
            self.logger.info(
                message=(
                    f"{self.log_prefix}: Creating {len(tags_to_create)}"
                    f" tag(s) as they do not exist for Organization"
                    f" '{organization_id}' on {PLATFORM_NAME} platform."
                ),
                details=f"Tags to be created: {', '.join(tags_to_create)}",
            )
            long_tags = self.parser.validate_tag_length(
                tags_list=tags_to_create,
                max_tag_length=TAG_CHARACTER_LENGTH_LIMIT,
            )
            if long_tags:
                self.logger.info(
                    message=(
                        f"{self.log_prefix}: Found {len(long_tags)} tag(s)"
                        f" with length exceeding {TAG_CHARACTER_LENGTH_LIMIT}"
                        " characters. Characters beyond this limit will be"
                        f" trimmed by {PLATFORM_NAME} platform."
                    ),
                    details=(
                        f"Tags with length greater than "
                        f"{TAG_CHARACTER_LENGTH_LIMIT}: {', '.join(long_tags)}"
                    ),
                )
            success = self._create_tags(
                tags_to_create,
                organization_id,
                access_token,
                storage,
            )
            # Update the final_tag_dict with the tags created
            final_tag_dict.update(success)

        return final_tag_dict

    def _fetch_tags(
        self,
        organization_id: str,
        access_token: str,
        storage: Dict,
    ) -> Dict[str, str]:
        """
        Fetch all tags from the Workspace ONE UEM platform for a specific
        organization.

        This method retrieves all tags associated with the specified
        organization from the Workspace ONE UEM platform and returns
        them as a dictionary mapping tag names to their corresponding IDs.

        Args:
            organization_id: ID of the organization for which to fetch tags
            access_token: Access token for authentication
            storage: Storage object

        Returns:
            Dict[str, str]: A dictionary mapping tag names to their IDs

        Raises:
            OmnissaWorkspaceOneUEMPluginException: If an error occurs while
                fetching tags
        """
        base_url, *_ = (
            self.omnissa_workspace_one_uem_helper.get_configuration_parameters(
                self.configuration
            )
        )
        url = FETCH_TAGS_ENDPOINT.format(
            base_url=base_url,
            organization_id=organization_id,
        )
        headers = self.omnissa_workspace_one_uem_helper.get_auth_headers(
            access_token=access_token,
            api_version=ONE,
        )
        logger_msg = (
            f"fetching tags for organization {organization_id}"
            f" from {PLATFORM_NAME} platform"
        )
        try:
            tags_data = {}
            response = self.omnissa_workspace_one_uem_helper.api_helper(
                logger_msg=logger_msg,
                url=url,
                method=GET,
                headers=headers,
                verify=self.ssl_validation,
                proxies=self.proxy,
                configuration=self.configuration,
                storage=storage,
                is_validation=False,
                is_handle_error_required=True,
                regenerate_access_token=True,
            )
            for tag in response.get("Tags", []):
                tags_data[tag.get("TagName").lower()] = tag.get("Id")
            return tags_data
        except OmnissaWorkspaceOneUEMPluginException:
            raise
        except Exception as err:
            err_msg = (
                f"Unexpected error occurred while {logger_msg}."
                f" Error: {err}"
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=traceback.format_exc(),
            )
            raise OmnissaWorkspaceOneUEMPluginException(err_msg)

    def _create_tags(
        self,
        tags_to_create: set[str],
        organization_id: str,
        access_token: str,
        storage: Dict,
    ) -> Dict[str, str]:
        """
        Create tags in the Workspace ONE UEM platform for a specific
        organization.

        This method creates new tags in the Workspace ONE UEM platform for
        the specified organization and returns a dictionary of successfully
        created tags along with a list of tags that failed to be created.

        Args:
            tags_to_create: Set of tag names to be created
            organization_id: ID of the organization for which to create tags
            access_token: Access token for authentication
            storage: Storage object

        Returns:
            Tuple[Dict[str, str], List[str]]: A tuple containing:
                - Dictionary mapping successfully created tag names to their
                    IDs
                - List of tag names that failed to be created
        """
        base_url, *_ = (
            self.omnissa_workspace_one_uem_helper.get_configuration_parameters(
                self.configuration
            )
        )
        url = CREATE_TAG_ENDPOINT.format(
            base_url=base_url,
        )
        headers = self.omnissa_workspace_one_uem_helper.get_auth_headers(
            access_token=access_token,
            api_version=ONE,
        )
        request_body = {
            "TagName": None,
            "LocationGroupId": organization_id,
        }
        success, error = {}, []
        for tag_name in tags_to_create:
            logger_msg = (
                f"creating tag {tag_name} for organization {organization_id}"
                f" on {PLATFORM_NAME} platform"
            )
            request_body["TagName"] = tag_name
            try:
                response = self.omnissa_workspace_one_uem_helper.api_helper(
                    logger_msg=logger_msg,
                    url=url,
                    method=POST,
                    headers=headers,
                    json=request_body,
                    verify=self.ssl_validation,
                    proxies=self.proxy,
                    configuration=self.configuration,
                    storage=storage,
                    is_validation=False,
                    is_handle_error_required=True,
                    regenerate_access_token=True,
                )
                success[tag_name] = response.get("Value")
            except OmnissaWorkspaceOneUEMPluginException as e:
                self.logger.error(
                    f"{self.log_prefix}: {e}"
                )
                error.append(tag_name)
                continue
            except Exception as err:
                err_msg = (
                    f"Unexpected error occurred while {logger_msg}."
                    f" Error: {err}"
                )
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg}",
                    details=traceback.format_exc(),
                )
                error.append(tag_name)
                continue
        self.logger.info(
            message=(
                f"{self.log_prefix}: Successfully created {len(success)}"
                f" tag(s) for Organization '{organization_id}' on"
                f" {PLATFORM_NAME} platform."
            ),
            details=f"Created tags: {', '.join(success.keys())}",
        )
        if error:
            self.logger.info(
                message=(
                    f"{self.log_prefix}: Failed to create {len(error)}"
                    f" tag(s) for Organization '{organization_id}' on"
                    f" {PLATFORM_NAME} platform. Failed tag(s) will be skipped"
                    " during the execution of the action."
                ),
                details=f"Failed tags: {', '.join(error)}",
            )
        return success

    def _tag_untag_devices_action(
        self,
        device_id_to_action_id: Dict[str, str],
        device_ids: List[str],
        tag_name: str,
        tag_id: int,
        action_name: Literal["tag", "untag"],
        batch_number: int,
        access_token: str,
        storage: Dict,
    ) -> Tuple[Dict[str, Dict], List[str]]:
        """
        Execute tag or untag operations on a batch of devices.

        This method performs the actual tagging or un-tagging operation
        on a batch of devices using the Workspace ONE UEM API. It processes
        each tag separately and tracks successful and failed operations.

        Args:
            device_id_to_action_id: Mapping of device IDs to their
                corresponding action IDs
            device_ids: List of device IDs to be tagged or un-tagged
            tag_name: Name of the tag to be applied or removed
            tag_id: ID of the tag
            action_name: The action to perform - either "tag" or "untag"
            batch_number: Batch number for logging and tracking purposes

        Returns:
            Tuple[Dict[str, Dict], List[str]]: A tuple containing:
                - Dictionary with results of tagging/un-tagging operations
                - List of action IDs that failed during processing

        Raises:
            OmnissaWorkspaceOneUEMPluginException: Exceptions may be raised
                during API calls, but most are caught internally and tracked
                in the failed_action_ids list
        """
        failed_action_ids = []
        base_url, *_ = (
            self.omnissa_workspace_one_uem_helper.get_configuration_parameters(
                self.configuration
            )
        )
        headers = self.omnissa_workspace_one_uem_helper.get_auth_headers(
            access_token,
            api_version=ONE,
        )
        request_body = {"BulkValues": {"Value": device_ids}}
        if action_name == "tag":
            action_endpoint = TAG_DEVICE_ENDPOINT
        else:
            action_endpoint = UNTAG_DEVICE_ENDPOINT
        action_result = {}
        logger_msg = (
            f"{action_name.capitalize()}ging {len(device_ids)} Device"
            f"(s) with tag '{tag_name}' for batch {batch_number}"
        )
        self.logger.info(
            message=f"{self.log_prefix}: {logger_msg}",
            details=(
                f"Device with ID(s) being {action_name}ged:"
                f" {', '.join(device_ids)}"
            ),
        )
        try:
            response = self.omnissa_workspace_one_uem_helper.api_helper(
                logger_msg=logger_msg,
                url=action_endpoint.format(
                    base_url=base_url,
                    tag_id=tag_id,
                ),
                method=POST,
                headers=headers,
                json=request_body,
                verify=self.ssl_validation,
                proxies=self.proxy,
                configuration=self.configuration,
                storage=storage,
                is_validation=False,
                is_handle_error_required=True,
                regenerate_access_token=True,
            )
            success_count = response.get("AcceptedItems")
            failed_count = response.get("FailedItems")
            failure_reason = response.get("Faults", {}).get("Fault", [])
            failed_devices = {}
            successfully_devices = device_ids
            # This skip list stores device ids
            # While tagging: devices that already have the tag attached
            # While un-tagging: devices that do not have the tag attached
            skip = []
            if failure_reason:
                (
                    failed_devices,
                    failed_action_ids,
                    skip,
                ) = self.parser.get_failed_device_details(
                    failure_reason=failure_reason,
                    device_id_to_action_id=device_id_to_action_id,
                    failed_action_ids=failed_action_ids,
                )
                successfully_devices = list(
                    set(device_ids) - set(failed_devices.keys())
                )
            # Since the tag is already attached we will consider that
            # action as success
            success_count += len(skip)
            self.logger.info(
                message=(
                    f"{self.log_prefix}: Successfully {action_name}ged"
                    f" {success_count} Device(s) with tag"
                    f" '{tag_name}'."
                ),
                details=(
                    f"Successfully {action_name}ged Device with ID(s):"
                    f" {', '.join(successfully_devices)}"
                )
            )
            # The API considers the devices
            # that already have the tag attached (while tagging) or
            # as failed actions. Hence we need to reduce the failed count
            # to provide proper count in the logger messages.
            # For un-tagging, if the device does not have that tag attached it
            # will be considered as an error/failed action
            failed_count = failed_count - len(skip)
            if failed_count:
                self.logger.info(
                    message=(
                        f"{self.log_prefix}: Failed to {action_name} "
                        f" {failed_count} Device(s) with tag '{tag_name}'."
                    ),
                    details=(
                        f"Failed to {action_name} Device(s) with IDs: "
                        f"{', '.join(failed_devices.keys())}."
                        f"\nReason: {failed_devices}."
                    )
                )
            if skip:
                if action_name == "tag":
                    logger_msg = (
                        f"Skipped tagging {len(skip)}"
                        f" Device(s) with tag '{tag_name}' since it is"
                        " already attached to the Device(s)."
                    )
                    details = (
                        "Device with ID(s) already attached to tag:"
                        f" {', '.join(skip)}"
                    )
                if action_name == "untag":
                    logger_msg = (
                        f"Skipped un-tagging {len(skip)}"
                        f" Device(s) with tag '{tag_name}' since it is"
                        " not attached to the Device(s)."
                    )
                    details = (
                        "Device with ID(s) not attached to tag:"
                        f" {', '.join(skip)}"
                    )
                self.logger.info(
                    message=f"{self.log_prefix}: {logger_msg}",
                    details=details,
                )

            action_result = self.parser.upsert_action_result_values(
                tag_name=tag_name,
                success_count=success_count,
                failed_count=failed_count,
                action_result=action_result,
            )
        except OmnissaWorkspaceOneUEMPluginException as e:
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Failed to {action_name}"
                    f" {len(device_ids)} Device(s) with"
                    f" tag '{tag_name}' for batch {batch_number}."
                    f" Error: {e}"
                )
            )
            failed_action_ids = self.parser.get_failed_device_action_ids(
                failed_device_ids=device_ids,
                device_id_to_action_id=device_id_to_action_id,
                failed_action_ids=failed_action_ids,
            )
            # Update the failed count to total devices count in batch
            # in case of exception
            action_result = self.parser.upsert_action_result_values(
                tag_name=tag_name,
                success_count=0,
                failed_count=len(device_ids),
                action_result=action_result,
            )
        except Exception as err:
            err_msg = (
                f"Unexpected error occurred while {action_name}ging"
                f" {len(device_ids)} Device(s) with tag '{tag_name}'"
                f" for batch {batch_number}. Error: {err}"
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=traceback.format_exc(),
            )
            failed_action_ids = self.parser.get_failed_device_action_ids(
                failed_device_ids=device_ids,
                device_id_to_action_id=device_id_to_action_id,
                failed_action_ids=failed_action_ids,
            )
            # Update the failed count to total devices count in batch
            # in case of exception
            action_result = self.parser.upsert_action_result_values(
                tag_name=tag_name,
                success_count=0,
                failed_count=len(device_ids),
                action_result=action_result,
            )
        return action_result, failed_action_ids
