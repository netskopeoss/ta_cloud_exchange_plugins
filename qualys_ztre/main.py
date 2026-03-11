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

CRE Qualys plugin.
"""

import json
import traceback
from datetime import datetime, timezone
from typing import Callable, Dict, List, Literal, Set, Tuple, Type, Union

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
from requests.auth import HTTPBasicAuth

from .utils.constants import (
    ASSET_FIELD_MAPPING,
    ASSET_VULN_ID_BATCH_SIZE,
    ASSET_VULNERABILITY_BASIC_INFO_FIELD_MAPPING,
    ASSET_VULNERABILITY_EXTRA_INFO_FIELD_MAPPING,
    CREATE_TAG_API_ENDPOINT,
    DATETIME_FORMAT,
    DEVICE_PAGE_SIZE,
    EMPTY_ERROR_MESSAGE,
    FETCH_ASSET_VULNERABILITY_IDS_API_ENDPOINT,
    FETCH_ASSETS_API_ENDPOINT,
    FETCH_TAGS_API_ENDPOINT,
    FETCH_TAGS_PAGE_SIZE,
    FETCH_VULNERABILITY_DETAILS_API_ENDPOINT,
    FETCH_WEB_APPLICATION_FINDING_IDS_API_ENDPOINT,
    FETCH_WEB_APPLICATIONS_API_ENDPOINT,
    FINDING_OR_VULN_BATCH_SIZE,
    INVALID_VALUE_ERROR_MESSAGE,
    MAXIMUM_CE_VERSION,
    MODULE_NAME,
    OVERRIDE_CONFIG_CPU_OPTIONS,
    PLATFORM_NAME,
    PLUGIN_NAME,
    PLUGIN_VERSION,
    QUALYS_API_SERVER_TO_API_GATEWAY_URL_MAPPING,
    SCAN_ASSET_API_ENDPOINT,
    SCAN_ASSET_BATCH_SIZE,
    SCAN_TYPE_OPTIONS,
    STORAGE_KEYS,
    TAG_ACTION_OPTIONS,
    TAG_ASSET_API_ENDPOINT,
    TAG_ASSET_BATCH_SIZE,
    TAG_NAME_LENGTH,
    TAG_WEBAPP_API_ENDPOINT,
    TYPE_ERROR_MESSAGE,
    VALIDATION_ERROR_MESSAGE,
    WEB_APP_FINDING_ID_BATCH_SIZE,
    WEB_APPLICATION_FINDING_BASIC_INFO_FIELD_MAPPING,
    WEB_APPLICATION_FINDING_EXTRA_INFO_FIELD_MAPPING,
    WEB_APPLICATION_PAGE_SIZE,
    WEB_APPS_FIELD_MAPPING,
    YES_NO_OPTIONS,
)
from .utils.exceptions import QualysPluginException, exception_handler
from .utils.helper import QualysHelper
from .utils.parser import QualysParser


class QualysPlugin(PluginBase):
    """Qualys plugin Class."""

    def __init__(
        self,
        name,
        *args,
        **kwargs,
    ):
        """Qualys plugin initializer.

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
        self.log_prefix = f"{MODULE_NAME} {self.plugin_name}"
        if name:
            self.log_prefix = f"{self.log_prefix} [{name}]"
        self.parser = QualysParser(
            logger=self.logger,
            log_prefix=self.log_prefix,
            partial_action_result_supported=self._is_ce_post_v512,
        )
        self.qualys_helper = QualysHelper(
            logger=self.logger,
            plugin_name=self.plugin_name,
            plugin_version=self.plugin_version,
            log_prefix=self.log_prefix,
            parser=self.parser,
        )
        self.provide_action_id = self._is_ce_post_v512

    def _get_plugin_info(self) -> tuple:
        """Get plugin name and version from manifest.

        Returns:
            tuple: tuple of plugin's name and version fetched from manifest.
        """
        try:
            manifest_json = QualysPlugin.metadata
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

    def _check_ce_version(self) -> bool:
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
        _, api_gateway_url, username, password, _, _ = (
            self.qualys_helper.get_configuration_parameters(
                configuration=configuration,
            )
        )
        current_config_hash = self.qualys_helper.hash_string(
            string=f"{api_gateway_url}{username}{password}"
        )
        if stored_access_token and stored_config_hash == current_config_hash:
            return stored_access_token, storage
        else:
            access_token = self.qualys_helper.generate_access_token(
                gateway_url=api_gateway_url,
                username=username,
                password=password,
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
        allowed_values: Dict = None,
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
        if isinstance(field_value, str):
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
        if allowed_values and field_value not in allowed_values.keys():
            allowed_values_str = ", ".join(allowed_values.values())
            err_msg = TYPE_ERROR_MESSAGE.format(
                field_name=field_name,
                parameter_type=parameter_type,
            )
            err_msg += INVALID_VALUE_ERROR_MESSAGE.format(
                allowed_values=allowed_values_str
            )
            self.logger.error(
                message=(
                    f"{self.log_prefix}: {VALIDATION_ERROR_MESSAGE} {err_msg}"
                ),
                resolution=(
                    "Please provide a valid value from the allowed values.\n"
                    f"Allowed values: {allowed_values_str}"
                )
            )
            return ValidationResult(success=False, message=err_msg)

    def _validate_connectivity(self, configuration: Dict) -> ValidationResult:
        """
        Validate connectivity with Qualys platform.

        Args:
            configuration (Dict): Configuration.

        Returns:
            ValidationResult: Validation result.
        """
        api_server_url, api_gateway_url, username, password, _, _ = (
            self.qualys_helper.get_configuration_parameters(
                configuration=configuration,
            )
        )

        try:
            # Validate Connectivity with the API Server URL
            basic_auth = HTTPBasicAuth(username, password)
            logger_msg = "validating connectivity with API Server URL"
            self.qualys_helper.api_helper(
                logger_msg=logger_msg,
                url=FETCH_WEB_APPLICATIONS_API_ENDPOINT.format(
                    api_server_url=api_server_url
                ),
                method="POST",
                params=None,
                headers=self.qualys_helper.get_headers(
                    access_token=None,
                    request_response_type="json",
                    x_requested_header=True
                ),
                json={
                    "ServiceRequest": {
                        "preferences": {
                            "limitResults": 1,
                        }
                    }
                },
                verify=self.ssl_validation,
                proxies=self.proxy,
                storage={},
                configuration=configuration,
                is_validation=True,
                is_handle_error_required=True,
                regenerate_access_token=False,
                basic_auth=basic_auth,
                response_format="json"
            )

            access_token, storage = self.get_access_token_and_storage(
                configuration=configuration,
                is_validation=True,
            )
            # Validate Connectivity with the API Gateway URL
            logger_msg = "validating connectivity with API Gateway URL"
            self.qualys_helper.api_helper(
                logger_msg=logger_msg,
                url=FETCH_ASSETS_API_ENDPOINT.format(
                    api_gateway_url=api_gateway_url
                ),
                method="POST",
                params={
                    "pageSize": 1,
                    "includeFields": "assetId"
                },
                headers=self.qualys_helper.get_headers(
                    access_token=access_token,
                    request_response_type="json",
                    x_requested_header=False
                ),
                json={},
                verify=self.ssl_validation,
                proxies=self.proxy,
                storage=storage,
                configuration=configuration,
                is_validation=True,
                is_handle_error_required=True,
                regenerate_access_token=True,
                basic_auth=None,
                response_format="json"
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
        except QualysPluginException as err:
            err_msg = (
                f"Error occurred while {logger_msg}. Error: {err}"
            )
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
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

    def validate(self, configuration: Dict) -> Tuple[bool, Dict]:
        """Validate the plugin configuration parameters."""
        (
            api_server_url,
            api_gateway_url,
            username,
            password,
            pull_asset_vulnerability,
            pull_webapp_findings,
        ) = self.qualys_helper.get_configuration_parameters(
            configuration=configuration
        )

        # Validate API Server URL
        if validation_result := self._validate_parameters(
            parameter_type="configuration",
            field_name="API Server URL",
            field_value=api_server_url,
            field_type=str,
            custom_validation_func=self.qualys_helper._validate_url,
        ):
            return validation_result

        # Validate API Gateway URL
        if validation_result := self._validate_parameters(
            parameter_type="configuration",
            field_name="API Gateway URL",
            field_value=api_gateway_url,
            field_type=str,
            custom_validation_func=self.qualys_helper._validate_url,
        ):
            return validation_result

        # Validate whether API Server URL and API Gateway URL pair is valid
        if api_server_url in QUALYS_API_SERVER_TO_API_GATEWAY_URL_MAPPING:
            expected_gateway_url = QUALYS_API_SERVER_TO_API_GATEWAY_URL_MAPPING.get(api_server_url)
            if expected_gateway_url is not None and expected_gateway_url != api_gateway_url:
                err_msg = (
                    "Incorrect value provided for the API Server URL"
                    " and API Gateway URL pair."
                )
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg}",
                    resolution=(
                        "Please provide a valid API Server URL and API"
                        " Gateway URL pair from the below provided list."
                        "\nAPI Server URL <=> API Gateway URL\n" +
                        ''.join([f'{k} <=> {v}\n' for k, v in QUALYS_API_SERVER_TO_API_GATEWAY_URL_MAPPING.items()])
                    )
                )
                return ValidationResult(
                    success=False,
                    message=err_msg,
                )

        # Validate Username
        if validation_result := self._validate_parameters(
            parameter_type="configuration",
            field_name="Username",
            field_value=username,
            field_type=str,
        ):
            return validation_result

        # Validate Password
        if validation_result := self._validate_parameters(
            parameter_type="configuration",
            field_name="Password",
            field_value=password,
            field_type=str,
        ):
            return validation_result

        # Validate Pull Asset Vulnerability
        if validation_result := self._validate_parameters(
            parameter_type="configuration",
            field_name="Pull Asset Vulnerability",
            field_value=pull_asset_vulnerability,
            field_type=str,
            allowed_values=YES_NO_OPTIONS,
        ):
            return validation_result

        # Validate Pull Web Application Findings
        if validation_result := self._validate_parameters(
            parameter_type="configuration",
            field_name="Pull Web Application Findings",
            field_value=pull_webapp_findings,
            field_type=str,
            allowed_values=YES_NO_OPTIONS,
        ):
            return validation_result

        return self._validate_connectivity(configuration=configuration)

    def get_entities(self) -> list[Entity]:
        """Get available entities."""
        *_, pull_asset_vulnerability, pull_webapp_findings = (
            self.qualys_helper.get_configuration_parameters(
                configuration=self.configuration,
            )
        )
        asset_data_fields = [
            EntityField(
                name="Asset ID",
                type=EntityFieldType.STRING,
                required=True,
            ),
            EntityField(
                name="Host ID",
                type=EntityFieldType.STRING,
                required=True,
            ),
            EntityField(
                name="Serial Number",
                type=EntityFieldType.STRING,
                required=True,
            ),
            EntityField(
                name="Risk Score",
                type=EntityFieldType.NUMBER,
            ),
            EntityField(
                name="Netskope Normalized Risk Score",
                type=EntityFieldType.NUMBER,
            ),
            EntityField(
                name="Criticality Score",
                type=EntityFieldType.NUMBER,
            ),
            EntityField(
                name="Tags",
                type=EntityFieldType.LIST,
            ),
            EntityField(
                name="Asset Type",
                type=EntityFieldType.STRING,
            ),
            EntityField(
                name="IP Address",
                type=EntityFieldType.STRING,
            ),
            EntityField(
                name="DNS Name",
                type=EntityFieldType.STRING,
            ),
            EntityField(
                name="Asset Name",
                type=EntityFieldType.STRING,
            ),
            EntityField(
                name="BIOS Asset Tag",
                type=EntityFieldType.STRING,
            ),
            EntityField(
                name="Users",
                type=EntityFieldType.LIST,
            ),
            EntityField(
                name="Open Ports",
                type=EntityFieldType.LIST,
            ),
            EntityField(
                name="Network Interfaces IPv4 Address",
                type=EntityFieldType.LIST,
            ),
            EntityField(
                name="Network Interfaces IPv6 Address",
                type=EntityFieldType.LIST,
            ),
            EntityField(
                name="Network Interfaces Mac Address",
                type=EntityFieldType.LIST,
            ),
            EntityField(
                name="Domain",
                type=EntityFieldType.LIST,
            ),
            EntityField(
                name="Sub Domain",
                type=EntityFieldType.LIST,
            ),
            EntityField(
                name="OS",
                type=EntityFieldType.STRING,
            ),
        ]
        asset_vulnerability_fields = [
            EntityField(
                name="Vulnerability QID",
                type=EntityFieldType.STRING,
            ),
            EntityField(
                name="Unique Vulnerability ID",
                type=EntityFieldType.STRING,
            ),
            EntityField(
                name="Vulnerability Type",
                type=EntityFieldType.STRING,
            ),
            EntityField(
                name="Vulnerability Severity",
                type=EntityFieldType.NUMBER,
            ),
            EntityField(
                name="Is SSL",
                type=EntityFieldType.NUMBER,
            ),
            EntityField(
                name="Vulnerability Status",
                type=EntityFieldType.STRING,
            ),
            EntityField(
                name="Vulnerability QDS Score",
                type=EntityFieldType.STRING,
            ),
            EntityField(
                name="Vulnerability Category",
                type=EntityFieldType.STRING,
            ),
            EntityField(
                name="Is Patchable",
                type=EntityFieldType.STRING,
            ),
            EntityField(
                name="Product",
                type=EntityFieldType.STRING,
            ),
            EntityField(
                name="Vendor",
                type=EntityFieldType.STRING,
            ),
            EntityField(
                name="CVE ID",
                type=EntityFieldType.STRING,
            ),
            EntityField(
                name="Base CVSS Score",
                type=EntityFieldType.NUMBER,
            ),
            EntityField(
                name="Temporal CVSS Score",
                type=EntityFieldType.NUMBER,
            ),
        ]
        web_app_data_fields = [
            EntityField(
                name="Web Application ID",
                type=EntityFieldType.STRING,
                required=True,
            ),
            EntityField(
                name="Web Application Name",
                type=EntityFieldType.STRING,
            ),
            EntityField(
                name="Web Application URL",
                type=EntityFieldType.STRING,
            ),
            EntityField(
                name="Risk Score",
                type=EntityFieldType.NUMBER,
            ),
            EntityField(
                name="Netskope Normalized Risk Score",
                type=EntityFieldType.NUMBER,
            ),
            EntityField(
                name="Tags",
                type=EntityFieldType.LIST,
            ),
        ]
        web_app_finding_fields = [
            EntityField(
                name="Finding QID",
                type=EntityFieldType.STRING,
            ),
            EntityField(
                name="Finding Type",
                type=EntityFieldType.STRING,
            ),
            EntityField(
                name="Potential",
                type=EntityFieldType.STRING,
            ),
            EntityField(
                name="Finding Detection Score",
                type=EntityFieldType.NUMBER,
            ),
            EntityField(
                name="Finding Severity",
                type=EntityFieldType.NUMBER,
            ),
            EntityField(
                name="Finding Status",
                type=EntityFieldType.STRING,
            ),
            EntityField(
                name="Is Patchable",
                type=EntityFieldType.STRING,
            ),
            EntityField(
                name="Base CVSS Score",
                type=EntityFieldType.NUMBER,
            ),
            EntityField(
                name="Temporal CVSS Score",
                type=EntityFieldType.NUMBER,
            ),
            EntityField(
                name="Base CVSS3 Score",
                type=EntityFieldType.NUMBER,
            ),
            EntityField(
                name="Temporal CVSS3 Score",
                type=EntityFieldType.NUMBER,
            ),
        ]
        if pull_asset_vulnerability == "Yes":
            asset_data_fields.extend(asset_vulnerability_fields)
        if pull_webapp_findings == "Yes":
            web_app_data_fields.extend(web_app_finding_fields)
        return [
            Entity(
                name="Assets",
                fields=asset_data_fields,
            ),
            Entity(
                name="Web Applications",
                fields=web_app_data_fields,
            ),
        ]

    @exception_handler
    def _fetch_assets(self, fetch_time: str, context={}):
        """
        Fetch assets from Qualys platform.

        Args:
            context (Dict, optional): Context. Defaults to {}.

        Returns:
            List[Dict]: List of assets.
        """
        _, api_gateway_url, _, _, _, _ = (
            self.qualys_helper.get_configuration_parameters(
                configuration=self.configuration
            )
        )
        access_token, storage = self.get_access_token_and_storage(
            configuration=self.configuration, is_validation=False
        )
        query_params = {
            "pageSize": DEVICE_PAGE_SIZE
        }
        if not fetch_time:
            self.logger.info(
                f"{self.log_prefix}: This is initial data pull hence pulling"
                f" all the assets from {PLATFORM_NAME} platform."
            )
            request_body = {}
        else:
            self.logger.info(
                f"{self.log_prefix}: Fetching assets seen after"
                f" '{self.last_run_at}' time from {PLATFORM_NAME} platform.",
            )
            request_body = {
                "filters": [
                    {
                        "field": "asset.lastUpdatedDate",
                        "operator": "GREATER",
                        "value": fetch_time,
                    }
                ]
            }
        headers = self.qualys_helper.get_headers(
            access_token=access_token, request_response_type="json"
        )
        url = FETCH_ASSETS_API_ENDPOINT.format(api_gateway_url=api_gateway_url)
        asset_records = []
        total_success = 0
        total_skip = 0
        page_number = 1
        while True:
            logger_msg = (
                f"fetching assets for {page_number} from"
                f" {PLATFORM_NAME} platform"
            )
            context["logger_msg"] = logger_msg
            page_success = 0
            page_skip = 0
            response = self.qualys_helper.api_helper(
                logger_msg=logger_msg,
                url=url,
                method="POST",
                params=query_params,
                headers=headers,
                json=request_body,
                verify=self.ssl_validation,
                proxies=self.proxy,
                storage=storage,
                configuration=self.configuration,
                is_validation=False,
                is_handle_error_required=True,
                regenerate_access_token=True,
                basic_auth=None,
                response_format="json"
            )
            assets = response.get("assetListData", {}).get("asset", [])
            if not assets:
                break
            for asset in assets:
                try:
                    extracted_fields = self.parser.extract_entity_fields(
                        event=asset,
                        entity_field_mapping=ASSET_FIELD_MAPPING,
                        event_type="json",
                        entity_name="assets",
                    )
                    if not extracted_fields:
                        page_skip += 1
                    else:
                        page_success += 1
                        asset_records.append(extracted_fields)
                except Exception as err:
                    err_msg = (
                        "Unable to extract fields from "
                        "asset record."
                    )
                    self.logger.error(
                        message=(
                            f"{self.log_prefix}: {err_msg} "
                            f"Error: {err}."
                        ),
                        details=traceback.format_exc(),
                    )
                    page_skip += 1

            total_success += page_success
            total_skip += total_skip

            fetch_msg = f"Successfully fetched {page_success} asset record(s)"
            if page_skip > 0:
                fetch_msg += (
                    f" , Skipped {page_skip} asset record(s)"
                )
            self.logger.info(
                f"{self.log_prefix}: {fetch_msg} for page {page_number}."
                f" Total assets fetched: {total_success}."
            )

            has_more = response.get("hasMore")
            if not has_more:
                break
            last_seen_asset_id = response.get("lastSeenAssetId")
            query_params.update({"lastSeenAssetId": last_seen_asset_id})
            page_number += 1

        self.logger.info(
            f"{self.log_prefix}: Successfully fetched {total_success}"
            f" asset record(s) from {PLATFORM_NAME} platform."
        )
        if total_skip > 0:
            self.logger.info(
                f"{self.log_prefix}: Skipped {total_skip} "
                f"asset record(s) from {PLATFORM_NAME} platform."
            )
        return asset_records

    @exception_handler
    def _fetch_web_applications(self, fetch_time: str, context={}):
        """
        Fetch web applications from Qualys platform.

        Args:
            context (Dict, optional): Context. Defaults to {}.

        Returns:
            List[Dict]: List of web applications.
        """
        api_server_url, _, username, password, _, _ = (
            self.qualys_helper.get_configuration_parameters(
                configuration=self.configuration
            )
        )
        request_body = {
            "ServiceRequest": {
                "preferences": {
                    "limitResults": WEB_APPLICATION_PAGE_SIZE,
                    "startFromOffset": 1,
                    "verbose": True
                }
            }
        }
        if not fetch_time:
            self.logger.info(
                f"{self.log_prefix}: This is initial data pull hence pulling"
                f" all the Web Applications from {PLATFORM_NAME} platform."
            )
        else:
            self.logger.info(
                f"{self.log_prefix}: Fetching Web Applications seen after"
                f" '{self.last_run_at}' time from {PLATFORM_NAME} platform.",
            )
            request_body["ServiceRequest"].update(
                {
                    "filters": {
                        "Criteria": [
                            {
                                "field": "updatedDate",
                                "operator": "GREATER",
                                "value": fetch_time,
                            }
                        ]
                    }
                }
            )
        headers = self.qualys_helper.get_headers(
            request_response_type="json",
            x_requested_header=True,
        )
        url = FETCH_WEB_APPLICATIONS_API_ENDPOINT.format(
            api_server_url=api_server_url
        )
        basic_auth = HTTPBasicAuth(username=username, password=password)
        page_number = 1
        offset = 1
        web_application_records = []
        total_success = 0
        total_skip = 0
        while True:
            logger_msg = (
                f"fetching web application for page {page_number} from"
                f" {PLATFORM_NAME} platform"
            )
            context["logger_msg"] = logger_msg
            page_success = 0
            page_skip = 0
            response = self.qualys_helper.api_helper(
                logger_msg=logger_msg,
                url=url,
                method="POST",
                params=None,
                headers=headers,
                json=request_body,
                verify=self.ssl_validation,
                proxies=self.proxy,
                storage={},
                configuration=self.configuration,
                is_validation=False,
                is_handle_error_required=True,
                regenerate_access_token=False,
                basic_auth=basic_auth,
                response_format="json"
            )
            service_response = response.get("ServiceResponse", {})
            web_applications = service_response.get("data", [])
            if not web_applications:
                break
            for web_application in web_applications:
                try:
                    web_app_data = web_application.get("WebApp", {})
                    if not web_app_data:
                        page_skip += 1
                        continue
                    extracted_fields = self.parser.extract_entity_fields(
                        event=web_app_data,
                        entity_field_mapping=WEB_APPS_FIELD_MAPPING,
                        event_type="json",
                        entity_name="web applications"
                    )
                    if not extracted_fields:
                        page_skip += 1
                    else:
                        page_success += 1
                        web_application_records.append(extracted_fields)
                except Exception as err:
                    err_msg = (
                        "Unable to extract fields from "
                        "asset record."
                    )
                    self.logger.error(
                        message=(
                            f"{self.log_prefix}: {err_msg} "
                            f"Error: {err}."
                        ),
                        details=traceback.format_exc(),
                    )
                    page_skip += 1

            total_success += page_success
            total_skip += total_skip

            fetch_msg = (
                f"Successfully fetched {page_success} web application"
                " record(s)"
            )
            if page_skip > 0:
                fetch_msg += (
                    f" , Skipped {page_skip} web application record(s)"
                )
            self.logger.info(
                f"{self.log_prefix}: {fetch_msg} for page {page_number}."
                f" Total web applications fetched: {total_success}."
            )
            has_more_records = service_response.get("hasMoreRecords")
            if has_more_records == "false":
                break
            if len(web_applications) < WEB_APPLICATION_PAGE_SIZE:
                break
            offset += WEB_APPLICATION_PAGE_SIZE
            request_body["ServiceRequest"]["preferences"].update(
                {"startFromOffset": offset}
            )
            page_number += 1
        self.logger.info(
            f"{self.log_prefix}: Successfully fetched {total_success}"
            f" web application record(s) from {PLATFORM_NAME} platform."
        )
        if total_skip > 0:
            self.logger.info(
                f"{self.log_prefix}: Skipped {total_skip} "
                f"web application record(s) from {PLATFORM_NAME} platform."
            )
        return web_application_records

    def _fetch_asset_vulnerabilities(
        self,
        host_id_to_required_fields: Dict[str, str],
        time_filter: str,
        storage: Dict,
    ) -> List[Dict]:
        """
        Fetch vulnerability information for specified assets from Qualys
        platform.

        This method retrieves vulnerability data for a given set of host IDs
        by:
        1. Batching host IDs to handle large datasets efficiently
        2. Fetching vulnerability IDs for each batch of assets
        3. Retrieving detailed vulnerability information for each
        vulnerability ID
        4. Combining vulnerability data with asset information

        Args:
            host_id_to_required_fields (Dict[str, str]): Dictionary mapping
                host IDs to their required field values for vulnerability
                records.
            time_filter (str): Time filter to fetch vulnerabilities detected
                after a specific time. If empty, fetches all vulnerabilities.

        Returns:
            List[Dict]: List of vulnerability records containing combined
                asset and vulnerability information. Each record includes
                basic vulnerability info, extra vulnerability details, and
                associated asset data.

        Raises:
            QualysPluginException: When API calls fail or response parsing
                errors occur.
            Exception: For unexpected errors during vulnerability data
                retrieval.

        Note:
            - Processes assets in batches defined by ASSET_VULN_ID_BATCH_SIZE
            - Skips vulnerabilities with missing QID or host ID
            - Logs detailed progress and error information for monitoring
            - Uses XML format for vulnerability ID API and combines with
                detailed info
        """
        api_server_url, _, username, password, _, _ = (
            self.qualys_helper.get_configuration_parameters(
                configuration=self.configuration
            )
        )
        headers = self.qualys_helper.get_headers(
            request_response_type="xml",
            x_requested_header=True
        )
        request_body = {
            "action": "list",
            "ids": None,
            "show_qds": 1,
        }
        if time_filter:
            request_body.update({"detection_updated_since": time_filter})
        host_ids = list(host_id_to_required_fields.keys())
        host_id_batches = self.parser.create_batches(
            host_ids,
            batch_size=ASSET_VULN_ID_BATCH_SIZE
        )
        url = FETCH_ASSET_VULNERABILITY_IDS_API_ENDPOINT.format(
            api_server_url=api_server_url
        )
        basic_auth = HTTPBasicAuth(username=username, password=password)
        vulnerability_info = []
        total_success = 0
        total_skip = 0
        skipped_asset_ids = 0
        for batch_number, host_id_batch in host_id_batches.items():
            host_id_batch_len = len(host_id_batch)
            try:
                batch_skip = 0
                logger_msg = (
                    f"fetching all vulnerability ids for {host_id_batch_len}"
                    f" assets in batch {batch_number} from {PLATFORM_NAME}"
                    " platform"
                )
                if time_filter:
                    logger_msg = (
                        f"fetching vulnerability ids detected after "
                        f" {time_filter} for {host_id_batch_len} assets"
                        f" in batch {batch_number} from {PLATFORM_NAME}"
                        " platform"
                    )
                request_body["ids"] = ",".join(host_id_batch)
                response = self.qualys_helper.api_helper(
                    logger_msg=logger_msg,
                    url=url,
                    method="POST",
                    params=None,
                    headers=headers,
                    data=request_body,
                    verify=self.ssl_validation,
                    proxies=self.proxy,
                    storage={},
                    configuration=self.configuration,
                    is_validation=False,
                    is_handle_error_required=True,
                    regenerate_access_token=False,
                    basic_auth=basic_auth,
                    response_format="xml"
                )
                vulnerability_id_to_host_id = {}
                _vulnerability_info = {}
                response_element = response.find("RESPONSE")
                if not response_element:
                    self.logger.info(
                        f"{self.log_prefix}: Skipped fetching vulnerability"
                        f" ids for {host_id_batch_len} assets in batch"
                        f" {batch_number} as no vulnerabilities were found."
                    )
                    continue
                host_list_element = response_element.find("HOST_LIST")
                if not host_list_element:
                    self.logger.info(
                        f"{self.log_prefix}: Skipped fetching vulnerability"
                        f" ids for {host_id_batch_len} assets in batch"
                        f" {batch_number} as no vulnerabilities were found."
                    )
                    continue
                host_list = host_list_element.findall("HOST")
                if not host_list:
                    self.logger.info(
                        f"{self.log_prefix}: Skipped fetching vulnerability"
                        f" ids for {host_id_batch_len} assets in batch"
                        f" {batch_number} as no vulnerabilities were found."
                    )
                    continue
                for host_details in host_list:
                    host_id = host_details.find("ID").text
                    if not host_id:
                        batch_skip += 1
                        continue
                    detection_list = host_details.find(
                        "DETECTION_LIST"
                    ).findall("DETECTION")
                    for detection in detection_list:
                        try:
                            qid = detection.find("QID").text
                            if not qid:
                                batch_skip += 1
                                continue
                            qid = str(qid)
                            extracted_fields = (
                                self.parser.extract_entity_fields(
                                    event=detection,
                                    entity_field_mapping=ASSET_VULNERABILITY_BASIC_INFO_FIELD_MAPPING,
                                    event_type="xml",
                                )
                            )
                            if not extracted_fields:
                                batch_skip += 1
                                continue
                            else:
                                _vulnerability_info[qid] = extracted_fields
                                vulnerability_id_to_host_id[qid] = str(host_id)
                        except Exception as err:
                            err_msg = (
                                "Unable to extract fields from "
                                "asset vulnerability record."
                            )
                            self.logger.error(
                                message=(
                                    f"{self.log_prefix}: {err_msg} "
                                    f"Error: {err}."
                                ),
                                details=traceback.format_exc(),
                            )
                            batch_skip += 1
                fetch_log = (
                    f"Successfully fetched {len(_vulnerability_info)}"
                    " vulnerability ids"
                )
                if batch_skip > 0:
                    fetch_log += (
                        f", Skipped {batch_skip} vulnerability ids"
                    )
                self.logger.info(
                    f"{self.log_prefix}: {fetch_log} for"
                    f" {host_id_batch_len} assets in batch"
                    f" {batch_number}."
                )
                _vulnerability_info, success, skip = (
                    self._fetch_vulnerability_info(
                        vulnerability_info=_vulnerability_info,
                        api_server_url=api_server_url,
                        basic_auth=basic_auth,
                        batch_number=batch_number,
                        entity_name="assets",
                        storage=storage,
                    )
                )
                total_success += success
                total_skip += skip
                combined_vulnerability_info = self.parser.combine_details(
                    vulnerability_info=_vulnerability_info,
                    vulnerability_qid_to_id_field=vulnerability_id_to_host_id,
                    host_id_to_required_fields=host_id_to_required_fields,
                )
                vulnerability_info.extend(combined_vulnerability_info)
            except QualysPluginException as err:
                err_msg = (
                    f"Error occurred while {logger_msg}. Error: {str(err)}"
                )
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg}",
                )
                skipped_asset_ids += len(host_id_batch)
                continue
            except Exception as err:
                err_msg = (
                    f"Unexpected error while {logger_msg}. Error: {str(err)}"
                )
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg}",
                    details=traceback.format_exc(),
                )
                skipped_asset_ids += len(host_id_batch)
                continue
        final_fetch_log = (
            f"Successfully fetched {total_success} vulnerability record(s)"
        )
        if total_skip > 0:
            final_fetch_log += (
                f", Skipped {total_skip} vulnerability record(s)"
            )
        self.logger.info(
            f"{self.log_prefix}: {final_fetch_log} for {len(host_ids)}"
            " asset(s)."
        )
        return vulnerability_info

    def _fetch_web_application_findings(
        self,
        web_app_ids: List[str],
        time_filter: str,
        storage: Dict,
    ) -> List[Dict]:
        """Fetch detailed findings for the provided web applications.

        Args:
            web_app_ids (List[str]): Qualys web application identifiers whose
                finding IDs and details need to be retrieved.
            time_filter (str): ISO timestamp used to limit findings to those
                detected after the supplied instant. An empty string disables
                the filter.

        Returns:
            List[Dict]: Normalized finding dictionaries containing base and
                supplemental fields combined from the ID and detail lookups.
        """
        api_server_url, _, username, password, _, _ = (
            self.qualys_helper.get_configuration_parameters(
                configuration=self.configuration
            )
        )
        headers = self.qualys_helper.get_headers(
            request_response_type="json",
            x_requested_header=True
        )
        web_app_id_batches = self.parser.create_batches(
            web_app_ids,
            batch_size=WEB_APP_FINDING_ID_BATCH_SIZE
        )
        url = FETCH_WEB_APPLICATION_FINDING_IDS_API_ENDPOINT.format(
            api_server_url=api_server_url
        )
        basic_auth = HTTPBasicAuth(username=username, password=password)
        updated_web_app_records = []
        total_success = 0
        total_skip = 0
        for web_app_batch_number, web_app_id_batch in web_app_id_batches.items():
            request_body = {
                "ServiceRequest": {
                    "preferences": {
                        "limitResults": WEB_APPLICATION_PAGE_SIZE
                    },
                    "filters": {
                        "Criteria": [
                            {
                                "field": "webApp.id",
                                "operator": "IN",
                                "value": ",".join(web_app_id_batch)
                            },
                        ]
                    }
                }
            }
            if time_filter:
                request_body["ServiceRequest"]["filters"]["Criteria"].append(
                    {
                        "field": "lastDetectedDate",
                        "operator": "GREATER",
                        "value": time_filter,
                    }
                )
            web_app_id_batch_len = len(web_app_id_batch)
            page_number = 1
            _finding_info = {}
            _finding_id_to_web_app_id = {}
            offset = 1
            batch_skip = 0
            try:
                while True:
                    logger_msg = (
                        f"fetching finding ids for {web_app_id_batch_len}"
                        f" web applications from page {page_number} in"
                        f" batch {web_app_batch_number} from {PLATFORM_NAME}"
                        " platform"
                    )
                    if time_filter:
                        logger_msg = (
                            f"fetching finding ids detected after"
                            f" {time_filter} for {web_app_id_batch_len}"
                            f" web applications from page {page_number}"
                            f" in batch {web_app_batch_number} from"
                            f" {PLATFORM_NAME} platform"
                        )
                    response = self.qualys_helper.api_helper(
                        logger_msg=logger_msg,
                        url=url,
                        method="POST",
                        params={},
                        json=request_body,
                        headers=headers,
                        verify=self.ssl_validation,
                        proxies=self.proxy,
                        storage={},
                        configuration=self.configuration,
                        is_validation=False,
                        is_handle_error_required=True,
                        regenerate_access_token=False,
                        basic_auth=basic_auth,
                        response_format="json"
                    )
                    service_response = response.get("ServiceResponse", {})
                    findings_data = service_response.get("data", [])
                    if not findings_data:
                        break
                    for finding in findings_data:
                        try:
                            finding_data = finding.get("Finding")
                            if not finding_data:
                                batch_skip += 1
                                continue
                            finding_qid = str(finding_data.get("qid", ""))
                            if not finding_qid:
                                batch_skip += 1
                                continue
                            web_app_id = finding_data.get(
                                "webApp", {}
                            ).get("id")
                            if not web_app_id:
                                batch_skip += 1
                                continue
                            extracted_fields = (
                                self.parser.extract_entity_fields(
                                    event=finding_data,
                                    entity_field_mapping=WEB_APPLICATION_FINDING_BASIC_INFO_FIELD_MAPPING,
                                    event_type="json",
                                )
                            )
                            if not extracted_fields:
                                batch_skip += 1
                                continue
                            else:
                                _finding_info[finding_qid] = extracted_fields
                                _finding_id_to_web_app_id[
                                    finding_qid
                                ] = str(web_app_id)
                        except Exception as err:
                            err_msg = (
                                "Unable to extract fields from "
                                "web application finding record."
                            )
                            self.logger.error(
                                message=(
                                    f"{self.log_prefix}: {err_msg} "
                                    f"Error: {err}."
                                ),
                                details=traceback.format_exc(),
                            )
                            batch_skip += 1
                    has_more_records = service_response.get(
                        "hasMoreRecords"
                    )
                    if has_more_records == "false":
                        break
                    if len(findings_data) < WEB_APP_FINDING_ID_BATCH_SIZE:
                        break
                    offset += WEB_APP_FINDING_ID_BATCH_SIZE
                    request_body["ServiceRequest"]["preferences"].update(
                        {"startFromOffset": offset}
                    )
                    page_number += 1
            except QualysPluginException as err:
                err_msg = (
                    f"Error occurred while {logger_msg}. Error: {str(err)}"
                )
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg}",
                )
                continue
            except Exception as err:
                err_msg = (
                    f"Unexpected error occurred while {logger_msg}."
                    f" Error: {str(err)}"
                )
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg}",
                    details=traceback.format_exc(),
                )
                continue
            batch_fetch_log = (
                f"Successfully fetched {len(_finding_info)} finding IDs"
            )
            if batch_skip > 0:
                batch_fetch_log += (
                    f", Skipped {batch_skip} finding IDs"
                )
            self.logger.info(
                message=(
                    f"{self.log_prefix}: {batch_fetch_log} for"
                    f" {web_app_id_batch_len} web applications"
                    f" in batch {web_app_batch_number}."
                )
            )
            _finding_info, success, skip = self._fetch_vulnerability_info(
                vulnerability_info=_finding_info,
                api_server_url=api_server_url,
                basic_auth=basic_auth,
                batch_number=web_app_batch_number,
                entity_name="web applications",
                storage=storage
            )
            total_success += success
            total_skip += skip
            combined_finding_info = self.parser.combine_details(
                vulnerability_info=_finding_info,
                vulnerability_qid_to_id_field=_finding_id_to_web_app_id,
                host_id_to_required_fields=None,
            )
            updated_web_app_records.extend(combined_finding_info)
        final_fetch_log = (
            f"Successfully fetched {total_success} finding record(s)"
        )
        if total_skip > 0:
            final_fetch_log += (
                f", Skipped {total_skip} finding record(s)"
            )
        self.logger.info(
            f"{self.log_prefix}: {final_fetch_log} for"
            f" {len(web_app_ids)} web application(s)."
        )
        return updated_web_app_records

    def _fetch_vulnerability_info(
        self,
        vulnerability_info: Dict,
        api_server_url: str,
        basic_auth: HTTPBasicAuth,
        batch_number: int,
        entity_name: Literal["assets", "web applications"],
        storage: Dict,
    ) -> Tuple[Dict, int, int]:
        """Augment finding/vulnerability records with detailed metadata.

        Args:
            vulnerability_info (Dict): Mapping of QIDs to partially populated
                finding or vulnerability payloads collected from the ID API.
            api_server_url (str): Qualys API base URL used for detail lookups.
            basic_auth (HTTPBasicAuth): Credentials for authenticating
                requests.
            batch_number (int): Sequential identifier for the parent entity
                batch, used only for logging context.
            entity_name (Literal["assets", "web applications"]): Type of entity
                that owns the QIDs; determines which field mappings to apply.

        Returns:
            Tuple[Dict, int, int]: Updated vulnerability_info dict along with
                counts of successfully enriched records and skipped records.
        """
        last_run_at_key = STORAGE_KEYS.get(entity_name, {}).get("update")
        finding_or_vulnerability = (
            "finding" if entity_name == "web applications" else "vulnerability"
        )
        if not vulnerability_info:
            self.logger.info(
                f"{self.log_prefix}: No {finding_or_vulnerability} IDs found"
                f" for {entity_name} batch {batch_number} hence skipped"
                f" fetching {finding_or_vulnerability} details."
            )
            storage.update(
                {
                    last_run_at_key: datetime.now(timezone.utc).strftime(
                        DATETIME_FORMAT
                    )
                }
            )
            return {}, 0, 0
        headers = self.qualys_helper.get_headers(
            access_token=None,
            request_response_type="xml",
            x_requested_header=True
        )
        vulnerability_id_batch = self.parser.create_batches(
            data_list=list(vulnerability_info.keys()),
            batch_size=FINDING_OR_VULN_BATCH_SIZE,
        )
        url = FETCH_VULNERABILITY_DETAILS_API_ENDPOINT.format(
            api_server_url=api_server_url
        )
        entity_field_mapping = (
            ASSET_VULNERABILITY_EXTRA_INFO_FIELD_MAPPING
            if entity_name == "assets"
            else WEB_APPLICATION_FINDING_EXTRA_INFO_FIELD_MAPPING
        )
        total_success = 0
        total_skip = 0
        for id_batch_number, id_list in vulnerability_id_batch.items():
            page_skip = 0
            page_success = 0
            request_body = {
                "action": "list",
                "details": "All",
                "ids": ",".join(id_list),
            }
            try:
                logger_msg = (
                    f"fetching {finding_or_vulnerability} info for"
                    f" {len(id_list)} {finding_or_vulnerability} ids"
                    f" for ids batch {id_batch_number} and {entity_name}"
                    f" batch {batch_number} from {PLATFORM_NAME}"
                    " platform"
                )
                response = self.qualys_helper.api_helper(
                    logger_msg=logger_msg,
                    url=url,
                    method="POST",
                    params={},
                    headers=headers,
                    data=request_body,
                    verify=self.ssl_validation,
                    proxies=self.proxy,
                    storage={},
                    configuration=self.configuration,
                    is_validation=False,
                    is_handle_error_required=True,
                    regenerate_access_token=False,
                    basic_auth=basic_auth,
                    response_format="xml"
                )
                storage.update(
                    {
                        last_run_at_key: datetime.now(timezone.utc).strftime(
                            DATETIME_FORMAT
                        )
                    }
                )
                response_element = response.find("RESPONSE")
                if not response_element:
                    continue
                vuln_list_element = response_element.find("VULN_LIST")
                if not vuln_list_element:
                    continue
                vulnerabilities = (
                    vuln_list_element.findall("VULN")
                )
                if not vulnerabilities:
                    continue
                for vulnerability in vulnerabilities:
                    try:
                        qid = vulnerability.find("QID").text
                        if not qid:
                            page_skip += 1
                            continue
                        extracted_fields = self.parser.extract_entity_fields(
                            event=vulnerability,
                            entity_field_mapping=entity_field_mapping,
                            event_type="xml",
                        )
                        if not extracted_fields:
                            page_skip += 1
                        else:
                            page_success += 1
                            vulnerability_info[qid].update(extracted_fields)
                    except Exception as err:
                        err_msg = (
                            "Unable to extract fields from "
                            f"{finding_or_vulnerability} record."
                        )
                        self.logger.error(
                            message=(
                                f"{self.log_prefix}: {err_msg} "
                                f"Error: {err}."
                            ),
                            details=traceback.format_exc(),
                        )
                        page_skip += 1
                total_success += page_success
                total_skip += page_skip
            except QualysPluginException as err:
                err_msg = (
                    f"Error occurred while {logger_msg}. Error: {str(err)}"
                )
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg}",
                )
                continue
            except Exception as err:
                err_msg = (
                    f"Unexpected error occurred while {logger_msg}."
                    f" Error: {str(err)}"
                )
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg}",
                    details=traceback.format_exc(),
                )
                continue
            fetch_log = (
                f"Successfully fetched {page_success}"
                f" {finding_or_vulnerability} details"
            )
            if page_skip > 0:
                fetch_log += (
                    f" and skipped {page_skip}"
                    f" {finding_or_vulnerability} details"
                )
            self.logger.debug(
                f"{self.log_prefix}: {fetch_log} for"
                f" {len(id_list)} {finding_or_vulnerability} ids"
                f" for ids batch {id_batch_number} and {entity_name}"
                f" batch {batch_number} from {PLATFORM_NAME}"
                " platform."
            )
        return vulnerability_info, total_success, total_skip

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
        fetch_time = None
        if self.last_run_at:
            fetch_time = datetime.strftime(self.last_run_at, DATETIME_FORMAT)
        storage = self._get_storage()
        if entity_name == "assets":
            assets = self._fetch_assets(fetch_time=fetch_time, context={})
            records.extend(assets)
            storage.update({"asset_last_run_at": fetch_time})
        elif entity_name == "web applications":
            web_applications = self._fetch_web_applications(
                fetch_time=fetch_time, context={}
            )
            records.extend(web_applications)
            storage.update({"web_app_last_run_at": fetch_time})
        else:
            err_msg = (
                f"Invalid entity found. {PLATFORM_NAME} plugin "
                "only supports 'Assets' and 'Web Applications` Entity."
            )
            self.logger.error(message=f"{self.log_prefix}: {err_msg}")
            raise QualysPluginException(err_msg)
        return records

    def update_records(self, entity: str, records: List[Dict]):
        """Update records present in Cloud Exchange.

        Args:
            entity (str): Entity to be updated.
            records (list): List of records to be updated.

        Returns:
            List: List of updated records.
        """
        updated_records = []
        entity_lower = entity.lower()
        *_, pull_asset_vulnerability, pull_webapp_findings = (
            self.qualys_helper.get_configuration_parameters(
                configuration=self.configuration
            )
        )
        storage = self._get_storage()
        if entity_lower == "assets":
            if pull_asset_vulnerability == "No":
                self.logger.info(
                    f"{self.log_prefix}: Skipping fetching vulnerabilities "
                    "for assets as it is disabled in plugin configuration."
                )
                return []
            time_filter = self._get_time_filter(
                storage=storage,
                entity_name=entity_lower,
            )
            host_id_to_required_fields = {}
            for record in records:
                host_id = record.get("Host ID")
                asset_id = record.get("Asset ID")
                serial_number = record.get("Serial Number")
                if host_id:
                    host_id_to_required_fields[host_id] = (
                        asset_id, serial_number
                    )
            self.logger.info(
                f"{self.log_prefix}: Fetching vulnerabilities for "
                f"{len(host_id_to_required_fields)} assets from"
                f" {PLATFORM_NAME} platform."
            )
            updated_records = self._fetch_asset_vulnerabilities(
                host_id_to_required_fields=host_id_to_required_fields,
                time_filter=time_filter,
                storage=storage
            )
            return updated_records
        elif entity_lower == "web applications":
            if pull_webapp_findings == "No":
                self.logger.info(
                    f"{self.log_prefix}: Skipping fetching findings "
                    "for web applications as it is disabled in plugin "
                    "configuration."
                )
                return []
            time_filter = self._get_time_filter(
                storage=storage,
                entity_name=entity_lower,
            )
            web_app_ids = []
            for record in records:
                web_app_id = record.get("Web Application ID")
                if web_app_id:
                    web_app_ids.append(web_app_id)
            self.logger.info(
                f"{self.log_prefix}: Fetching findings for "
                f"{len(web_app_ids)} web applications from "
                f"{PLATFORM_NAME} platform."
            )
            updated_records = self._fetch_web_application_findings(
                web_app_ids=web_app_ids,
                time_filter=time_filter,
                storage=storage,
            )
            return updated_records
        else:
            err_msg = (
                f"Invalid entity found. {PLATFORM_NAME} plugin "
                "only supports 'Assets' and 'Web Applications' Entity."
            )
            self.logger.error(message=f"{self.log_prefix}: {err_msg}")
            raise QualysPluginException(err_msg)

    def _get_time_filter(
        self,
        storage: Dict,
        entity_name: Literal["assets", "web applications"],
    ) -> str:
        """Return the timestamp string to scope incremental data pulls.

        Args:
            self_last_run_at: Timestamp captured on the plugin instance
                (typically ``self.last_run_at``) representing the previous run
                time available in memory.
            storage (Dict): Persistent storage object that may already have a
                saved last-run timestamp for the given entity type.
            storage_key (Literal): Key inside ``storage`` that maps to the
                relevant last-run timestamp (asset or web-app specific).

        Returns:
            str: Timestamp formatted according to ``DATETIME_FORMAT`` when a
                value is found, otherwise ``None``.
        """
        time_keys = STORAGE_KEYS.get(entity_name)
        fetch_last_run_at = time_keys.get("fetch")
        update_last_run_at = time_keys.get("update")
        # Check if last run at time was updated during the update_records call
        if storage.get(update_last_run_at):
            time_filter = storage.get(update_last_run_at)
        # Check if last run at time was updated during the fetch_records call
        elif storage.get(fetch_last_run_at):
            time_filter = storage.get(fetch_last_run_at)
        else:
            time_filter = None
        return time_filter

    def get_actions(self) -> List[ActionWithoutParams]:
        """Get available actions.

        Args:
            None

        Returns:
            [...] list of ActionWithoutParams: List of ActionWithoutParams
                which has label and value defined

        """
        return [
            ActionWithoutParams(
                label="Add/Remove Asset Tag(s)",
                value="asset_tag_untag",
            ),
            ActionWithoutParams(label="Scan Asset(s)", value="asset_scan"),
            ActionWithoutParams(
                label="Add/Remove Web Application Tag(s)",
                value="web_app_tag_untag",
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
        if action.value == "asset_tag_untag":
            return [
                {
                    "label": "Action Type",
                    "key": "tag_action_type",
                    "type": "choice",
                    "choices": [
                        {"key": "Add Tag(s)", "value": "add"},
                        {"key": "Remove Tag(s)", "value": "remove"},
                    ],
                    "default": "add",
                    "mandatory": True,
                    "description": "Choose action to perform on Asset(s).",
                },
                {
                    "label": "Asset ID",
                    "key": "asset_id",
                    "type": "text",
                    "default": "",
                    "mandatory": True,
                    "description": (
                        "Comma separated Asset ID(s) of "
                        "the asset to perform the action on."
                    ),
                },
                {
                    "label": "Tags",
                    "key": "tags",
                    "type": "text",
                    "default": "",
                    "mandatory": True,
                    "description": (
                        "Comma separated Tag(s) to be added/removed."
                    ),
                }
            ]
        if action.value == "asset_scan":
            return [
                {
                    "label": "Asset ID",
                    "key": "asset_id",
                    "type": "text",
                    "default": "",
                    "mandatory": True,
                    "description": "ID of asset to be scanned.",
                },
                {
                    "label": "Scan Type",
                    "key": "scan_type",
                    "type": "choice",
                    "choices": [
                        {"key": "Inventory Scan", "value": "Inventory_Scan"},
                        {
                            "key": "Vulnerability Scan",
                            "value": "Vulnerability_Scan",
                        },
                        {
                            "key": "Policy Audit Scan",
                            "value": "PolicyCompliance_Scan",
                        },
                        {"key": "UDC Scan", "value": "UDC_Scan"},
                        {"key": "SCA Scan", "value": "SCA_Scan"},
                        {"key": "SWCA Scan", "value": "SWCA_scan"},
                    ],
                    "default": "Inventory_Scan",
                    "mandatory": True,
                    "description": "On-demand scan type.",
                },
                {
                    "label": "Override Config CPU",
                    "key": "override_config_cpu",
                    "type": "choice",
                    "choices": [
                        {"key": "Yes", "value": "True"},
                        {"key": "No", "value": "False"},
                    ],
                    "default": "True",
                    "mandatory": True,
                    "description": (
                        "Set this flag to define the CPU throttle limits that"
                        " the on demand scan will use."
                    ),
                },
            ]
        if action.value == "web_app_tag_untag":
            return [
                {
                    "label": "Action Type",
                    "key": "tag_action_type",
                    "type": "choice",
                    "choices": [
                        {"key": "Add Tag(s)", "value": "add"},
                        {"key": "Remove Tag(s)", "value": "remove"},
                    ],
                    "default": "add",
                    "mandatory": True,
                    "description": (
                        "Choose action to perform on Web Applications(s)."
                    ),
                },
                {
                    "label": "Web Application ID",
                    "key": "web_app_id",
                    "type": "text",
                    "default": "",
                    "mandatory": True,
                    "description": (
                        "Comma separated Web Application ID(s) of "
                        "the web application to perform the action on."
                    ),
                },
                {
                    "label": "Tags",
                    "key": "tags",
                    "type": "text",
                    "default": "",
                    "mandatory": True,
                    "description": (
                        "Comma separated Tag(s) to be added/removed."
                    ),
                }
            ]

    @exception_handler
    def validate_action(self, action: Action):
        """Validate Netskope configuration.

        Args:
            action (Action): Action object.

        Returns:
            ValidationResult: Validation result.
        """
        action_value = action.value
        action_params = action.parameters
        if action_value == "generate":
            log_msg = (
                "Successfully validated action configuration"
                f" for '{action.label}'."
            )
            self.logger.debug(f"{self.log_prefix}: {log_msg}")
            return ValidationResult(success=True, message=log_msg)
        if action_value not in [
            "generate",
            "asset_tag_untag",
            "asset_scan",
            "web_app_tag_untag",
        ]:
            err_msg = (
                f"Unsupported action {action_value} provided in the action"
                " configuration. Supported Actions are - 'Add/Remove Asset"
                " Tag(s)', 'Scan Asset(s)' and 'Add/Remove Web Application"
                " Tag(s)'."
            )
            resolution = (
                "Ensure that the action is selected from the supported actions"
                " 'Add/Remove Asset Tag(s)', 'Scan Asset(s)', 'Add/Remove"
                " Web Application Tag(s)' or 'No Action' in the action"
                " configuration."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                resolution=resolution,
            )
            return ValidationResult(
                success=False, message="Unsupported action provided."
            )
        if action_value == "asset_tag_untag":
            tag_action_type = action_params.get("tag_action_type")
            asset_id = action_params.get("asset_id")
            tags = action_params.get("tags")

            if validation_result := self._validate_parameters(
                parameter_type="action",
                field_name="Action Type",
                field_value=tag_action_type,
                field_type=str,
                allowed_values=TAG_ACTION_OPTIONS
            ):
                return validation_result

            if validation_result := self._validate_parameters(
                parameter_type="action",
                field_name="Asset ID",
                field_value=asset_id,
                field_type=str,
                check_dollar=True,
            ):
                return validation_result

            if validation_result := self._validate_parameters(
                parameter_type="action",
                field_name="Tags",
                field_value=tags,
                field_type=str,
                check_dollar=True,
                custom_validation_func=self.qualys_helper.validate_tags_string,
            ):
                return validation_result

            if not self.qualys_helper.validate_tags(tags=tags):
                return ValidationResult(
                    success=False,
                    message=(
                        "Invalid tag provided. Ensure the tag length is less"
                        f" than {TAG_NAME_LENGTH} characters."
                    )
                )
        if action_value == "asset_scan":
            asset_id = action_params.get("asset_id")
            scan_type = action_params.get("scan_type")
            override_config_cpu = action_params.get("override_config_cpu")

            if validation_result := self._validate_parameters(
                parameter_type="action",
                field_name="Asset ID",
                field_value=asset_id,
                field_type=str,
                check_dollar=True,
            ):
                return validation_result

            if validation_result := self._validate_parameters(
                parameter_type="action",
                field_name="Scan Type",
                field_value=scan_type,
                field_type=str,
                allowed_values=SCAN_TYPE_OPTIONS,
            ):
                return validation_result

            if validation_result := self._validate_parameters(
                parameter_type="action",
                field_name="Override Config CPU",
                field_value=override_config_cpu,
                field_type=str,
                allowed_values=OVERRIDE_CONFIG_CPU_OPTIONS,
            ):
                return validation_result

        if action_value == "web_app_tag_untag":
            web_app_id = action_params.get("web_app_id")
            tag_action_type = action_params.get("tag_action_type")
            tags = action_params.get("tags")
            if validation_result := self._validate_parameters(
                parameter_type="action",
                field_name="Action Type",
                field_value=tag_action_type,
                field_type=str,
                allowed_values=TAG_ACTION_OPTIONS
            ):
                return validation_result

            if validation_result := self._validate_parameters(
                parameter_type="action",
                field_name="Web Application ID",
                field_value=web_app_id,
                field_type=str,
                check_dollar=True,
            ):
                return validation_result

            if validation_result := self._validate_parameters(
                parameter_type="action",
                field_name="Tags",
                field_value=tags,
                field_type=str,
                check_dollar=True,
                custom_validation_func=self.qualys_helper.validate_tags_string,
            ):
                return validation_result

            if not self.qualys_helper.validate_tags(tags=tags):
                return ValidationResult(
                    success=False,
                    message=(
                        "Invalid tag provided. Ensure the tag length is less"
                        f" than {TAG_NAME_LENGTH} characters."
                    )
                )
        return ValidationResult(
            success=True, message="Successfully validated action parameters"
        )

    @exception_handler
    def execute_actions(self, actions: List[Action]):
        """Execute actions on the record.

        Args:
            actions (List[Action]): List of actions to execute.
        """
        first_action = (
            actions[0].get("params", {})
            if self._is_ce_post_v512
            else actions[0]
        )
        action_label = first_action.label
        action_value = first_action.value
        self.logger.info(
            f"{self.log_prefix}: Executing '{action_label}' action "
            f"for {len(actions)} records."
        )
        if action_value == "generate":
            self.logger.info(
                f"{self.log_prefix}: Successfully executed '{action_label}' "
                "action. Note: No processing will be done from plugin for "
                f"the '{action_label}' action."
            )
            return
        if action_value == "asset_tag_untag":
            tag_action_type = first_action.parameters.get("tag_action_type")
            failed_action_ids = self._execute_asset_tag_untag_action(
                actions=actions,
                tag_action_type=tag_action_type,
                action_label=action_label,
                context={}
            )
            if self._is_ce_post_v512:
                from netskope.integrations.crev2.plugin_base import \
                    ActionResult
                return ActionResult(
                    success=True,
                    message=(
                        f"Successfully executed {action_label} action."
                    ),
                    failed_action_ids=list(failed_action_ids),
                )
            return
        if action_value == "asset_scan":
            failed_action_ids = self._execute_asset_scan_action(
                actions=actions,
            )
            if self._is_ce_post_v512:
                from netskope.integrations.crev2.plugin_base import \
                    ActionResult
                return ActionResult(
                    success=True,
                    message=(
                        f"Successfully executed {action_label} action."
                    ),
                    failed_action_ids=list(failed_action_ids),
                )
            return
        if action_value == "web_app_tag_untag":
            tag_action_type = first_action.parameters.get("tag_action_type")
            failed_action_ids = self._execute_webapp_tag_untag_action(
                actions=actions,
                tag_action_type=tag_action_type,
                action_label=action_label,
                context={},
            )
            if self._is_ce_post_v512:
                from netskope.integrations.crev2.plugin_base import \
                    ActionResult
                return ActionResult(
                    success=True,
                    message=(
                        f"Successfully executed {action_label} action."
                    ),
                    failed_action_ids=list(failed_action_ids),
                )
            return

    @exception_handler
    def _execute_asset_tag_untag_action(
        self,
        actions: List[Action],
        tag_action_type: Literal["add", "remove"],
        action_label: str,
        context={},
    ):
        """Execute Add/Remove Tag action for assets in grouped batches.

        Args:
            actions (List[Action]): Action payloads received from Cloud
                Exchange.
            tag_action_type (Literal["add", "remove"]): Operation to perform
                on the provided tags.
            action_label (str): UI label for logging the action progress.

        Returns:
            Set: Action IDs that failed because of missing IDs or API errors.
        """
        context["logger_msg"] = (
            f"Executing {action_label} action for {len(actions)} asset(s)."
        )
        (
            grouped_actions,
            id_field_to_action_id_mapping,
            all_action_tags,
            empty_id_field_count,
            empty_id_field_action_id,
        ) = self.parser.group_actions(
            group_by_field="tags",
            actions=actions,
            id_field="asset_id",
        )
        if empty_id_field_count > 0:
            self.logger.info(
                f"{self.log_prefix}: Skipped executing"
                f" {tag_action_type.capitalize()} Tag action on"
                f" {empty_id_field_count} asset(s) since"
                " Asset ID field is empty."
            )

        tag_name_to_id_mapping = self._upsert_tags(
            action_tags=all_action_tags,
            grouped_actions=grouped_actions,
            tag_action_type=tag_action_type,
            entity_name="asset",
        )

        if not tag_name_to_id_mapping:
            self.logger.info(
                f"{self.log_prefix}: Skipped executing"
                f" '{action_label}' action on"
                " assets as no tags were found on the"
                f" {PLATFORM_NAME} platform."
            )
            return set(list(id_field_to_action_id_mapping.values()))
        # Execute Action
        failed_action_ids, action_stats = self._add_remove_asset_tags(
            grouped_actions=grouped_actions,
            tag_action_type=tag_action_type,
            asset_id_to_action_id=id_field_to_action_id_mapping,
            tag_name_to_id_mapping=tag_name_to_id_mapping,
        )
        self.logger.info(
            message=(
                f"{self.log_prefix}: Successfully executed action"
                f" '{action_label}'. Expand the log to view action"
                " stats."
            ),
            details=f"Action stats: {action_stats}"
        )
        failed_action_ids.update(empty_id_field_action_id)
        return failed_action_ids

    def _add_remove_asset_tags(
        self,
        grouped_actions: Dict[str, Set[str]],
        tag_action_type: Literal["add", "remove"],
        asset_id_to_action_id: Dict,
        tag_name_to_id_mapping: Dict,
    ) -> Tuple[Set, Dict[str, Dict[str, int]]]:
        """Invoke Qualys API to add or remove tags from assets.

        Args:
            grouped_actions (Dict[str, Set[str]]): Mapping of tag names to the
                associated asset IDs grouped by parser.
            tag_action_type (Literal["add", "remove"]): Requested tag
                operation.
            asset_id_to_action_id (Dict): Mapping from asset ID to action ID to
                correlate failures.
            tag_name_to_id_mapping (Dict): Cached Qualys tag name to tag ID map
                produced by `_upsert_tags`.

        Returns:
            Tuple[Set, Dict[str, Dict[str, int]]]: A tuple containing failed
                action IDs and per-tag success/failed stats.
        """
        failed_action_ids = set()
        action_stats = {}
        tag_action_type_capitalize = tag_action_type.capitalize()
        api_server_url, _, username, password, _, _ = (
            self.qualys_helper.get_configuration_parameters(self.configuration)
        )
        headers = self.qualys_helper.get_headers(
            access_token=None,
            request_response_type="json",
            x_requested_header=True,
        )
        basic_auth = HTTPBasicAuth(username, password)
        url = TAG_ASSET_API_ENDPOINT.format(api_server_url=api_server_url)
        for tag_name, asset_id_list in grouped_actions.items():
            asset_id_list = list(asset_id_list)
            action_stats[tag_name] = {
                "success": 0,
                "failed": 0,
            }
            tag_id = tag_name_to_id_mapping.get(tag_name)
            batch_number = 1
            for index in range(0, len(asset_id_list), TAG_ASSET_BATCH_SIZE):
                asset_id_batch = asset_id_list[
                    index:index + TAG_ASSET_BATCH_SIZE
                ]
                logger_msg = (
                    f"executing '{tag_action_type_capitalize} Tag(s)' for tag"
                    f" {tag_name} on {len(asset_id_batch)} asset(s) for batch"
                    f" {batch_number}"
                )
                self.logger.info(
                    message=(
                        f"{self.log_prefix}: Executing"
                        f" '{tag_action_type_capitalize} Tag(s)' for tag"
                        f" {tag_name} on {len(asset_id_batch)} asset(s)"
                        f" for batch {batch_number}"
                    ),
                    details=(
                        f"Asset ID(s) in batch {batch_number}:"
                        f" {', '.join(asset_id_batch)}"
                    ),
                )
                asset_ids_string = ",".join(asset_id_batch)
                request_body = {
                    "ServiceRequest": {
                        "filters": {
                            "Criteria": [
                                {
                                    "field": "id",
                                    "operator": "IN",
                                    "value": asset_ids_string,
                                }
                            ]
                        },
                        "data": {
                            "HostAsset": {
                                "tags": {
                                    f"{tag_action_type}": {
                                        "TagSimple": [
                                            {"id": tag_id},
                                        ]
                                    }
                                }
                            }
                        },
                    }
                }
                success_asset_id = set()
                success = 0
                skip = 0
                try:
                    response = self.qualys_helper.api_helper(
                        logger_msg=logger_msg,
                        url=url,
                        method="POST",
                        params={},
                        json=request_body,
                        headers=headers,
                        verify=self.ssl_validation,
                        proxies=self.proxy,
                        storage={},
                        configuration=self.configuration,
                        is_validation=False,
                        is_handle_error_required=True,
                        regenerate_access_token=False,
                        basic_auth=basic_auth,
                        response_format="json",
                    )
                    data = response.get("ServiceResponse", {}).get("data", [])
                    for host_asset in data:
                        asset_id = str(host_asset.get(
                            "HostAsset", {}
                        ).get("id", ""))
                        success_asset_id.add(asset_id)
                        success += 1
                    skip = len(asset_id_batch) - len(success_asset_id)
                    failed_asset_ids = set(asset_id_batch) - success_asset_id
                    for failed_asset_id in failed_asset_ids:
                        if failed_action_id := asset_id_to_action_id.get(
                            failed_asset_id
                        ):
                            failed_action_ids.add(failed_action_id)
                    self.logger.info(
                        message=(
                            f"{self.log_prefix}: Successfully executed "
                            f"'{tag_action_type_capitalize} Tag(s)' for tag "
                            f"{tag_name} on {success} asset(s) for batch "
                            f"{batch_number}."
                        ),
                        details=f"Asset ID(s): {', '.join(success_asset_id)}"
                    )
                    if skip > 0:
                        self.logger.info(
                            message=(
                                f"{self.log_prefix}: Failed to execute "
                                f"'{tag_action_type_capitalize} Tag(s)' for "
                                f"tag {tag_name} on {skip} asset(s) for batch"
                                f" {batch_number}."
                            ),
                            details=(
                                f"Asset ID(s):"
                                f"{', '.join(failed_asset_ids)}"
                            )
                        )
                    action_stats[tag_name]["success"] += success
                    action_stats[tag_name]["failed"] += skip
                    batch_number += 1
                except QualysPluginException as err:
                    err_msg = (
                        f"Error occurred while {logger_msg}. Error: {err}"
                    )
                    self.logger.error(
                        message=f"{self.log_prefix}: {err_msg}",
                        details=f"Failed asset ID(s): {asset_ids_string}",
                    )
                    for failed_asset_id in asset_id_batch:
                        if failed_action_id := asset_id_to_action_id.get(
                            failed_asset_id
                        ):
                            failed_action_ids.add(failed_action_id)
                    action_stats[tag_name]["failed"] += len(asset_id_batch)
                    batch_number += 1
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
                    for failed_asset_id in asset_id_batch:
                        if failed_action_id := asset_id_to_action_id.get(
                            failed_asset_id
                        ):
                            failed_action_ids.add(failed_action_id)
                    action_stats[tag_name]["failed"] += len(asset_id_batch)
                    batch_number += 1
                    continue
        return failed_action_ids, action_stats

    def _execute_asset_scan_action(self, actions: Action) -> Set:
        """Trigger on-demand Qualys agent scans for the supplied assets.

        Args:
            actions (Action): List of action payloads describing scan type,
                override flag, and asset IDs.

        Returns:
            Set: Action IDs that failed due to validation or API execution
            issues.
        """
        first_action_param = self.parser._get_action_params(
            action=actions[0],
            action_fields=["scan_type", "override_config_cpu"],
        )
        scan_type = first_action_param.get("scan_type")
        scan_name_for_logger = SCAN_TYPE_OPTIONS.get(scan_type)
        override_config_cpu = first_action_param.get("override_config_cpu")
        asset_id_list = []
        # This list (asset_id_list_int) is used to store asset_ids in integer
        # format which is later used to calculate failed asset_ids, where we
        # subtract this list from the success asset_ids List[int] we get from
        # api response.
        asset_id_list_int = []
        empty_asset_id_count = 0
        failed_action_ids = set()
        asset_id_to_action_id = {}
        for action in actions:
            action_params = self.parser._get_action_params(
                action=action,
                action_fields=["asset_id"],
            )
            if asset_id_str := action_params.get("asset_id", ""):
                asset_id_list.append(asset_id_str)
                asset_id_list_int.append(int(asset_id_str))
                asset_id_to_action_id[
                    asset_id_str
                ] = action_params.get("action_id")
            else:
                empty_asset_id_count += 1
                failed_action_ids.add(action_params.get("action_id"))
        if empty_asset_id_count > 0:
            self.logger.info(
                f"{self.log_prefix}: Skipped running scan on"
                f" {empty_asset_id_count} asset(s) since"
                " Asset ID field is empty."
            )
        api_server_url, _, username, password, _, _ = (
            self.qualys_helper.get_configuration_parameters(
                configuration=self.configuration
            )
        )
        url = SCAN_ASSET_API_ENDPOINT.format(api_server_url=api_server_url)
        headers = self.qualys_helper.get_headers(
            access_token=None,
            request_response_type="json",
            x_requested_header=True,
        )
        query_params = {
            "scan": scan_type,
            "overrideConfigCpu": override_config_cpu,
        }
        basic_auth = HTTPBasicAuth(username, password)
        batch_number = 1
        success = 0
        skip = 0
        for index in range(0, len(asset_id_list), SCAN_ASSET_BATCH_SIZE):
            asset_id_batch = asset_id_list[index:index + SCAN_ASSET_BATCH_SIZE]
            asset_id_batch_int = asset_id_list_int[index:index + SCAN_ASSET_BATCH_SIZE]
            asset_ids_string = ",".join(asset_id_batch)
            logger_msg = (
                f"executing {scan_name_for_logger} on"
                f" {len(asset_id_batch)} asset(s) for batch {batch_number}"
            )
            self.logger.info(
                f"{self.log_prefix}: Executing {scan_name_for_logger}"
                f" on {len(asset_id_batch)} asset(s) for batch"
                f" {batch_number}."
            )
            request_body = {
                "ServiceRequest": {
                    "filters": {
                        "Criteria": {
                            "field": "id",
                            "operator": "IN",
                            "value": asset_ids_string,
                        }
                    }
                }
            }
            try:
                response = self.qualys_helper.api_helper(
                    logger_msg=logger_msg,
                    url=url,
                    method="POST",
                    params=query_params,
                    json=request_body,
                    headers=headers,
                    verify=self.ssl_validation,
                    proxies=self.proxy,
                    storage={},
                    configuration=self.configuration,
                    is_validation=False,
                    is_handle_error_required=True,
                    regenerate_access_token=False,
                    basic_auth=basic_auth,
                    response_format="json",

                )
                single_module_response = (
                    response.get("ServiceResponse", {})
                    .get("data", [{}])[0]
                    .get("SingleModuleResponse", {})
                )
                success_asset_ids = json.loads(
                    single_module_response.get("assetIds", "[]")
                )
                success_count = single_module_response.get(
                    "count", len(success_asset_ids)
                )
                failed_asset_ids = set(asset_id_batch_int) - set(success_asset_ids)
                failed_action_ids.update(
                    [
                        # In the asset_id_to_action_id dict keys are in string
                        # format and the asset id we get from response are on
                        # int format
                        asset_id_to_action_id.get(str(asset_id))
                        for asset_id in failed_asset_ids
                    ]
                )
            except QualysPluginException as err:
                err_msg = (
                    f"Error occurred while {logger_msg}. Error: {err}"
                )
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg}",
                    details=f"Failed Asset IDs: {asset_ids_string}",
                )
                for failed_asset_id in asset_id_batch:
                    if failed_action_id := asset_id_to_action_id.get(
                        failed_asset_id
                    ):
                        failed_action_ids.add(failed_action_id)
                skip += len(asset_id_batch)
                batch_number += 1
                continue
            except Exception as err:
                err_msg = (
                    f"Unexpected error occurred while {logger_msg}."
                    f" Error: {err}"
                )
                self.logger.error(
                    f"{self.log_prefix}: {err_msg}",
                    details=traceback.format_exc(),
                )
                for failed_asset_id in asset_id_batch:
                    if failed_action_id := asset_id_to_action_id.get(
                        failed_asset_id
                    ):
                        failed_action_ids.add(failed_action_id)
                skip += len(asset_id_batch)
                batch_number += 1
                continue
            success += success_count
            skip += len(failed_asset_ids)
            self.logger.info(
                f"{self.log_prefix}: Successfully executed"
                f" {scan_name_for_logger} on {success_count}"
                f" asset(s) for batch {batch_number}."
            )
            if failed_asset_ids:
                self.logger.info(
                    message=(
                        f"{self.log_prefix}: Failed to execute"
                        f" {scan_name_for_logger} on"
                        f" {len(failed_asset_ids)} asset(s) for batch"
                        f" {batch_number}."
                    ),
                    details=(
                        f"Failed Asset IDs: "
                        f"{','.join([str(asset_id) for asset_id in failed_asset_ids])}"
                    ),
                )
            batch_number += 1
        final_logger = (
            f"Successfully executed {scan_name_for_logger} on"
            f" {success} asset(s)."
        )
        if skip > 0:
            final_logger += (
                f" Failed to execute {scan_name_for_logger} on"
                f" {skip} asset(s)."
            )
        self.logger.info(f"{self.log_prefix}: {final_logger}")
        return failed_action_ids

    @exception_handler
    def _execute_webapp_tag_untag_action(
        self,
        actions: List[Action],
        tag_action_type: Literal["add", "remove"],
        action_label: str,
        context: Dict = {},
    ) -> Set:
        """Execute Add/Remove Tag action for Qualys web applications.

        Args:
            actions (List[Action]): Action payloads received from Cloud
                Exchange.
            tag_action_type (Literal["add", "remove"]): Tag operation to
                perform.
            action_label (str): Human-readable label used for logging.

        Returns:
            Set: Action IDs that were skipped or failed during execution.
        """
        context["logger_msg"] = (
            f"Executing {action_label} action for {len(actions)} web app(s)."
        )
        (
            grouped_actions,
            webapp_id_to_action_id_mapping,
            all_action_tags,
            empty_id_field_count,
            empty_id_field_action_id,
        ) = self.parser.group_actions(
            group_by_field="id_field",
            actions=actions,
            id_field="web_app_id",
        )

        if empty_id_field_count > 0:
            self.logger.info(
                f"{self.log_prefix}: Skipped executing"
                f" {tag_action_type.capitalize()} Tag action on"
                f" {empty_id_field_count} asset(s) since"
                " Asset ID field is empty."
            )
        tag_name_to_id_mapping = self._upsert_tags(
            action_tags=all_action_tags,
            grouped_actions=grouped_actions,
            tag_action_type=tag_action_type,
            entity_name="asset",
        )
        if not tag_name_to_id_mapping:
            self.logger.info(
                f"{self.log_prefix}: Skipped executing"
                f" '{action_label}' action on"
                " web applications as no tags were found"
                f" on the {PLATFORM_NAME} platform."
            )
            return set(list(webapp_id_to_action_id_mapping))
        failed_action_id, action_stats = self._add_remove_webapp_tags(
            grouped_actions=grouped_actions,
            tag_action_type=tag_action_type,
            webapp_id_to_action_id=webapp_id_to_action_id_mapping,
            tag_name_to_id_mapping=tag_name_to_id_mapping,
        )
        self.logger.info(
            message=(
                f"{self.log_prefix}: Successfully executed action"
                f" '{action_label}'. Expand the log to view action"
                " stats."
            ),
            details=f"Action stats: {action_stats}"
        )
        failed_action_id.update(empty_id_field_action_id)
        return failed_action_id

    def _add_remove_webapp_tags(
        self,
        grouped_actions: Dict[str, Set[str]],
        tag_action_type: Literal["add", "remove"],
        webapp_id_to_action_id: Dict,
        tag_name_to_id_mapping: Dict,
    ) -> Tuple[Set, Dict[str, Dict[str, int]]]:
        """Apply tag add/remove operations to individual web applications.

        Args:
            grouped_actions (Dict): Mapping of web app IDs to their target tag
                names.
            tag_action_type (Literal["add", "remove"]): Operation to perform
                on tags.
            webapp_id_to_action_id (Dict): Mapping from web app ID to action ID
                for failure attribution.
            tag_name_to_id_mapping (Dict): Mapping of tag names to Qualys tag
                IDs available for use.

        Returns:
            Tuple[Set, Dict[str, Dict[str, int]]]: Failed action IDs and per
                web app execution statistics.
        """
        failed_action_ids = set()
        action_stats = {}
        tag_action_type_capitalize = tag_action_type.capitalize()
        for web_app_id, tags_list in grouped_actions.items():
            action_stats[web_app_id] = {
                "success": 0,
                "failed": 0,
                "skipped": 0,
            }
            tag_ids = []
            tag_names_string = ""
            skipped_tags = []
            for tag_name in tags_list:
                if tag_id := tag_name_to_id_mapping.get(tag_name):
                    tag_ids.append({"id": tag_id})
                    tag_names_string += f"{tag_name}, "
                else:
                    skipped_tags.append(tag_name)
            tag_names_string = tag_names_string[:-2]
            self.logger.info(
                message=(
                    f"{self.log_prefix}: Executing"
                    f" '{tag_action_type_capitalize} Tag(s)' for"
                    f" {len(tag_ids)} tag(s) on Web Application"
                    f" with ID {web_app_id}."
                ),
                details=f"Tags: {tag_names_string}",
            )
            if skipped_tags:
                self.logger.info(
                    message=(
                        f"{self.log_prefix}: Skipped executing"
                        f" '{tag_action_type_capitalize} Tag(s)' for"
                        f" {len(skipped_tags)} tag(s) on Web Application"
                        f" with ID {web_app_id} as they do not exist"
                        f" on {PLATFORM_NAME} platform."
                    ),
                    details=f"Skipped tag(s): {', '.join(skipped_tags)}",
                )
                action_stats[web_app_id]["skipped"] += len(skipped_tags)
            logger_msg = (
                f"executing '{tag_action_type_capitalize} Tag(s)' for "
                f" {len(tag_ids)} tag(s) on Web Application with"
                f" ID {web_app_id}"
            )
            api_server_url, _, username, password, _, _ = (
                self.qualys_helper.get_configuration_parameters(
                    self.configuration
                )
            )
            url = TAG_WEBAPP_API_ENDPOINT.format(
                api_server_url=api_server_url,
                web_app_id=web_app_id,
            )
            headers = self.qualys_helper.get_headers(
                access_token=None,
                request_response_type="json",
                x_requested_header=True,
            )
            request_body = {
                "ServiceRequest": {
                    "data": {
                        "WebApp": {
                            "tags": {
                                f"{tag_action_type}": {
                                    "Tag": tag_ids
                                }
                            }
                        }
                    }
                }
            }
            basic_auth = HTTPBasicAuth(username, password)
            try:
                response = self.qualys_helper.api_helper(
                    logger_msg=logger_msg,
                    url=url,
                    method="POST",
                    params={},
                    json=request_body,
                    headers=headers,
                    verify=self.ssl_validation,
                    proxies=self.proxy,
                    storage={},
                    configuration=self.configuration,
                    is_validation=False,
                    is_handle_error_required=True,
                    regenerate_access_token=False,
                    basic_auth=basic_auth,
                    response_format="json",
                )
                response_web_app_id = str(
                    response.get("ServiceResponse", {})
                    .get("data", [{}])[0]
                    .get("WebApp", {})
                    .get("id", "")
                )
                if web_app_id == response_web_app_id:
                    self.logger.info(
                        message=(
                            f"{self.log_prefix}: Successfully executed"
                            f" '{tag_action_type_capitalize} Tag(s)' for"
                            f" {len(tag_ids)} tag(s) on Web Application"
                            f" with ID {web_app_id}."
                        ),
                        details=f"Tags: {tag_names_string}",
                    )
                    action_stats[web_app_id]["success"] += len(tag_ids)
                else:
                    if failed_action_id := webapp_id_to_action_id.get(
                        web_app_id
                    ):
                        failed_action_ids.add(failed_action_id)
                    action_stats[web_app_id]["failed"] += len(tag_ids)
            except QualysPluginException as err:
                err_msg = (
                    f"Error occurred while {logger_msg}. Error: {err}"
                )
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg}",
                )
                if failed_action_id := webapp_id_to_action_id.get(web_app_id):
                    failed_action_ids.add(failed_action_id)
                action_stats[web_app_id]["failed"] += len(tag_ids)
                continue
            except Exception as err:
                err_msg = (
                    f"Unexpected error occurred while {logger_msg}."
                    f" Error: {err}"
                )
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg}",
                )
                if failed_action_id := webapp_id_to_action_id.get(web_app_id):
                    failed_action_ids.add(failed_action_id)
                action_stats[web_app_id]["failed"] += len(tag_ids)
                continue
        return failed_action_ids, action_stats

    @exception_handler
    def _upsert_tags(
        self,
        action_tags: Set[str],
        grouped_actions: Dict[str, Set[str]],
        tag_action_type: Literal["add", "remove"],
        entity_name: Literal["asset", "web application"],
    ) -> Dict[str, str]:
        """Ensure tags referenced in the actions exist on Qualys.

        Args:
            action_tags (Set[str]): Unique set of tag names gathered from
                action payloads.
            grouped_actions (Dict[str, Set[str]]): Grouped mapping used for
                downstream execution; may be mutated if tags are invalid.
            tag_action_type (Literal["add", "remove"]): Whether tags should
                be created (add) or merely validated (remove).
            entity_name (Literal["asset", "web application"]): Entity type
                targeted by the tag action, used when pruning invalid tags.

        Returns:
            Dict[str, str]: Mapping of tag name to Qualys tag ID available for
                later API calls.
        """
        existing_tags = self._fetch_tags()
        tags_to_create = []
        tags_not_to_create = {}
        empty_tags = []
        empty_tag_asset_ids = []
        for action_tag in action_tags:
            if (
                isinstance(action_tag, str) and not action_tag.strip()
            ) or action_tag is None or action_tag.strip() == "None":
                empty_tags.append(action_tag)
                continue
            if action_tag in existing_tags:
                tags_not_to_create[action_tag] = existing_tags[action_tag]
            else:
                tags_to_create.append(action_tag)
        # Remove the tags that are empty from the grouped_actions dictionary
        # and fail action for these asset ids
        empty_tag_logger_msg = (
            f"Skipped {len(empty_tags)} tag(s) as they are empty."
        )
        if empty_tags:
            if entity_name == "asset":
                for tag in empty_tags:
                    if asset_ids := grouped_actions.pop(tag, None):
                        empty_tag_asset_ids.extend(asset_ids)
                self.logger.info(
                    f"{self.log_prefix}: {empty_tag_logger_msg}",
                    details=(
                        "Skipped Asset IDs:"
                        f" {', '.join(empty_tag_asset_ids)}",
                    )
                )
            else:
                self.logger.info(
                    f"{self.log_prefix}: {empty_tag_logger_msg}"
                )

        if tags_to_create:
            if tag_action_type == "add":
                created_tags, long_tags = self._create_tags(
                    tags_to_create=tags_to_create
                )
                tags_not_to_create.update(created_tags)

                # Remove the tags that have length greater than 1024 from the
                # grouped_actions dictionary since they were not created on the
                # platform.
                # Remove them only from the grouped_actions only for Asset
                # entity
                if long_tags:
                    if entity_name == "asset":
                        long_tag_asset_ids = []
                        for tag in long_tags:
                            if asset_ids := grouped_actions.pop(tag, None):
                                long_tag_asset_ids.extend(asset_ids)
                        self.logger.info(
                            message=(
                                f"{self.log_prefix}: Skipped creating"
                                f" {len(long_tags)} tag(s) as they exceeded"
                                f" the maximum length of {TAG_NAME_LENGTH}"
                                " characters."
                            ),
                            details=(
                                f"Long tags: {', '.join(long_tags)}\n"
                                f"Skipped Asset IDs: "
                                f"{', '.join(long_tag_asset_ids)}"
                            ),
                        )
                    # For Web Applications just print the list of long tags.
                    # They will be skipped before the action execution.
                    else:
                        self.logger.info(
                            message=(
                                f"{self.log_prefix}: Failed to create"
                                f" {len(long_tags)} tag(s) as they exceeded"
                                " the maximum length of"
                                f" {TAG_NAME_LENGTH} characters."
                            ),
                            details=f"Long tags: {', '.join(long_tags)}",
                        )
            else:
                if entity_name == "asset":
                    for tag in tags_to_create:
                        grouped_actions.pop(tag, None)
                # During Remove Tag action if the tag does not exist on the
                # platform we do not add it to the tag_name_to_id_mapping
                # dictionary. So here we might not need to remove the tags
                # from the grouped_actions dictionary since during action
                # execution there is a check for if the tag_name does not exist
                # in the tag_name_to_id_mapping dictionary (Line: 2074) we will
                # not include them in the action.
                created_tags = {}
                self.logger.info(
                    message=(
                        f"{self.log_prefix}: Skipped removing"
                        f" {len(tags_to_create)} tag(s) from"
                        f" {entity_name} as they do not exist"
                        f" on {PLATFORM_NAME} platform."
                    ),
                    details=f"Skipped tag(s): {', '.join(tags_to_create)}",
                )
        return tags_not_to_create

    def _fetch_tags(self):
        """Retrieve all tags from the Qualys platform with pagination.

        Returns:
            Dict[str, str]: Mapping of tag names to their Qualys tag IDs.

        Raises:
            QualysPluginException: When an unexpected error occurs while
                calling the API.
        """
        api_server_url, _, username, password, _, _ = (
            self.qualys_helper.get_configuration_parameters(self.configuration)
        )
        headers = self.qualys_helper.get_headers(
            access_token=None,
            request_response_type="json",
            x_requested_header=True,
        )
        request_body = {
            "ServiceRequest": {
                "preferences": {
                    "limitResults": FETCH_TAGS_PAGE_SIZE,
                }
            }
        }
        url = FETCH_TAGS_API_ENDPOINT.format(api_server_url=api_server_url)
        basic_auth = HTTPBasicAuth(username, password)
        existing_tags = {}
        page_number = 1
        offset = 1
        total_success = 0
        total_skip = 0
        while True:
            try:
                page_success = 0
                page_skip = 0
                logger_msg = (
                    f"fetching tags for page {page_number} from"
                    f" {PLATFORM_NAME} platform"
                )
                response = self.qualys_helper.api_helper(
                    logger_msg=logger_msg,
                    url=url,
                    method="POST",
                    params={},
                    headers=headers,
                    json=request_body,
                    verify=self.ssl_validation,
                    proxies=self.proxy,
                    storage={},
                    configuration=self.configuration,
                    is_validation=False,
                    is_handle_error_required=True,
                    regenerate_access_token=False,
                    basic_auth=basic_auth,
                    response_format="json"
                )
                service_response = response.get("ServiceResponse", {})
                tags_data = service_response.get("data", [])
                if not tags_data:
                    break
                for tag_data in tags_data:
                    tag = tag_data.get("Tag", {})
                    if not tag:
                        page_skip += 1
                        continue
                    tag_id = str(tag.get("id", ""))
                    tag_name = tag.get("name")
                    if not tag_id or not tag_name:
                        page_skip += 1
                        continue
                    existing_tags[tag_name] = tag_id
                    page_success += 1
                total_success += page_success
                total_skip += page_skip
                fetch_msg = f"Successfully fetched {page_success} tag(s)"
                if page_skip:
                    fetch_msg += f", Skipped fetching {page_skip} tag(s)"
                self.logger.debug(
                    f"{self.log_prefix}: {fetch_msg} for page {page_number}"
                    f" from {PLATFORM_NAME} platform. Total tag(s) fetched:"
                    f" {total_success}."
                )
                has_more_records = service_response.get("hasMoreRecords")
                if has_more_records == "false":
                    break
                if len(tags_data) < FETCH_TAGS_PAGE_SIZE:
                    break
                offset += FETCH_TAGS_PAGE_SIZE
                request_body["ServiceRequest"]["preferences"].update(
                    {"startFromOffset": offset}
                )
                page_number += 1
            except QualysPluginException:
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
                raise QualysPluginException(err_msg)
        self.logger.info(
            f"{self.log_prefix}: Successfully fetched {total_success}"
            f" tag(s) from {PLATFORM_NAME} platform."
        )
        return existing_tags

    def _create_tags(
        self, tags_to_create: List[str]
    ) -> Tuple[Dict[str, str], List[str]]:
        """Create tags on Qualys and return successfully created ones.

        Args:
            tags_to_create (List[str]): Tag names that do not already exist.

        Returns:
            Tuple[Dict[str, str], List[str]]: Mapping of newly created tag
                names to IDs and list of tags skipped due to length violations.
        """
        api_server_url, _, username, password, _, _ = (
            self.qualys_helper.get_configuration_parameters(self.configuration)
        )
        headers = self.qualys_helper.get_headers(
            access_token=None,
            request_response_type="json",
            x_requested_header=True,
        )
        url = CREATE_TAG_API_ENDPOINT.format(api_server_url=api_server_url)
        basic_auth = HTTPBasicAuth(username, password)
        created_tags = {}
        failed_to_create_tags = []
        long_tags = []
        for tag_name in tags_to_create:
            if len(tag_name) > TAG_NAME_LENGTH:
                long_tags.append(tag_name)
                continue
            request_body = {
                "ServiceRequest": {"data": {"Tag": [{"name": tag_name}]}}
            }
            logger_msg = (
                f"creating tag {tag_name} on {PLATFORM_NAME} platform"
            )
            try:
                response = self.qualys_helper.api_helper(
                    logger_msg=logger_msg,
                    url=url,
                    method="POST",
                    json=request_body,
                    headers=headers,
                    verify=self.ssl_validation,
                    proxies=self.proxy,
                    storage={},
                    configuration=self.configuration,
                    is_validation=False,
                    is_handle_error_required=True,
                    regenerate_access_token=False,
                    basic_auth=basic_auth,
                    response_format="json"
                )
                tag_id = (
                    response.get("ServiceResponse", {})
                    .get("data", [{}])[0]
                    .get("Tag", {})
                    .get("id")
                )
                if not tag_id:
                    self.logger.info(
                        f"{self.log_prefix}: Error occurred while "
                        f"{logger_msg}. Tag ID not found in response."
                    )
                    failed_to_create_tags.append(tag_name)
                    continue
                created_tags[tag_name] = str(tag_id)
            except QualysPluginException as err:
                err_msg = (
                    f"Error occurred while {logger_msg}. Error: {err}"
                )
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg}",
                )
                failed_to_create_tags.append(tag_name)
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
                failed_to_create_tags.append(tag_name)
                continue
        self.logger.info(
            message=(
                f"{self.log_prefix}: Successfully created"
                f" {len(created_tags)} tag(s) on"
                f" {PLATFORM_NAME} platform."
            ),
            details=f"Created Tag(s): {', '.join(created_tags.keys())}"
        )
        if failed_to_create_tags:
            self.logger.info(
                message=(
                    f"{self.log_prefix}: Failed to create"
                    f" {len(failed_to_create_tags)} tag(s) on"
                    f" {PLATFORM_NAME} platform. Failed tag(s) will be"
                    " skipped during the execution of the action."
                ),
                details=f"Failed tags: {', '.join(failed_to_create_tags)}",
            )
        return created_tags, long_tags
