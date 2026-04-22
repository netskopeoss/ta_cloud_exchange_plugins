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

Microsoft Azure Monitor Plugin."""

import datetime
import traceback
import json
import sys
from typing import Dict, List, Tuple, Union
from jsonpath import jsonpath
from packaging import version

from netskope.common.api import __version__ as CE_VERSION
from netskope.integrations.cls.plugin_base import (
    PluginBase,
    ValidationResult,
    PushResult
)
from netskope.common.utils import AlertsHelper
from .utils.monitor_cef_generator import CEFGenerator
from .utils.monitor_validator import AzureMonitorValidator
from .utils.monitor_client import AzureMonitorClient
from .utils.monitor_helper import (
    validate_monitor_mappings,
    get_monitor_mappings,
    split_into_size
)
from .utils.monitor_exceptions import (
    FieldNotFoundError,
    MicrosoftAzureMonitorPluginException,
    MappingValidationError,
    EmptyExtensionError,
)
from .utils.monitor_constants import (
    PLUGIN_NAME,
    PLUGIN_VERSION,
    MODULE_NAME,
    PUSH_DATA_ENDPOINT,
    VALIDATION_ERROR_MSG,
    MAXIMUM_CE_VERSION,
)


class AzureMonitorPlugin(PluginBase):
    """The Microsoft Azure Monitor CLS plugin implementation class."""

    def __init__(
        self,
        name,
        *args,
        **kwargs,
    ):
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

    def _get_plugin_info(self) -> tuple:
        """Get plugin name and version from manifest.

        Returns:
            tuple: Tuple of plugin's name and version fetched from manifest.
        """
        try:
            manifest_json = AzureMonitorPlugin.metadata
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

    @staticmethod
    def get_subtype_mapping(mappings, subtype):
        """Retrieve subtype mappings (mappings for subtypes of alerts/events) \
            case insensitively.

        :param mappings: Mapping JSON from which subtypes are to be retrieved
        :param subtype: Subtype (e.g. DLP for alerts) for which \
            the mapping is to be fetched
        :return: Fetched mapping JSON object
        """
        mappings = {k.lower(): v for k, v in mappings.items()}
        if subtype.lower() in mappings:
            return mappings[subtype.lower()]
        else:
            return mappings[subtype.upper()]

    def push(self, transformed_data, data_type, subtype) -> PushResult:
        """Transform and ingests the given data chunks to \
            Microsoft Azure Monitor.

        :param data_type: The type of data being pushed.
         Current possible values: alerts, events and webtx
        :param transformed_data: Transformed data to be ingested to
        Microsoft Azure Monitor in chunks
        :param subtype: The subtype of data being pushed.
        E.g. subtypes of alert is "dlp", "policy" etc.
        """
        try:
            batch_size = sys.getsizeof(f"{transformed_data}") / (1024 * 1024)
            if batch_size > 1:
                transformed_data = split_into_size(transformed_data)
            else:
                transformed_data = [transformed_data]

            monitor_client = AzureMonitorClient(
                logger=self.logger,
                log_prefix=self.log_prefix,
                plugin_name=self.plugin_name,
                plugin_version=self.plugin_version,
                verify_ssl=self.ssl_validation,
                proxy=self.proxy,
            )

            (
                tenant_id,
                app_id,
                app_secret,
                dce_uri,
                dcr_immutable_id,
                custom_log_table_name,
                _,
            ) = monitor_client.get_configuration_parameters(self.configuration)

            auth_header, storage = self.get_access_token_and_storage(
                tenant_id=tenant_id,
                app_id=app_id,
                app_secret=app_secret,
                dce_uri=dce_uri,
                dcr_immutable_id=dcr_immutable_id,
                custom_log_table_name=custom_log_table_name,
                monitor_client=monitor_client,
            )

            url_endpoint = PUSH_DATA_ENDPOINT.format(
                dce_uri=dce_uri,
                dcr_immutable_id=dcr_immutable_id,
                custom_log_table_name=custom_log_table_name,
            )

            skipped_count = 0
            total_count = 0
            page = 0

            for chunk in transformed_data:
                page += 1
                try:
                    logger_msg = (
                        f"ingesting data to {PLUGIN_NAME} for page {page}"
                    )
                    monitor_client.api_helper(
                        logger_msg=logger_msg,
                        url=url_endpoint,
                        method="POST",
                        data=json.dumps(chunk),
                        headers=auth_header,
                        verify=self.ssl_validation,
                        proxies=self.proxy,
                        configuration=self.configuration,
                        storage=storage,
                    )
                    log_msg = (
                        f"[{data_type}][{subtype}] Successfully ingested "
                        f"{len(chunk)} {data_type} for page {page} "
                        f"to {PLUGIN_NAME}."
                    )
                    self.logger.info(f"{self.log_prefix}: {log_msg}")
                    total_count += len(chunk)
                except Exception as err:
                    self.logger.error(
                        message=(
                            f"{self.log_prefix}: [{data_type}][{subtype}] "
                            f"Error occurred while ingesting data. "
                            f"Error: {err}"
                        ),
                        details=str(traceback.format_exc()),
                    )
                    skipped_count += len(chunk)
                    continue
            if skipped_count > 0:
                self.logger.info(
                    f"{self.log_prefix}: Skipped {skipped_count} records "
                    "due to some unexpected error occurred, "
                    "check logs for more details."
                )

            log_msg = (
                f"[{data_type}][{subtype}] Successfully ingested "
                f"{total_count} {data_type} to {PLUGIN_NAME}."
            )
            self.logger.info(f"{self.log_prefix}: {log_msg}")
            return PushResult(
                success=True,
                message=log_msg,
            )
        except MicrosoftAzureMonitorPluginException as err:
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Error occurred while ingesting "
                    f"[{data_type}][{subtype}]. Error: {err}"
                ),
                details=str(traceback.format_exc()),
            )
            raise err
        except Exception as err:
            # Raise this exception from here so that it does not update
            # the checkpoint, as this means data ingestion is failed
            # even after a few retries.
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Error occurred while ingesting "
                    f"[{data_type}][{subtype}]. Error: {err}"
                ),
                details=str(traceback.format_exc()),
            )
            raise err

    def get_mapping_value_from_json_path(self, data, json_path):
        """To Fetch the value from given JSON object using given JSON path.

        Args:
            data: JSON object from which the value is to be fetched
            json_path: JSON path indicating the path of the value in given JSON

        Returns:
            fetched value.
        """
        return jsonpath(data, json_path)

    def get_mapping_value_from_field(self, data, field):
        """To Fetch the value from given field.

        Args:
            data: JSON object from which the value is to be fetched
            field: Field whose value is to be fetched

        Returns:
            fetched value.
        """
        return (
            (data[field], True)
            if data[field] or isinstance(data[field], int)
            else ("null", False)
        )

    def get_extensions(self, extension_mappings, data):
        """Fetch extensions from given mappings.

        Args:
            extension_mappings: Mapping of extensions
            data: The data to be transformed

        Returns:
            extensions (dict)
        """
        extension = {}
        missing_fields = []
        mapped_field_flag = False
        # Iterate over mapped extensions
        for cef_extension, extension_mapping in extension_mappings.items():
            try:
                (
                    extension[cef_extension],
                    mapped_field,
                ) = self.get_field_value_from_data(
                    extension_mapping,
                    data,
                    is_json_path="is_json_path" in extension_mapping,
                )
                if mapped_field:
                    mapped_field_flag = mapped_field
            except (Exception, FieldNotFoundError) as err:
                missing_fields.append(str(err))
        return extension, mapped_field_flag

    def get_headers(self, header_mappings, data, data_type):
        """To Create a dictionary of CEF headers from \
            given header mappings for given Netskope alert/event record.

        Args:
            data_type: Data type for which the headers are being transformed
            header_mappings: CEF header mapping with Netskope fields
            data: The alert/event for which the CEF header is being generated

        Returns:
            header dict
        """
        headers = {}
        mapping_variables = {}
        if data_type != "webtx":
            if not hasattr(self, "tenant"):
                helper = AlertsHelper()
                self.tenant = helper.get_tenant_cls(self.source)
            mapping_variables = {"$tenant_name": self.tenant.name}

        missing_fields = []
        mapped_field_flag = False
        # Iterate over mapped headers
        for cef_header, header_mapping in header_mappings.items():
            try:
                (
                    headers[cef_header], mapped_field,
                ) = self.get_field_value_from_data(
                    header_mapping, data, False
                )
                if mapped_field:
                    mapped_field_flag = mapped_field

                # Handle variable mappings
                if (
                    isinstance(headers[cef_header], str)
                    and headers[cef_header].lower() in mapping_variables
                ):
                    headers[cef_header] = mapping_variables[
                        headers[cef_header].lower()
                    ]
            except FieldNotFoundError as err:
                missing_fields.append(str(err))

        return headers, mapped_field_flag

    def get_nested_field_value(self, data, field_path):
        """Extract value from nested dictionary using dot notation.

        Args:
            data: The data dictionary
            field_path: Dot-separated field path \
                (e.g., 'host_info.device_make')

        Returns:
            tuple: (value, exists) where exists is True if field was found
        """

        try:
            current_data = data
            field_parts = field_path.split('.')

            for i, part in enumerate(field_parts):

                if isinstance(current_data, dict) and part in current_data:
                    current_data = current_data[part]
                else:
                    return None, False

            return current_data, True

        except Exception as exp:
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Error occurred while"
                    f" getting nested field value. Error: {exp}"
                ),
                details=str(traceback.format_exc()),
            )
            return None, False

    def get_field_value_from_data(
        self,
        extension_mapping,
        data,
        is_json_path=False
    ) -> Tuple[Union[str, int], bool]:
        """To Fetch the value of extension based on \
            "mapping" and "default" fields.

        Args:
            extension_mapping: Dict containing "mapping" and "default" fields
            data: Data instance retrieved from Netskope
            is_json_path: Whether the mapped value is JSON path or direct
            field name

        Returns:
            Fetched values of extension

        ---------------------------------------------------------------------
             Mapping          |    Response    |    Retrieved Value
        ----------------------|                |
        default  |  Mapping   |                |
        ---------------------------------------------------------------------
           P     |     P      |        P       |           Mapped
           P     |     P      |        NP      |           Default
           P     |     NP     |        P       |           Default
           NP    |     P      |        P       |           Mapped
           P     |     NP     |        NP      |           Default
           NP    |     P      |        NP      |           -
           NP    |     NP     |        P       |           - (Not possible)
           NP    |     NP     |        NP      |           - (Not possible)
        -----------------------------------------------------------------------
        """
        mapped_field = False
        if (
            "mapping_field" in extension_mapping
            and extension_mapping["mapping_field"]
        ):
            if is_json_path:
                # If mapping field specified by JSON path is present in data,
                # map that field, else skip by raising exception:
                value = self.get_mapping_value_from_json_path(
                    data, extension_mapping["mapping_field"]
                )
                if value:
                    mapped_field = True
                    return ",".join([str(val) for val in value]), mapped_field
                else:
                    raise FieldNotFoundError(
                        extension_mapping["mapping_field"]
                    )
            else:
                # If mapping is present in data, map that field,
                # else skip by raising exception
                if extension_mapping["mapping_field"] in data:  # case #1 and case #4  # noqa
                    if (
                        extension_mapping.get("transformation") == "Time Stamp"
                        and data[extension_mapping["mapping_field"]]
                    ):
                        try:
                            mapped_field = True
                            return (
                                int(data[extension_mapping["mapping_field"]]),
                                mapped_field,
                            )
                        except Exception:
                            pass
                    return self.get_mapping_value_from_field(
                        data, extension_mapping["mapping_field"]
                    )
                else:
                    # Try nested field access using dot notation
                    nested_value, field_exists = self.get_nested_field_value(
                        data, extension_mapping["mapping_field"]
                    )

                    if field_exists:
                        if (
                            extension_mapping.get("transformation") == "Time Stamp"  # noqa
                            and nested_value
                        ):
                            try:
                                mapped_field = True
                                timestamp_value = int(nested_value)
                                return timestamp_value, mapped_field
                            except Exception:
                                pass

                        mapped_field = True
                        final_result = (
                            (nested_value, True)
                            if nested_value or isinstance(nested_value, int)
                            else ("null", False)
                        )
                        return final_result
                    elif "default_value" in extension_mapping:
                        # If mapped value is not found in response and
                        # default is mapped, map the default value (case #2)
                        return extension_mapping["default_value"], mapped_field
                    else:  # case #6
                        raise FieldNotFoundError(
                            extension_mapping["mapping_field"]
                        )
        else:
            # If mapping is not present, 'default_value' must be there
            # because of validation (case #3 and case #5)
            return extension_mapping["default_value"], mapped_field

    def map_json_data(self, mappings, data):
        """Filter the raw data and returns the filtered data.

        :param mappings: List of fields to be pushed
        :param data: Data to be mapped (retrieved from Netskope)
        :param logger: Logger object for logging purpose
        :return: Mapped data based on fields given in mapping file
        """
        if mappings == []:
            return data

        mapped_dict = {}
        data_keys = data.keys()
        for key in mappings:
            if key in data_keys:
                mapped_dict[key] = data[key]
            else:
                (
                    value,
                    field_exist
                ) = self.get_nested_field_value(data, key)
                if field_exist:
                    mapped_dict[key] = value
        return mapped_dict

    def transform(self, raw_data, data_type, subtype) -> List:
        """To Transform the raw netskope JSON data into \
            target platform supported data formats."""

        skip_count = 0
        log_source_identifier = self.configuration.get(
            "log_source_identifier", "Netskope CE"
        )
        transform_data_json = False
        if version.parse(CE_VERSION) <= version.parse(MAXIMUM_CE_VERSION):
            if not self.configuration.get("transformData", True):
                transform_data_json = True
        else:
            if self.configuration.get("transformData", "json") == "json":
                transform_data_json = True
        if transform_data_json:
            formatted_raw_data = []
            if data_type not in ["alerts", "events"]:
                for data in raw_data:
                    formatted_raw_data.append(
                        {
                            "RawData": data,
                            "Application": log_source_identifier,
                            "DataType": data_type,
                            "SubType": subtype,
                            "TimeGenerated": f"{datetime.datetime.now()}",
                        }
                    )
                return formatted_raw_data

            try:
                if (
                    version.parse(CE_VERSION) <=
                    version.parse(MAXIMUM_CE_VERSION)
                ):
                    validate_monitor_mappings(
                        self.mappings,
                        data_type,
                    )
                (
                    delimiter,
                    cef_version,
                    monitor_mappings,
                ) = get_monitor_mappings(
                    self.mappings
                )
            except KeyError as err:
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: An error occurred while fetching "
                        f"the mappings. Error: {err}"
                    ),
                    details=str(traceback.format_exc()),
                )
                raise
            except MappingValidationError as err:
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: An error occurred while "
                        f"validating the mapping file. {str(err)}"
                    ),
                    details=str(traceback.format_exc()),
                )
                raise
            except Exception as err:
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: An error occurred while mapping "
                        f"data using given json mappings. Error: {err}"
                    ),
                    details=str(traceback.format_exc()),
                )
                raise

            try:
                subtype_mapping = self.get_subtype_mapping(
                    monitor_mappings["json"][data_type], subtype
                )
            except Exception:
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: Error occurred while retrieving "
                        f"mappings for datatype: {data_type} "
                        f"(subtype: {subtype}) Transformation will be skipped."
                    ),
                    details=str(traceback.format_exc()),
                )
                raise

            formatted_transformed_data = []
            for data in raw_data:
                mapped_dict = self.map_json_data(subtype_mapping, data)
                if mapped_dict:
                    formatted_transformed_data.append(
                        {
                            "RawData": mapped_dict,
                            "Application": log_source_identifier,
                            "DataType": data_type,
                            "SubType": subtype,
                            "TimeGenerated": f"{datetime.datetime.now()}",
                        }
                    )
                else:
                    skip_count += 1
            if skip_count > 0:
                self.logger.debug(
                    "{}: Plugin couldn't process {} records because they "
                    "either had no data or contained invalid/missing "
                    "fields according to the configured JSON mapping. "
                    "Therefore, the transformation and ingestion for those "
                    "records were skipped.".format(self.log_prefix, skip_count)
                )
            return formatted_transformed_data

        else:
            try:
                if (
                    version.parse(CE_VERSION) <=
                    version.parse(MAXIMUM_CE_VERSION)
                ):
                    validate_monitor_mappings(
                        self.mappings,
                        data_type,
                    )
                (
                    delimiter, cef_version, monitor_mappings,
                ) = get_monitor_mappings(
                    self.mappings
                )
            except KeyError as err:
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: An error occurred while "
                        f"fetching the mappings. Error: {err}"
                    ),
                    details=str(traceback.format_exc()),
                )
                raise
            except MappingValidationError as err:
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: An error occurred while "
                        f"validating the mapping file. {err}"
                    ),
                    details=str(traceback.format_exc()),
                )
                raise
            except Exception as err:
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: An error occurred while mapping "
                        f"data using given json mappings. Error: {err}"
                    ),
                    details=str(traceback.format_exc()),
                )
                raise

            cef_generator = CEFGenerator(
                self.mappings,
                delimiter,
                cef_version,
                self.logger,
                self.log_prefix
            )

            try:
                subtype_mapping = self.get_subtype_mapping(
                    monitor_mappings[data_type], subtype
                )
            except Exception:
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: Error occurred while retrieving "
                        f"mappings for subtype {subtype}. "
                        "Transformation of current batch will be skipped."
                    ),
                    details=str(traceback.format_exc()),
                )
                return []
            transformed_data = []
            for data in raw_data:
                if not data:
                    skip_count += 1
                    continue
                # Generating the CEF header
                try:
                    header, mapped_flag_header = self.get_headers(
                        subtype_mapping["header"], data, data_type
                    )
                except Exception as err:
                    self.logger.error(
                        message=(
                            f"{self.log_prefix}: [{data_type}][{subtype}]- "
                            f"Error occurred while creating CEF header: {err}. "  # noqa
                            "Transformation of current record will be skipped."  # noqa
                        ),
                        details=str(traceback.format_exc()),
                    )
                    skip_count += 1
                    continue

                try:
                    extension, mapped_flag_extension = self.get_extensions(
                        subtype_mapping["extension"], data
                    )
                except Exception as err:
                    self.logger.error(
                        message=(
                            f"{self.log_prefix}: [{data_type}][{subtype}]- "
                            f"Error occurred while creating CEF extension: {err}. "  # noqa
                            "Transformation of the current record will be skipped."  # noqa
                        ),
                        details=str(traceback.format_exc()),
                    )
                    skip_count += 1
                    continue

                try:
                    if not (mapped_flag_header or mapped_flag_extension):
                        skip_count += 1
                        continue
                    cef_generated_event = cef_generator.get_cef_event(
                        data, header, extension, data_type, subtype
                    )
                    if cef_generated_event:
                        transformed_data.append(
                            {
                                "RawData": cef_generated_event,
                                "Application": log_source_identifier,
                                "DataType": data_type,
                                "SubType": subtype,
                                "TimeGenerated": f"{datetime.datetime.now()}",
                            }
                        )

                except EmptyExtensionError:
                    self.logger.error(
                        message=(
                            f"{self.log_prefix}: [{data_type}][{subtype}]- Got"
                            " empty extension during transformation. "
                            "Transformation of current record will be skipped."
                        ),
                        details=str(traceback.format_exc()),
                    )
                    skip_count += 1
                except Exception as err:
                    self.logger.error(
                        message=(
                            f"{self.log_prefix}: [{data_type}][{subtype}]- An "
                            f"error occurred during transformation. Error: {err}"  # noqa
                        ),
                        details=str(traceback.format_exc()),
                    )
                    skip_count += 1

            if skip_count > 0:
                self.logger.debug(
                    "{}: Plugin couldn't process {} records because they "
                    "either had no data or contained invalid/missing "
                    "fields according to the configured mapping. "
                    "Therefore, the transformation and ingestion for those "
                    "records were skipped.".format(self.log_prefix, skip_count)
                )

        return transformed_data

    def _get_storage(self) -> Dict:
        """Get storage object.

        Returns:
            Dict: Storage object.
        """
        storage = self.storage if self.storage is not None else {}
        return storage

    def get_access_token_and_storage(
        self,
        tenant_id: str,
        app_id: str,
        app_secret: str,
        dce_uri: str,
        dcr_immutable_id: str,
        custom_log_table_name: str,
        monitor_client: AzureMonitorClient,
        is_validation: bool = False
    ) -> Tuple[Dict, Dict]:
        """
        Get authentication header and storage.

        Args:
            tenant_id (str): Tenant ID.
            app_id (str): App ID.
            app_secret (str): App secret.
            dce_uri (str): DCE URI.
            dcr_immutable_id (str): DCR Immutable ID.
            custom_log_table_name (str): Custom log table name.
            monitor_client (AzureMonitorClient): Monitor client.
            is_validation (bool, optional): Is validation. Defaults to False.

        Returns:
            Tuple[Dict, Dict]: Authentication header and storage.
        """
        storage = self._get_storage()
        auth_header = storage.get("auth_header")
        stored_config_hash = storage.get("config_hash")

        current_config_hash = monitor_client.hash_string(
            string=(
                f"{tenant_id}{app_id}{app_secret}"
                f"{dce_uri}{dcr_immutable_id}{custom_log_table_name}"
            )
        )
        if auth_header and stored_config_hash == current_config_hash:
            return auth_header, storage
        else:
            auth_header = monitor_client.generate_auth_token(
                tenant_id=tenant_id,
                app_id=app_id,
                app_secret=app_secret,
                is_validation=is_validation,
            )
            storage.update(
                {
                    "auth_header": auth_header,
                    "config_hash": current_config_hash,
                }
            )
            return auth_header, storage

    def _validate_parameters(
        self,
        field_name: str,
        field_value: Union[str, List, bool, int],
        field_type: type,
        is_required: bool = True,
    ) -> Union[ValidationResult, None]:
        """
        Validate the given configuration field value.

        Args:
            field_name (str): Name of the configuration field.
            field_value (str, List, bool, int): Value of the configuration
                field.
            field_type (type): Expected type of the configuration field.
            max_value (int, optional): Maximum value for the configuration
                field. Defaults to None.
            min_value (int, optional): Minimum value for the configuration
                field. Defaults to None.
            is_required (bool, optional): Whether the field is required.
                Defaults to True.
            check_dollar (bool, optional): Whether to check for the dollar
                sign in the field value. Defaults to False.
            is_source_field_allowed (bool, optional): Whether the source field
                is allowed. Defaults to True.

        Returns:
            ValidationResult: ValidationResult object indicating whether the
                validation was successful or not.
        """
        if field_type is str and isinstance(field_value, str):
            field_value = field_value.strip()
        if (
            is_required and
            not isinstance(field_value, int) and
            not field_value
        ):
            err_msg = (
                f"'{field_name}' is a required configuration parameter."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {VALIDATION_ERROR_MSG}{err_msg}",
                resolution=(
                    f"Ensure that {field_name} field value is provided."
                ),
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        if not isinstance(field_value, field_type):
            err_msg = (
                f"Invalid value provided for the configuration "
                f"parameter '{field_name}'."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {VALIDATION_ERROR_MSG}{err_msg}",
                resolution=(
                    f"Ensure that {field_name} field value is valid."
                ),
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )

    def _validate_connectivity(
        self,
        configuration: Dict,
        tenant_id: str,
        app_id: str,
        app_secret: str,
        dce_uri: str,
        dcr_immutable_id: str,
        custom_log_table_name: str,
        monitor_client: AzureMonitorClient,
    ) -> ValidationResult:
        """
        Validate connectivity to Microsoft Azure Monitor.

        Args:
            configuration (Dict): Configuration.
            tenant_id (str): Tenant ID.
            app_id (str): App ID.
            app_secret (str): App secret.
            dce_uri (str): DCE URI.
            dcr_immutable_id (str): DCR Immutable ID.
            custom_log_table_name (str): Custom log table name.
            monitor_client (AzureMonitorClient): Monitor client.

        Returns:
            ValidationResult: ValidationResult object indicating whether \
                the connectivity was successful or not.
        """
        self.logger.debug(
            f"{self.log_prefix}: Validating credentials "
            f"for {PLUGIN_NAME} platform."
        )
        try:
            auth_header, storage = self.get_access_token_and_storage(
                tenant_id=tenant_id,
                app_id=app_id,
                app_secret=app_secret,
                dce_uri=dce_uri,
                dcr_immutable_id=dcr_immutable_id,
                custom_log_table_name=custom_log_table_name,
                monitor_client=monitor_client,
                is_validation=True,
            )

            url_endpoint = PUSH_DATA_ENDPOINT.format(
                dce_uri=dce_uri,
                dcr_immutable_id=dcr_immutable_id,
                custom_log_table_name=custom_log_table_name,
            )
            monitor_client.api_helper(
                logger_msg="validating credentials",
                url=url_endpoint,
                method="POST",
                data=json.dumps([]),
                headers=auth_header,
                verify=self.ssl_validation,
                proxies=self.proxy,
                configuration=configuration,
                storage=storage,
                is_validation=True,
            )
            logger_msg = (
                "Successfully validated "
                f"credentials for {PLUGIN_NAME} platform."
            )
            self.logger.debug(
                f"{self.log_prefix}: {logger_msg}"
            )
            return ValidationResult(
                success=True, message=logger_msg,
            )
        except MicrosoftAzureMonitorPluginException as exp:
            err_msg = f"Validation error occurred. Error: {exp}"
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=str(traceback.format_exc()),
            )
            return ValidationResult(
                success=False,
                message=f"{str(exp)} Check logs for more details."
            )
        except Exception as exp:
            err_msg = "Unexpected validation error occurred."
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {exp}",
                details=str(traceback.format_exc()),
            )
            return ValidationResult(
                success=False,
                message=f"{err_msg} Check logs for more details.",
            )

    def validate_mappings(self):
        """Validate the Microsoft Azure Monitor mappings for all data type.

        Raises:
            MappingValidationError: When validation fails for \
                any of the configured data_type.
        """
        validation_err_msg = (
            f"{self.log_prefix}: Mapping validation error occurred."
        )
        err_msg = "Invalid attribute mapping provided."
        monitor_validator = AzureMonitorValidator(self.logger, self.log_prefix)

        def _validate_json_data(json_string):
            """Validate that the jsonData should not be empty."""
            try:
                json_object = json.loads(json_string)
                if not bool(json_object):
                    raise ValueError("JSON data should not be empty.")
            except json.decoder.JSONDecodeError as e:
                raise ValueError(f"Invalid JSON: {e}")
            except Exception as e:
                raise ValueError(f"Error occurred while validating JSON: {e}.")
            return json_object

        try:
            mappings = _validate_json_data(self.mappings.get("jsonData"))
        except Exception as err:
            return ValidationResult(
                success=False,
                message=str(err),
            )

        if (
            not isinstance(mappings, dict)
            or not monitor_validator.validate_monitor_map(mappings)
        ):
            self.logger.error(f"{validation_err_msg} {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )

        for data_type in mappings.get("taxonomy", {}).keys():
            try:
                self.logger.info(
                    message=(
                        f"{self.log_prefix}: Validating the mappings for "
                        f"monitor {data_type}."
                    )
                )
                validate_monitor_mappings(mappings, data_type)
            except MappingValidationError as mapping_validation_error:
                self.logger.error(
                    message=(
                        f"{validation_err_msg} {err_msg} Error: "
                        f"{mapping_validation_error}"
                    ),
                    details=str(traceback.format_exc()),
                )
                return ValidationResult(
                    success=False,
                    message=err_msg,
                )

        return ValidationResult(
            success=True,
            message="Mappings validation successful.",
        )

    def validate(self, configuration: dict) -> ValidationResult:
        """Validate the configuration parameters dict.

        Args:
            configuration (dict): Configuration parameters.

        Returns:
            ValidationResult: ValidationResult object indicating whether the
                validation was successful or not.
        """
        monitor_client = AzureMonitorClient(
            logger=self.logger,
            log_prefix=self.log_prefix,
            plugin_name=self.plugin_name,
            plugin_version=self.plugin_version,
            verify_ssl=self.ssl_validation,
            proxy=self.proxy,
        )

        (
            tenant_id,
            app_id,
            app_secret,
            dce_uri,
            dcr_immutable_id,
            custom_log_table_name,
            log_source_identifier,
        ) = monitor_client.get_configuration_parameters(configuration)

        # Validate Directory (tenant) ID
        if validation_result := self._validate_parameters(
            field_name="Directory (tenant) ID",
            field_value=tenant_id,
            field_type=str,
        ):
            return validation_result

        # Validate Application (client) ID
        if validation_result := self._validate_parameters(
            field_name="Application (client) ID",
            field_value=app_id,
            field_type=str,
        ):
            return validation_result

        # Validate Client Secret
        if validation_result := self._validate_parameters(
            field_name="Client Secret",
            field_value=app_secret,
            field_type=str,
        ):
            return validation_result

        # Validate DCE URI
        if validation_result := self._validate_parameters(
            field_name="DCE URI",
            field_value=dce_uri,
            field_type=str,
        ):
            return validation_result

        # Validate DCR Immutable ID
        if validation_result := self._validate_parameters(
            field_name="DCR Immutable ID",
            field_value=dcr_immutable_id,
            field_type=str,
        ):
            return validation_result

        # Validate Custom Log Table Name
        if validation_result := self._validate_parameters(
            field_name="Custom Log Table Name",
            field_value=custom_log_table_name,
            field_type=str,
        ):
            return validation_result

        # Validate Log Source Identifier
        if validation_result := self._validate_parameters(
            field_name="Log Source Identifier",
            field_value=log_source_identifier,
            field_type=str,
        ):
            return validation_result

        # Validate Mapping
        mappings_validation_result = self.validate_mappings()
        if not mappings_validation_result.success:
            return mappings_validation_result

        # Validate Connectivity
        connectivity_validation_result = self._validate_connectivity(
            configuration=configuration,
            tenant_id=tenant_id,
            app_id=app_id,
            app_secret=app_secret,
            dce_uri=dce_uri,
            dcr_immutable_id=dcr_immutable_id,
            custom_log_table_name=custom_log_table_name,
            monitor_client=monitor_client,
        )

        return connectivity_validation_result
