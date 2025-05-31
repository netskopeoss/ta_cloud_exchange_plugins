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

Elastic plugin.
"""

import json
import traceback
from typing import Dict, List, Tuple
from jsonpath import jsonpath

from netskope.common.utils import AlertsHelper
from netskope.integrations.cls.plugin_base import (
    PluginBase,
    ValidationResult,
    PushResult,
)
from .utils.elastic_client import (
    ElasticClient,
)
from .utils.elastic_helper import (
    get_elastic_mappings,
)
from .utils.elastic_ecs_generator import (
    ECSGenerator,
)
from .utils.elastic_validator import (
    ElasticValidator,
)
from .utils.elastic_exceptions import (
    MappingValidationError,
    EmptyExtensionError,
    FieldNotFoundError,
    ElasticPluginException,
)
from .utils.elastic_constants import (
    MODULE_NAME,
    PLUGIN_NAME,
    PLUGIN_VERSION,
    PLATFORM_NAME,
    BATCH_SIZE,
)


class ElasticPlugin(PluginBase):
    """The Elastic plugin implementation class."""

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

    def _get_plugin_info(self) -> Tuple:
        """Get plugin name and version from manifest.

        Returns:
            tuple: Tuple of plugin's name and version pulled from manifest.
        """
        try:
            manifest_json = ElasticPlugin.metadata
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

    def test_server_connectivity(self, configuration: Dict):
        """Tests whether the configured server is reachable or not.

        Args:
            configuration (Dict): Configuration dictionary.
        """
        elastic_client = ElasticClient(
            configuration, self.logger, self.log_prefix
        )
        try:
            # Elastic Client
            elastic_client.get_socket(is_validation=True)
        except ElasticPluginException:
            raise
        except Exception as err:
            err_msg = (
                "Unable to establish connection with Elastic Server. "
                "Verify the Server Address and Server Port provided in the "
                "configuration parameters."
            )
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Validation error occurred, {err_msg}"
                    f"Error: {err}"
                ),
                details=str(traceback.format_exc()),
            )
            raise ElasticPluginException(err_msg)
        finally:
            elastic_client.close()

    def validate(self, configuration: Dict) -> ValidationResult:
        """Validate the configuration parameters dict.

        Args:
            configuration (Dict): Configuration parameters.

        Returns:
            ValidationResult: Validation result with flag and message.
        """
        ecs_validator = ElasticValidator(self.logger, self.log_prefix)
        validation_err_msg = f"{self.log_prefix}: Validation error occurred."
        server_address = configuration.get("server_address", "").strip()

        if not server_address:
            err_msg = "Server Address is a required configuration parameter."
            self.logger.error(f"{validation_err_msg} {err_msg}")
            return ValidationResult(success=False, message=err_msg)
        elif not isinstance(server_address, str):
            err_msg = (
                "Invalid Server Address provided in the "
                "configuration parameters."
            )
            self.logger.error(f"{validation_err_msg} {err_msg}")
            return ValidationResult(success=False, message=err_msg)

        server_port = configuration.get("server_port")

        if not server_port:
            err_msg = "Server Port is a required configuration parameter."
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            return ValidationResult(success=False, message=err_msg)
        elif not isinstance(
            server_port, int
        ) or not ecs_validator.validate_server_port(server_port):
            err_msg = (
                "Invalid Server Port provided in the configuration"
                " parameters. Server Port should be an integer in "
                "range 0 to 65535."
            )
            self.logger.error(f"{validation_err_msg} {err_msg}")
            return ValidationResult(success=False, message=err_msg)

        if server_address in ["127.0.0.1", "0.0.0.0"]:
            err_msg = (
                "Invalid Server Address provided in configuration"
                " parameters. If the elastic agent is deployed on the"
                " same machine as Cloud Exchange, use IP address "
                "of machine as the Server Address."
            )
            self.logger.error(f"{validation_err_msg} {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )

        mappings = self.mappings.get("jsonData", None)
        mappings = json.loads(mappings)
        if not isinstance(
            mappings, dict
        ) or not ecs_validator.validate_elastic_map(mappings):
            err_msg = (
                "Invalid attribute mapping found."
                " Verify the mapping file provided in Basic configuration."
            )
            self.logger.error(f"{validation_err_msg} {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )

        try:
            self.test_server_connectivity(configuration)
        except ElasticPluginException as exp:
            return ValidationResult(
                success=False,
                message=str(exp),
            )
        except Exception as exp:
            err_msg = (
                "Unable to establish connection with Elastic "
                "Server. Make sure you have provided correct "
                "Server Address and Server Port."
            )
            self.logger.error(
                message=f"{validation_err_msg} {err_msg} Error: {exp}",
                details=str(traceback.format_exc()),
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        self.logger.info(
            f"{self.log_prefix}: Successfully validated {PLUGIN_NAME}"
            " configuration."
        )
        return ValidationResult(success=True, message="Validation successful.")

    def push(self, transformed_data, data_type, subtype) -> PushResult:
        """Push the transformed_data to the 3rd party platform.

        Args:
            transformed_data (list): The transformed data to be ingested.
            data_type (str): The type of data to be ingested (alert/event)
            subtype (str): The subtype of data to be ingested (DLP,
            anomaly etc. in case of alerts)

        Returns:
            PushResult: Result indicating ingesting outcome and message
        """
        successful_log_push_counter, skipped_logs = 0, 0
        elastic_client = ElasticClient(
            self.configuration, self.logger, self.log_prefix
        )
        try:
            # Elastic Client
            elastic_client.get_socket()
            for i in range(0, len(transformed_data), BATCH_SIZE):
                try:
                    batch = transformed_data[i : i + BATCH_SIZE]  # noqa
                    payload = [
                        json.dumps(event) + "\n" for event in batch if event
                    ]
                    payload = "".join(payload)
                    elastic_client.push_data(payload)
                    successful_log_push_counter += len(batch)
                except Exception as err:
                    self.logger.error(
                        message=(
                            f"{self.log_prefix}: Error while sending data to"
                            f" {PLATFORM_NAME} server. Error: {err}"
                        ),
                        details=str(traceback.format_exc()),
                    )

            skipped_logs = len(transformed_data) - successful_log_push_counter

            if skipped_logs > 0:
                self.logger.debug(
                    f"{self.log_prefix}: Unable to send"
                    f" data for {skipped_logs} log(s) to {PLATFORM_NAME}"
                    " server as there might be empty data in it"
                    " or due to some other error occurred while ingesting."
                    " Hence ingestion of these log(s) will be skipped."
                )
            log_msg = (
                f"[{data_type}] [{subtype}] - "
                f"Successfully ingested {successful_log_push_counter} log(s)"
                f" to {PLATFORM_NAME} server."
            )
            self.logger.info(f"{self.log_prefix}: {log_msg}")
            return PushResult(
                success=True,
                message=log_msg,
            )
        except Exception as err:
            err_msg = "Error occurred during data ingestion."
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {err}.",
                details=str(traceback.format_exc()),
            )
            raise ElasticPluginException(err_msg)
        finally:
            elastic_client.close()

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
            else (None, False)
        )

    def get_subtype_mapping(self, mappings, subtype):
        """To Retrieve subtype mappings (mappings for subtypes of
        alerts/events) case insensitively.

        Args:
            mappings: Mapping JSON from which subtypes are to be retrieved
            subtype: Subtype (e.g. DLP for alerts) for which the mapping is
            to be fetched

        Returns:
            Fetched mapping JSON object
        """
        mappings = {k.lower(): v for k, v in mappings.items()}
        if subtype.lower() in mappings:
            return mappings[subtype.lower()]
        else:
            return mappings[subtype.upper()]

    def get_headers(self, header_mappings, data, data_type, subtype):
        """To Create a dictionary of ECS headers from given header mappings
        for given Netskope alert/event record.

        Args:
            subtype: Subtype for which the headers are being transformed
            data_type: Data type for which the headers are being transformed
            header_mappings: ECS header mapping with Netskope fields
            data: The alert/event for which the ECS header is being generated

        Returns:
            header dict
        """
        headers = {}
        mapping_variables = {}
        if data_type != "webtx":
            helper = AlertsHelper()
            tenant = helper.get_tenant_cls(self.source)
            mapping_variables = {"$tenant_name": tenant.name}

        missing_fields = []
        mapped_field_flag = False
        # Iterate over mapped headers
        for ecs_header, header_mapping in header_mappings.items():
            try:
                field_value, mapped_field = self.get_field_value_from_data(
                    header_mapping, data, data_type, subtype, False
                )
                if field_value is not None:
                    headers[ecs_header] = field_value

                if mapped_field:
                    mapped_field_flag = mapped_field

                # Handle variable mappings
                if (
                    isinstance(headers[ecs_header], str)
                    and headers[ecs_header].lower() in mapping_variables
                ):
                    headers[ecs_header] = mapping_variables[
                        headers[ecs_header].lower()
                    ]
            except FieldNotFoundError as err:
                missing_fields.append(str(err))

        return headers, mapped_field_flag

    def get_extensions(self, extension_mappings, data, data_type, subtype):
        """Fetch extensions from given mappings.

        Args:
            subtype: Subtype for which the headers are being transformed
            data_type: Data type for which the headers are being transformed
            extension_mappings: Mapping of extensions
            data: The data to be transformed

        Returns:
            extensions (dict)
        """
        extension = {}
        missing_fields = []
        mapped_field_flag = False

        # Iterate over mapped extensions
        for ecs_extension, extension_mapping in extension_mappings.items():
            try:

                field_value, mapped_field = self.get_field_value_from_data(
                    extension_mapping,
                    data,
                    data_type,
                    subtype,
                    is_json_path="is_json_path" in extension_mapping,
                )
                if field_value is not None:
                    extension[ecs_extension] = field_value
                if mapped_field:
                    mapped_field_flag = mapped_field
            except FieldNotFoundError as err:
                missing_fields.append(str(err))

        return extension, mapped_field_flag

    def get_field_value_from_data(
        self, extension_mapping, data, data_type, subtype, is_json_path=False
    ):
        """To Fetch the value of extension based on "mapping" and "default"
          fields.

        Args:
            extension_mapping: Dict containing "mapping" and "default" fields
            data: Data instance retrieved from Netskope
            subtype: Subtype for which the extension are being transformed
            data_type: Data type for which the headers are being transformed
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
                # mapped_field will be returned as true only if the value
                # returned is using the mapping_field and not default_value
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
                # If mapping is present in data, map that field, else skip by
                # raising exception
                if (
                    extension_mapping["mapping_field"] in data
                ):  # case #1 and case #4
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
                elif "default_value" in extension_mapping:
                    # If mapped value is not found in response and default is \
                    # mapped, map the default value (case #2)
                    return extension_mapping["default_value"], mapped_field
                else:  # case #6
                    raise FieldNotFoundError(
                        extension_mapping["mapping_field"]
                    )
        else:
            # If mapping is not present, 'default_value' must be there because
            # of validation (case #3 and case #5)
            return extension_mapping["default_value"], mapped_field

    def map_json_data(self, mappings, data):
        """Filter the raw data and returns the filtered data.

        Args:
            mappings (Dict): List of fields to be pushed.
            data: Data to be mapped (retrieved from Netskope).
            data_type: Logger object for logging purpose.
            subtype: Mapped data based on fields given in mapping file.

        Returns:
            mapped_dict (Dict): Mapped data.
        """

        if mappings == []:
            return data

        mapped_dict = {}
        for key in mappings:
            if key in data:
                mapped_dict[key] = data[key]

        return mapped_dict

    def transform(self, raw_data, data_type, subtype) -> List:
        """Transform the raw netskope JSON data into target platform supported
          data formats.

        Args:
            raw_data (list): The raw data to be transformed.
            data_type (str): The type of data to be ingested (alert/event)
            subtype (str): The subtype of data to be ingested (DLP, anomaly
              etc. in case of alerts)

        Raises:
            NotImplementedError: If the method is not implemented.

        Returns:
            List: list of transformed data.
        """
        count = 0
        transformed_data = []
        if not self.configuration.get("transformData", True):
            if data_type not in ["alerts", "events"]:
                return raw_data

            try:
                ecs_version, elastic_mappings = get_elastic_mappings(
                    self.mappings, "json"
                )
            except KeyError as err:
                err_msg = "An error occurred while fetching the mappings."
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg} Error: {err}",
                    details=str(traceback.format_exc()),
                )
                raise ElasticPluginException(err_msg)
            except MappingValidationError as err:
                err_msg = (
                    "An error occurred while validating the mapping file."
                )
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg} {err}",
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
                    elastic_mappings["json"][data_type], subtype
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

            for data in raw_data:
                mapped_dict = self.map_json_data(subtype_mapping, data)
                if mapped_dict:
                    transformed_data.append(mapped_dict)
                else:
                    count += 1

        else:
            try:
                ecs_version, elastic_mappings = get_elastic_mappings(
                    self.mappings, data_type
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
                        f"{self.log_prefix}: An error occurred while"
                        f" validating the mapping file. {err}"
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

            ecs_generator = ECSGenerator(
                self.mappings,
                ecs_version,
                self.logger,
                self.log_prefix,
            )

            # First retrieve the mapping of subtype being transformed
            try:
                subtype_mapping = self.get_subtype_mapping(
                    elastic_mappings[data_type], subtype
                )
            except KeyError:
                self.logger.info(
                    f"{self.log_prefix}: Unable to find the mapping for "
                    f"[{data_type}] [{subtype}] in the mapping file, "
                    "Transformation of current batch will be skipped."
                )
                return []
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

            for data in raw_data:
                # First retrieve the mapping of subtype being transformed
                if not data:
                    count += 1
                    continue

                # Generating the ECS header
                try:
                    header, mapped_flag_header = self.get_headers(
                        subtype_mapping["header"], data, data_type, subtype
                    )
                except Exception as err:
                    self.logger.error(
                        message=(
                            f"{self.log_prefix}: [{data_type}][{subtype}] - "
                            f"Error occurred while creating CEF header: {err}."
                            " Transformation of current record will "
                            "be skipped."
                        ),
                        details=str(traceback.format_exc()),
                    )
                    count += 1
                    continue

                try:
                    extension, mapped_flag_extension = self.get_extensions(
                        subtype_mapping["extension"], data, data_type, subtype
                    )
                except Exception as err:
                    self.logger.error(
                        message=(
                            f"{self.log_prefix}: [{data_type}][{subtype}] - "
                            "Error occurred while creating CEF extension: "
                            f"{err}. Transformation of the current record "
                            "will be skipped."
                        ),
                        details=str(traceback.format_exc()),
                    )
                    count += 1
                    continue

                try:
                    if not (mapped_flag_header or mapped_flag_extension):
                        count += 1
                        continue
                    ecs_generated_event = ecs_generator.get_ecs_event(
                        header, extension, data_type, subtype
                    )
                    if ecs_generated_event:
                        transformed_data.append(ecs_generated_event)

                except EmptyExtensionError:
                    self.logger.error(
                        message=(
                            f"{self.log_prefix}: [{data_type}][{subtype}] - "
                            "Got empty extension during transformation. "
                            "Transformation of current record will be skipped."
                        ),
                        details=str(traceback.format_exc()),
                    )
                    count += 1
                except Exception as err:
                    self.logger.error(
                        message=(
                            f"{self.log_prefix}: [{data_type}][{subtype}] - An"
                            f" error occurred during transformation. "
                            f"Error: {err}"
                        ),
                        details=str(traceback.format_exc()),
                    )
                    count += 1

        if count > 0:
            self.logger.debug(
                f"{self.log_prefix}: Plugin couldn't process "
                f"{count} records because they either had no data or "
                "contained invalid/missing fields according to the "
                "configured mapping. Therefore, the transformation "
                "and ingestion for those records were skipped."
            )
        return transformed_data
