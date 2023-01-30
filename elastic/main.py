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
"""

"""Elastic plugin."""


import json
from typing import List
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
)


class ElasticPlugin(PluginBase):
    """The Elastic plugin implementation class."""

    def test_server_connectivity(self, configuration):
        """Tests whether the configured server is reachable or not."""
        elastic_client = ElasticClient(configuration, self.logger)
        try:
            # Elastic Client
            elastic_client.get_socket()
        except Exception as e:
            self.logger.error(
                f"Elastic Plugin: Validation error occurred. "
                f"While establishing connection with server: {e}."
            )
            raise e
        finally:
            elastic_client.close()

    def validate(self, configuration: dict) -> ValidationResult:
        """Validate the configuration parameters dict."""
        ecs_validator = ElasticValidator(self.logger)

        if (
            "server_address" not in configuration
            or type(configuration["server_address"]) != str
            or not configuration["server_address"].strip()
        ):
            self.logger.error(
                "Elastic Plugin: Validation error occurred. Error: "
                "Invalid Server Address found in the configuration parameters."
            )
            return ValidationResult(
                success=False, message="Invalid Server Address provided."
            )

        if (
            "server_port" not in configuration
            or not configuration["server_port"]
            or not ecs_validator.validate_server_port(
                configuration["server_port"]
            )
        ):
            self.logger.error(
                "Elastic Plugin: Validation error occurred. Error: "
                "Invalid Server port found in the configuration parameters."
            )
            return ValidationResult(
                success=False, message="Invalid Server port provided."
            )
        server_address = configuration["server_address"].strip()
        if server_address in ["127.0.0.1", "0.0.0.0"]:
            self.logger.error(
                "Elastic Plugin: Validation error occurred. Error: "
                "Invalid Server Address found in the configuration parameters."
            )
            return ValidationResult(
                success=False,
                message="Invalid Server Address provided. If the elastic"
                " agent is deployed on the same machine as CE,"
                " use IP address of machine as the Server Address.",
            )

        mappings = self.mappings.get("jsonData", None)
        mappings = json.loads(mappings)
        if type(mappings) != dict or not ecs_validator.validate_elastic_map(
            mappings
        ):
            self.logger.error(
                "Elastic Plugin: Validation error occurred. Error: "
                "Invalid Elastic attribute mapping found in the configuration parameters."
            )
            return ValidationResult(
                success=False,
                message="Invalid Elastic attribute mapping provided.",
            )

        try:
            self.test_server_connectivity(configuration)
        except Exception:
            return ValidationResult(
                success=False,
                message="Error occurred while establishing connection with Server. "
                "Make sure you have provided correct Server Address and Port.",
            )

        return ValidationResult(success=True, message="Validation successful.")

    def push(self, transformed_data, data_type, subtype) -> PushResult:
        """Push the transformed_data to the 3rd party platform.

        Args:
            transformed_data (list): The transformed data to be ingested.
            data_type (str): The type of data to be ingested (alert/event)
            subtype (str): The subtype of data to be ingested (DLP, anomaly etc. in case of alerts)


        Returns:
            PushResult: Result indicating ingesting outcome and message
        """
        elastic_client = ElasticClient(self.configuration, self.logger)
        try:
            # Elastic Client
            elastic_client.get_socket()

            # Prepare data to push (String of events/alerts seperated by '\n'.
            data = []
            for json_data in transformed_data:
                data.append(json.dumps(json_data))

            final_data = "\n".join(data)
            elastic_client.push_data(final_data)
        except Exception as e:
            self.logger.error(f"Error while pushing data: {e}")
            raise
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
            data[field]
            if data[field] or isinstance(data[field], int)
            else "null"
        )

    def get_subtype_mapping(self, mappings, subtype):
        """To Retrieve subtype mappings (mappings for subtypes of alerts/events) case insensitively.

        Args:
            mappings: Mapping JSON from which subtypes are to be retrieved
            subtype: Subtype (e.g. DLP for alerts) for which the mapping is to be fetched

        Returns:
            Fetched mapping JSON object
        """
        mappings = {k.lower(): v for k, v in mappings.items()}
        if subtype.lower() in mappings:
            return mappings[subtype.lower()]
        else:
            return mappings[subtype.upper()]

    def get_headers(self, header_mappings, data, data_type, subtype):
        """To Create a dictionary of ECS headers from given header mappings for given Netskope alert/event record.

        Args:
            subtype: Subtype for which the headers are being transformed
            data_type: Data type for which the headers are being transformed
            header_mappings: ECS header mapping with Netskope fields
            data: The alert/event for which the ECS header is being generated

        Returns:
            header dict
        """
        headers = {}
        helper = AlertsHelper()
        tenant = helper.get_tenant_cls(self.source)
        mapping_variables = {"$tenant_name": tenant.name}

        missing_fields = []
        # Iterate over mapped headers
        for ecs_header, header_mapping in header_mappings.items():
            try:
                headers[ecs_header] = self.get_field_value_from_data(
                    header_mapping, data, data_type, subtype, False
                )

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

        return headers

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

        # Iterate over mapped extensions
        for ecs_extension, extension_mapping in extension_mappings.items():
            try:
                extension[ecs_extension] = self.get_field_value_from_data(
                    extension_mapping,
                    data,
                    data_type,
                    subtype,
                    is_json_path="is_json_path" in extension_mapping,
                )
            except FieldNotFoundError as err:
                missing_fields.append(str(err))

        return extension

    def get_field_value_from_data(
        self, extension_mapping, data, data_type, subtype, is_json_path=False
    ):
        """To Fetch the value of extension based on "mapping" and "default" fields.

        Args:
            extension_mapping: Dict containing "mapping" and "default" fields
            data: Data instance retrieved from Netskope
            subtype: Subtype for which the extension are being transformed
            data_type: Data type for which the headers are being transformed
            is_json_path: Whether the mapped value is JSON path or direct field name

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
        if (
            "mapping_field" in extension_mapping
            and extension_mapping["mapping_field"]
        ):
            if is_json_path:
                # If mapping field specified by JSON path is present in data, map that field, else skip by raising
                # exception:
                value = self.get_mapping_value_from_json_path(
                    data, extension_mapping["mapping_field"]
                )
                if value:
                    return ",".join([str(val) for val in value])
                else:
                    raise FieldNotFoundError(
                        extension_mapping["mapping_field"]
                    )
            else:
                # If mapping is present in data, map that field, else skip by raising exception
                if (
                    extension_mapping["mapping_field"] in data
                ):  # case #1 and case #4
                    return self.get_mapping_value_from_field(
                        data, extension_mapping["mapping_field"]
                    )
                elif "default_value" in extension_mapping:
                    # If mapped value is not found in response and default is mapped, map the default value (case #2)
                    return extension_mapping["default_value"]
                else:  # case #6
                    raise FieldNotFoundError(
                        extension_mapping["mapping_field"]
                    )
        else:
            # If mapping is not present, 'default_value' must be there because of validation (case #3 and case #5)
            return extension_mapping["default_value"]

    def map_json_data(self, mappings, data, data_type, subtype):
        """Filter the raw data and returns the filtered data.

        :param mappings: List of fields to be pushed
        :param data: Data to be mapped (retrieved from Netskope)
        :param logger: Logger object for logging purpose
        :return: Mapped data based on fields given in mapping file
        """

        if mappings == []:
            return data

        mapped_dict = {}
        for key in mappings:
            if key in data:
                mapped_dict[key] = data[key]

        return mapped_dict

    def transform(self, raw_data, data_type, subtype) -> List:
        """Transform the raw netskope JSON data into target platform supported data formats.

        Args:
            raw_data (list): The raw data to be tranformed.
            data_type (str): The type of data to be ingested (alert/event)
            subtype (str): The subtype of data to be ingested (DLP, anomaly etc. in case of alerts)

        Raises:
            NotImplementedError: If the method is not implemented.

        Returns:
            List: list of transformed data.
        """
        if not self.configuration.get("transformData", True):
            if data_type not in ["alerts", "events"]:
                return raw_data

            try:
                ecs_version, elastic_mappings = get_elastic_mappings(
                    self.mappings, "json"
                )
            except KeyError as err:
                self.logger.error(
                    "Error in elastic mapping file. Error: {}".format(str(err))
                )
                raise
            except MappingValidationError as err:
                self.logger.error(str(err))
                raise
            except Exception as err:
                self.logger.error(
                    "An error occurred while mapping data using given json mappings. Error: {}".format(
                        str(err)
                    )
                )
                raise

            try:
                subtype_mapping = self.get_subtype_mapping(
                    elastic_mappings["json"][data_type], subtype
                )
            except Exception:
                self.logger.error(
                    'Error occurred while retrieving mappings for datatype: "{}" (subtype "{}"). '
                    "Transformation will be skipped.".format(
                        data_type, subtype
                    )
                )
                raise

            transformed_data = []

            for data in raw_data:
                transformed_data.append(
                    self.map_json_data(
                        subtype_mapping, data, data_type, subtype
                    )
                )

            return transformed_data

        else:
            try:
                ecs_version, elastic_mappings = get_elastic_mappings(
                    self.mappings, data_type
                )
            except KeyError as err:
                self.logger.error(
                    "Error in elastic mapping file. Error: {}".format(str(err))
                )
                raise
            except MappingValidationError as err:
                self.logger.error(str(err))
                raise
            except Exception as err:
                self.logger.error(
                    "An error occurred while mapping data using given json mappings. Error: {}".format(
                        str(err)
                    )
                )
                raise

            transformed_data = []
            ecs_generator = ECSGenerator(
                self.mappings,
                ecs_version,
                self.logger,
            )

            for data in raw_data:
                # First retrieve the mapping of subtype being transformed
                try:
                    subtype_mapping = self.get_subtype_mapping(
                        elastic_mappings[data_type], subtype
                    )
                except Exception:
                    self.logger.error(
                        'Error occurred while retrieving mappings for subtype "{}". '
                        "Transformation of current record will be skipped.".format(
                            subtype
                        )
                    )
                    continue

                # Generating the ECS header
                try:
                    header = self.get_headers(
                        subtype_mapping["header"], data, data_type, subtype
                    )
                except Exception as err:
                    self.logger.error(
                        "[{}][{}]: Error occurred while creating ECS header: {}. Transformation of "
                        "current record will be skipped.".format(
                            data_type, subtype, str(err)
                        )
                    )
                    continue

                try:
                    extension = self.get_extensions(
                        subtype_mapping["extension"], data, data_type, subtype
                    )
                except Exception as err:
                    self.logger.error(
                        "[{}][{}]: Error occurred while creating ECS extension: {}. Transformation of "
                        "the current record will be skipped".format(
                            data_type, subtype, str(err)
                        )
                    )
                    continue

                try:
                    transformed_data.append(
                        ecs_generator.get_ecs_event(
                            header, extension, data_type, subtype
                        )
                    )
                    pass
                except EmptyExtensionError:
                    self.logger.error(
                        "[{}][{}]: Got empty extension during transformation."
                        "Transformation of current record will be skipped".format(
                            data_type, subtype
                        )
                    )
                except Exception as err:
                    self.logger.error(
                        "[{}][{}]: An error occurred during transformation."
                        " Error: {}".format(data_type, subtype, str(err))
                    )
            return transformed_data
