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

Syslog Plugin."""

import logging
import logging.handlers
import threading
import socket
import json
import traceback
import time
from typing import List
from jsonpath import jsonpath
from netskope.common.utils import AlertsHelper
from netskope.integrations.cls.plugin_base import (
    PluginBase,
    ValidationResult,
    PushResult,
)
from .utils.syslog_constants import (
    SYSLOG_FORMATS,
    SYSLOG_PROTOCOLS,
    PLATFORM_NAME,
    MODULE_NAME,
    PLUGIN_VERSION,
)
from .utils.syslog_validator import SyslogValidator
from .utils.syslog_helper import get_syslog_mappings
from .utils.syslog_exceptions import (
    MappingValidationError,
    EmptyExtensionError,
    FieldNotFoundError,
)
from .utils.syslog_cef_generator import CEFGenerator
from .utils.syslog_ssl import SSLSysLogHandler


class SyslogPlugin(PluginBase):
    """The Syslog plugin implementation class."""

    def __init__(
        self,
        name,
        *args,
        **kwargs,
    ):
        """Initialize SyslogPlugin class."""
        super().__init__(
            name,
            *args,
            **kwargs,
        )
        self.plugin_name, self.plugin_version = self._get_plugin_info()
        self.log_prefix = f"{MODULE_NAME} {self.plugin_name} [{name}]"

    def _get_plugin_info(self) -> tuple:
        """Get plugin name and version from manifest.
        Returns:
            tuple: Tuple of plugin's name and version fetched from manifest.
        """
        try:
            manifest_json = SyslogPlugin.metadata
            plugin_name = manifest_json.get("name", PLATFORM_NAME)
            plugin_version = manifest_json.get("version", PLUGIN_VERSION)
            return (plugin_name, plugin_version)
        except Exception as exp:
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Error occurred while"
                    f" getting plugin details. Error: {exp}"
                ),
                details=str(traceback.format_exc()),
            )
        return (PLATFORM_NAME, PLUGIN_VERSION)

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

    def get_subtype_mapping(self, mappings, subtype):
        """To Retrieve subtype mappings (mappings for subtypes of \
            alerts/events) case insensitively.

        Args:
            mappings: Mapping JSON from which subtypes are to be retrieved
            subtype: Subtype (e.g. DLP for alerts) for which the \
                mapping is to be fetched

        Returns:
            Fetched mapping JSON object
        """
        mappings = {k.lower(): v for k, v in mappings.items()}
        if subtype.lower() in mappings:
            return mappings[subtype.lower()]
        else:
            return mappings[subtype.upper()]

    def get_headers(self, header_mappings, data, data_type, subtype):
        """To Create a dictionary of CEF headers from given header mappings\
              for given Netskope alert/event record.

        Args:
            subtype: Subtype for which the headers are being transformed
            data_type: Data type for which the headers are being transformed
            header_mappings: CEF header mapping with Netskope fields
            data: The alert/event for which the CEF header is being generated

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
        for cef_header, header_mapping in header_mappings.items():
            try:
                (
                    headers[cef_header],
                    mapped_field,
                ) = self.get_field_value_from_data(
                    header_mapping, data, data_type, subtype, False
                )

                if mapped_field:
                    mapped_field_flag = mapped_field

                # Handle variable mappings
                if (
                    isinstance(headers[cef_header], str)
                    and headers[cef_header].lower() in mapping_variables
                ):
                    headers[cef_header] = mapping_variables[headers[cef_header].lower()]
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
        for cef_extension, extension_mapping in extension_mappings.items():
            try:
                (
                    extension[cef_extension],
                    mapped_field,
                ) = self.get_field_value_from_data(
                    extension_mapping,
                    data,
                    data_type,
                    subtype,
                    is_json_path="is_json_path" in extension_mapping,
                )

                if mapped_field:
                    mapped_field_flag = mapped_field
            except FieldNotFoundError as err:
                missing_fields.append(str(err))

        return extension, mapped_field_flag

    def get_field_value_from_data(
        self, extension_mapping, data, data_type, subtype, is_json_path=False
    ):
        """To Fetch the value of extension based on "mapping" \
            and "default" fields.

        Args:
            extension_mapping: Dict containing "mapping" and "default" fields
            data: Data instance retrieved from Netskope
            subtype: Subtype for which the extension are being transformed
            data_type: Data type for which the headers are being transformed
            is_json_path: Whether the mapped value is \
                JSON path or direct field name

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
        # mapped_field will be returned as true only if the value returned is\
        # using the mapping_field and not default_value
        mapped_field = False
        if "mapping_field" in extension_mapping and extension_mapping["mapping_field"]:
            if is_json_path:
                # If mapping field specified by JSON path is present in data,\
                #  map that field, else skip by raising
                # exception:
                value = self.get_mapping_value_from_json_path(
                    data, extension_mapping["mapping_field"]
                )
                if value:
                    mapped_field = True
                    return ",".join([str(val) for val in value]), mapped_field
                else:
                    raise FieldNotFoundError(extension_mapping["mapping_field"])
            else:
                # If mapping is present in data, map that field, \
                # else skip by raising exception
                if extension_mapping["mapping_field"] in data:  # case #1 and case #4
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
                    raise FieldNotFoundError(extension_mapping["mapping_field"])
        else:
            # If mapping is not present, 'default_value' must be there\
            #  because of validation (case #3 and case #5)
            return extension_mapping["default_value"], mapped_field

    def map_json_data(self, mappings, data):
        """Filter the raw data and returns the filtered data.

        :param mappings: List of fields to be pushed
        :param data: Data to be mapped (retrieved from Netskope)
        :param logger: Logger object for logging purpose
        :return: Mapped data based on fields given in mapping file
        """

        if mappings == [] or not data:
            return data

        mapped_dict = {}
        for key in mappings:
            if key in data:
                mapped_dict[key] = data[key]

        return mapped_dict

    def transform(self, raw_data, data_type, subtype) -> List:
        """To Transform the raw netskope JSON data into target platform \
            supported data formats."""
        count = 0
        log_source_identifier = self.configuration.get(
            "log_source_identifier", "netskopece"
        )
        if not self.configuration.get("transformData", True):
            try:
                delimiter, cef_version, syslog_mappings = get_syslog_mappings(
                    self.mappings, "json", self.name
                )
            except KeyError as err:
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: An error occurred while fetching the mappings. Error: {err}"
                    ),
                    details=str(traceback.format_exc()),
                )
                raise
            except MappingValidationError as err:
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: An error occurred while validating the mapping file. {err}"
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
                    syslog_mappings["json"][data_type], subtype
                )
                if subtype_mapping == []:
                    transformed_data = []
                    for data in raw_data:
                        result = "{} {} {}".format(
                            time.strftime(
                                "%b %d %H:%M:%S", time.localtime(time.time())
                            ),
                            log_source_identifier,
                            json.dumps(data),
                        )
                        transformed_data.append(result)
                    return transformed_data
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

            transformed_data = []
            for data in raw_data:
                mapped_dict = self.map_json_data(subtype_mapping, data)
                if mapped_dict:
                    result = "{} {} {}".format(
                        time.strftime("%b %d %H:%M:%S", time.localtime(time.time())),
                        log_source_identifier,
                        json.dumps(mapped_dict),
                    )
                    transformed_data.append(result)
                else:
                    count += 1

            if count > 0:
                self.logger.debug(
                    "{}: Plugin couldn't process {} records because they "
                    "either had no data or contained invalid/missing "
                    "fields according to the configured JSON mapping. "
                    "Therefore, the transformation and ingestion for those "
                    "records were skipped.".format(self.log_prefix, count)
                )

            return transformed_data
        else:
            try:
                delimiter, cef_version, syslog_mappings = get_syslog_mappings(
                    self.mappings, data_type, self.name
                )
            except KeyError as err:
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: An error occurred while fetching the mappings. Error: {err}"
                    ),
                    details=str(traceback.format_exc()),
                )
                raise
            except MappingValidationError as err:
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: An error occurred while validating the mapping file. {err}"
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
                self.log_prefix,
            )

            # First retrieve the mapping of subtype being transformed
            try:
                subtype_mapping = self.get_subtype_mapping(
                    syslog_mappings[data_type], subtype
                )
            except KeyError:
                self.logger.info(
                    f"{self.log_prefix}: Unable to find the "
                    f"[{data_type}]:[{subtype}] mappings in the mapping file, "
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

            transformed_data = []
            for data in raw_data:
                if not data:
                    count += 1
                    continue

                # Generating the CEF header
                try:
                    header, mapped_flag_header = self.get_headers(
                        subtype_mapping["header"], data, data_type, subtype
                    )
                except Exception as err:
                    self.logger.error(
                        message=(
                            f"{self.log_prefix}: [{data_type}][{subtype}]- "
                            f"Error occurred while creating CEF header: {err}."
                            " Transformation of current record will be skipped."
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
                            f"{self.log_prefix}: [{data_type}][{subtype}]- Error "
                            f"occurred while creating CEF extension: {err}. "
                            "Transformation of the current record will be skipped."
                        ),
                        details=str(traceback.format_exc()),
                    )
                    count += 1
                    continue

                try:
                    if not (mapped_flag_header or mapped_flag_extension):
                        count += 1
                        continue
                    cef_generated_event = cef_generator.get_cef_event(
                        data,
                        header,
                        extension,
                        data_type,
                        subtype,
                        log_source_identifier,
                    )
                    if cef_generated_event:
                        transformed_data.append(cef_generated_event)
                except EmptyExtensionError:
                    self.logger.error(
                        message=(
                            f"{self.log_prefix}: [{data_type}][{subtype}]- Got"
                            " empty extension during transformation. "
                            "Transformation of current record will be skipped."
                        ),
                        details=str(traceback.format_exc()),
                    )
                    count += 1
                except Exception as err:
                    self.logger.error(
                        message=(
                            f"{self.log_prefix}: [{data_type}][{subtype}]- An "
                            f"error occurred during transformation. Error: {err}"
                        ),
                        details=str(traceback.format_exc()),
                    )
                    count += 1
            if count > 0:
                self.logger.debug(
                    "{}: Plugin couldn't process {} records because they "
                    "either had no data or contained invalid/missing "
                    "fields according to the configured mapping. "
                    "Therefore, the transformation and ingestion for those "
                    "records were skipped.".format(self.log_prefix, count)
                )

            return transformed_data

    def init_handler(self, configuration):
        """Initialize unique Syslog handler per thread\
              based on configured protocol."""
        syslogger = logging.getLogger("SYSLOG_LOGGER_{}".format(threading.get_ident()))
        syslogger.setLevel(logging.INFO)
        syslogger.handlers = []
        syslogger.propagate = False

        if configuration["syslog_protocol"] == "TLS":
            tls_handler = SSLSysLogHandler(
                configuration["syslog_protocol"],
                address=(
                    configuration["syslog_server"].strip(),
                    configuration["syslog_port"],
                ),
                certs=configuration["syslog_certificate"],
            )
            syslogger.addHandler(tls_handler)
        else:
            socktype = socket.SOCK_DGRAM  # Set protocol to UDP by default
            if configuration["syslog_protocol"] == "TCP":
                socktype = socket.SOCK_STREAM

            # Create a syslog handler with given configuration parameters
            handler = SSLSysLogHandler(
                configuration["syslog_protocol"],
                address=(
                    configuration["syslog_server"].strip(),
                    configuration["syslog_port"],
                ),
                socktype=socktype,
            )

            if configuration["syslog_protocol"] == "TCP":
                # This will add a line break to the message before it is \
                # 'emitted' which ensures that the messages are
                # split up over multiple lines, \
                # see https://bugs.python.org/issue28404
                handler.setFormatter(logging.Formatter("%(message)s\n"))
                # In order for the above to work, then we need to ensure\
                # that the null terminator is not included
                handler.append_nul = False

            syslogger.addHandler(handler)

        return syslogger

    def push(self, transformed_data, data_type, subtype) -> PushResult:
        """Push the transformed_data to the 3rd party platform."""
        successful_log_push_counter, skipped_logs = 0, 0
        try:
            syslogger = self.init_handler(self.configuration)
        except Exception as err:
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Error occurred during "
                    f"initializing connection. Error: {err}"
                ),
                details=str(traceback.format_exc()),
            )
            raise

        # Log the transformed data to given syslog server
        for data in transformed_data:
            try:
                if data:
                    syslogger.info(json.dumps(data) if isinstance(data, dict) else data)
                    successful_log_push_counter += 1
                    syslogger.handlers[0].flush()
                else:
                    skipped_logs += 1

            except Exception as err:
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: Error occurred during data ingestion."
                        f" Error: {err}. Record will be skipped."
                    ),
                    details=str(traceback.format_exc()),
                )

        # Clean up
        try:
            syslogger.handlers[0].close()
            del syslogger.handlers[:]
            del syslogger

            if skipped_logs > 0:
                self.logger.debug(
                    "{}: Received empty transformed data for {} log(s) hence "
                    "ingestion of those log(s) will be skipped.".format(
                        self.log_prefix,
                        skipped_logs,
                    )
                )
            log_msg = (
                "[{}] [{}] Successfully ingested {} log(s)"
                " to {} server.".format(
                    data_type,
                    subtype,
                    successful_log_push_counter,
                    self.plugin_name,
                )
            )
            self.logger.info(f"{self.log_prefix}: {log_msg}")
            return PushResult(
                success=True,
                message=log_msg,
            )

        except Exception as err:
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Error occurred during Clean up. Error: {err}"
                ),
                details=str(traceback.format_exc()),
            )

    def test_server_connectivity(self, configuration):
        """Tests whether the configured syslog server is reachable or not."""
        try:
            syslogger = self.init_handler(configuration)
        except Exception as err:
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Error occurred while establishing "
                    "connection with syslog server. Make sure "
                    "you have provided correct syslog server and port."
                ),
                details=str(traceback.format_exc()),
            )
            raise err
        else:
            # Clean up for further use
            syslogger.handlers[0].flush()
            syslogger.handlers[0].close()
            del syslogger.handlers[:]
            del syslogger

    def validate(self, configuration: dict) -> ValidationResult:
        """Validate the configuration parameters dict."""
        syslog_validator = SyslogValidator(self.logger, self.log_prefix)
        validation_err_msg = f"{self.log_prefix}: Validation error occurred."
        syslog_server = configuration.get("syslog_server", "").strip()
        if not syslog_server:
            err_msg = "Syslog Server is a required configuration parameter."
            self.logger.error(f"{validation_err_msg} {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        elif not isinstance(syslog_server, str):
            err_msg = "Invalid Syslog Server provided in configuration parameters."
            self.logger.error(f"{validation_err_msg} {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )

        syslog_format = configuration.get("syslog_format", "").strip()
        if not syslog_format:
            err_msg = "Syslog Format is a required configuration parameter."
            self.logger.error(f"{validation_err_msg} {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        elif not isinstance(syslog_format, str) or syslog_format not in SYSLOG_FORMATS:
            err_msg = "Invalid Syslog Format provided in configuration parameters."
            self.logger.error(f"{validation_err_msg} {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )

        syslog_protocol = configuration.get("syslog_protocol", "").strip()
        if not syslog_protocol:
            err_msg = "Syslog Protocol is a required configuration parameter."
            self.logger.error(f"{validation_err_msg} {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        elif (
            not isinstance(syslog_protocol, str)
            or syslog_protocol not in SYSLOG_PROTOCOLS
        ):
            err_msg = "Invalid Syslog Protocol provided in configuration parameters."
            self.logger.error(f"{validation_err_msg} {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )

        syslog_port = configuration.get("syslog_port")
        if not syslog_port:
            err_msg = "Syslog Port is a required configuration parameter."
            self.logger.error(f"{validation_err_msg} {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        elif not isinstance(syslog_port, int):
            err_msg = "Invalid Syslog Port provided in configuration parameters."
            self.logger.error(f"{validation_err_msg} {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        elif not syslog_validator.validate_syslog_port(syslog_port):
            err_msg = "Invalid Syslog Port provided in configuration parameters. it should be in range 0-65535."
            self.logger.error(f"{validation_err_msg} {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )

        mappings = self.mappings.get("jsonData", None)
        mappings = json.loads(mappings)
        if not isinstance(mappings, dict) or not syslog_validator.validate_syslog_map(
            mappings
        ):
            err_msg = "Invalid attribute mapping provided."
            self.logger.error(f"{validation_err_msg} {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )

        syslog_certificate = configuration.get("syslog_certificate", "").strip()
        if syslog_protocol.upper() == "TLS":
            if not syslog_certificate:
                err_msg = (
                    "Syslog Certificate is a required configuration parameter when "
                    "TLS is provided in the configuration parameters."
                )
                self.logger.error(f"{validation_err_msg} {err_msg}")
                return ValidationResult(
                    success=False,
                    message=err_msg,
                )
            elif not isinstance(syslog_certificate, str):
                err_msg = (
                    "Invalid Syslog Certificate provided in configuration parameters."
                )
                self.logger.error(f"{validation_err_msg} {err_msg}")
                return ValidationResult(
                    success=False,
                    message=err_msg,
                )

        log_source_identifier = configuration.get("log_source_identifier", "").strip()
        if not log_source_identifier:
            err_msg = "Log Source Identifier is a required configuration parameter."
            self.logger.error(f"{validation_err_msg} {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        elif not isinstance(log_source_identifier, str):
            err_msg = (
                "Invalid Log Source Identifier provided in configuration parameters."
            )
            self.logger.error(f"{validation_err_msg} {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        # Validate Server connection.
        try:
            self.test_server_connectivity(configuration)
        except Exception:
            err_msg = (
                "Error occurred while establishing connection with Syslog Server. "
                "Make sure you have provided correct Syslog Server, Port and "
                "Syslog Certificate(if required)."
            )
            self.logger.error(f"{validation_err_msg} {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )

        return ValidationResult(success=True, message="Validation successful.")

    def chunk_size(self):
        """Chunk size to be ingested per thread."""
        return 2000
