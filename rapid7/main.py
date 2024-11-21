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

"""Rapid7 CLS Plugin."""

import json
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
from .utils.rapid7_constants import (
    RAPID7_PROTOCOLS,
    PLUGIN_VERSION,
    PLATFORM_NAME,
    MODULE_NAME,
)
from .utils.rapid7_validator import (
    Rapid7Validator,
)
from .utils.rapid7_helper import (
    get_rapid7_mappings,
)
from .utils.rapid7_exceptions import (
    MappingValidationError,
    EmptyExtensionError,
    FieldNotFoundError,
    Rapid7PluginError,
)
from .utils.rapid7_cef_generator import (
    CEFGenerator,
)
from .utils.rapid7_ssl import SSLSysLogHandler


class Rapid7Plugin(PluginBase):
    """The Rapid7 plugin implementation class."""

    def __init__(
        self,
        name,
        *args,
        **kwargs,
    ):
        """Initialize Rapid7 class."""
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
            manifest_json = Rapid7Plugin.metadata
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
                    headers[cef_header] = mapping_variables[
                        headers[cef_header].lower()
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
        if (
            "mapping_field" in extension_mapping
            and extension_mapping["mapping_field"]
        ):
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
                    raise FieldNotFoundError(
                        extension_mapping["mapping_field"]
                    )
            else:
                # If mapping is present in data, map that field,
                # else skip by raising exception
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

        if mappings == [] or not data:
            return data

        mapped_dict = {}
        for key in mappings:
            if key in data:
                mapped_dict[key] = data[key]

        return mapped_dict

    def transform(self, raw_data: list, data_type: str, subtype: str) -> list:
        """To Transform the raw netskope JSON data into
        target platform supported data formats.

        Args:
            raw_data (list): Raw Data.
            data_type (str): Data type. e.g. alerts,events or webtx
            subtype (str): Subtype e.g. DLP,application,page,network,etc

        Returns:
            list: Transformed data.
        """
        count = 0
        log_source_identifier = self.configuration.get(
            "log_source_identifier", "netskopece"
        )
        if not self.configuration.get("transformData", True):
            try:
                delimiter, cef_version, rapid7_mappings = get_rapid7_mappings(
                    self.mappings, "json", self.name
                )
            except KeyError as err:
                error_msg = (
                    f"[{data_type}][{subtype}] "
                    "An error occurred while fetching the mappings."
                )
                self.logger.error(
                    message=(f"{self.log_prefix}: {error_msg} Error: {err}"),
                    details=str(traceback.format_exc()),
                )
                raise Rapid7PluginError(error_msg)
            except MappingValidationError as err:
                error_msg = (
                    f"[{data_type}][{subtype}] "
                    "An error occurred while validating the mapping file."
                )
                self.logger.error(
                    message=(f"{self.log_prefix}: {error_msg} {err}"),
                    details=str(traceback.format_exc()),
                )
                raise Rapid7PluginError(error_msg)
            except Exception as err:
                error_msg = (
                    f"[{data_type}][{subtype}] "
                    "An error occurred while mapping "
                    "data using given json mappings."
                )
                self.logger.error(
                    message=(f"{self.log_prefix}: {error_msg} Error: {err}"),
                    details=str(traceback.format_exc()),
                )
                raise Rapid7PluginError(error_msg)

            try:
                subtype_mapping = self.get_subtype_mapping(
                    rapid7_mappings["json"][data_type], subtype
                )
                if subtype_mapping == []:
                    transformed_data = []
                    for data in raw_data:
                        if data:
                            result = "{} {} {}".format(
                                time.strftime(
                                    "%b %d %H:%M:%S",
                                    time.localtime(time.time()),
                                ),
                                log_source_identifier,
                                json.dumps(data),
                            )
                            transformed_data.append(result)
                        else:
                            count += 1
                    return transformed_data
            except Rapid7PluginError:
                raise
            except Exception as err:
                error_msg = (
                    f"[{data_type}][{subtype}] "
                    "Error occurred while retrieving "
                    f"mappings."
                )
                self.logger.error(
                    message=(f"{self.log_prefix}: {error_msg} Error: {err}"),
                    details=str(traceback.format_exc()),
                )
                raise Rapid7PluginError(error_msg)

            transformed_data = []
            for data in raw_data:
                mapped_dict = self.map_json_data(subtype_mapping, data)
                if mapped_dict:
                    result = "{} {} {}".format(
                        time.strftime(
                            "%b %d %H:%M:%S", time.localtime(time.time())
                        ),
                        log_source_identifier,
                        json.dumps(mapped_dict),
                    )
                    transformed_data.append(result)
                else:
                    count += 1

            if count > 0:
                self.logger.info(
                    "{}: Plugin couldn't process {} records because they "
                    "either had no data or contained invalid/missing "
                    "fields according to the configured JSON mapping. "
                    "Therefore, the transformation and ingestion for those "
                    "records were skipped.".format(self.log_prefix, count)
                )
            return transformed_data

        else:
            try:
                delimiter, cef_version, rapid7_mappings = get_rapid7_mappings(
                    self.mappings, data_type, self.name
                )
            except KeyError as err:
                error_msg = (
                    f"[{data_type}][{subtype}] "
                    "An error occurred while "
                    "fetching the mappings."
                )
                self.logger.error(
                    message=(f"{self.log_prefix}: {error_msg} Error: {err}"),
                    details=str(traceback.format_exc()),
                )
                raise Rapid7PluginError(error_msg)
            except MappingValidationError as err:
                error_msg = (
                    f"[{data_type}][{subtype}] "
                    "An error occurred while validating the mapping file."
                )
                self.logger.error(
                    message=(f"{self.log_prefix}: {error_msg} {err}"),
                    details=str(traceback.format_exc()),
                )
                raise Rapid7PluginError(error_msg)
            except Exception as err:
                error_msg = (
                    f"[{data_type}]:[{subtype}] "
                    "An error occurred while mapping "
                    "data using given json mappings."
                )
                self.logger.error(
                    message=(f"{self.log_prefix}: {error_msg} Error: {err}"),
                    details=str(traceback.format_exc()),
                )
                raise Rapid7PluginError(error_msg)

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
                    rapid7_mappings[data_type], subtype
                )
            except KeyError as err:
                error_msg = (
                    f"[{data_type}][{subtype}] Unable to find the "
                    "mappings in the mapping file."
                )
                self.logger.info(
                    f"{self.log_prefix}: {error_msg}" f"Error: {err}"
                )
                raise Rapid7PluginError(error_msg)
            except Exception as err:
                error_msg = (
                    f"[{data_type}]:[{subtype}] Error occurred while"
                    f" retrieving mappings for subtype {subtype}."
                )
                self.logger.error(
                    message=(f"{self.log_prefix}: {error_msg} Error: {err}"),
                    details=str(traceback.format_exc()),
                )
                raise Rapid7PluginError(error_msg)

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
                            f"{self.log_prefix}: [{data_type}][{subtype}] "
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
                            f"{self.log_prefix}: [{data_type}][{subtype}]"
                            f" Error occurred while creating CEF extension:"
                            f" {err}. Transformation of the current record "
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
                            f"{self.log_prefix}: [{data_type}][{subtype}] Got"
                            " empty extension during transformation. "
                            "Transformation of current record will be skipped."
                        ),
                        details=str(traceback.format_exc()),
                    )
                    count += 1
                except Exception as err:
                    self.logger.error(
                        message=(
                            f"{self.log_prefix}: [{data_type}][{subtype}] An "
                            f"error occurred during transformation."
                            f" Error: {err}"
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
        """Initialize unique Rapid7 handler per thread
        based on configured protocol."""
        syslogger = logging.getLogger(
            "SYSLOG_LOGGER_{}".format(threading.get_ident())
        )
        syslogger.setLevel(logging.INFO)
        syslogger.handlers = []
        syslogger.propagate = False

        if configuration.get("rapid7_protocol") == "TLS":
            tls_handler = SSLSysLogHandler(
                configuration.get("rapid7_protocol"),
                address=(
                    configuration.get("rapid7_server"),
                    configuration.get("rapid7_port"),
                ),
                certs=configuration.get("rapid7_certificate"),
            )
            syslogger.addHandler(tls_handler)
        else:
            socktype = socket.SOCK_DGRAM  # Set protocol to UDP by default
            if configuration.get("rapid7_protocol") == "TCP":
                socktype = socket.SOCK_STREAM

            # Create a rapid7 handler with given configuration parameters
            handler = SSLSysLogHandler(
                configuration.get("rapid7_protocol"),
                address=(
                    configuration.get("rapid7_server").strip(),
                    configuration.get("rapid7_port"),
                ),
                socktype=socktype,
            )

            if configuration.get("rapid7_protocol") == "TCP":
                # This will add a line break to the message before
                # it is 'emitted' which ensures that the messages are
                # split up over multiple lines,
                # see https://bugs.python.org/issue28404
                handler.setFormatter(logging.Formatter("%(message)s\n"))
                # In order for the above to work, then we need to ensure that
                # the null terminator is not included
                handler.append_nul = False

            syslogger.addHandler(handler)

        return syslogger

    def log_success_msg(
        self, data_type, subtype, successful_log_push_counter, skipped_logs
    ):
        """Log the success message."""
        log_msg = ""
        if successful_log_push_counter > 0:
            log_msg = (
                f"[{data_type}] [{subtype}] Successfully "
                f"ingested {successful_log_push_counter} log(s)"
                f" to {self.plugin_name} server."
            )
        if log_msg and skipped_logs:
            log_msg += (
                " Received empty transformed data for "
                f"{skipped_logs} log(s) hence ingestion of those log(s) "
                "will be skipped."
            )
        if log_msg:
            self.logger.info(f"{self.log_prefix}: {log_msg}")
        return log_msg

    def push(self, transformed_data, data_type, subtype) -> PushResult:
        """Push the transformed_data to the 3rd party platform."""
        self.logger.debug(
            f"{self.log_prefix}: "
            f"Initializing the sharing of {len(transformed_data)} "
            f"[{data_type}]:[{subtype}] logs "
            f"to the {PLATFORM_NAME} server."
        )
        successful_log_push_counter, skipped_logs = 0, 0
        try:
            syslogger = self.init_handler(self.configuration)
        except (TimeoutError, ConnectionRefusedError, Exception) as err:
            error_msg = {
                TimeoutError: (
                    "Timeout error occurred during initializing "
                    "connection with Rapid7 server."
                ),
                ConnectionRefusedError: (
                    "Connection refused during initializing "
                    "connection with Rapid7 server."
                ),
            }.get(type(err), "Error occurred during initializing connection.")
            self.logger.error(
                message=f"{self.log_prefix}: {error_msg} Error: {err}.",
                details=str(traceback.format_exc()),
            )
            raise Rapid7PluginError(error_msg)

        try:
            for data in transformed_data:
                if data:
                    syslogger.info(
                        json.dumps(data) if isinstance(data, dict) else data
                    )
                    syslogger.handlers[0].flush()
                    successful_log_push_counter += 1
                else:
                    skipped_logs += 1

            log_msg = self.log_success_msg(
                data_type, subtype, successful_log_push_counter, skipped_logs
            )
            return PushResult(
                success=True,
                message=log_msg,
            )
        except Exception as err:
            failed_logs = len(transformed_data) - successful_log_push_counter
            _ = self.log_success_msg(
                data_type, subtype, successful_log_push_counter, skipped_logs
            )
            # Remove the data already been ingested
            del transformed_data[:successful_log_push_counter]
            error_msg = (
                "Error occurred while ingesting "
                f"data to Rapid7 server. {failed_logs} log(s) "
                "failed to be ingested."
            )
            self.logger.error(
                message=(f"{self.log_prefix}: {error_msg} Error: {err}"),
                details=str(traceback.format_exc()),
            )
            raise Rapid7PluginError(error_msg)

        # Clean up
        finally:
            try:
                syslogger.handlers[0].close()
                del syslogger.handlers[:]
                del syslogger
            except Exception as err:
                error_msg = "Error occurred while cleaning up Rapid7 handler."
                self.logger.debug(
                    f"{self.log_prefix}: {error_msg} Error: {err}"
                )

    def test_server_connectivity(self, configuration):
        """Tests whether the configured rapid7 server is reachable or not."""
        try:
            syslogger = self.init_handler(configuration)
        except Exception as err:
            error_msg = (
                "Error occurred while establishing "
                "connection with Rapid7 server. Make sure "
                "you have provided correct Rapid7 server and port."
            )
            self.logger.error(
                message=(f"{self.log_prefix}: {error_msg} Error: {err}"),
                details=str(traceback.format_exc()),
            )
            raise Rapid7PluginError(error_msg)
        else:
            # Clean up for further use
            syslogger.handlers[0].flush()
            syslogger.handlers[0].close()
            del syslogger.handlers[:]
            del syslogger

    def validate(self, configuration: dict) -> ValidationResult:
        """Validate the configuration parameters dict."""

        rapid7_validator = Rapid7Validator(self.logger, self.log_prefix)
        validation_err_msg = f"{self.log_prefix}: Validation error occurred."

        rapid7_server = configuration.get("rapid7_server", "").strip()
        if not rapid7_server:
            err_msg = "Rapid7 Server is a required configuration parameter."
            self.logger.error(f"{validation_err_msg} {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        elif not isinstance(rapid7_server, str):
            err_msg = (
                "Invalid Rapid7 Server provided in configuration parameters."
            )
            self.logger.error(f"{validation_err_msg} {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )

        rapid7_protocol = configuration.get("rapid7_protocol", "").strip()
        if not rapid7_protocol:
            err_msg = "Rapid7 Protocol is a required configuration parameter."
            self.logger.error(f"{validation_err_msg} {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        elif (
            not isinstance(rapid7_protocol, str)
            or rapid7_protocol not in RAPID7_PROTOCOLS
        ):
            err_msg = (
                "Invalid Rapid7 Protocol provided in configuration parameters."
            )
            self.logger.error(f"{validation_err_msg} {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )

        rapid7_port = configuration.get("rapid7_port")
        if not rapid7_port:
            err_msg = "Rapid7 Port is a required configuration parameter."
            self.logger.error(f"{validation_err_msg} {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        elif not isinstance(rapid7_port, int):
            err_msg = (
                "Invalid Rapid7 Port provided in configuration parameters."
            )
            self.logger.error(f"{validation_err_msg} {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        elif not rapid7_validator.validate_rapid7_port(rapid7_port):
            err_msg = (
                "Invalid Rapid7 Port provided in configuration "
                "parameters. it should be in range 0-65535."
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
        ) or not rapid7_validator.validate_rapid7_map(mappings):
            err_msg = "Invalid attribute mapping provided."
            self.logger.error(f"{validation_err_msg} {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )

        rapid7_certificate = configuration.get(
            "rapid7_certificate", ""
        ).strip()
        if rapid7_protocol.upper() == "TLS":
            if not rapid7_certificate:
                err_msg = (
                    "Rapid7 Certificate is a required configuration "
                    "parameter when TLS is provided in the "
                    "configuration parameters."
                )
                self.logger.error(f"{validation_err_msg} {err_msg}")
                return ValidationResult(
                    success=False,
                    message=err_msg,
                )
            elif not isinstance(rapid7_certificate, str):
                err_msg = (
                    "Invalid Rapid7 Certificate provided in "
                    "configuration parameters."
                )
                self.logger.error(f"{validation_err_msg} {err_msg}")
                return ValidationResult(
                    success=False,
                    message=err_msg,
                )

        log_source_identifier = configuration.get(
            "log_source_identifier", ""
        ).strip()
        if not log_source_identifier:
            err_msg = (
                "Log Source Identifier is a required configuration parameter."
            )
            self.logger.error(f"{validation_err_msg} {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        elif not isinstance(log_source_identifier, str):
            err_msg = (
                "Invalid Log Source Identifier provided in "
                "configuration parameters."
            )
            self.logger.error(f"{validation_err_msg} {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        # Validate Server connection.
        try:
            self.test_server_connectivity(configuration)
        except Rapid7PluginError as err:
            return ValidationResult(
                success=False,
                message=str(err),
            )
        except Exception:
            err_msg = (
                "Error occurred while establishing connection with Rapid7 "
                "Server. Make sure you have provided correct Rapid7 Server"
                ", Port and Rapid7 Certificate(if required)."
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
