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

FortiSIEM Plugin."""

import logging
import logging.handlers
import threading
import socket
import json
import traceback
import time
from typing import List
from jsonpath import jsonpath
from netskope.integrations.cls.plugin_base import (
    PluginBase,
    ValidationResult,
    PushResult,
)
from .utils.fortisiem_constants import (
    FORTISIEM_PROTOCOLS,
    PLATFORM_NAME,
    MODULE_NAME,
    PLUGIN_VERSION,
    DATE_FORMAT,
    NETSKOPECE,
)
from .utils.fortisiem_validator import FortisiemValidator
from .utils.fortisiem_helper import get_fortisiem_mappings
from .utils.fortisiem_exceptions import (
    MappingValidationError,
    FortisiemPluginException,
)
from .utils.fortisiem_ssl import SSLFortisiemHandler


class FortisiemPlugin(PluginBase):
    """The FortiSIEM plugin implementation class."""

    def __init__(
        self,
        name,
        *args,
        **kwargs,
    ):
        """Initialize FortisiemPlugin class."""
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
            manifest_json = FortisiemPlugin.metadata
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
        """Transform the raw netskope JSON data into target platform supported
          data formats.

        Args:
            raw_data (list): The raw data to be transformed.
            data_type (str): The type of data to be ingested (alert/event)
            subtype (str): The subtype of data to be ingested (DLP, anomaly
              etc. in case of alerts)

        Returns:
            List: list of transformed data.
        """
        if self.configuration.get("transformData", True):
            error_message = (
                "Error occurred - this plugin only supports sharing of"
                f' JSON formatted data to {PLATFORM_NAME}: "{data_type}"'
                f' (subtype "{subtype}"). '
                "Transformation will be skipped."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {error_message}",
                details=traceback.format_exc(),
            )
            raise FortisiemPluginException(error_message)

        count = 0
        log_source_identifier = self.configuration.get(
            "log_source_identifier", NETSKOPECE
        )
        try:
            delimiter, cef_version, fortisiem_mappings = (
                get_fortisiem_mappings(self.mappings, "json", self.name)
            )
        except KeyError as err:
            err_msg = (
                f"{self.log_prefix}: An error occurred while "
                f"fetching the mappings."
            )
            self.logger.error(
                message=f"{err_msg} {err}",
                details=str(traceback.format_exc()),
            )
            raise FortisiemPluginException(err_msg)
        except MappingValidationError as err:
            err_msg = (
                f"{self.log_prefix}: An error occurred while "
                f"validating the mapping file."
            )
            self.logger.error(
                message=f"{err_msg} {err}",
                details=str(traceback.format_exc()),
            )
            raise FortisiemPluginException(err_msg)
        except Exception as err:
            err_msg = (
                f"{self.log_prefix}: An error occurred while mapping "
                f"data using given json mappings."
            )
            self.logger.error(
                message=f"{err_msg} {err}",
                details=str(traceback.format_exc()),
            )
            raise FortisiemPluginException(err_msg)

        transformed_data = []
        subtype_mapping = self.get_subtype_mapping(
            fortisiem_mappings["json"][data_type], subtype
        )
        mapped_dict = {}
        for data in raw_data:
            try:
                if subtype_mapping:
                    mapped_dict = self.map_json_data(subtype_mapping, data)
                    if mapped_dict:
                        result = "{} {} {}".format(
                            time.strftime(
                                DATE_FORMAT, time.localtime(time.time())
                            ),
                            log_source_identifier,
                            json.dumps(mapped_dict),
                        )
                        transformed_data.append(result)
                    else:
                        count += 1
                else:
                    result = "{} {} {}".format(
                        time.strftime(
                            DATE_FORMAT, time.localtime(time.time())
                        ),
                        log_source_identifier,
                        json.dumps(data),
                    )
                    transformed_data.append(result)

            except Exception:
                err_msg = (
                    f"{self.log_prefix}: Error occurred while retrieving "
                    f"mappings for datatype: {data_type} "
                    f"(subtype: {subtype}) Transformation will be skipped."
                )
                self.logger.error(
                    message=err_msg,
                    details=str(traceback.format_exc()),
                )
                raise FortisiemPluginException(err_msg)

        if count > 0:
            self.logger.info(
                "{}: Plugin couldn't process {} records because they "
                "either had no data or contained invalid/missing "
                "fields according to the configured JSON mapping. "
                "Therefore, the transformation and ingestion for those "
                "records were skipped.".format(self.log_prefix, count)
            )

        return transformed_data

    def init_handler(self, configuration):
        """Initialize unique FortiSIEM handler per thread\
              based on configured protocol.

            Args:
                configuration (dict): Configuration of the FortiSIEM plugin.
        """

        fortisiemlogger = logging.getLogger(
            "SYSLOG_LOGGER_{}".format(threading.get_ident())
        )
        fortisiemlogger.setLevel(logging.INFO)
        fortisiemlogger.handlers = []
        fortisiemlogger.propagate = False
        fortisiem_protocol = configuration.get(
            "fortisiem_protocol", ""
        ).strip()
        if fortisiem_protocol == "TLS":
            tls_handler = SSLFortisiemHandler(
                fortisiem_protocol,
                address=(
                    configuration.get("fortisiem_server", "").strip(),
                    configuration.get("fortisiem_port", ""),
                ),
                certs=configuration.get("fortisiem_certificate", "").strip(),
            )
            fortisiemlogger.addHandler(tls_handler)
        else:
            socktype = socket.SOCK_DGRAM  # Set protocol to UDP by default
            if fortisiem_protocol == "TCP":
                socktype = socket.SOCK_STREAM

            # Create a fortisiem handler with given configuration parameters
            handler = SSLFortisiemHandler(
                fortisiem_protocol,
                address=(
                    configuration.get("fortisiem_server", "").strip(),
                    configuration.get("fortisiem_port", ""),
                ),
                socktype=socktype,
            )

            if fortisiem_protocol == "TCP":
                # This will add a line break to the message before it is \
                # 'emitted' which ensures that the messages are
                # split up over multiple lines, \
                # see https://bugs.python.org/issue28404
                handler.setFormatter(logging.Formatter("%(message)s\n"))
                # In order for the above to work, then we need to ensure\
                # that the null terminator is not included
                handler.append_nul = False

            fortisiemlogger.addHandler(handler)

        return fortisiemlogger

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
        try:
            fortisiemlogger = self.init_handler(self.configuration)
        except TimeoutError as err:
            err_msg = (
                f"{self.log_prefix}: Timeout error occurred during "
                f"initializing connection."
            )
            self.logger.error(
                message=f"{err_msg} {err}.",
                details=str(traceback.format_exc()),
            )
            raise FortisiemPluginException(err_msg)
        except ConnectionRefusedError as err:
            err_msg = (
                f"{self.log_prefix}: Connection refused error occurred during "
                f"initializing connection."
            )
            self.logger.error(
                message=f"{err_msg} {err}.",
                details=str(traceback.format_exc()),
            )
            raise FortisiemPluginException(err_msg)
        except Exception as err:
            err_msg = (
                f"{self.log_prefix}: Error occurred during "
                f"initializing connection."
            )
            self.logger.error(
                message=f"{err_msg} {err}",
                details=str(traceback.format_exc()),
            )
            raise FortisiemPluginException(err_msg)

        try:
            # Log the transformed data to given fortisiem server
            for data in transformed_data:
                if data:
                    fortisiemlogger.info(
                        json.dumps(data) if isinstance(data, dict) else data
                    )
                    successful_log_push_counter += 1
                    fortisiemlogger.handlers[0].flush()
                else:
                    skipped_logs += 1

            if skipped_logs > 0:
                self.logger.info(
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

        except FortisiemPluginException as err:
            raise err
        except Exception as err:
            err_msg = (
                f"{self.log_prefix}: Error occurred during data ingestion."
            )
            self.logger.error(
                message=f"{err_msg} {err}",
                details=str(traceback.format_exc()),
            )
            raise FortisiemPluginException(err)
        finally:
            try:
                # Clean up
                fortisiemlogger.handlers[0].close()
                del fortisiemlogger.handlers[:]
                del fortisiemlogger
            except Exception as err:
                err_msg = "Error occurred during Clean up."
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg} {err}",
                    details=str(traceback.format_exc()),
                )
                raise FortisiemPluginException(err_msg)

    def test_server_connectivity(self, configuration):
        """Tests whether the configured FortiSIEM server is reachable or not.

        Args:
            configuration (Dict): Configuration dictionary.
        """
        try:
            fortisiemlogger = self.init_handler(configuration)
        except Exception as err:
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Error occurred while establishing "
                    f"connection with {PLATFORM_NAME} server. Make sure "
                    f"you have provided correct {PLATFORM_NAME} "
                    "server and port."
                ),
                details=str(traceback.format_exc()),
            )
            raise err
        else:
            # Clean up for further use
            fortisiemlogger.handlers[0].flush()
            fortisiemlogger.handlers[0].close()
            del fortisiemlogger.handlers[:]
            del fortisiemlogger

    def validate(self, configuration: dict) -> ValidationResult:
        """Validate the configuration parameters dict.

        Args:
            configuration (Dict): Configuration parameters.

        Returns:
            ValidationResult: Validation result with flag and message.
        """
        fortisiem_validator = FortisiemValidator(self.logger, self.log_prefix)
        validation_err_msg = f"{self.log_prefix}: Validation error occurred."
        fortisiem_server = configuration.get("fortisiem_server", "").strip()
        if configuration.get("transformData", True):
            err_msg = (
                "This plugin only supports JSON formatted data - "
                "Please disable the transformation toggle."
            )
            self.logger.error(
                f"{self.log_prefix}: Validation error occurred. {err_msg}"
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        if not fortisiem_server:
            err_msg = (
                f"{PLATFORM_NAME} Server is a required "
                "configuration parameter."
            )
            self.logger.error(f"{validation_err_msg} {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        elif not isinstance(fortisiem_server, str):
            err_msg = (
                f"Invalid {PLATFORM_NAME} Server provided in "
                "configuration parameters."
            )
            self.logger.error(f"{validation_err_msg} {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )

        fortisiem_protocol = configuration.get(
            "fortisiem_protocol", ""
        ).strip()
        if not fortisiem_protocol:
            err_msg = (
                f"{PLATFORM_NAME} Protocol is a required "
                "configuration parameter."
            )
            self.logger.error(f"{validation_err_msg} {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        elif (
            not isinstance(fortisiem_protocol, str)
            or fortisiem_protocol not in FORTISIEM_PROTOCOLS
        ):
            err_msg = (
                f"Invalid {PLATFORM_NAME} Protocol provided in "
                "configuration parameters. Supported protocols are: "
                "UDP, TCP, TLS."
            )
            self.logger.error(f"{validation_err_msg} {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )

        fortisiem_port = configuration.get("fortisiem_port", "")
        if not fortisiem_port:
            err_msg = (
                f"{PLATFORM_NAME} Port is a required "
                "configuration parameter."
            )
            self.logger.error(f"{validation_err_msg} {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        elif not isinstance(fortisiem_port, int):
            err_msg = (
                f"Invalid {PLATFORM_NAME} Port provided in "
                "configuration parameters."
            )
            self.logger.error(f"{validation_err_msg} {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        elif not fortisiem_validator.validate_fortisiem_port(fortisiem_port):
            err_msg = (
                f"Invalid {PLATFORM_NAME} Port provided in "
                "configuration parameters. it should be in range 0-65535."
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
        ) or not fortisiem_validator.validate_fortisiem_map(mappings):
            err_msg = "Invalid attribute mapping provided."
            self.logger.error(f"{validation_err_msg} {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )

        fortisiem_certificate = configuration.get(
            "fortisiem_certificate", ""
        ).strip()
        if fortisiem_protocol.upper() == "TLS":
            if not fortisiem_certificate:
                err_msg = (
                    f"{PLATFORM_NAME} Certificate is a required "
                    "configuration parameter when "
                    "TLS is provided in the configuration parameters."
                )
                self.logger.error(f"{validation_err_msg} {err_msg}")
                return ValidationResult(
                    success=False,
                    message=err_msg,
                )
            elif not isinstance(fortisiem_certificate, str):
                err_msg = (
                    f"Invalid {PLATFORM_NAME} Certificate provided "
                    "in configuration parameters."
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
        except Exception:
            err_msg = (
                f"Error occurred while establishing connection with"
                f" {PLATFORM_NAME} Server. Make sure you have provided"
                f" correct {PLATFORM_NAME} Server, Port and {PLATFORM_NAME}"
                " Certificate(if required)."
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
