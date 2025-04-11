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

Microsoft Azure Event Hubs Plugin.
"""

import json
import traceback
import time
from typing import Dict, List

from jsonpath import jsonpath

import os
import sys
kafka_path = os.path.join(os.path.dirname(__file__), 'lib')
if kafka_path not in sys.path:
    sys.path.insert(0, kafka_path)

from kafka import KafkaProducer, KafkaConsumer
from kafka.errors import (
    AuthenticationFailedError,
    AuthenticationMethodNotSupported,
    ClusterAuthorizationFailedError,
    InvalidTopicError,
    KafkaConnectionError,
    KafkaTimeoutError,
    MessageSizeTooLargeError,
    NoBrokersAvailable,
    TopicAuthorizationFailedError,
)

from netskope.common.utils import AlertsHelper, add_user_agent
from netskope.integrations.cls.plugin_base import (
    PluginBase,
    ValidationResult,
    PushResult,
)

from .utils.event_hub_cef_generator import CEFGenerator
from .utils.event_hub_constants import (
    ACKS,
    EVENT_HUBS_SECURITY_PROTOCOL,
    MODULE_NAME,
    TIMEOUT,
    PLATFORM_NAME,
    PLUGIN_VERSION,
    BATCH_SIZE,
    RETRIES,
    TIMEOUT_MS,
    SASL_MECHANISM,
    SASL_PLAIN_USERNAME,
    LINGER_MS,
    VALIDATION_RETRIES,
    LOG_SOURCE_IDENTIFIER,
)
from .utils.event_hub_exceptions import (
    MappingValidationError,
    EmptyExtensionError,
    FieldNotFoundError,
    MicrosoftAzureEventHubsPluginError,
)
from .utils.event_hub_helper import (
    get_azure_event_hubs_mappings,
    get_config_params,
)
from .utils.event_hub_validator import MicrosoftAzureEventHubsValidator


class MicrosoftAzureEventHubsPlugin(PluginBase):
    """The Microsoft Azure Event Hubs plugin implementation class."""

    def __init__(
        self,
        name,
        *args,
        **kwargs,
    ):
        """Initialize MicrosoftAzureEventHubsPlugin class."""
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
            manifest_json = MicrosoftAzureEventHubsPlugin.metadata
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

    def _add_user_agent(self) -> Dict:
        """Add user agent to the the to each request.

        Returns:
            user_agent (str): String containing the User-Agent.
        """

        headers = add_user_agent()
        ce_added_agent = headers.get("User-Agent", "netskope-ce")
        user_agent = "{}-{}-{}-v{}".format(
            ce_added_agent,
            MODULE_NAME.lower(),
            self.plugin_name.lower().replace(" ", "-"),
            self.plugin_version,
        )
        return user_agent

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
        """To Retrieve subtype mappings (mappings for subtypes of
            alerts/events) case insensitively.

        Args:
            mappings: Mapping JSON from which subtypes are to be retrieved
            subtype: Subtype (e.g. DLP for alerts) for which the
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
                # If mapping is present in data, map that field, \
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
            # If mapping is not present, 'default_value' must be there\
            #  because of validation (case #3 and case #5)
            return extension_mapping["default_value"], mapped_field

    def map_json_data(self, mappings, data):
        """Filter the raw data and returns the filtered data.

        Args:
            mappings (list): List of fields to be pushed
            data (list): Data to be mapped (retrieved from Netskope)

        Returns:
            dict: Mapped data based on fields given in mapping file
        """
        if not (mappings and data):
            # If mapping is empty or data is empty return data.
            return data

        mapped_dict = {}
        for key in mappings:
            if key in data:
                mapped_dict[key] = data[key]

        return mapped_dict

    def transform(self, raw_data, data_type, subtype) -> List:
        """To Transform the raw netskope JSON data into target platform
        supported data formats.

        Args:
            raw_data (list): Raw logs retrieved from Netskope Tenant.
            data_type (str): Datatype for logs. e.g. alerts,events,webtx, etc.
            subtype (str): Subtype of alerts/events e.g network,uba,etc.

        Returns:
            List: List of transformed logs.
        """
        skipped_logs = 0
        data_type_sub_type = f"[{data_type}][{subtype}] - "
        log_source_identifier = self.configuration.get(
            "log_source_identifier", LOG_SOURCE_IDENTIFIER
        )
        if not self.configuration.get("transformData", True):
            try:
                (
                    delimiter,
                    cef_version,
                    azure_event_hubs_mappings,
                ) = get_azure_event_hubs_mappings(
                    self.mappings, "json", self.log_prefix
                )
            except KeyError as err:
                error_msg = (
                    f"{data_type_sub_type}"
                    "An error occurred while fetching the mappings."
                )
                self.logger.error(
                    message=(f"{self.log_prefix}: {error_msg} Error: {err}"),
                    details=str(traceback.format_exc()),
                )
                raise MicrosoftAzureEventHubsPluginError(error_msg)
            except MappingValidationError as err:
                error_msg = (
                    f"{data_type_sub_type}"
                    "An error occurred while validating the mapping file."
                )
                self.logger.error(
                    message=(f"{self.log_prefix}: {error_msg} {err}"),
                    details=str(traceback.format_exc()),
                )
                raise MicrosoftAzureEventHubsPluginError(error_msg)
            except Exception as err:
                error_msg = (
                    f"{data_type_sub_type}"
                    "An error occurred while mapping "
                    "data using given json mappings."
                )
                self.logger.error(
                    message=(f"{self.log_prefix}: {error_msg} Error: {err}"),
                    details=str(traceback.format_exc()),
                )
                raise MicrosoftAzureEventHubsPluginError(error_msg)

            try:
                subtype_mapping = self.get_subtype_mapping(
                    azure_event_hubs_mappings["json"][data_type], subtype
                )
                if not subtype_mapping:
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
                            skipped_logs += 1
                    return transformed_data

            except MicrosoftAzureEventHubsPluginError:
                raise
            except Exception as err:
                error_msg = (
                    f"{data_type_sub_type}"
                    "Error occurred while retrieving "
                    f"mappings."
                )
                self.logger.error(
                    message=(f"{self.log_prefix}: {error_msg} Error: {err}"),
                    details=str(traceback.format_exc()),
                )
                raise MicrosoftAzureEventHubsPluginError(error_msg)

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
                    skipped_logs += 1

            if skipped_logs > 0:
                self.logger.info(
                    "{}: {}Plugin couldn't process {} records because they "
                    "either had no data or contained invalid/missing "
                    "fields according to the configured JSON mapping. "
                    "Therefore, the transformation and ingestion for those "
                    "records were skipped.".format(
                        self.log_prefix, data_type_sub_type, skipped_logs
                    )
                )
            return transformed_data
        else:
            try:
                delimiter, cef_version, azure_event_hubs_mappings = (
                    get_azure_event_hubs_mappings(
                        self.mappings, data_type, self.log_prefix
                    )
                )
            except KeyError as err:
                error_msg = (
                    f"{data_type_sub_type}"
                    "An error occurred while "
                    "fetching the mappings."
                )
                self.logger.error(
                    message=(f"{self.log_prefix}: {error_msg} Error: {err}"),
                    details=str(traceback.format_exc()),
                )
                raise MicrosoftAzureEventHubsPluginError(error_msg)
            except MappingValidationError as err:
                error_msg = (
                    f"{data_type_sub_type}"
                    "An error occurred while validating the mapping file."
                )
                self.logger.error(
                    message=(f"{self.log_prefix}: {error_msg} {err}"),
                    details=str(traceback.format_exc()),
                )
                raise MicrosoftAzureEventHubsPluginError(error_msg)
            except Exception as err:
                error_msg = (
                    f"{data_type_sub_type}"
                    "An error occurred while mapping "
                    "data using given json mappings."
                )
                self.logger.error(
                    message=(f"{self.log_prefix}: {error_msg} Error: {err}"),
                    details=str(traceback.format_exc()),
                )
                raise MicrosoftAzureEventHubsPluginError(error_msg)

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
                    azure_event_hubs_mappings[data_type], subtype
                )

            except KeyError as err:
                error_msg = (
                    f"{data_type_sub_type}Unable to find the "
                    "mappings in the mapping file."
                )
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: {error_msg}" f"Error: {err}"
                    ),
                    details=str(traceback.format_exc()),
                )
                raise MicrosoftAzureEventHubsPluginError(error_msg)
            except Exception as err:
                error_msg = (
                    f"{data_type_sub_type}Error occurred while"
                    f" retrieving mappings for subtype {subtype}."
                )
                self.logger.error(
                    message=(f"{self.log_prefix}: {error_msg} Error: {err}"),
                    details=str(traceback.format_exc()),
                )
                raise MicrosoftAzureEventHubsPluginError(error_msg)

            transformed_data = []
            for data in raw_data:
                if not data:
                    # Drop the empty data.
                    skipped_logs += 1
                    continue

                # Generating the CEF header
                try:
                    header, mapped_flag_header = self.get_headers(
                        subtype_mapping["header"], data, data_type, subtype
                    )
                except Exception as err:
                    self.logger.error(
                        message=(
                            "{}: {}Error "
                            "occurred while creating CEF header: {}. "
                            "Transformation of current record will be "
                            "skipped.".format(
                                self.log_prefix, data_type_sub_type, err
                            )
                        ),
                        details=traceback.format_exc(),
                    )
                    skipped_logs += 1
                    continue

                try:
                    extension, mapped_flag_extension = self.get_extensions(
                        subtype_mapping["extension"], data, data_type, subtype
                    )
                except Exception as err:
                    self.logger.error(
                        message=(
                            "{}: {}Error "
                            "occurred while creating CEF extension: {}. "
                            "Transformation of the current record will be "
                            "skipped.".format(
                                self.log_prefix, data_type_sub_type, err
                            )
                        ),
                        details=traceback.format_exc(),
                    )
                    skipped_logs += 1
                    continue

                try:
                    if not (mapped_flag_header or mapped_flag_extension):
                        skipped_logs += 1
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
                            "{}: {}Got empty "
                            "extension during transformation. "
                            "Transformation of current record will be "
                            "skipped.".format(
                                self.log_prefix, data_type_sub_type
                            )
                        ),
                        details=traceback.format_exc(),
                    )
                    skipped_logs += 1
                except Exception as err:
                    self.logger.error(
                        message=(
                            "{}: {}An error "
                            "occurred during transformation. Transformation "
                            "of current record will be skipped. "
                            "Error: {}".format(
                                self.log_prefix, data_type_sub_type, err
                            )
                        ),
                        details=traceback.format_exc(),
                    )
                    skipped_logs += 1

            if skipped_logs > 0:
                self.logger.debug(
                    "{}: {}Plugin couldn't process {} records because they "
                    "either had no data or contained invalid/missing "
                    "fields according to the configured mapping. "
                    "Therefore, the transformation and ingestion for those "
                    "records were skipped.".format(
                        self.log_prefix, data_type_sub_type, skipped_logs
                    )
                )

            return transformed_data

    def push(self, transformed_data, data_type, subtype) -> PushResult:
        """Push the transformed_data to the Microsoft Azure Event\
              Hubs event hub.

        Args:
            transformed_data (list): Transformed data list.
            data_type (str): Datatype for logs. e.g. alerts,events,webtx, etc.
            subtype (str): Subtype of alerts/events e.g network,uba,etc.

        Returns:
            PushResult: Push result object with message and status.
        """
        data_type_sub_type = f"[{data_type}][{subtype}] - "

        self.logger.info(
            f"{self.log_prefix}: "
            f"Initializing the sharing of {len(transformed_data)} "
            f"{data_type_sub_type}logs "
            f"to the {PLATFORM_NAME} server."
        )

        event_hub_name = self.configuration.get("event_hub_name", "").strip()
        successful_log_push_counter, skipped_logs = 0, 0
        try:
            producer = self._get_producer(self.configuration)

        except MicrosoftAzureEventHubsPluginError as exp:
            err_msg = (
                "Error occurred while creating producer "
                "for configured Microsoft Azure event hub."
            )
            self.logger.error(
                message=(
                    f"{self.log_prefix}: {data_type_sub_type}"
                    f"{err_msg} Error: {exp}"
                ),
                details=traceback.format_exc(),
            )
            raise MicrosoftAzureEventHubsPluginError(err_msg)
        except Exception as err:
            err_msg = (
                "Unexpected error occurred while "
                "creating producer for configured Microsoft"
                " Azure Event Hub."
            )
            self.logger.error(
                message=(
                    f"{self.log_prefix}: {data_type_sub_type}"
                    f"{err_msg} Error: {err}"
                ),
                details=str(traceback.format_exc()),
            )
            raise MicrosoftAzureEventHubsPluginError(err_msg)

        # Log the transformed data to given Microsoft Azure Event Hubs server
        for data in transformed_data:
            try:
                if data:
                    producer.send(
                        topic=event_hub_name,
                        value=(
                            data
                            if not isinstance(data, dict)
                            else json.dumps(data)
                        ),
                    )
                    successful_log_push_counter += 1
                else:
                    skipped_logs += 1
            except MessageSizeTooLargeError as error:
                err_msg = (
                    "Message too large error occurred while sending "
                    "logs to Microsoft Azure Event Hubs."
                )
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: {data_type_sub_type}"
                        f"{err_msg} Error: {error}"
                    ),
                    details=traceback.format_exc(),
                )
                raise MicrosoftAzureEventHubsPluginError(err_msg)
            except KafkaTimeoutError as error:
                err_msg = (
                    "Maximum timeout exceeded while sending logs"
                    " to {}.".format(PLATFORM_NAME)
                )
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: {data_type_sub_type}"
                        f"{err_msg} Error: {error}"
                    ),
                    details=traceback.format_exc(),
                )
                raise MicrosoftAzureEventHubsPluginError(err_msg)
            except Exception as e:
                err_msg = (
                    "Error occurred while sending data to {}"
                    " {} event hub. Record will be skipped.".format(
                        PLATFORM_NAME, event_hub_name
                    )
                )
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: {data_type_sub_type}"
                        f"{err_msg} Error: {e}"
                    ),
                    details=traceback.format_exc(),
                )
                raise MicrosoftAzureEventHubsPluginError(err_msg)

        try:
            producer.flush(timeout=TIMEOUT)
            if skipped_logs > 0:
                self.logger.debug(
                    "{}: {}Received empty transformed data for {} log(s)"
                    " hence ingestion of those log(s) will be skipped.".format(
                        self.log_prefix,
                        data_type_sub_type,
                        skipped_logs,
                    )
                )
            log_msg = (
                "{}Successfully ingested {} log(s)"
                ' to "{}" event hub.'.format(
                    data_type_sub_type,
                    successful_log_push_counter,
                    event_hub_name,
                )
            )
            self.logger.info(f"{self.log_prefix}: {log_msg}")
            return PushResult(
                success=True,
                message=log_msg,
            )
        except Exception as exp:
            err_msg = (
                "Error occurred while transferring "
                f"logs to {PLATFORM_NAME}."
            )
            self.logger.error(
                message=(
                    f"{self.log_prefix}: {data_type_sub_type}"
                    f"{err_msg} Error: {exp}"
                ),
                details=traceback.format_exc(),
            )
            raise MicrosoftAzureEventHubsPluginError(err_msg)
        finally:
            producer.close(timeout=TIMEOUT)

    def _get_custom_logger(self, err_msg, is_validation=False, exception=None):
        """
        Get custom logger
        Args:
            err_msg (str): Error message
            is_validation (bool, optional): Validation flag. Defaults to False.
        """
        error_msg = err_msg
        if is_validation:
            error_msg = "Validation error occurred, " + error_msg

        self.logger.error(
            message=f"{self.log_prefix}: {error_msg} Error: {str(exception)}",
            details=str(traceback.format_exc()),
        )

        raise MicrosoftAzureEventHubsPluginError(err_msg)

    def _get_producer(
        self,
        configuration: dict,
        retries: int = RETRIES,
        is_validation: bool = False,
    ):
        """Get Producer for Microsoft Azure Event Hubs.

        Args:
            configuration (dict): Configuration parameters.
            retries (int, optional): Retries. Defaults to RETRIES.
            is_validation (bool, optional): Validation flag. Defaults to False.

        Returns:
            KafkaProducer: Producer for Microsoft Azure Event Hubs
        """
        valaidation_err_msg = (
            "unable to connect to Microsoft Azure "
            "Event hubs, Verify the Namespace Name, Event Hub Name,"
            " Port and Event Hubs Namespace connection string provided"
            " in configuration parameters."
        )
        bootstrap_server, connection_string, event_hub_name, _ = (
            get_config_params(configuration)
        )
        try:
            consumer = KafkaConsumer(
                event_hub_name,
                bootstrap_servers=bootstrap_server,
                security_protocol=EVENT_HUBS_SECURITY_PROTOCOL,
                sasl_mechanism=SASL_MECHANISM,
                sasl_plain_username=SASL_PLAIN_USERNAME,
                sasl_plain_password=connection_string,
                request_timeout_ms=TIMEOUT_MS,
                reconnect_backoff_ms=TIMEOUT_MS,
                client_id=self._add_user_agent(),
            )
            available_event_hubs = consumer.topics()
            event_hub_exists = event_hub_name in available_event_hubs

            if not event_hub_exists:
                err_msg = (
                    "The Event Hub Name provided in configuration"
                    " parameter does not exist in the configured Event Hub"
                    " Namespace."
                )
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg}",
                    details=(
                        f"Available Event Hubs are: {available_event_hubs}"
                    ),
                )
                raise MicrosoftAzureEventHubsPluginError(err_msg)
            producer = KafkaProducer(
                bootstrap_servers=bootstrap_server,
                security_protocol=EVENT_HUBS_SECURITY_PROTOCOL,
                sasl_mechanism=SASL_MECHANISM,
                sasl_plain_username=SASL_PLAIN_USERNAME,
                sasl_plain_password=connection_string,
                batch_size=BATCH_SIZE,
                acks=ACKS,
                retries=retries,
                linger_ms=LINGER_MS,
                request_timeout_ms=TIMEOUT_MS,
                reconnect_backoff_ms=TIMEOUT_MS,
                value_serializer=lambda x: x.encode("utf-8"),
                client_id=self._add_user_agent(),
            )

            return producer
        except InvalidTopicError as error:
            err_msg = (
                "Invalid Event Hub error raised from {}. This "
                "error may caused when plugin attempts to access the"
                " invalid Event Hub or if an attempt is made to write "
                "to an internal Event Hub.".format(PLATFORM_NAME)
            )
            if is_validation:
                err_msg = (
                    "Unable to connect to Event Hub. Verify the"
                    " Event Hub Name provided in "
                    "the configuration parameter."
                )
            self._get_custom_logger(err_msg, is_validation, error)
        except TopicAuthorizationFailedError as error:
            err_msg = (
                "Configured authorization credentials does not have"
                " access to Event Hub {}".format(
                    configuration.get("event_hub_name", "").strip()
                )
            )
            if is_validation:
                err_msg = valaidation_err_msg

            self._get_custom_logger(err_msg, is_validation, error)

        except ClusterAuthorizationFailedError as error:
            err_msg = (
                "Unable to authenticate with the configured {} Security "
                "Protocol and authentication credentials.".format(
                    PLATFORM_NAME
                )
            )
            if is_validation:
                err_msg = valaidation_err_msg

            self._get_custom_logger(err_msg, is_validation, error)

        except KafkaConnectionError as error:
            err_msg = (
                "Error occur while connecting with {} cluster. Verify"
                " the authentication credentials provided in "
                "configuration parameters.".format(PLATFORM_NAME)
            )
            if is_validation:
                err_msg = valaidation_err_msg

            self._get_custom_logger(err_msg, is_validation, error)
        except NoBrokersAvailable as error:
            err_msg = (
                "{} Event Hub is unreachable or {} cluster might be down."
                " Verify {} Event Hub Name and {} Event Hub port"
                " provided in configuration parameters.".format(
                    PLATFORM_NAME, PLATFORM_NAME, PLATFORM_NAME, PLATFORM_NAME
                )
            )
            if is_validation:
                err_msg = valaidation_err_msg

            self._get_custom_logger(err_msg, is_validation, error)
        except AuthenticationMethodNotSupported as error:
            err_msg = (
                "Microsoft Azure Event Hubs does not support the selected"
                " authentication method."
            )
            if is_validation:
                err_msg = valaidation_err_msg

            self._get_custom_logger(err_msg, is_validation, error)
        except AuthenticationFailedError as error:
            err_msg = (
                "Authentication failed. Verify authentication "
                "credentials provided in configuration parameters."
            )
            if is_validation:
                err_msg = valaidation_err_msg

            self._get_custom_logger(err_msg, is_validation, error)
        except MicrosoftAzureEventHubsPluginError:
            raise
        except Exception as exp:
            err_msg = (
                f"Unable to connect to configured {PLATFORM_NAME} Namespace"
                " event hub."
            )
            if is_validation:
                err_msg = valaidation_err_msg

            self._get_custom_logger(err_msg, is_validation, exp)

    def validate(self, configuration: dict) -> ValidationResult:
        """Validate the configuration parameters dict.

        Args:
            configuration (dict): Configuration dictionary.

        Returns:
            ValidationResult: Validation result with validation flag and
            message.
        """
        validation_err_msg = f"{self.log_prefix}: Validation error occurred,"

        microsoft_azure_event_hubs_validator = (
            MicrosoftAzureEventHubsValidator(self.logger, self.log_prefix)
        )

        namespace_name = configuration.get("namespace_name", "").strip()
        if not namespace_name:
            err_msg = (
                "Event Hubs Namespace Name is a required"
                " configuration parameter."
            )
            self.logger.error(f"{validation_err_msg} {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        elif not isinstance(namespace_name, str):
            err_msg = (
                "Invalid Event Hubs Namespace Name provided in configuration"
                " parameters."
            )
            self.logger.error(f"{validation_err_msg} {err_msg}")
            return ValidationResult(success=False, message=err_msg)

        port = configuration.get("port")
        if not port:
            err_msg = "Port is a required configuration parameter."
            self.logger.error(f"{validation_err_msg} {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        elif not isinstance(port, int):
            err_msg = "Invalid Port provided in configuration parameters."
            self.logger.error(f"{validation_err_msg} {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        elif not microsoft_azure_event_hubs_validator.validate_event_hubs_port(
            port
        ):
            err_msg = (
                "Invalid Port provided in configuration "
                "parameters. it should be in range 0-65535."
            )
            self.logger.error(f"{validation_err_msg} {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )

        connection_string = configuration.get("connection_string", "").strip()
        if not connection_string:
            err_msg = (
                "Event Hubs Namespace Connection String is a "
                "required configuration parameter."
            )
            self.logger.error(f"{validation_err_msg} {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        elif not isinstance(connection_string, str):
            err_msg = (
                "Invalid Event Hubs Namespace Connection String "
                "provided in configuration parameters."
            )
            self.logger.error(f"{validation_err_msg} {err_msg}")
            return ValidationResult(success=False, message=err_msg)

        event_hub_name = configuration.get("event_hub_name", "").strip()
        if not event_hub_name:
            err_msg = "Event Hub Name is a required configuration parameter."
            self.logger.error(f"{validation_err_msg} {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        elif not isinstance(event_hub_name, str):
            err_msg = (
                "Invalid Event Hub Name provided in configuration"
                " parameters."
            )
            self.logger.error(f"{validation_err_msg} {err_msg}")
            return ValidationResult(success=False, message=err_msg)

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
                "Invalid Log Source Identifier found in"
                " configuration parameters."
            )
            self.logger.error(
                f"{validation_err_msg} {err_msg}",
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )

        mappings = self.mappings.get("jsonData", None)
        mappings = json.loads(mappings)
        if not (
            isinstance(mappings, dict)
            and microsoft_azure_event_hubs_validator.validate_event_hubs_map(
                mappings
            )
        ):
            err_msg = (
                "Invalid {} attribute mapping found in "
                "the configuration parameters.".format(PLATFORM_NAME)
            )
            self.logger.error(f"{validation_err_msg} Error: {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )

        return self._validate_auth_params(configuration, validation_err_msg)

    def _validate_auth_params(
        self, configuration: dict, validation_err_msg: str
    ):
        """
        Validate auth params

        args:
            configuration: dict
            validation_err_msg: str

        returns:
            ValidationResult
        """

        self.logger.debug(f"{self.log_prefix}: Validating auth credentials,")

        # Validate Server connection.
        try:
            producer = self._get_producer(
                configuration, retries=VALIDATION_RETRIES, is_validation=True
            )
            if producer.bootstrap_connected():
                return ValidationResult(
                    message="Validation successful.", success=True
                )
            else:
                err_msg = (
                    "Unable to connect to configured Microsoft Azure Event"
                    " Hub. Verify the authentication credentials provided in "
                    "configuration parameters."
                )
                self.logger.error(f"{validation_err_msg} {err_msg}")
                return ValidationResult(message=err_msg, success=False)
        except MicrosoftAzureEventHubsPluginError as exp:
            
            return ValidationResult(success=False, message=str(exp))
        except Exception as exp:
            self.logger.error(
                message=f"{validation_err_msg} Error: {exp}",
                details=traceback.format_exc(),
            )
            return ValidationResult(
                success=False,
                message=(
                    "Validation error occurred while creating connection"
                    " with configured {} event hub. Refer logs for more "
                    "details.".format(PLATFORM_NAME)
                ),
            )
