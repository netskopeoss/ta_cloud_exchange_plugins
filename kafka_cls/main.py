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

CLS Kafka Plugin.
"""

import json
import os
import re
from ssl import SSLError
import tempfile
import traceback
from typing import List

from jsonpath import jsonpath
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
from kafka.partitioner import DefaultPartitioner
from netskope.common.utils import AlertsHelper, add_user_agent
from netskope.integrations.cls.plugin_base import (
    PluginBase,
    PushResult,
    ValidationResult,
)

from .utils.kafka_cef_generator import CEFGenerator
from .utils.kafka_constants import (
    ACKS,
    COMPRESSION_TYPE,
    KAFKA_SECURITY_PROTOCOLS,
    LINGER_MS,
    MODULE_NAME,
    TIMEOUT,
    PLATFORM_NAME,
    PLUGIN_VERSION,
    BATCH_SIZE,
    RETRIES,
    TIMEOUT_MS,
)
from .utils.kafka_exceptions import (
    EmptyExtensionError,
    FieldNotFoundError,
    MappingValidationError,
)
from .utils.kafka_helper import get_kafka_mappings
from .utils.kafka_validator import KafkaValidator


class KafkaException(Exception):
    "Custom Exception class for Kafka Plugin."
    pass


class KafkaPlugin(PluginBase):
    """The kafka plugin implementation class."""

    def __init__(
        self,
        name,
        *args,
        **kwargs,
    ):
        """Initialize KafkaPlugin class."""
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
            file_path = os.path.join(
                str(os.path.dirname(os.path.abspath(__file__))),
                "manifest.json",
            )
            with open(file_path, "r") as manifest:
                manifest_json = json.load(manifest)
                plugin_name = manifest_json.get("name", PLATFORM_NAME)
                plugin_version = manifest_json.get("version", PLUGIN_VERSION)
                return (plugin_name, plugin_version)
        except Exception as exp:
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Error occurred while"
                    f" getting plugin details. Error: {exp}"
                ),
                details=traceback.format_exc(),
            )
        return (PLATFORM_NAME, PLUGIN_VERSION)

    def _get_user_agent(self) -> str:
        """Add Client Name to request plugin make.

        Returns:
            str: String containing the Client Name.
        """
        headers = add_user_agent()
        plugin_name = PLATFORM_NAME.lower()
        ce_added_agent = headers.get("User-Agent", "netskope-ce")
        user_agent = "{}-cls-{}-v{}".format(
            ce_added_agent, plugin_name, self.plugin_version
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
        if not self.configuration.get("transformData", True):
            try:
                delimiter, cef_version, kafka_mappings = get_kafka_mappings(
                    self.mappings, "json", self.log_prefix
                )
            except KeyError as err:
                self.logger.error(
                    message=(
                        "{}: Error in {} mapping file. "
                        "Error: {}".format(self.log_prefix, PLATFORM_NAME, err)
                    ),
                    details=traceback.format_exc(),
                )
                raise
            except MappingValidationError as err:
                self.logger.error(
                    message="{}: Validation error occurred. {}".format(
                        self.log_prefix, err
                    ),
                    details=traceback.format_exc(),
                )
                raise
            except Exception as err:
                self.logger.error(
                    message=(
                        "{}: An error occurred while mapping data "
                        "using given json mappings. Error: {}".format(
                            self.log_prefix, err
                        )
                    ),
                    details=traceback.format_exc(),
                )
                raise

            try:
                subtype_mapping = self.get_subtype_mapping(
                    kafka_mappings["json"][data_type], subtype
                )
                if not subtype_mapping:
                    return raw_data

            except Exception:
                self.logger.error(
                    message=(
                        "{}: Error occurred while retrieving mappings "
                        "for datatype: {} (subtype: {}) "
                        "Transformation will be skipped.".format(
                            self.log_prefix, data_type, subtype
                        )
                    ),
                    details=traceback.format_exc(),
                )
                raise

            transformed_data = []

            for data in raw_data:
                mapped_dict = self.map_json_data(subtype_mapping, data)
                if mapped_dict:
                    transformed_data.append(mapped_dict)
                else:
                    skipped_logs += 1

            if skipped_logs > 0:
                self.logger.debug(
                    "{}: Plugin couldn't process {} records because they "
                    "either had no data or contained invalid/missing "
                    "fields according to the configured JSON mapping. "
                    "Therefore, the transformation and ingestion for those "
                    "records were skipped.".format(
                        self.log_prefix, skipped_logs
                    )
                )
            return transformed_data
        else:
            try:
                delimiter, cef_version, kafka_mappings = get_kafka_mappings(
                    self.mappings, data_type, self.log_prefix
                )
            except KeyError as err:
                self.logger.error(
                    message=(
                        "{}: Error in {} mapping file. "
                        "Error: {}".format(self.log_prefix, PLATFORM_NAME, err)
                    ),
                    details=traceback.format_exc(),
                )
                raise
            except MappingValidationError as err:
                self.logger.error(
                    message="{}: Validation error occurred. {}".format(
                        self.log_prefix, err
                    ),
                    details=traceback.format_exc(),
                )
                raise
            except Exception as err:
                self.logger.error(
                    message=(
                        "{}: An error occurred while mapping data "
                        "using given json mappings. Error: {}".format(
                            self.log_prefix, err
                        )
                    ),
                    details=traceback.format_exc(),
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
                    kafka_mappings[data_type], subtype
                )

            except Exception:
                self.logger.error(
                    message=(
                        "{}: Error occurred while retrieving "
                        "mappings for subtype {}. Transformation"
                        " of current batch will be skipped.".format(
                            self.log_prefix, subtype
                        )
                    ),
                    details=traceback.format_exc(),
                )
                return []

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
                            "{}: [{}][{}]- Error "
                            "occurred while creating CEF header: {}. "
                            "Transformation of current record will be "
                            "skipped.".format(
                                self.log_prefix, data_type, subtype, err
                            )
                        ),
                        details=traceback.format_exc(),
                    )

                    continue

                try:
                    extension, mapped_flag_extension = self.get_extensions(
                        subtype_mapping["extension"], data, data_type, subtype
                    )
                except Exception as err:
                    self.logger.error(
                        message=(
                            "{}: [{}][{}]- Error "
                            "occurred while creating CEF extension: {}. "
                            "Transformation of the current record will be "
                            "skipped.".format(
                                self.log_prefix, data_type, subtype, err
                            )
                        ),
                        details=traceback.format_exc(),
                    )

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
                        self.configuration.get(
                            "log_source_identifier", "netskopece"
                        ),
                    )
                    if cef_generated_event:
                        transformed_data.append(cef_generated_event)
                except EmptyExtensionError:
                    self.logger.error(
                        message=(
                            "{}: [{}][{}]- Got empty "
                            "extension during transformation. "
                            "Transformation of current record will be "
                            "skipped.".format(
                                self.log_prefix, data_type, subtype
                            )
                        ),
                        details=traceback.format_exc(),
                    )
                except Exception as err:
                    self.logger.error(
                        message=(
                            "{}: [{}][{}]- An error "
                            "occurred during transformation. Transformation "
                            "of current record will be skipped. "
                            "Error: {}".format(
                                self.log_prefix, data_type, subtype, err
                            )
                        ),
                        details=traceback.format_exc(),
                    )

            if skipped_logs > 0:
                self.logger.debug(
                    "{}: Plugin couldn't process {} records because they "
                    "either had no data or contained invalid/missing "
                    "fields according to the configured mapping. "
                    "Therefore, the transformation and ingestion for those "
                    "records were skipped.".format(
                        self.log_prefix, skipped_logs
                    )
                )

            return transformed_data

    def push(self, transformed_data, data_type, subtype) -> PushResult:
        """Push the transformed_data to the Kafka Topic.

        Args:
            transformed_data (list): Transformed data list.
            data_type (str): Datatype for logs. e.g. alerts,events,webtx, etc.
            subtype (str): Subtype of alerts/events e.g network,uba,etc.

        Returns:
            PushResult: Push result object with message and status.
        """
        kafka_topic_name = self.configuration.get("kafka_topic", "").strip()
        successful_log_push_counter, skipped_logs = 0, 0
        try:
            (
                producer,
                kafka_ca_file,
                kafka_cert_file,
                kafka_key_file,
            ) = self._get_producer(self.configuration)

        except KafkaException as exp:
            err_msg = (
                "Error occurred while creating producer "
                "for configured {} broker.".format(PLATFORM_NAME)
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {exp}",
                details=traceback.format_exc(),
            )
            raise
        except Exception as err:
            self.logger.error(
                message=(
                    "{}: Unexpected error occurred while "
                    " creating producer for configured {} broker. "
                    "Error: {}".format(self.log_prefix, PLATFORM_NAME, err)
                ),
                details=str(traceback.format_exc()),
            )
            raise

        # Log the transformed data to given kafka server
        for data in transformed_data:
            try:
                if data:
                    producer.send(
                        topic=kafka_topic_name,
                        value=data
                        if not isinstance(data, dict)
                        else json.dumps(data),
                    )
                    successful_log_push_counter += 1
                else:
                    skipped_logs += 1
            except MessageSizeTooLargeError as error:
                err_msg = (
                    "Message too large error occurred while sending "
                    "logs to Kafka."
                )
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg} Error: {error}",
                    details=traceback.format_exc(),
                )
            except KafkaTimeoutError as error:
                err_msg = (
                    "Maximum timeout exceeded while sending logs"
                    " to {}.".format(PLATFORM_NAME)
                )
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg} Error: {error}",
                    details=traceback.format_exc(),
                )
            except Exception as exp:
                self.logger.error(
                    message=(
                        "{}: Error occurred during sending data to Kafka {} "
                        "Topic. Record will be skipped. Error: {}".format(
                            self.log_prefix, kafka_topic_name, exp
                        )
                    ),
                    details=traceback.format_exc(),
                )
        try:
            producer.flush(timeout=TIMEOUT)
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
                ' to "{}" topic.'.format(
                    data_type,
                    subtype,
                    successful_log_push_counter,
                    kafka_topic_name,
                )
            )
            self.logger.info(f"{self.log_prefix}: {log_msg}")
            return PushResult(
                success=True,
                message=log_msg,
            )
        except Exception as exp:
            self.logger.error(
                message=(
                    "{}: Error occurred while transferring "
                    "logs to Kafka server. Error: {}".format(
                        self.log_prefix, exp
                    )
                ),
                details=traceback.format_exc(),
            )
            raise KafkaException(exp)
        finally:
            producer.close(timeout=TIMEOUT)
            if (
                kafka_ca_file is not None
                and kafka_cert_file is not None
                and kafka_key_file is not None
            ):
                os.remove(kafka_ca_file)
                os.remove(kafka_cert_file)
                os.remove(kafka_key_file)

    def _create_tmp_file(
        self,
        kafka_ca_certificate: str,
        kafka_client_certificate: str,
        kafka_client_private_key: str,
    ):
        """Create tmp files.

        Args:
            kafka_ca_certificate (str): Kafka CA Certificate
            kafka_client_certificate (str): Kafka Client Certificate
            kafka_client_private_key (str): Kafka Client Private Key
        """
        tmp_ca_file = tempfile.NamedTemporaryFile(delete=False, suffix=".pem")
        tmp_ca_file.write(kafka_ca_certificate.encode())
        tmp_ca_file.close()

        tmp_cert_file = tempfile.NamedTemporaryFile(
            delete=False, suffix=".pem"
        )
        tmp_cert_file.write(kafka_client_certificate.encode())
        tmp_cert_file.close()

        tmp_private_key_file = tempfile.NamedTemporaryFile(
            delete=False, suffix=".pem"
        )
        tmp_private_key_file.write(kafka_client_private_key.encode())
        tmp_private_key_file.close()

        return tmp_ca_file.name, tmp_cert_file.name, tmp_private_key_file.name

    def _get_producer(self, configuration: dict):
        """Get Producer for Kafka.

        Args:
            configuration (dict): Configuration parameters.
        """
        kafka_security_protocol = configuration.get("security_protocol")
        kafka_broker_address = "{}:{}".format(
            configuration.get("kafka_broker", "").strip(),
            configuration.get("kafka_port"),
        )
        kafka_ca_certificate = configuration.get("kafka_ca_certificate")
        kafka_client_certificate = configuration.get(
            "kafka_client_certificate"
        )
        kafka_client_private_key = configuration.get(
            "kafka_client_private_key"
        )
        kafka_ssl_password = configuration.get("kafka_ssl_password", "")
        kafka_topic = configuration.get("kafka_topic", "").strip()
        (
            tmp_ca_file,
            tmp_cert_file,
            tmp_private_key_file,
        ) = self._create_tmp_file(
            kafka_ca_certificate,
            kafka_client_certificate,
            kafka_client_private_key,
        )
        try:
            if kafka_security_protocol == "PLAINTEXT":
                consumer = KafkaConsumer(
                    bootstrap_servers=kafka_broker_address,
                    security_protocol=kafka_security_protocol,
                    request_timeout_ms=TIMEOUT_MS,
                )
                available_topics = consumer.topics()
                topic_exists = kafka_topic in available_topics

                if not topic_exists:
                    err_msg = (
                        "The Kafka Topic Name provided in configuration"
                        " parameter does not exist on configured Kafka"
                        " cluster."
                    )
                    self.logger.error(f"{self.log_prefix}: {err_msg}")
                    raise KafkaException(err_msg)
                producer = (
                    KafkaProducer(
                        bootstrap_servers=kafka_broker_address,
                        value_serializer=lambda x: x.encode("utf-8"),
                        acks=ACKS,
                        partitioner=DefaultPartitioner(),
                        retries=RETRIES,
                        linger_ms=LINGER_MS,
                        client_id=self._get_user_agent(),
                        batch_size=BATCH_SIZE,
                        compression_type=COMPRESSION_TYPE,
                        request_timeout_ms=TIMEOUT_MS,
                    ),
                    tmp_ca_file,
                    tmp_cert_file,
                    tmp_private_key_file,
                )
            elif kafka_security_protocol == "SSL":
                # If selected security protocol is SSL use the certificates
                # provided in configuration parameters.
                consumer = KafkaConsumer(
                    bootstrap_servers=kafka_broker_address,
                    security_protocol=kafka_security_protocol,
                    ssl_cafile=tmp_ca_file,
                    ssl_certfile=tmp_cert_file,
                    ssl_keyfile=tmp_private_key_file,
                    ssl_password=kafka_ssl_password,
                    request_timeout_ms=TIMEOUT_MS,
                )

                available_topics = (
                    consumer.topics()
                )  # Returns the list of topics present on Kafka cluster
                topic_exists = (
                    kafka_topic in available_topics
                )  # Check whether the topic is present on
                # Kafka cluster or not.

                if not topic_exists:
                    err_msg = (
                        "The Kafka Topic Name provided in configuration "
                        "parameter does not exist on configured Kafka cluster."
                    )
                    self.logger.error(f"{self.log_prefix}: {err_msg}")
                    raise KafkaException(err_msg)
                producer = (
                    KafkaProducer(
                        bootstrap_servers=[
                            "{}:{}".format(
                                configuration.get("kafka_broker", "").strip(),
                                configuration.get("kafka_port"),
                            )
                        ],
                        value_serializer=lambda x: x.encode("utf-8"),
                        acks=ACKS,
                        partitioner=DefaultPartitioner(),
                        retries=RETRIES,
                        client_id=self._get_user_agent(),
                        batch_size=BATCH_SIZE,
                        linger_ms=LINGER_MS,
                        compression_type=COMPRESSION_TYPE,
                        security_protocol=kafka_security_protocol,
                        ssl_cafile=tmp_ca_file,
                        ssl_certfile=tmp_cert_file,
                        ssl_keyfile=tmp_private_key_file,
                        ssl_password=kafka_ssl_password,
                        request_timeout_ms=TIMEOUT_MS,
                    ),
                    tmp_ca_file,
                    tmp_cert_file,
                    tmp_private_key_file,
                )
            return producer
        except InvalidTopicError as error:
            err_msg = (
                "Invalid topic error raised from {} server. This "
                "error may caused when plugin attempts to access the"
                " invalid topic or if an attempt is made to write "
                "to an internal topic.".format(PLATFORM_NAME)
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=str(error),
            )
            raise KafkaException(err_msg)
        except TopicAuthorizationFailedError as error:
            err_msg = (
                "Configured authorization credentials does not have"
                " access to topic {}".format(
                    configuration.get("kafka_topic", "").strip()
                )
            )
            self.logger.error(
                f"{self.log_prefix}: {err_msg}", details=str(error)
            )
            raise KafkaException(err_msg)
        except ClusterAuthorizationFailedError:
            err_msg = (
                "Unable to authenticate with the configured {} Security "
                "Protocol and authentication credentials.".format(
                    PLATFORM_NAME
                )
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}.",
                details=traceback.format_exc(),
            )
            raise KafkaException(err_msg)
        except KafkaConnectionError as error:
            err_msg = (
                "Error occur while connecting with {} cluster. Verify"
                " the authentication credentials provided in "
                "configuration parameters.".format(PLATFORM_NAME)
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}", details=str(error)
            )
            raise KafkaException(err_msg)
        except NoBrokersAvailable as error:
            err_msg = (
                "{} Broker is unreachable or {} cluster might be down."
                " Verify {} Broker Address and {} Port"
                " provided in configuration parameters.".format(
                    PLATFORM_NAME, PLATFORM_NAME, PLATFORM_NAME, PLATFORM_NAME
                )
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {error}",
                details=traceback.format_exc(),
            )
            raise KafkaException(err_msg)
        except AuthenticationMethodNotSupported as error:
            err_msg = (
                "Kafka Cluster does not support the selected"
                " authentication method."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}", details=str(error)
            )
            raise KafkaException(err_msg)
        except AuthenticationFailedError as error:
            err_msg = (
                "Authentication failed. Verify authentication "
                "credentials provided in configuration parameters."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}", details=str(error)
            )
            raise KafkaException(err_msg)
        except SSLError as error:
            err_msg = (
                "Authentication failed. Verify Kafka CA Certificate, "
                "Kafka Client Certificate, Kafka Client Private Key and Kafka"
                " SSL Private Key Password provided in "
                "configuration parameters."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}", details=str(error)
            )
            raise KafkaException(err_msg)
        except KafkaException:
            raise
        except Exception as exp:
            err_msg = (
                "Unable to connect to configured {} broker. "
                "Error: {}".format(PLATFORM_NAME, exp)
            )
            self.logger.error(
                f"{self.log_prefix}: {err_msg}",
                details=str(traceback.format_exc()),
            )
            raise Exception(err_msg)

    def validate(self, configuration: dict) -> ValidationResult:
        """Validate the configuration parameters dict.

        Args:
            configuration (dict): Configuration dictionary.

        Returns:
            ValidationResult: Validation result with validation flag and
            message.
        """
        kafka_validator = KafkaValidator(self.logger, self.log_prefix)

        kafka_broker = configuration.get("kafka_broker", "").strip()
        if "kafka_broker" not in configuration or not kafka_broker:
            err_msg = (
                "{} Broker Address is a required configuration"
                " parameter.".format(PLATFORM_NAME)
            )
            self.logger.error(
                "{}: Validation error occurred. Error: {}".format(
                    self.log_prefix, err_msg
                )
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        elif not isinstance(kafka_broker, str):
            err_msg = (
                "Invalid {} Broker Address provided in configuration"
                " parameters.".format(PLATFORM_NAME)
            )
            self.logger.error(
                "{}: Validation error occurred. Error: {}".format(
                    self.log_prefix,
                    err_msg,
                )
            )
            return ValidationResult(success=False, message=err_msg)

        kafka_port = configuration.get("kafka_port")
        if "kafka_port" not in configuration or kafka_port is None:
            err_msg = (
                f"{PLATFORM_NAME} Port is a required configuration parameter."
            )
            self.logger.error(
                "{}: Validation error occurred. Error: {}".format(
                    self.log_prefix, err_msg
                )
            )
            return ValidationResult(success=False, message=err_msg)

        elif not kafka_validator.validate_kafka_port(kafka_port):
            err_msg = (
                "Invalid {} Port provided in "
                "configuration parameters. Value should be an integer"
                " in range 1 to 65535.".format(PLATFORM_NAME)
            )
            self.logger.error(
                "{}: Validation error occurred. Error: {}".format(
                    self.log_prefix, err_msg
                )
            )
            return ValidationResult(success=False, message=err_msg)

        security_protocol = configuration.get("security_protocol")

        if "security_protocol" not in configuration or not security_protocol:
            err_msg = (
                "Kafka Security Protocol is a required "
                "configuration parameter."
            )
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            return ValidationResult(success=False, message=err_msg)

        elif security_protocol not in KAFKA_SECURITY_PROTOCOLS:
            err_msg = (
                "Invalid Kafka Security Protocol provided in configuration "
                "parameters. Accepted value are {}.".format(
                    KAFKA_SECURITY_PROTOCOLS
                )
            )
            self.logger.error(f"{self.log_prefix}: {err_msg}")

            return ValidationResult(success=False, message=err_msg)

        if security_protocol == "SSL":
            kafka_ca_certificate = configuration.get("kafka_ca_certificate")
            if (
                "kafka_ca_certificate" not in configuration
                or not kafka_ca_certificate
                or kafka_ca_certificate is None
            ):
                err_msg = (
                    "Kafka CA Certificate is a required configuration"
                    " parameter if SSL is selected as Kafka Security Protocol."
                )
                self.logger.error(f"{self.log_prefix}: {err_msg}")
                return ValidationResult(success=False, message=err_msg)

            elif not isinstance(kafka_ca_certificate, str):
                err_msg = (
                    "Invalid Kafka CA Certificate provided in "
                    "configuration parameters."
                )
                self.logger.error(f"{self.log_prefix}: {err_msg}")
                return ValidationResult(success=False, message=err_msg)

            kafka_client_certificate = configuration.get(
                "kafka_client_certificate"
            )
            if (
                "kafka_client_certificate" not in configuration
                or not kafka_client_certificate
                or kafka_client_certificate is None
            ):
                err_msg = (
                    "Kafka Client Certificate is a required configuration"
                    " parameter if SSL is selected as Kafka Security Protocol."
                )
                self.logger.error(f"{self.log_prefix}: {err_msg}")
                return ValidationResult(success=False, message=err_msg)

            elif not isinstance(kafka_client_certificate, str):
                err_msg = (
                    "Invalid Kafka Client Certificate provided"
                    " in configuration parameters."
                )
                self.logger.error(f"{self.log_prefix}: {err_msg}")
                return ValidationResult(success=False, message=err_msg)

            kafka_client_private_key = configuration.get(
                "kafka_client_private_key"
            )
            if (
                "kafka_client_private_key" not in configuration
                or not kafka_client_private_key
                or kafka_client_private_key is None
            ):
                err_msg = (
                    "Kafka Client Private Key is a required configuration"
                    " parameter if SSL is selected as Kafka Security Protocol."
                )
                self.logger.error(f"{self.log_prefix}: {err_msg}")
                return ValidationResult(success=False, message=err_msg)

            elif not isinstance(kafka_client_private_key, str):
                err_msg = (
                    "Invalid Kafka Client Private Key provided in "
                    "configuration parameters."
                )
                self.logger.error(f"{self.log_prefix}: {err_msg}")
                return ValidationResult(success=False, message=err_msg)

            kafka_ssl_password = configuration.get("kafka_ssl_password", "")

            if not isinstance(kafka_ssl_password, str):
                err_msg = (
                    "Invalid Kafka SSL Private Key Password provided"
                    " in configuration parameters."
                )
                self.logger.error(f"{self.log_prefix}: {err_msg}")
                return ValidationResult(success=False, message=err_msg)

        kafka_topic = configuration.get("kafka_topic", "").strip()
        if "kafka_topic" not in configuration or not kafka_topic:
            err_msg = (
                "{} Topic is a required configuration"
                " parameter.".format(PLATFORM_NAME)
            )
            self.logger.error(
                "{}: Validation error occurred. Error: {}".format(
                    self.log_prefix, err_msg
                )
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )

        elif not isinstance(kafka_topic, str) or bool(
            re.search(r"\s", kafka_topic)
        ):
            err_msg = (
                "Invalid {} Topic provided in configuration"
                " parameters. Value should be an string without any "
                "spaces.".format(PLATFORM_NAME)
            )
            self.logger.error(
                "{}: Validation error occurred. Error: {}".format(
                    self.log_prefix,
                    err_msg,
                )
            )
            return ValidationResult(success=False, message=err_msg)

        mappings = self.mappings.get("jsonData", None)
        mappings = json.loads(mappings)
        if not (
            isinstance(mappings, dict)
            and kafka_validator.validate_kafka_map(mappings)
        ):
            self.logger.error(
                "{}: Validation error occurred. Error: "
                "Invalid {} attribute mapping found in "
                "the configuration parameters.".format(
                    self.log_prefix, PLATFORM_NAME
                )
            )
            return ValidationResult(
                success=False,
                message=f"Invalid {PLATFORM_NAME} attribute mapping provided.",
            )

        log_source_identifier = configuration.get(
            "log_source_identifier", ""
        ).strip()

        if (
            "log_source_identifier" not in configuration
            or not log_source_identifier
        ):
            err_msg = (
                "Log Source Identifier is a required configuration parameter."
            )
            self.logger.error(
                "{}: Validation error occurred. Error: {}".format(
                    self.log_prefix, err_msg
                )
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )

        elif not isinstance(log_source_identifier, str):
            err_msg = (
                "Invalid Log Source Identifier found in "
                "configuration parameters."
            )
            self.logger.error(
                "{}: Validation error occurred. Error: {}".format(
                    self.log_prefix, err_msg
                )
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        # Validate Server connection.
        kafka_ca_file, kafka_cert_file, kafka_key_file = None, None, None
        try:
            (
                producer,
                kafka_ca_file,
                kafka_cert_file,
                kafka_key_file,
            ) = self._get_producer(configuration)
            if producer.bootstrap_connected():
                producer.close(timeout=TIMEOUT)
                return ValidationResult(
                    message="Validation successful.", success=True
                )
            else:
                err_msg = (
                    "Unable to connect to configured {} broker. Verify the"
                    " authentication credentials provided in "
                    "configuration parameters.".format(PLATFORM_NAME)
                )
                self.logger.error(f"{self.log_prefix}: {err_msg}")
                return ValidationResult(message=err_msg, success=False)
        except KafkaException as exp:
            self.logger.error(
                message=f"{self.log_prefix}: Validation error occurred. {exp}",
                details=traceback.format_exc(),
            )
            return ValidationResult(success=False, message=str(exp))
        except Exception as exp:
            self.logger.error(
                message="{}: Validation error occurred. {}".format(
                    self.log_prefix, exp
                ),
                details=traceback.format_exc(),
            )
            return ValidationResult(
                success=False,
                message=(
                    "Validation error occurred while creating connection"
                    " with configured {} broker. Refer logs for more "
                    "details.".format(PLATFORM_NAME)
                ),
            )
        finally:
            if (
                kafka_ca_file is not None
                and kafka_cert_file is not None
                and kafka_key_file is not None
            ):
                os.remove(kafka_ca_file)
                os.remove(kafka_cert_file)
                os.remove(kafka_key_file)
