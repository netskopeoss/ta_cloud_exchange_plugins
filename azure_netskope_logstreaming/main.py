"""Azure Netskope LogStreaming CLS plugin.

BSD 3-Clause License

Copyright (c) 2021, Netskope OSS
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

1. Redistributions of source code must retain the above copyright
   notice, this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright
   notice, this list of conditions and the following disclaimer in the
   documentation and/or other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its
   contributors may be used to endorse or promote products derived from
   this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
"""

import gzip
import threading
import traceback
import json
import pandas as pd
import csv
import time
from typing import List, Tuple, Dict, Any, Generator, Union
from io import BytesIO, StringIO
import base64

from packaging import version
from netskope.common.api import __version__ as CE_VERSION
from netskope.common.utils import (
    Notifier,
)
from netskope.common.utils.plugin_provider_helper import PluginProviderHelper
from netskope.common.models.other import ActionType
from netskope.integrations.cls.plugin_base import (
    PluginBase,
    ValidationResult,
)
from netskope.common.utils import back_pressure
from netskope.common.models import NetskopeFieldType, FieldDataType

from .utils.client import AzureNLSClient
from .utils.exceptions import AzureNLSException
from .utils.helper import extract_container_name

from .utils.constants import (
    MODULE_NAME,
    PLUGIN_VERSION,
    PLATFORM_NAME,
    MAINTENANCE_PULL,
    HISTORICAL_PULL,
    TYPE_EVENT,
    RESULT,
    BACK_PRESSURE_WAIT_TIME,
    BATCH_SIZE,
    NLS_EVENT_MAPPINGS,
    ALERTS,
    EVENTS,
    WEBTX,
    STRING_FIELDS,
    TYPE_ALERT,
    TYPE_WEBTX,
    PLUGIN_NAME,
    MESSAGES_PER_PAGE,
    VISIBILITY_TIMEOUT,
    VALIDATION_ERROR_MSG,
    MAXIMUM_CORE_VERSION,
)

from .lib.azure.core.exceptions import (
    AzureError,
    HttpResponseError,
    ServiceRequestError,
)

plugin_provider_helper = PluginProviderHelper()
notifier = Notifier()


class AzureNetskopeLogStreaming(PluginBase):
    """Azure Netskope LogStreaming ProviderPlugin class."""

    def __init__(
        self,
        name,
        *args,
        **kwargs,
    ):
        """Init function.

        Args:
            name (str): Configuration Name.
        """
        super().__init__(
            name,
            *args,
            **kwargs,
        )
        self.should_exit = threading.Event()
        self.plugin_name, self.plugin_version = self._get_plugin_info()
        self.log_prefix = f"{MODULE_NAME} {self.plugin_name}"
        if name:
            self.log_prefix = f"{self.log_prefix} [{name}]"
        self.resolution_support = version.parse(CE_VERSION) > version.parse(
            MAXIMUM_CORE_VERSION
        )
        self._patch_logger_methods()

    def _patch_logger_methods(self):
        """Patch logger.error to pass resolution= only on CE > 5.1.2.

        CE versions up to and including 5.1.2 do not accept the
        resolution keyword argument.  This wrapper swallows it
        silently on older installs so the plugin runs on both old
        and new CE versions without branching at every call site.
        """
        original_error = self.logger.error

        def patched_error(
            message=None, details=None, resolution=None, **kwargs
        ):
            log_kwargs = {"message": message}
            if details:
                log_kwargs["details"] = details
            if resolution and self.resolution_support:
                log_kwargs["resolution"] = resolution
            log_kwargs.update(kwargs)
            return original_error(**log_kwargs)

        self.logger.error = patched_error

    def _get_plugin_info(self) -> Tuple[str, str]:
        """Get plugin name and version from manifest.

        Returns:
            tuple: Tuple of plugin name and version from manifest.
        """
        try:
            manifest_json = AzureNetskopeLogStreaming.metadata
            plugin_name = manifest_json.get("name", PLUGIN_NAME)
            plugin_version = manifest_json.get("version", PLUGIN_VERSION)
            return (plugin_name, plugin_version)
        except Exception as exp:
            self.logger.error(
                message=(
                    "{} {}: Error occurred while getting plugin "
                    "details. Error: {}".format(MODULE_NAME, PLUGIN_NAME, exp)
                ),
                details=traceback.format_exc(),
            )
        return (PLUGIN_NAME, PLUGIN_VERSION)

    def chunk_size(self) -> int:
        """Return the optimal chunk size for this plugin.

        Returns:
            int: Number of records per batch yielded to the framework.
        """
        return BATCH_SIZE

    def transform(
        self,
        raw_data: List[Dict[str, Any]],
        data_type: str,
        subtype: str,
        **kwargs,
    ) -> List:
        """Transform raw Netskope data to the target platform format.

        Each record is processed individually so that a single malformed
        record does not abort the entire batch.

        Args:
            raw_data (List): Raw data to be transformed.
            data_type (str): Data type of the raw data.
            subtype (str): Subtype of the raw data.

        Returns:
            List: List of transformed data.
        """
        transformed = []
        for record in raw_data:
            try:
                transformed.append(record)
            except Exception as e:
                self.logger.debug(
                    message=(
                        f"{self.log_prefix}: Skipping "
                        f"{data_type}/{subtype} record due to "
                        f"transformation error. Error: {e}"
                    ),
                    details=traceback.format_exc(),
                )
        return transformed

    def _validate_parameters(
        self,
        field_name: str,
        field_value: Union[str, List, bool, int],
        field_type: type,
        is_required: bool = True,
    ) -> Union[ValidationResult, None]:
        """Validate a single configuration parameter.

        Logs the error and returns a failed ValidationResult when
        validation fails; returns None when the value is acceptable.
        The caller can use a walrus-operator pattern to short-circuit.

        Args:
            field_name: Human-readable label used in error messages.
            field_value: Value to validate.
            field_type: Expected Python type.
            is_required: Whether the field must be non-empty.

        Returns:
            ValidationResult on failure, None on success.
        """
        if field_type is str and isinstance(field_value, str):
            field_value = field_value.strip()
        if (
            is_required
            and not isinstance(field_value, int)
            and not field_value
        ):
            err_msg = f"'{field_name}' is a required configuration parameter."
            self.logger.error(
                message=(
                    f"{self.log_prefix}: {VALIDATION_ERROR_MSG}" f"{err_msg}"
                ),
                resolution=(
                    f"Ensure that the {field_name} is provided in "
                    "the plugin configuration parameters."
                ),
            )
            return ValidationResult(success=False, message=err_msg)
        if not isinstance(field_value, field_type):
            err_msg = (
                f"Invalid value provided for the configuration "
                f"parameter '{field_name}'."
            )
            self.logger.error(
                message=(
                    f"{self.log_prefix}: {VALIDATION_ERROR_MSG}" f"{err_msg}"
                ),
                resolution=(
                    f"Ensure that the {field_name} field value is "
                    "valid and of the correct type."
                ),
            )
            return ValidationResult(success=False, message=err_msg)
        return None

    def _validate_connection_string_auth(
        self,
        configuration: dict,
    ) -> Union[ValidationResult, None]:
        """Validate the connection string via live blob service connectivity.

        Returns None on success, ValidationResult(success=False) on failure.
        """
        try:
            azure_helper = AzureNLSClient(
                configuration,
                self.logger,
                self.log_prefix,
            )
            azure_helper.get_blob_service_client(is_validation=True)
            return None
        except AzureNLSException as exp:
            return ValidationResult(success=False, message=str(exp))
        except Exception as err:
            err_msg = (
                f"Error occurred while creating {PLATFORM_NAME} "
                f"blob service client object for {PLUGIN_NAME}. "
                f"Verify the {PLATFORM_NAME} Storage Account "
                "Connection String provided in the configuration "
                "parameters."
            )
            self.logger.error(
                message=(
                    f"{self.log_prefix}: {VALIDATION_ERROR_MSG}"
                    f"{err_msg} Error: {err}"
                ),
                details=traceback.format_exc(),
                resolution=(
                    "Ensure that the Microsoft Azure Storage Account"
                    " Connection String is correct and accessible "
                    "from the CE host."
                ),
            )
            return ValidationResult(success=False, message=err_msg)

    def _validate_queue_exists(
        self,
        configuration: dict,
        queue_name: str,
    ) -> Union[ValidationResult, None]:
        """Validate that the queue exists in the Azure Storage Account.

        Returns None on success, ValidationResult(success=False) on failure.
        """
        try:
            azure_helper = AzureNLSClient(
                configuration,
                self.logger,
                self.log_prefix,
            )
            queue_service_client = azure_helper.get_queue_service_client()
            queues = queue_service_client.list_queues()
            for queue in queues:
                if queue.name == queue_name:
                    return None
            err_msg = (
                f"Invalid {PLATFORM_NAME} Data Storage Queue Name "
                f"provided. The queue '{queue_name}' does not exist"
                f" in the {PLATFORM_NAME} Storage Account."
            )
            self.logger.error(
                message=(
                    f"{self.log_prefix}: {VALIDATION_ERROR_MSG}"
                    f"{err_msg}"
                ),
                details="",
                resolution=(
                    f"Ensure that the queue '{queue_name}' exists "
                    f"under {PLATFORM_NAME} Storage Account > "
                    "Queues."
                ),
            )
            return ValidationResult(success=False, message=err_msg)
        except AzureNLSException as exp:
            return ValidationResult(success=False, message=str(exp))
        except Exception as err:
            err_msg = (
                f"Error occurred while listing {PLATFORM_NAME} "
                f"Storage queues for {PLUGIN_NAME}."
            )
            self.logger.error(
                message=(
                    f"{self.log_prefix}: {VALIDATION_ERROR_MSG}"
                    f"{err_msg} Error: {err}"
                ),
                details=traceback.format_exc(),
                resolution=(
                    "Ensure that the Microsoft Azure Storage Account"
                    " Connection String is correct and Queue is accessible."
                ),
            )
            return ValidationResult(success=False, message=err_msg)

    def validate(self, configuration: Dict[str, Any]) -> ValidationResult:
        """Validate the Plugin configuration parameters.

        Args:
            configuration (dict): Dict object having all the Plugin
                configuration parameters.

        Returns:
            ValidationResult object with success flag and message.
        """
        # Validate Azure Storage Account Connection String
        connection_string = configuration.get("connection_string", "")
        if validation_result := self._validate_parameters(
            field_name=(
                f"{PLATFORM_NAME} Storage Account Connection String"
            ),
            field_value=connection_string,
            field_type=str,
        ):
            return validation_result

        # Validate connection string via live blob service connectivity
        if validation_result := self._validate_connection_string_auth(
            configuration
        ):
            return validation_result

        # Validate Azure Queue Name
        queue_name = configuration.get("queue_name", "").strip()
        if validation_result := self._validate_parameters(
            field_name=f"{PLATFORM_NAME} Data Storage Queue Name",
            field_value=queue_name,
            field_type=str,
        ):
            return validation_result

        # Validate the queue exists in the Storage Account
        if validation_result := self._validate_queue_exists(
            configuration, queue_name
        ):
            return validation_result

        validation_msg = f"Validation successful for {PLUGIN_NAME} plugin."
        self.logger.debug(
            f"{self.log_prefix}: {validation_msg}"
        )
        return ValidationResult(success=True, message=validation_msg)

    def _get_messages_from_response(
        self, azure_helper: AzureNLSClient, queue_client
    ) -> List:
        """Receive messages from the queue and extract blob references.

        Deletes each processed message from the queue after the blob
        URL is successfully extracted.

        Args:
            azure_helper: AzureNLSClient for get_queue_messages().
            queue_client: QueueClient used for delete_message().

        Returns:
            List of (container_name, blob_name) tuples for download.
        """
        messages = azure_helper.get_queue_messages(
            queue_client=queue_client,
            messages_per_page=MESSAGES_PER_PAGE,
            visibility_timeout=VISIBILITY_TIMEOUT,
        )
        messages_list = []
        try:
            for msg_batch in messages.by_page():
                for msg in msg_batch:
                    try:
                        # Decode from Base64
                        decoded_bytes = base64.b64decode(msg.content)
                        decoded_str = decoded_bytes.decode("utf-8")

                        # Parse JSON
                        event_data = json.loads(decoded_str)
                        blob_url = event_data.get("data", {}).get("url", "")
                        if blob_url:
                            container_name = extract_container_name(blob_url)
                            blob_name = (
                                blob_url.split(f"/{container_name}/")[1]
                                if container_name
                                else None
                            )
                            if blob_name:
                                messages_list.append(
                                    (container_name, blob_name)
                                )
                                try:
                                    # Delete the message after processing
                                    queue_client.delete_message(
                                        message=msg.id,
                                        pop_receipt=msg.pop_receipt,
                                    )
                                except Exception as e:
                                    err_msg = (
                                        "Error occurred while "
                                        "deleting message "
                                        "containing blob url: "
                                        f"{blob_url} from "
                                        f"{PLATFORM_NAME} "
                                        "Storage Queue."
                                    )
                                    self.logger.error(
                                        message=(
                                            f"{self.log_prefix}:"
                                            f" {err_msg}"
                                            f" Error: {e}"
                                        ),
                                        details=traceback.format_exc(),
                                    )
                                    continue
                    except Exception as e:
                        err_msg = (
                            "Unexpected error occurred while "
                            "parsing a message from "
                            f"{PLATFORM_NAME} Storage Queue."
                        )
                        self.logger.error(
                            message=(
                                f"{self.log_prefix}: {err_msg}" f" Error: {e}"
                            ),
                            details=traceback.format_exc(),
                        )
                        continue

        except (ServiceRequestError, HttpResponseError, AzureError) as e:
            err_msg = (
                "Error occurred while communicating with "
                f"{PLATFORM_NAME} Storage Queue."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {e}",
                details=traceback.format_exc(),
                resolution=(
                    "Ensure that the CE host has network "
                    "connectivity to the Azure Storage endpoint "
                    "and that the Connection String is valid and "
                    "has not expired."
                ),
            )
            raise AzureNLSException(err_msg)
        except Exception as e:
            err_msg = (
                "Unexpected error occurred while receiving "
                f"messages from {PLATFORM_NAME} Storage Queue."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {e}",
                details=traceback.format_exc(),
                resolution=(
                    "Ensure that the Azure Storage Queue is "
                    "properly configured and accessible."
                ),
            )
            raise AzureNLSException(err_msg)

        return messages_list

    def _process_incident_event(
        self, incident_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Convert known integer fields to strings for incident data.

        Args:
            incident_data: Incident record dict to be processed.
        """
        for key in STRING_FIELDS:
            if key in incident_data and incident_data[key]:
                incident_data[key] = str(incident_data[key])
        return incident_data

    def _bifurcate_data(
        self,
        data_list: List[Dict[str, Any]],
        container_name: str,
        blob_name: str,
    ) -> Generator[Tuple[Dict[str, Any], str, str], None, None]:
        """Categorise records into alerts, events, or webtx groups.

        Args:
            data_list: Parsed records from a single CSV chunk.
            container_name: Azure container name (for log messages).
            blob_name: Blob file name (for log messages).
        """
        result = {}
        skip_count = 0
        for data in data_list:
            try:
                record_type = data.get("record_type")
                alert_type = data.get("alert_type")
                if record_type and record_type in NLS_EVENT_MAPPINGS:
                    target_key = NLS_EVENT_MAPPINGS.get(record_type)
                    if record_type == "incident":
                        incident_data = self._process_incident_event(data)
                        result.setdefault(target_key, []).append(incident_data)
                    else:
                        result.setdefault(target_key, []).append(data)
                elif (
                    record_type
                    and record_type == "alert"
                    and alert_type
                    and alert_type in NLS_EVENT_MAPPINGS
                ):
                    target_key = NLS_EVENT_MAPPINGS.get(alert_type)
                    result.setdefault(target_key, []).append(data)
                elif data.get("x-cs-timestamp"):
                    result.setdefault("v2", []).append(data)
                else:
                    skip_count += 1
            except Exception as e:
                self.logger.debug(
                    message=(
                        f"{self.log_prefix}: Skipped a record from"
                        f" file '{blob_name}' due to unexpected "
                        f"error. Error: {e}"
                    ),
                    details=traceback.format_exc(),
                )
                skip_count += 1
                continue

        if skip_count > 0:
            self.logger.info(
                f"{self.log_prefix}: Skipped {skip_count} out of "
                f"{len(data_list)} logs from file '{blob_name}' in"
                f" container '{container_name}' due to invalid data"
                " or unsupported subtype."
            )

        for subtype, data in result.items():
            if data:
                # Reset for every subtype — prevents a stale value
                # from a previous iteration being emitted when a
                # subtype is unrecognised.
                datatype = None
                if subtype.lower() in ALERTS:
                    datatype = "alerts"
                elif subtype.lower() in EVENTS:
                    datatype = "events"
                elif subtype.lower() in WEBTX:
                    datatype = "webtx"

                yield data, datatype, subtype

    def _process_gzipped_csv_in_batches(
        self, data: bytes, container_name: str, blob_name: str, batch_size: int
    ) -> Generator[Tuple[Dict[str, Any], str, str], None, None]:
        """Decompress and parse a gzip-compressed CSV blob in batches.

        Args:
            data (bytes): Raw gzip-compressed blob content.
            container_name: Azure container name (for log messages).
            blob_name: Blob file name (for log messages).
            batch_size: Number of CSV rows per batch.
        """
        try:
            with gzip.GzipFile(fileobj=BytesIO(data), mode="rb") as gz:

                # Read the CSV content
                csv_content = gz.read().decode("utf-8")
                # Automatically detect delimiter
                sniffer = csv.Sniffer()
                # Default delimiter
                delimiter = ","
                try:
                    delimiter = sniffer.sniff(
                        csv_content.split("\n")[0]
                    ).delimiter
                except Exception as e:
                    err_msg = (
                        "Error occurred while detecting delimiter "
                        "from CSV file. Using default delimiter ','."
                    )
                    self.logger.error(
                        message=(
                            f"{self.log_prefix}: {err_msg}" f" Error: {e}"
                        ),
                        details=traceback.format_exc(),
                        resolution=(
                            "Ensure that the blob file is a valid "
                            "gzip-compressed CSV produced by "
                            "Netskope Log Streaming."
                        ),
                    )

                for chunk in pd.read_csv(
                    StringIO(csv_content),
                    delimiter=delimiter,
                    engine="python",
                    on_bad_lines="skip",
                    chunksize=batch_size,
                ):
                    chunk.replace(
                        to_replace=r"^-$",
                        value="",
                        regex=True,
                        inplace=True,
                    )
                    file_data = json.loads(chunk.to_json(orient="records"))
                    for data, datatype, subtype in self._bifurcate_data(
                        file_data, container_name, blob_name
                    ):
                        yield data, datatype, subtype

        except Exception as e:
            err_msg = (
                "Unexpected error occurred while processing "
                f"container file '{blob_name}'."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {e}",
                details=traceback.format_exc(),
                resolution=(
                    "Ensure that the blob files in the Azure "
                    "Container are gzip-compressed CSV files "
                    "produced by Netskope Log Streaming. Malformed "
                    "or unsupported file formats will be skipped."
                ),
            )
            raise AzureNLSException(err_msg)

    def _process_messages(
        self, azure_helper: AzureNLSClient, messages_list: list
    ) -> Generator[Tuple[Dict[str, Any], str, str], None, None]:
        """Download and process blobs referenced in the message list.

        Args:
            azure_helper: AzureNLSClient with retry-enabled
                download_blob().
            messages_list: List of (container_name, blob_name) tuples.
        """
        skip_count = 0
        for container_name, blob_name in messages_list:
            try:
                data = azure_helper.download_blob(container_name, blob_name)
                for (
                    file_data,
                    datatype,
                    subtype,
                ) in self._process_gzipped_csv_in_batches(
                    data,
                    container_name,
                    blob_name,
                    batch_size=BATCH_SIZE,
                ):
                    yield file_data, datatype, subtype

            except AzureNLSException:
                skip_count += 1
                continue
            except Exception as e:
                err_msg = (
                    "Error occurred while processing storage queue "
                    f"messages for {PLUGIN_NAME} plugin."
                )
                self.logger.error(
                    message=(f"{self.log_prefix}: {err_msg} Error: {e}"),
                    details=traceback.format_exc(),
                    resolution=(
                        f"Ensure that the blob '{blob_name}' exists"
                        f" in container '{container_name}' and is "
                        "accessible with the credentials provided "
                        "in the Connection String."
                    ),
                )
                skip_count += 1
                continue

        if skip_count > 0:
            self.logger.info(
                f"{self.log_prefix}: Skipped processing data for "
                f"{skip_count} message(s) from {PLATFORM_NAME} "
                "Storage Queue because the file format or data is "
                "unsupported."
            )

    def _get_container_data_in_batches(
        self, configuration: Dict[str, Any]
    ) -> Generator[Tuple[Dict[str, Any], str, str], None, None]:
        """Orchestrate queue receive → blob download → batch pipeline.

        Args:
            configuration (dict): Plugin configuration dictionary.
        """
        try:
            queue_name = configuration.get("queue_name", "").strip()
            azure_helper = AzureNLSClient(
                configuration,
                self.logger,
                self.log_prefix,
            )
            queue_client = azure_helper.get_queue_client()

            messages_list = self._get_messages_from_response(
                azure_helper, queue_client
            )

            if messages_list:
                self.logger.info(
                    f"{self.log_prefix}: {len(messages_list)} "
                    f"message(s) from {PLATFORM_NAME} Storage queue"
                    f" '{queue_name}' will be processed."
                )
            else:
                self.logger.info(
                    f"{self.log_prefix}: No message(s) available to"
                    f" process from queue '{queue_name}'."
                )

            for batch_data, datatype, subtype in self._process_messages(
                azure_helper, messages_list
            ):
                yield batch_data, datatype, subtype

        except AzureNLSException:
            raise
        except Exception as e:
            err_msg = (
                "Unexpected error occurred while processing "
                f"container data for {PLUGIN_NAME} plugin."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {e}",
                details=traceback.format_exc(),
                resolution=(
                    "Ensure that the Azure Storage Account "
                    "Connection String and Queue configuration are "
                    "correct."
                ),
            )
            raise AzureNLSException(err_msg)

    def load_maintenance(
        self, configuration: Dict[str, Any]
    ) -> Generator[Tuple[Dict[str, Any], str, str], None, None]:
        """Maintenance pulling from the storage queue.

        Args:
            configuration (dict): Plugin configuration dictionary.
        """
        if back_pressure.STOP_PULLING:
            self.logger.debug(
                f"{self.log_prefix}: Maintenance pulling for plugin"
                f" {PLUGIN_NAME} is paused due to back pressure."
            )
            time.sleep(BACK_PRESSURE_WAIT_TIME)

        for (
            file_data,
            datatype,
            subtype,
        ) in self._get_container_data_in_batches(configuration):
            yield file_data, datatype, subtype

    def pull(
        self, start_time=None, end_time=None
    ) -> Generator[Tuple[Tuple[bytes, str, str], None], None, None]:
        """Pull data from container using Azure Storage Queue.

        Args:
            start_time: Start time for historical pulling (unsupported).
            end_time: End time for historical pulling (unsupported).
        """
        if start_time is not None or end_time is not None:
            self.logger.info(
                f"{self.log_prefix}: {HISTORICAL_PULL} is not "
                f"supported for {PLUGIN_NAME}."
            )
            return

        page_data = []
        log_data_type = "alerts"
        sub_type = "device"
        total_records = 0

        try:
            self.should_exit.clear()
            back_pressure_thread = threading.Thread(
                target=back_pressure.should_stop_pulling,
                daemon=True,
                args=(self.should_exit,),
            )
            back_pressure_thread.start()

            for page_data, log_data_type, sub_type in self.load_maintenance(
                self.configuration
            ):
                self.log_message(
                    PLUGIN_NAME,
                    page_data,
                    log_data_type,
                    sub_type,
                    MAINTENANCE_PULL,
                )
                total_records += len(page_data)

                if sub_type != "v2":
                    page_data = gzip.compress(
                        json.dumps({RESULT: page_data}).encode("utf-8"),
                        compresslevel=3,
                    )
                else:
                    page_data = gzip.compress(
                        json.dumps(page_data).encode("utf-8"),
                        compresslevel=3,
                    )

                yield (page_data, log_data_type, sub_type), None

        except AzureNLSException:
            yield (page_data, log_data_type, sub_type), None
        except Exception as err:
            error_msg = (
                "Error occurred while pulling alerts, events and "
                f"webtx logs from {PLATFORM_NAME} Storage Account "
                f"for {PLUGIN_NAME}."
            )
            self.logger.error(
                message=(f"{self.log_prefix}: {error_msg} Error: {err}"),
                details=traceback.format_exc(),
                resolution=(
                    "Ensure that the Microsoft Azure Storage Account"
                    " credentials and Queue configuration are "
                    "correct and accessible from the CE host."
                ),
            )
            raise AzureNLSException(error_msg)
        finally:
            self.should_exit.set()
            self.logger.info(
                f"{self.log_prefix}: Maintenance pull complete. "
                f"Total records pulled: {total_records}."
            )

    def log_message(
        self,
        plugin_name: str,
        data: Dict[str, Any],
        log_data_type: str,
        sub_type: str,
        pull_type: str,
    ) -> None:
        """Log a summary of pulled records for a given subtype batch.

        Args:
            plugin_name (str): Plugin name for the log message.
            data (List[dict]): Records pulled.
            log_data_type (str): Data type (alerts/events/webtx).
            sub_type (str): Subtype of the data.
            pull_type (str): Pull mode label (e.g. maintenance).
        """
        if log_data_type == "alerts":
            log_data_type = "alert"
        elif log_data_type == "events":
            log_data_type = "event"

        if sub_type == "v2":
            log_msg = (
                f"Pulled {len(data)} {log_data_type} log(s) "
                f"for plugin {plugin_name} from {pull_type} "
                "in JSON format."
            )
        else:
            log_msg = (
                f"Pulled {len(data)} {sub_type} {log_data_type}(s)"
                f" for plugin {plugin_name} from {pull_type} "
                "in JSON format."
            )
        self.logger.info(
            message=f"{self.log_prefix}: {log_msg}"
        )

    def extract_and_store_fields(
        self,
        items: List[dict],
        typeOfField=NetskopeFieldType.EVENT,
        sub_type=None,
    ):
        """Extract and store field metadata from a list of log records.

        Args:
            items (List[dict]): List of log records (alerts or events).
            typeOfField (str): Alert or Event field type.
            sub_type (str): Subtype of alerts or events.
        """
        typeOfField = typeOfField.rstrip("s")
        fields = set()

        for item in items:
            if not isinstance(item, dict):
                item = item.dict()

            item_id = item.get("_id", None)
            if not sub_type and typeOfField == TYPE_EVENT:
                sub_type = item.get("record_type", None)
            elif not sub_type and typeOfField == TYPE_ALERT:
                sub_type = item.get("alert_type", None)
            elif not sub_type and typeOfField == TYPE_WEBTX:
                sub_type = "v2"
            if not item_id:
                item_id = item.get("id")
            for field, field_value in item.items():
                if field in fields:
                    continue
                if field_value is None or (
                    isinstance(field_value, (str, list, dict, tuple, set))
                    and not field_value
                ):
                    continue
                field_obj = plugin_provider_helper.get_stored_field(field)
                if typeOfField == TYPE_WEBTX and not field_obj:
                    self.logger.info(
                        f"{self.log_prefix}: The CE platform has "
                        f"detected new field '{field}' in the WebTx"
                        " logs. Configure CLS to use this field if "
                        "you wish to sent it to the SIEM."
                    )
                    notifier.info(
                        f"The CE platform has detected new field "
                        f"'{field}' in the WebTx logs. Configure "
                        "CLS to use this field if you wish to sent "
                        "it to the SIEM."
                    )
                elif not field_obj:
                    self.logger.info(
                        f"{self.log_prefix}: The CE platform has "
                        f"detected new field '{field}' in the "
                        f"{sub_type} event with id {item_id}. "
                        "Configure CLS to use this field if you "
                        "wish to sent it to the SIEM."
                    )
                    notifier.info(
                        f"The CE platform has detected new "
                        f"field '{field}' in the {sub_type}"
                        f" event with id {item_id}. Configure CLS "
                        "to use this field if you wish to sent it "
                        "to the SIEM."
                    )
                datatype = (
                    FieldDataType.BOOLEAN
                    if isinstance(field_value, bool)
                    else (
                        FieldDataType.NUMBER
                        if isinstance(field_value, (int, float))
                        else FieldDataType.TEXT
                    )
                )
                plugin_provider_helper.store_new_field(
                    field,
                    typeOfField,
                    (
                        FieldDataType.TEXT
                        if field in STRING_FIELDS
                        else datatype
                    ),
                )
            fields = fields.union(item.keys())

    def cleanup(self, action_type: str = ActionType.DELETE.value) -> None:
        """Remove all related dependencies before record deletion."""
        pass
