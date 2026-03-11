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

Azure Netskope LogStreaming plugin.
"""

import gzip
import threading
import traceback
import json
import pandas as pd
import csv
import time
import requests
from typing import List, Tuple, Dict, Any, Generator
from io import BytesIO, StringIO
import base64
from urllib.parse import urlparse

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

    def _get_plugin_info(self) -> Tuple[str, str]:
        """Get plugin name and version from manifest.

        Returns:
            tuple: Tuple of plugin's name and version fetched from manifest.
        """
        try:
            manifest_json = AzureNetskopeLogStreaming.metadata
            plugin_name = manifest_json.get("name", PLUGIN_NAME)
            plugin_version = manifest_json.get("version", PLUGIN_VERSION)
            return (plugin_name, plugin_version)
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

    def transform(
        self,
        raw_data: List[Dict[str, Any]],
        data_type: str,
        subtype: str,
        **kwargs,
    ) -> List:
        """Transform the raw netskope target platform supported.

        Args:
            raw_data (List): Raw data to be transformed.
            data_type (str): Data type of the raw data.
            subtype (str): Subtype of the raw data.

        Returns:
            List: List of transformed data
        """
        return raw_data

    def _validate_auth_params(
        self, configuration: dict, queue_name: str, validation_err_msg: str
    ) -> Tuple[bool, str]:
        """Validate the Plugin configuration parameters.

        Args:
            data (dict): Dict object having all the Plugin
            configuration parameters.
            queue_name (str): Queue name.
            validation_err_msg (str): validation error message.
        """
        try:
            azure_helper = AzureNLSClient(
                configuration,
                self.logger,
                self.log_prefix,
            )
            azure_helper.get_blob_service_client(is_validation=True)
            azure_helper.get_queue_client()
            queue_service_client = azure_helper.get_queue_service_client()

            # validating the queue name provided in the config params
            valid_queue_name = False
            try:
                queues = queue_service_client.list_queues()
            except Exception as e:
                err_msg = (
                    f"Error occurred while getting {PLATFORM_NAME} Data"
                    f" Storage queues for {PLUGIN_NAME}."
                )
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg} Error: {e}",
                    details=traceback.format_exc(),
                )
                raise AzureNLSException(err_msg)
            for queue in queues:
                if queue.name == queue_name:
                    valid_queue_name = True
                    break

            if not valid_queue_name:
                err_msg = (
                    f"Invalid {PLATFORM_NAME} Data Storage Queue Name"
                    f" provided, the provided queue '{queue_name}' does"
                    f" not exist on {PLATFORM_NAME}."
                )
                raise AzureNLSException(err_msg)

            return True, "success"
        except AzureNLSException as exp:
            self.logger.error(
                message=(
                    f"{self.log_prefix}: {validation_err_msg} Error: {exp}"
                ),
                details=traceback.format_exc(),
            )
            return False, str(exp)
        except Exception as err:
            error_msg = (
                "Unexpected error occurred while validating configuration"
                " parameters. Check logs for more details."
            )
            self.logger.error(
                message=(
                    f"{self.log_prefix}: {validation_err_msg} {error_msg}"
                    f" Error: {err}"
                ),
                details=traceback.format_exc(),
            )
            return False, error_msg

    def validate(self, configuration: Dict[str, Any]) -> ValidationResult:
        """Validate the Plugin configuration parameters.

        Args:
            configuration (dict): Dict object having all the Plugin
            configuration parameters.
        Returns:
            ValidateResult object with success flag and message.
        """

        validation_err_msg = "Validation error occurred."

        # Validate Azure Storage Account Connection String
        connection_string = configuration.get("connection_string", "").strip()
        if not connection_string:
            err_msg = (
                f"{PLATFORM_NAME} Storage Account Connection String "
                "is a required configuration parameter."
            )
            self.logger.error(
                f"{self.log_prefix}: {validation_err_msg} Error: {err_msg}"
            )
            return ValidationResult(success=False, message=err_msg)
        elif not isinstance(connection_string, str):
            err_msg = (
                f"Invalid {PLATFORM_NAME} Storage Account Connection String"
                f" found in the configuration parameters. {PLATFORM_NAME}"
                " Storage Account Connection String should be a valid string."
            )
            self.logger.error(
                f"{self.log_prefix}: {validation_err_msg} Error: {err_msg}"
            )
            return ValidationResult(success=False, message=err_msg)

        # Validate Azure Queue name.
        queue_name = configuration.get("queue_name", "").strip()
        if not queue_name:
            err_msg = (
                f"{PLATFORM_NAME} Data Storage Queue Name is a "
                "required configuration parameter."
            )
            self.logger.error(
                f"{self.log_prefix}: {validation_err_msg} Error: {err_msg}"
            )
            return ValidationResult(success=False, message=err_msg)
        elif not isinstance(queue_name, str):
            err_msg = (
                f"Invalid {PLATFORM_NAME} Data Storage Queue Name found in the"
                f" configuration parameters. {PLATFORM_NAME} Data Storage "
                "Queue Name should be a valid string."
            )
            self.logger.error(
                f"{self.log_prefix}: {validation_err_msg} Error: {err_msg}"
            )
            return ValidationResult(success=False, message=err_msg)

        # Validate authentication parameters
        success, message = self._validate_auth_params(
            configuration, queue_name, validation_err_msg
        )

        if not success:
            return ValidationResult(success=False, message=f"{message}")

        # validation successful
        validation_msg = f"Validation Successful for {PLUGIN_NAME} plugin."
        self.logger.debug(f"{self.log_prefix}: {validation_msg}")
        return ValidationResult(success=True, message=validation_msg)

    def extract_container_name(self, blob_url: str) -> str:
        """
        Extracts the container name from an Azure Blob Storage URL.

        Args:
            blob_url (str): The full blob URL.

        Returns:
            str: The container name.
        """
        parsed = urlparse(blob_url)
        # Path will be like: /container/blob-name
        parts = parsed.path.strip("/").split("/")
        return parts[0] if parts else None

    def _get_messages_from_response(self, queue_client) -> List:
        """
        Get messages from response

        Args:
            queue_client: The Azure queue client
        """
        messages = queue_client.receive_messages(
            messages_per_page=20, visibility_timeout=3000
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
                            container_name = self.extract_container_name(
                                blob_url
                            )
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
                                        "Error occurred while deleting message"
                                        f" containing blob url: {blob_url} "
                                        f"from {PLATFORM_NAME} Storage Queue."
                                    )
                                    self.logger.error(
                                        message=(
                                            f"{self.log_prefix}: {err_msg}"
                                            f" Error: {e}"
                                        ),
                                        details=traceback.format_exc(),
                                    )
                                    continue
                    except Exception as e:
                        err_msg = (
                            "Unexpected error occurred while "
                            f"receiving messages from {PLATFORM_NAME} "
                            "Storage Queue."
                        )
                        self.logger.error(
                            message=f"{self.log_prefix}: {err_msg} Error: {e}",
                            details=traceback.format_exc(),
                        )
                        continue

        except requests.exceptions.RequestException as e:
            err_msg = (
                "Error occurred while communicating with "
                f"{PLATFORM_NAME} Storage queue."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {e}",
                details=traceback.format_exc(),
            )
            raise AzureNLSException(err_msg)
        except Exception as e:
            err_msg = (
                "Unexpected error occurred while receiving "
                f"messages from {PLATFORM_NAME} Storage queue."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {e}",
                details=traceback.format_exc(),
            )
            raise AzureNLSException(err_msg)

        return messages_list

    def _process_incident_event(
        self, incident_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Process incident data to convert some int fields to sting

        Args:
            incident_data: Incidnet data to be processed
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
        """Bifurcate the data.

        Args:
            data (bytes): The json data.
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
            except Exception:
                skip_count += 1
                continue

        if skip_count > 0:
            self.logger.info(
                f"{self.log_prefix}: Skipped {skip_count} out "
                f"of {len(data_list)} logs from file '{blob_name}' "
                f"from container '{container_name}' due to invalid data or "
                "unsupported subtype."
            )
        datatype = None
        for subtype, data in result.items():
            if data:
                if subtype in ALERTS:
                    datatype = "alerts"
                elif subtype in EVENTS:
                    datatype = "events"
                elif subtype in WEBTX:
                    datatype = "webtx"

                yield data, datatype, subtype

    def _process_gzipped_csv_in_batches(
        self, data: bytes, container_name: str, blob_name: str, batch_size: int
    ) -> Generator[Tuple[Dict[str, Any], str, str], None, None]:
        """Process the gzipped CSV data in batches.

        Args:
            data (bytes): The gzipped CSV data.
            s3_client (boto3.client): The S3 client.
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
                        "Error occurred while detecting delimiter from"
                        " csv file. Using default delimiter ','."
                    )
                    self.logger.error(
                        message=f"{self.log_prefix}: {err_msg} Error: {e}",
                        details=traceback.format_exc(),
                    )
                # batching for the batch size
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
                "Unexpected error occurred while processing container file."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {e}",
                details=traceback.format_exc(),
            )
            raise AzureNLSException(err_msg)

    def _process_messages(
        self, azure_helper: AzureNLSClient, messages_list: list
    ) -> Generator[Tuple[Dict[str, Any], str, str], None, None]:
        """Process the messages.

        Args:
            messages (list): List of messages.
            configuration (dict): The configuration dictionary.
        """
        file_data = []
        skip_count = 0
        blob_service_client = azure_helper.get_blob_service_client()
        for container_name, blob_name in messages_list:
            try:
                blob_client = blob_service_client.get_blob_client(
                    container=container_name, blob=blob_name
                )
                data = blob_client.download_blob().readall()
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
                    "Error occurred while processing storage queue messages "
                    f"for {PLUGIN_NAME} plugin."
                )
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg} Error: {e}",
                    details=traceback.format_exc(),
                )
                skip_count += 1
                continue

        if skip_count > 0:
            self.logger.info(
                f"{self.log_prefix}: Skipped processing data for {skip_count}"
                f" messages from {PLATFORM_NAME} Storage Queue because either"
                " the file format or the data is of unsupported format."
            )

    def _get_container_data_in_batches(
        self, configuration: Dict[str, Any]
    ) -> Generator[Tuple[Dict[str, Any], str, str], None, None]:
        """Get the container data in batches.

        Args:
            configuration (dict): The configuration dictionary.
        """
        try:
            queue_name = configuration.get("queue_name", "").strip()
            azure_helper = AzureNLSClient(
                configuration,
                self.logger,
                self.log_prefix,
            )
            queue_client = azure_helper.get_queue_client()

            # get the messages from the storage queue
            messages_list = []
            messages_list = self._get_messages_from_response(queue_client)

            if len(messages_list) > 0:
                self.logger.info(
                    f"{self.log_prefix}: {len(messages_list)} message(s) from"
                    f" {PLATFORM_NAME} Storage queue '{queue_name}' will"
                    " be processed."
                )
            else:
                self.logger.info(
                    f"{self.log_prefix}: No message(s) available to process"
                    f" from queue '{queue_name}'."
                )

            # process the messages
            for batch_data, datatype, subtype in self._process_messages(
                azure_helper, messages_list
            ):
                yield batch_data, datatype, subtype

        except AzureNLSException:
            raise
        except Exception as e:
            err_msg = (
                "Error unexpected occurred while processing"
                f" container data for {PLUGIN_NAME} plugin."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {e}",
                details=traceback.format_exc(),
            )
            raise AzureNLSException(err_msg)

    def load_maintenance(
        self, configuration: Dict[str, Any]
    ) -> Generator[Tuple[Dict[str, Any], str, str], None, None]:
        """maintainence pulling from the storage queue.

        Args:
            configuration (dict): The configuration dictionary.
        """

        if back_pressure.STOP_PULLING:
            self.logger.debug(
                f"{self.log_prefix}: Maintenance pulling"
                f" for plugin {PLUGIN_NAME} "
                "is paused due to back pressure."
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
        """Pull data from container using azure storage queue.

        Args:
            start_time: start time for historical pulling.
            end_time: end time for historical pulling.
        """

        if start_time is not None or end_time is not None:
            self.logger.info(
                f"{self.log_prefix}: {HISTORICAL_PULL} "
                f"is not supported for {PLUGIN_NAME}."
            )
            return {"success": False}

        page_data = []
        log_data_type = "alerts"
        sub_type = "device"
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
                "Error occurred while fetching alerts, events and webtx logs "
                f"from {PLATFORM_NAME} Storage Account for {PLUGIN_NAME}."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {error_msg} Error: {err}",
                details=traceback.format_exc(),
            )
            raise AzureNLSException(error_msg)

    def log_message(
        self,
        plugin_name: str,
        data: Dict[str, Any],
        log_data_type: str,
        sub_type: str,
        pull_type: str,
    ) -> None:
        """Log the message for pulling data from Netskope log streaming.

        Args:
            data (List[dict]): List of dictionaries of data pulled from
            Netskope API.
            sub_type (str): Subtype of the data.
            pull_type (str): Type of pulling (maintenance, historical,
            real-time).
        """
        if sub_type == "v2":
            log_msg = (
                f"Pulled {len(data)} {log_data_type} log(s) "
                f"for plugin {plugin_name} from {pull_type}"
                f" in JSON format."
            )
        else:
            log_msg = (
                f"Pulled {len(data)} {sub_type} {log_data_type}(s) "
                f"for plugin {plugin_name} from {pull_type}"
                f" in JSON format."
            )

        self.logger.info(
            message=f"{self.log_prefix}: {log_msg}",
        )

    def extract_and_store_fields(
        self,
        items: List[dict],
        typeOfField=NetskopeFieldType.EVENT,
        sub_type=None,
    ):
        """Extract and store keys from list of dictionaries.

        Args:
            items (List[dict]): List of dictionaries. i.e. alerts, or events.
            typeOfField (str): Alert or Event
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
                if not field_value:
                    continue
                field_obj = plugin_provider_helper.get_stored_field(field)
                if typeOfField == TYPE_WEBTX and not field_obj:
                    self.logger.info(
                        f"{self.log_prefix}: The CE platform has detected new"
                        f" field '{field}' in the WebTx logs."
                        " Configure CLS to use this field if "
                        "you wish to sent it to the SIEM."
                    )
                    notifier.info(
                        f"The CE platform has detected new field '{field}' in"
                        " the WebTx logs. Configure CLS to use this field if"
                        " you wish to sent it to the SIEM."
                    )

                elif not field_obj:
                    self.logger.info(
                        f"{self.log_prefix}: The CE platform has detected new "
                        f"field '{field}' in the {sub_type}"
                        f" event with id {item_id}. Configure CLS to use "
                        "this field if you wish to sent it to the SIEM."
                    )
                    notifier.info(
                        f"The CE platform has detected new "
                        f"field '{field}' in the {sub_type}"
                        f" event with id {item_id}. Configure CLS to use this"
                        " field if you wish to sent it to the SIEM."
                    )
                datatype = (
                    FieldDataType.BOOLEAN
                    if isinstance(field_value, bool)
                    else (
                        FieldDataType.NUMBER
                        if isinstance(field_value, int)
                        or isinstance(field_value, float)
                        else FieldDataType.TEXT
                    )
                )
                plugin_provider_helper.store_new_field(
                    field,
                    typeOfField,
                    FieldDataType.TEXT if field in STRING_FIELDS else datatype,
                )
            fields = fields.union(item.keys())

    def cleanup(self, action_type: str = ActionType.DELETE.value) -> None:
        """Remove all related dependencies of the record before
        its deletion, ensuring data integrity."""
        pass
