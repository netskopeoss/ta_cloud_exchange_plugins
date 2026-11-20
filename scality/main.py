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


Scality Plugin.
"""

import json
import traceback
from tempfile import NamedTemporaryFile
from typing import Any, Dict, List, Optional, Union

from netskope.integrations.cls.plugin_base import (
    PluginBase,
    PushResult,
    ValidationResult,
)

from .utils import constants as CONST
from .utils.client import ScalityClient
from .utils.credentials import ScalityCredentials
from .utils.exceptions import ScalityException
from .utils.helper import (
    ScalityConfig,
    get_mappings,
    log_and_raise,
    log_error,
    map_json_data,
    remove_local_file,
    scality_add_user_agent,
    serialize_webtx_records,
)
from .utils.validator import ScalityValidator


class ScalityPlugin(PluginBase):
    """Scality CLS plugin implementation class."""

    def __init__(self, name, *args, **kwargs):
        """Initialize ScalityPlugin.

        Args:
            name (str): Configuration name.
        """
        super().__init__(name, *args, **kwargs)
        self.plugin_name, self.plugin_version = self._get_plugin_info()
        self.log_prefix = f"{CONST.MODULE_NAME} {self.plugin_name}"
        if name:
            self.log_prefix = f"{self.log_prefix} [{name}]"

    def _get_plugin_info(self) -> tuple:
        """Get the plugin name and version from the manifest metadata.

        Returns:
            tuple: (plugin_name, plugin_version).
        """
        try:
            manifest_json = ScalityPlugin.metadata
            plugin_name = manifest_json.get("name", CONST.PLUGIN_NAME)
            plugin_version = manifest_json.get("version", CONST.PLUGIN_VERSION)
            return plugin_name, plugin_version
        except Exception as exp:
            log_error(
                self.logger,
                f"{CONST.MODULE_NAME} {CONST.PLUGIN_NAME}",
                "getting plugin details",
                (
                    "Ensure that the manifest.json file of the plugin"
                    " is present and valid."
                ),
                cause=str(exp),
            )
        return CONST.PLUGIN_NAME, CONST.PLUGIN_VERSION

    # --- Configuration Helpers ---

    def _get_config_params(self, configuration: dict) -> ScalityConfig:
        """Get the configuration parameters of the plugin.

        Args:
            configuration (dict): Plugin configuration parameters.

        Returns:
            ScalityConfig: The parameters, read null-safe so that
                ``validate`` can report a missing or invalid value.
        """
        (
            endpoint_url,
            access_key,
            secret_access_key,
            bucket_name,
        ) = ScalityCredentials.get_credentials(configuration)
        return ScalityConfig(
            endpoint_url=endpoint_url,
            access_key=access_key,
            secret_access_key=secret_access_key,
            bucket_name=bucket_name,
        )

    def _get_client(self, configuration: dict) -> ScalityClient:
        """Create a Scality client for the given configuration.

        Args:
            configuration (dict): Plugin configuration parameters.

        Returns:
            ScalityClient: Client used to reach Scality.
        """
        return ScalityClient(
            configuration,
            self.logger,
            self.proxy,
            self.log_prefix,
            scality_add_user_agent(),
        )

    @staticmethod
    def _is_json_format(configuration: dict) -> bool:
        """Return True when the configured output format is JSON.

        Cloud Exchange 5.1.2 and older pass a boolean, newer versions
        pass the format name, so both are handled.

        Args:
            configuration (dict): Plugin configuration parameters.

        Returns:
            bool: True when JSON output is selected.
        """
        transform_data = configuration.get(
            CONST.TRANSFORM_DATA_KEY, CONST.JSON_FORMAT
        )
        if isinstance(transform_data, bool):
            return not transform_data
        return str(transform_data).lower() == CONST.JSON_FORMAT

    def _validate_configuration_parameters(
        self,
        field_name: str,
        field_value: Union[str, List, bool, int],
        field_type: type,
        is_required: bool = True,
        validation_err_msg: str = CONST.VALIDATION_ERROR_MESSAGE,
    ) -> Union[ValidationResult, None]:
        """Validate a single configuration field.

        Args:
            field_name (str): Name of the field to validate.
            field_value: Value of the field to validate.
            field_type (type): Expected type of the field.
            is_required (bool): Whether the field is required.
            validation_err_msg (str): Base validation error message.

        Returns:
            ValidationResult on failure, None on success.
        """
        action = "validating configuration parameters"
        if field_type is str and isinstance(field_value, str):
            field_value = field_value.strip()

        if (
            is_required
            and not isinstance(field_value, int)
            and not field_value
        ):
            err_msg = (
                f"{field_name} is a required configuration parameter."
            )
            log_error(
                self.logger,
                self.log_prefix,
                action,
                (
                    f"Ensure that {field_name} is provided in the"
                    " configuration parameters."
                ),
                cause=err_msg,
                details=f"{validation_err_msg} {err_msg}",
            )
            return ValidationResult(success=False, message=err_msg)

        if (field_value or isinstance(field_value, int)) and (
            not isinstance(field_value, field_type)
            or (field_type is int and isinstance(field_value, bool))
        ):
            err_msg = (
                "Invalid value provided for the configuration"
                f" parameter '{field_name}'."
            )
            log_error(
                self.logger,
                self.log_prefix,
                action,
                (
                    f"Ensure that a valid {field_name} is provided in"
                    " the configuration parameters."
                ),
                cause=err_msg,
                details=f"{validation_err_msg} {err_msg}",
            )
            return ValidationResult(success=False, message=err_msg)

        self.logger.debug(
            f"{self.log_prefix}: Validation successful for"
            f" '{field_name}' configuration parameter."
        )
        return None

    # --- Transform Flow ---

    @staticmethod
    def get_subtype_mapping(mappings: Dict, subtype: str) -> Optional[Any]:
        """Retrieve the mapping of a subtype case insensitively.

        Args:
            mappings (Dict): Mapping dict keyed by subtype name.
            subtype (str): Subtype to look up.

        Returns:
            Optional[Any]: The mapping of the subtype, or None when the
                subtype is not present in the mapping.
        """
        if not isinstance(mappings, dict) or not subtype:
            return None
        lowered = {
            key.lower(): value
            for key, value in mappings.items()
            if isinstance(key, str)
        }
        return lowered.get(subtype.lower())

    def validate_mappings(self) -> ValidationResult:
        """Validate the configured mapping.

        Parses the jsonData mapping string, checks that it is not empty
        and validates the taxonomy.json structure.

        Returns:
            ValidationResult: Success or failure with a message.
        """
        scality_validator = ScalityValidator(
            logger=self.logger,
            log_prefix=self.log_prefix,
        )

        def _validate_json_data(json_string):
            """Parse jsonData and raise ValueError for invalid content."""
            try:
                json_object = json.loads(json_string)
                if not bool(json_object):
                    raise ValueError("JSON data should not be empty.")
            except json.decoder.JSONDecodeError as err:
                raise ValueError(f"Invalid JSON: {err}")
            except ValueError:
                raise
            except Exception as err:
                raise ValueError(
                    f"Error occurred while validating JSON: {err}."
                )
            return json_object

        try:
            mappings = _validate_json_data(
                (self.mappings or {}).get(CONST.MAPPINGS_JSON_DATA_KEY)
            )
        except Exception as err:
            log_error(
                self.logger,
                self.log_prefix,
                "validating the Scality mappings",
                (
                    "Ensure that the mapping configured under"
                    " Settings > Log Shipper is valid JSON and is not"
                    " empty."
                ),
                cause=str(err),
            )
            return ValidationResult(success=False, message=str(err))

        if not scality_validator.validate_mappings(mappings):
            err_msg = (
                "Invalid mapping configuration. Please check the"
                " mapping settings in Settings > Log Shipper."
            )
            return ValidationResult(success=False, message=err_msg)

        return ValidationResult(
            success=True, message="Mappings validation successful."
        )

    def transform(self, raw_data, data_type, subtype) -> List:
        """Transform the raw Netskope data using the configured mapping.

        WebTx data is sent as received because the plugin stores raw
        logs.

        Args:
            raw_data (list): Raw records received from Netskope.
            data_type (str): Data type - ``alerts``, ``events`` or
                ``webtx``.
            subtype (str): Subtype of the records.

        Returns:
            List: Records to be pushed to Scality.

        Raises:
            ScalityException: When the mapping cannot be read.
        """
        if not self._is_json_format(self.configuration):
            log_and_raise(
                self.logger,
                self.log_prefix,
                "transforming data",
                (
                    "Ensure that 'JSON' is selected as the data format"
                    " in the plugin configuration."
                ),
                cause=(
                    f"This plugin only sends JSON data to"
                    f" {CONST.PLATFORM_NAME}."
                ),
            )

        if data_type == CONST.WEBTX_DATA_TYPE:
            return raw_data

        try:
            mappings = get_mappings(self.mappings, data_type)
        except Exception as err:
            log_and_raise(
                self.logger,
                self.log_prefix,
                (
                    f"fetching the mapping for [{data_type}]"
                    f"[{subtype}] logs"
                ),
                (
                    "Ensure that the mapping configured under"
                    " Settings > Log Shipper contains the"
                    f" '{data_type}' data type."
                ),
                cause=str(err),
            )

        subtype_mappings = self.get_subtype_mapping(mappings, subtype)
        if not subtype_mappings:
            if subtype_mappings is None:
                self.logger.debug(
                    f"{self.log_prefix}: [{data_type}][{subtype}] No"
                    " mapping found for this subtype hence the log(s)"
                    " will be ingested as received."
                )
            return raw_data

        skipped_logs = 0
        failed_logs = 0
        last_error = ""
        first_traceback = ""
        transformed_data = []
        for data in raw_data:
            if not data:
                skipped_logs += 1
                continue
            try:
                mapped = map_json_data(subtype_mappings, data)
                if mapped:
                    transformed_data.append(mapped)
                else:
                    skipped_logs += 1
            except Exception as err:
                failed_logs += 1
                last_error = str(err)
                if not first_traceback:
                    first_traceback = traceback.format_exc()

        if failed_logs > 0:
            skipped_logs += failed_logs
            log_error(
                self.logger,
                self.log_prefix,
                (
                    f"transforming {failed_logs} [{data_type}]"
                    f"[{subtype}] log(s); they were skipped"
                ),
                (
                    "Ensure that the log(s) received from the source"
                    " are valid JSON objects."
                ),
                cause=f"Last error: {last_error}",
                details=(
                    f"[{data_type}][{subtype}] {failed_logs} log(s)"
                    f" could not be transformed. Last error:"
                    f" {last_error}. Traceback of the first failure:"
                    f" {first_traceback}"
                ),
            )

        if skipped_logs > 0:
            self.logger.debug(
                f"{self.log_prefix}: [{data_type}][{subtype}] Plugin"
                f" couldn't process {skipped_logs} record(s) because"
                " they either had no data or contained invalid/missing"
                " fields according to the configured JSON mapping."
                " Those records were skipped."
            )
        return transformed_data

    # --- Push Flow ---

    def push(
        self, transformed_data: List, data_type: str, subtype: str
    ) -> PushResult:
        """Push the transformed data to the Scality bucket.

        Args:
            transformed_data (List): Records to push.
            data_type (str): Data type - ``alerts``, ``events`` or
                ``webtx``.
            subtype (str): Subtype of the records.

        Returns:
            PushResult: Result with a success flag and a message.

        Raises:
            ScalityException: When the logs could not be pushed, so
                that Cloud Exchange retries the batch.
        """
        bucket_name = self._get_config_params(self.configuration).bucket_name
        log_tag = self._get_log_tag(data_type, subtype)
        self.logger.debug(
            f"{self.log_prefix}: {log_tag} Initializing the sharing of"
            f" {len(transformed_data or [])} log(s) to"
            f" {CONST.PLATFORM_NAME} Bucket {bucket_name}."
        )
        try:
            scality_client = self._get_client(self.configuration)
            if data_type == CONST.WEBTX_DATA_TYPE:
                return self._push_webtx_data(
                    scality_client,
                    bucket_name,
                    transformed_data,
                    subtype,
                    log_tag,
                )
            return self._push_alerts_events_data(
                scality_client,
                bucket_name,
                transformed_data,
                data_type,
                subtype,
                log_tag,
            )
        except ScalityException:
            raise
        except Exception as exp:
            log_and_raise(
                self.logger,
                self.log_prefix,
                (
                    f"pushing {log_tag} log(s) to {CONST.PLATFORM_NAME}"
                    f" Bucket '{bucket_name}'"
                ),
                (
                    "Ensure that the plugin configuration is valid and"
                    " check the logs for more details."
                ),
                cause=str(exp),
            )

    @staticmethod
    def _get_log_tag(data_type: str, subtype: str) -> str:
        """Build the ``[data_type] [subtype]`` tag used in log messages.

        Args:
            data_type (str): Data type of the logs.
            subtype (str): Subtype of the logs.

        Returns:
            str: e.g. ``[webtx] [v2]``.
        """
        return f"[{data_type}] [{subtype}]"

    def _push_webtx_data(
        self,
        scality_client: ScalityClient,
        bucket_name: str,
        transformed_data: List,
        subtype: str,
        log_tag: str,
    ) -> PushResult:
        """Push WebTx logs to the Scality bucket as one gzip object.

        The records are ``dict`` objects, written as one JSON line each.

        Args:
            scality_client (ScalityClient): Client used to reach
                Scality.
            bucket_name (str): Configured bucket name.
            transformed_data (List): Records to push.
            subtype (str): Subtype of the records.
            log_tag (str): Tag used in log messages.

        Returns:
            PushResult: Result with a success flag and a message.

        Raises:
            ScalityException: When the logs could not be pushed.
        """
        temp_path = None
        try:
            try:
                with NamedTemporaryFile(
                    "wb", delete=False, suffix=CONST.GZIP_EXTENSION
                ) as temp_obj_file:
                    temp_path = temp_obj_file.name
                    result = serialize_webtx_records(
                        transformed_data or [], temp_obj_file
                    )
            except ScalityException:
                raise
            except Exception as err:
                log_and_raise(
                    self.logger,
                    self.log_prefix,
                    "writing log(s) to the temporary object file",
                    (
                        "Ensure that the Cloud Exchange host has free"
                        " disk space and write access to its temporary"
                        " directory."
                    ),
                    cause=str(err),
                )

            if result.failed:
                log_error(
                    self.logger,
                    self.log_prefix,
                    (
                        f"serializing {result.failed} WebTx log(s);"
                        " they were skipped"
                    ),
                    (
                        "Ensure that the source plugin sends valid"
                        " WebTx records."
                    ),
                    details=(
                        f"{log_tag} {result.failed} WebTx log(s) could"
                        " not be converted to JSON."
                    ),
                )
            if result.skipped:
                self.logger.info(
                    f"{self.log_prefix}: {log_tag} Skipped"
                    f" {result.skipped} empty or unsupported WebTx"
                    " log(s)."
                )
            if not result.written:
                log_msg = f"{log_tag} No log(s) to ingest."
                self.logger.debug(
                    f"{self.log_prefix}: {log_msg} Nothing was"
                    " uploaded."
                )
                return PushResult(success=True, message=log_msg)

            object_key = scality_client.push(
                temp_path, CONST.WEBTX_DATA_TYPE, subtype
            )
            log_msg = (
                f"{log_tag} Successfully ingested {result.written}"
                f" log(s) to {CONST.PLATFORM_NAME} Bucket '{bucket_name}'."
                f" Object: '{object_key}'."
            )
            self.logger.info(f"{self.log_prefix}: {log_msg}")
            return PushResult(success=True, message=log_msg)
        finally:
            remove_local_file(temp_path)

    def _push_alerts_events_data(
        self,
        scality_client: ScalityClient,
        bucket_name: str,
        transformed_data: List,
        data_type: str,
        subtype: str,
        log_tag: str,
    ) -> PushResult:
        """Push alert and event logs to the Scality bucket as JSON.

        Args:
            scality_client (ScalityClient): Client used to reach
                Scality.
            bucket_name (str): Configured bucket name.
            transformed_data (List): Records to push.
            data_type (str): Data type - ``alerts`` or ``events``.
            subtype (str): Subtype of the records.
            log_tag (str): Tag used in log messages.

        Returns:
            PushResult: Result with a success flag and a message.

        Raises:
            ScalityException: When the logs could not be pushed.
        """
        filtered_list = [data for data in (transformed_data or []) if data]
        empty_dict_count = len(transformed_data or []) - len(filtered_list)
        if empty_dict_count > 0:
            self.logger.debug(
                f"{self.log_prefix}: {log_tag} Received empty log(s)"
                f" from the source for {empty_dict_count} log(s) hence"
                " ingestion of those log(s) was skipped."
            )
        if not filtered_list:
            log_msg = f"{log_tag} No log(s) to ingest."
            self.logger.debug(
                f"{self.log_prefix}: {log_msg} Nothing was uploaded."
            )
            return PushResult(success=True, message=log_msg)

        temp_path = None
        try:
            try:
                with NamedTemporaryFile(
                    "w",
                    delete=False,
                    suffix=CONST.ALERTS_EVENTS_EXTENSION,
                    encoding=CONST.TEXT_ENCODING,
                ) as temp_obj_file:
                    temp_path = temp_obj_file.name
                    json.dump(filtered_list, temp_obj_file, default=str)
            except (TypeError, ValueError) as err:
                # A data problem, not a disk problem: say so, so the
                # resolution points at the logs and not at the host.
                log_and_raise(
                    self.logger,
                    self.log_prefix,
                    f"serializing {log_tag} log(s) to JSON",
                    (
                        "Ensure that the logs received from the source"
                        " are valid JSON objects."
                    ),
                    cause=str(err),
                )
            except OSError as err:
                log_and_raise(
                    self.logger,
                    self.log_prefix,
                    "writing log(s) to the temporary object file",
                    (
                        "Ensure that the Cloud Exchange host has free"
                        " disk space and write access to its temporary"
                        " directory."
                    ),
                    cause=str(err),
                )

            object_key = scality_client.push(
                temp_path, data_type, subtype
            )
            log_msg = (
                f"{log_tag} Successfully ingested"
                f" {len(filtered_list)} log(s) to {CONST.PLATFORM_NAME}"
                f" Bucket '{bucket_name}'. Object: '{object_key}'."
            )
            self.logger.info(f"{self.log_prefix}: {log_msg}")
            return PushResult(success=True, message=log_msg)
        finally:
            remove_local_file(temp_path)

    # --- Connectivity Validation ---

    def _validate_connectivity(
        self,
        configuration: dict,
        scality_validator: ScalityValidator,
        bucket_name: str,
    ) -> Union[ValidationResult, None]:
        """Validate connectivity to the Scality instance.

        Two checks run in order:
          1. the credentials are accepted by Scality,
          2. the configured bucket exists.

        Args:
            configuration (dict): Plugin configuration parameters.
            scality_validator (ScalityValidator): Validator instance.
            bucket_name (str): Configured bucket name.

        Returns:
            ValidationResult: Failure result when a check fails.
            None: All checks passed.
        """
        try:
            scality_client = self._get_client(configuration)
            scality_validator.validate_credentials(scality_client)
        except ScalityException as exp:
            return ValidationResult(success=False, message=str(exp))
        except Exception as err:
            err_msg = log_error(
                self.logger,
                self.log_prefix,
                "validating credentials",
                (
                    "Ensure that the Access Key and Secret Access Key"
                    " provided in the configuration parameters are"
                    " valid."
                ),
                cause=str(err),
            )
            return ValidationResult(success=False, message=err_msg)

        try:
            scality_client.get_bucket(
                validation_retries=CONST.VALIDATION_MAX_RETRIES
            )
        except ScalityException as exp:
            return ValidationResult(success=False, message=str(exp))
        except Exception as err:
            err_msg = log_error(
                self.logger,
                self.log_prefix,
                f"verifying {CONST.PLATFORM_NAME} Bucket '{bucket_name}'",
                (
                    "Ensure that the Bucket Name provided in the"
                    " configuration parameters exists on"
                    f" {CONST.PLATFORM_NAME} and that the user has"
                    " permission to access it."
                ),
                cause=str(err),
            )
            return ValidationResult(success=False, message=err_msg)

        return None

    # --- Validation Flow ---

    def validate(self, configuration: dict) -> ValidationResult:
        """Validate the plugin configuration parameters.

        Validation order:
          1. transformData format check (the plugin is JSON only)
          2. Scality Endpoint URL (present and a string; the format is
             left to boto3, which is the authority on what Scality
             accepts)
          3. Access Key
          4. Secret Access Key
          5. Scality Bucket Name
          6. Mapping structure
          7. Connectivity: credentials, then bucket

        Args:
            configuration (dict): Plugin configuration parameters.

        Returns:
            ValidationResult: Validation result with a success flag and
                a message.
        """
        validation_err_msg = CONST.VALIDATION_ERROR_MESSAGE
        (
            endpoint_url,
            access_key,
            secret_access_key,
            bucket_name,
        ) = self._get_config_params(configuration)

        scality_validator = ScalityValidator(
            logger=self.logger,
            log_prefix=self.log_prefix,
        )

        # 1. Validate the selected format - the plugin is JSON only.
        if not self._is_json_format(configuration):
            err_msg = (
                f"This plugin only sends JSON data to {CONST.PLATFORM_NAME}."
                " Please select 'JSON' as the format to continue."
            )
            log_error(
                self.logger,
                self.log_prefix,
                "validating configuration parameters",
                (
                    "Ensure that 'JSON' is selected as the data format"
                    " in the plugin configuration."
                ),
                cause=err_msg,
                details=f"{validation_err_msg} {err_msg}",
            )
            return ValidationResult(success=False, message=err_msg)

        # 2. Validate Scality Endpoint URL.
        if url_result := self._validate_configuration_parameters(
            field_name=f"{CONST.PLATFORM_NAME} Endpoint URL",
            field_value=endpoint_url,
            field_type=str,
            validation_err_msg=validation_err_msg,
        ):
            return url_result
        # 3. Validate Access Key.
        if access_key_result := self._validate_configuration_parameters(
            field_name="Access Key",
            field_value=access_key,
            field_type=str,
            validation_err_msg=validation_err_msg,
        ):
            return access_key_result

        # 4. Validate Secret Access Key.
        if secret_result := self._validate_configuration_parameters(
            field_name="Secret Access Key",
            field_value=secret_access_key,
            field_type=str,
            validation_err_msg=validation_err_msg,
        ):
            return secret_result

        # 5. Validate Scality Bucket Name.
        if bucket_result := self._validate_configuration_parameters(
            field_name=f"{CONST.PLATFORM_NAME} Bucket Name",
            field_value=bucket_name,
            field_type=str,
            validation_err_msg=validation_err_msg,
        ):
            return bucket_result

        # 6. Validate the mapping structure.
        mappings_result = self.validate_mappings()
        if not mappings_result.success:
            return mappings_result

        # 7. Connectivity validations.
        if connectivity_result := self._validate_connectivity(
            configuration=configuration,
            scality_validator=scality_validator,
            bucket_name=bucket_name,
        ):
            return connectivity_result

        self.logger.debug(
            f"{self.log_prefix}: Successfully validated configuration"
            " parameters."
        )
        return ValidationResult(success=True, message="Validation successful.")
