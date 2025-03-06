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
import os
import traceback
from typing import List, Dict
from tempfile import NamedTemporaryFile
from netskope.integrations.cls.plugin_base import (
    PluginBase,
    ValidationResult,
    PushResult,
)
from .utils.validator import (
    ScalityValidator,
)
from .utils.client import (
    ScalityClient,
    BucketNotFoundError,
    BucketNameAlreadyTaken,
)
from .utils.exception import (
    ScalityException,
    MappingValidationError,
)

from .utils.credentials import ScalityCredentials
from .utils.helper import get_mappings, map_data, scality_add_user_agent
from .utils.constants import (
    MODULE_NAME,
    PLUGIN_NAME,
    PLUGIN_VERSION,
    VALIDATION_MAX_RETRIES,
)


class ScalityPlugin(PluginBase):
    """The Scality Plugin implementation class."""

    def __init__(
        self,
        name,
        *args,
        **kwargs,
    ):
        """Initialize Scality Plugin class."""
        super().__init__(
            name,
            *args,
            **kwargs,
        )
        self.plugin_name, self.plugin_version = self._get_plugin_info()
        self.log_prefix = f"{MODULE_NAME} {self.plugin_name}"
        if name:
            self.log_prefix = f"{self.log_prefix} [{name}]"

    def _get_plugin_info(self) -> tuple:
        """Get plugin name and version from manifest.

        Returns:
            tuple: Tuple of plugin's name and version fetched from manifest.
        """
        try:
            manifest_json = ScalityPlugin.metadata
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

    @staticmethod
    def get_subtype_mapping(mappings: Dict, subtype: str) -> Dict:
        """Retrieve subtype mappings (mappings for subtypes of alerts/events)
        case insensitively.

        Args:
            mappings (Dict): Mapping JSON from which subtypes are to
            be retrieved
            subtype (str): Subtype (e.g. DLP for alerts) for which the
            subtype mapping is to be fetched

        Returns:
            Dict: Fetched mapping JSON object
        """
        mappings = {k.lower(): v for k, v in mappings.items()}
        if subtype.lower() in mappings:
            return mappings[subtype.lower()]
        else:
            return mappings[subtype.upper()]

    def transform(self, raw_data, data_type, subtype) -> List:
        """Transform the raw netskope JSON data into target platform supported
        data formats.

        Args:
            raw_data (list): The raw data to be transformed.
            data_type (str): The type of data to be ingested (alert/event)
            subtype (str): The subtype of data to be ingested
            (DLP, anomaly etc. in case of alerts)

        Raises:
            NotImplementedError: If the method is not implemented.

        Returns:
            List: list of transformed data.
        """
        if self.configuration.get("transformData", False):
            err_msg = (
                f"This Plugin is designed to send raw data to {PLUGIN_NAME}"
                " Bucket - Please disable the transformation toggle."
            )
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            raise ScalityException(err_msg)

        if data_type == "webtx":
            return raw_data

        skipped_logs = 0
        try:
            mappings = get_mappings(self.mappings, data_type)
        except MappingValidationError as err:
            err_msg = "Mapping validation error occurred."
            self.logger.error(
                message=(
                    f"{self.log_prefix}: [{data_type}][{subtype}]"
                    f" {err_msg} Error: {err}"
                ),
                details=str(traceback.format_exc()),
            )
            raise ScalityException(err_msg)
        except Exception as err:
            err_msg = (
                f"An error occurred while mapping data using "
                f"given mapping [{data_type}][{subtype}]."
            )
            self.logger.error(
                message=(
                    f"{self.log_prefix}: [{data_type}][{subtype}] "
                    f"{err_msg} Error: {err}"
                ),
                details=traceback.format_exc(),
            )
            raise ScalityException(err_msg)

        transformed_data = []
        subtype_mappings = self.get_subtype_mapping(mappings, subtype)
        if not subtype_mappings:
            return raw_data
        for data in raw_data:
            try:
                data = map_data(subtype_mappings, data)
                if data:
                    transformed_data.append(data)
                else:
                    skipped_logs += 1
            except Exception as err:
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: Could not transform data of"
                        f" [{data_type}][{subtype}]. Error: {err}"
                    ),
                    details=str(traceback.format_exc()),
                )
                skipped_logs += 1
        if skipped_logs > 0:
            self.logger.debug(
                "{}: [{}][{}] Plugin couldn't process {} records because they "
                "either had no data or contained invalid/missing "
                "fields according to the configured JSON mapping. "
                "Therefore, the transformation and ingestion for those "
                "records were skipped.".format(
                    self.log_prefix, data_type, subtype, skipped_logs
                )
            )
        return transformed_data

    def push(
        self, transformed_data: List, data_type: str, subtype: str
    ) -> PushResult:
        """Push the transformed_data to the 3rd party platform.

        Args:
            transformed_data (List): Transformed Data
            data_type (str): The type of data to be ingested (alert/event)
            subtype (str): The subtype of data to be ingested
            (DLP, anomaly etc. in case of alerts)

        Returns:
            PushResult: Push result object with message and status.
        """
        try:
            self.logger.debug(
                f"{self.log_prefix}: "
                f"Initializing the sharing of {len(transformed_data)} "
                f"[{data_type}] [{subtype}] logs "
                f"to the {PLUGIN_NAME} server."
            )
            bucket_name = self.configuration.get("bucket_name", "").strip()
            user_agent = scality_add_user_agent()
            aws_client = ScalityClient(
                self.configuration,
                self.logger,
                self.proxy,
                self.log_prefix,
                user_agent,
            )

            if data_type == "webtx":
                return self.push_webtx_data(
                    aws_client,
                    bucket_name,
                    transformed_data,
                    data_type,
                    subtype,
                )
            else:
                return self.push_alerts_events_data(
                    aws_client,
                    bucket_name,
                    transformed_data,
                    data_type,
                    subtype,
                )
        except ScalityException:
            raise
        except Exception as exp:
            err_msg = (
                "Error occurred while pushing "
                f"log(s) to {PLUGIN_NAME} Bucket {bucket_name}."
            )
            self.logger.error(
                message=(f"{self.log_prefix}: {err_msg} Error: {exp}"),
                details=str(traceback.format_exc()),
            )
            raise ScalityException(err_msg)

    def push_webtx_data(
        self, aws_client, bucket_name, transformed_data, data_type, subtype
    ):
        """Push the transformed_data webtx logs to the Scality platform.

        Args:
            transformed_data (List): List of data to push to Scality bucket.
            data_type (str): Data type.
            subtype (str): Subtype

        Returns:
            PushResult: Push Result containing message and status.
        """
        try:
            skipped_logs, successful_log_push_counter = 0, 0
            temp_obj_file = NamedTemporaryFile("wb", delete=False)
            for data in transformed_data:
                if data:
                    try:
                        temp_obj_file.write(data)
                        successful_log_push_counter += 1
                    except Exception as exp:
                        err_msg = (
                            "Error occurred while "
                            "writing log(s) to temporary object file."
                        )
                        self.logger.error(
                            message=(
                                f"{self.log_prefix}: {err_msg} Error: {exp}"
                            ),
                            details=str(traceback.format_exc()),
                        )
                        skipped_logs += 1
                else:
                    skipped_logs += 1
            temp_obj_file.flush()
            aws_client.push(temp_obj_file.name, data_type, subtype)
            temp_obj_file.close()
            os.unlink(temp_obj_file.name)
            if skipped_logs > 0:
                self.logger.debug(
                    f"{self.log_prefix}: Received empty log(s) from PubSub "
                    f"or failed to write to the object file for {skipped_logs}"
                    " log(s) hence ingestion of those log(s) were skipped."
                )
            log_msg = (
                "[{}] [{}] Successfully ingested {} log(s)"
                " to {} Bucket {}.".format(
                    data_type,
                    subtype,
                    successful_log_push_counter,
                    PLUGIN_NAME,
                    bucket_name,
                )
            )
            self.logger.info(f"{self.log_prefix}: {log_msg}")
            return PushResult(
                success=True,
                message=log_msg,
            )
        except ScalityException:
            raise
        except Exception as exp:
            err_msg = (
                "Error occurred while "
                "writing log(s) to temporary object file."
            )
            self.logger.error(
                message=(f"{self.log_prefix}: {err_msg} Error: {exp}"),
                details=str(traceback.format_exc()),
            )
            raise ScalityException(str(exp))

    def push_alerts_events_data(
        self, aws_client, bucket_name, transformed_data, data_type, subtype
    ):
        """
        Push the transformed_data to the Scality platform.

        args:
            transformed_data (List): List of data to push to Scality bucket.
            data_type (str): Data type.
            subtype (str): Subtype

        Returns:
            PushResult: Push Result containing message and status
        """
        filtered_list = list(filter(lambda d: bool(d), transformed_data))
        empty_dict_count = len(transformed_data) - len(filtered_list)
        try:
            temp_obj_file = NamedTemporaryFile("w", delete=False)
            temp_obj_file.write(json.dumps(filtered_list))
            temp_obj_file.flush()
            aws_client.push(temp_obj_file.name, data_type, subtype)
        except ScalityException:
            raise
        except Exception as exp:
            err_msg = (
                "Error occurred while "
                "writing log(s) to temporary object file."
            )
            self.logger.error(
                message=(f"{self.log_prefix}: {err_msg} Error: {exp}"),
                details=str(traceback.format_exc()),
            )
            raise ScalityException(str(exp))
        finally:
            temp_obj_file.close()
            os.unlink(temp_obj_file.name)
        if empty_dict_count > 0:
            self.logger.debug(
                f"{self.log_prefix}: Received empty log(s) from tenant "
                f"or failed to write to the object file "
                f"for {empty_dict_count}log(s) hence ingestion of"
                " those log(s) were skipped."
            )
        log_msg = (
            "[{}] [{}] Successfully ingested {} log(s)"
            " to {} Bucket {}.".format(
                data_type,
                subtype,
                len(filtered_list),
                PLUGIN_NAME,
                bucket_name,
            )
        )
        self.logger.info(f"{self.log_prefix}: {log_msg}")
        return PushResult(
            success=True,
            message=log_msg,
        )

    def validate(self, configuration: dict) -> ValidationResult:
        """Validate the configuration parameters dict.

        Args:
            configuration (dict): Plugin configuration parameters.

        Returns:
            ValidationResult: Validation Result.
        """
        user_agent = scality_add_user_agent()
        scality_validator = ScalityValidator(
            configuration, self.logger, self.proxy, self.log_prefix, user_agent
        )

        validation_err_msg = "Validation error occurred."

        if configuration.get("transformData", False):
            err_msg = (
                f"This Plugin is designed to send raw data to {PLUGIN_NAME}"
                " Bucket - Please disable the transformation toggle."
            )
            self.logger.error(
                f"{self.log_prefix}: {validation_err_msg} Error: {err_msg}"
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )

        endpoint_url, access_key, secret_access_key, bucket_name = (
            ScalityCredentials.get_credentials(self, configuration)
        )
        if not endpoint_url:
            err_msg = (
                f"{PLUGIN_NAME} Endpoint URL is a required "
                "configuration parameter."
            )
            self.logger.error(
                f"{self.log_prefix}: {validation_err_msg} Error: {err_msg}"
            )
            return ValidationResult(success=False, message=err_msg)
        elif not isinstance(endpoint_url, str):
            err_msg = (
                f"Invalid {PLUGIN_NAME} Endpoint URL found in the"
                " configuration parameters."
            )
            self.logger.error(
                f"{self.log_prefix}: {validation_err_msg} Error: {err_msg}"
            )
            return ValidationResult(success=False, message=err_msg)

        if not access_key:
            err_msg = "Access Key is a required configuration parameter."
            self.logger.error(
                f"{self.log_prefix}: {validation_err_msg} Error: {err_msg}"
            )
            return ValidationResult(success=False, message=err_msg)
        elif not isinstance(access_key, str):
            err_msg = (
                "Invalid Access Key provided in configuration parameters."
            )
            self.logger.error(
                f"{self.log_prefix}: {validation_err_msg} Error: {err_msg}"
            )
            return ValidationResult(success=False, message=err_msg)

        if not secret_access_key:
            err_msg = (
                "Secret Access Key is a required configuration parameter."
            )
            self.logger.error(
                f"{self.log_prefix}: {validation_err_msg} Error: {err_msg}"
            )
            return ValidationResult(success=False, message=err_msg)
        elif not isinstance(secret_access_key, str):
            err_msg = (
                "Invalid Secret Access Key provided in the"
                " configuration parameters."
            )
            self.logger.error(
                f"{self.log_prefix}: {validation_err_msg} Error: {err_msg}"
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )

        if not bucket_name:
            err_msg = "Bucket Name is a required configuration parameter."
            self.logger.error(
                f"{self.log_prefix}: {validation_err_msg} Error: {err_msg}"
            )
            return ValidationResult(success=False, message=err_msg)
        elif not isinstance(bucket_name, str):
            err_msg = (
                "Invalid Bucket Name provided in the configuration parameters."
            )
            self.logger.error(
                f"{self.log_prefix}: {validation_err_msg} Error: {err_msg}"
            )
            return ValidationResult(success=False, message=err_msg)
        # Validate Max File Size.
        max_file_size = configuration.get("max_file_size")
        if max_file_size is None:
            err_msg = "Max File Size is the required configuration parameter."
            self.logger.error(
                f"{self.log_prefix}: {validation_err_msg} Error: {err_msg}"
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )

        if not (
            isinstance(max_file_size, int)
            and scality_validator.validate_max_file_size(max_file_size)
        ):
            err_msg = (
                "Invalid Maximum File Size found in the "
                "configuration parameters. Maximum File Size "
                "should be an integer between 1 to 100."
            )
            self.logger.error(
                f"{self.log_prefix}: {validation_err_msg} Error: {err_msg}"
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )

        # Validate Max Duration.
        max_duration = configuration.get("max_duration")
        if max_duration is None:
            err_msg = "Max Duration is the required configuration parameter."
            self.logger.error(
                f"{self.log_prefix}: {validation_err_msg} Error: {err_msg}"
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        elif not (
            isinstance(max_duration, int)
            and scality_validator.validate_max_duration(max_duration)
        ):
            err_msg = (
                "Invalid Max Duration found in the configuration parameters."
            )
            self.logger.error(
                f"{self.log_prefix}: {validation_err_msg} Error: {err_msg}"
            )
            return ValidationResult(success=False, message=err_msg)
        return self.validate_auth_params(configuration, validation_err_msg)

    def validate_auth_params(self, configuration, validation_err_msg):
        """Validate the authentication params with scality platform.

        Args: configuration (dict).

        Returns:
            ValidationResult: ValidationResult object having validation
            results after making an API call.
        """
        # Validate Auth Credentials.
        try:
            self.logger.debug(
                f"{self.log_prefix}: Validating auth credentials."
            )
            user_agent = scality_add_user_agent()
            scality_validator = ScalityValidator(
                configuration,
                self.logger,
                self.proxy,
                self.log_prefix,
                user_agent,
            )
            aws_client = ScalityClient(
                configuration,
                self.logger,
                self.proxy,
                self.log_prefix,
                user_agent,
            )
            scality_validator.validate_credentials(aws_client)
        except ScalityException as exp:
            return ValidationResult(
                success=False,
                message=f"{validation_err_msg} {exp}",
            )
        except Exception as err:
            error_msg = (
                "Invalid authentication parameters provided."
                " Check logs for more details."
            )
            self.logger.error(
                message=(
                    f"{self.log_prefix}: {validation_err_msg} Error: {err}"
                ),
                details=str(traceback.format_exc()),
            )
            return ValidationResult(
                success=False,
                message=error_msg,
            )
        try:
            aws_client.get_bucket(validation_retries=VALIDATION_MAX_RETRIES)
        except BucketNameAlreadyTaken:
            err_msg = (
                f"Provided Bucket Name already exists on {PLUGIN_NAME} at a "
                "different region. Please try with different name or "
                "use the correct endpoint url."
            )

            self.logger.error(
                message=f"{self.log_prefix}: {validation_err_msg} {err_msg}",
                details=str(traceback.format_exc()),
            )
            return ValidationResult(success=False, message=err_msg)
        except BucketNotFoundError:
            err_msg = (
                f"Provided Bucket Name does not exist on {PLUGIN_NAME}. "
                "Please try with different bucket name or "
                "use the correct endpoint url."
            )
            self.logger.error(
                message=(
                    f"{self.log_prefix}: {validation_err_msg} Error: {err_msg}"
                ),
                details=str(traceback.format_exc()),
            )
            return ValidationResult(success=False, message=err_msg)
        except ScalityException as exp:
            self.logger.error(
                message=f"{self.log_prefix}: {validation_err_msg} {str(exp)}",
                details=str(traceback.format_exc()),
            )
            return ValidationResult(success=False, message=str(exp))
        except ValueError as err:
            self.logger.error(
                message=(
                    f"{self.log_prefix}: {validation_err_msg} "
                    f"Error: {str(err)}"
                ),
                details=str(traceback.format_exc()),
            )
            return ValidationResult(
                success=False,
                message=str(err),
            )
        except Exception as err:
            error_msg = f"{self.log_prefix}: {validation_err_msg} {err}"
            self.logger.error(
                message=error_msg, details=str(traceback.format_exc())
            )
            return ValidationResult(
                success=False,
                message=str(err),
            )
        log_msg = "Validation successful."
        self.logger.debug(
            f"{self.log_prefix}: {log_msg} Successfully validated"
            " configuration parameters."
        )
        return ValidationResult(success=True, message=log_msg)
