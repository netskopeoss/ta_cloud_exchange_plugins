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

Local Export Plugin."""


import time
import traceback
from typing import List, Tuple
import os

from netskope.integrations.cls.plugin_base import (
    PluginBase,
    ValidationResult,
    PushResult,
)

MODULE_NAME = "CLS"
PLUGIN_NAME = "Local Export"
PLUGIN_VERSION = "1.0.0"


class DiskPlugin(PluginBase):
    """The Local Export plugin implementation class."""

    def __init__(
        self,
        name,
        *args,
        **kwargs,
    ):
        """Initialize Plugin class."""
        super().__init__(
            name,
            *args,
            **kwargs,
        )
        self.plugin_name, self.plugin_version = self._get_plugin_info()
        self.log_prefix = f"{MODULE_NAME} {self.plugin_name}"
        if name:
            self.log_prefix = f"{self.log_prefix} [{name}]"

    def _get_plugin_info(self) -> Tuple:
        """Get plugin name and version from manifest.

        Returns:
            tuple: Tuple of plugin's name and version fetched from manifest.
        """
        try:
            manifest_json = DiskPlugin.metadata
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
        return raw_data

    def push(self, transformed_data, data_type, subtype) -> PushResult:
        """
        Pushes the transformed data to disk.

        Args:
            transformed_data (List[bytes]): The transformed data to be stored.
            data_type (str): The type of data being stored.
            subtype (str): The subtype of the data being stored.

        Returns:
            PushResult: An object representing the result of the push operation.

        Raises:
            Exception: If an error occurs while storing the data to disk.
        """
        total_count = 0
        skip_count = 0
        try:
            self.logger.info(
                f"{self.log_prefix}: Storing transformed data to local storage.",
            )
            storage_path = self.configuration.get("storage_path")
            obj_prefix = self.configuration.get("obj_prefix", "default")
            filename = f"{obj_prefix}_webtx_{int(time.time())}.txt.gz"
            with open(
                os.path.join(
                    storage_path,
                    filename,
                ),
                "wb",
            ) as out:
                for data in transformed_data:
                    try:
                        out.write(data)
                        total_count += 1
                    except Exception:
                        self.logger.error(
                            message=f"{self.log_prefix}: Error occurred whie writing object.",
                            details=str(traceback.format_exc()),
                        )
                        skip_count += 1
                        pass

            self.logger.info(
                f"{self.log_prefix}: Successfully {total_count} records stored to local storage with File name: {filename}.",
            )
            if skip_count > 0:
                self.logger.info(
                    f"{self.log_prefix}: Skipped {skip_count} records due to error while storing to local storage.",
                )

        except Exception as e:
            self.logger.error(
                message=f"{self.log_prefix}: Error occurred while storing to local storage: {e}",
                details=str(traceback.format_exc()),
            )
            raise

    def validate(self, configuration: dict) -> ValidationResult:
        """
        Validates the configuration provided by checking if the storage path and object prefix are present and valid. If the storage path or object prefix are missing or not of type string, a validation error message is logged and a ValidationResult object with success=False and the corresponding error message is returned. If the storage path does not exist, a validation error message is logged and a ValidationResult object with success=False and the corresponding error message is returned. If all validations pass, a ValidationResult object with success=True and the message "Validation successful." is returned.

        :param configuration: A dictionary containing the configuration parameters.
        :type configuration: dict
        :return: A ValidationResult object indicating whether the validation was successful and the corresponding message.
        :rtype: ValidationResult
        """

        validation_err_msg = f"{self.log_prefix}: Validation error occurred."

        storage_path = configuration.get("storage_path", "").strip()
        if not storage_path:
            err_msg = "Storage path is a required configuration parameter."
            self.logger.error(f"{validation_err_msg} {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        elif not isinstance(storage_path, str):
            err_msg = "Invalid Storage path provided in configuration parameters."
            self.logger.error(f"{validation_err_msg} {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )

        obj_prefix = configuration.get("obj_prefix", "").strip()
        if not obj_prefix:
            err_msg = "Object prefix is a required configuration parameter."
            self.logger.error(f"{validation_err_msg} {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        elif not isinstance(obj_prefix, str):
            err_msg = "Invalid Object prefix provided in configuration parameters."
            self.logger.error(f"{validation_err_msg} {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        elif obj_prefix.find("/") > -1:
            err_msg = "Invalid Object prefix provided in configuration parameters. '/' is not allowed in object prefix."
            self.logger.error(f"{validation_err_msg} {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        # Validate Max File Size.
        max_file_size = configuration.get("max_file_size")
        if max_file_size is None:
            err_msg = (
                "Maximum File Size (in MBs) is the required configuration parameter."
            )
            self.logger.error(f"{validation_err_msg} {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        elif not isinstance(max_file_size, int):
            err_msg = "Invalid Maximum File Size (in MBs) provided in configuration parameters."
            self.logger.error(f"{validation_err_msg} {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        elif max_file_size <= 0 or max_file_size > 100:
            err_msg = (
                "Maximum File Size (in MBs) should be an integer between 1 to 100."
            )
            self.logger.error(f"{validation_err_msg} {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )

        # Validate Max Duration.
        max_duration = configuration.get("max_duration")
        if max_duration is None:
            err_msg = (
                "Maximum Duration (in Seconds) is the required configuration parameter."
            )
            self.logger.error(f"{validation_err_msg} {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        elif not isinstance(max_duration, int):
            err_msg = "Invalid Maximum Duration (in Seconds) provided in configuration parameters."
            self.logger.error(f"{validation_err_msg} {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        elif max_duration <= 0:
            err_msg = "Maximum Duration (in Seconds) should be greater than 0."
            self.logger.error(f"{validation_err_msg} {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        elif max_duration > 315360000:  # 10 years
            err_msg = "Maximum Duration (in Seconds) can not be greater than 10 years."
            self.logger.error(f"{validation_err_msg} {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )

        isExist = os.path.exists(storage_path)
        if not isExist:
            err_msg = "Storage path does not exist."
            self.logger.error(f"{validation_err_msg} {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        if not os.access(storage_path, os.W_OK):
            err_msg = "Storage path does not have writable permission."
            self.logger.error(f"{validation_err_msg} {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )

        if not os.access(storage_path, os.X_OK):
            err_msg = "Storage path does not have executable permission."
            self.logger.error(f"{validation_err_msg} {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )

        return ValidationResult(success=True, message="Validation successful.")
