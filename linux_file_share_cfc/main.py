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

# Built-in libraries
import traceback

# Local imports
from netskope.integrations.cfc.models import DirectoryConfigurationMetadataOut
from netskope.integrations.cfc.plugin_base import (
    PluginBase,
    ValidationResult,
    PullResult,
)
from netskope.integrations.cfc.utils import (
    CustomException as LinuxFileShareCFCError,
)

from .utils.constants import (
    PLUGIN_NAME,
    PLUGIN_VERSION,
    MODULE_NAME,
    LINUX_FILE_SHARE_FIELDS,
)
from .utils.helper import LinuxFileShareHelper


class LinuxFileShareCFCPlugin(PluginBase):
    """
    Linux File Share CFC plugin class.

    This plugin class is used to pull the image data from the configured
    Linux server.
    """

    def __init__(
        self,
        name,
        *args,
        **kwargs,
    ):
        """Linux File Share CFC plugin initializer.

        Args:
            name (str): Plugin configuration name.
        """
        super().__init__(
            name,
            *args,
            **kwargs,
        )
        self.plugin_name, self.plugin_version = self._get_plugin_info()
        self.log_prefix = f"{MODULE_NAME} {self.plugin_name}"
        if name:
            self.log_prefix = f"{self.log_prefix} [{name}]"
        self.helper = LinuxFileShareHelper(
            name=name,
            logger=self.logger,
            log_prefix=self.log_prefix,
        )

    def _get_plugin_info(self) -> tuple:
        """Get plugin name and version from manifest.

        Returns:
            tuple: tuple of plugin's name and version fetched from manifest.
        """
        try:
            manifest_json = LinuxFileShareCFCPlugin.metadata
            plugin_name = manifest_json.get("name", PLUGIN_NAME)
            plugin_version = manifest_json.get("version", PLUGIN_VERSION)
            return plugin_name, plugin_version
        except Exception as exp:
            self.logger.error(
                message=(
                    "{} {}: Error occurred while getting plugin details."
                    " Error: {}".format(MODULE_NAME, PLUGIN_NAME, exp)
                ),
                details=traceback.format_exc(),
                resolution=(
                    "Ensure that the plugin manifest file is present "
                    "and correctly formatted."
                ),
            )
        return (PLUGIN_NAME, PLUGIN_VERSION)

    def _get_configurations(self) -> tuple:
        """Get server and directory configurations.

        Returns:
            tuple: (server_configuration, directory_configuration)
        """
        server_configuration = self.configuration.get(
            "configuration_parameters", {}
        )
        directory_configuration = self.configuration.get(
            "directory_configuration", {}
        )
        return server_configuration, directory_configuration

    def validate_configuration_parameters(self) -> ValidationResult:
        """Validate the configuration parameters.

        Returns:
            ValidationResult: Validation result.
        """
        self.logger.debug(
            f"{self.log_prefix}: Validating configuration parameters."
        )
        try:
            configuration, _ = self._get_configurations()
            self.helper.strip_string_values(configuration)

            result = self.helper.validate_configuration_parameters(
                configuration
            )

            if result.success is False:
                return result

            self.helper.verify_connection(configuration)
            message = (
                "Successfully validated configuration parameters."
            )
            self.logger.debug(
                message=f"{self.log_prefix}: {message}"
            )
            return ValidationResult(
                success=True,
                message=message,
            )
        except LinuxFileShareCFCError as error:
            return ValidationResult(
                success=False,
                message=str(error),
            )
        except Exception:
            error_message = (
                "Error occurred while verifying the connection with "
                "the provided configuration parameters."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {error_message}",
                details=traceback.format_exc(),
                resolution=(
                    "Ensure that the Server Hostname/IP, Username, Password "
                    "and Port are correct and the Linux server is reachable "
                    "from the Netskope CE instance."
                ),
            )
            return ValidationResult(
                success=False,
                message=error_message,
            )

    def validate_directory_configuration(self) -> ValidationResult:
        """Validate the directory configuration.

        Raises:
            LinuxFileShareCFCError: If an error occurred while verifying
            directory configuration.

        Returns:
            ValidationResult: Directory configuration with verification result.
        """
        self.logger.debug(
            f"{self.log_prefix}: Validating directory configuration."
        )

        try:
            server_configuration, directory_configuration = (
                self._get_configurations()
            )
            self.helper.strip_string_values(server_configuration)

            if not directory_configuration:
                err_msg = "Directory configuration is required."
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: Validation error occurred. "
                        f"{err_msg}"
                    ),
                    resolution=(
                        "Ensure that the directory configuration is "
                        "provided before proceeding."
                    ),
                )
                raise LinuxFileShareCFCError(message=err_msg)

            validation_result: ValidationResult = (
                self.helper.validate_directory_inputs(directory_configuration)
            )

            if not validation_result.success:
                raise LinuxFileShareCFCError(
                    message=validation_result.message
                )

            verification_result: ValidationResult = (
                self.helper.verify_directory_inputs(
                    server_configuration, directory_configuration
                )
            )
            verification_result.data = {
                "directory_configuration": verification_result.data
            }
            self.logger.debug(
                f"{self.log_prefix}: Successfully validated "
                "directory configuration."
            )
            return verification_result
        except ValueError as error:
            self.logger.error(
                message=f"{self.log_prefix}: {str(error)}",
                details=traceback.format_exc(),
                resolution=(
                    "Ensure that there are no duplicate directory path "
                    "and filename filter combinations in the "
                    "directory configuration."
                ),
            )
            raise LinuxFileShareCFCError(
                message=str(error)
            ) from error

        except LinuxFileShareCFCError:
            raise

        except Exception as error:
            error_message = (
                "Error occurred while verifying directory configuration."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {error_message}",
                details=traceback.format_exc(),
                resolution=(
                    "Ensure that the directory configuration is valid and "
                    "the configured paths are accessible on the Linux server."
                ),
            )
            raise LinuxFileShareCFCError(
                message=error_message
            ) from error

    def fetch_images_metadata(self) -> DirectoryConfigurationMetadataOut:
        """Fetch images metadata for the plugin directory configuration.

        Raises:
            LinuxFileShareCFCError: If an error occurred while fetching
            images metadata.

        Returns:
            DirectoryConfigurationMetadataOut: Images metadata for the
            plugin directory configuration.
        """
        self.logger.debug(
            f"{self.log_prefix}: Pulling images metadata."
        )
        try:
            server_configuration, directory_configuration = (
                self._get_configurations()
            )
            images_metadata: DirectoryConfigurationMetadataOut = (
                self.helper.fetch_images_metadata(
                    server_configuration, directory_configuration
                )
            )
            self.logger.debug(
                f"{self.log_prefix}: Successfully pulled images metadata "
                "from the Linux server."
            )
            return images_metadata

        except LinuxFileShareCFCError:
            raise

        except Exception as err:
            error_message = (
                "Error occurred while pulling images metadata "
                "from the Linux server."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {error_message}",
                details=traceback.format_exc(),
                resolution=(
                    "Ensure directory configuration and all configured "
                    "directories are accessible. Check that the configured "
                    "paths exist and contain supported file types."
                ),
            )
            raise LinuxFileShareCFCError(
                message=error_message
            ) from err

    def validate_step(self, step: str) -> ValidationResult:
        """Validate the step for the plugin.

        Args:
            step (str): The step to validate.

        Returns:
            ValidationResult: The validation result.
        """
        if step == "configuration_parameters":
            return self.validate_configuration_parameters()
        elif step == "directory_configuration":
            try:
                return self.validate_directory_configuration()
            except LinuxFileShareCFCError as error:
                return ValidationResult(
                    success=False,
                    message=str(error),
                )
        elif step == "file_results":
            try:
                metadata_result = self.fetch_images_metadata()
                if metadata_result.filesCount.get("error", False):
                    err_msg = metadata_result.filesCount.get("message", "")
                    self.logger.error(
                        message=f"{self.log_prefix}: {err_msg}",
                        resolution=(
                            "Reduce the number of files by refining the "
                            "directory paths or filename filters."
                        ),
                    )
                    return ValidationResult(
                        success=False,
                        message=err_msg,
                    )
                if metadata_result.filesSize.get("error", False):
                    err_msg = metadata_result.filesSize.get("message", "")
                    self.logger.error(
                        message=f"{self.log_prefix}: {err_msg}",
                        resolution=(
                            "Reduce the total size of configured paths by "
                            "selecting fewer directories or using filename "
                            "filters."
                        ),
                    )
                    return ValidationResult(
                        success=False,
                        message=err_msg,
                    )
            except LinuxFileShareCFCError as error:
                return ValidationResult(
                    success=False,
                    message=str(error),
                )
            except Exception:
                error_message = (
                    "Error occurred while validating Preview File Results."
                )
                self.logger.error(
                    message=f"{self.log_prefix}: {error_message}",
                    details=traceback.format_exc(),
                    resolution=(
                        "Ensure that the Linux server is reachable and "
                        "the configured directory paths are accessible."
                    ),
                )
                return ValidationResult(
                    success=False,
                    message=error_message,
                )
            message = "Successfully validated Preview File Results."
            self.logger.debug(
                message=f"{self.log_prefix}: {message}"
            )
            return ValidationResult(
                success=True,
                message=message,
            )
        err_msg = "Validation failed."
        return ValidationResult(
            success=False,
            message=err_msg,
        )

    def pull(self, pull_files=False) -> list:
        """Pull images metadata from remote Linux machine.

        Raises:
            LinuxFileShareCFCError: If any error occurs during the metadata
            retrieval or validation.

        Returns:
            list: List of images metadata.
        """
        try:
            server_configuration, directory_config = self._get_configurations()

            self.helper.strip_string_values(server_configuration)
            self.helper.strip_string_values(directory_config)

            self.logger.info(
                (
                    f"{self.log_prefix}: Pulling "
                    f"images{' and their' if pull_files else ''} metadata from"
                    f" the Linux server."
                )
            )

            stored_paths = self.helper.generate_dir_path_uuid(
                self.configuration, self.storage
            )
            self.storage["directory_paths"] = stored_paths
            directory_storage = self.storage.get("directory_paths", {})

            success = True
            pull_metadata_failed = False
            pull_files_failed = False

            metadata, success = self.helper.pull_metadata(
                server_configuration, directory_config, directory_storage
            )

            if not success:
                pull_metadata_failed = True

            if pull_files:
                status = self.helper.pull_files(server_configuration, metadata)
                if not status:
                    success = status
                    pull_files_failed = True

            partial_errors = []
            if pull_files_failed:
                partial_errors.append(
                    "Error(s) observed during image file download"
                )
            if pull_metadata_failed:
                partial_errors.append(
                    "Error(s) observed during metadata pull"
                )

            error_suffix = (
                f" {'; '.join(partial_errors)}." if partial_errors else "."
            )

            pull_target = (
                "images and their metadata" if pull_files else "images metadata"
            )

            if not metadata and not success:
                self.logger.info(
                    f"{self.log_prefix}: No {pull_target} were pulled."
                    f"{error_suffix}"
                )
            elif partial_errors:
                self.logger.info(
                    f"{self.log_prefix}: {error_suffix}"
                )
            else:
                self.logger.info(
                    f"{self.log_prefix}: Successfully pulled {pull_target}."
                )

            return PullResult(
                metadata=metadata,
                success=success,
            )
        except LinuxFileShareCFCError:
            raise
        except Exception as error:
            error_message = (
                f"Error occurred while pulling the"
                f"{' images and their' if pull_files else ''} metadata."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {error_message}",
                details=traceback.format_exc(),
            )
            raise LinuxFileShareCFCError(
                message=error_message
            ) from error

    def get_fields(self, name: str, configuration: dict) -> list:
        """Get the fields for the specified step name.

        Args:
            name (str): The name of the step.
            configuration (dict): Configuration parameters dictionary.

        Returns:
            list: The fields for the specified step.
        """
        if name in LINUX_FILE_SHARE_FIELDS:
            fields = LINUX_FILE_SHARE_FIELDS[name]
            if name == "file_results":
                for field in fields:
                    if field["type"] == "file_count_result":
                        try:
                            field["default"] = self.fetch_images_metadata()
                        except LinuxFileShareCFCError as error:
                            self.logger.error(
                                message=(
                                    f"{self.log_prefix}: Error occurred while "
                                    f"fetching images metadata for preview. "
                                    f"Error: {str(error)}"
                                ),
                                details=traceback.format_exc(),
                                resolution=(
                                    "Ensure that the Linux server is "
                                    "reachable and the configured directory "
                                    "paths are accessible."
                                ),
                            )
                        except Exception:
                            self.logger.error(
                                message=(
                                    f"{self.log_prefix}: Error occurred while "
                                    "fetching images metadata for preview."
                                ),
                                details=traceback.format_exc(),
                                resolution=(
                                    "Ensure that the Linux server is "
                                    "reachable and the configured directory "
                                    "paths are accessible."
                                ),
                            )
            return fields
        else:
            raise NotImplementedError(
                "No fields available for the specified step name."
            )
