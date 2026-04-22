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

SMB File Share CFC Plugin pulls the image or zip files from the directories
present on a remote SMB server (Windows or Samba).
"""

# Built-in libraries
from copy import deepcopy
import traceback

# Local imports
from .utils.helper import SMBProtocolFileShareCFCPlugin
from .utils.constants import (
    SMB_FILE_SHARE_CFC_FIELDS,
    PLUGIN_NAME,
    MODULE_NAME,
    PLUGIN_VERSION,
)
from netskope.integrations.cfc.models import DirectoryConfigurationMetadataOut
from netskope.integrations.cfc.plugin_base import (
    PluginBase,
    ValidationResult,
    PullResult,
)
from netskope.integrations.cfc.utils import CustomException as SMBFileShareCFC


class SMBFileShareCFCPlugin(PluginBase):
    """SMB File Share Plugin Class.

    This plugin class is used to pull the image data
    from the configured SMB server.
    """

    def __init__(
        self,
        name,
        *args,
        **kwargs,
    ):
        """SMB File Share plugin initializer.

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
        self.protocol_object = SMBProtocolFileShareCFCPlugin(
            self.name, self.logger, self.log_prefix
        )

    def _get_plugin_info(self) -> tuple:
        """Get plugin name and version from manifest.

        Returns:
            tuple: tuple of plugin's name and version fetched from manifest.
        """
        try:
            manifest_json = SMBFileShareCFCPlugin.metadata
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
            f"{self.log_prefix}: Validating configuration "
            "parameters."
        )

        try:
            server_configuration, _ = self._get_configurations()

            validation_result = (
                self.protocol_object.validate_configuration_parameters(
                    server_configuration
                )
            )

            if not validation_result.success:
                return validation_result

            verification_result = self.protocol_object.verify_connection(
                server_configuration
            )

            self.logger.debug(
                f"{self.log_prefix}: Successfully validated "
                "configuration parameters."
            )

            return verification_result

        except Exception as err:
            error_message = (
                "Could not verify the connection with the provided parameters."
            )
            self.logger.error(
                message=(
                    f"{self.log_prefix}: {error_message} Error: {err}"
                ),
                details=traceback.format_exc(),
                resolution=(
                    "Ensure that SMB server hostname/IP, port, "
                    "username, and password. Ensure the SMB server "
                    "is reachable."
                ),
            )
            return ValidationResult(
                success=False,
                message=error_message,
            )

    def validate_directory_configuration(self) -> ValidationResult:
        """Validate the directory configuration.

        Raises:
            SMBFileShareCFC: If an error occurred
            while verifying directory configuration.

        Returns:
            DirectoryConfigurationOut: Directory configuration
            with verification result.
        """
        self.logger.debug(
            f"{self.log_prefix}: Validating directory configuration."
        )

        try:
            (
                server_configuration,
                directory_configuration
            ) = self._get_configurations()

            if not directory_configuration:
                raise SMBFileShareCFC(
                    message="Directory configuration is required."
                )

            validation_result: ValidationResult = (
                self.protocol_object.validate_directory_inputs(
                    directory_configuration
                )
            )

            if not validation_result.success:
                raise SMBFileShareCFC(message=validation_result.message)

            verification_result: ValidationResult = (
                self.protocol_object.verify_directory_inputs(
                    server_configuration, directory_configuration
                )
            )
            verification_result.data = {
                "directory_configuration": verification_result.data
            }
            self.logger.debug(
                f"{self.log_prefix}: Successfully validated the "
                "directory configuration parameters."
            )
            return verification_result
        except SMBFileShareCFC:
            raise
        except ValueError as err:
            error_message = str(err)
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Validation error in directory "
                    f"configuration. Error: {error_message}"
                ),
                details=traceback.format_exc(),
                resolution=(
                    "Ensure that directory path provided in the "
                    "configuration and try again. Ensure that "
                    "directory exists and is accessible on the remote "
                    "SMB server."
                ),
            )
            raise SMBFileShareCFC(
                message=error_message, value=err
            ) from err

        except Exception as err:
            error_message = (
                "An unexpected error occurred while validating "
                "the directory configuration."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {error_message} Error: {err}",
                details=traceback.format_exc(),
                resolution=(
                    "Ensure that the directory configuration is correct and, "
                    "ensure the shared directory name and all configured "
                    "paths are valid and accessible on the remote SMB server."
                ),
            )
            raise SMBFileShareCFC(
                message=error_message, value=err
            ) from err

    def fetch_images_metadata(self) -> DirectoryConfigurationMetadataOut:
        """Fetch images metadata for the plugin directory configuration.

        Raises:
            SMBFileShareCFC: If an error occurred
            while fetching images metadata

        Returns:
            DirectoryConfigurationMetadataOut: Images metadata for the
            plugin directory configuration.
        """
        self.logger.debug(f"{self.log_prefix}: Pulling images metadata.")

        try:
            (
                server_configuration,
                directory_configuration
            ) = self._get_configurations()

            images_metadata: DirectoryConfigurationMetadataOut = (
                self.protocol_object.fetch_images_metadata(
                    server_configuration, directory_configuration
                )
            )
            self.logger.debug(
                f"{self.log_prefix}: Successfully pulled images metadata "
                "from the SMB server."
            )

            return images_metadata

        except SMBFileShareCFC:
            raise

        except Exception as err:
            error_message = (
                "An unexpected error occurred while pulling images metadata "
                "from the SMB server."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {error_message}",
                details=traceback.format_exc(),
                resolution=(
                    "Ensure directory configuration and all "
                    "configured directories are accessible. Check that the "
                    "configured paths exist and contain supported file types."
                ),
            )
            raise SMBFileShareCFC(
                message=error_message, value=err
            ) from err

    def validate_step(self, step: str) -> ValidationResult:
        """Validate the step for the plugin.

        Args:
            step (str): The step to validate.

        Returns:
            ValidationResult: The validation result.
        """
        result = ValidationResult(
            success=False,
            message="Step validation failed.",
        )
        if step == "configuration_parameters":
            result = self.validate_configuration_parameters()
        elif step == "directory_configuration":
            result = self.validate_directory_configuration()
        elif step == "file_results":
            try:
                metadata = self.fetch_images_metadata()

                files_size_info = getattr(metadata, "filesSize", None)
                files_count_info = getattr(metadata, "filesCount", None)

                size_error = (
                    isinstance(files_size_info, dict)
                    and files_size_info.get("error")
                )
                count_error = (
                    isinstance(files_count_info, dict)
                    and files_count_info.get("error")
                )

                if size_error or count_error:
                    message = (
                        files_size_info.get(
                            "message",
                            "Total file size limit exceeded.",
                        )
                        if size_error
                        else files_count_info.get(
                            "message",
                            "Total file count limit exceeded.",
                        )
                    )
                    result = ValidationResult(success=False, message=message)
                else:
                    message = "Successfully validated the file results step."
                    result = ValidationResult(
                        success=True,
                        message=message,
                    )
                    self.logger.debug(
                        f"{self.log_prefix}: {message}"
                    )
            except SMBFileShareCFC as err:
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: Validation failed for the "
                        f"'file_results' step. Error: {err.message}"
                    ),
                    details=traceback.format_exc(),
                    resolution=(
                        "Ensure that directory configuration and all "
                        "configured paths are valid and accessible on "
                        "the remote SMB server."
                    ),
                )
                result = ValidationResult(
                    success=False,
                    message=f"Validation failed: {err.message}",
                )
            except Exception as err:
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: An unexpected error occurred "
                        f"while validating the 'file_results' step. "
                        f"Error: {err}"
                    ),
                    details=traceback.format_exc(),
                    resolution=(
                        "Ensure that configuration parameters and directory "
                        "settings, and ensure the SMB server is accessible "
                        "and the configured paths are correct."
                    ),
                )
                result = ValidationResult(
                    success=False,
                    message=f"Validation failed: {str(err)}",
                )
        return result

    def get_fields(self, name: str, configuration: dict) -> list:
        """Get the fields for the specified step name.

        Args:
            name (str): The name of the step.
            configuration (dict): Configuration parameters dictionary.

        Raises:
            NotImplementedError: If the method is not implemented
            for the specified step.
            ValueError: If the provided protocol is not supported.

        Returns:
            list: The fields for the specified step.
        """
        if name in SMB_FILE_SHARE_CFC_FIELDS:
            fields = deepcopy(SMB_FILE_SHARE_CFC_FIELDS[name])
            if name == "file_results":
                for field in fields:
                    if field["type"] == "file_count_result":
                        try:
                            field["default"] = self.fetch_images_metadata()
                        except (Exception, SMBFileShareCFC) as err:
                            self.logger.error(
                                message=f"{self.log_prefix}: Error occurred "
                                f"while pulling plugin fields. Error: {err}",
                                details=traceback.format_exc(),
                                resolution=(
                                    "Ensure that configuration is valid "
                                    "and the SMB server is accessible."
                                ),
                            )
                            field["default"] = {}
            return fields
        else:
            raise NotImplementedError(
                "No fields available for the specified step name."
            )

    def pull(self, pull_files=False) -> list:
        """Pull images metadata from remote SMB server.

        Raises:
            SMBFileShareCFC: If any error occurs during the metadata retrieval
            or validation.

        Returns:
            list: List of images metadata.
        """
        pull_target = (
            "images and their metadata"
            if pull_files
            else "images metadata"
        )
        try:
            server_configuration, directory_config = self._get_configurations()

            self.logger.info(
                f"{self.log_prefix}: Pulling of {pull_target} "
                "from the SMB server."
            )

            self.storage["directory_paths"] = (
                self.protocol_object.generate_dir_path_uuid(
                    self.configuration, self.storage
                )
            )
            directory_storage = self.storage.get("directory_paths", {})
            success = True
            pull_metadata_failed = False
            pull_files_failed = False

            metadata, success = self.protocol_object.pull_metadata(
                server_configuration,
                directory_config,
                directory_storage
            )

            if not success:
                pull_metadata_failed = True

            if pull_files:
                status = self.protocol_object.pull_files(
                    server_configuration, metadata
                )
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

            if not metadata and not success:
                self.logger.info(
                    f"{self.log_prefix}: No {pull_target} were pulled. "
                    f"{error_suffix}"
                )
            elif partial_errors:
                self.logger.info(
                    f"{self.log_prefix}: {error_suffix}"
                )
            else:
                self.logger.info(
                    f"{self.log_prefix}: Successfully pulled "
                    f"{pull_target}."
                )

            return PullResult(
                metadata=metadata,
                success=success,
            )

        except Exception as err:
            error_message = (
                f"An unexpected error occurred while pulling "
                f"{pull_target} from the SMB server."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {error_message}.",
                details=traceback.format_exc(),
                resolution=(
                    "Ensure that SMB server connection and directory "
                    "configuration are correct, and ensure the files are "
                    "accessible and within the allowed size and count limits."
                ),
            )
            raise SMBFileShareCFC(
                value=err, message=error_message
            ) from err
