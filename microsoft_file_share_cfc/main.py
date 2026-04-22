"""
BSD 3-Clause License

Copyright (c) 2021, Netskope OSS
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice,
   this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its
   contributors may be used to endorse or promote products derived from
   this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
POSSIBILITY OF SUCH DAMAGE.

Microsoft File Share plugin is used to pull the image data from the
configured Windows machine.
"""

# Built-in libraries
import traceback

# Local imports
from .utils.constants import (
    MICROSOFT_FILE_SHARE_FIELDS,
    MODULE_NAME,
    PLUGIN_NAME,
    PLUGIN_VERSION,
)
from .utils.helper import (
    SMBProtocolFileSharePlugin,
    SFTPProtocolFileSharePlugin
)
from netskope.integrations.cfc.models import (
    DirectoryConfigurationMetadataOut
)
from netskope.integrations.cfc.plugin_base import (
    PluginBase,
    PullResult,
    ValidationResult,
)
from netskope.integrations.cfc.utils import (
    CustomException as MicrosoftFileShareError
)


class MicrosoftFileSharePlugin(PluginBase):
    """Microsoft File Share plugin class.

    This plugin class is used to pull the image data from the
    configured Windows server.
    """

    def __init__(
        self,
        name,
        *args,
        **kwargs,
    ):
        """Microsoft File Share plugin initializer.

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

        # Initialize protocol helper objects
        self.smb_helper = SMBProtocolFileSharePlugin(
            self.name, self.logger, self.log_prefix
        )
        self.sftp_helper = SFTPProtocolFileSharePlugin(
            self.name, self.logger, self.log_prefix
        )

    def _get_plugin_info(self) -> tuple:
        """Get plugin name and version from manifest.

        Returns:
            tuple: tuple of plugin's name and version fetched from
            manifest.
        """
        try:
            manifest_json = MicrosoftFileSharePlugin.metadata
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

    def get_protocol_helper(self, protocol_name: str):
        """Return the helper object for the provided protocol.

        Args:
            protocol_name (str): Name of the protocol.

        Returns:
            Helper object for the provided protocol.
        """
        if protocol_name == "SMB":
            return self.smb_helper
        elif protocol_name == "SFTP":
            return self.sftp_helper

    def validate_protocol(
        self, protocol_configuration: dict
    ) -> ValidationResult:
        """Validate the protocol configuration.

        Args:
            protocol_configuration (dict): Protocol configuration.

        Returns:
            ValidationResult: Validation result.
        """
        if "name" in protocol_configuration:
            if protocol_configuration.get("name") in ["SMB", "SFTP"]:
                msg = "Successfully validated the protocol."
                self.logger.debug(f"{self.log_prefix}: {msg}")
                return ValidationResult(success=True, message=msg)
            else:
                err_msg = (
                    "Invalid protocol provided."
                )
                self.logger.error(f"{self.log_prefix}: {err_msg}")
                return ValidationResult(success=False, message=err_msg)
        else:
            err_msg = "Protocol is required field."
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            return ValidationResult(success=False, message=err_msg)

    def validate_configuration_parameters(self) -> ValidationResult:
        """Validate the configuration parameters.

        Returns:
            ValidationResult: Validation result.
        """
        self.logger.debug(
            f"{self.log_prefix}: Validating configuration parameters."
        )

        try:
            protocol_configuration = self.configuration.get(
                "protocol", {}
            )
            protocol_validation_result: ValidationResult = (
                self.validate_protocol(protocol_configuration)
            )

            if not protocol_validation_result.success:
                return protocol_validation_result

            server_configuration = self.configuration.get(
                "configuration_parameters", {}
            )

            protocol_helper = self.get_protocol_helper(
                self.configuration.get("protocol", {}).get("name")
            )

            validation_result: ValidationResult = (
                protocol_helper.validate_configuration_parameters(
                    server_configuration
                )
            )

            if not validation_result.success:
                return validation_result

            verification_result: ValidationResult = (
                protocol_helper.verify_connection(server_configuration)
            )

            self.logger.debug(
                (
                    f"{self.log_prefix}: Successfully validated "
                    "configuration parameters."
                )
            )

            return verification_result

        except MicrosoftFileShareError:
            raise

        except Exception as err:
            error_message = (
                "Could not verify the connection with the provided "
                "parameters."
            )
            resolution = (
                "Ensure that Server Hostname/IP, port, "
                "username, and password are correct. Ensure the "
                "server is reachable."
            )
            self.logger.error(
                message=(
                    f"{self.log_prefix}: {error_message} Error: {err}"
                ),
                details=traceback.format_exc(),
                resolution=resolution,
            )
            raise MicrosoftFileShareError(
                message=error_message, value=err
            ) from err

    def validate_directory_configuration(self) -> ValidationResult:
        """Validate the directory configuration.

        Raises:
            MicrosoftFileShareError: If an error occurred while
            verifying directory configuration.

        Returns:
            DirectoryConfigurationOut: Directory configuration with
            verification result.
        """
        self.logger.debug(
            f"{self.log_prefix}: Validating directory configuration."
        )

        try:
            server_configuration = self.configuration.get(
                "configuration_parameters", {}
            )

            directory_configuration = self.configuration.get(
                "directory_configuration", {}
            )

            if not directory_configuration:
                raise MicrosoftFileShareError(
                    message="Directory configuration is required."
                )

            protocol_helper = self.get_protocol_helper(
                self.configuration.get("protocol", {}).get("name")
            )

            validation_result: ValidationResult = (
                protocol_helper.validate_directory_inputs(
                    directory_configuration
                )
            )

            if not validation_result.success:
                raise MicrosoftFileShareError(
                    message=validation_result.message
                )

            verification_result: ValidationResult = (
                protocol_helper.verify_directory_inputs(
                    server_configuration, directory_configuration
                )
            )
            verification_result.data = {
                "directory_configuration": verification_result.data
            }
            self.logger.debug(
                (
                    f"{self.log_prefix}: Successfully validated the "
                    "directory configuration parameters."
                )
            )
            return verification_result
        except MicrosoftFileShareError:
            raise
        except ValueError as err:
            error_message = str(err)
            resolution = (
                "Ensure that directory path provided in the "
                "configuration and try again. Ensure that "
                "directory exists and is accessible on the "
                "remote server."
            )
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Validation error in "
                    f"directory configuration. Error: {error_message}"
                ),
                details=traceback.format_exc(),
                resolution=resolution,
            )
            raise MicrosoftFileShareError(
                message=error_message, value=err
            ) from err

        except Exception as err:
            error_message = (
                "An unexpected error occurred while validating "
                "the directory configuration."
            )
            resolution = (
                "Ensure that the directory configuration is correct "
                "and, ensure the shared directory name and all "
                "configured paths are valid and accessible on the "
                "remote server."
            )
            self.logger.error(
                message=(
                    f"{self.log_prefix}: {error_message} Error: {err}"
                ),
                details=traceback.format_exc(),
                resolution=resolution,
            )
            raise MicrosoftFileShareError(
                message=error_message, value=err
            ) from err

    def fetch_images_metadata(self) -> DirectoryConfigurationMetadataOut:
        """Fetch images metadata for the plugin directory configuration.

        Raises:
            MicrosoftFileShareError: If an error occurred while
            fetching images metadata

        Returns:
            DirectoryConfigurationMetadataOut: Images metadata for the
            plugin directory configuration.
        """
        self.logger.debug(
            f"{self.log_prefix}: Pulling images metadata."
        )

        try:
            server_configuration = self.configuration.get(
                "configuration_parameters", {}
            )

            directory_configuration = self.configuration.get(
                "directory_configuration", {}
            )

            protocol_helper = self.get_protocol_helper(
                self.configuration.get("protocol", {}).get("name")
            )

            images_metadata: DirectoryConfigurationMetadataOut = (
                protocol_helper.fetch_images_metadata(
                    server_configuration, directory_configuration
                )
            )
            self.logger.debug(
                (
                    f"{self.log_prefix}: Successfully pulled images "
                    "metadata."
                )
            )

            return images_metadata

        except MicrosoftFileShareError:
            raise

        except Exception as err:
            error_message = (
                "An unexpected error occurred while pulling images "
                "metadata from the server."
            )
            resolution = (
                "Ensure directory configuration and all "
                "configured directories are accessible. Check that "
                "the configured paths exist and contain supported "
                "file types."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {error_message}",
                details=traceback.format_exc(),
                resolution=resolution,
            )
            raise MicrosoftFileShareError(
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
        if step == "protocol":
            result = self.validate_protocol(
                self.configuration.get("protocol", {})
            )
        elif step == "configuration_parameters":
            result = self.validate_configuration_parameters()
        elif step == "directory_configuration":
            result = self.validate_directory_configuration()
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
                msg = "Successfully validated Preview File Results."
                self.logger.debug(f"{self.log_prefix}: {msg}")
                result = ValidationResult(success=True, message=msg)
            except MicrosoftFileShareError as error:
                return ValidationResult(
                    success=False,
                    message=str(error),
                )
            except Exception:
                err_msg = (
                    "Error occurred while validating Preview File Results."
                )
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg}",
                    details=traceback.format_exc(),
                    resolution=(
                        "Ensure that the directory configuration and all "
                        "configured paths are accessible on the remote server."
                    ),
                )
                return ValidationResult(
                    success=False,
                    message=err_msg,
                )
        return result

    def get_fields(self, name: str, configuration: dict) -> list:
        """Get the fields for the specified step name.

        Args:
            name (str): The name of the step.
            configuration (dict): Configuration parameters dictionary.

        Raises:
            NotImplementedError: If the method is not implemented for
            the specified step.
            ValueError: If the provided protocol is not supported.

        Returns:
            list: The fields for the specified step.
        """
        protocol_configuration = self.configuration.get("protocol", {})
        protocol_name = protocol_configuration.get("name")
        if protocol_name in ["SMB", "SFTP"]:
            fields_dict = MICROSOFT_FILE_SHARE_FIELDS.get(
                protocol_name, {}
            )
            if name in fields_dict:
                fields = fields_dict.get(name)
                if name == "file_results":
                    for field in fields:
                        if field.get("type") == "file_count_result":
                            field["default"] = (
                                self.fetch_images_metadata()
                            )
                return fields
            else:
                err_msg = "No fields available for the specified step name."
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: {err_msg}"
                    ),
                    details=traceback.format_exc(),
                )
                raise NotImplementedError(err_msg)
        else:
            err_msg = (
                "Protocol is required field & It should be either "
                "'SMB' or 'SFTP'"
            )
            self.logger.error(
                message=(
                    f"{self.log_prefix}: {err_msg}"
                ),
                details=traceback.format_exc(),
            )
            raise ValueError(err_msg)

    def pull(self, pull_files=False) -> PullResult:
        """Pull images metadata from remote Microsoft machine.

        Raises:
            MicrosoftFileShareError: If any error occurs during the
            metadata retrieval or validation.

        Returns:
            PullResult: PullResult object.
        """
        pull_target = (
            "images and their metadata"
            if pull_files
            else "images metadata"
        )
        try:
            protocol_configuration = self.configuration.get(
                "protocol", {}
            )
            protocol_validation_result = self.validate_protocol(
                protocol_configuration
            )

            if not protocol_validation_result.success:
                return protocol_validation_result

            directory_config = self.configuration.get(
                "directory_configuration", {}
            )
            server_configuration = self.configuration.get(
                "configuration_parameters", {}
            )

            protocol_helper = self.get_protocol_helper(
                self.configuration.get("protocol", {}).get("name")
            )
            self.logger.info(
                f"{self.log_prefix}: Pulling {pull_target}."
            )
            self.storage["directory_paths"] = (
                protocol_helper.generate_dir_path_uuid(
                    self.configuration, self.storage
                )
            )
            directory_storage = self.storage.get("directory_paths", {})
            success = True
            pull_metadata_failed = False
            pull_files_failed = False

            metadata, success = protocol_helper.pull_metadata(
                server_configuration, directory_config, directory_storage
            )

            if not success:
                pull_metadata_failed = True

            if pull_files:
                status = protocol_helper.pull_files(
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

        except MicrosoftFileShareError:
            raise

        except Exception as err:
            error_message = (
                f"An unexpected error occurred while pulling "
                f"{pull_target} from the server."
            )
            resolution = (
                "Ensure that remote server connection and directory "
                "configuration are correct, and ensure the files are "
                "accessible and within the allowed size and count "
                "limits."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {error_message}.",
                details=traceback.format_exc(),
                resolution=resolution,
            )
            raise MicrosoftFileShareError(
                value=err, message=error_message
            ) from err
