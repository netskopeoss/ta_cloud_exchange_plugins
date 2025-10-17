"""Microsoft File Share CFC Plugin.

Microsoft File Share plugin is used to pull the image data from the configured Windows machine.
"""

# Built-in libraries
import os
import re
import stat
import traceback
from datetime import datetime
from uuid import uuid4

# Third-party libraries
from .lib import paramiko
from .lib.paramiko.ssh_exception import AuthenticationException, SSHException
from .lib.smb.base import NotConnectedError, NotReadyError
from .lib.smb.SMBConnection import SMBConnection

# Local imports
from .utils.constants import (
    ALLOWED_FILE_COUNT, ALLOWED_FILE_SIZE,
    MICROSOFT_FILE_SHARE_FIELDS, PLUGIN_NAME,
    SUPPORTED_IMAGE_FILE_EXTENSIONS, MODULE_NAME,
    PLUGIN_VERSION)
from netskope.common.utils import Logger
from netskope.integrations.cfc.models import (
    DirectoryConfigurationMetadataOut)
from netskope.integrations.cfc.plugin_base import PluginBase, ValidationResult, PullResult
from netskope.integrations.cfc.utils import \
    CustomException as MicrosoftFileShareError, FILE_PATH


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


class MicrosoftFileSharePlugin(PluginBase):
    """
    Microsoft File Share plugin class.

    This plugin class is used to pull the image data from the configured Windows server.
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

    def _get_plugin_info(self) -> tuple:
        """Get plugin name and version from manifest.

        Returns:
            tuple: tuple of plugin's name and version fetched from manifest.
        """
        try:
            manifest_json = MicrosoftFileSharePlugin.metadata
            plugin_name = manifest_json.get("name", PLUGIN_NAME)
            plugin_version = manifest_json.get("version", PLUGIN_VERSION)
            return plugin_name, plugin_version
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

    def get_protocol_class(self, protocol_name: str) -> PluginBase:
        """Return the helper class for the provided protocol.

        Args:
            protocol_name (str): Name of the protocol.

        Returns:
            PluginBase: Helper class for the provided protocol.
        """
        if protocol_name == "SMB":
            return SMBProtocolFileSharePlugin(
                self.name, self.logger, self.log_prefix
            )
        elif protocol_name == "SFTP":
            return SFTPProtocolFileSharePlugin(
                self.name, self.logger, self.log_prefix
            )

    def validate_protocol(self, protocol_configuration: dict) -> ValidationResult:
        """Validate the protocol configuration.

        Args:
            protocol_configuration (dict): Protocol configuration.

        Returns:
            ValidationResult: Validation result.
        """
        if "name" in protocol_configuration:
            if protocol_configuration["name"] in ["SMB", "SFTP"]:
                return ValidationResult(
                    success=True,
                    message="Protocol validated successfully.",
                )
            else:
                return ValidationResult(
                    success=False,
                    message=(
                        "Invalid protocol provided. "
                        "Protocol should be either 'SMB' or 'SFTP'."
                    ),
                )
        else:
            return ValidationResult(
                success=False, message="Protocol is required field."
            )

    def strip_string_values(self, configuration: dict):
        """Strip the string values from the configuration parameters.

        Args:
            configuration (dict): Configuration parameters.
        """
        for parameter, value in configuration.items():
            if isinstance(value, str):
                configuration[parameter] = value.strip()

    def validate_configuration_parameters(self) -> ValidationResult:
        """Validate the configuration parameters.

        Returns:
            ValidationResult: Validation result.
        """
        self.logger.debug(
            f"{self.log_prefix}: Validating configuration parameters for '{self.name}' plugin."
        )

        try:
            protocol_configuration = self.configuration.get("protocol", {})
            protocol_validation_result: ValidationResult = self.validate_protocol(
                protocol_configuration
            )

            if not protocol_validation_result.success:
                return protocol_validation_result

            server_configuration = self.configuration.get(
                "configuration_parameters", {}
            )
            self.strip_string_values(server_configuration)

            protocol_object = self.get_protocol_class(
                self.configuration["protocol"]["name"]
            )

            validation_result: ValidationResult = (
                protocol_object.validate_configuration_parameters(server_configuration)
            )

            if not validation_result.success:
                return validation_result

            verification_result: ValidationResult = protocol_object.verify_connection(
                server_configuration
            )

            self.logger.debug(
                f"{self.log_prefix}: Configuration parameter validated for '{self.name}' plugin."
            )

            return verification_result

        except Exception:
            error_message = f"Could not verify the connection with the provided parameters for '{self.name}' plugin."
            self.logger.error(
                message=f"{self.log_prefix}: {error_message}",
                details=traceback.format_exc(),
            )
            return ValidationResult(
                success=False,
                message=error_message,
            )

    def validate_directory_configuration(self) -> ValidationResult:
        """Validate the directory configuration.

        Raises:
            MicrosoftFileShareError: If an error occurred while verifying directory configuration.

        Returns:
            DirectoryConfigurationOut: Directory configuration with verification result.
        """
        self.logger.debug(
            f"{self.log_prefix}: Validating directory configuration for '{self.name}' plugin."
        )

        try:
            server_configuration = self.configuration["configuration_parameters"]
            self.strip_string_values(server_configuration)

            directory_configuration = self.configuration.get(
                "directory_configuration", {}
            )

            if not directory_configuration:
                raise MicrosoftFileShareError(
                    message="Directory configuration is required."
                )

            protocol_object = self.get_protocol_class(
                self.configuration["protocol"]["name"]
            )

            validation_result: ValidationResult = (
                protocol_object.validate_directory_inputs(directory_configuration)
            )

            if not validation_result.success:
                raise MicrosoftFileShareError(message=validation_result.message)

            verification_result: ValidationResult = (
                protocol_object.verify_directory_inputs(
                    server_configuration, directory_configuration
                )
            )
            verification_result.data = {"directory_configuration": verification_result.data}
            self.logger.debug(
                f"{self.log_prefix}: Directory configuration validated for '{self.name}' plugin."
            )
            return verification_result
        except ValueError as error:
            self.logger.error(message=str(error), details=traceback.format_exc())
            raise MicrosoftFileShareError(message=str(error), value=error) from error

        except Exception as error:
            error_message = f"Error occurred while verifying directory configuration for '{self.name}' plugin."
            self.logger.error(
                message=f"{self.log_prefix}: {error_message}",
                details=traceback.format_exc(),
            )
            raise MicrosoftFileShareError(
                message=error_message, value=error
            ) from error

    def fetch_images_metadata(self) -> DirectoryConfigurationMetadataOut:
        """Fetch images metadata for the plugin directory configuration.

        Raises:
            MicrosoftFileShareError: If an error occurred while fetching images metadata

        Returns:
            DirectoryConfigurationMetadataOut: Images metadata for the plugin directory configuration.
        """
        self.logger.debug(
            f"{self.log_prefix}: Fetching images metadata for '{self.name}' plugin."
        )

        try:
            server_configuration = self.configuration["configuration_parameters"]
            self.strip_string_values(server_configuration)

            directory_configuration = self.configuration.get(
                "directory_configuration", {}
            )

            protocol_object = self.get_protocol_class(
                self.configuration["protocol"]["name"]
            )

            images_metadata: DirectoryConfigurationMetadataOut = (
                protocol_object.fetch_images_metadata(
                    server_configuration, directory_configuration
                )
            )
            self.logger.debug(
                f"{self.log_prefix}: Images metadata fetched for '{self.name}' plugin."
            )

            return images_metadata

        except Exception as error:
            error_message = f"Error occurred while fetching images metadata for '{self.name}' plugin."
            self.logger.error(
                message=f"{self.log_prefix}: {error_message}",
                details=traceback.format_exc(),
            )
            raise MicrosoftFileShareError(
                message=error_message, value=error
            ) from error

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
            result = ValidationResult(
                success=True,
                message="Step validated successfully.",
            )
        return result

    def get_fields(self, name: str, configuration: dict) -> list:
        """Get the fields for the specified step name.

        Args:
            name (str): The name of the step.
            configuration (dict): Configuration parameters dictionary.

        Raises:
            NotImplementedError: If the method is not implemented for the specified step.
            ValueError: If the provided protocol is not supported.

        Returns:
            list: The fields for the specified step.
        """
        protocol_configuration = self.configuration.get("protocol", {})
        if "name" in protocol_configuration and protocol_configuration["name"] in [
            "SMB",
            "SFTP",
        ]:
            if name in MICROSOFT_FILE_SHARE_FIELDS[protocol_configuration["name"]]:
                fields = MICROSOFT_FILE_SHARE_FIELDS[
                    protocol_configuration["name"]
                ][name]
                if name == "file_results":
                    for field in fields:
                        if field["type"] == "file_count_result":
                            field["default"] = self.fetch_images_metadata()
                return fields
            else:
                raise NotImplementedError(
                    "No fields available for the specified step name."
                )
        else:
            raise ValueError(
                "Protocol is required field & It should be either 'SMB' or 'SFTP'"
            )

    def pull(self, pull_files=False) -> list:
        """Pull images metadata from remote Microsoft machine.

        Raises:
            MicrosoftFileShareError: If any error occurs during the metadata retrieval or validation.

        Returns:
            list: List of images metadata.
        """
        try:
            protocol_configuration = self.configuration.get("protocol", {})
            protocol_validation_result = self.validate_protocol(protocol_configuration)

            if not protocol_validation_result.success:
                return protocol_validation_result

            directory_config = self.configuration.get("directory_configuration", {})
            server_configuration = self.configuration.get("configuration_parameters", {})
            self.strip_string_values(server_configuration)

            protocol_object = self.get_protocol_class(
                self.configuration["protocol"]["name"]
            )

            self.logger.info(
                (
                    f"{self.log_prefix}: Fetching the images{' and their' if pull_files else ''} metadata from the Windows server for "
                    f"configuration '{self.name}'."
                )
            )
            self.storage["directory_paths"] = protocol_object.generate_dir_path_uuid(
                self.configuration, self.storage
            )
            directory_storage = self.storage.get("directory_paths", {})
            success = True
            metadata, success = protocol_object.pull_metadata(
                server_configuration, directory_config, directory_storage
            )

            if pull_files:
                status = protocol_object.pull_files(server_configuration, metadata)
                # if pull_files fails, set success to False
                if not status:
                    success = status

            self.logger.info(
                (
                    f"{self.log_prefix}: Images{' and their' if pull_files else ''} metadata fetched successfully from "
                    f"the Windows server for configuration '{self.name}'."
                )
            )

            return PullResult(
                metadata=metadata,
                success=success,
            )
        except Exception as error:
            error_message = (
                f"Error: '{error}' occurred while pulling the"
                f"{' images and their' if pull_files else ''} metadata"
            )
            self.logger.error(
                message=f"{self.log_prefix}: {error_message} for configuration '{self.name}'.",
                details=traceback.format_exc(),
            )
            raise MicrosoftFileShareError(
                value=error, message=str(error)
            ) from error


class SMBProtocolFileSharePlugin:
    """Microsoft File Share plugin helper class for SMB protocol.

    This class implements helper methods to validate & verify SMB protocol based configuration.
    """

    def __init__(self, name: str, logger: Logger, log_prefix: str):
        """Initialize method for this class.

        Args:
            name (str): Name of the plugin configuration.
            logger (Logger): Logger object.
            log_prefix (str): Prefix string to be added to the log messages.
        """
        self.name = name
        self.logger = logger
        self.log_prefix = log_prefix

    def validate_configuration_parameters(
        self, configuration: dict
    ) -> ValidationResult:
        """Validate the configuration parameters.

        Args:
            configuration (dict): Configuration parameters.

        Returns:
            ValidationResult: Validation result.
        """
        server_ip = "smb_server_ip"
        if server_ip in configuration:
            if (
                isinstance(configuration[server_ip], str)
                and configuration[server_ip].strip()
            ):
                pass
            else:
                return ValidationResult(
                    success=False,
                    message="Windows Server IP/Hostname should be a non-empty string value.",
                )
        else:
            return ValidationResult(
                success=False, message="Server IP/Hostname is required field."
            )

        machine_name = "smb_machine_name"
        if machine_name in configuration:
            if (
                isinstance(configuration[machine_name], str)
                and configuration[machine_name].strip()
            ):
                pass
            else:
                return ValidationResult(
                    success=False,
                    message="Windows Machine name should be a non-empty string value.",
                )
        else:
            return ValidationResult(
                success=False, message="Windows Machine name is required field."
            )

        username = "smb_username"
        if username in configuration:
            if (
                isinstance(configuration[username], str)
                and configuration[username].strip()
            ):
                pass
            else:
                return ValidationResult(
                    success=False,
                    message="Username should be a non-empty string value.",
                )
        else:
            return ValidationResult(
                success=False, message="Username is required field."
            )

        password = "smb_password"
        if password in configuration:
            if (
                isinstance(configuration[password], str)
                and configuration[password].strip()
            ):
                pass
            else:
                return ValidationResult(
                    success=False,
                    message="Password should be a non-empty string value.",
                )
        else:
            return ValidationResult(
                success=False, message="Password is required field."
            )

        return ValidationResult(
            success=True,
            message="Validation of configuration parameters completed successful.",
        )

    def get_smb_connection_object(self, configuration: dict, retry: bool = True) -> (SMBConnection, bool):
        """Get a SMB connection to the remote Windows server.

        Args:
            configuration (dict): Configuration parameters.
            retry (bool, optional): Retry flag. Defaults to True.

        Raises:
            MicrosoftFileShareError: If an error occurred while connecting with the Windows server.

        Returns:
            (SMBConnection, bool): SMB connection object and connection result.
        """
        try:
            connection = SMBConnection(
                username=configuration["smb_username"],
                password=configuration["smb_password"],
                my_name="netskope_machine",
                remote_name=configuration["smb_machine_name"],
            )
            connection_result = connection.connect(
                ip=configuration["smb_server_ip"],
            )
            return connection, connection_result
        except NotReadyError as error:
            error_message = ("Authentication failed while connecting with the "
                             f"Windows server '{configuration['smb_server_ip']}'.")
            self.logger.error(
                message=f"{self.log_prefix}: {error_message}",
                details=traceback.format_exc(),
            )
            raise MicrosoftFileShareError(
                message=error_message, value=error
            ) from error
        except NotConnectedError as error:
            error_message = f"Couldn't connect with the Windows server '{configuration['smb_server_ip']}'."
            self.logger.error(
                message=f"{self.log_prefix}: {error_message}",
                details=traceback.format_exc(),
            )
            if retry:
                self.logger.warn(
                    message=(f"{self.log_prefix}: Reconnecting with the Windows server "
                             f"'{configuration['smb_server_ip']}'.")
                )
                return self.get_smb_connection_object(
                    configuration=configuration, retry=False
                )
            raise MicrosoftFileShareError(
                message=error_message, value=error
            ) from error
        except TimeoutError as error:
            error_message = ("Connection request to the Windows server "
                             f"'{configuration['smb_server_ip']}' got timed out.")
            self.logger.error(
                message=f"{self.log_prefix}: {error_message}",
                details=traceback.format_exc(),
            )
            raise MicrosoftFileShareError(
                message=error_message, value=error
            ) from error

    def verify_connection(self, configuration: dict) -> ValidationResult:
        """Verify the connection with the Windows server.

        Args:
            configuration (dict): Configuration parameters.

        Returns:
            ValidationResult: Validation result.
        """
        server_ip = configuration["smb_server_ip"]
        connection, connection_result = self.get_smb_connection_object(configuration)
        if connection_result:
            connection.close()
            return ValidationResult(
                success=True,
                message=(
                    "Connection with the Windows server "
                    f"'{server_ip}' verified successfully."
                ),
            )

        return ValidationResult(
            success=False,
            message=(
                f"Couldn't verify the connection with the Windows server "
                f"'{server_ip}'."
            ),
        )

    def validate_directory_inputs(
        self, directory_configuration: dict
    ) -> ValidationResult:
        """Validate the directory configuration.

        Args:
            directory_configuration (dict): Directory configuration.

        Returns:
            ValidationResult: Validation result.
        """
        directory_inputs = directory_configuration.get("directory_inputs", [])

        if not directory_inputs:
            return ValidationResult(
                success=False,
                message="Directory inputs are required field.",
            )

        for directory_configuration in directory_inputs:
            if "sharedDirectoryName" in directory_configuration:
                if (
                    isinstance(directory_configuration["sharedDirectoryName"], str)
                    and directory_configuration["sharedDirectoryName"].strip()
                ):
                    pass
                else:
                    return ValidationResult(
                        success=False,
                        message="Shared directory name should be a non-empty string value.",
                    )
            else:
                return ValidationResult(
                    success=False,
                    message="Shared directory name is required field.",
                )

            directory_list = directory_configuration.get("directory_paths", [])

            if directory_list:
                for directory in directory_list:
                    if "directory_path" in directory:
                        if (
                            isinstance(directory["directory_path"], str)
                            and directory["directory_path"].strip()
                        ):
                            pass
                        else:
                            return ValidationResult(
                                success=False,
                                message="Directory path should be a non-empty string value.",
                            )
                    else:
                        return ValidationResult(
                            success=False,
                            message="Directory path is required field.",
                        )

                    if "filename_filter" in directory:
                        if isinstance(directory["filename_filter"], str):
                            pass
                        else:
                            return ValidationResult(
                                success=False,
                                message="Filename filter should be a string value.",
                            )
                    else:
                        return ValidationResult(
                            success=False,
                            message="Filename filter is required field.",
                        )
            else:
                return ValidationResult(
                    success=False,
                    message="At least one directory path is required.",
                )

        shared_directories_set = set()

        for directory_configuration in directory_inputs:
            shared_directory_name = directory_configuration[
                "sharedDirectoryName"
            ].strip()

            if shared_directory_name in shared_directories_set:
                return ValidationResult(
                    success=False,
                    message=f"Shared directory {shared_directory_name} is duplicated.",
                )
            shared_directories_set.add(shared_directory_name)

        for directory_configuration in directory_inputs:
            shared_directory_name = directory_configuration["sharedDirectoryName"].strip()
            directory_list = directory_configuration["directory_paths"]

            directory_set = set()

            for directory in directory_list:
                directory_path = directory["directory_path"].strip()
                filename_filter = directory["filename_filter"]

                if tuple((directory_path, filename_filter)) in directory_set:
                    if filename_filter:
                        error_message = (
                            f"Directory path '{directory_path}' and "
                            f"filename filter '{filename_filter}' are duplicated for "
                            f"directory '{shared_directory_name}'."
                        )
                    else:
                        error_message = (
                            f"Directory path '{directory_path}' is and "
                            "empty filename filter are duplicated for directory "
                            f"'{shared_directory_name}'."
                        )
                    raise ValueError(error_message)
                directory_set.add(tuple((directory_path, filename_filter)))

        return ValidationResult(
            success=True,
            message="Validation of directory inputs completed successfully.",
        )

    def verify_directory_inputs(
        self, configuration: dict, directory_configurations: dict
    ) -> ValidationResult:
        """Verify the directory configuration.

        Args:
            configuration (dict): Configuration parameters.
            directory_configurations (dict): Directory configuration.

        Raises:
            MicrosoftFileShareError: If an error occurred while verifying directory configuration.

        Returns:
            DirectoryConfigurationOut: Directory configuration with verification result.
        """
        directory_inputs = directory_configurations["directory_inputs"]

        success_status = True

        result_data = list()

        connection, connection_result = self.get_smb_connection_object(configuration)

        if connection_result:
            for directory_configuration in directory_inputs:
                shared_directory_name = directory_configuration[
                    "sharedDirectoryName"
                ].strip()
                directory_list = directory_configuration["directory_paths"]

                directory_result = {
                    "sharedDirectoryName": shared_directory_name,
                    "directory_paths": list(),
                }
                shared_directory_exist = True
                directory_entry_invalid = False

                for directory in directory_list:
                    directory_path = directory["directory_path"].strip()
                    filename_filter = directory["filename_filter"]

                    directory_entry = {
                        "directory_path": directory_path,
                        "filename_filter": filename_filter,
                    }

                    if not shared_directory_exist:
                        directory_result["directory_paths"].append(
                            directory_entry
                        )
                        continue

                    try:
                        _ = connection.listPath(shared_directory_name, directory_path)
                    except Exception as error:
                        success_status = False
                        if "Unable to connect to shared device" in error.message:
                            shared_directory_exist = False
                            directory_result.update(
                                {
                                    "error": True,
                                    "message": "Unable to connect to shared directory.",
                                    "errorType": "shared_directory_error"
                                }
                            )
                            directory_result["directory_paths"].append(
                                directory_entry
                            )
                            continue
                        elif any(
                            message in error.message
                            for message in [
                                "Path not found",
                                "Unable to open directory",
                            ]
                        ):
                            error_message = "Directory does not exist."
                        else:
                            error_message = "Couldn't access the directory."
                        directory_entry_invalid = True
                        directory_entry.update(
                            {
                                "error": {
                                    "directory_path": error_message
                                }
                            }
                        )

                    try:
                        re.compile(filename_filter)
                    except Exception:
                        success_status = False
                        directory_entry_invalid = True
                        error_message = "Filename filter should be a valid regular expression."
                        directory_entry.setdefault("error", {}).update({"filename_filter": error_message})

                    directory_result["directory_paths"].append(
                        directory_entry
                    )
                if directory_entry_invalid:
                    directory_result.update(
                        {
                            "error": True,
                            "message": "One or more directory configurations are invalid.",
                            "errorType": "directory_entry_invalid"
                        }
                    )
                result_data.append(directory_result)

            connection.close()
            if success_status:
                message = "Validation of directory inputs completed successfully."
            else:
                message = ("One or more directory configurations are invalid. "
                           "Please check the provided directory inputs.")
            return ValidationResult(
                success=success_status, message=message, data={"directory_inputs": result_data}
            )
        else:
            raise MicrosoftFileShareError(
                message=f"Could not connect with the Windows server '{configuration['smb_server_ip']}'."
            )

    def fetch_images_metadata(
        self, configuration: dict, directory_configuration: dict
    ) -> DirectoryConfigurationMetadataOut:
        """Fetch images metadata for the plugin directory configuration.

        Args:
            configuration (dict): Configuration parameters.
            directory_configuration (dict): Directory configuration.

        Raises:
            MicrosoftFileShareError: If an error occurred while fetching metadata for images.

        Returns:
            DirectoryConfigurationMetadataOut: Images metadata for the plugin directory configuration.
        """
        directory_inputs = directory_configuration["directory_inputs"]

        connection, connection_result = self.get_smb_connection_object(configuration)

        if connection_result:
            directory_inputs_metadata = []
            total_files_count = 0
            total_files_size = 0

            for directory_configuration in directory_inputs:
                shared_directory_name = directory_configuration[
                    "sharedDirectoryName"
                ].strip()
                directory_list = directory_configuration["directory_paths"]

                for directory in directory_list:
                    directory_path = directory["directory_path"].strip()
                    filename_filter = directory["filename_filter"]

                    files_count = 0
                    files_size = 0

                    files_list = connection.listPath(
                        shared_directory_name, directory_path
                    )

                    for file in files_list:
                        if (
                            (not file.isDirectory)
                            and any(
                                file.filename.lower().endswith(file_extension)
                                for file_extension in SUPPORTED_IMAGE_FILE_EXTENSIONS
                            )
                            and (
                                not filename_filter
                                or re.search(filename_filter, file.filename)
                            )
                        ):
                            files_count = files_count + 1
                            files_size = files_size + file.file_size

                    if files_count == 0:
                        directory_inputs_metadata.append(
                            {
                                "sharedDirectoryName": shared_directory_name,
                                "directoryPath": directory_path,
                                "filenameFilter": filename_filter,
                                "filesCount": files_count,
                                "filesSize": files_size,
                                "error": True,
                                "message": "No images found.",
                            }
                        )
                        continue

                    total_files_count = total_files_count + files_count
                    total_files_size = total_files_size + files_size

                    directory_inputs_metadata.append(
                        {
                            "sharedDirectoryName": shared_directory_name,
                            "directoryPath": directory_path,
                            "filenameFilter": filename_filter,
                            "filesCount": files_count,
                            "filesSize": files_size,
                        }
                    )

            connection.close()

            files_count_exceeded = total_files_count > ALLOWED_FILE_COUNT
            files_count_message = "Total file count is within the allowed file count limit."
            if files_count_exceeded:
                files_count_message = "Total file count exceeded the allowed file count limit."

            files_size_exceeded = total_files_size > ALLOWED_FILE_SIZE
            files_size_message = "Total file size is within the allowed file size limit."
            if files_size_exceeded:
                files_size_message = "Total file size exceeded the allowed file size limit."

            return DirectoryConfigurationMetadataOut(
                data=directory_inputs_metadata,
                filesCount={
                    "total": total_files_count,
                    "error": files_count_exceeded,
                    "message": files_count_message,
                },
                filesSize={
                    "total": total_files_size,
                    "error": files_size_exceeded,
                    "message": files_size_message,
                }
            )
        else:
            raise MicrosoftFileShareError(
                f"Could not connect with the Windows server '{configuration['smb_server_ip']}'."
            )

    def generate_dir_path_uuid(self, configuration, storage):
        """Generate uuid for directory path configurations.

        Args:
            configuration (dict): plugin configuration
            storage (dict): plugin storage

        Returns:
            dict: directory configuration with uuid.
        """

        directory_inputs = configuration.get("directory_configuration", {}).get(
            "directory_inputs", []
        )

        directory_storage = storage.get("directory_paths", {})
        stored_paths = set(list(directory_storage.keys()))

        input_paths = set()
        for directory_path in directory_inputs:
            input_paths = input_paths | set(
                (
                    "{}\\{}".format(
                        directory_path["sharedDirectoryName"],
                        paths["directory_path"].strip("\\"),
                    )
                )
                for paths in directory_path["directory_paths"]
            )
        stored_paths = {
            **{
                key: directory_storage[key]
                for key in list(stored_paths.intersection(input_paths))
            },
            **{key: str(uuid4()) for key in list(input_paths - stored_paths)},
        }
        return stored_paths

    def validate_directory_path(self, connection, shared_directory_name, directory_path):
        """Validate directory path.

        Args:
            connection (SMBConnection): SMB connection.
            shared_directory_name (str): Shared directory name.
            directory_path (str): Directory path.

        Raises:
            MicrosoftFileShareError: If an error occurred while validating directory path.
        """
        # Check if path exists by attempting to retrieve attributes and check it is a valid directory
        try:
            directory_attributes = connection.getAttributes(shared_directory_name, directory_path)
            if not directory_attributes.isDirectory:
                error_message = f"Path '{directory_path}' exists but is not a directory on the remote server."
                raise MicrosoftFileShareError(message=error_message)
        except Exception as error:
            error_message = f"Path '{directory_path}' does not exist on the remote server."
            raise MicrosoftFileShareError(message=error_message, value=error)

    def pull_metadata(self, server_configuration, directory_config, directory_storage):
        """Pull metadata from server for provided directory configuration.

        Args:
            server_configuration (dict): server configuration.
            directory_config (dict): directory configuration.
            directory_storage (dict): directory storage.

        Raises:
            MicrosoftFileShareError: If an error occurred while pulling images metadata.

        Returns:
            list: List of images metadata.
        """
        last_fetched_time = datetime.now()
        directory_inputs = directory_config.get("directory_inputs", [])
        success = True

        try:
            connection, connection_result = self.get_smb_connection_object(
                server_configuration
            )
            if connection_result:

                images_metadata = []

                for directory_configuration in directory_inputs:
                    shared_directory_name = directory_configuration["sharedDirectoryName"].strip()
                    directory_list = directory_configuration["directory_paths"]

                    for directory in directory_list:
                        directory_path = directory["directory_path"].strip().strip("\\")
                        filename_filter = directory["filename_filter"]
                        try:
                            self.validate_directory_path(
                                connection,
                                shared_directory_name,
                                directory_path,
                            )
                        except MicrosoftFileShareError as error:
                            self.logger.error(
                                f"{self.log_prefix}: Invalid directory path {str(error)}"
                            )
                            success = False
                            continue
                        files_list = connection.listPath(shared_directory_name, directory_path)

                        for file in files_list:
                            file_metadata = dict()
                            if (
                                (not file.isDirectory)
                                and any(
                                    file.filename.lower().endswith(file_extension)
                                    for file_extension in SUPPORTED_IMAGE_FILE_EXTENSIONS
                                )
                                and (
                                    not filename_filter
                                    or re.search(filename_filter, file.filename)
                                )
                            ):
                                filename = file.filename
                                remote_file_path = f"{directory_path}\\{filename}"
                                if remote_file_path.startswith("\\"):
                                    remote_file_path = remote_file_path.strip("\\")

                                file_metadata["sourcePlugin"] = self.name
                                file_metadata["file"] = filename
                                file_metadata[
                                    "path"
                                ] = f"{shared_directory_name}\\{remote_file_path}"
                                file_metadata["extension"] = (
                                    os.path.splitext(filename)[1].split(".")[1].upper()
                                )
                                file_metadata["lastFetched"] = last_fetched_time

                                file_metadata["dirUuid"] = directory_storage[
                                    f"{shared_directory_name}\\{directory_path}"
                                ]

                                file_metadata["fileSize"] = file.file_size
                                file_metadata[
                                    "shared_directory"
                                ] = shared_directory_name
                                file_metadata["remote_path"] = remote_file_path

                                images_metadata.append(file_metadata)
                connection.close()
                return images_metadata, success
            else:
                raise MicrosoftFileShareError(
                    f"Could not connect with the Windows server '{server_configuration['smb_server_ip']}'."
                )
        except MicrosoftFileShareError as error:
            raise error
        except Exception as error:
            error_message = f"Error occurred while fetching images metadata for '{self.name}' plugin."
            raise MicrosoftFileShareError(value=error, message=error_message) from error

    def validate_file_path(self, connection, shared_directory_name, file_path):
        """Validate file path.

        Args:
            connection (SMBConnection): SMB connection.
            shared_directory_name (str): Shared directory name.
            file_path (str): File path.

        Raises:
            MicrosoftFileShareError: If the file path is invalid or inaccessible or not a regular file.
        """
        try:
            # Check if file exists by attempting to get attributes
            file_attributes = connection.getAttributes(shared_directory_name, file_path)

            # Check if it's a regular file by examining file attributes
            # First check it's not a directory
            if file_attributes.isDirectory:
                error_message = (
                    f"Path '{file_path}' exists but is not a file on the remote server."
                )
                raise MicrosoftFileShareError(message=error_message)

            # Check if it's a regular file by examining the file mode
            # In SMB, we can check file attributes to determine if it's a regular file
            # Regular files should not have special attributes like device, symlink, etc.
            file_mode = file_attributes.file_attributes
            is_regular_file = not (
                file_mode & stat.S_IFDIR
                or file_mode & stat.S_IFLNK
                or file_mode & stat.S_IFCHR
                or file_mode & stat.S_IFBLK
                or file_mode & stat.S_IFIFO
                or file_mode & stat.S_IFSOCK
            )

            if not is_regular_file:
                error_message = f"Path '{file_path}' exists but is not a regular file on the remote server."
                raise MicrosoftFileShareError(message=error_message)
        except MicrosoftFileShareError:
            # Re-raise the custom exception
            raise
        except Exception as error:
            error_message = f"Could not access path '{file_path}' on the remote server."
            raise MicrosoftFileShareError(message=error_message, value=error)

    def pull_files(self, server_configuration, metadata):
        """Pull files from server when sharing is configured for this plugin.

        Args:
            server_configuration (dict): server configuration
            metadata (list): list of metadata fetched.
        """
        success = True
        try:
            connection, connection_result = self.get_smb_connection_object(
                server_configuration
            )
            if connection_result:
                for data in metadata:
                    image_file_path = (
                        f"{FILE_PATH}/{self.name}/{data['dirUuid']}/{data['file']}"
                    )
                    if not os.path.exists(os.path.dirname(image_file_path)):
                        os.makedirs(os.path.dirname(image_file_path))
                    try:
                        self.validate_file_path(connection, data["shared_directory"], data["remote_path"])
                    except MicrosoftFileShareError as error:
                        self.logger.error(
                            f"{self.log_prefix}: Invalid file path {str(error)}",
                            details=traceback.format_exc(),
                        )
                        success = False
                        continue
                    with open(image_file_path, "wb") as file_object:
                        connection.retrieveFile(
                            data["shared_directory"],
                            data["remote_path"],
                            file_obj=file_object,
                        )
        except Exception as error:
            error_message = f"Error occurred while fetching images  for '{self.name}' plugin."
            raise MicrosoftFileShareError(value=error, message=error_message) from error
        return success

class SFTPProtocolFileSharePlugin:
    """Microsoft File Share plugin helper class for SFTP protocol.

    This class implements helper methods to validate & verify SMB protocol based configuration.
    """

    def __init__(self, name: str, logger: Logger, log_prefix: str):
        """Initialize method for this class.

        Args:
            name (str): Name of the plugin configuration.
            logger (Logger): Logger object.
            log_prefix (str): Prefix string to be added to the log messages.
        """
        self.name = name
        self.logger = logger
        self.log_prefix = log_prefix

    def validate_configuration_parameters(
        self, configuration: dict
    ) -> ValidationResult:
        """Validate the configuration parameters.

        Args:
            configuration (dict): Configuration parameters.

        Returns:
            ValidationResult: Validation result.
        """
        server_ip = "sftp_server_ip"
        if server_ip in configuration:
            if (
                isinstance(configuration[server_ip], str)
                and configuration[server_ip].strip()
            ):
                pass
            else:
                return ValidationResult(
                    success=False,
                    message="Windows Server IP/Hostname should be a non-empty string value.",
                )
        else:
            return ValidationResult(
                success=False, message="Server IP/Hostname is required field."
            )

        username = "sftp_username"
        if username in configuration:
            if (
                isinstance(configuration[username], str)
                and configuration[username].strip()
            ):
                pass
            else:
                return ValidationResult(
                    success=False,
                    message="Username should be a non-empty string value.",
                )
        else:
            return ValidationResult(
                success=False, message="Username is required field."
            )

        password = "sftp_password"
        if password in configuration:
            if (
                isinstance(configuration[password], str)
                and configuration[password].strip()
            ):
                pass
            else:
                return ValidationResult(
                    success=False,
                    message="Password should be a non-empty string value.",
                )
        else:
            return ValidationResult(
                success=False, message="Password is required field."
            )

        port = "sftp_port"
        if port in configuration:
            if isinstance(configuration[port], int) and 0 < configuration[port] < 65536:
                pass
            else:
                return ValidationResult(
                    success=False,
                    message="Port number should be an integer value ranging between 1 to 65535.",
                )
        else:
            return ValidationResult(
                success=False, message="Port number is required field."
            )

        return ValidationResult(
            success=True,
            message="Basic validation of the configuration parameters completed successfully.",
        )

    def get_ssh_connection_object(self, configuration: dict) -> paramiko.SSHClient:
        """Get a SSH connection to the remote Windows server.

        Args:
            configuration (dict): Configuration parameters.

        Raises:
            MicrosoftFileShareError: If an error occurred while connecting with the Windows server.

        Returns:
            paramiko.SSHClient: SSH connection object.
        """
        try:
            ssh_connection = paramiko.SSHClient()
            ssh_connection.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh_connection.connect(
                hostname=configuration["sftp_server_ip"],
                username=configuration["sftp_username"],
                password=configuration["sftp_password"],
                port=configuration["sftp_port"],
            )
            return ssh_connection
        except AuthenticationException as error:
            error_message = ("Authentication failed while connecting to the "
                             f"Windows server'{configuration['sftp_server_ip']}'.")
            self.logger.error(
                message=f"{self.log_prefix}: {error_message}",
                details=traceback.format_exc(),
            )
            raise MicrosoftFileShareError(
                message=error_message, value=error
            ) from error
        except SSHException as error:
            error_message = ("Couldn't establish SSH session with the "
                             f"Windows server'{configuration['sftp_server_ip']}'.")
            self.logger.error(
                message=f"{self.log_prefix}: {error_message}",
                details=traceback.format_exc(),
            )
            raise MicrosoftFileShareError(
                message=error_message, value=error
            ) from error

    def verify_connection(self, configuration: dict) -> ValidationResult:
        """Verify the connection with the Windows server.

        Args:
            configuration (dict): Configuration parameters.

        Returns:
            ValidationResult: Validation result.
        """
        server_ip = configuration["sftp_server_ip"]
        ssh_connection = self.get_ssh_connection_object(configuration)
        ssh_connection.close()
        return ValidationResult(
            success=True,
            message=(
                "Connection with the Windows server "
                f"{server_ip} verified successfully."
            ),
        )

    def validate_directory_inputs(
        self, directory_configuration: dict
    ) -> ValidationResult:
        """Validate the directory configuration.

        Args:
            directory_configuration (dict): Directory configuration.

        Returns:
            ValidationResult: Validation result.
        """
        directory_paths = directory_configuration.get("directory_paths", [])

        if not directory_paths:
            return ValidationResult(
                success=False,
                message="Directory paths are required field.",
            )

        for directory in directory_paths:
            if "directory_path" in directory:
                if (
                    isinstance(directory["directory_path"], str)
                    and directory["directory_path"].strip()
                ):
                    pass
                else:
                    return ValidationResult(
                        success=False,
                        message="Directory path should be a non-empty string value.",
                    )
            else:
                return ValidationResult(
                    success=False,
                    message="Directory path is required field.",
                )

            if "filename_filter" in directory:
                if isinstance(directory["filename_filter"], str):
                    pass
                else:
                    return ValidationResult(
                        success=False,
                        message="Filename filter should be a string value.",
                    )
            else:
                return ValidationResult(
                    success=False,
                    message="Filename filter is required field.",
                )

        directory_set = set()

        for directory in directory_paths:
            directory_path = directory["directory_path"].strip()
            filename_filter = directory["filename_filter"]

            if tuple((directory_path, filename_filter)) in directory_set:
                if filename_filter:
                    error_message = (
                        f"Directory path '{directory_path}' and "
                        f"filename filter '{filename_filter}' are duplicated."
                    )
                else:
                    error_message = (
                        f"Directory path '{directory_path}' and "
                        "empty filename filter are duplicated."
                    )
                raise ValueError(error_message)
            directory_set.add(tuple((directory_path, filename_filter)))

        return ValidationResult(
            success=True,
            message="Basic validation of the directory inputs completed successfully.",
        )

    def verify_directory_inputs(
        self, configuration: dict, directory_configurations: dict
    ) -> ValidationResult:
        """Verify the directory configuration.

        Args:
            configuration (dict): Configuration parameters.
            directory_configurations (dict): Directory configuration.

        Returns:
            DirectoryConfigurationOut: Directory configuration with verification result.
        """
        directory_paths = directory_configurations["directory_paths"]

        success_status = True

        result_data = list()
        ssh_connection = self.get_ssh_connection_object(configuration)

        for directory in directory_paths:
            directory_path = directory["directory_path"].strip()
            filename_filter = directory["filename_filter"]

            directory_entry = {
                "directory_path": directory_path,
                "filename_filter": filename_filter,
            }

            if directory_path == '/':
                success_status = False
                directory_entry.update(
                    {
                        "error": {
                            "directory_path": "Directory path is not supported.",
                        }
                    }
                )
            else:
                with ssh_connection.open_sftp() as sftp_session:
                    try:
                        _ = sftp_session.listdir(directory_path)
                    except Exception:
                        success_status = False
                        directory_entry.update(
                            {
                                "error": {
                                    "directory_path": "Couldn't access the directory.",
                                }
                            }
                        )

            try:
                re.compile(filename_filter)
            except Exception:
                success_status = False
                error_message = "Filename filter should be a valid regular expression."
                directory_entry.setdefault("error", {}).update({"filename_filter": error_message})

            result_data.append(
                directory_entry
            )

        ssh_connection.close()

        if success_status:
            message = "Validation of directory configuration completed successfully."
        else:
            message = "One or more directory configurations are invalid. Please check the provided directory inputs."

        return ValidationResult(
            success=success_status, message=message, data={"directory_paths": result_data}
        )

    def fetch_images_metadata(
        self, configuration: dict, directory_configurations: dict
    ) -> DirectoryConfigurationMetadataOut:
        """Fetch images metadata for the plugin directory configuration.

        Args:
            configuration (dict): Configuration parameters.
            directory_configuration (dict): Directory configuration.

        Returns:
            DirectoryConfigurationMetadataOut: Images metadata for the plugin directory configuration.
        """
        directory_paths = directory_configurations["directory_paths"]

        ssh_connection = self.get_ssh_connection_object(configuration)

        directory_inputs_metadata = []
        total_files_count = 0
        total_files_size = 0

        for directory in directory_paths:

            directory_path = directory["directory_path"].strip()
            filename_filter = directory["filename_filter"]

            files_count = 0
            files_size = 0

            with ssh_connection.open_sftp() as sftp_session:

                files = sftp_session.listdir(directory_path)

                for file in files:
                    file_attributes = sftp_session.lstat(f"{directory_path}\\{file}")

                    if (
                        stat.S_ISREG(file_attributes.st_mode)
                        and any(
                            file.lower().endswith(file_extension)
                            for file_extension in SUPPORTED_IMAGE_FILE_EXTENSIONS
                        )
                        and (not filename_filter or re.search(filename_filter, file))
                    ):
                        files_count = files_count + 1
                        files_size = files_size + file_attributes.st_size

            if files_count == 0:
                directory_inputs_metadata.append(
                    {
                        "directoryPath": directory_path,
                        "filenameFilter": filename_filter,
                        "filesCount": files_count,
                        "filesSize": files_size,
                        "error": True,
                        "message": "No images found.",
                    }
                )
                continue

            total_files_count = total_files_count + files_count
            total_files_size = total_files_size + files_size

            directory_inputs_metadata.append(
                {
                    "directoryPath": directory_path,
                    "filenameFilter": filename_filter,
                    "filesCount": files_count,
                    "filesSize": files_size,
                }
            )

        ssh_connection.close()

        files_count_exceeded = total_files_count > ALLOWED_FILE_COUNT
        files_count_message = "Total file count is within the allowed file count limit."
        if files_count_exceeded:
            files_count_message = "Total file count exceeded the allowed file count limit."

        files_size_exceeded = total_files_size > ALLOWED_FILE_SIZE
        files_size_message = "Total file size is within the allowed file size limit."
        if files_size_exceeded:
            files_size_message = "Total file size exceeded the allowed file size limit."

        return DirectoryConfigurationMetadataOut(
            data=directory_inputs_metadata,
            filesCount={
                "total": total_files_count,
                "error": files_count_exceeded,
                "message": files_count_message,
            },
            filesSize={
                "total": total_files_size,
                "error": files_size_exceeded,
                "message": files_size_message,
            }
        )

    def generate_dir_path_uuid(self, configuration, storage):
        """Generate uuid for directory path configurations.

        Args:
            configuration (dict): plugin configuration
            storage (dict): plugin storage

        Returns:
            dict: directory configuration with uuid.
        """
        directory_paths = configuration.get("directory_configuration", {}).get(
            "directory_paths", []
        )

        directory_storage = storage.get("directory_paths", {})

        input_paths = set(paths["directory_path"] for paths in directory_paths)
        stored_paths = set(list(directory_storage.keys()))
        stored_paths = {
            **{
                key: directory_storage[key]
                for key in list(stored_paths.intersection(input_paths))
            },
            **{key: str(uuid4()) for key in list(input_paths - stored_paths)},
        }
        return stored_paths

    def validate_directory_path(self, sftp_session, directory_path):
        """Validate directory path.

        Args:
            sftp_session: SFTP session object.
            directory_path (str): directory path.

        Raises:
            MicrosoftFileShareError: If the directory path is invalid or inaccessible.
        """
        try:
            # Check if path exists by attempting to get attributes
            file_attributes = sftp_session.stat(directory_path)
            # Check if it's a directory
            if not stat.S_ISDIR(file_attributes.st_mode):
                error_message = f"Path '{directory_path}' exists but is not a directory on the remote server."
                raise MicrosoftFileShareError(message=error_message)
        except FileNotFoundError as error:
            error_message = f"Path '{directory_path}' does not exist on the remote server."
            raise MicrosoftFileShareError(message=error_message, value=error)
        except Exception as error:
            error_message = f"Could not access path '{directory_path}' on the remote server."
            raise MicrosoftFileShareError(message=error_message, value=error)

    def pull_metadata(self, server_configuration, directory_config, directory_storage):
        """Pull metadata from server for provided directory configuration.

        Args:
            server_configuration (dict): server configuration.
            directory_config (dict): directory configuration.
            directory_storage (dict): directory storage.

        Raises:
            MicrosoftFileShareError: If an error occurred while pulling images metadata.

        Returns:
            list: List of images metadata.
        """
        last_fetched_time = datetime.now()
        directory_paths = directory_config.get("directory_paths", [])
        success = True

        try:
            ssh_connection = self.get_ssh_connection_object(server_configuration)
            images_metadata = []

            for directory in directory_paths:
                directory_path = directory["directory_path"].strip()
                filename_filter = directory["filename_filter"]

                with ssh_connection.open_sftp() as sftp_session:
                    try:
                        # Validate directory path before processing
                        self.validate_directory_path(
                            sftp_session,
                            directory_path
                        )
                    except MicrosoftFileShareError as error:
                        self.logger.error(
                            f"{self.log_prefix}: Invalid directory path: {error}",
                            details=traceback.format_exc(),
                        )
                        success = False
                        continue

                    files = sftp_session.listdir(directory_path)

                    for file in files:
                        file_metadata = dict()
                        file_attributes = sftp_session.lstat(
                            f"{directory_path}\\{file}"
                        )

                        if (
                            stat.S_ISREG(file_attributes.st_mode)
                            and any(
                                file.lower().endswith(file_extension)
                                for file_extension in SUPPORTED_IMAGE_FILE_EXTENSIONS
                            )
                            and (
                                not filename_filter or re.search(filename_filter, file)
                            )
                        ):
                            remote_file_path = f"{directory_path}\\{file}"
                            file_metadata["sourcePlugin"] = self.name
                            file_metadata["file"] = file
                            file_metadata["path"] = remote_file_path
                            file_metadata["extension"] = (
                                os.path.splitext(file)[1].split(".")[1].upper()
                            )
                            file_metadata["lastFetched"] = last_fetched_time
                            file_metadata["dirUuid"] = directory_storage[directory_path]
                            file_metadata["fileSize"] = file_attributes.st_size
                            images_metadata.append(file_metadata)
            ssh_connection.close()
            return images_metadata, success
        except Exception as error:
            error_message = "Failed fetching metadata."
            raise MicrosoftFileShareError(
                value=error, message=error_message
            ) from error

    def validate_file_path(self, sftp_session, file_path):
        """Validate file path.

        Args:
            sftp_session: SFTP session object.
            file_path (str): File path.

        Raises:
            MicrosoftFileShareError: If the file path is invalid or inaccessible or not a regular file.
        """
        try:
            # Check if file exists by attempting to get attributes
            file_attributes = sftp_session.stat(file_path)
            # Check if it's a regular file using stat.S_ISREG
            if not stat.S_ISREG(file_attributes.st_mode):
                error_message = f"Path '{file_path}' exists but is not a regular file on the remote server."
                raise MicrosoftFileShareError(message=error_message)
        except FileNotFoundError as error:
            error_message = f"Path '{file_path}' does not exist on the remote server."
            raise MicrosoftFileShareError(message=error_message, value=error)
        except MicrosoftFileShareError:
            # Re-raise the custom exception
            raise
        except Exception as error:
            error_message = f"Could not access path '{file_path}' on the remote server."
            raise MicrosoftFileShareError(message=error_message, value=error)

    def pull_files(self, server_configuration, metadata):
        """Pull files from server when sharing is configured for this plugin.

        Args:
            server_configuration (dict): server configuration
            metadata (list): list of metadata fetched.
        """
        success = True
        try:
            ssh_connection = self.get_ssh_connection_object(server_configuration)
            for data in metadata:
                with ssh_connection.open_sftp() as sftp_session:
                    file_path = f"{FILE_PATH}/{self.name}/{data['dirUuid']}"
                    if not os.path.exists(file_path):
                        os.makedirs(file_path)
                    try:
                        self.validate_file_path(sftp_session, data["path"])
                    except MicrosoftFileShareError as error:
                        self.logger.error(
                            f"{self.log_prefix}: Invalid file path {str(error)}",
                            details=traceback.format_exc(),
                        )
                        success = False
                        continue
                    sftp_session.get(
                        data["path"],
                        os.path.join(file_path, data["file"]),
                    )
        except Exception as error:
            error_message = f"Error occurred while fetching images  for '{self.name}' plugin."
            raise MicrosoftFileShareError(value=error, message=error_message) from error
        return success
