"""Linux File Share CFC Plugin.

Linux File Share CFC plugin is used to pull the image data from the configured Linux machine.
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

# Local imports
from netskope.integrations.cfc.models import (
    DirectoryConfigurationMetadataOut
)
from netskope.integrations.cfc.plugin_base import PluginBase, ValidationResult
from netskope.integrations.cfc.utils import (
    FILE_PATH,
    CustomException as LinuxFileShareCFCError,
)

from .utils.constants import (
    ALLOWED_FILE_COUNT,
    ALLOWED_FILE_SIZE,
    PLUGIN_NAME,
    PLUGIN_VERSION,
    MODULE_NAME,
    SUPPORTED_IMAGE_FILE_EXTENSIONS,
    LINUX_FILE_SHARE_FIELDS,
)

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


class LinuxFileShareCFCPlugin(PluginBase):
    """
    Linux File Share CFC plugin class.

    This plugin class is used to pull the image data from the configured Linux server.
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
                    "{} {}: Error occurred while"
                    " getting plugin details. Error: {}".format(
                        MODULE_NAME, PLUGIN_NAME, exp
                    )
                ),
                details=traceback.format_exc(),
            )
        return (PLUGIN_NAME, PLUGIN_VERSION)

    def strip_string_values(self, configuration: dict):
        """Strip the string values from the configuration parameters.

        Args:
            configuration (dict): Configuration parameters.
        """
        for parameter, value in configuration.items():
            if isinstance(value, str):
                configuration[parameter] = value.strip()

    def get_ssh_connection_object(self, configuration: dict) -> paramiko.SSHClient:
        """Get a SSH connection to the remote Linux server.

        Args:
            configuration (dict): Configuration parameters.

        Raises:
            LinuxFileShareCFCError: If an error occurred while connecting with the Linux server.

        Returns:
            paramiko.SSHClient: SSH connection object.
        """
        try:
            ssh_connection = paramiko.SSHClient()
            ssh_connection.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh_connection.connect(
                hostname=configuration["server_ip"],
                username=configuration["username"],
                password=configuration["password"],
                port=configuration["port"],
            )
            return ssh_connection
        except AuthenticationException as error:
            error_message = (
                "Authentication failed while connecting to the "
                f"Linux server'{configuration['server_ip']}'."
            )
            self.logger.error(
                message=f"{self.log_prefix} {error_message}",
                details=traceback.format_exc(),
            )
            raise LinuxFileShareCFCError(message=error_message, value=error) from error
        except SSHException as error:
            error_message = (
                "Couldn't establish SSH session with the "
                f"Linux server'{configuration['server_ip']}'."
            )
            self.logger.error(
                message=f"{self.log_prefix} {error_message}",
                details=traceback.format_exc(),
            )
            raise LinuxFileShareCFCError(message=error_message, value=error) from error

    def verify_connection(self, configuration: dict) -> ValidationResult:
        """Verify the connection with the Linux server.

        Args:
            configuration (dict): Configuration parameters.

        Returns:
            ValidationResult: Validation result.
        """
        server_ip = configuration["server_ip"]
        ssh_connection = self.get_ssh_connection_object(configuration)
        ssh_connection.close()
        return ValidationResult(
            success=True,
            message=(
                "Connection with the Linux server "
                f"{server_ip} verified successfully."
            ),
        )

    def verify_parameters_provided(self, configuration) -> ValidationResult:
        """Verify all configuration parameters are provided.

        Args:
            configuration (dict): Configuration parameters.

        Returns:
            ValidationResult: Validation status for provided parameters.
        """
        server_ip = "server_ip"
        if server_ip in configuration:
            if (
                isinstance(configuration[server_ip], str)
                and configuration[server_ip].strip()
            ):
                pass
            else:
                return ValidationResult(
                    success=False,
                    message="Linux Server IP/Hostname should be a non-empty string value.",
                )
        else:
            return ValidationResult(
                success=False, message="Server IP/Hostname is required field."
            )

        username = "username"
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

        password = "password"
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

        port = "port"
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
            success=True, message="verified configuration parameters are provided."
        )

    def validate_configuration_parameters(self) -> ValidationResult:
        """Validate the configuration parameters.

        Returns:
            ValidationResult: Validation result.
        """
        try:
            configuration = self.configuration.get("configuration_parameters", {})
            self.strip_string_values(configuration)

            result = self.verify_parameters_provided(configuration)

            if result.success is False:
                return result

            self.verify_connection(configuration)

            return ValidationResult(
                success=True,
                message="Basic validation of the configuration parameters completed successfully.",
            )
        except Exception:
            error_message = f"Could not verify the connection with the provided parameters for '{self.name}' plugin."
            self.logger.error(
                message=f"{self.log_prefix} {error_message}",
                details=traceback.format_exc(),
            )
            return ValidationResult(
                success=False,
                message=error_message,
            )

    def validate_directory_configuration(self) -> ValidationResult:
        """Validate the directory configuration.

        Raises:
            LinuxFileShareCFCError: If an error occurred while verifying directory configuration.

        Returns:
            ValidationResult: Directory configuration with verification result.
        """
        self.logger.debug(
            f"{self.log_prefix} Validating directory configuration for '{self.name}' plugin."
        )

        try:
            server_configuration = self.configuration["configuration_parameters"]
            self.strip_string_values(server_configuration)

            directory_configuration = self.configuration.get(
                "directory_configuration", {}
            )

            if not directory_configuration:
                raise LinuxFileShareCFCError(
                    message="Directory configuration is required."
                )

            validation_result: ValidationResult = self.validate_directory_inputs(
                directory_configuration
            )

            if not validation_result.success:
                raise LinuxFileShareCFCError(message=validation_result.message)

            verification_result: ValidationResult = (
                self.verify_directory_inputs(
                    server_configuration, directory_configuration
                )
            )
            verification_result.data = {
                "directory_configuration": verification_result.data
            }
            self.logger.debug(
                f"{self.log_prefix} Directory configuration validated for '{self.name}' plugin."
            )
            return verification_result
        except ValueError as error:
            self.logger.error(message=str(error), details=traceback.format_exc())
            raise LinuxFileShareCFCError(message=str(error), value=error) from error

        except Exception as error:
            error_message = f"Error occurred while verifying directory configuration for '{self.name}' plugin."
            self.logger.error(
                message=f"{self.log_prefix} {error_message}",
                details=traceback.format_exc(),
            )
            raise LinuxFileShareCFCError(message=error_message, value=error) from error

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
            ValidationResult: Directory configuration with verification result.
        """
        directory_paths = directory_configurations["directory_paths"]

        success_status = True

        result_data = list()
        ssh_connection = self.get_ssh_connection_object(configuration)

        with ssh_connection.open_sftp() as sftp_session:
            for directory in directory_paths:
                directory_path = directory["directory_path"].strip()
                filename_filter = directory["filename_filter"]

                directory_entry = {
                    "directory_path": directory_path,
                    "filename_filter": filename_filter,
                }

                try:
                    _ = sftp_session.listdir(directory_path)
                except Exception as e:
                    self.logger.info(str(e))
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
                    error_message = (
                        "Filename filter should be a valid regular expression."
                    )
                    directory_entry.setdefault("error", {}).update(
                        {"filename_filter": error_message}
                    )

                result_data.append(directory_entry)
        ssh_connection.close()

        if success_status:
            message = "Validation of directory configuration completed successfully."
        else:
            message = "One or more directory configurations are invalid. Please check the provided directory inputs."

        return ValidationResult(
            success=success_status,
            message=message,
            data={"directory_paths": result_data},
        )

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
            result = ValidationResult(
                success=True,
                message="Step validated successfully.",
            )
        return result

    def pull_metadata(self, server_configuration, directory_config, directory_storage):
        last_fetched_time = datetime.now()
        directory_paths = directory_config.get("directory_paths", [])
        try:
            ssh_connection = self.get_ssh_connection_object(server_configuration)
            images_metadata = []

            with ssh_connection.open_sftp() as sftp_session:
                for directory in directory_paths:
                    directory_path = directory["directory_path"].strip()
                    filename_filter = directory["filename_filter"]

                    files = sftp_session.listdir(directory_path)

                    for file in files:
                        file_metadata = dict()
                        file_attributes = sftp_session.lstat(f"{directory_path}/{file}")

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
                            remote_file_path = f"{directory_path}/{file}"
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
            return images_metadata
        except Exception as error:
            error_message = "Failed fetching metadata."
            raise LinuxFileShareCFCError(value=error, message=error_message) from error

    def pull_files(self, server_configuration, metadata):
        """Pull files from server when sharing is configured for this plugin.

        Args:
            server_configuration (dict): server configuration
            metadata (list): list of metadata fetched.
        """
        ssh_connection = self.get_ssh_connection_object(server_configuration)
        for data in metadata:
            with ssh_connection.open_sftp() as sftp_session:
                file_path = f"{FILE_PATH}/{self.name}/{data['dirUuid']}"
                if not os.path.exists(file_path):
                    os.makedirs(file_path)
                sftp_session.get(
                    data["path"],
                    os.path.join(file_path, data["file"]),
                )

    def pull(self, pull_files=False) -> list:
        """Pull images metadata from remote Linux machine.

        Raises:
            LinuxFileShareCFCError: If any error occurs during the metadata retrieval or validation.

        Returns:
            list: List of images metadata.
        """
        try:
            server_configuration = self.configuration.get(
                "configuration_parameters", {}
            )
            directory_config = self.configuration.get("directory_configuration", {})

            self.strip_string_values(server_configuration)
            self.strip_string_values(directory_config)

            self.logger.info(
                (
                    f"{self.log_prefix} Fetching the images metadata from the Linux server for "
                    f"configuration '{self.name}'."
                )
            )
            self.generate_dir_path_uuid()
            directory_storage = self.storage.get("directory_paths", {})

            metadata = self.pull_metadata(
                server_configuration, directory_config, directory_storage
            )

            if pull_files:
                self.pull_files(server_configuration, metadata)

            # metadata = self.pull_files_and_metadata(
            #     server_configuration, directory_config, pull_files=pull_files
            # )
            self.logger.info(
                (
                    f"{self.log_prefix} Images{' and their' if pull_files else ''} metadata fetched successfully from "
                    f"the Linux server for configuration '{self.name}'."
                )
            )

            return metadata
        except Exception as error:
            error_message = f"Error: '{error}' occurred while running pull method for configuration '{self.name}'"
            self.logger.error(
                message=f"{self.log_prefix} {error_message} for configuration '{self.name}'.",
                details=traceback.format_exc(),
            )
            raise LinuxFileShareCFCError(value=error, message=str(error)) from error

    def generate_dir_path_uuid(self):
        """Generate uuid for directory path configurations.

        Args:
            directory_config (dict): Directory configuration.

        Returns:
            dict: Directory configuration with uuid for each path.
        """
        directory_paths = self.configuration.get("directory_configuration", {}).get(
            "directory_paths", []
        )

        directory_storage = self.storage.get("directory_paths", {})

        input_paths = set(paths["directory_path"] for paths in directory_paths)
        stored_paths = set(list(directory_storage.keys()))
        stored_paths = {
            **{
                key: directory_storage[key]
                for key in list(stored_paths.intersection(input_paths))
            },
            **{key: str(uuid4()) for key in list(input_paths - stored_paths)},
        }
        self.storage["directory_paths"] = stored_paths
        return stored_paths

    def fetch_images_metadata(self) -> DirectoryConfigurationMetadataOut:
        """Fetch images metadata for the plugin directory configuration.

        Raises:
            LinuxFileShareCFCError: If an error occurred while fetching images metadata

        Returns:
            DirectoryConfigurationMetadataOut: Images metadata for the plugin directory configuration.
        """
        self.logger.debug(
            f"{self.log_prefix} Fetching images metadata for '{self.name}' plugin."
        )

        try:
            server_configuration = self.configuration["configuration_parameters"]
            self.strip_string_values(server_configuration)

            directory_configuration = self.configuration.get(
                "directory_configuration", {}
            )
            directory_paths = directory_configuration["directory_paths"]

            ssh_connection = self.get_ssh_connection_object(server_configuration)

            directory_inputs_metadata = []
            total_files_count = 0
            total_files_size = 0

            with ssh_connection.open_sftp() as sftp_session:
                for directory in directory_paths:
                    directory_path = directory["directory_path"].strip()
                    filename_filter = directory["filename_filter"]

                    files_count = 0
                    files_size = 0

                    files = sftp_session.listdir(directory_path)

                    for file in files:
                        file_attributes = sftp_session.lstat(f"{directory_path}/{file}")

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
            files_count_message = (
                "Total file count is within the allowed file count limit."
            )
            if files_count_exceeded:
                files_count_message = (
                    "Total file count exceeded the allowed file count limit."
                )

            files_size_exceeded = total_files_size > ALLOWED_FILE_SIZE
            files_size_message = (
                "Total file size is within the allowed file size limit."
            )
            if files_size_exceeded:
                files_size_message = (
                    "Total file size exceeded the allowed file size limit."
                )

            self.logger.debug(
                f"{self.log_prefix} Images metadata fetched for '{self.name}' plugin."
            )

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
                },
            )

        except Exception as error:
            error_message = f"Error occurred while fetching images metadata for '{self.name}' plugin."
            self.logger.error(
                message=f"{self.log_prefix} {error_message}",
                details=traceback.format_exc(),
            )
            raise LinuxFileShareCFCError(message=error_message, value=error) from error

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
                        field["default"] = self.fetch_images_metadata()
            return fields
        else:
            raise NotImplementedError(
                "No fields available for the specified step name."
            )
