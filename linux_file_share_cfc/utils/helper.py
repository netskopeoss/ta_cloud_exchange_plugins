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

Linux File Share CFC Plugin helper class.
"""

# Built-in libraries
import os
import re
import stat
import traceback
from datetime import datetime
from uuid import uuid4

# Third-party libraries
from ..lib import paramiko
from ..lib.paramiko.ssh_exception import AuthenticationException, SSHException

# Local imports
from netskope.integrations.cfc.models import DirectoryConfigurationMetadataOut
from netskope.integrations.cfc.plugin_base import ValidationResult
from netskope.integrations.cfc.utils import (
    FILE_PATH,
    CustomException as LinuxFileShareCFCError,
)
from netskope.common.utils import Logger

from .constants import (
    ALLOWED_FILE_COUNT,
    ALLOWED_FILE_SIZE,
    SUPPORTED_IMAGE_FILE_EXTENSIONS,
)


class LinuxFileShareHelper:
    """Linux File Share CFC Plugin Helper Class."""

    def __init__(self, name: str, logger: Logger, log_prefix: str):
        """Initialize method for LinuxFileShareHelper class."""
        self.name = name
        self.logger = logger
        self.log_prefix = log_prefix

    def strip_string_values(self, configuration: dict):
        """Strip the string values from the configuration parameters.

        Args:
            configuration (dict): Configuration parameters.
        """
        for parameter, value in configuration.items():
            if parameter == "password":
                continue
            if isinstance(value, str):
                configuration[parameter] = value.strip()

    @staticmethod
    def _sanitize_relative_path(path: str) -> str:
        """Normalize a Linux path by collapsing consecutive forward slashes.
        """
        path = (path or "").strip()
        if not path:
            return path
        return os.path.normpath(path)

    def get_ssh_connection_object(
        self, configuration: dict
    ) -> paramiko.SSHClient:
        """Get a SSH connection to the remote Linux server.

        Args:
            configuration (dict): Configuration parameters.

        Raises:
            LinuxFileShareCFCError: If an error occurred while connecting with
            the Linux server.

        Returns:
            paramiko.SSHClient: SSH connection object.
        """
        server_ip = configuration.get("server_ip")
        try:
            ssh_connection = paramiko.SSHClient()
            ssh_connection.set_missing_host_key_policy(
                paramiko.AutoAddPolicy()
            )
            ssh_connection.connect(
                hostname=configuration.get("server_ip"),
                username=configuration.get("username"),
                password=configuration.get("password"),
                port=configuration.get("port"),
            )
            return ssh_connection
        except AuthenticationException as error:
            error_message = (
                f"Error occurred while connecting to the "
                f"Linux server '{server_ip}'."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {error_message}",
                details=traceback.format_exc(),
                resolution=(
                    "Ensure that the Server Hostname/IP, Username, Password "
                    "and Port provided in the configuration are correct."
                ),
            )
            raise LinuxFileShareCFCError(
                message=error_message
            ) from error
        except SSHException as error:
            error_message = (
                f"Error occurred while establishing SSH session with the "
                f"Linux server '{server_ip}'."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {error_message}",
                details=traceback.format_exc(),
                resolution=(
                    "Ensure that the Linux server is reachable and "
                    "accessible from the Netskope CE instance."
                ),
            )
            raise LinuxFileShareCFCError(
                message=error_message
            ) from error
        except Exception as error:
            error_message = (
                f"Error occurred while connecting to the Linux server "
                f"'{server_ip}'. Verify that the Server Hostname/IP, "
                f"Port, Username and Password are correct and the "
                f"server is reachable."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {error_message}",
                details=traceback.format_exc(),
                resolution=(
                    "Ensure that the Server Hostname/IP, Port, Username "
                    "and Password are correct and the Linux server is "
                    "reachable from the Netskope CE instance."
                ),
            )
            raise LinuxFileShareCFCError(
                message=error_message
            ) from error

    def verify_connection(self, configuration: dict) -> ValidationResult:
        """Verify the connection with the Linux server.

        Args:
            configuration (dict): Configuration parameters.

        Returns:
            ValidationResult: Validation result.
        """
        server_ip = configuration.get("server_ip")
        ssh_connection = self.get_ssh_connection_object(configuration)
        try:
            message = (
                f"Successfully connected to the Linux server '{server_ip}'."
            )
            self.logger.debug(
                message=f"{self.log_prefix}: {message}"
            )
            return ValidationResult(
                success=True,
                message=message,
            )
        finally:
            ssh_connection.close()

    def validate_configuration_parameters(
        self, configuration: dict
    ) -> ValidationResult:
        """Validate Linux connection configuration.

        Args:
            configuration (dict): Configuration dictionary containing Linux
            parameters.

        Returns:
            ValidationResult: Validation result with success status
            and message.
        """
        # Validate Linux Server Hostname/IP
        server_ip = configuration.get("server_ip", "")
        if not server_ip:
            err_msg = (
                "Server Hostname/IP is a required configuration parameter."
            )
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Validation error occurred. {err_msg}"
                ),
                resolution=(
                    "Ensure that a valid Server Hostname/IP is provided."
                ),
            )
            return ValidationResult(success=False, message=err_msg)
        if not isinstance(server_ip, str) or not server_ip.strip():
            err_msg = "Invalid Server Hostname/IP provided."
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Validation error occurred. {err_msg}"
                ),
                resolution=(
                    "Ensure that the Server Hostname/IP is a "
                    "non-empty string value."
                ),
            )
            return ValidationResult(success=False, message=err_msg)

        # Validate Username
        username = configuration.get("username", "")
        if not username:
            err_msg = "Username is a required configuration parameter."
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Validation error occurred. {err_msg}"
                ),
                resolution="Ensure that a valid Username is provided.",
            )
            return ValidationResult(success=False, message=err_msg)
        if not isinstance(username, str) or not username.strip():
            err_msg = "Invalid Username provided."
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Validation error occurred. {err_msg}"
                ),
                resolution=(
                    "Ensure that the Username is a non-empty string value."
                ),
            )
            return ValidationResult(success=False, message=err_msg)

        # Validate Password (do not strip)
        password = configuration.get("password", "")
        if not password:
            err_msg = "Password is a required configuration parameter."
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Validation error occurred. {err_msg}"
                ),
                resolution="Ensure that a valid Password is provided.",
            )
            return ValidationResult(success=False, message=err_msg)
        if not isinstance(password, str) or not password.strip():
            err_msg = "Invalid Password provided."
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Validation error occurred. {err_msg}"
                ),
                resolution=(
                    "Ensure that the Password is a non-empty string value."
                ),
            )
            return ValidationResult(success=False, message=err_msg)

        # Validate Port
        port = configuration.get("port")
        if port is None:
            err_msg = "Port is a required configuration parameter."
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Validation error occurred. {err_msg}"
                ),
                resolution="Ensure that a valid Port is provided.",
            )
            return ValidationResult(success=False, message=err_msg)
        if not isinstance(port, int) or not (0 < port < 65536):
            err_msg = (
                "Invalid Port provided. Port should be an "
                "integer between 1 and 65535."
            )
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Validation error occurred. {err_msg}"
                ),
                resolution=(
                    "Ensure that the Port is an integer between 1 and 65535."
                ),
            )
            return ValidationResult(success=False, message=err_msg)
        message = "Successfully validated configuration parameters."

        return ValidationResult(
            success=True,
            message=message,
        )

    def validate_directory_inputs(
        self, directory_configuration: dict
    ) -> ValidationResult:
        """Validate the directory configuration inputs.

        Args:
            directory_configuration (dict): Directory configuration.

        Returns:
            ValidationResult: Validation result.
        """
        directory_paths = directory_configuration.get("directory_paths", [])

        if not directory_paths:
            err_msg = "Directory paths is a required configuration parameter."
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Validation error occurred. {err_msg}"
                ),
                resolution=(
                    "Ensure that at least one directory path is configured."
                ),
            )
            return ValidationResult(success=False, message=err_msg)

        for directory in directory_paths:
            directory_path = directory.get("directory_path")
            if not directory_path:
                err_msg = (
                    "Directory path is a required configuration parameter."
                )
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: Validation error "
                        f"occurred. {err_msg}"
                    ),
                    resolution=(
                        "Ensure that a valid directory path is provided."
                    ),
                )
                return ValidationResult(success=False, message=err_msg)
            if not isinstance(directory_path, str) or not directory_path.strip():  # noqa E501
                err_msg = (
                    "Directory path should be a non-empty string value."
                )
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: Validation "
                        f"error occurred. {err_msg}"
                    ),
                    resolution=(
                        "Ensure that the directory path is a "
                        "non-empty string value."
                    ),
                )
                return ValidationResult(success=False, message=err_msg)

            filename_filter = directory.get("filename_filter")
            if filename_filter is None:
                err_msg = (
                    "Filename filter is a required configuration parameter."
                )
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: Validation error "
                        f"occurred. {err_msg}"
                    ),
                    resolution=(
                        "Ensure that a filename filter value is provided. "
                        "Use an empty string to match all files."
                    ),
                )
                return ValidationResult(success=False, message=err_msg)
            if not isinstance(filename_filter, str):
                err_msg = "Filename filter should be a string value."
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: Validation error "
                        f"occurred. {err_msg}"
                    ),
                    resolution=(
                        "Ensure that the filename filter "
                        "is a string value."
                    ),
                )
                return ValidationResult(success=False, message=err_msg)

        directory_set = set()

        for directory in directory_paths:
            directory_path = directory.get("directory_path").strip()
            filename_filter = directory.get("filename_filter")
            normalized_path = self._sanitize_relative_path(directory_path)

            if (normalized_path, filename_filter) in directory_set:
                if filename_filter:
                    error_message = (
                        f"Directory path '{directory_path}' and "
                        f"filename filters '{filename_filter}' are duplicated."
                    )
                else:
                    error_message = (
                        f"Directory path '{directory_path}' and "
                        "empty filename filters are duplicated."
                    )
                    self.logger.error(
                        f"{self.log_prefix}: {error_message}"
                    )
                raise ValueError(error_message)
            directory_set.add((normalized_path, filename_filter))

        message = "Successfully validated directory inputs."
        self.logger.debug(
            message=f"{self.log_prefix}: {message}"
        )

        return ValidationResult(
            success=True,
            message=message,
        )

    def verify_directory_inputs(
        self, configuration: dict, directory_configurations: dict
    ) -> ValidationResult:
        """Verify the directory configuration against the remote server.

        Args:
            configuration (dict): Configuration parameters.
            directory_configurations (dict): Directory configuration.

        Returns:
            ValidationResult: Directory configuration with verification result.
        """
        directory_paths = directory_configurations.get("directory_paths")

        success_status = True

        result_data = list()
        ssh_connection = self.get_ssh_connection_object(configuration)

        try:
            with ssh_connection.open_sftp() as sftp_session:
                for directory in directory_paths:
                    directory_path = directory.get("directory_path").strip()
                    filename_filter = directory.get("filename_filter")

                    directory_entry = {
                        "directory_path": directory_path,
                        "filename_filter": filename_filter,
                    }

                    try:
                        _ = sftp_session.listdir(directory_path)
                    except Exception as e:
                        self.logger.error(
                            message=(
                                f"{self.log_prefix}: Error occurred while "
                                f"accessing directory '{directory_path}'. "
                                f"Error: {str(e)}"
                            ),
                            details=traceback.format_exc(),
                            resolution=(
                                "Ensure that the directory path exists and "
                                "is accessible on the remote Linux server."
                            ),
                        )
                        success_status = False
                        directory_entry.update(
                            {
                                "error": {
                                    "directory_path": "Couldn't access "
                                    "the directory.",
                                }
                            }
                        )
                    try:
                        re.compile(filename_filter)
                    except Exception:
                        success_status = False
                        error_message = (
                            "Filename filter should be a valid "
                            "regular expression."
                        )
                        directory_entry.setdefault("error", {}).update(
                            {"filename_filter": error_message}
                        )

                    result_data.append(directory_entry)
        finally:
            ssh_connection.close()

        if success_status:
            message = (
                "Successfully validated directory configuration."
            )
            self.logger.debug(
                message=f"{self.log_prefix}: {message}"
            )
        else:
            message = (
                "One or more directory configurations are invalid. "
                "Check the provided directory inputs."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {message}",
                resolution=(
                    "Ensure that the directory configurations are valid. "
                    "Check the provided directory inputs."
                ),
            )

        return ValidationResult(
            success=success_status,
            message=message,
            data={"directory_paths": result_data},
        )

    def validate_directory_path(self, sftp_session, directory_path):
        """Validate directory path on the remote server.

        Args:
            sftp_session: SFTP session object.
            directory_path (str): Directory path.

        Raises:
            LinuxFileShareCFCError: If the directory path is
            invalid or inaccessible.
        """
        try:
            file_attributes = sftp_session.stat(directory_path)
            if not stat.S_ISDIR(file_attributes.st_mode):
                error_message = (
                    f"Path '{directory_path}' exists but is not a "
                    "directory on the remote server."
                )
                raise LinuxFileShareCFCError(message=error_message)
        except FileNotFoundError as error:
            error_message = (
                f"Path '{directory_path}' does not exist on the remote server."
            )
            raise LinuxFileShareCFCError(
                message=error_message
            ) from error
        except LinuxFileShareCFCError:
            raise
        except Exception as error:
            error_message = (
                f"Error occurred while accessing path '{directory_path}' "
                "on the remote server."
            )
            raise LinuxFileShareCFCError(
                message=error_message
            ) from error

    def validate_file_path(self, sftp_session, file_path):
        """Validate file path on the remote server.

        Args:
            sftp_session: SFTP session object.
            file_path (str): File path.

        Raises:
            LinuxFileShareCFCError: If the file path is invalid or
            inaccessible or not a regular file.
        """
        try:
            file_attributes = sftp_session.stat(file_path)
            if not stat.S_ISREG(file_attributes.st_mode):
                error_message = (
                    f"Path '{file_path}' exists but is not a "
                    "regular file on the remote server."
                )
                raise LinuxFileShareCFCError(message=error_message)
        except FileNotFoundError as error:
            error_message = (
                f"Path '{file_path}' does not exist on the remote server."
            )
            raise LinuxFileShareCFCError(
                message=error_message
            ) from error
        except LinuxFileShareCFCError:
            raise
        except Exception as error:
            error_message = (
                f"Error occurred while accessing path '{file_path}' "
                "on the remote server."
            )
            raise LinuxFileShareCFCError(
                message=error_message
            ) from error

    def generate_dir_path_uuid(
        self, configuration: dict, storage: dict
    ) -> dict:
        """Generate uuid for directory path configurations.

        Args:
            configuration (dict): Plugin configuration.
            storage (dict): Plugin storage.

        Returns:
            dict: Mapping of directory paths to their UUIDs.
        """
        directory_paths = configuration.get("directory_configuration", {}).get(
            "directory_paths", []
        )

        directory_storage = storage.get("directory_paths", {})

        input_paths = set(
            paths.get("directory_path") for paths in directory_paths
        )
        stored_paths = set(directory_storage.keys())

        # Historical path→UUID registry. Never used for pulling metadata —
        # only consulted here so that a path removed then re-added gets back
        # its original UUID instead of a new one.
        path_uuid_history = storage.get("path_uuid_history", {})

        result = {
            # Paths still in config keep their existing UUID.
            **{
                key: directory_storage.get(key)
                for key in stored_paths.intersection(input_paths)
            },
            # New or re-added paths: reuse UUID from history if present,
            # otherwise mint a fresh one.
            **{
                key: path_uuid_history.get(key, str(uuid4()))
                for key in input_paths - stored_paths
            },
        }

        # Persist all current path→UUID assignments into the history so
        # future re-adds can look them up.
        storage["path_uuid_history"] = {**path_uuid_history, **result}

        return result

    def pull_metadata(
        self, server_configuration, directory_config, directory_storage
    ):
        """Pull metadata from server for provided directory configuration.

        Args:
            server_configuration (dict): Server configuration.
            directory_config (dict): Directory configuration.
            directory_storage (dict): Directory storage.

        Raises:
            LinuxFileShareCFCError: If an error occurred while pulling images
            metadata.

        Returns:
            tuple: Tuple containing list of images metadata and success status.
        """
        last_fetched_time = datetime.now()
        directory_paths = directory_config.get("directory_paths", [])
        success = True

        try:
            ssh_connection = self.get_ssh_connection_object(
                server_configuration
            )
        except LinuxFileShareCFCError:
            raise
        except Exception as error:
            error_message = (
                "Error occurred while connecting to the Linux server "
                "for pulling metadata."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {error_message}",
                details=traceback.format_exc(),
                resolution=(
                    "Ensure that the Server Hostname/IP, Port, Username "
                    "and Password are correct and the Linux server is "
                    "reachable from the Netskope CE instance."
                ),
            )
            raise LinuxFileShareCFCError(
                message=error_message
            ) from error

        images_metadata = []

        try:
            with ssh_connection.open_sftp() as sftp_session:
                for directory in directory_paths:
                    directory_path = directory.get(
                        "directory_path"
                    ).strip()
                    filename_filter = directory.get("filename_filter")
                    try:
                        self.validate_directory_path(
                            sftp_session, directory_path
                        )
                    except LinuxFileShareCFCError as error:
                        self.logger.error(
                            message=(
                                f"{self.log_prefix}: Invalid directory "
                                f"path. Error: {str(error)}"
                            ),
                            details=traceback.format_exc(),
                            resolution=(
                                "Ensure that the directory path in the "
                                "configuration exists and is accessible "
                                "on the remote Linux server."
                            ),
                        )
                        success = False
                        continue

                    files = sftp_session.listdir(directory_path)

                    for file in files:
                        file_metadata = dict()
                        file_attributes = sftp_session.lstat(
                            f"{directory_path}/{file}"
                        )

                        if (
                            stat.S_ISREG(file_attributes.st_mode)
                            and any(
                                file.lower().endswith(file_extension)
                                for file_extension in
                                SUPPORTED_IMAGE_FILE_EXTENSIONS
                            )
                            and (
                                not filename_filter
                                or re.search(filename_filter, file)
                            )
                        ):
                            remote_file_path = (
                                f"{directory_path}/{file}"
                            )
                            dirUuid = directory_storage.get(
                                directory_path, ""
                            )
                            file_metadata["sourcePlugin"] = self.name
                            file_metadata["file"] = file
                            file_metadata["path"] = remote_file_path
                            file_metadata["extension"] = (
                                os.path.splitext(file)[1]
                                .split(".")[1]
                                .upper()
                            )
                            file_metadata["lastFetched"] = (
                                last_fetched_time
                            )
                            file_metadata["dirUuid"] = dirUuid
                            file_metadata["fileSize"] = (
                                file_attributes.st_size
                            )
                            images_metadata.append(file_metadata)
        except LinuxFileShareCFCError:
            raise
        except Exception as error:
            error_message = (
                "Error occurred while pulling metadata from the "
                "Linux server."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {error_message}",
                details=traceback.format_exc(),
                resolution=(
                    "Ensure that the Linux server is reachable and the "
                    "configured directory paths are accessible."
                ),
            )
            raise LinuxFileShareCFCError(
                message=error_message
            ) from error
        finally:
            ssh_connection.close()

        # Validate total file size before returning
        total_files_size = sum(
            file_metadata.get("fileSize", 0)
            for file_metadata in images_metadata
        )
        if total_files_size > ALLOWED_FILE_SIZE:
            size_error_message = (
                f"No files will be pulled as the total size of the "
                f"provided paths "
                f"({total_files_size / (1024 ** 3):.2f} GB) exceeds "
                f"the allowed file size limit of "
                f"{ALLOWED_FILE_SIZE / (1024 ** 3):.2f} GB. "
                f"Reduce the total size of the configured paths."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {size_error_message}",
                resolution=(
                    "Reduce the total size of configured paths by "
                    "selecting fewer directories or using filename "
                    "filters."
                ),
            )
            return [], False

        return images_metadata, success

    def pull_files(self, server_configuration, metadata):
        """Pull files from server when sharing is configured for this plugin.

        Args:
            server_configuration (dict): Server configuration.
            metadata (list): List of metadata fetched.

        Returns:
            bool: Success status of the operation.
        """
        success = True
        try:
            ssh_connection = self.get_ssh_connection_object(
                server_configuration
            )
            try:
                for data in metadata:
                    with ssh_connection.open_sftp() as sftp_session:
                        file_path = (
                            f"{FILE_PATH}/{self.name}/{data.get('dirUuid', '')}"  # noqa E501
                        )
                        if not os.path.exists(file_path):
                            os.makedirs(file_path)
                        try:
                            self.validate_file_path(
                                sftp_session, data.get("path")
                            )
                        except LinuxFileShareCFCError as error:
                            self.logger.error(
                                message=(
                                    f"{self.log_prefix}: Invalid file "
                                    f"path. Error: {str(error)}"
                                ),
                                details=traceback.format_exc(),
                                resolution=(
                                    "Ensure that the file path in the "
                                    "configuration exists and is accessible "
                                    "on the remote Linux server."
                                ),
                            )
                            success = False
                            continue
                        try:
                            sftp_session.get(
                                data.get("path"),
                                os.path.join(file_path, data.get("file", "")),
                            )
                        except PermissionError as error:
                            self.logger.debug(
                                message=(
                                    f"{self.log_prefix}: Permission denied "
                                    f"while pulling file "
                                    f"'{data.get('path', '')}'. "
                                    f"Error: {str(error)}"
                                ),
                                details=traceback.format_exc(),
                            )
                            success = False
                            continue
            finally:
                ssh_connection.close()
        except LinuxFileShareCFCError:
            raise
        except Exception as error:
            error_message = "Error occurred while pulling images."
            raise LinuxFileShareCFCError(
                message=error_message
            ) from error
        return success

    def fetch_images_metadata(
        self, server_configuration: dict, directory_configuration: dict
    ) -> DirectoryConfigurationMetadataOut:
        """Fetch images metadata for the plugin directory configuration.

        Args:
            server_configuration (dict): Server configuration parameters.
            directory_configuration (dict): Directory configuration.

        Raises:
            LinuxFileShareCFCError: If an error occurred while fetching
            images metadata.

        Returns:
            DirectoryConfigurationMetadataOut: Images metadata for the plugin
            directory configuration.
        """
        self.logger.debug(f"{self.log_prefix}: Pulling images metadata.")

        try:
            directory_paths = directory_configuration.get("directory_paths")

            ssh_connection = self.get_ssh_connection_object(
                server_configuration
            )

            directory_inputs_metadata = []
            total_files_count = 0
            total_files_size = 0

            try:
                with ssh_connection.open_sftp() as sftp_session:
                    for directory in directory_paths:
                        directory_path = directory.get(
                            "directory_path"
                        ).strip()
                        filename_filter = directory.get("filename_filter")

                        files_count = 0
                        files_size = 0

                        files = sftp_session.listdir(directory_path)

                        for file in files:
                            file_attributes = sftp_session.lstat(
                                f"{directory_path}/{file}"
                            )

                            if (
                                stat.S_ISREG(file_attributes.st_mode)
                                and any(
                                    file.lower().endswith(file_extension)
                                    for file_extension in
                                    SUPPORTED_IMAGE_FILE_EXTENSIONS
                                )
                                and (
                                    not filename_filter
                                    or re.search(filename_filter, file)
                                )
                            ):
                                files_count = files_count + 1
                                files_size = (
                                    files_size + file_attributes.st_size
                                )

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
            finally:
                ssh_connection.close()

            files_count_exceeded = total_files_count > ALLOWED_FILE_COUNT
            files_count_message = (
                "Total file count is within the allowed file count limit."
            )
            if files_count_exceeded:
                files_count_message = (
                    f"Total file count ({total_files_count}) exceeded the "
                    f"allowed limit of {ALLOWED_FILE_COUNT} files."
                )
                self.logger.error(
                    message=f"{self.log_prefix}: {files_count_message}",
                    resolution=(
                        "Reduce the number of files by refining the directory "
                        "paths or filename filters."
                    ),
                )

            files_size_exceeded = total_files_size > ALLOWED_FILE_SIZE
            files_size_message = (
                "Total file size is within the allowed file size limit."
            )
            if files_size_exceeded:
                files_size_message = (
                    f"Total size of the provided paths "
                    f"({total_files_size / (1024 ** 3):.2f} GB) "
                    f"exceeds the allowed file size limit of "
                    f"{ALLOWED_FILE_SIZE / (1024 ** 3):.2f} GB. "
                    f"No files will be pulled. Reduce the total size "
                    f"of the configured paths."
                )
                self.logger.error(
                    message=f"{self.log_prefix}: {files_size_message}",
                    resolution=(
                        "Reduce the total file size by selecting fewer "
                        "directories or removing large files from the "
                        "configured paths."
                    ),
                )

            self.logger.debug(
                f"{self.log_prefix}: Successfully pulled images metadata."
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

        except LinuxFileShareCFCError:
            raise
        except Exception as error:
            error_message = "Error occurred while pulling images metadata."
            self.logger.error(
                message=f"{self.log_prefix}: {error_message}",
                details=traceback.format_exc(),
            )
            raise LinuxFileShareCFCError(
                message=error_message
            ) from error
