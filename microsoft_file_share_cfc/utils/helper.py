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

SMB and SFTP Protocol File Share CFC Plugin helper module.
"""

import os
import re
import stat
import traceback
from datetime import datetime
from typing import Tuple
from uuid import uuid4

from ..lib import paramiko
from ..lib.paramiko.ssh_exception import AuthenticationException, SSHException
from ..lib.smb.base import NotConnectedError, NotReadyError
from ..lib.smb.smb_structs import OperationFailure
from ..lib.smb.SMBConnection import SMBConnection
from ..utils.constants import (
    ALLOWED_FILE_COUNT,
    ALLOWED_FILE_SIZE,
    SUPPORTED_IMAGE_FILE_EXTENSIONS,
)
from netskope.common.utils import Logger
from netskope.integrations.cfc.models import DirectoryConfigurationMetadataOut
from netskope.integrations.cfc.plugin_base import ValidationResult
from netskope.integrations.cfc.utils import (
    CustomException as MicrosoftFileShareError,
    FILE_PATH,
)


class SMBProtocolFileSharePlugin:
    """Microsoft File Share plugin helper class for SMB protocol.

    This class implements helper methods to validate & verify SMB protocol
    based configuration.
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

    @staticmethod
    def _sanitize_relative_path(path: str) -> str:
        """Sanitize SMB relative path by removing leading/trailing backslashes.

        Args:
            path (str): Path to sanitize.

        Returns:
            str: Sanitized path.
        """
        sanitized_path = (path or "").strip()
        sanitized_path = sanitized_path.strip("\\")
        parts = [segment for segment in sanitized_path.split("\\") if segment]
        return "\\".join(parts)

    @staticmethod
    def _get_directory_storage_key(
        shared_directory_name: str, relative_directory_path: str
    ) -> str:
        """Build deterministic directory storage key.

        Args:
            shared_directory_name (str): Shared directory name.
            relative_directory_path (str): Relative directory path.

        Returns:
            str: Directory storage key.
        """
        if relative_directory_path:
            return f"{shared_directory_name}\\{relative_directory_path}"
        return shared_directory_name

    def validate_configuration_parameters(
        self, configuration: dict
    ) -> ValidationResult:
        """Validate the configuration parameters.

        Args:
            configuration (dict): Configuration parameters.

        Returns:
            ValidationResult: Validation result.
        """
        # Validate Server Hostname/IP
        # Strip string values except password
        for key, value in configuration.items():
            if isinstance(value, str) and key != "smb_password":
                configuration[key] = value.strip()
        server_ip = configuration.get("smb_server_ip", "")
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

        # Validate Machine Name
        machine_name = configuration.get("smb_machine_name", "")
        if not machine_name:
            err_msg = (
                "Machine Name is a required configuration parameter."
            )
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Validation error occurred. {err_msg}"
                ),
                resolution=(
                    "Ensure that a valid Machine Name is provided."
                ),
            )
            return ValidationResult(success=False, message=err_msg)
        if not isinstance(machine_name, str) or not machine_name.strip():
            err_msg = "Invalid Machine Name provided."
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Validation error occurred. {err_msg}"
                ),
                resolution=(
                    "Ensure that the Machine Name is a "
                    "non-empty string value."
                ),
            )
            return ValidationResult(success=False, message=err_msg)

        # Validate Username
        username = configuration.get("smb_username", "")
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
                    "Ensure that the Username is a "
                    "non-empty string value."
                ),
            )
            return ValidationResult(success=False, message=err_msg)

        # Validate Password
        password = configuration.get("smb_password", "")
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
                    "Ensure that the Password is a "
                    "non-empty string value."
                ),
            )
            return ValidationResult(success=False, message=err_msg)

        message = "Successfully validated configuration parameters."
        return ValidationResult(
            success=True,
            message=message,
        )

    def get_smb_connection_object(
        self, configuration: dict, retry: bool = True
    ) -> Tuple[SMBConnection, bool]:
        """Get a SMB connection to the remote Windows server.

        Args:
            configuration (dict): Configuration parameters.
            retry (bool, optional): Retry flag. Defaults to True.

        Raises:
            MicrosoftFileShareError: If an error occurred while connecting with
                the Windows server.

        Returns:
            (SMBConnection, bool): SMB connection object and connection result.
        """
        try:
            connection = SMBConnection(
                username=configuration.get("smb_username", ""),
                password=configuration.get("smb_password", ""),
                my_name="netskope_machine",
                remote_name=configuration.get("smb_machine_name", ""),
            )
            connection_result = connection.connect(
                ip=configuration.get("smb_server_ip", ""),
            )
            return connection, connection_result
        except NotReadyError as error:
            error_message = (
                "Authentication failed while connecting with the "
                f"server '{configuration.get('smb_server_ip', '')}'."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {error_message}",
                details=traceback.format_exc(),
            )
            raise MicrosoftFileShareError(
                message=error_message, value=error
            ) from error
        except NotConnectedError as error:
            error_message = (
                "Couldn't connect with the Windows server "
                f"'{configuration.get('smb_server_ip', '')}'."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {error_message}",
                details=traceback.format_exc(),
            )
            if retry:
                self.logger.info(
                    message=(
                        f"{self.log_prefix}: Reconnecting with the Windows "
                        f"server '{configuration.get('smb_server_ip', '')}'."
                    )
                )
                return self.get_smb_connection_object(
                    configuration=configuration, retry=False
                )
            raise MicrosoftFileShareError(
                message=error_message, value=error
            ) from error
        except TimeoutError as error:
            error_message = (
                "Connection request to the Windows server "
                f"'{configuration.get('smb_server_ip', '')}' got timed out."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {error_message}",
                details=traceback.format_exc(),
            )
            raise MicrosoftFileShareError(
                message=error_message, value=error
            ) from error
        except Exception as error:
            error_message = (
                "An unexpected error occurred while connecting to the "
                f"Windows server '{configuration.get('smb_server_ip', '')}'."
            )
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
        server_ip = configuration.get("smb_server_ip", "")
        connection, connection_result = self.get_smb_connection_object(
            configuration
        )
        if connection_result:
            connection.close()
            msg = (
                "Connection with the Windows server "
                f"'{server_ip}' verified successfully."
            )
            self.logger.debug(f"{self.log_prefix}: {msg}")
            return ValidationResult(success=True, message=msg)

        err_msg = (
            "Couldn't verify the connection with the "
            f"Windows server '{server_ip}'."
        )
        self.logger.error(f"{self.log_prefix}: {err_msg}")
        return ValidationResult(success=False, message=err_msg)

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
            err_msg = (
                "Directory inputs are a required configuration parameter."
            )
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Validation error "
                    f"occurred. {err_msg}"
                ),
                resolution=(
                    "Ensure that at least one "
                    "directory input is provided."
                ),
            )
            return ValidationResult(success=False, message=err_msg)

        normalized_shared_directories = set()

        for directory_configuration in directory_inputs:
            if "sharedDirectoryName" in directory_configuration:
                if (
                    isinstance(
                        directory_configuration.get("sharedDirectoryName", ""),
                        str,
                    )
                    and directory_configuration.get(
                        "sharedDirectoryName", ""
                    ).strip()
                ):
                    shared_directory_name = directory_configuration.get(
                        "sharedDirectoryName", ""
                    ).strip()
                    if "/" in shared_directory_name:
                        err_msg = (
                            "Invalid shared directory name. "
                            "Only backslashes (\\) are supported; "
                            "forward slashes (/) cannot be used in "
                            "shared directory names."
                        )
                        self.logger.error(
                            message=(
                                f"{self.log_prefix}: Validation error "
                                f"occurred. {err_msg}"
                            ),
                            resolution=(
                                "Ensure that all forward slashes (/) "
                                "are replaced with backslashes (\\) "
                                "in the shared directory name."
                            ),
                        )
                        return ValidationResult(success=False, message=err_msg)
                    normalized_name = self._sanitize_relative_path(
                        shared_directory_name
                    )
                    if normalized_name in normalized_shared_directories:
                        err_msg = (
                            "Shared directory "
                            f"'{shared_directory_name}' is already "
                            "configured for this path."
                        )
                        self.logger.error(
                            message=(
                                f"{self.log_prefix}: Validation error "
                                f"occurred. {err_msg}"
                            ),
                            resolution=(
                                "Ensure that each shared directory "
                                "name is unique and not duplicated."
                            ),
                        )
                        return ValidationResult(success=False, message=err_msg)
                    normalized_shared_directories.add(normalized_name)
                else:
                    err_msg = (
                        "Shared directory name should be "
                        "a non-empty string value."
                    )
                    self.logger.error(
                        message=(
                            f"{self.log_prefix}: Validation error "
                            f"occurred. {err_msg}"
                        ),
                        resolution=(
                            "Ensure that the shared directory name "
                            "is a non-empty string value."
                        ),
                    )
                    return ValidationResult(success=False, message=err_msg)
            else:
                err_msg = (
                    "Shared directory name is a required "
                    "configuration parameter."
                )
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: Validation error "
                        f"occurred. {err_msg}"
                    ),
                    resolution=(
                        "Ensure that a valid shared "
                        "directory name is provided."
                    ),
                )
                return ValidationResult(success=False, message=err_msg)

            directory_list = directory_configuration.get("directory_paths", [])

            if not directory_list:
                err_msg = "At least one directory path is required."
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: Validation "
                        f"error occurred. {err_msg}"
                    ),
                    resolution=(
                        "Ensure that at least one "
                        "directory path is provided."
                    ),
                )
                return ValidationResult(success=False, message=err_msg)

            for directory in directory_list:
                # Validate Directory Path
                directory_path = directory.get("directory_path", "")
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
                            "Ensure that a valid directory "
                            "path is provided."
                        ),
                    )
                    return ValidationResult(success=False, message=err_msg)
                if not isinstance(
                    directory_path, str
                ) or not directory_path.strip():
                    err_msg = (
                        "Directory path should be a "
                        "non-empty string value."
                    )
                    self.logger.error(
                        message=(
                            f"{self.log_prefix}: Validation error "
                            f"occurred. {err_msg}"
                        ),
                        resolution=(
                            "Ensure that the directory path is a "
                            "non-empty string value."
                        ),
                    )
                    return ValidationResult(success=False, message=err_msg)

                # Validate Filename Filter
                filename_filter = directory.get("filename_filter", "")
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

        for directory_configuration in directory_inputs:
            shared_directory_name = directory_configuration.get(
                "sharedDirectoryName", ""
            ).strip()
            directory_list = directory_configuration.get("directory_paths", [])

            directory_set = set()

            for directory in directory_list:
                directory_path = directory.get("directory_path", "").strip()
                filename_filter = directory.get("filename_filter", "")

                if directory_path.startswith(
                    "\\\\"
                ) or directory_path.startswith("//"):
                    err_msg = (
                        "Directory path should be relative to "
                        "the shared directory, not a full UNC path."
                    )
                    self.logger.error(
                        message=(
                            f"{self.log_prefix}: Validation error "
                            f"occurred. {err_msg}"
                        ),
                        resolution=(
                            "Ensure that the path is relative to the "
                            "share root, not a full UNC path."
                        ),
                    )
                    return ValidationResult(success=False, message=err_msg)
                if "/" in directory_path:
                    err_msg = (
                        "Invalid directory path format. Use backslashes "
                        "(\\) only; forward slashes (/) are not "
                        "supported in SMB paths. For example, use "
                        "'folder\\subfolder' instead of "
                        "'folder/subfolder'."
                    )
                    self.logger.error(
                        message=(
                            f"{self.log_prefix}: Validation error "
                            f"occurred. {err_msg}"
                        ),
                        resolution=(
                            "Ensure that all forward slashes (/) "
                            "are replaced with backslashes (\\) in the "
                            "directory path."
                        ),
                    )
                    return ValidationResult(success=False, message=err_msg)

                sanitized_directory_path = self._sanitize_relative_path(
                    directory_path
                )

                if (
                    sanitized_directory_path,
                    filename_filter,
                ) in directory_set:
                    if filename_filter:
                        err_msg = (
                            f"Directory path '{directory_path}' and filename "
                            f"filter '{filename_filter}' are duplicated "
                            f"for directory '{shared_directory_name}'."
                        )
                        self.logger.error(
                            message=(
                                f"{self.log_prefix}: Validation "
                                f"error occurred. {err_msg}"
                            ),
                            resolution=(
                                "Ensure that each directory path and "
                                "filename filter combination is unique."
                            ),
                        )
                        return ValidationResult(success=False, message=err_msg)
                    else:
                        err_msg = (
                            f"Directory path '{directory_path}' and "
                            "empty filename filter are duplicated for "
                            f"directory '{shared_directory_name}'."
                        )
                        self.logger.error(
                            message=(
                                f"{self.log_prefix}: Validation error "
                                f"occurred. {err_msg}"
                            ),
                            resolution=(
                                "Ensure that each directory path "
                                "and filename filter combination is unique."
                            ),
                        )
                        return ValidationResult(success=False, message=err_msg)

                directory_set.add((sanitized_directory_path, filename_filter))

        msg = "Successfully validated directory inputs."
        self.logger.debug(f"{self.log_prefix}: {msg}")
        return ValidationResult(success=True, message=msg)

    def verify_directory_inputs(
        self, configuration: dict, directory_configurations: dict
    ) -> ValidationResult:
        """Verify the directory configuration.

        Args:
            configuration (dict): Configuration parameters.
            directory_configurations (dict): Directory configuration.

        Raises:
            MicrosoftFileShareError: If an error occurred while verifying
                directory configuration.

        Returns:
            DirectoryConfigurationOut: Directory configuration
            with verification result.
        """
        directory_inputs = directory_configurations.get("directory_inputs", [])

        success_status = True

        result_data = list()

        connection, connection_result = self.get_smb_connection_object(
            configuration
        )

        if connection_result:
            for directory_configuration in directory_inputs:
                shared_directory_name = directory_configuration.get(
                    "sharedDirectoryName", ""
                ).strip()
                directory_list = directory_configuration.get(
                    "directory_paths", []
                )

                directory_result = {
                    "sharedDirectoryName": shared_directory_name,
                    "directory_paths": list(),
                }
                shared_directory_exist = True
                directory_entry_invalid = False

                for directory in directory_list:
                    directory_path = directory.get(
                        "directory_path", ""
                    ).strip()
                    filename_filter = directory.get("filename_filter", "")

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
                        _ = connection.listPath(
                            shared_directory_name, directory_path
                        )
                    except Exception as error:
                        success_status = False
                        error_str = str(error)
                        self.logger.error(
                            message=(
                                f"{self.log_prefix}: Error accessing "
                                f"directory '{directory_path}'. Error: {error}"
                            ),
                            details=traceback.format_exc(),
                        )
                        if (
                            "Unable to connect to shared device"
                            in error_str
                        ):
                            shared_directory_exist = False
                            directory_result.update(
                                {
                                    "error": True,
                                    "message": (
                                        "Unable to connect to shared "
                                        "directory."
                                    ),
                                    "errorType": "shared_directory_error",
                                }
                            )
                            directory_result["directory_paths"].append(
                                directory_entry
                            )
                            continue
                        elif any(
                            message in error_str
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
                            {"error": {"directory_path": error_message}}
                        )

                    try:
                        re.compile(filename_filter)
                    except Exception as error:
                        success_status = False
                        directory_entry_invalid = True
                        error_message = (
                            "Filename filter should be a valid regular "
                            "expression."
                        )
                        self.logger.error(
                            message=(
                                f"{self.log_prefix}: Invalid filename "
                                f"filter '{filename_filter}'. Error: {error}"
                            ),
                            details=traceback.format_exc(),
                        )
                        directory_entry.setdefault("error", {}).update(
                            {"filename_filter": error_message}
                        )

                    directory_result["directory_paths"].append(directory_entry)
                if directory_entry_invalid:
                    directory_result.update(
                        {
                            "error": True,
                            "message": (
                                "One or more directory configurations are "
                                "invalid."
                            ),
                            "errorType": "directory_entry_invalid",
                        }
                    )
                result_data.append(directory_result)

            connection.close()
            if success_status:
                message = (
                    "Validation of directory inputs completed successfully."
                )
                self.logger.debug(f"{self.log_prefix}: {message}")
            else:
                message = (
                    "One or more directory configurations are invalid. "
                    "Please check the provided directory inputs."
                )
                self.logger.error(f"{self.log_prefix}: {message}")
            return ValidationResult(
                success=success_status,
                message=message,
                data={"directory_inputs": result_data},
            )
        else:
            raise MicrosoftFileShareError(
                message=(
                    "Could not connect with the Windows server "
                    f"'{configuration.get('smb_server_ip', '')}'."
                )
            )

    def fetch_images_metadata(
        self, configuration: dict, directory_configuration: dict
    ) -> DirectoryConfigurationMetadataOut:
        """Fetch images metadata for the plugin directory configuration.

        Args:
            configuration (dict): Configuration parameters.
            directory_configuration (dict): Directory configuration.

        Raises:
            MicrosoftFileShareError: If an error occurred while fetching
                metadata for images.

        Returns:
            DirectoryConfigurationMetadataOut: Images metadata for the plugin
                directory configuration.
        """
        try:
            directory_inputs = directory_configuration.get(
                "directory_inputs", []
            )

            connection, connection_result = (
                self.get_smb_connection_object(configuration)
            )

            if not connection_result:
                raise MicrosoftFileShareError(
                    message=(
                        "Could not connect with the Windows server "
                        f"'{configuration.get('smb_server_ip', '')}'."
                    )
                )

            directory_inputs_metadata = []
            total_files_count = 0
            total_files_size = 0

            try:
                for directory_configuration in directory_inputs:
                    shared_directory_name = (
                        directory_configuration.get(
                            "sharedDirectoryName", ""
                        ).strip()
                    )
                    directory_list = directory_configuration.get(
                        "directory_paths", []
                    )

                    for directory in directory_list:
                        directory_path = directory.get(
                            "directory_path", ""
                        ).strip()
                        filename_filter = directory.get(
                            "filename_filter", ""
                        )

                        files_count = 0
                        files_size = 0

                        try:
                            files_list = connection.listPath(
                                shared_directory_name, directory_path
                            )

                            for file in files_list:
                                try:
                                    if (
                                        (not file.isDirectory)
                                        and any(
                                            file.filename.lower()
                                            .endswith(file_extension)
                                            for file_extension in (
                                                SUPPORTED_IMAGE_FILE_EXTENSIONS
                                            )
                                        )
                                        and (
                                            not filename_filter
                                            or re.search(
                                                filename_filter,
                                                file.filename,
                                            )
                                        )
                                    ):
                                        files_count = files_count + 1
                                        files_size = (
                                            files_size + file.file_size
                                        )
                                except Exception:
                                    # Skip inaccessible files
                                    continue
                        except Exception:
                            # Skip directory if listing fails
                            continue

                        if files_count == 0:
                            directory_inputs_metadata.append(
                                {
                                    "sharedDirectoryName": (
                                        shared_directory_name
                                    ),
                                    "directoryPath": directory_path,
                                    "filenameFilter": filename_filter,
                                    "filesCount": files_count,
                                    "filesSize": files_size,
                                    "error": True,
                                    "message": "No images found.",
                                }
                            )
                            continue

                        total_files_count = (
                            total_files_count + files_count
                        )
                        total_files_size = (
                            total_files_size + files_size
                        )

                        directory_inputs_metadata.append(
                            {
                                "sharedDirectoryName": (
                                    shared_directory_name
                                ),
                                "directoryPath": directory_path,
                                "filenameFilter": filename_filter,
                                "filesCount": files_count,
                                "filesSize": files_size,
                            }
                        )
            finally:
                connection.close()

            files_count_exceeded = (
                total_files_count > ALLOWED_FILE_COUNT
            )
            files_count_message = (
                "Total file count is within the allowed file count limit."
            )
            if files_count_exceeded:
                files_count_message = (
                    f"Total file count ({total_files_count}) exceeded the "
                    f"allowed limit of {ALLOWED_FILE_COUNT} files."
                )
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: {files_count_message}"
                    ),
                    resolution=(
                        "Reduce the number of files by refining the "
                        "directory paths or filename filters."
                    ),
                )

            files_size_exceeded = (
                total_files_size > ALLOWED_FILE_SIZE
            )
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
                    message=(
                        f"{self.log_prefix}: {files_size_message}"
                    ),
                    resolution=(
                        "Reduce the total file size by selecting fewer "
                        "directories or removing large files from the "
                        "configured paths."
                    ),
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

        except MicrosoftFileShareError:
            raise
        except Exception as error:
            error_message = (
                "Error occurred while pulling images metadata."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {error_message}",
                details=traceback.format_exc(),
            )
            raise MicrosoftFileShareError(
                message=error_message
            ) from error

    def generate_dir_path_uuid(self, configuration, storage):
        """Generate uuid for directory path configurations.

        Args:
            configuration (dict): plugin configuration
            storage (dict): plugin storage

        Returns:
            dict: directory configuration with uuid.
        """

        directory_inputs = configuration.get(
            "directory_configuration", {}
        ).get("directory_inputs", [])

        directory_storage = storage.get("directory_paths", {})
        stored_paths = set(directory_storage.keys())
        input_paths = set()

        for directory_configuration in directory_inputs:
            shared_directory_name = directory_configuration.get(
                "sharedDirectoryName", ""
            ).strip()
            input_paths.update(
                {
                    self._get_directory_storage_key(
                        shared_directory_name,
                        self._sanitize_relative_path(
                            directory.get("directory_path", "")
                        ),
                    )
                    for directory in directory_configuration.get(
                        "directory_paths", []
                    )
                }
            )

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

        # Persist all current path→UUID assignments into history so
        # future re-adds can look them up.
        storage["path_uuid_history"] = {**path_uuid_history, **result}

        return result

    def validate_directory_path(
        self, connection, shared_directory_name, directory_path
    ):
        """Validate directory path.

        Args:
            connection (SMBConnection): SMB connection.
            shared_directory_name (str): Shared directory name.
            directory_path (str): Directory path.

        Raises:
            MicrosoftFileShareError: If an error occurred
            while validating directory path.
        """
        # Check if path exists by attempting to retrieve attributes
        # and check it is a valid directory
        try:
            directory_attributes = connection.getAttributes(
                shared_directory_name, directory_path
            )
            if not directory_attributes.isDirectory:
                error_message = (
                    f"Path '{directory_path}' exists but is not a "
                    "directory on the remote server."
                )
                raise MicrosoftFileShareError(message=error_message)
        except MicrosoftFileShareError:
            raise
        except Exception as error:
            error_message = (
                f"Path '{directory_path}' does not exist on the "
                "remote server."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {error_message}",
                details=traceback.format_exc(),
            )
            raise MicrosoftFileShareError(message=error_message, value=error)

    def pull_metadata(
        self, server_configuration, directory_config, directory_storage
    ):
        """Pull metadata from server for provided directory configuration.

        Args:
            server_configuration (dict): server configuration.
            directory_config (dict): directory configuration.
            directory_storage (dict): directory storage.

        Raises:
            MicrosoftFileShareError: If an error occurred while
            pulling images metadata.

        Returns:
            list: List of images metadata.
        """
        last_fetched_time = datetime.now()
        directory_inputs = directory_config.get("directory_inputs", [])
        success = True
        connection = None

        try:
            connection, connection_result = self.get_smb_connection_object(
                server_configuration
            )
            if not connection_result:
                raise MicrosoftFileShareError(
                    message=(
                        "Could not connect with the Windows server "
                        f"'{server_configuration.get('smb_server_ip', '')}'."
                    )
                )

            images_metadata = []

            for directory_configuration in directory_inputs:
                shared_directory_name = directory_configuration.get(
                    "sharedDirectoryName", ""
                ).strip()
                directory_list = directory_configuration.get(
                    "directory_paths", []
                )

                for directory in directory_list:
                    directory_path = directory.get(
                        "directory_path", ""
                    ).strip()
                    filename_filter = directory.get("filename_filter", "")
                    sanitized_directory_path = (
                        self._sanitize_relative_path(directory_path)
                    )
                    directory_key = self._get_directory_storage_key(
                        shared_directory_name, sanitized_directory_path
                    )
                    if directory_key not in directory_storage:
                        raise MicrosoftFileShareError(
                            message=(
                                "Internal consistency error: missing "
                                "directory UUID mapping "
                                f"for '{directory_key}'."
                            )
                        )

                    dirUuid = directory_storage.get(directory_key, "")

                    try:
                        self.validate_directory_path(
                            connection,
                            shared_directory_name,
                            sanitized_directory_path,
                        )
                    except MicrosoftFileShareError as error:
                        self.logger.error(
                            message=(
                                f"{self.log_prefix}: Invalid directory "
                                f"path. Error: {str(error)}"
                            ),
                            details=traceback.format_exc(),
                            resolution=(
                                "Ensure that the directory path in the "
                                "configuration exists and is accessible "
                                "on the remote Windows server."
                            ),
                        )
                        success = False
                        continue
                    except Exception:
                        self.logger.error(
                            message=(
                                f"{self.log_prefix}: Error validating "
                                f"directory path '{sanitized_directory_path}'"
                            ),
                            details=traceback.format_exc(),
                        )
                        success = False
                        continue

                    try:
                        files_list = connection.listPath(
                            shared_directory_name, sanitized_directory_path
                        )
                    except Exception:
                        self.logger.error(
                            message=(
                                f"{self.log_prefix}: Error listing files in "
                                f"directory '{sanitized_directory_path}'"
                            ),
                            details=traceback.format_exc(),
                        )
                        success = False
                        continue

                    for file in files_list:
                        if (
                            (not file.isDirectory)
                            and any(
                                file.filename.lower().endswith(
                                    file_extension
                                )
                                for file_extension in
                                SUPPORTED_IMAGE_FILE_EXTENSIONS
                            )
                            and (
                                not filename_filter
                                or re.search(
                                    filename_filter, file.filename
                                )
                            )
                        ):
                            filename = file.filename
                            remote_file_path = (
                                f"{sanitized_directory_path}\\{filename}"
                                if sanitized_directory_path
                                else filename
                            )
                            full_file_path = (
                                f"{shared_directory_name}\\{remote_file_path}"
                            )
                            # Check if this file path already exists in
                            # metadata for the same dirUuid to
                            # avoid duplicates
                            file_already_exists = any(
                                meta.get("path") == full_file_path
                                and meta.get("dirUuid") == dirUuid
                                for meta in images_metadata
                            )
                            if file_already_exists:
                                continue

                            file_metadata = dict()
                            file_metadata["sourcePlugin"] = self.name
                            file_metadata["file"] = filename
                            file_metadata["path"] = full_file_path
                            file_metadata["extension"] = (
                                os.path.splitext(filename)[1]
                                .split(".")[1]
                                .upper()
                            )
                            file_metadata["lastFetched"] = (
                                last_fetched_time
                            )
                            file_metadata["dirUuid"] = dirUuid
                            file_metadata["fileSize"] = file.file_size
                            file_metadata["shared_directory"] = (
                                shared_directory_name
                            )
                            file_metadata["remote_path"] = remote_file_path

                            images_metadata.append(file_metadata)

            # Validate total file size before returning
            total_files_size = sum(
                file_metadata.get("fileSize", 0)
                for file_metadata in images_metadata
            )
            if total_files_size > ALLOWED_FILE_SIZE:
                size_error_message = (
                    f"No files will be pulled as the total size of files "
                    f"({total_files_size / (1024 ** 3):.2f} GB) exceeds the "
                    f"allowed file size limit of "
                    f"{ALLOWED_FILE_SIZE / (1024 ** 3):.2f} GB. Reduce the "
                    f"total size of configured paths."
                )
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: {size_error_message}"
                    ),
                    resolution=(
                        "Reduce the total size of configured paths by "
                        "selecting fewer directories or using filename "
                        "filters."
                    ),
                )
                return [], False

            return images_metadata, success

        except MicrosoftFileShareError:
            # Re-raise custom exception
            raise
        except Exception as error:
            error_message = "Error occurred while pulling images metadata."
            self.logger.error(
                message=f"{self.log_prefix}: {error_message}",
                details=traceback.format_exc(),
            )
            raise MicrosoftFileShareError(
                value=error, message=error_message
            ) from error
        finally:
            connection.close()

    def validate_file_path(self, connection, shared_directory_name, file_path):
        """Validate file path.

        Args:
            connection (SMBConnection): SMB connection.
            shared_directory_name (str): Shared directory name.
            file_path (str): File path.

        Raises:
            MicrosoftFileShareError: If the file path is invalid or
            inaccessible or not a regular file.
        """
        try:
            # Check if file exists by attempting to get attributes
            file_attributes = connection.getAttributes(
                shared_directory_name, file_path
            )

            # Check if it's a regular file by examining file attributes
            # First check it's not a directory
            if file_attributes.isDirectory:
                error_message = (
                    f"Path '{file_path}' exists but is not a file on "
                    "the remote server."
                )
                raise MicrosoftFileShareError(message=error_message)

            # Check if it's a regular file by examining the file mode
            # In SMB, we can check file attributes to determine
            # if it's a regular file
            # Regular files should not have special attributes
            # like device, symlink, etc.
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
                error_message = (
                    f"Path '{file_path}' exists but is not a regular "
                    "file on the remote server."
                )
                raise MicrosoftFileShareError(message=error_message)
        except MicrosoftFileShareError:
            raise
        except Exception as error:
            error_message = (
                f"Could not access path '{file_path}' on the remote server."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {error_message}",
                details=traceback.format_exc(),
            )
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
                        f"{FILE_PATH}/{self.name}/"
                        f"{data.get('dirUuid', '')}/{data.get('file', '')}"
                    )
                    if not os.path.exists(os.path.dirname(image_file_path)):
                        os.makedirs(os.path.dirname(image_file_path))
                    try:
                        self.validate_file_path(
                            connection,
                            data.get("shared_directory", ""),
                            data.get("remote_path", ""),
                        )
                    except MicrosoftFileShareError as error:
                        self.logger.error(
                            message=(
                                f"{self.log_prefix}: Invalid file "
                                f"path {str(error)}"
                            ),
                            details=traceback.format_exc(),
                        )
                        success = False
                        continue
                    try:
                        with open(image_file_path, "wb") as file_object:
                            connection.retrieveFile(
                                data.get("shared_directory", ""),
                                data.get("remote_path", ""),
                                file_obj=file_object,
                            )
                    except OperationFailure as error:
                        self.logger.debug(
                            message=(
                                f"{self.log_prefix}: Permission denied "
                                f"while pulling file "
                                f"'{data.get('remote_path', '')}'. "
                                f"Error: {str(error)}"
                            ),
                            details=traceback.format_exc(),
                        )
                        success = False
                        continue
        except MicrosoftFileShareError:
            # Re-raise custom exception
            raise
        except Exception as error:
            error_message = "Error occurred while pulling images."
            self.logger.error(
                message=f"{self.log_prefix}: {error_message}",
                details=traceback.format_exc(),
            )
            raise MicrosoftFileShareError(
                value=error, message=error_message
            ) from error
        return success


class SFTPProtocolFileSharePlugin:
    """Microsoft File Share plugin helper class for SFTP protocol.

    This class implements helper methods to validate & verify SMB protocol
    based configuration.
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

    @staticmethod
    def _normalize_directory_path(path: str) -> str:
        """Normalize directory path for consistent storage key generation.

        Args:
            path (str): Directory path.

        Returns:
            str: Normalized directory path.
        """
        if not path:
            return ""
        # Convert backslashes to forward slashes and remove trailing slashes
        normalized = path.replace("\\", "/").rstrip("/")
        return normalized

    def validate_configuration_parameters(
        self, configuration: dict
    ) -> ValidationResult:
        """Validate SFTP connection configuration.

        Args:
            configuration (dict): Configuration dictionary containing SFTP
            parameters.

        Returns:
            ValidationResult: Validation result with success status
            and message.
        """
        # Validate Server Hostname/IP
        for key, value in configuration.items():
            if isinstance(value, str) and key != "sftp_password":
                configuration[key] = value.strip()
        server_ip = configuration.get("sftp_server_ip", "")
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
        username = configuration.get("sftp_username", "")
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
                    "Ensure that the Username is a "
                    "non-empty string value."
                ),
            )
            return ValidationResult(success=False, message=err_msg)

        # Validate Password
        password = configuration.get("sftp_password", "")
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
                    "Ensure that the Password is a "
                    "non-empty string value."
                ),
            )
            return ValidationResult(success=False, message=err_msg)

        # Validate Port
        port = configuration.get("sftp_port")
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

    def get_ssh_connection_object(
        self, configuration: dict
    ) -> paramiko.SSHClient:
        """Get a SSH connection to the remote Windows server.

        Args:
            configuration (dict): Configuration parameters.

        Raises:
            MicrosoftFileShareError: If an error occurred while connecting
            with the Windows server.

        Returns:
            paramiko.SSHClient: SSH connection object.
        """
        try:
            ssh_connection = paramiko.SSHClient()
            ssh_connection.set_missing_host_key_policy(
                paramiko.AutoAddPolicy()
            )
            ssh_connection.connect(
                hostname=configuration.get("sftp_server_ip", ""),
                username=configuration.get("sftp_username", ""),
                password=configuration.get("sftp_password", ""),
                port=configuration.get("sftp_port", 22),
            )
            return ssh_connection
        except AuthenticationException as error:
            error_message = (
                "Authentication failed while connecting to the "
                f"Windows server '{configuration.get('sftp_server_ip', '')}'."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {error_message}",
                details=traceback.format_exc(),
                resolution=(
                    "Ensure that the Server Hostname/IP, Username, Password "
                    "and Port provided in the configuration are correct."
                ),
            )
            raise MicrosoftFileShareError(
                message=error_message, value=error
            ) from error
        except SSHException as error:
            error_message = (
                "Couldn't establish SSH session with the "
                f"Windows server' {configuration.get('sftp_server_ip', '')}'."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {error_message}",
                details=traceback.format_exc(),
                resolution=(
                    "Ensure that the Windows server is reachable and "
                    "accessible from the Netskope CE instance."
                ),
            )
            raise MicrosoftFileShareError(
                message=error_message, value=error
            ) from error
        except Exception as error:
            error_message = (
                "An unexpected error occurred while connecting to the "
                f"Windows server '{configuration.get('sftp_server_ip', '')}'."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {error_message}",
                details=traceback.format_exc(),
                resolution=(
                    "Ensure that the Server Hostname/IP, Port, Username "
                    "and Password are correct and the Windows server is "
                    "reachable from the Netskope CE instance."
                ),
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
        server_ip = configuration.get("sftp_server_ip", "")
        ssh_connection = self.get_ssh_connection_object(configuration)
        ssh_connection.close()
        msg = (
            f"Connection with the Windows server {server_ip} "
            "verified successfully."
        )
        self.logger.debug(f"{self.log_prefix}: {msg}")
        return ValidationResult(success=True, message=msg)

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
            err_msg = "Directory paths are a required configuration parameter."
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Validation error "
                    f"occurred. {err_msg}"
                ),
                resolution=(
                    "Ensure that at least one directory "
                    "path is provided."
                ),
            )
            return ValidationResult(success=False, message=err_msg)

        for directory in directory_paths:
            # Validate Directory Path
            directory_path = directory.get("directory_path", "")
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
                        "Ensure that a valid directory "
                        "path is provided."
                    ),
                )
                return ValidationResult(success=False, message=err_msg)
            if not isinstance(
                directory_path, str
            ) or not directory_path.strip():
                err_msg = (
                    "Directory path should be a "
                    "non-empty string value."
                )
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: Validation error "
                        f"occurred. {err_msg}"
                    ),
                    resolution=(
                        "Ensure that the directory path is a "
                        "non-empty string value."
                    ),
                )
                return ValidationResult(success=False, message=err_msg)

            # Validate Filename Filter
            filename_filter = directory.get("filename_filter", "")
            if not isinstance(filename_filter, str):
                err_msg = "Filename filter should be non-empty string value."
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
            directory_path = directory.get("directory_path", "").strip()
            filename_filter = directory.get("filename_filter", "")

            if tuple((directory_path, filename_filter)) in directory_set:
                if filename_filter:
                    err_msg = (
                        f"Directory path '{directory_path}' and "
                        f"filename filter '{filename_filter}' are duplicated."
                    )
                else:
                    err_msg = (
                        f"Directory path '{directory_path}' and "
                        "empty filename filter are duplicated."
                    )
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: Validation error "
                        f"occurred. {err_msg}"
                    ),
                    resolution=(
                        "Ensure that each directory path and filename "
                        "filter combination is unique."
                    ),
                )
                return ValidationResult(success=False, message=err_msg)
            directory_set.add(tuple((directory_path, filename_filter)))

        msg = "Successfully validated the directory inputs parameters."
        self.logger.debug(f"{self.log_prefix}: {msg}")
        return ValidationResult(success=True, message=msg)

    def verify_directory_inputs(
        self, configuration: dict, directory_configurations: dict
    ) -> ValidationResult:
        """Verify the directory configuration.

        Args:
            configuration (dict): Configuration parameters.
            directory_configurations (dict): Directory configuration.

        Returns:
            DirectoryConfigurationOut: Directory configuration with
            verification result.
        """
        directory_paths = directory_configurations.get("directory_paths", [])

        success_status = True

        result_data = list()
        ssh_connection = self.get_ssh_connection_object(configuration)

        try:
            with ssh_connection.open_sftp() as sftp_session:
                for directory in directory_paths:
                    directory_path = directory.get(
                        "directory_path", "").strip()
                    filename_filter = directory.get("filename_filter", "")

                    directory_entry = {
                        "directory_path": directory_path,
                        "filename_filter": filename_filter,
                    }

                    if directory_path == "/":
                        success_status = False
                        directory_entry.update(
                            {
                                "error": {
                                    "directory_path": "Directory path "
                                    "is not supported.",
                                }
                            }
                        )
                    else:
                        try:
                            _ = sftp_session.listdir(directory_path)
                        except Exception as error:
                            success_status = False
                            self.logger.error(
                                message=(
                                    f"{self.log_prefix}: Error accessing "
                                    f"directory '{directory_path}'. "
                                    f"Error: {error}"
                                ),
                                details=traceback.format_exc(),
                            )
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
                    except Exception as error:
                        success_status = False
                        error_message = (
                            "Filename filter should be a valid regular "
                            "expression."
                        )
                        self.logger.error(
                            message=(
                                f"{self.log_prefix}: Invalid filename "
                                f"filter '{filename_filter}'. Error: {error}"
                            ),
                            details=traceback.format_exc(),
                        )
                        directory_entry.setdefault("error", {}).update(
                            {"filename_filter": error_message}
                        )

                    result_data.append(directory_entry)
        finally:
            ssh_connection.close()

        if success_status:
            message = (
                "Validation of directory configuration "
                "completed successfully."
            )
            self.logger.debug(f"{self.log_prefix}: {message}")
        else:
            message = (
                "One or more directory configurations are invalid. "
                "Please check the provided directory inputs."
            )
            self.logger.error(f"{self.log_prefix}: {message}")

        return ValidationResult(
            success=success_status,
            message=message,
            data={"directory_paths": result_data},
        )

    def fetch_images_metadata(
        self, configuration: dict, directory_configurations: dict
    ) -> DirectoryConfigurationMetadataOut:
        """Fetch images metadata for the plugin directory configuration.

        Args:
            configuration (dict): Configuration parameters.
            directory_configurations (dict): Directory configuration.

        Returns:
            DirectoryConfigurationMetadataOut: Images metadata
            for the plugin directory configuration.
        """
        try:
            directory_paths = directory_configurations.get(
                "directory_paths", []
            )

            ssh_connection = self.get_ssh_connection_object(configuration)

            directory_inputs_metadata = []
            total_files_count = 0
            total_files_size = 0

            try:
                with ssh_connection.open_sftp() as sftp_session:
                    for directory in directory_paths:
                        directory_path = (
                            directory.get("directory_path", "").strip()
                        )
                        filename_filter = directory.get("filename_filter", "")

                        files_count = 0
                        files_size = 0

                        try:
                            files = sftp_session.listdir(directory_path)

                            for file in files:
                                try:
                                    file_attributes = (
                                        sftp_session.lstat(
                                            f"{directory_path}/{file}"
                                        )
                                    )

                                    if (
                                        stat.S_ISREG(
                                            file_attributes.st_mode
                                        )
                                        and any(
                                            file.lower().endswith(
                                                file_extension
                                            )
                                            for file_extension in
                                            SUPPORTED_IMAGE_FILE_EXTENSIONS
                                        )
                                        and (
                                            not filename_filter
                                            or re.search(
                                                filename_filter, file
                                            )
                                        )
                                    ):
                                        files_count = files_count + 1
                                        files_size = (
                                            files_size +
                                            file_attributes.st_size
                                        )
                                except (FileNotFoundError, IOError):
                                    # Skip inaccessible files
                                    continue
                        except Exception:
                            # Skip directory if listing fails
                            continue

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

            files_count_exceeded = (
                total_files_count > ALLOWED_FILE_COUNT
            )
            files_count_message = (
                "Total file count is within the allowed file count limit."
            )
            if files_count_exceeded:
                files_count_message = (
                    f"Total file count ({total_files_count}) exceeded the "
                    f"allowed limit of {ALLOWED_FILE_COUNT} files."
                )
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: {files_count_message}"
                    ),
                    resolution=(
                        "Reduce the number of files by refining the "
                        "directory paths or filename filters."
                    ),
                )

            files_size_exceeded = (
                total_files_size > ALLOWED_FILE_SIZE
            )
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
                    message=(
                        f"{self.log_prefix}: {files_size_message}"
                    ),
                    resolution=(
                        "Reduce the total file size by selecting fewer "
                        "directories or removing large files from the "
                        "configured paths."
                    ),
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

        except MicrosoftFileShareError:
            raise
        except Exception as error:
            error_message = (
                "Error occurred while pulling images metadata."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {error_message}",
                details=traceback.format_exc(),
            )
            raise MicrosoftFileShareError(
                message=error_message
            ) from error

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
        stored_paths = set(directory_storage.keys())
        input_paths = set(
            self._normalize_directory_path(
                paths.get("directory_path", "").strip()
            )
            for paths in directory_paths
        )

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

        # Persist all current path→UUID assignments into history so
        # future re-adds can look them up.
        storage["path_uuid_history"] = {**path_uuid_history, **result}

        return result

    def validate_directory_path(self, sftp_session, directory_path):
        """Validate directory path.

        Args:
            sftp_session: SFTP session object.
            directory_path (str): directory path.

        Raises:
            MicrosoftFileShareError: If the directory path is invalid
             or inaccessible.
        """
        try:
            # Check if path exists by attempting to get attributes
            file_attributes = sftp_session.stat(directory_path)
            # Check if it's a directory
            if not stat.S_ISDIR(file_attributes.st_mode):
                error_message = (
                    f"Path '{directory_path}' exists but is not a "
                    "directory on the remote server."
                )
                raise MicrosoftFileShareError(message=error_message)
        except MicrosoftFileShareError:
            # Re-raise custom exception
            raise
        except FileNotFoundError as error:
            error_message = (
                f"Path '{directory_path}' does not exist on the "
                "remote server."
            )
            raise MicrosoftFileShareError(message=error_message, value=error)
        except Exception as error:
            error_message = (
                f"Could not access path '{directory_path}' on the "
                "remote server."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {error_message}",
                details=traceback.format_exc(),
            )
            raise MicrosoftFileShareError(message=error_message, value=error)

    def pull_metadata(
        self, server_configuration, directory_config, directory_storage
    ):
        """Pull metadata from server for provided directory configuration.

        Args:
            server_configuration (dict): server configuration.
            directory_config (dict): directory configuration.
            directory_storage (dict): directory storage.

        Raises:
            MicrosoftFileShareError: If an error occurred while
            pulling images metadata.

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
        except MicrosoftFileShareError:
            raise
        except Exception as error:
            error_message = (
                "Error occurred while connecting to the server "
                "for pulling metadata."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {error_message}",
                details=traceback.format_exc(),
                resolution=(
                    "Ensure that the Server Hostname/IP, Port, Username "
                    "and Password are correct and the server is "
                    "reachable from the Netskope CE instance."
                ),
            )
            raise MicrosoftFileShareError(
                message=error_message
            ) from error

        images_metadata = []

        try:
            with ssh_connection.open_sftp() as sftp_session:
                for directory in directory_paths:
                    directory_path = directory.get(
                        "directory_path", ""
                    ).strip()
                    filename_filter = directory.get("filename_filter", "")
                    normalized_directory_path = self._normalize_directory_path(
                        directory_path
                    )
                    dirUuid = directory_storage.get(
                        normalized_directory_path, ""
                        )

                    try:
                        # Validate directory path before processing
                        self.validate_directory_path(
                            sftp_session,
                            normalized_directory_path
                        )
                    except MicrosoftFileShareError as error:
                        self.logger.error(
                            message=(
                                f"{self.log_prefix}: Invalid directory "
                                f"path. Error: {str(error)}"
                            ),
                            details=traceback.format_exc(),
                            resolution=(
                                "Ensure that the directory path in the "
                                "configuration exists and is accessible "
                                "on the remote Windows server."
                            ),
                        )
                        success = False
                        continue
                    except Exception:
                        self.logger.error(
                            message=(
                                f"{self.log_prefix}: Error validating "
                                f"directory path '{directory_path}'"
                            ),
                            details=traceback.format_exc(),
                        )
                        success = False
                        continue

                    try:
                        files = sftp_session.listdir(normalized_directory_path)

                        for file in files:
                            try:
                                file_attributes = sftp_session.lstat(
                                    f"{normalized_directory_path}/{file}"
                                )

                                if (
                                    stat.S_ISREG(file_attributes.st_mode)
                                    and any(
                                        file.lower().endswith(file_extension)
                                        for file_extension in
                                        SUPPORTED_IMAGE_FILE_EXTENSIONS
                                    )
                                    and (
                                        not filename_filter or
                                        re.search(filename_filter, file)
                                    )
                                ):
                                    remote_file_path = (
                                        f"{normalized_directory_path}/{file}"
                                    )

                                    file_metadata = dict()
                                    file_metadata["sourcePlugin"] = self.name
                                    file_metadata["file"] = file
                                    file_metadata["path"] = remote_file_path
                                    file_metadata["extension"] = (
                                        os.path.splitext(file)[1].split(".")[1]
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
                            except (FileNotFoundError, IOError) as err:
                                self.logger.debug(
                                    message=(
                                        f"{self.log_prefix}: Unable to "
                                        f"access file '{file}' in directory "
                                        f"'{directory_path}'. Skipping file. "
                                        f"Error: {err}"
                                    )
                                )
                                continue
                    except Exception:
                        self.logger.error(
                            message=(
                                f"{self.log_prefix}: Error listing files "
                                f"in directory '{directory_path}'"
                            ),
                            details=traceback.format_exc(),
                        )
                        success = False
                        continue
        except MicrosoftFileShareError:
            raise
        except Exception as error:
            error_message = "Error occurred while pulling metadata."
            self.logger.error(
                message=f"{self.log_prefix}: {error_message}",
                details=traceback.format_exc(),
                resolution=(
                    "Ensure that the SFTP server is reachable and the "
                    "configured directory paths are accessible."
                ),
            )
            raise MicrosoftFileShareError(
                value=error, message=error_message
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
                f"No files will be pulled as the total size of files "
                f"({total_files_size / (1024 ** 3):.2f} GB) exceeds the "
                f"allowed file size limit of "
                f"{ALLOWED_FILE_SIZE / (1024 ** 3):.2f} GB. Reduce the "
                f"total size of configured paths."
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

        self.logger.debug(
            f"{self.log_prefix}: Successfully pulled images metadata."
        )
        return images_metadata, success

    def validate_file_path(self, sftp_session, file_path):
        """Validate file path.

        Args:
            sftp_session: SFTP session object.
            file_path (str): File path.

        Raises:
            MicrosoftFileShareError: If the file path is invalid or
            inaccessible or not a regular file.
        """
        try:
            # Check if file exists by attempting to get attributes
            file_attributes = sftp_session.stat(file_path)
            # Check if it's a regular file using stat.S_ISREG
            if not stat.S_ISREG(file_attributes.st_mode):
                error_message = (
                    f"Path '{file_path}' exists but is not "
                    "a regular file on the remote server."
                )
                raise MicrosoftFileShareError(message=error_message)
        except MicrosoftFileShareError:
            # Re-raise custom exception
            raise
        except FileNotFoundError as error:
            error_message = (
                f"Path '{file_path}' does not exist on the remote server."
            )
            raise MicrosoftFileShareError(message=error_message, value=error)
        except Exception as error:
            error_message = (
                f"Could not access path '{file_path}' on the remote server."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {error_message}",
                details=traceback.format_exc(),
            )
            raise MicrosoftFileShareError(message=error_message, value=error)

    def pull_files(self, server_configuration, metadata):
        """Pull files from server when sharing is configured for this plugin.

        Args:
            server_configuration (dict): server configuration
            metadata (list): list of metadata fetched.
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
                                f"{FILE_PATH}/{self.name}"
                                f"/{data.get('dirUuid', '')}"
                            )
                            if not os.path.exists(file_path):
                                os.makedirs(file_path)
                            try:
                                self.validate_file_path(
                                    sftp_session, data.get("path", "")
                                )
                            except MicrosoftFileShareError as error:
                                self.logger.error(
                                    message=(
                                        f"{self.log_prefix}: Invalid file path "
                                        f"{str(error)}"
                                    ),
                                    details=traceback.format_exc(),
                                )
                                success = False
                                continue
                            try:
                                sftp_session.get(
                                    data.get("path", ""),
                                    os.path.join(
                                        file_path, data.get("file", "")
                                    ),
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
        except MicrosoftFileShareError:
            # Re-raise custom exception
            raise
        except Exception as error:
            error_message = "Error occurred while pulling images."
            self.logger.error(
                message=f"{self.log_prefix}: {error_message}",
                details=traceback.format_exc(),
            )
            raise MicrosoftFileShareError(
                value=error, message=error_message
            ) from error
        return success
