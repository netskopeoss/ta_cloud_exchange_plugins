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

SMB Protocol File Share CFC Plugin helper module.
"""

# Built-in libraries
import os
import re
import shutil
import stat
import traceback
from datetime import datetime
from uuid import uuid4

# Third-party libraries
from ..lib import smbclient
from ..lib.smbprotocol.exceptions import (
    SMBException,
    SMBResponseException,
)
from ..lib.smbprotocol.header import NtStatus

# Local imports
from .constants import (
    ALLOWED_FILE_COUNT,
    ALLOWED_FILE_SIZE,
    SUPPORTED_IMAGE_FILE_EXTENSIONS,
)
from netskope.common.utils import Logger
from netskope.integrations.cfc.models import DirectoryConfigurationMetadataOut
from netskope.integrations.cfc.plugin_base import ValidationResult
from netskope.integrations.cfc.utils import (
    CustomException as SMBFileShareCFC,
    FILE_PATH,
)


class SMBProtocolFileShareCFCPlugin:
    """SMB File Share CFC Plugin Class for SMB protocol."""

    def __init__(self, name: str, logger: Logger, log_prefix: str):
        """Initialize method for SMBProtocolFileShareCFCPlugin class."""
        self.name = name
        self.logger = logger
        self.log_prefix = log_prefix

    @staticmethod
    def _get_server_name(configuration: dict) -> str:
        """Get server hostname/IP from configuration."""
        server = configuration.get("smb_server_ip", "")
        return server.strip() if isinstance(server, str) else ""

    @staticmethod
    def _sanitize_relative_path(path: str) -> str:
        """Sanitize SMB relative path without separator conversion."""
        sanitized_path = (path or "").strip()
        sanitized_path = sanitized_path.strip("\\")
        parts = [segment for segment in sanitized_path.split("\\") if segment]
        return "\\".join(parts)

    def _build_unc_path(self, server: str, share: str, path: str = "") -> str:
        """Build UNC path from server, share and relative path."""
        relative_path = (path or "").lstrip("\\/")
        if relative_path:
            return f"\\\\{server}\\{share}\\{relative_path}"
        return f"\\\\{server}\\{share}"

    @staticmethod
    def _get_directory_storage_key(
        shared_directory_name: str, relative_directory_path: str
    ) -> str:
        """Build deterministic directory storage key."""
        if relative_directory_path:
            return f"{shared_directory_name}\\{relative_directory_path}"
        return shared_directory_name

    @staticmethod
    def _is_not_found_error(error: Exception) -> bool:
        """Check if exception indicates missing SMB path."""
        if isinstance(error, SMBResponseException):
            if error.status in (
                NtStatus.STATUS_NOT_FOUND,
                NtStatus.STATUS_OBJECT_NAME_NOT_FOUND,
                NtStatus.STATUS_OBJECT_PATH_NOT_FOUND,
            ):
                return True
        if isinstance(error, FileNotFoundError):
            return True
        error_message = str(error).lower()
        return any(
            token in error_message
            for token in (
                "not found",
                "no such file",
                "path not found",
                "object_name_not_found",
                "object_path_not_found",
            )
        )

    @staticmethod
    def _is_shared_directory_error(error: Exception) -> bool:
        """Check if exception indicates shared directory level failure."""
        if isinstance(error, SMBResponseException):
            if error.status in (
                NtStatus.STATUS_BAD_NETWORK_NAME,
                NtStatus.STATUS_NETWORK_NAME_DELETED,
            ):
                return True
        error_message = str(error).lower()
        return any(
            token in error_message
            for token in (
                "unable to connect to shared device",
                "status_bad_network_name",
                "bad network name",
                "bad_network_name",
                "network name cannot be found",
                "tree connect failed",
            )
        )

    @staticmethod
    def _get_file_size(file_entry) -> int:
        """Get file size without calling stat twice when possible."""
        smb_info = getattr(file_entry, "smb_info", None)
        end_of_file = getattr(smb_info, "end_of_file", None)

        if isinstance(end_of_file, int):
            return end_of_file

        return file_entry.stat().st_size

    def validate_configuration_parameters(
        self,
        configuration: dict
    ) -> ValidationResult:
        """Validate SMB connection configuration.

        Args:
            configuration: Configuration dictionary containing SMB parameters

        Returns:
            ValidationResult: Validation result with success status and message
        """
        # Validate SMB Server Hostname/IP
        smb_server_ip = configuration.get("smb_server_ip", "")
        if isinstance(smb_server_ip, str):
            smb_server_ip = smb_server_ip.strip()
        if not smb_server_ip:
            return ValidationResult(
                success=False,
                message="SMB Server Hostname/IP is a required field.",
            )
        if not isinstance(smb_server_ip, str) or not smb_server_ip.strip():
            return ValidationResult(
                success=False,
                message="Invalid SMB Server Hostname/IP provided."
            )

        # Validate Username
        smb_username = configuration.get("smb_username", "")
        if not smb_username:
            return ValidationResult(
                success=False, message="Username is a required field."
            )
        if isinstance(smb_username, str):
            smb_username = smb_username.strip()

        if not isinstance(smb_username, str) or not smb_username.strip():
            return ValidationResult(
                success=False, message="Invalid Username provided."
            )

        # Validate Password (do not strip)
        smb_password = configuration.get("smb_password", "")
        if not smb_password:
            return ValidationResult(
                success=False, message="Password is a required field."
            )
        if not isinstance(smb_password, str) or not smb_password.strip():
            return ValidationResult(
                success=False, message="Invalid Password provided."
            )

        # Validate Port
        smb_port = configuration.get("smb_port")
        if smb_port is None:
            return ValidationResult(
                success=False,
                message="Port is a required field.",
            )
        if (
            not isinstance(smb_port, int)
            or not (0 < smb_port < 65536)
        ):
            return ValidationResult(
                success=False,
                message=(
                    "Invalid Port provided. Port should be an "
                    "integer between 1 and 65535."
                )
            )

        return ValidationResult(
            success=True,
            message=(
                "Successfully validated configuration parameters."
            )
        )

    def _register_session(self, configuration: dict) -> str:
        """Register an SMB session with the server."""
        server = self._get_server_name(configuration)
        smbclient.register_session(
            server,
            username=configuration.get("smb_username"),
            password=configuration.get("smb_password"),
            port=configuration.get("smb_port", 445),
        )
        return server

    @staticmethod
    def _close_session() -> None:
        """Close active SMB sessions."""
        smbclient.reset_connection_cache()

    def verify_connection(self, configuration: dict) -> ValidationResult:
        """Verify the connection with an SMB server using SMB protocol."""
        server = self._get_server_name(configuration)
        try:
            self._register_session(configuration)
            return ValidationResult(
                success=True,
                message=(
                    "Connection with the SMB server "
                    f"'{server}' verified successfully."
                ),
            )
        except (SMBException, SMBResponseException) as error:
            self.logger.error(
                message=f"{self.log_prefix}: Error occured while "
                f"validating the connection with the SMB server '{server}'. "
                f"Error: {str(error)}",
                details=traceback.format_exc(),
                resolution=(
                    "Ensure that server hostname/IP, username, and "
                    "password in the configuration and, "
                    "ensure that SMB server is reachable and accessible "
                    "from the Netskope CE instance."
                ),
            )
        except Exception as error:
            self.logger.error(
                message=f"{self.log_prefix}: Error occured while "
                f"validating the connection with the SMB server '{server}'. "
                f"Error: {str(error)}",
                details=traceback.format_exc(),
                resolution=(
                    "Ensure that SMB server connectivity and credentials and, "
                    "ensure server is reachable and the provided "
                    "credentials are correct."
                ),
            )
        finally:
            self._close_session()

        return ValidationResult(
            success=False,
            message=(
                f"Error occured while validating the "
                f"SMB server '{server}'."
            ),
        )

    def validate_directory_inputs(
        self, directory_configuration: dict
    ) -> ValidationResult:
        """Validate the directory configuration."""
        directory_inputs = directory_configuration.get("directory_inputs", [])

        if not directory_inputs:
            return ValidationResult(
                success=False,
                message="Directory inputs are required field.",
            )

        normalized_shared_directories = set()

        for directory_configuration in directory_inputs:
            if "sharedDirectoryName" in directory_configuration:
                if (
                    isinstance(
                        directory_configuration.get(
                            "sharedDirectoryName", ""
                        ), str
                    )
                    and directory_configuration.get(
                        "sharedDirectoryName", ""
                    ).strip()
                ):
                    shared_directory_name = (
                        directory_configuration.get(
                            "sharedDirectoryName", ""
                        ).strip()
                    )
                    if "/" in shared_directory_name:
                        return ValidationResult(
                            success=False,
                            message=(
                                "Invalid shared directory name. "
                                "Only backslashes (\\) are supported; "
                                "forward slashes (/) cannot be used in "
                                "shared directory names."
                            ),
                        )
                    normalized_name = self._sanitize_relative_path(
                        shared_directory_name
                    )
                    if normalized_name in normalized_shared_directories:
                        return ValidationResult(
                            success=False,
                            message=(
                                f"Shared directory "
                                f"'{shared_directory_name}' is already "
                                "configured for this path."
                            ),
                        )
                    normalized_shared_directories.add(normalized_name)
                else:
                    return ValidationResult(
                        success=False,
                        message="Shared directory name should "
                        "be a non-empty string value.",
                    )
            else:
                return ValidationResult(
                    success=False,
                    message="Shared directory name is required field.",
                )

            directory_list = directory_configuration.get("directory_paths", [])
            if not directory_list:
                return ValidationResult(
                    success=False,
                    message="At least one directory path is required.",
                )

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
                            message="Directory path should be a non-empty "
                            "string value.",
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
                            message="Filename filter should be a "
                            "string value.",
                        )
                else:
                    return ValidationResult(
                        success=False,
                        message="Filename filter is required field.",
                    )

        for directory_configuration in directory_inputs:
            shared_directory_name = (
                directory_configuration.get("sharedDirectoryName", "").strip()
            )
            directory_list = directory_configuration.get("directory_paths", [])
            directory_set = set()

            for directory in directory_list:
                directory_path = directory.get("directory_path", "").strip()
                filename_filter = directory.get("filename_filter", "")
                if (
                    directory_path.startswith("\\\\")
                    or directory_path.startswith("//")
                ):
                    return ValidationResult(
                        success=False,
                        message=(
                            "Directory path should be relative to the shared "
                            "directory, not a full UNC path."
                        ),
                    )
                if "/" in directory_path:
                    return ValidationResult(
                        success=False,
                        message=(
                            "Invalid directory path format. Use backslashes "
                            "(\\) only; forward slashes (/) are not "
                            "supported in SMB paths. For example, use "
                            "'folder\\subfolder' instead of "
                            "'folder/subfolder'."
                        ),
                    )
                sanitized_directory_path = self._sanitize_relative_path(
                    directory_path
                )

                if (
                    sanitized_directory_path,
                    filename_filter,
                ) in directory_set:
                    if filename_filter:
                        error_message = (
                            f"Directory path '{directory_path}' and filename "
                            f"filter '{filename_filter}' are duplicated "
                            f"for directory '{shared_directory_name}'."
                        )
                    else:
                        error_message = (
                            f"Directory path '{directory_path}' and "
                            "empty filename filter are duplicated "
                            f"for directory '{shared_directory_name}'."
                        )
                    raise ValueError(error_message)

                directory_set.add((sanitized_directory_path, filename_filter))

        return ValidationResult(
            success=True,
            message="Validation of directory inputs completed successfully.",
        )

    def verify_directory_inputs(
        self, configuration: dict, directory_configurations: dict
    ) -> ValidationResult:
        """Verify configured shared directories and directory paths."""
        directory_inputs = directory_configurations.get(
            "directory_inputs", []
        )
        success_status = True
        result_data = []
        try:
            server = self._register_session(configuration)

            for directory_configuration in directory_inputs:
                shared_directory_name = (
                    directory_configuration.get(
                        "sharedDirectoryName", ""
                    ).strip()
                )
                directory_list = (
                    directory_configuration.get("directory_paths", [])
                )

                directory_result = {
                    "sharedDirectoryName": shared_directory_name,
                    "directory_paths": [],
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
                        directory_result[
                            "directory_paths"].append(directory_entry)
                        continue

                    sanitized_directory_path = self._sanitize_relative_path(
                        directory_path
                    )
                    directory_unc_path = self._build_unc_path(
                        server, shared_directory_name, sanitized_directory_path
                    )

                    try:
                        _ = list(smbclient.scandir(directory_unc_path))
                    except (SMBException, SMBResponseException) as error:
                        success_status = False
                        if self._is_shared_directory_error(error):
                            shared_directory_exist = False
                            directory_result.update(
                                {
                                    "error": True,
                                    "message": "Unable to connect to shared "
                                    "directory.",
                                    "errorType": "shared_directory_error",
                                }
                            )
                            directory_result[
                                "directory_paths"
                            ].append(directory_entry)
                            continue
                        directory_entry_invalid = True
                        if self._is_not_found_error(error):
                            error_message = "Directory does not exist."
                        else:
                            error_message = "Couldn't access the directory."
                        directory_entry.update(
                            {"error": {"directory_path": error_message}}
                        )
                    except Exception as error:
                        success_status = False
                        if self._is_shared_directory_error(error):
                            shared_directory_exist = False
                            directory_result.update(
                                {
                                    "error": True,
                                    "message": "Unable to connect to shared "
                                    "directory.",
                                    "errorType": "shared_directory_error",
                                }
                            )
                            directory_result[
                                "directory_paths"
                            ].append(directory_entry)
                            continue
                        directory_entry_invalid = True
                        if self._is_not_found_error(error):
                            error_message = "Directory does not exist."
                        else:
                            error_message = "Couldn't access the directory."
                        directory_entry.update(
                            {"error": {"directory_path": error_message}}
                        )

                    try:
                        re.compile(filename_filter)
                    except Exception:
                        success_status = False
                        directory_entry_invalid = True
                        error_message = (
                            "Filename filter should be a "
                            "valid regular expression."
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
        except Exception as error:
            raise SMBFileShareCFC(
                message="Error occurred while verifying "
                "directory configuration.",
                value=error,
            ) from error
        finally:
            self._close_session()

        if success_status:
            message = "Validation of directory inputs completed successfully."
        else:
            message = (
                "One or more directory configurations are invalid. "
                "Please check the provided directory inputs."
            )

        return ValidationResult(
            success=success_status,
            message=message,
            data={"directory_inputs": result_data},
        )

    def fetch_images_metadata(
        self, configuration: dict, directory_configuration: dict
    ) -> DirectoryConfigurationMetadataOut:
        """Fetch image metadata for configured SMB directories."""
        directory_inputs = directory_configuration.get("directory_inputs")
        total_files_count = 0
        total_files_size = 0
        directory_inputs_metadata = []

        try:
            server = self._register_session(configuration)

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
                    sanitized_directory_path = self._sanitize_relative_path(
                        directory_path
                    )
                    directory_unc_path = self._build_unc_path(
                        server, shared_directory_name, sanitized_directory_path
                    )

                    files_count = 0
                    files_size = 0

                    for file_entry in smbclient.scandir(directory_unc_path):
                        filename = file_entry.name

                        if (
                            file_entry.is_file()
                            and any(
                                filename.lower().endswith(file_extension)
                                for file_extension
                                in SUPPORTED_IMAGE_FILE_EXTENSIONS
                            )
                            and (
                                not filename_filter
                                or re.search(filename_filter, filename)
                            )
                        ):
                            files_count += 1
                            files_size += self._get_file_size(file_entry)

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

                    total_files_count += files_count
                    total_files_size += files_size

                    directory_inputs_metadata.append(
                        {
                            "sharedDirectoryName": shared_directory_name,
                            "directoryPath": directory_path,
                            "filenameFilter": filename_filter,
                            "filesCount": files_count,
                            "filesSize": files_size,
                        }
                    )
        except Exception as error:
            error_message = "Error occurred while pulling images metadata."
            raise SMBFileShareCFC(
                value=error,
                message=error_message
            ) from error
        finally:
            self._close_session()

        files_count_exceeded = total_files_count > ALLOWED_FILE_COUNT
        files_count_message = (
            "Total file count is within the "
            "allowed file count limit."
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
                    "paths or filename filters. "
                    "Current file count: {total_files_count}, "
                    "Allowed limit: {ALLOWED_FILE_COUNT}."
                ),
            )

        files_size_exceeded = total_files_size > ALLOWED_FILE_SIZE
        if files_size_exceeded:
            files_size_message = (
                f"Total size of the provided paths "
                f"({total_files_size / (1024 ** 3):.2f} GB) "
                f"exceeds the allowed file size limit of "
                f"{ALLOWED_FILE_SIZE / (1024 ** 3):.2f} GB. "
                f"No files will be pulled. Reduce the total size "
                f"of the configured paths and try again."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {files_size_message}",
                resolution=(
                    "Reduce the total file size by selecting fewer "
                    "directories or removing large files from the "
                    "configured paths."
                ),
            )
        else:
            files_size_message = (
                "Total file size is within the allowed file size limit."
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

    def generate_dir_path_uuid(
        self, configuration: dict, storage: dict
    ) -> dict:
        """Generate UUID values for directory path configurations."""
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
        self, server: str, shared_directory_name: str, directory_path: str
    ):
        """Validate that directory path exists on remote SMB server."""
        directory_unc_path = self._build_unc_path(
            server, shared_directory_name, directory_path
        )

        try:
            directory_attributes = smbclient.stat(directory_unc_path)
            if not stat.S_ISDIR(directory_attributes.st_mode):
                error_message = (
                    f"Path '{directory_path}' exists but is not a directory "
                    "on the remote server."
                )
                raise SMBFileShareCFC(message=error_message)
        except SMBFileShareCFC:
            raise
        except (SMBException, SMBResponseException) as error:
            if self._is_not_found_error(error):
                error_message = (
                    f"Path '{directory_path}' does not exist "
                    "on the remote server."
                )
            else:
                error_message = (
                    f"Could not access path '{directory_path}' on "
                    "the remote server."
                )
            raise SMBFileShareCFC(
                message=error_message,
                value=error
            ) from error
        except Exception as error:
            if self._is_not_found_error(error):
                error_message = (
                    f"Path '{directory_path}' does not exist on "
                    "the remote server."
                )
            else:
                error_message = (
                    f"Could not access path '{directory_path}' on the "
                    "remote server."
                )
            raise SMBFileShareCFC(
                message=error_message,
                value=error
            ) from error

    def pull_metadata(
        self,
        server_configuration,
        directory_config,
        directory_storage
    ):
        """
        Pull metadata from SMB server for provided directory configuration.

        Args:
            server_configuration: Server configuration dictionary
            directory_config: Directory configuration dictionary
            directory_storage: Directory storage dictionary

        Returns:
            DirectoryConfigurationMetadataOut: Metadata containing
            file information
        """
        last_fetched_time = datetime.now()
        directory_inputs = directory_config.get("directory_inputs", [])
        success = True

        try:
            server = self._register_session(server_configuration)
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
                    sanitized_directory_path = self._sanitize_relative_path(
                        directory_path
                    )

                    try:
                        self.validate_directory_path(
                            server,
                            shared_directory_name,
                            sanitized_directory_path,
                        )
                    except SMBFileShareCFC as error:
                        self.logger.error(
                            f"{self.log_prefix}: Invalid directory "
                            f"path {str(error)}",
                            details=traceback.format_exc(),
                            resolution=(
                                "Ensure that directory path in the "
                                "configuration and, "
                                "ensure the directory exists and is "
                                "accessible on the remote SMB server."
                            ),
                        )
                        success = False
                        continue

                    directory_key = self._get_directory_storage_key(
                        shared_directory_name, sanitized_directory_path
                    )

                    if directory_key not in directory_storage:
                        raise SMBFileShareCFC(
                            message=(
                                "Internal consistency error: missing "
                                "directory UUID mapping "
                                f"for '{directory_key}'."
                            )
                        )

                    dirUuid = directory_storage.get(directory_key, "")

                    directory_unc_path = self._build_unc_path(
                        server, shared_directory_name, sanitized_directory_path
                    )

                    for file_entry in smbclient.scandir(directory_unc_path):
                        filename = file_entry.name

                        if (
                            file_entry.is_file()
                            and any(
                                filename.lower().endswith(file_extension)
                                for file_extension
                                in SUPPORTED_IMAGE_FILE_EXTENSIONS
                            )
                            and (
                                not filename_filter
                                or re.search(filename_filter, filename)
                            )
                        ):
                            file_metadata = {}
                            remote_file_path = (
                                f"{sanitized_directory_path}\\{filename}"
                                if sanitized_directory_path
                                else filename
                            )
                            full_file_path = (
                                f"{shared_directory_name}\\{remote_file_path}"
                            )

                            file_size = self._get_file_size(file_entry)

                            file_metadata["sourcePlugin"] = self.name
                            file_metadata["file"] = filename
                            file_metadata["path"] = full_file_path
                            file_metadata["extension"] = (
                                os.path.splitext(
                                    filename
                                )[1].lstrip(".").upper()
                            )
                            file_metadata["lastFetched"] = last_fetched_time
                            file_metadata["dirUuid"] = dirUuid
                            file_metadata["fileSize"] = file_size
                            file_metadata[
                                "shared_directory"
                            ] = shared_directory_name
                            file_metadata["remote_path"] = remote_file_path

                            images_metadata.append(file_metadata)

            total_files_size = sum(
                file_metadata.get("fileSize", 0)
                for file_metadata in images_metadata
            )
            if total_files_size > ALLOWED_FILE_SIZE:
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: No files will be pulled as "
                        f"the total size of the provided paths "
                        f"({total_files_size / (1024 ** 3):.2f} GB) "
                        f"exceeds the allowed file size limit of "
                        f"{ALLOWED_FILE_SIZE / (1024 ** 3):.2f} GB. "
                        f"Reduce the total size of the configured paths."
                    ),
                    resolution=(
                        "Reduce the total size of configured paths by "
                        "selecting fewer directories or using filename "
                        "filters. "
                    ),
                )
                return [], False

            return images_metadata, success
        except SMBFileShareCFC:
            raise
        except Exception as error:
            error_message = "Error occurred while pulling images metadata."
            raise SMBFileShareCFC(
                value=error,
                message=error_message
            ) from error
        finally:
            self._close_session()

    def validate_file_path(
        self, server: str, shared_directory_name: str, file_path: str
    ):
        """Validate that file path exists and is a regular file."""
        file_unc_path = self._build_unc_path(
            server, shared_directory_name,
            file_path
        )

        try:
            file_attributes = smbclient.stat(file_unc_path)
            if not stat.S_ISREG(file_attributes.st_mode):
                error_message = (
                    f"Path '{file_path}' exists but is not a regular file "
                    "on the remote server."
                )
                raise SMBFileShareCFC(message=error_message)
        except SMBFileShareCFC:
            raise
        except (SMBException, SMBResponseException) as error:
            if self._is_not_found_error(error):
                error_message = (
                    f"Path '{file_path}' does not exist on the "
                    "remote server."
                )
            else:
                error_message = (
                    f"Could not access path '{file_path}' on the "
                    "remote server."
                )
            raise SMBFileShareCFC(
                message=error_message,
                value=error
            ) from error
        except Exception as error:
            if self._is_not_found_error(error):
                error_message = (
                    f"Path '{file_path}' does not exist on "
                    "the remote server."
                )
            else:
                error_message = (
                    f"Could not access path '{file_path}' on "
                    "the remote server."
                )
            raise SMBFileShareCFC(
                message=error_message,
                value=error
            ) from error

    def pull_files(self, server_configuration: dict, metadata: list):
        """Pull files from SMB server when sharing is configured for plugin."""
        success = True

        try:
            server = self._register_session(server_configuration)
            for data in metadata:
                image_file_path = (
                    f"{FILE_PATH}/{self.name}/{data['dirUuid']}/{data['file']}"
                )
                os.makedirs(os.path.dirname(image_file_path), exist_ok=True)
                try:
                    self.validate_file_path(
                        server, data["shared_directory"], data["remote_path"]
                    )
                except SMBFileShareCFC as error:
                    self.logger.error(
                        f"{self.log_prefix}: Invalid file path {str(error)}",
                        resolution=(
                            "Ensure that file path in the configuration and, "
                            "ensure the file exists and is accessible on "
                            "the remote SMB server."
                        ),
                        details=traceback.format_exc(),
                    )
                    success = False
                    continue

                remote_file_unc_path = self._build_unc_path(
                    server, data["shared_directory"], data["remote_path"]
                )
                try:
                    with smbclient.open_file(
                        remote_file_unc_path,
                        "rb"
                    ) as remote_file:
                        with open(image_file_path, "wb") as file_object:
                            shutil.copyfileobj(remote_file, file_object)
                except OSError as error:
                    if (
                        hasattr(error, "ntstatus")
                        and error.ntstatus == 0xC0000022  # STATUS_ACCESS_DENIED
                    ):
                        self.logger.debug(
                            message=(
                                f"{self.log_prefix}: Permission denied "
                                f"while pulling file "
                                f"'{data.get('remote_path', '')}'. "
                                f"Error: {error}"
                            ),
                            details=traceback.format_exc(),
                        )
                        success = False
                        continue
                    raise
        except (SMBException, SMBResponseException) as error:
            error_message = "Error occurred while pulling images "
            raise SMBFileShareCFC(
                value=error,
                message=error_message
            ) from error
        except Exception as error:
            error_message = "Error occurred while pulling images."
            raise SMBFileShareCFC(
                value=error,
                message=error_message
            ) from error
        finally:
            self._close_session()

        return success
