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

Linux File Share Plugin Helper file.
"""

import csv
import io
import stat
import traceback

from ..lib import paramiko
from ..lib.paramiko.ssh_exception import (
    AuthenticationException,
    SSHException,
)
from netskope.integrations.edm.plugin_base import ValidationResult
from netskope.integrations.edm.utils import (
    CustomException as LinuxFileShareEDM,
)


class LinuxProtocolFileShareEDMPlugin:
    """Linux File Share Plugin Class for SSH/SFTP protocol."""

    def __init__(self, logger, log_prefix) -> None:
        """Initialize method for LinuxProtocolFileShareEDMPlugin class."""
        self.logger = logger
        self.log_prefix = log_prefix

    def validate_configuration_parameters(
        self, configuration
    ) -> ValidationResult:
        """Validate the configuration parameters for an SSH connection."""
        # Validate server IP/hostname
        server_ip = configuration.get("server_ip")
        if not server_ip:
            err_msg = (
                "Server IP/Hostname is a required configuration " "parameter."
            )
            self.logger.error(
                message=(
                        f"{self.log_prefix}: Validation error "
                        f"occurred. {err_msg}"
                    ),
                resolution=(
                    "Ensure that a valid Server IP/Hostname is provided."
                ),
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        if not isinstance(server_ip, str) or not server_ip.strip():
            err_msg = (
                "Invalid value provided for the configuration parameter "
                "Server IP/Hostname."
            )
            self.logger.error(
                message=(
                        f"{self.log_prefix}: Validation error "
                        f"occurred. {err_msg}"
                    ),
                resolution="Ensure that the Server IP/Hostname is a non-empty "
                "string value.",
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )

        # Validate username
        username = configuration.get("username")
        if not username:
            err_msg = "Username is a required configuration parameter."
            self.logger.error(
                message=(
                        f"{self.log_prefix}: Validation error "
                        f"occurred. {err_msg}"
                    ),
                resolution="Ensure that a valid Username is provided.",
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        if not isinstance(username, str) or not username.strip():
            err_msg = (
                "Invalid value provided for the configuration parameter "
                "Username."
            )
            self.logger.error(
                message=(
                        f"{self.log_prefix}: Validation error "
                        f"occurred. {err_msg}"
                    ),
                resolution="Ensure that the Username is a non-empty "
                "string value.",
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )

        # Validate password
        password = configuration.get("password")
        if not password:
            err_msg = "Password is a required configuration parameter."
            self.logger.error(
                message=(
                        f"{self.log_prefix}: Validation error "
                        f"occurred. {err_msg}"
                    ),
                resolution="Ensure that a valid Password is provided.",
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        if not isinstance(password, str) or not password.strip():
            err_msg = (
                "Invalid value provided for the configuration parameter "
                "Password."
            )
            self.logger.error(
                message=(
                        f"{self.log_prefix}: Validation error "
                        f"occurred. {err_msg}"
                    ),
                resolution="Ensure that the Password is a non-empty "
                "string value.",
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )

        # Validate port
        port = configuration.get("port")
        if port is None:
            err_msg = "Port is a required configuration parameter."
            self.logger.error(
                message=(
                        f"{self.log_prefix}: Validation error "
                        f"occurred. {err_msg}"
                    ),
                resolution="Ensure that a valid Port is provided.",
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        if not isinstance(port, int) or not (0 < port < 65536):
            err_msg = "Port should be an integer between 1 and 65535."
            self.logger.error(
                message=(
                        f"{self.log_prefix}: Validation error "
                        f"occurred. {err_msg}"
                    ),
                resolution=(
                    "Ensure that the Port is an integer between "
                    "1 and 65535."
                ),
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )

        # Validate filepath
        filepath = configuration.get("filepath")
        if not filepath:
            err_msg = "CSV File Path is a required configuration "
            "parameter."
            self.logger.error(
                message=(
                        f"{self.log_prefix}: Validation error "
                        f"occurred. {err_msg}"
                    ),
                resolution="Ensure that a valid CSV File Path is provided.",
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        if not isinstance(filepath, str) or not filepath.strip():
            err_msg = (
                "Invalid value provided for the configuration parameter "
                "CSV File Path."
            )
            self.logger.error(
                message=(
                        f"{self.log_prefix}: Validation error "
                        f"occurred. {err_msg}"
                    ),
                resolution=(
                    "Ensure that the CSV File Path is a non-empty "
                    "string value."
                ),
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        # Validate file extension
        if not filepath.strip().lower().endswith((".csv", ".txt")):
            err_msg = "Invalid file path provided in the configuration "
            "parameter. The plugin only supports .csv and .txt file"
            self.logger.error(
                message=(
                        f"{self.log_prefix}: Validation error "
                        f"occurred. {err_msg}"
                    ),
                resolution=(
                    "Ensure that only supported .csv and .txt file extensions "
                    "provided."
                ),
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )

        # Validate delimiter
        delimiter = configuration.get("delimiter", ",")
        if not isinstance(delimiter, str) or not delimiter.strip():
            err_msg = (
                "Invalid value provided for the configuration parameter "
                "Delimiter."
            )
            self.logger.error(
                message=(
                        f"{self.log_prefix}: Validation error "
                        f"occurred. {err_msg}"
                    ),
                resolution=(
                    "Ensure that the Delimiter is a non-empty string value."
                ),
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        if len(delimiter.strip()) > 1:
            err_msg = "Delimiter should be a single character."
            self.logger.error(
                message=(
                        f"{self.log_prefix}: Validation error "
                        f"occurred. {err_msg}"
                    ),
                resolution=(
                    "Ensure that a single character (e.g. ',', '|', '\\t') is "
                    "provided for Delimiter."
                ),
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )

        remove_quotes = configuration.get("remove_quotes", False)
        if not isinstance(remove_quotes, bool):
            err_msg = (
                "Invalid value provided for the configuration parameter "
                "Remove Quotes."
            )
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Validation error occurred. {err_msg}"
                ),
                resolution="Ensure that Remove Quotes is a valid "
                "boolean value.",
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )

        message = "Successfully validated configuration parameters."
        return ValidationResult(success=True, message=message)

    def get_ssh_connection_object(self, configuration) -> paramiko.SSHClient:
        """Establish an SSH connection to a remote server.

        Args:
            configuration: parameter configuration dictionary.

        Raises:
            LinuxFileShareEDM: If any errors occur during SSH connection.

        Returns:
            paramiko.SSHClient: An SSHClient object representing the SSH
                connection.
        """
        server_ip = configuration.get("server_ip", "")
        port = configuration.get("port", 22)
        try:
            ssh_connection = paramiko.SSHClient()
            ssh_connection.set_missing_host_key_policy(
                paramiko.AutoAddPolicy()
            )
            ssh_connection.connect(
                hostname=server_ip,
                username=configuration.get("username", ""),
                password=configuration.get("password", ""),
                port=port,
            )
            return ssh_connection
        except AuthenticationException as error:
            error_message = (
                f"Authentication failed while connecting to "
                f"the Linux server '{server_ip}'. "
                "Ensure that the Server IP/Hostname, Username, Port and "
                "Password are correct"
            )
            self.logger.error(
                message=f"{self.log_prefix}: {error_message}",
                resolution=(
                    "Ensure that the username and password provided in "
                    "the configuration are correct and the user has "
                    "access to the server."
                ),
                details=traceback.format_exc(),
            )
            raise LinuxFileShareEDM(
                value=error, message=error_message
            ) from error
        except SSHException as error:
            error_message = (
                f"Error occurred while establishing SSH session with "
                f"the Linux server '{server_ip}' over port '{port}'."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {error_message}",
                resolution=(
                    "Ensure that the server hostname/IP and port "
                    "provided in the configuration are correct and the "
                    "SSH server is reachable."
                ),
                details=traceback.format_exc(),
            )
            raise LinuxFileShareEDM(value=error, message=str(error)) from error

    def verify_connection(self, configuration) -> ValidationResult:
        """Verify the connection with a Linux server using SFTP protocol.

        Args:
            configuration: parameter configuration dictionary.

        Returns:
            ValidationResult: Validation result object.
        """
        server_ip = configuration.get("server_ip", "")
        try:
            ssh_connection = self.get_ssh_connection_object(configuration)
            ssh_connection.close()
            message = (
                "Successfully verified connection "
                f"with the Linux server '{server_ip}'."
            )
            self.logger.debug(message=f"{self.log_prefix}: {message}")
            return ValidationResult(
                success=True,
                message=message,
            )
        except LinuxFileShareEDM:
            raise
        except Exception as error:
            error_message = (
                "Error occurred while connecting with remote server. "
                "Verify that the Server IP/Hostname, Port, Username "
                "and Password are correct."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {error_message}",
                resolution=(
                    "Ensure that the Server IP/Hostname, Port, "
                    "Username and Password are correct and the "
                    "Linux server is reachable."
                ),
                details=traceback.format_exc(),
            )
            return ValidationResult(
                success=False,
                message=error_message,
            )

    def validate_remote_file(
        self,
        configuration: dict,
        delimiter: str,
    ) -> None:
        """Validate that the file exists and is accessible on the
        remote server.

        Args:
            configuration: parameter configuration dictionary.
            delimiter: CSV delimiter.

        Raises:
            LinuxFileShareEDM: If the file does not exist, is not accessible,
            or is not a regular file.
        """
        remote_file_path = configuration.get("filepath", "")
        ssh_connection = self.get_ssh_connection_object(configuration)
        try:
            with ssh_connection.open_sftp() as sftp_session:
                try:
                    # Check if file exists
                    file_attributes = sftp_session.stat(remote_file_path)

                    # Check if it's a regular file
                    if not stat.S_ISREG(file_attributes.st_mode):
                        error_message = (
                            f"Path '{remote_file_path}' exists but is "
                            "not a regular file on the remote server."
                        )
                        self.logger.error(
                            message=f"{self.log_prefix}: {error_message}",
                            resolution=(
                                "Ensure that the file path points to a "
                                "regular file."
                            ),
                        )
                        raise LinuxFileShareEDM(message=error_message)

                    # Check if file is readable
                    try:
                        with sftp_session.file(
                            remote_file_path, "r"
                        ) as remote_file:
                            file_content = remote_file.readline()
                            if isinstance(file_content, bytes):
                                file_content = file_content.decode("utf-8")
                            file_like_object = io.StringIO(file_content)

                            csv_reader = csv.reader(
                                file_like_object, delimiter=delimiter
                            )
                            column_names = next(csv_reader)

                            if len(column_names) > 25:
                                error_message = (
                                    "Maximum 25 columns allowed. Reduce "
                                    "columns from the source file and try "
                                    "again."
                                )
                                self.logger.error(
                                    message=(
                                        f"{self.log_prefix}: {error_message}"
                                    ),
                                    resolution=(
                                        "Ensure the number of columns in "
                                        "the source file is reduced."
                                    ),
                                )
                                raise LinuxFileShareEDM(message=error_message)
                            return column_names
                    except UnicodeDecodeError as error:
                        error_message = (
                            "Only CSV/TXT file is supported. "
                            "Provide a valid file."
                        )
                        self.logger.error(
                            message=f"{self.log_prefix}: {error_message}",
                            resolution=(
                                "Ensure the file is a valid CSV/TXT file "
                                "with UTF-8 encoding."
                            ),
                            details=traceback.format_exc(),
                        )
                        raise LinuxFileShareEDM(
                            value=error, message=error_message
                        ) from error
                    except PermissionError as error:
                        error_message = (
                            f"File '{remote_file_path}' exists but is "
                            "not readable on the remote server."
                        )
                        self.logger.error(
                            message=f"{self.log_prefix}: {error_message}",
                            resolution=(
                                "Ensure the user has read permissions "
                                "for the file."
                            ),
                            details=traceback.format_exc(),
                        )
                        raise LinuxFileShareEDM(
                            value=error, message=error_message
                        ) from error

                except FileNotFoundError as error:
                    error_message = (
                        f"File '{remote_file_path}' does not exist "
                        "on the remote server."
                    )
                    self.logger.error(
                        message=f"{self.log_prefix}: {error_message}",
                        resolution=(
                            "Ensure that the file exists and is "
                            "accessible on the remote server."
                        ),
                        details=traceback.format_exc(),
                    )
                    raise LinuxFileShareEDM(
                        value=error, message=error_message
                    ) from error
                except LinuxFileShareEDM:
                    raise
                except Exception as error:
                    error_message = f"Error accessing file: {str(error)}"
                    self.logger.error(
                        message=f"{self.log_prefix}: {error_message}",
                        resolution=(
                            "Verify file path and permissions on the "
                            "remote server."
                        ),
                        details=traceback.format_exc(),
                    )
                    raise LinuxFileShareEDM(
                        value=error, message=error_message
                    ) from error
        except LinuxFileShareEDM:
            raise
        except Exception as error:
            error_message = (
                "Error occurred while validating remote file: "
                f"{str(error)}"
            )
            self.logger.error(
                message=f"{self.log_prefix}: {error_message}",
                resolution=(
                    "Ensure the SSH connection is stable and the "
                    "file is accessible."
                ),
                details=traceback.format_exc(),
            )
            raise LinuxFileShareEDM(
                value=error, message=error_message
            ) from error
        finally:
            ssh_connection.close()

    def pull_csv_file_records(
        self, configuration: dict, csv_file_path: str, record_count: int = 0
    ) -> None:
        """Pull CSV/TXT file records from a remote location and save locally.

        Args:
            configuration: parameter configuration dictionary.
            csv_file_path: The local file path where pulled records
            will be saved.
            record_count: The number of records to pull (default is 0).

        Raises:
            LinuxFileShareEDM: If the operation to retrieve CSV/TXT data fails.
        """
        remote_file_path = configuration.get("filepath", "")
        try:
            ssh_connection = self.get_ssh_connection_object(configuration)
            with ssh_connection.open_sftp() as sftp_session:
                if record_count:
                    file_content = []
                    with sftp_session.file(
                        remote_file_path, "r"
                    ) as remote_file:
                        for _ in range(record_count + 1):
                            record = remote_file.readline()
                            if not record:
                                break
                            file_content.append(record)
                    with open(
                        csv_file_path, "w", encoding="utf-8", newline="\n"
                    ) as local_file:
                        local_file.writelines(file_content)
                else:
                    sftp_session.get(remote_file_path, csv_file_path)
        except LinuxFileShareEDM:
            raise
        except FileNotFoundError as error:
            error_message = (
                f"File '{remote_file_path}' does not exist "
                "on the remote server."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {error_message}",
                resolution=(
                    "Ensure that the file exists and is "
                    "accessible on the remote server."
                ),
                details=traceback.format_exc(),
            )
            raise LinuxFileShareEDM(
                value=error, message=error_message
            ) from error
        except Exception as error:
            error_message = (
                f"Data retrieval operation failed for file: "
                f"{remote_file_path}"
            )
            self.logger.error(
                message=f"{self.log_prefix}: {error_message}",
                resolution=(
                    "Ensure the file exists, is accessible, and the SSH "
                    "connection is stable."
                ),
                details=traceback.format_exc(),
            )
            raise LinuxFileShareEDM(value=error, message=str(error)) from error
        finally:
            ssh_connection.close()
