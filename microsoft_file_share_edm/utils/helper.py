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

SMB File Share Plugin Helper file.
"""

# Built-in libraries
import csv
import io
import traceback

# Third-party libraries
from ..lib import paramiko
from ..lib.paramiko.ssh_exception import AuthenticationException, SSHException
from ..lib.smb.base import NotConnectedError, NotReadyError
from ..lib.smb.SMBConnection import SMBConnection
from ..lib.smb.smb_structs import OperationFailure

from netskope.integrations.edm.plugin_base import ValidationResult
from netskope.integrations.edm.utils import (
    CustomException as MicrosoftFileShareEDM,
)


class SMBProtocolFileShareEDMPlugin:
    """Microsoft File Share EDM Plugin Class for SMB protocol.

    This Class implements helper method to Pull & Validate the CSV file using
        SMB protocol.
    """

    def __init__(self, logger, log_prefix) -> None:
        """Initialize method for SMBProtocolFileShareEDMPlugin class."""
        self.logger = logger
        self.log_prefix = log_prefix

    def validate_configuration_parameters(
        self, configuration
    ) -> ValidationResult:
        """Validate the configuration parameters for an SMB connection.

        Args:
            configuration: parameter configuration dictionary.

        Returns:
            ValidationResult: An object indicating the result
            of the validation.
            - success (bool): True if all parameters are valid,
            False otherwise.
            - message (str): A message describing the validation result.
        """
        server_ip = configuration.get("smb_server_ip")
        if not server_ip:
            err_msg = (
                "Server Hostname/IP is a required "
                "configuration parameter."
            )
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Validation error occurred. {err_msg}"
                ),
                resolution=(
                    "Ensure that a valid Server Hostname/IP is provided."
                ),
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        if not isinstance(server_ip, str) or not server_ip.strip():
            err_msg = (
                "Server IP/Hostname should be a "
                "non-empty string value."
            )
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Validation error occurred. {err_msg}"
                ),
                resolution=(
                    "Ensure that the Server IP/Hostname is a "
                    "non-empty string value."
                ),
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )

        machine_name = configuration.get("smb_machine_name")
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
            err_msg = (
                "Machine Name should be a "
                "non-empty string value."
            )
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

        username = configuration.get("smb_username")
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
            err_msg = "Username should be a non-empty string value."
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Validation error occurred. {err_msg}"
                ),
                resolution=(
                    "Ensure that the Username is a non-empty string value."
                ),
            )
            return ValidationResult(success=False, message=err_msg)

        password = configuration.get("smb_password")
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
            err_msg = "Password should be a non-empty string value."
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Validation error occurred. {err_msg}"
                ),
                resolution=(
                    "Ensure that the Password is a non-empty string value."
                ),
            )
            return ValidationResult(success=False, message=err_msg)

        filepath = configuration.get("smb_filepath")
        if not filepath:
            err_msg = "File path is a required configuration parameter."
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Validation error occurred. {err_msg}"
                ),
                resolution="Ensure that a valid File path is provided.",
            )
            return ValidationResult(success=False, message=err_msg)
        if not isinstance(filepath, str) or not filepath.strip():
            err_msg = "File path should be a non-empty string value."
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Validation error occurred. {err_msg}"
                ),
                resolution=(
                    "Ensure that the File path is a non-empty string value."
                ),
            )
            return ValidationResult(success=False, message=err_msg)
        if not filepath.strip().lower().endswith((".csv", ".txt")):
            err_msg = "Only .csv and .txt file extensions are supported."
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Validation error occurred. {err_msg}"
                ),
                resolution=(
                    "Ensure that only supported .csv or .txt file extensions "
                    "are provided in the File path."
                ),
            )
            return ValidationResult(success=False, message=err_msg)

        shared_directory_name = configuration.get("smb_shared_directory_name")
        if not shared_directory_name:
            err_msg = (
                "Windows shared directory name is a required configuration "
                "parameter."
            )
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Validation error occurred. {err_msg}"
                ),
                resolution=(
                    "Ensure that a valid Windows shared directory name "
                    "is provided."
                ),
            )
            return ValidationResult(success=False, message=err_msg)
        if (
            not isinstance(shared_directory_name, str)
            or not shared_directory_name.strip()
        ):
            err_msg = (
                "Windows shared directory name should be "
                "a non-empty string value."
            )
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Validation error occurred. {err_msg}"
                ),
                resolution=(
                    "Ensure that the Windows shared directory name is a "
                    "non-empty string value."
                ),
            )
            return ValidationResult(success=False, message=err_msg)

        # Validate delimiter
        delimiter = configuration.get("delimiter", ",")
        if not isinstance(delimiter, str) or not delimiter.strip():
            err_msg = "Delimiter should be a non-empty string value."
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Validation error occurred. {err_msg}"
                ),
                resolution=(
                    "Ensure that the Delimiter is a non-empty string value."
                ),
            )
            return ValidationResult(success=False, message=err_msg)
        if len(delimiter.strip()) > 1:
            err_msg = "Delimiter should be a single character."
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Validation error occurred. {err_msg}"
                ),
                resolution=(
                    "Ensure that a single character is "
                    "provided for Delimiter."
                ),
            )
            return ValidationResult(success=False, message=err_msg)

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
                resolution=(
                    "Ensure that the Remove Quotes is a valid "
                    "boolean value."
                ),
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )

        message = "Successfully validated configuration parameters."
        return ValidationResult(
            success=True,
            message=message,
        )

    def validate_remote_file(self, configuration: dict) -> None:
        """
        Validate that the file exists and is accessible on the remote server.

        Args:
            configuration: parameter configuration dictionary.

        Raises:
            MicrosoftFileShareEDM: If the file does not exist,
            is not accessible, or is not a regular file.
        """
        connection, connection_result = self.get_smb_connection_object(
            configuration
        )
        if not connection_result:
            raise MicrosoftFileShareEDM(
                message=(
                    "Couldn't verify the connection with the Windows server."
                )
            )
        shared_directory_name = configuration.get("smb_shared_directory_name")
        remote_file_path = configuration.get("smb_filepath")
        if remote_file_path.startswith("\\"):
            remote_file_path = remote_file_path.strip("\\")
        remote_file_path = remote_file_path.replace("\\", "\\\\")

        try:
            # Check if file exists by attempting to retrieve file attributes
            try:
                file_attributes = connection.getAttributes(
                    shared_directory_name, remote_file_path
                )

                # Check if it's a regular file (not a directory)
                if file_attributes.isDirectory:
                    error_message = (
                        f"Path '{remote_file_path}' exists but is a directory,"
                        " not a file on the remote server."
                    )
                    raise MicrosoftFileShareEDM(message=error_message)

                # Check if file is readable by attempting to read its content
                try:
                    file_obj = io.BytesIO()
                    connection.retrieveFileFromOffset(
                        shared_directory_name,
                        remote_file_path,
                        file_obj,
                        offset=0,
                        max_length=1024,
                    )
                    file_obj.seek(0)

                    # Try to read as CSV
                    csv_reader = csv.reader(
                        io.TextIOWrapper(file_obj, encoding="utf-8")
                    )

                    # Get the first row as column names
                    column_names = next(csv_reader, None)

                    if column_names is None:
                        error_message = (
                            f"File '{remote_file_path}' is empty or not "
                            "readable as CSV."
                        )
                        raise MicrosoftFileShareEDM(message=error_message)

                    if len(column_names) > 25:
                        error_message = (
                            "Maximum 25 columns allowed. Reduce "
                            "columns from the source file and try again."
                        )
                        raise MicrosoftFileShareEDM(message=error_message)

                except MicrosoftFileShareEDM:
                    raise
                except UnicodeDecodeError as error:
                    error_message = (
                        "Only CSV file is supported. Provide "
                        "a valid CSV file."
                    )
                    raise MicrosoftFileShareEDM(
                        value=error, message=error_message
                    ) from error
                except Exception as error:
                    error_message = (
                        f"File '{remote_file_path}' exists but is not readable"
                        " or not a valid CSV file."
                    )
                    self.logger.error(
                        f"{self.log_prefix}: {error_message}",
                        details=traceback.format_exc(),
                        resolution=(
                            "Ensure that the file is present on the SMB "
                            "server and server is reachable and accessible."
                        ),
                    )
                    raise MicrosoftFileShareEDM(
                        value=error, message=error_message
                    ) from error

            except OperationFailure as error:
                error_message = (
                    f"File '{remote_file_path}' does not exist or is not "
                    "accessible on the remote server."
                )
                self.logger.error(
                    message=f"{self.log_prefix}: {error_message}",
                    details=traceback.format_exc(),
                    resolution=(
                        "Ensure that the file is present on the SMB server "
                        "and server is reachable and accessible."
                    ),
                )
                raise MicrosoftFileShareEDM(
                    value=error, message=error_message
                ) from error

        except MicrosoftFileShareEDM:
            raise
        except Exception as error:
            error_message = "Error occurred while validating the remote file."
            self.logger.error(
                message=f"{self.log_prefix}: {error_message}",
                resolution=(
                    "Ensure that the file is present on the remote server "
                    "and server is reachable and accessible."
                ),
                details=traceback.format_exc(),
            )
            raise MicrosoftFileShareEDM(
                value=error, message=error_message
            ) from error
        finally:
            connection.close()

    def get_smb_connection_object(
        self, configuration
    ) -> (SMBConnection, bool):
        """Create a connection to a remote server using SMB protocol.

        Args:
            configuration: parameter configuration dictionary.

        Raises:
            MicrosoftFileShareEDM: If authentication fails
            or there are connection issues.

        Returns:
            tuple: A tuple containing the following items:
            - connection (type): The established connection object.
            - connection_result (bool): True if the connection was successful;
            False otherwise.
        """
        try:
            connection = SMBConnection(
                username=configuration.get("smb_username"),
                password=configuration.get("smb_password"),
                my_name="netskope_machine",
                remote_name=configuration.get("smb_machine_name"),
            )
            connection_result = connection.connect(
                ip=configuration.get("smb_server_ip"),
            )
            return connection, connection_result
        except NotReadyError as error:
            error_message = (
                "Authentication failed for the Windows server "
                f"'{configuration.get('smb_server_ip')}'."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {error_message}",
                resolution=(
                    "Ensure that the Server Hostname/IP, Username and "
                    "Password provided in the configuration is correct "
                    "and SMB server is reachable and accessible."
                ),
                details=traceback.format_exc(),
            )
            raise MicrosoftFileShareEDM(
                value=error, message=error_message
            ) from error
        except NotConnectedError as error:
            error_message = (
                "Couldn't connect with the Windows server "
                f"'{configuration.get('smb_server_ip')}'."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {error_message}",
                details=traceback.format_exc(),
            )
            raise MicrosoftFileShareEDM(
                value=error, message=error_message
            ) from error
        except TimeoutError as error:
            error_message = (
                "Connection request to the Windows server "
                f"'{configuration.get('smb_server_ip')}' got timed out."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {error_message}",
                resolution=(
                    "Ensure that the SMB Server is reachable and accessible."
                ),
                details=traceback.format_exc(),
            )
            raise MicrosoftFileShareEDM(
                value=error, message=error_message
            ) from error
        except Exception as error:
            error_message = (
                "Error occurred while connecting to the Windows server "
                f"'{configuration.get('smb_server_ip')}'. "
                "Verify that the Server Hostname/IP, Port, Username "
                "and Password are correct and the server is reachable."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {error_message}",
                resolution=(
                    "Ensure that the Server Hostname/IP, Username and "
                    "Password provided in the configuration are correct "
                    "and the SMB server is reachable and accessible."
                ),
                details=traceback.format_exc(),
            )
            raise MicrosoftFileShareEDM(
                value=error, message=error_message
            ) from error

    def verify_connection(self, configuration) -> ValidationResult:
        """Verify the connection with a Windows server using SMB protocol.

        Args:
            configuration: parameter configuration dictionary.

        Returns:
            ValidationResult: An object indicating the result of
            the validation.
            - success (bool): True if all parameters are valid,
            False otherwise.
            - message (str): A message describing the validation result.
        """
        server_ip = configuration.get("smb_server_ip")
        connection, connection_result = self.get_smb_connection_object(
            configuration
        )
        if connection_result:
            connection.close()
            message = (
                "Connection with the remote server "
                f"'{server_ip}' verified successfully."
            )
            self.logger.debug(
                message=f"{self.log_prefix}: {message}"
            )
            return ValidationResult(
                success=True,
                message=message,
            )

        err_msg = (
            "Couldn't verify the connection with the Windows server "
            f"'{server_ip}'."
        )
        self.logger.error(
            message=f"{self.log_prefix}: {err_msg}",
            resolution=(
                "Ensure that the Server Hostname/IP, Port, Username and "
                "Password are correct and the SMB server is reachable."
            ),
        )
        return ValidationResult(
            success=False,
            message=err_msg,
        )

    def pull_csv_file_records(
        self, configuration: dict, csv_file_path: str, record_count: int = 0
    ) -> None:
        """
        Pull CSV file records from a remote location using SMB protocol.

        And save them locally.

        Args:
            configuration: parameter configuration dictionary.
            csv_file_path (str): The local file path where the pulled records
            will be saved.
            record_count (int, optional): The number of records to pull from
            the CSV file
                (default is 0).

        Raises:
            MicrosoftFileShareEDM: If the operation to retrieve the
            CSV data fails.
                The exception includes details about the failure.
        """
        shared_directory_name = configuration.get("smb_shared_directory_name")
        remote_file_path = configuration.get("smb_filepath")
        if remote_file_path.startswith("\\"):
            remote_file_path = remote_file_path.strip("\\")
        remote_file_path = remote_file_path.replace("\\", "\\\\")

        smb_connection = None
        try:
            smb_connection, connection_result = self.get_smb_connection_object(
                configuration
            )
            if connection_result:
                with open(csv_file_path, "wb") as file_object:
                    if record_count:
                        smb_connection.retrieveFileFromOffset(
                            shared_directory_name,
                            remote_file_path,
                            file_obj=file_object,
                            offset=0,
                            max_length=record_count * 5 * 1024,
                        )
                    else:
                        smb_connection.retrieveFile(
                            shared_directory_name,
                            remote_file_path,
                            file_obj=file_object,
                        )
            else:
                raise Exception("Couldn't connect with the Windows server.")
        except OperationFailure as error:
            error_message = (
                "Data retrieval operation failed for "
                f"file: {remote_file_path}."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {error_message}",
                details=traceback.format_exc(),
            )
            raise MicrosoftFileShareEDM(
                value=error, message=error_message
            ) from error
        finally:
            if smb_connection:
                smb_connection.close()


class SFTPProtocolFileShareEDMPlugin:
    """Microsoft File Share EDM Plugin Class for SFTP protocol.

    This Class implements helper method to Pull & Validate the CSV file using
        SFTP protocol.
    """

    def __init__(self, logger, log_prefix) -> None:
        """Initialize method for SFTPProtocolFileShareEDMPlugin class."""
        self.logger = logger
        self.log_prefix = log_prefix

    def validate_configuration_parameters(
        self, configuration
    ) -> ValidationResult:
        """Validate the configuration parameters for an SFTP connection.

        Args:
            configuration: parameter configuration dictionary.

        Returns:
            ValidationResult: An object indicating the result of
            the validation.
            - success (bool): True if all parameters are valid,
            False otherwise.
            - message (str): A message describing the validation result.
        """
        server_ip = configuration.get("sftp_server_ip")
        if not server_ip:
            err_msg = (
                "Server Hostname/IP is a required "
                "configuration parameter."
            )
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Validation error occurred. {err_msg}"
                ),
                resolution=(
                    "Ensure that a valid Server Hostname/IP is provided."
                ),
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        if not isinstance(server_ip, str) or not server_ip.strip():
            err_msg = (
                "Server Hostname/IP should be a "
                "non-empty string value."
            )
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Validation error occurred. {err_msg}"
                ),
                resolution=(
                    "Ensure that the Server Hostname/IP is a "
                    "non-empty string value."
                ),
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )

        username = configuration.get("sftp_username")
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
            err_msg = "Username should be a non-empty string value."
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Validation error occurred. {err_msg}"
                ),
                resolution=(
                    "Ensure that the Username is a non-empty string value."
                ),
            )
            return ValidationResult(success=False, message=err_msg)

        password = configuration.get("sftp_password")
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
            err_msg = "Password should be a non-empty string value."
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Validation error occurred. {err_msg}"
                ),
                resolution=(
                    "Ensure that the Password is a non-empty string value."
                ),
            )
            return ValidationResult(success=False, message=err_msg)

        port = configuration.get("sftp_port")
        if port is None:
            err_msg = "Port number is a required configuration parameter."
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Validation error occurred. {err_msg}"
                ),
                resolution="Ensure that a valid Port number is provided.",
            )
            return ValidationResult(success=False, message=err_msg)
        if not isinstance(port, int) or not (0 < port < 65536):
            err_msg = (
                "Port number should be an integer value ranging "
                "between 1 to 65535."
            )
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Validation error occurred. {err_msg}"
                ),
                resolution=(
                    "Ensure that the Port number is an integer between "
                    "1 and 65535."
                ),
            )
            return ValidationResult(success=False, message=err_msg)

        filepath = configuration.get("sftp_filepath")
        if not filepath:
            err_msg = "File path is a required configuration parameter."
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Validation error occurred. {err_msg}"
                ),
                resolution="Ensure that a valid File path is provided.",
            )
            return ValidationResult(success=False, message=err_msg)
        if not isinstance(filepath, str) or not filepath.strip():
            err_msg = "File path should be a non-empty string value."
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Validation error occurred. {err_msg}"
                ),
                resolution=(
                    "Ensure that the File path is a non-empty string value."
                ),
            )
            return ValidationResult(success=False, message=err_msg)
        if not filepath.strip().lower().endswith((".csv", ".txt")):
            err_msg = "Only .csv and .txt file extensions are supported."
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Validation error occurred. {err_msg}"
                ),
                resolution=(
                    "Ensure that only supported .csv or .txt file extensions "
                    "are provided in the File path."
                ),
            )
            return ValidationResult(success=False, message=err_msg)

        # Validate delimiter
        delimiter = configuration.get("delimiter", ",")
        if not isinstance(delimiter, str) or not delimiter.strip():
            err_msg = "Delimiter should be a non-empty string value."
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Validation error occurred. {err_msg}"
                ),
                resolution=(
                    "Ensure that the Delimiter is a non-empty string value."
                ),
            )
            return ValidationResult(success=False, message=err_msg)
        if len(delimiter.strip()) > 1:
            err_msg = "Delimiter should be a single character."
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Validation error occurred. {err_msg}"
                ),
                resolution=(
                    "Ensure that a single character is "
                    "provided for Delimiter."
                ),
            )
            return ValidationResult(success=False, message=err_msg)

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
                resolution=(
                    "Ensure that the Remove Quotes is a valid "
                    "boolean value."
                ),
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )

        message = "Successfully validated configuration parameters."
        return ValidationResult(
            success=True,
            message=message,
        )

    def get_ssh_connection_object(self, configuration) -> paramiko.SSHClient:
        """
        Establish an SSH connection to a remote server using the configuration.

        Args:
            configuration: parameter configuration dictionary.

        Raises:
            MicrosoftFileShareEDM: If any errors occur during the
            SSH connection establishment,
                including AuthenticationException or SSHException.

        Returns:
            paramiko.SSHClient: An SSHClient object representing
            the SSH connection.
        """
        try:
            ssh_connection = paramiko.SSHClient()
            ssh_connection.set_missing_host_key_policy(
                paramiko.AutoAddPolicy()
            )
            ssh_connection.connect(
                hostname=configuration.get("sftp_server_ip"),
                username=configuration.get("sftp_username"),
                password=configuration.get("sftp_password"),
                port=configuration.get("sftp_port"),
            )
            return ssh_connection
        except AuthenticationException as error:
            error_message = (
                "Authentication failed while connecting to "
                f"the remote server '{configuration.get('sftp_server_ip')}'."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {error_message}",
                details=traceback.format_exc(),
            )
            raise MicrosoftFileShareEDM(
                value=error, message=error_message
            ) from error
        except SSHException as error:
            error_message = (
                "Error occurred while establishing SSH session with "
                f"the remote server '{configuration.get('sftp_server_ip')}'."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {error_message}",
                resolution=(
                    "Ensure that the Server Hostname/IP, Username and "
                    "Password provided in the configuration and SFTP server "
                    "is reachable and accessible."
                ),
                details=traceback.format_exc(),
            )
            raise MicrosoftFileShareEDM(
                value=error, message=error_message
            ) from error
        except Exception as error:
            error_message = (
                "Error occurred while connecting to the SFTP server "
                f"'{configuration.get('sftp_server_ip')}'. "
                "Verify that the Server Hostname/IP, Port, Username "
                "and Password are correct and the server is reachable."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {error_message}",
                resolution=(
                    "Ensure that the Server Hostname/IP, Port, Username and "
                    "Password provided in the configuration are correct "
                    "and the SFTP server is reachable and accessible."
                ),
                details=traceback.format_exc(),
            )
            raise MicrosoftFileShareEDM(
                value=error, message=error_message
            ) from error

    def verify_connection(self, configuration) -> ValidationResult:
        """Verify the connection with a Windows server using SFTP protocol.

        Args:
            configuration: parameter configuration dictionary.

        Returns:
            ValidationResult: An object indicating the result of
            the validation.
            - success (bool): True if all parameters are valid,
            False otherwise.
            - message (str): A message describing the validation result.
        """
        server_ip = configuration.get("sftp_server_ip")
        ssh_connection = self.get_ssh_connection_object(configuration)
        ssh_connection.close()

        message = (
            "Connection with the remote server "
            f"'{server_ip}' verified successfully."
        )
        self.logger.debug(
            message=f"{self.log_prefix}: {message}"
        )
        return ValidationResult(
            success=True,
            message=message,
        )

    def validate_remote_file(self, configuration: dict) -> None:
        """
        Validate that the file exists and is accessible on the remote server.

        Args:
            ssh_connection: SSH connection object.

        Raises:
            MicrosoftFileShareEDM: If the file does not exist,
            is not accessible, or is not a regular file.
        """
        ssh_connection = self.get_ssh_connection_object(configuration)
        remote_file_path = configuration.get("sftp_filepath")
        try:
            with ssh_connection.open_sftp() as sftp_session:
                try:
                    # Check if file exists
                    file_attributes = sftp_session.stat(remote_file_path)

                    # Check if it's a regular file
                    # (not a directory or special file)
                    import stat

                    if not stat.S_ISREG(file_attributes.st_mode):
                        error_message = (
                            f"Path '{remote_file_path}' exists but is not a "
                            "regular file on the remote server."
                        )
                        raise MicrosoftFileShareEDM(message=error_message)

                    # Check if file is readable by attempting to open it
                    try:
                        with sftp_session.file(
                            remote_file_path, "r"
                        ) as remote_file:
                            file_content = remote_file.readline()
                            if isinstance(file_content, bytes):
                                file_content = file_content.decode("utf-8")
                            # Convert the file content to a file-like object
                            # (string buffer)
                            file_like_object = io.StringIO(file_content)

                            # Use CSV reader to read the file
                            csv_reader = csv.reader(file_like_object)

                            # Get the first row as column names
                            try:
                                column_names = next(csv_reader)

                                if len(column_names) > 25:
                                    error_message = (
                                        "Maximum 25 columns allowed. "
                                        "Reduce columns from the source"
                                        " file and try again."
                                    )
                                    raise MicrosoftFileShareEDM(
                                        message=error_message
                                    )

                            except StopIteration:
                                error_message = (
                                    f"File '{remote_file_path}' is empty or "
                                    "not readable as CSV."
                                )
                                self.logger.error(
                                    f"{self.log_prefix}: {error_message}",
                                    details=traceback.format_exc(),
                                    resolution=(
                                        "Ensure that the file is not empty "
                                        "and can be read as a valid CSV."
                                    )
                                )
                                raise MicrosoftFileShareEDM(
                                    message=error_message
                                )

                    except UnicodeDecodeError as error:
                        error_message = (
                            "Only CSV file is supported. "
                            "Provide a valid CSV file."
                        )
                        raise MicrosoftFileShareEDM(
                            value=error, message=error_message
                        ) from error
                    except PermissionError as error:
                        error_message = (
                            f"File '{remote_file_path}' exists but is "
                            "not readable on the remote server."
                        )
                        self.logger.error(
                            f"{self.log_prefix}: {error_message}",
                            details=traceback.format_exc(),
                            resolution=(
                                "Ensure that the file is accessible and "
                                "can be read on the remote server."
                            ),
                        )
                        raise MicrosoftFileShareEDM(
                            value=error, message=error_message
                        ) from error

                except FileNotFoundError as error:
                    error_message = (
                        f"File '{remote_file_path}' does not exist on "
                        "the remote server."
                    )
                    self.logger.error(
                        f"{self.log_prefix}: {error_message}",
                        details=traceback.format_exc(),
                        resolution=(
                            "Ensure that the file is present on the remote "
                            "server and server is reachable and accessible."
                        )
                    )
                    raise MicrosoftFileShareEDM(
                        value=error, message=error_message
                    ) from error
                except MicrosoftFileShareEDM:
                    raise
                except Exception as error:
                    raise MicrosoftFileShareEDM(
                        value=error, message=str(error)
                    ) from error
        except MicrosoftFileShareEDM:
            raise
        except Exception as error:
            error_message = "Error occurred while validating the remote file."
            self.logger.error(
                message=f"{self.log_prefix}: {error_message}",
                resolution=(
                    "Ensure that the file is present on the remote server "
                    "and server is reachable and accessible."
                ),
                details=traceback.format_exc(),
            )
            raise MicrosoftFileShareEDM(
                value=error, message=error_message
            ) from error
        finally:
            ssh_connection.close()

    def pull_csv_file_records(
        self, configuration: dict, csv_file_path: str, record_count: int = 0
    ) -> None:
        """
        Pull CSV file records from a remote location using SFTP protocol.

        And save them locally.

        Args:
            configuration: parameter configuration dictionary.
            csv_file_path (str): The local file path where the pulled
            records will be saved.
            record_count (int, optional): The number of records to pull
            from the CSV file
                (default is 0).

        Raises:
            MicrosoftFileShareEDM: If the operation to retrieve the CSV
            data fails.
                The exception includes details about the failure.
        """
        ssh_connection = self.get_ssh_connection_object(configuration)
        remote_file_path = configuration.get("sftp_filepath")
        try:
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
        finally:
            ssh_connection.close()
