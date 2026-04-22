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
import shutil
import stat
import traceback

# Third-party libraries
from ..lib import smbclient
from ..lib.smbprotocol.exceptions import (
    SMBException,
    SMBResponseException,
)
from netskope.integrations.edm.plugin_base import ValidationResult
from netskope.integrations.edm.utils import CustomException as SMBFileShareEDM


class SMBProtocolFileShareEDMPlugin:
    """SMB File Share Plugin Class for SMB protocol."""

    def __init__(self, logger, log_prefix) -> None:
        """Initialize method for SMBProtocolFileShareEDMPlugin class."""
        self.logger = logger
        self.log_prefix = log_prefix

    @staticmethod
    def _get_server_name(configuration: dict) -> str:
        """Get server hostname/IP from configuration."""
        server = configuration.get("smb_server_ip", "")
        return server.strip() if isinstance(server, str) else ""

    def validate_configuration_parameters(
      self, configuration
    ) -> ValidationResult:
        """Validate the configuration parameters for an SMB connection."""
        # Validate server IP/hostname
        server_ip = configuration.get("smb_server_ip")
        if not server_ip:
            err_msg = (
                "Server Hostname/IP is a required configuration parameter."
            )
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Validation error occurred. {err_msg}"
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

        # Validate username
        username = configuration.get("smb_username")
        if not username:
            err_msg = "Username is a required configuration parameter."
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Validation error occurred. {err_msg}"
                ),
                resolution=(
                    "Ensure that a valid Username is provided."
                ),
            )
            return ValidationResult(success=False, message=err_msg)
        if not isinstance(username, str) or not username.strip():
            err_msg = "Username should be a non-empty string value."
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Validation error occurred. {err_msg}"
                ),
                resolution=(
                    "Ensure that the Username is a non-empty "
                    "string value."
                ),
            )
            return ValidationResult(success=False, message=err_msg)

        # Validate password
        password = configuration.get("smb_password")
        if not password:
            err_msg = "Password is a required configuration parameter."
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Validation error occurred. {err_msg}"
                ),
                resolution=(
                    "Ensure that a valid Password is provided."
                ),
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

        # Validate share name
        share_name = configuration.get("smb_shared_directory_name")
        if not share_name:
            err_msg = (
                "Share Directory Name is a required configuration parameter."
            )
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Validation error occurred. {err_msg}"
                ),
                resolution=(
                    "Ensure that a valid Share Directory Name is provided."
                ),
            )
            return ValidationResult(success=False, message=err_msg)
        if not isinstance(share_name, str) or not share_name.strip():
            err_msg = (
                "Share Directory Name should be a non-empty string value."
            )
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Validation error occurred. {err_msg}"
                ),
                resolution=(
                    "Ensure that the Share Directory Name is "
                    "a non-empty string value."
                ),
            )
            return ValidationResult(success=False, message=err_msg)

        # Validate filepath
        filepath = configuration.get("smb_filepath")
        if not filepath:
            err_msg = "CSV File Path is a required configuration parameter."
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Validation error occurred. {err_msg}"
                ),
                resolution="Ensure that a valid CSV File Path is provided.",
            )
            return ValidationResult(success=False, message=err_msg)
        if not isinstance(filepath, str) or not filepath.strip():
            err_msg = "CSV File Path should be a non-empty string value."
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Validation error occurred. {err_msg}"
                ),
                resolution=(
                    "Ensure that the CSV File Path is a non-empty "
                    "string value."
                ),
            )
            return ValidationResult(success=False, message=err_msg)
        # Enforce backslash-only relative path (no forward slashes)
        filepath_stripped = filepath.strip()
        if "/" in filepath_stripped:
            err_msg = "CSV File Path should use backslashes (\\) only."
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Validation error occurred. {err_msg}"
                ),
                resolution=(
                    "Ensure that all forward slashes (//) replaces with "
                    "backslashes (\\) in the CSV File Path."
                ),
            )
            return ValidationResult(success=False, message=err_msg)
        # Check for accidental UNC path paste
        if filepath_stripped.startswith(
         "\\\\"
         ) or filepath_stripped.startswith("//"):
            err_msg = (
                "CSV File Path should be relative to the share, "
                "not a full UNC path. "
                "From UNC '\\\\server\\share\\folder\\file.csv', "
                "enter only 'folder\\file.csv'."
            )
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Validation error occurred. {err_msg}"
                ),
                resolution=(
                    "Ensure that the path is relative to the share root, "
                    "not a full UNC path."
                ),
            )
            return ValidationResult(success=False, message=err_msg)
        # Validate file extension
        if not filepath_stripped.lower().endswith((".csv", ".txt")):
            err_msg = "Only .csv and .txt file extensions are supported."
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Validation error occurred. {err_msg}"
                ),
                resolution=(
                    "Ensure that only supported .csv and .txt file extensions "
                    "provided."
                ),
            )
            return ValidationResult(success=False, message=err_msg)

        # Validate port
        smb_port = configuration.get("smb_port")
        if smb_port is None:
            err_msg = "Port is a required configuration parameter."
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Validation error occurred. {err_msg}"
                ),
                resolution="Ensure that a valid Port is provided.",
            )
            return ValidationResult(success=False, message=err_msg)
        if not isinstance(smb_port, int) or not (0 < smb_port < 65536):
            err_msg = "Port should be an integer between 1 and 65535."
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Validation error occurred. {err_msg}"
                ),
                resolution=(
                    "Ensure that the Port is an integer between "
                    "1 and 65535."
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
            success=True, message=message
        )

    def verify_connection(self, configuration) -> ValidationResult:
        """Verify the connection with an SMB server using SMB protocol."""
        # Block 1: Attempt to register the session
        # (i.e., authenticate/establish connection)
        server = self._get_server_name(configuration)
        try:
            server = self._register_session(configuration)
        except Exception:
            error_message = (
                "Error occurred while establishing the SMB session. "
                "Verify that the Server Hostname/IP, Port, Username "
                "and Password are correct."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {error_message}",
                resolution=(
                    "Ensure that the Server Hostname/IP, Port, Username and "
                    "Password is correct in the configuration and SMB server "
                    "is reachable and accessible."
                ),
                details=traceback.format_exc(),
            )
            self._close_session()
            return ValidationResult(
                success=False,
                message=error_message,
            )

        # Block 2: Attempt to access the share/path (file/folder existence)
        try:
            directory_path = configuration.get("smb_shared_directory_name", "")
            file_path = configuration.get("smb_filepath", "")

            unc_path = self._build_unc_path(
                server,
                directory_path,
                file_path,
            )
            smbclient.stat(unc_path)

            message = (
                "Successfully verified connection with the server "
                f"'{server}'."
            )
            self.logger.debug(
                message=f"{self.log_prefix}: {message}"
            )
            result = ValidationResult(
                success=True,
                message=message,
            )
        except Exception:
            error_message = (
                "Error occurred while accessing the "
                f"specified file path '{unc_path}'."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {error_message}",
                resolution=(
                    "Ensure that the file or directory exists "
                    "and is accessible to the provided user account."
                ),
                details=traceback.format_exc(),
            )
            result = ValidationResult(
                success=False,
                message=error_message,
            )
        finally:
            self._close_session()

        return result

    def _build_unc_path(self, server: str, share: str, path: str) -> str:
        relative_path = (path or "").lstrip("\\/")
        if relative_path:
            return f"\\\\{server}\\{share}\\{relative_path}"
        return f"\\\\{server}\\{share}"

    def _register_session(self, configuration: dict) -> str:
        """Register an SMB session with the server."""
        server = self._get_server_name(configuration)
        username = configuration.get("smb_username")
        password = configuration.get("smb_password")
        port = configuration.get("smb_port", 445)

        smbclient.register_session(
            server,
            username=username,
            password=password,
            port=port,
        )
        return server

    @staticmethod
    def _close_session() -> None:
        smbclient.reset_connection_cache(fail_on_error=False)

    def validate_remote_file(self, configuration: dict) -> None:
        """
        Validate that the file exists and is accessible on the remote server.

        Args:
            configuration (dict): The configuration dictionary.
        """
        server = self._get_server_name(configuration)
        shared_directory_name = configuration.get(
         "smb_shared_directory_name", ""
        )
        remote_file_path = configuration.get("smb_filepath", "")
        delimiter = configuration.get("delimiter", ",")

        try:
            server = self._register_session(configuration)
            unc_path = self._build_unc_path(
                server, shared_directory_name, remote_file_path
            )
            # Check if file exists by attempting to retrieve file attributes
            try:
                stat_result = smbclient.stat(unc_path)

                # Check if it's a regular file (not a directory)
                if stat.S_ISDIR(stat_result.st_mode):
                    error_message = (
                        f"Path '{remote_file_path}' exists but is a directory,"
                        " not a file on the SMB server."
                    )
                    raise SMBFileShareEDM(message=error_message)

                # Check if file is readable by attempting to read its content
                try:
                    with smbclient.open_file(
                     unc_path, mode="rb"
                    ) as remote_file:
                        file_obj = io.BytesIO(remote_file.read(1024))
                    file_obj.seek(0)

                    # Try to read as CSV/TXT
                    csv_reader = csv.reader(
                        io.TextIOWrapper(file_obj, encoding="utf-8"),
                        delimiter=delimiter,
                    )

                    # Get the first row as column names
                    column_names = next(csv_reader, None)

                    if column_names is None:
                        error_message = f"File '{remote_file_path}' is empty "
                        "or not readable."
                        raise SMBFileShareEDM(message=error_message)

                    if len(column_names) > 25:
                        error_message = (
                            "Maximum 25 columns allowed. Reduce columns"
                            " from the source file and try again."
                        )
                        raise SMBFileShareEDM(message=error_message)
                except UnicodeDecodeError as error:
                    error_message = (
                        "Only CSV/TXT file is supported. "
                        "Provide a valid file."
                    )
                    raise SMBFileShareEDM(
                     value=error, message=str(error)
                    ) from error
                except Exception as error:
                    error_message = (
                        f"File '{remote_file_path}' exists but is not readable"
                        " or not a valid CSV/TXT file."
                    )
                    raise SMBFileShareEDM(
                     value=error, message=str(error)
                    ) from error
            except (SMBException, SMBResponseException) as error:
                error_message = (
                    f"File '{remote_file_path}' does not exist or is not "
                    "accessible on the SMB server."
                )
                self.logger.error(
                    message=f"{self.log_prefix}: {error_message}",
                    resolution=(
                        "Ensure that the file exists and "
                        "is accessible on the SMB server."
                    ),
                    details=traceback.format_exc(),
                )
                raise SMBFileShareEDM(
                  value=error, message=str(error)
                ) from error
        except Exception as error:
            error_message = (
               "Error occurred while validating remote file."
            )
            self.logger.error(
                message=(
                    f"{self.log_prefix}: {error_message}"
                ),
                details=traceback.format_exc(),
            )
            raise SMBFileShareEDM(value=error, message=str(error)) from error
        finally:
            self._close_session()

    def pull_csv_file_records(
        self, configuration: dict, csv_file_path: str, record_count: int = 0
    ) -> None:
        """
        Pull CSV/TXT file records from a remote location using SMB protocol.

        And save records locally.
        """
        shared_directory_name = configuration.get("smb_shared_directory_name")
        remote_file_path = configuration.get("smb_filepath")

        try:
            server = self._register_session(configuration)
            unc_path = self._build_unc_path(
                server, shared_directory_name, remote_file_path
            )
            with smbclient.open_file(unc_path, mode="rb") as remote_file:
                with open(csv_file_path, "wb") as file_object:
                    if record_count:
                        # Read line by line until we have enough records
                        # +1 to include header row
                        lines_to_read = record_count + 1
                        for _ in range(lines_to_read):
                            line = remote_file.readline()
                            if not line:
                                break
                            file_object.write(line)
                    else:
                        shutil.copyfileobj(remote_file, file_object)
        except (SMBException, SMBResponseException) as error:
            error_message = (
                f"Data retrieval operation failed for file: {remote_file_path}"
            )
            self.logger.error(
                message=f"{self.log_prefix}: {error_message}",
                details=traceback.format_exc(),
            )
            raise SMBFileShareEDM(value=error, message=str(error)) from error
        finally:
            self._close_session()
