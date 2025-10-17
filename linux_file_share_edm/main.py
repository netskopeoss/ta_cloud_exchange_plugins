"""Linux File Share EDM Plugin.

Linux File Share EDM Plugin is used to pull the CSV file from the Linux server
and it perform sanitization on the pulled data.
"""

# Built-in libraries
import csv
import os
import io
import shutil
import stat
import traceback

from copy import deepcopy
from typing import List

# Third-party libraries
from .lib import paramiko
from .lib.paramiko.ssh_exception import AuthenticationException, SSHException

# Local imports
from netskope.integrations.edm.models import Action, ActionWithoutParams
from netskope.integrations.edm.plugin_base import PluginBase, ValidationResult
from netskope.integrations.edm.utils import CONFIG_TEMPLATE, FILE_PATH
from netskope.integrations.edm.utils import CustomException as LinuxFileShareEDM
from netskope.integrations.edm.utils import run_sanitizer
from netskope.integrations.edm.utils.constants import EDM_HASH_CONFIG
from netskope.integrations.edm.utils.edm.hash_generator.edm_hash_generator import (
    generate_edm_hash,
)
from .utils.constants import (
    LINUX_FILE_SHARE_FIELDS,
    MODULE_NAME,
    PLUGIN_NAME,
    PLUGIN_VERSION,
    SAMPLE_DATA_RECORD_COUNT,
    SAMPLE_CSV_FILE_NAME,
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


class LinuxFileShareEDMPlugin(PluginBase):
    """Linux File Share Plugin Class.

    This plugin is used to pull the CSV file from the Linux server
    and perform sanitization on the pulled data.
    """

    def __init__(
        self,
        name,
        *args,
        **kwargs,
    ):
        """Linux File Share plugin initializer.

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
            manifest_json = LinuxFileShareEDMPlugin.metadata
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

    def strip_string_values(self, configuration: dict) -> None:
        """Strip leading and trailing whitespace from string values in the provided dictionary.

        Args:
            configuration (dict): A dictionary containing key-value pairs.
        """
        for parameter, value in configuration.items():
            if isinstance(value, str):
                configuration[parameter] = value.strip()

    def validate_configuration_parameters(self, configuration):
        """Validate configuration parameters.

        Args:
            configuration (dict): plugin configuration

        Returns:
            ValidationResult: validate result of configuration
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

        filepath = "filepath"
        if filepath in configuration:
            if (
                isinstance(configuration[filepath], str)
                and configuration[filepath].strip()
            ):
                pass
            else:
                return ValidationResult(
                    success=False,
                    message="File path should be a non-empty string value.",
                )
        else:
            return ValidationResult(
                success=False, message="File path is required field."
            )

        return ValidationResult(
            success=True, message="Basic validation completed successfully."
        )

    def get_ssh_connection_object(self, configuration) -> paramiko.SSHClient:
        """Establish an SSH connection to a remote server using the provided configuration.

        Args:
            configuration: parameter configuration dictionary.

        Raises:
            LinuxFileShareEDM: If any errors occur during the SSH connection establishment,
                including AuthenticationException or SSHException.

        Returns:
            paramiko.SSHClient: An SSHClient object representing the SSH connection.
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
                f"Authentication failed while connecting to "
                f"the Linux server'{configuration['server_ip']}'."
            )
            self.logger.error(
                message=f"{self.log_prefix} {error_message}",
                details=traceback.format_exc(),
            )
            raise LinuxFileShareEDM(value=error, message=error_message) from error
        except SSHException as error:
            error_message = (
                "Error occurred in establishing SSH session with "
                f"the Linux server'{configuration['server_ip']}'."
            )
            self.logger.error(
                message=f"{self.log_prefix} {error_message}",
                details=traceback.format_exc(),
            )
            raise LinuxFileShareEDM(value=error, message=str(error)) from error

    def verify_connection(self, configuration) -> ValidationResult:
        """Verify the connection with a Linux server using SFTP protocol.

        Args:
            configuration: parameter configuration dictionary.

        Returns:
            ValidationResult: An object indicating the result of the validation.
            - success (bool): True if all parameters are valid, False otherwise.
            - message (str): A message describing the validation result.
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

    def validate(self, configuration: dict) -> ValidationResult:
        """Validate a connection to a Linux server using the provided configuration.

        Args:
            configuration (dict): A dictionary containing configuration parameters.

        Returns:
            ValidationResult: An instance of ValidationResult with either success=True and a success
            message if the connection is verified, or success=False and an error message if the
            validation fails.
        """
        self.logger.debug(
            f"{self.log_prefix} Executing validate method for Linux File Share EDM plugin."
        )
        try:
            server_configuration = configuration.get("configuration", {})
            self.strip_string_values(server_configuration)

            validation_result = self.validate_configuration_parameters(
                server_configuration
            )

            if not validation_result.success:
                return validation_result

            verification_result = self.verify_connection(server_configuration)

            # Validate that the file exists and is accessible on the remote server
            try:
                input_path = f"{FILE_PATH}/{self.name}/{SAMPLE_CSV_FILE_NAME}"
                self.storage.update({"csv_path": input_path})
                self.pull_sample_data()
            except Exception as error:
                return ValidationResult(
                    success=False,
                    message=str(error),
                )

            self.logger.debug(
                (
                    f"{self.log_prefix} Successfully executed validate method for "
                    f"Linux File Share EDM plugin."
                )
            )

            return verification_result
        except Exception as error:
            error_message = (
                f"Error: '{error}' occurred while connecting to the Linux server."
            )
            self.logger.error(
                message=f"{self.log_prefix} {error_message}",
                details=traceback.format_exc(),
            )
            return ValidationResult(
                success=False,
                message=str(error),
            )

    @staticmethod
    def create_csv_directory(csv_file_path: str):
        """Create the directory for a CSV file.

        Args:
            csv_file_path (str): The file path to the CSV file.
        """
        if os.path.isfile(csv_file_path):
            os.remove(csv_file_path)
        else:
            directory_path = os.path.dirname(csv_file_path)
            if not os.path.exists(directory_path):
                os.makedirs(directory_path)

    def validate_remote_file(
        self, ssh_connection: paramiko.SSHClient, configuration: dict
    ) -> None:
        """Validate that the file exists and is accessible on the remote server.

        Args:
            ssh_connection: SSH connection object.
            configuration: parameter configuration dictionary.

        Raises:
            LinuxFileShareEDM: If the file does not exist, is not accessible, or is not a regular file.
        """
        remote_file_path = configuration["filepath"]
        try:
            with ssh_connection.open_sftp() as sftp_session:
                try:
                    # Check if file exists
                    file_attributes = sftp_session.stat(remote_file_path)

                    # Check if it's a regular file (not a directory or special file)
                    if not stat.S_ISREG(file_attributes.st_mode):
                        error_message = f"Path '{remote_file_path}' exists but is not a regular file on the remote server."
                        raise LinuxFileShareEDM(message=error_message)

                    # Check if file is readable by attempting to open it
                    try:
                        with sftp_session.file(remote_file_path, "r") as remote_file:
                            file_content = remote_file.readline()
                            if isinstance(file_content, bytes):
                                file_content = file_content.decode("utf-8")
                            # Convert the file content to a file-like object (string buffer)
                            file_like_object = io.StringIO(
                                file_content
                            )  # Decode from bytes to string

                            # Use CSV reader to read the file
                            csv_reader = csv.reader(file_like_object)

                            # Get the first row as column names
                            column_names = next(csv_reader)

                            if len(column_names) > 25:
                                error_message = (
                                    "Maximum 25 columns allowed. Please reduce "
                                    "columns from the source file and try again."
                                )
                                raise LinuxFileShareEDM(message=error_message)
                            return column_names
                    except UnicodeDecodeError as error:
                        error_message = (
                            "Only CSV file is supported. Please provide a valid CSV file."
                        )
                        raise LinuxFileShareEDM(
                            value=error, message=error_message
                        ) from error
                    except PermissionError as error:
                        error_message = f"File '{remote_file_path}' exists but is not readable on the remote server."
                        raise LinuxFileShareEDM(
                            value=error, message=error_message
                        ) from error

                except LinuxFileShareEDM:
                    raise
                except FileNotFoundError as error:
                    error_message = f"File '{remote_file_path}' does not exist on the remote server."
                    raise LinuxFileShareEDM(
                        value=error, message=error_message
                    ) from error
                except Exception as error:
                    raise LinuxFileShareEDM(
                        value=error, message=str(error)
                    ) from error
        except Exception as error:
            error_message = (
                f"Error validating remote file: {str(error)}"
            )
            self.logger.error(
                message=f"{self.log_prefix} {error_message}",
                details=traceback.format_exc(),
            )
            raise LinuxFileShareEDM(value=error, message=error_message) from error

    def pull_csv_file_records(
        self, configuration: dict, csv_file_path: str, record_count: int = 0
    ) -> None:
        """Pull CSV file records from a remote location and save them locally.

        Args:
            configuration: parameter configuration dictionary.
            csv_file_path (str): The local file path where the pulled records will be saved.
            record_count (int, optional): The number of records to pull from the CSV file
                (default is 0).

        Raises:
            LinuxFileShareEDM: If the operation to retrieve the CSV data fails.
                The exception includes details about the failure.
        """
        ssh_connection = self.get_ssh_connection_object(configuration)
        # Validate that the file exists and is accessible on the remote server
        self.validate_remote_file(ssh_connection, configuration)
        remote_file_path = configuration["filepath"]
        with ssh_connection.open_sftp() as sftp_session:
            if record_count:
                file_content = []
                with sftp_session.file(remote_file_path, "r") as remote_file:
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
        ssh_connection.close()

    def validate_csv_file_records(
        self, csv_file_path: str, record_count: int = 0
    ) -> dict:
        """Validate the content of a CSV file.

        Args:
            csv_file_path (str): The file path to the CSV file to be validated.
            record_count (int, optional): The maximum number of records to validate. If set
                to a positive value, only the first 'record_count' records will be validated.
                If set to 0 (default), all records in the file will be validated.

        Raises:
            LinuxFileShareEDM: If validation fails due to incorrect data or missing data.

        Returns:
            dict: A dictionary containing the header columns of the CSV file as a list.
        """
        row_count = 0
        header = None
        sample_data = []

        try:
            with open(csv_file_path, "r", encoding="UTF-8") as csv_file_object:
                # Create a CSV reader object to iterate through the CSV file.
                csv_reader = csv.reader(csv_file_object)

                for row in csv_reader:
                    row_count += 1

                    # Check if 'record_count' is specified and if the row count exceeds the limit.
                    if record_count and row_count > record_count + 1:
                        break

                    if record_count:
                        sample_data.append(row)

                    # Handle the first row as the header row.
                    if row_count == 1:
                        header = row
                        if any(cell.strip() == "" for cell in header):
                            raise ValueError(
                                "Column name in provided file should not have an empty value."
                            )
                        continue

                    # Check if the current row has the same number of columns as the header row.
                    if len(row) != len(header):
                        raise ValueError(
                            f"Row '{row_count}' does not contain the correct number of columns."
                        )

                # Check if at least 1 record is present in the CSV file.
                if row_count < 2:
                    raise ValueError(
                        (
                            "At least 1 record must be present in the CSV file "
                            "in addition to header row."
                        )
                    )

            # Keep only the records which has been validated
            if record_count:
                with open(
                    csv_file_path, "w", encoding="UTF-8", newline=""
                ) as csv_file_object:
                    writer = csv.writer(csv_file_object)
                    writer.writerows(sample_data)

            return {"columns": header}
        except ValueError as error:
            self.logger.error(
                message=f"{self.log_prefix} {str(error)} Plugin Configuration: '{self.name}'.",
                details=traceback.format_exc(),
            )
            raise LinuxFileShareEDM(value=error, message=str(error)) from error

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
        if step == "configuration":
            result = self.validate(self.configuration)
        elif step == "sanity_inputs":
            result = ValidationResult(
                success=True,
                message="Step validated successfully.",
            )
            input_path = f"{FILE_PATH}/{self.name}/{SAMPLE_CSV_FILE_NAME}"
            output_path = f"{FILE_PATH}/{self.name}"
            try:
                self.storage.update(
                    {
                        "csv_path": input_path,
                        "sanitization_data_path": output_path,
                    }
                )
                self.sanitize(file_name="sample", sample_data=True)
            except Exception:
                error_message = (
                    f"Error occurred while sanitizing the sample data for configuration '{self.name}'."
                )
                self.logger.error(
                    message=f"{self.log_prefix} {error_message}",
                    details=traceback.format_exc(),
                )
                result = ValidationResult(
                    success=False,
                    message=error_message,
                )
        elif step == "sanity_results":
            result = ValidationResult(
                success=True,
                message="Step validated successfully.",
            )
        return result

    def pull_sample_data(self):
        """Pull sample data from a remote server and validate it.

        Raises:
            LinuxFileShareEDM: If any error occurs during the sample data retrieval
                or validation.

        Returns:
            dict: contains csv validate result
        """
        self.logger.debug(
            f"{self.log_prefix} Executing pull sample data method for configuration '{self.name}'."
        )
        try:
            server_configuration = self.configuration.get("configuration", {})
            self.strip_string_values(server_configuration)

            csv_file_path = self.storage["csv_path"].strip()
            self.create_csv_directory(csv_file_path)

            self.pull_csv_file_records(
                server_configuration, csv_file_path, SAMPLE_DATA_RECORD_COUNT
            )
        except Exception as error:
            error_message = f"Error: '{error}' occurred while pulling the sample data for configuration '{self.name}'."
            self.logger.error(
                message=f"{self.log_prefix} {error_message}",
                details=traceback.format_exc(),
            )
            raise LinuxFileShareEDM(value=error, message=str(error)) from error

        try:
            columns_data = self.validate_csv_file_records(
                csv_file_path, SAMPLE_DATA_RECORD_COUNT
            )
            columns = columns_data.get("columns", [])
            if len(columns) > 25:
                error_message = (
                    "Maximum 25 columns allowed. Please reduce "
                    "columns from the source file and try again."
                )
                self.logger.error(
                    message=f"{self.log_prefix} {error_message}",
                )
                raise LinuxFileShareEDM(
                    message=f"{self.log_prefix} {error_message}",
                )
            self.logger.debug(
                (
                    f"{self.log_prefix} Successfully executed pull sample data method for "
                    f"configuration '{self.name}'."
                )
            )
            return columns_data
        except Exception as error:
            error_message = (
                f"Error: '{error}' occurred while validating the sample data. "
                f"Plugin Configuration: '{self.name}'."
            )
            self.logger.error(
                message=f"{self.log_prefix} {error_message}",
                details=traceback.format_exc(),
            )
            raise LinuxFileShareEDM(value=error, message=str(error)) from error

    def pull(self):
        """Pull CSV from a remote location of Linux machine, sanitize it and save it locally.

        Raises:
            LinuxFileShareEDM: If any error occurs during the data retrieval or validation.
        """
        try:
            server_configuration = self.configuration.get("configuration", {})
            is_unsanitized_data = self.configuration.get("sanity_results", {}).get(
                "is_unsanitized_data", True
            )
            self.strip_string_values(server_configuration)

            csv_file_name = f"{self.name}_data"
            csv_file_name = (
                csv_file_name.replace(" ", "_").replace("\t", "_").replace("-", "_")
            )
            self.storage["csv_path"] = f"{FILE_PATH}/{self.name}/{csv_file_name}.csv"
            self.storage["file_name"] = f"{csv_file_name}.csv"
            self.storage["sanitization_data_path"] = f"{FILE_PATH}/{self.name}"
            csv_file_path = self.storage["csv_path"]
            self.create_csv_directory(csv_file_path)

            self.logger.info(
                (
                    f"{self.log_prefix} Fetching the CSV file from the Linux server for "
                    f"configuration '{self.name}'."
                )
            )
            self.pull_csv_file_records(server_configuration, csv_file_path)
            self.logger.info(
                (
                    (
                        f"{self.log_prefix} The CSV file fetched successfully from "
                        f"the Linux server for configuration '{self.name}'."
                    )
                )
            )
        except Exception as error:
            error_message = f"Error: '{error}' occurred while pulling the data for configuration '{self.name}'."
            self.logger.error(
                message=f"{self.log_prefix} {error_message}",
                details=traceback.format_exc(),
            )
            raise LinuxFileShareEDM(value=error, message=str(error)) from error

        try:
            self.logger.info(
                f"{self.log_prefix} Validating the CSV file for configuration '{self.name}'."
            )
            self.validate_csv_file_records(csv_file_path)
            self.logger.info(
                (
                    f"{self.log_prefix} The CSV file validated successfully for "
                    f"configuration '{self.name}'."
                )
            )
        except Exception as error:
            error_message = (
                f"Error: '{error}' occurred while validating the data. "
                f"Plugin Configuration: '{self.name}'."
            )
            self.logger.error(
                message=f"{self.log_prefix} {error_message}",
                details=traceback.format_exc(),
            )
            raise LinuxFileShareEDM(value=error, message=str(error))
        if is_unsanitized_data:
            if os.path.exists(csv_file_path):
                os.rename(
                    csv_file_path, f"{FILE_PATH}/{self.name}/{csv_file_name}.good"
                )
                self.logger.debug(
                    f"{self.log_prefix} Do not perform any data sanitization."
                )
            else:
                error_message = f"Data file doesn't exist at {csv_file_path}."
                self.logger.error(message=f"{self.log_prefix} {error_message}")
                raise LinuxFileShareEDM(error_message)
        else:
            self.logger.info(
                f"{self.log_prefix} Sanitizing the CSV file for configuration '{self.name}'."
            )
            self.sanitize(csv_file_name)
            self.logger.info(
                (
                    f"{self.log_prefix} The CSV file sanitized successfully for "
                    f"configuration '{self.name}'."
                )
            )
        self.generate_csv_edm_hash(csv_file=csv_file_name)
        return {
            "message": "Remote CSV File pulled and "
            + "EDM Hash generated successfully."
        }

    def push(self):
        """Plugin is not push supported.

        Raises:
            NotImplementedError: If the method is not implemented.
        """
        raise NotImplementedError()

    def sanitize(self, file_name: str = "", sample_data: bool = False) -> None:
        """Sanitize the data from a CSV file and store good & bad files.

        Args:
            file_name (str): The name of the output file.

        Raises:
            LinuxFileShareEDM: If an error occurs during the sanitization process.
        """
        try:
            sanitization_input = self.configuration.get("sanity_inputs", {}).get(
                "sanitization_input", {}
            )

            exclude_stopwords = self.configuration.get("sanity_inputs", {}).get(
                "exclude_stopwords", False
            )

            for field_input in sanitization_input:
                self.strip_string_values(field_input)

            # Prepare EDM input configuration based on sanitization input.
            edm_input_configuration = deepcopy(CONFIG_TEMPLATE)
            edm_input_configuration.update(
                {
                    "names": [
                        field_input.get("field", "")
                        for field_input in sanitization_input
                        if field_input.get("nameColumn", False)
                    ]
                }
            )
            if "stopwords" in edm_input_configuration and not exclude_stopwords:
                del edm_input_configuration["stopwords"]

            csv_file_path = self.storage["csv_path"]
            sanitization_output_path = self.storage["sanitization_data_path"]
            sanitization_output_file = f"{sanitization_output_path}/{file_name}"

            # Check if the CSV data file exists
            if not os.path.isfile(csv_file_path):
                error_message = (
                    f"Data file doesn't exist at {csv_file_path} for sanitization."
                )
                self.logger.error(message=f"{self.log_prefix} {error_message}")
                raise LinuxFileShareEDM(error_message)

            for file_extension in ["good", "bad"]:
                file_path = f"{sanitization_output_file}.{file_extension}"
                if os.path.isfile(file_path):
                    os.remove(file_path)

            # Create the output directory if it doesn't exist.
            if not os.path.exists(sanitization_output_path):
                os.makedirs(sanitization_output_path)

            run_sanitizer(
                csv_file_path, sanitization_output_file, edm_input_configuration
            )
            if not sample_data:
                if os.path.exists(csv_file_path):
                    os.remove(csv_file_path)
                if os.path.exists(f"{sanitization_output_file}.bad"):
                    os.remove(f"{sanitization_output_file}.bad")
        except Exception as error:
            error_message = (
                f"Error: {error} occurred while sanitizing the data at {csv_file_path}"
            )
            self.logger.error(
                message=f"{self.log_prefix} {error_message}",
                details=traceback.format_exc(),
            )
            raise LinuxFileShareEDM(value=error, message=str(error)) from error

    def get_actions(self) -> List[ActionWithoutParams]:
        """Get list of supported actions.

        Returns:
            List[ActionWithoutParams]: List of actions.
        """
        return []

    def get_action_fields(self, action: Action) -> List:
        """Get list of fields to be rendered in UI.

        Args:
            action (Action): Action object

        Returns:
            List: List of fields to be rendered.
        """
        return []

    def validate_action(self, action: Action) -> ValidationResult:
        """Validate action parameters.

        Args:
            action (Action): Action object.

        Returns:
            ValidationResult: Validation result object.
        """
        return ValidationResult(success=True, message="Validation successful.")

    def create_directory(self, dir_path):
        """Create a directory at the specified path, \
            including all necessary parent directories.

        Args:
            dir_path (string): The path of the directory to be created.

        Raises:
            Error: If there's an issue creating the directory.

        """
        try:
            if not os.path.exists(dir_path):
                os.makedirs(dir_path)
        except Exception as error:
            self.logger.error(
                message=f"{self.log_prefix} Error occurred while creating nested "
                + "directories to store sanitized data or EDM hashes.",
                details=traceback.format_exc(),
            )
            raise error

    def get_field_indices(self, sanity_inputs):
        """Get the indices of fields based on normalization and sensitivity.

        Args:
            sanity_inputs (dict): Sanitization inputs with field info.

        Returns:
            string: Three strings:
                 - case sensitive indices
                 - case insensitive indices
                 - number indices
        """
        try:
            string_case_sensitive_indices = []
            string_case_insensitive_indices = []
            number_indices = []
            string_indices = []

            for index, field_info in enumerate(
                sanity_inputs.get("sanitization_input", {})
            ):
                if field_info.get("normalization", "") == "number":
                    number_indices.append(index)
                elif field_info.get("normalization", "") == "string":
                    string_indices.append(index)

                if field_info.get("caseSensitivity", "") == "sensitive":
                    string_case_sensitive_indices.append(index)
                elif field_info.get("caseSensitivity", "") == "insensitive":
                    string_case_insensitive_indices.append(index)
            string_cs = ",".join(map(str, string_case_sensitive_indices))
            string_cins = ",".join(map(str, string_case_insensitive_indices))
            num_norm = ",".join(map(str, number_indices))
            str_norm = ",".join(map(str, string_indices))

            return string_cs, string_cins, num_norm, str_norm
        except Exception as error:
            raise LinuxFileShareEDM(
                f"Error occurred while getting "
                "indices from sanity input fields based on normalization and sensitivity."
            ) from error

    def remove_files(self, temp_edm_hash_dir_path, input_file_dir, output_path):
        """Remove csv files and temp EDM hashes after EDM hash generation.

        Args:
            temp_edm_hash_dir_path (str): Temporary EDM Hash Path
            input_file_dir (str): Input CSV File Path
            output_path (str): Path where all CSV files are located

        Raises:
            error: If there's an issue removing files.
        """
        try:
            if os.path.exists(temp_edm_hash_dir_path):
                shutil.rmtree(temp_edm_hash_dir_path)
            if os.path.exists(input_file_dir):
                shutil.rmtree(input_file_dir)
            for file in os.listdir(output_path):
                file_path = os.path.join(output_path, file)
                if os.path.isfile(file_path):
                    os.remove(file_path)
        except Exception as error:
            self.logger.error(
                message=f"{self.log_prefix} Error occurred while removing"
                + "csv files.",
                details=traceback.format_exc(),
            )
            raise error

    def generate_csv_edm_hash(self, csv_file):
        """Generate EDM Hashes from sanitized data.

        Raises:
            LinuxFileShareEDM: If an error occures while
            generating EDM hashes.
        """
        try:
            self.logger.info(
                message=f"{self.log_prefix} Generating EDM Hash "
                + f"for configuration '{self._name}' of "
                + "Linux File Share EDM Plugin."
            )
            output_path = os.path.dirname(self.storage["csv_path"])

            good_csv_path = f"{output_path}/{csv_file}.good"
            input_file_dir = f"{output_path}/input"
            self.create_directory(dir_path=input_file_dir)
            input_csv_file = f"{input_file_dir}/{csv_file}.csv"
            shutil.move(good_csv_path, input_csv_file)

            if not os.path.isfile(input_csv_file):
                self.logger.error(
                    message=f"{self.log_prefix} Error occurred while generating"
                    " EDM Hash. '.csv' file does not exist for "
                    + f"configuration '{self._name}' of "
                    + "Linux File Share EDM Plugin.",
                )
                raise LinuxFileShareEDM(
                    message="Error occurred while generating "
                    "EDM Hash of Linux File Share EDM Plugin."
                )

            temp_edm_hash_dir_path = f"{output_path}/temp_edm_hashes"
            self.create_directory(dir_path=temp_edm_hash_dir_path)
            output_dir_path = temp_edm_hash_dir_path

            sanity_inputs = self.configuration.get("sanity_inputs", {})
            dict_cs, dict_cins, norm_num, norm_str = self.get_field_indices(
                sanity_inputs
            )

            edm_hash_config = deepcopy(EDM_HASH_CONFIG)
            edm_hash_config.update(
                {
                    "dict_cs": dict_cs,
                    "dict_cins": dict_cins,
                    "norm_num": norm_num,
                    "norm_str": norm_str,
                    "input_csv": input_csv_file,
                    "output_dir": output_dir_path,
                }
            )

            status, metadata_file = generate_edm_hash(
                conf_name=self._name, edm_conf=edm_hash_config
            )
            if os.path.exists(input_file_dir):
                shutil.rmtree(input_file_dir)
            if status is True:
                edm_hash_dir_path = f"{output_path}/edm_hashes"
                if os.path.exists(edm_hash_dir_path):
                    shutil.rmtree(edm_hash_dir_path)
                self.create_directory(dir_path=edm_hash_dir_path)
                temp_metadata_file = f"{output_path}/{metadata_file}"
                if os.path.exists(temp_metadata_file):
                    shutil.move(temp_metadata_file, f"{edm_hash_dir_path}/")
                self.storage["edm_hash_folder"] = edm_hash_dir_path
                self.storage["edm_hash_available"] = True
                metadata_file = metadata_file.replace(".tgz", ".json")
                temp_metadata_file = f"{temp_edm_hash_dir_path}/{metadata_file}"
                edm_hash_cfg = f"{edm_hash_dir_path}/{metadata_file}"
                if os.path.exists(temp_metadata_file):
                    shutil.move(temp_metadata_file, f"{edm_hash_dir_path}/")
                if os.path.exists(edm_hash_cfg):
                    self.storage["edm_hashes_cfg"] = edm_hash_cfg
                self.remove_files(temp_edm_hash_dir_path, input_file_dir, output_path)

                self.logger.info(
                    message=f"{self.log_prefix} EDM Hash generated successfully"
                    + f" for configuration '{self._name}' of "
                    + "Linux File Share EDM Plugin."
                )
            else:
                self.storage["edm_hash_available"] = False
                raise LinuxFileShareEDM(
                    message=f"{self.log_prefix} Error occurred while generating EDM Hash "
                    + f"for configuration '{self._name}' of "
                    + "Linux File Share EDM Plugin."
                )
        except Exception as error:
            if self.storage.get("csv_path"):
                output_path = os.path.dirname(self.storage["csv_path"])
                input_file_dir = f"{output_path}/input"
                temp_edm_hash_dir_path = f"{output_path}/temp_edm_hashes"
                self.remove_files(
                    temp_edm_hash_dir_path=temp_edm_hash_dir_path,
                    input_file_dir=input_file_dir,
                    output_path=output_path,
                )
            self.logger.error(
                message=f"{self.log_prefix} Error occurred while generating "
                "EDM Hash for Linux File Share EDM data.",
                details=traceback.format_exc(),
            )
            raise LinuxFileShareEDM(
                value=error,
                message="Error occurred while generating "
                "EDM Hash of Linux File Share EDM data.",
            ) from error

    def get_fields(self, name: str, configuration: dict):
        """Get fields configuration based on the specified protocol.

        Args:
            name (str): The name of the field configuration to retrieve
            configuration (dict): Configuration parameters dictionary.

        Raises:
            ValueError: If the specified protocol in the configuration is not supported.
            NotImplementedError: If a field configuration with the specified name
                is not implemented.

        Returns:
            list: List of configuration parameters.
        """
        if name in LINUX_FILE_SHARE_FIELDS:
            fields = LINUX_FILE_SHARE_FIELDS[name]
            if name == "sanity_inputs":
                for field in fields:
                    if field["type"] == "sanitization_input":
                        input_path = f"{FILE_PATH}/{self.name}/{SAMPLE_CSV_FILE_NAME}"
                        self.storage.update({"csv_path": input_path})
                        field["default"] = self.pull_sample_data()
            elif name == "sanity_results":
                for field in fields:
                    if field["type"] == "sanitization_preview":
                        field["default"] = {
                            "sanitizationStatus": True,
                            "message": "Sanitization Done Successfully",
                        }
            return fields
        raise NotImplementedError()
