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

SMB File Share Plugin pulls a CSV/TXT file from an SMB server and performs
sanitization on the pulled data.
"""

# Built-in libraries
from copy import deepcopy
import csv
import os
import shutil
import traceback
from typing import List

# Third-party libraries
from .lib.smbprotocol.exceptions import SMBException, SMBResponseException

# Local imports
from .utils.constants import (
    SMB_FILE_SHARE_EDM_FIELDS,
    SAMPLE_DATA_RECORD_COUNT,
    PLUGIN_NAME,
    PLUGIN_VERSION,
    MODULE_NAME,
    SAMPLE_CSV_FILE_NAME,
)
from .utils.helper import SMBProtocolFileShareEDMPlugin
from netskope.integrations.edm.plugin_base import PluginBase, ValidationResult
from netskope.integrations.edm.utils import CONFIG_TEMPLATE, FILE_PATH
from netskope.integrations.edm.utils import CustomException as SMBFileShareEDM
from netskope.integrations.edm.utils import run_sanitizer
from netskope.integrations.edm.models import ActionWithoutParams, Action
from netskope.integrations.edm.utils.constants import EDM_HASH_CONFIG
from netskope.integrations.edm.utils.edm.hash_generator.edm_hash_generator import (  # noqa: E501
    generate_edm_hash,
)


class SMBFileShareEDMPlugin(PluginBase):
    """SMB File Share Plugin Class.

    This plugin pulls the CSV/TXT file from an SMB server and performs
    sanitization on the pulled data.
    """

    def __init__(
        self,
        name,
        *args,
        **kwargs,
    ):
        """SMB File Share plugin initializer.

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
        self.protocol_object = SMBProtocolFileShareEDMPlugin(
            self.logger, self.log_prefix
        )

    def _get_plugin_info(self) -> tuple:
        """Get plugin name and version from manifest.

        Returns:
            tuple: tuple of plugin's name and version fetched from manifest.
        """
        try:
            manifest_json = SMBFileShareEDMPlugin.metadata
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

    def validate_configuration_parameters(self):
        """Validate configuration parameters.

        Raises:
            NotImplementedError: This method must be implemented in
            concrete subclasses.
        """
        raise NotImplementedError

    def verify_connection(self):
        """Verify the connection to a remote server.

        Raises:
            NotImplementedError: This method must be implemented in
            concrete subclasses.
        """
        raise NotImplementedError

    def get_fields(self, name: str, configuration: dict):
        """Get fields configuration based on the specified protocol.

        Args:
            name (str): The name of the field configuration to retrieve
            configuration (dict): Configuration parameters dictionary.

        Raises:
            ValueError: If the specified protocol in the configuration
            is not supported.
            NotImplementedError: If a field configuration with the
                specified name is not implemented.

        Returns:
            str: List of configuration parameters.
        """
        if name in SMB_FILE_SHARE_EDM_FIELDS:
            fields = SMB_FILE_SHARE_EDM_FIELDS[name]
            if name == "sanity_inputs":
                for field in fields:
                    if field["type"] == "sanitization_input":
                        input_path = (
                            f"{FILE_PATH}/{self.name}/{SAMPLE_CSV_FILE_NAME}"
                        )
                        self.storage.update({"csv_path": input_path})
                        # Get delimiter from configuration
                        delimiter = self.get_delimiter()
                        # Only get column names without
                        # validation for field config
                        columns_data = self._get_column_names_only(
                            input_path, delimiter
                        )
                        field["default"] = columns_data
            elif name == "sanity_results":
                for field in fields:
                    if field["type"] == "sanitization_preview":
                        field["default"] = {
                            "sanitizationStatus": True,
                            "message": "Sanitization Done Successfully",
                        }
            return fields
        raise NotImplementedError()

    def validate(self, configuration: dict) -> ValidationResult:
        """
        Validate a connection to an SMB server using the configuration.

        Args:
            configuration (dict): A dictionary containing
            configuration parameters.

        Returns:
            ValidationResult: An instance of ValidationResult with either
            success=True and a success
            message if the connection is verified, or success=False and an
            error message if the
            validation fails.
        """
        self.logger.debug(
            f"{self.log_prefix}: Validating configuration parameters."
        )
        try:
            server_configuration = configuration.get("configuration", {})
            self.strip_string_values(server_configuration)

            validation_result = (
                self.protocol_object.validate_configuration_parameters(
                    server_configuration
                )
            )
            if not validation_result.success:
                return validation_result

            verification_result = self.protocol_object.verify_connection(
                server_configuration
            )
            if not verification_result.success:
                return verification_result

            # Validate that the file exists and is
            # accessible on the remote server
            try:
                input_path = f"{FILE_PATH}/{self.name}/{SAMPLE_CSV_FILE_NAME}"
                self.storage.update({"csv_path": input_path})
                self.pull_sample_data()
                self.logger.debug(
                    f"{self.log_prefix}: Successfully validated "
                    "configuration parameters."
                )
            except SMBFileShareEDM as error:
                return ValidationResult(success=False, message=str(error))
            except Exception as error:
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: An unexcepted error occurred "
                        "while verifying that the file exists and is "
                        "accessible on the SMB server"
                    ),
                    resolution=(
                        "Ensure that file exists and is accessible on "
                        "the SMB server"
                    ),
                )
                return ValidationResult(success=False, message=str(error))

            self.logger.debug(
                (
                    f"{self.log_prefix}: Successfully validated that file "
                    "exists and accessible on the SMB server."
                )
            )

            return verification_result
        except Exception as error:
            error_message = (
                "Error occurred while connecting to "
                "the SMB server."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {error_message}",
                resolution=(
                    "Ensure that Server Hostname/IP, Port, Username "
                    "and Password is correct and server is reachable."
                ),
                details=traceback.format_exc(),
            )
            return ValidationResult(
                success=False,
                message=str(error),
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
            message="Validation failed.",
        )
        if step == "configuration":
            result = self.validate(self.configuration)
        elif step == "sanity_inputs":
            message = (
                "Successfully validated Hash Generation and "
                "Sanitization Parameters."
            )
            self.logger.debug(
                f"{self.log_prefix}: {message}"
            )
            result = ValidationResult(
                success=True,
                message=message,
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
                    "Error occurred while sanitizing the sample data."
                )
                self.logger.error(
                    message=f"{self.log_prefix}: {error_message}",
                    details=traceback.format_exc(),
                )
                result = ValidationResult(
                    success=False,
                    message=error_message,
                )
        elif step == "sanity_results":
            message = "Successfully validated Preview Sanitization Results."
            self.logger.debug(
                f"{self.log_prefix}: {message}"
            )
            result = ValidationResult(
                success=True,
                message=message,
            )
        return result

    def pull_sample_data(self):
        """Pull sample data from a remote server and validate it.

        Raises:
            SMBFileShareEDM: If any error occurs during the sample data
            retrieval or validation.
        """
        self.logger.debug(
            f"{self.log_prefix}: Pulling sample data."
        )
        try:
            server_configuration = self.configuration.get("configuration", {})
            self.strip_string_values(server_configuration)

            csv_file_path = (self.storage.get("csv_path") or "").strip()
            if not csv_file_path:
                raise SMBFileShareEDM(
                    message="CSV path is not configured in storage."
                )
            self.create_csv_directory(csv_file_path)

            self.protocol_object.validate_remote_file(server_configuration)
            self.protocol_object.pull_csv_file_records(
                server_configuration, csv_file_path, SAMPLE_DATA_RECORD_COUNT
            )
        except (SMBException, SMBResponseException) as error:
            error_message = (
                "Error occured while connecting to SMB server or accessing"
                " the remote file. Verify the server configuration "
                "and network connectivity."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {error_message}"
            )
            raise SMBFileShareEDM(
                value=error,
                message=str(error)
            ) from error
        except Exception as error:
            error_message = (
                "Error occurred while pulling the sample data."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {error_message}",
                details=traceback.format_exc(),
            )
            raise SMBFileShareEDM(value=error, message=str(error)) from error

        try:
            columns_data = self.validate_csv_file_records(
                csv_file_path, SAMPLE_DATA_RECORD_COUNT
            )
            columns = columns_data.get("columns", [])
            if len(columns) > 25:
                error_message = (
                    "Maximum 25 columns allowed. Reduce "
                    "columns from the source file and try again."
                )
                self.logger.error(
                    message=f"{self.log_prefix}: {error_message}",
                    resolution=(
                        "Ensure the number of columns in the source "
                        "file is reduced."
                    ),
                )
                raise SMBFileShareEDM(
                    message=f"{self.log_prefix}: {error_message}",
                )
            self.logger.debug(
                f"{self.log_prefix}: Successfully pulled sample data."
            )
            return columns_data
        except Exception as error:
            error_message = "Error occurred while validating the sample data."
            self.logger.error(
                message=f"{self.log_prefix}: {error_message}",
                details=traceback.format_exc(),
            )
            raise SMBFileShareEDM(value=error, message=str(error)) from error

    def strip_string_values(self, configuration: dict) -> None:
        """
        Strip leading and trailing whitespace from string values.

        Values belong to the provided dictionary.

        Args:
            configuration (dict): A dictionary containing key-value pairs.
        """
        for parameter, value in configuration.items():
            if parameter == "smb_password":
                continue
            if isinstance(value, str):
                configuration[parameter] = value.strip()

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

    def get_delimiter(self):
        """Get the delimiter from the configuration.

        Returns:
            str: The delimiter.
        """
        delimiter = self.configuration.get("configuration", {}).get(
            "delimiter", ","
        )
        if not delimiter:
            error_message = "Delimiter is not specified in the configuration."
            self.logger.error(
                message=f"{self.log_prefix}: {error_message}"
            )
            raise SMBFileShareEDM(
                message=error_message
            )
        if len(delimiter) > 1:
            error_message = "Delimiter should be a single character."
            self.logger.error(
                message=f"{self.log_prefix}: {error_message}"
            )
            raise SMBFileShareEDM(
                message=error_message
            )
        return delimiter

    def pull_csv_file_records(
        self, configuration: dict, csv_file_path: str, record_count: int = 0
    ):
        """Abstract method to pull records from a CSV/TXT file.

        Args:
            configuration: parameter configuration dictionary.
            csv_file_path (str): The local file path where the
            pulled records will be saved.
            record_count (int, optional): The number of records to
            pull from the CSV/TXT file (default is 0).

        Raises:
            NotImplementedError: This method must be implemented
            in concrete subclasses.
        """
        raise NotImplementedError

    def validate_csv_file_records(
        self, csv_file_path: str, record_count: int = 0
    ) -> dict:
        """Validate the content of a CSV/TXT file.

            Opens the file in binary mode (rb/wb) so the write-back of the
            truncated sample is never re-quoted or modified by a csv.writer —
            mirroring EdmDataSanitizer.py's parseCSV approach.

        Args:
            csv_file_path (str): The file path to the CSV/TXT file to be
            validated.
            record_count (int, optional): The maximum number of records to
            validate. If set to a positive value, only the first
                record_count' records will be validated. If set to 0 (default),
                all records in the file will be validated.

        Raises:
            SMBFileShareEDM: If validation fails due to incorrect
            data or missing data.

        Returns:
            dict: A dictionary containing the header columns
            of the CSV/TXT file as a list.
        """
        encoding = "UTF-8"
        row_count = 0
        header = None
        delimiter = self.get_delimiter()
        # Stores (raw_bytes_line, parsed_row) tuples for the sample write-back.
        sample_raw_lines = []

        # Local generator: yields decoded text lines to csv.reader while
        # capturing each raw bytes line — mirrors EdmDataSanitizer.py's
        # char_encoder + CURLINE pattern.  Defined here so it is available
        # to both the read pass and (conceptually) the write-back.
        cur_line_box = [None]
        remove_quotes = csv.QUOTE_ALL if self.configuration.get(
            "configuration", {}
        ).get("remove_quotes", False) else csv.QUOTE_NONE

        def _char_encoder(binary_file):
            while True:
                line = binary_file.readline()
                if not line:
                    return
                cur_line_box[0] = line  # raw bytes for lossless write-back
                yield line.decode(encoding)

        try:
            with open(csv_file_path, "rb") as csv_file_object:
                # Read and store header raw bytes separately
                # (written back first).
                hdr_raw = csv_file_object.readline()
                if not hdr_raw:
                    raise ValueError(
                        "At least 1 record must be present in the CSV/TXT file"
                        " in addition to header row."
                    )

                # Parse header fields for validation.
                header = next(
                    csv.reader(
                        [hdr_raw.decode(encoding)],
                        delimiter=delimiter,
                        quoting=remove_quotes,
                    )
                )
                if any(cell.strip() == "" for cell in header):
                    raise ValueError(
                        "Column name in provided file should not "
                        "have an empty value."
                    )

                row_count = 1  # header counted

                # Stream data rows through csv.reader.
                csv_reader = csv.reader(
                    _char_encoder(csv_file_object),
                    delimiter=delimiter,
                    quoting=remove_quotes,
                )
                for row in csv_reader:
                    row_count += 1

                    # Check if 'record_count' is specified and if the row
                    # count exceeds the limit.
                    if record_count and row_count > record_count + 1:
                        break

                    if record_count:
                        # Store raw bytes snapshot captured by _char_encoder.
                        sample_raw_lines.append(cur_line_box[0])
                    # Check if the current row has the same number of columns
                    # as the header row.
                    if len(row) != len(header):
                        raise ValueError(
                            f"Row '{row_count}' does not contain the correct "
                            "number of columns."
                        )

                # Check if at least 1 record is present in the CSV/TXT file.
                if row_count < 2:
                    raise ValueError(
                        "At least 1 record must be present in the CSV/TXT file"
                        " in addition to header row."
                    )

            # Write back only the validated sample
            # rows (header + truncated data).
            # Uses raw bytes so quoting in the original file is never altered.
            if record_count:
                with open(csv_file_path, "wb") as csv_file_object:
                    csv_file_object.write(hdr_raw)
                    for raw_line in sample_raw_lines:
                        csv_file_object.write(raw_line)

            return {"columns": header}
        except ValueError as error:
            self.logger.error(
                message=f"{self.log_prefix}: {str(error)}",
                resolution=(
                    "Ensure to re-validate the CSV file provided in "
                    "configuration and try again. "
                    "\n• The file should contain at least 1 record in "
                    "addition to header row."
                    "\n• Column name in provided file should not "
                    "have an empty value."
                    "\n• Each row should contain the correct number of "
                    "columns as the header row."
                    "\n• Maximum 25 columns allowed."
                ),
                details=traceback.format_exc(),
            )
            raise SMBFileShareEDM(value=error, message=str(error)) from error

    def sanitize(self, file_name: str = "", sample_data: bool = False) -> None:
        """Sanitize the data from a CSV/TXT file and store good & bad files.

        Args:
            file_name (str): The name of the output file.

        Raises:
            SMBFileShareEDM: If an error occurs during the
            sanitization process.
        """
        try:
            delimiter = self.get_delimiter()
            sanitization_input = self.configuration.get(
                "sanity_inputs", {}
            ).get("sanitization_input", {})

            exclude_stopwords = self.configuration.get(
                "sanity_inputs", {}
            ).get("exclude_stopwords", False)

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
            edm_input_configuration.update({"delimiter": delimiter})

            if (
                "stopwords" in edm_input_configuration
                and not exclude_stopwords
            ):
                del edm_input_configuration["stopwords"]

            csv_file_path = self.storage.get("csv_path")
            sanitization_output_path = self.storage.get(
                "sanitization_data_path"
            )
            sanitization_output_file = (
                f"{sanitization_output_path}/{file_name}"
            )

            # Check if the CSV data file exists
            if not os.path.isfile(csv_file_path):
                error_message = (
                    f"Data file doesn't exist at {csv_file_path} "
                    "for sanitization."
                )
                self.logger.error(
                    message=f"{self.log_prefix}: {error_message}",
                    resolution=(
                        "Ensure a valid CSV/TXT file is provided in the"
                        " configuration."
                    ),
                )
                raise SMBFileShareEDM(error_message)

            for file_extension in ["good", "bad"]:
                file_path = f"{sanitization_output_file}.{file_extension}"
                if os.path.isfile(file_path):
                    os.remove(file_path)

            # Create the output directory if it doesn't exist.
            if not os.path.exists(sanitization_output_path):
                os.makedirs(sanitization_output_path)
            edm_input_configuration["remove-quotes"] = self.configuration.get(
                "configuration", {}
            ).get("remove_quotes", False)

            run_sanitizer(
                csv_file_path,
                sanitization_output_file,
                edm_input_configuration,
            )
            if not sample_data:
                if os.path.exists(csv_file_path):
                    os.remove(csv_file_path)
                if os.path.exists(f"{sanitization_output_file}.bad"):
                    os.remove(f"{sanitization_output_file}.bad")
        except Exception as error:
            error_message = (
                "Error occurred while sanitizing "
                f"the data at {csv_file_path}."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {error_message}",
                details=traceback.format_exc(),
            )
            raise SMBFileShareEDM(value=error, message=str(error)) from error

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
                message=(
                    f"{self.log_prefix}: Error occurred while creating "
                    "nested directories to store sanitized data or EDM hashes."
                ),
                details=traceback.format_exc(),
            )
            raise SMBFileShareEDM(value=error, message=str(error)) from error

    def _get_column_names_only(
        self, csv_file_path: str, delimiter: str = ","
    ) -> dict:
        """Extract column names from CSV without validation.

        This method is used by get_fields during plugin upgrade to avoid
        strict validation issues while still providing column names.

        Args:
            csv_file_path (str): Path to the CSV file
            delimiter (str): CSV delimiter (default: ",")

        Returns:
            dict: Dictionary containing column names
        """
        try:
            encoding = "UTF-8"
            with open(
                csv_file_path, "rb"
            ) as csv_file_object:
                # Read header and parse with proper
                # quoting to handle quoted fields
                hdr_raw = csv_file_object.readline()
                if not hdr_raw:
                    return {"columns": []}

                # Remove quotes from column names if remove_quotes is enabled
                remove_quotes = csv.QUOTE_ALL if self.configuration.get(
                    "configuration", {}
                ).get("remove_quotes", False) else csv.QUOTE_NONE

                header = next(
                    csv.reader(
                        [hdr_raw.decode(encoding)],
                        delimiter=delimiter,
                        quoting=remove_quotes,
                    )
                )

                return {"columns": header}
        except Exception as error:
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Error occurred while "
                    "extracting column names. "
                    f"Error: {str(error)}"
                ),
                details=traceback.format_exc(),
            )
            # Return empty columns on error to allow plugin upgrade to continue
            return {"columns": []}

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
            error_message = (
                "Error occurred while getting "
                "indices from sanity input fields based on "
                "normalization and sensitivity."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {error_message}"
            )
            raise SMBFileShareEDM(
                value=error,
                message=str(error)
            ) from error

    def remove_files(
        self, temp_edm_hash_dir_path, input_file_dir, output_path
    ):
        """Remove files and temp EDM hashes after EDM hash generation.

        Args:
            temp_edm_hash_dir_path (str): Temporary EDM Hash Path
            input_file_dir (str): Input File Path
            output_path (str): Path where all files are located

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
                message=(
                    f"{self.log_prefix}: Error occurred while removing"
                    " files."
                ),
                details=traceback.format_exc(),
            )
            raise SMBFileShareEDM(value=error, message=str(error)) from error

    def generate_csv_edm_hash(self, csv_file):
        """Generate EDM Hashes from sanitized data.

        Raises:
            SMBFileShareEDM: If an error occures while
            generating EDM hashes.
        """
        try:
            self.logger.info(
                message=f"{self.log_prefix}: Generating EDM Hashes."
            )
            csv_storage_path = self.storage.get("csv_path")
            if not csv_storage_path:
                raise SMBFileShareEDM(
                    message=(
                        f"{self.log_prefix}: CSV path is not available for "
                        "EDM hash generation."
                    )
                )
            output_path = os.path.dirname(csv_storage_path)

            good_csv_path = f"{output_path}/{csv_file}.good"
            input_file_dir = f"{output_path}/input"
            self.create_directory(dir_path=input_file_dir)
            input_csv_file = f"{input_file_dir}/{csv_file}.csv"
            shutil.move(good_csv_path, input_csv_file)

            if not os.path.isfile(input_csv_file):
                error_message = (
                    "Error occurred while generating EDM Hash. "
                    "CSV/TXT file does not exist."
                )
                self.logger.error(
                    message=f"{self.log_prefix}: {error_message}",
                    resolution=(
                        "Ensure a valid CSV/TXT file is provided in the"
                        " configuration."
                    ),
                )
                raise SMBFileShareEDM(
                    message=error_message
                )

            temp_edm_hash_dir_path = f"{output_path}/temp_edm_hashes"
            self.create_directory(dir_path=temp_edm_hash_dir_path)
            output_dir_path = temp_edm_hash_dir_path

            sanity_inputs = self.configuration.get("sanity_inputs", {})
            dict_cs, dict_cins, norm_num, norm_str = self.get_field_indices(
                sanity_inputs
            )
            delimiter = self.get_delimiter()

            # Get remove_quotes flag from configuration (default to False)
            remove_quotes = self.configuration.get("configuration", {}).get(
                "remove_quotes", False
            )

            edm_hash_config = deepcopy(EDM_HASH_CONFIG)
            edm_hash_config.update(
                {
                    "delimiter": delimiter,
                    "dict_cs": dict_cs,
                    "dict_cins": dict_cins,
                    "norm_num": norm_num,
                    "norm_str": norm_str,
                    "input_csv": input_csv_file,
                    "output_dir": output_dir_path,
                    "remove_quotes": remove_quotes,
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
                temp_metadata_file = (
                    f"{temp_edm_hash_dir_path}/{metadata_file}"
                )
                edm_hash_cfg = f"{edm_hash_dir_path}/{metadata_file}"
                if os.path.exists(temp_metadata_file):
                    shutil.move(temp_metadata_file, f"{edm_hash_dir_path}/")
                if os.path.exists(edm_hash_cfg):
                    self.storage["edm_hashes_cfg"] = edm_hash_cfg
                self.remove_files(
                    temp_edm_hash_dir_path, input_file_dir, output_path
                )

                self.logger.info(
                    message=(
                        f"{self.log_prefix}: EDM Hash generated "
                        "successfully."
                    )
                )
            else:
                self.storage["edm_hash_available"] = False
                error_message = (
                    "Error occurred while generating "
                    "EDM Hash."
                )
                self.logger.error(
                    message=f"{self.log_prefix}: {error_message}"
                )
                raise SMBFileShareEDM(
                    message=error_message
                )
        except Exception as error:
            if self.storage.get("csv_path"):
                output_path = os.path.dirname(self.storage.get("csv_path"))
                input_file_dir = f"{output_path}/input"
                temp_edm_hash_dir_path = f"{output_path}/temp_edm_hashes"
                self.remove_files(
                    temp_edm_hash_dir_path=temp_edm_hash_dir_path,
                    input_file_dir=input_file_dir,
                    output_path=output_path,
                )
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Error occurred while generating "
                    "EDM Hash."
                ),
                details=traceback.format_exc(),
            )
            raise SMBFileShareEDM(value=error, message=str(error)) from error

    def pull(self):
        """
        Pull and sanitize CSV/TXT from an SMB server.

        Retrieve the remote file, sanitize its contents, and store it locally.

        Raises:
            SMBFileShareEDM: If any error occurs during
                the data retrieval or validation.
        """
        try:
            server_configuration = self.configuration.get("configuration", {})
            is_unsanitized_data = self.configuration.get(
                "sanity_results", {}
            ).get("is_unsanitized_data", True)
            self.strip_string_values(server_configuration)
            smb_filepath = server_configuration.get("smb_filepath", "")
            if not smb_filepath:
                raise SMBFileShareEDM(
                    message="SMB file path is not configured."
                )
            file_extension = smb_filepath.split(".")[-1]

            csv_file_name = f"{self.name}_data"
            csv_file_name = (
                csv_file_name.replace(" ", "_")
                .replace("\t", "_")
                .replace("-", "_")
            )
            self.storage["csv_path"] = (
                f"{FILE_PATH}/{self.name}/{csv_file_name}.{file_extension}"
            )
            self.storage["file_name"] = f"{csv_file_name}.{file_extension}"
            self.storage["sanitization_data_path"] = f"{FILE_PATH}/{self.name}"
            csv_file_path = self.storage.get("csv_path")
            self.create_csv_directory(csv_file_path)

            self.logger.info(
                f"{self.log_prefix}: Pulling the file from the SMB server."
            )
            self.protocol_object.validate_remote_file(server_configuration)
            self.protocol_object.pull_csv_file_records(
                server_configuration, csv_file_path
            )
            self.logger.info(
                f"{self.log_prefix}: Successfully pulled file "
                "from the SMB server."
            )
        except Exception as error:
            error_message = (
                "Error occurred while pulling the data."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {error_message}",
                details=traceback.format_exc(),
            )
            raise SMBFileShareEDM(value=error, message=str(error)) from error

        try:
            self.logger.info(f"{self.log_prefix}: Validating the file.")
            self.validate_csv_file_records(csv_file_path)
            self.logger.info(
                (f"{self.log_prefix}: Successfully validated file.")
            )
        except Exception as error:
            error_message = (
                "Error occurred while validating the data. "
            )
            self.logger.error(
                message=f"{self.log_prefix}: {error_message}",
                details=traceback.format_exc(),
            )
            raise SMBFileShareEDM(value=error, message=str(error)) from error

        if is_unsanitized_data:
            if os.path.exists(csv_file_path):
                os.rename(
                    csv_file_path,
                    f"{FILE_PATH}/{self.name}/{csv_file_name}.good",
                )
                self.logger.debug(
                    message=(
                        f"{self.log_prefix}: Sanitization skipped for file"
                        f" '{csv_file_name}' as Proceed Without Sanitization "
                        "is enabled."
                    )
                )
            else:
                error_message = f"Data file doesn't exist at {csv_file_path}."
                self.logger.error(
                    message=f"{self.log_prefix}: {error_message}",
                    resolution=(
                        "Ensure a valid CSV/TXT file is provided in the"
                        " configuration."
                    ),
                )
                raise SMBFileShareEDM(error_message)
        else:
            self.logger.info(f"{self.log_prefix}: Sanitizing the data.")
            self.sanitize(csv_file_name)
            self.logger.info(
                (f"{self.log_prefix}: Successfully sanitized data.")
            )
        self.generate_csv_edm_hash(csv_file=csv_file_name)
        return {
            "message": "Remote File pulled and EDM Hash "
            "generated successfully."
        }

    def push(self):
        """Plugin is not push supported.

        Raises:
            NotImplementedError: If the method is not implemented.
        """
        raise NotImplementedError()

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
