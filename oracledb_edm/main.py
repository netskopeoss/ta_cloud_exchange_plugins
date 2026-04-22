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

OracleDB Plugin is used to pull data from OracleDB server, store
it in CSV format, perform sanitization and EDM Hash Generation from the same.
"""

import csv
import os
import shutil
import traceback
from copy import deepcopy
from typing import List
from netskope.integrations.edm.models import Action, ActionWithoutParams
from netskope.integrations.edm.plugin_base import PluginBase, ValidationResult
from netskope.integrations.edm.utils import CONFIG_TEMPLATE, FILE_PATH
from netskope.integrations.edm.utils import CustomException as OracleDLPError
from netskope.integrations.edm.utils import run_sanitizer
from netskope.integrations.edm.utils.constants import EDM_HASH_CONFIG
from netskope.integrations.edm.utils.edm.hash_generator.edm_hash_generator import (  # noqa = E501
    generate_edm_hash,
)
from .utils.constants import (
    MODULE_NAME,
    ORACLE_EDM_FIELDS,
    PLUGIN_NAME,
    PLUGIN_VERSION,
    SAMPLE_CSV_FILE_NAME,
    SAMPLE_CSV_ROW_COUNT,
)
from .utils.helper import OracleDBHelper


class OracleDBPlugin(PluginBase):
    """OracleDB EDM plugin is used to pull data from configured \
    OracleDB server, store it in CSV format to perform sanitization \
    and EDM Hash Generation on pulled data."""

    def __init__(
        self,
        name,
        *args,
        **kwargs,
    ):
        """OracleDB EDM plugin initializer.

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
        self.helper = OracleDBHelper(self.logger, self.log_prefix)

    def _get_plugin_info(self) -> tuple:
        """Get plugin name and version from manifest.

        Returns:
            tuple: tuple of plugin's name and version fetched from manifest.
        """
        try:
            manifest_json = OracleDBPlugin.metadata
            plugin_name = manifest_json.get("name", PLUGIN_NAME)
            plugin_version = manifest_json.get("version", PLUGIN_VERSION)
            return plugin_name, plugin_version
        except Exception as exp:
            self.logger.error(
                message=(
                    f"{MODULE_NAME} {PLUGIN_NAME}: Error occurred while"
                    f" getting plugin details. Error: {exp}"
                ),
                details=traceback.format_exc(),
            )
        return (PLUGIN_NAME, PLUGIN_VERSION)

    def create_directory(self, dir_path):
        """Create a directory at the specified path,
        including all necessary parent directories.

        Args:
            dir_path (string): The path of the directory to be created.

        Raises:
            OracleDLPError: If there's an issue creating the directory.
        """
        try:
            if not os.path.exists(dir_path):
                os.makedirs(dir_path)
        except Exception as error:
            err_msg = (
                f"Failed to create directory '{dir_path}'. Ensure the path is "
                "valid and you have write permissions."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=traceback.format_exc(),
            )
            raise OracleDLPError(value=error, message=err_msg) from error

    def _get_column_names_only(
        self, csv_file_path: str
    ) -> dict:
        """Extract column names from CSV without validation.

        This method is used by get_fields during plugin upgrade to avoid
        strict validation issues while still providing column names.

        Args:
            csv_file_path (str): Path to the CSV file

        Returns:
            dict: Dictionary containing column names
        """
        try:
            encoding = "UTF-8"
            with open(csv_file_path, "rb") as csv_file_object:
                # Read header and parse with proper
                # quoting to handle quoted fields
                hdr_raw = csv_file_object.readline()
                if not hdr_raw:
                    return {"columns": []}

                # Remove quotes from column names if remove_quotes is enabled
                remove_quotes = (
                    csv.QUOTE_ALL
                    if self.configuration.get("configuration", {}).get(
                        "remove_quotes", False
                    )
                    else csv.QUOTE_NONE
                )

                header = next(
                    csv.reader(
                        [hdr_raw.decode(encoding)],
                        quoting=remove_quotes,
                    )
                )

                return {"columns": header}
        except Exception as error:
            self.logger.error(
                message=f"{self.log_prefix}: Error extracting column names: "
                f"{str(error)}",
                details=traceback.format_exc(),
            )
            # Return empty columns on error to allow plugin upgrade to continue
            return {"columns": []}

    def validate_csv_file_records(
        self, csv_file_path: str, record_count: int = 0
    ) -> dict:
        """Validate the content of a CSV file.

        Args:
            csv_file_path (str): The file path to the CSV file to be validated.
            record_count (int, optional): The maximum number of records to
                validate. If set to a positive value, only the first
                'record_count' records will be validated. If set to 0
                (default), all records in the file will be validated.

        Raises:
            OracleDLPError: If validation fails due to incorrect data or
            missing data.

        Returns:
            dict: A dictionary containing the header columns of the CSV file
                as a list.
        """
        encoding = "UTF-8"
        row_count = 0
        header = None
        sample_raw_lines = []

        cur_line_box = [None]
        remove_quotes = (
            csv.QUOTE_ALL
            if self.configuration.get("configuration", {}).get(
                "remove_quotes", False
            )
            else csv.QUOTE_NONE
        )

        def _char_encoder(binary_file):
            while True:
                line = binary_file.readline()
                if not line:
                    return
                cur_line_box[0] = line
                yield line.decode(encoding)

        try:
            with open(csv_file_path, "rb") as csv_file_object:
                hdr_raw = csv_file_object.readline()
                if not hdr_raw:
                    raise ValueError(
                        "Provided query should return at least one record."
                    )

                header = next(
                    csv.reader(
                        [hdr_raw.decode(encoding)],
                        quoting=remove_quotes,
                    )
                )
                if any(cell.strip() == "" for cell in header):
                    raise ValueError(
                        "Column name in provided file should not "
                        "have an empty value."
                    )

                row_count = 1

                csv_reader = csv.reader(
                    _char_encoder(csv_file_object),
                    quoting=remove_quotes,
                )

                for row in csv_reader:
                    row_count += 1

                    if record_count and row_count > record_count + 1:
                        break

                    if record_count:
                        sample_raw_lines.append(cur_line_box[0])

                    if len(row) != len(header):
                        raise ValueError(
                            f"Row '{row_count}' does not contain the correct "
                            f"number of columns."
                        )

                if row_count < 2:
                    raise ValueError(
                        "Provided query should return at least one record."
                    )

            if record_count:
                with open(csv_file_path, "wb") as csv_file_object:
                    csv_file_object.write(hdr_raw)
                    for raw_line in sample_raw_lines:
                        csv_file_object.write(raw_line)

            return {"columns": header}
        except ValueError as error:
            self.logger.error(
                message=(
                    f"{self.log_prefix}: {str(error)}"
                ),
                resolution=(
                    "Ensure to re-validate the query and try again. "
                    "\n• The query should return at least 1 record."
                    "\n• Column name in provided file should not "
                    "have an empty value."
                    "\n• Each row should contain the correct number of "
                    "columns as the header row."
                    "\n• Maximum 25 columns allowed."
                ),
                details=traceback.format_exc(),
            )
            raise OracleDLPError(value=error, message=str(error)) from error

    def pull_sample_data(self):
        """Pull sample data from OracleDB database and store it in csv file.

        Raises:
            OracleDLPError: If any error occurs in sample data pulling

        Returns:
            dict: dictionary containing column names from fetched data.
        """
        try:
            self.logger.debug(
                message=f"{self.log_prefix}: Pulling sample data."
            )
            config = self.configuration.get("configuration", {})
            csv_path = self.storage.get("csv_path", "")
            if not csv_path:
                err_msg = "CSV path is not configured in storage."
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg}",
                    resolution="Ensure the CSV path is properly configured.",
                )
                raise OracleDLPError(message=err_msg)

            if os.path.exists(csv_path):
                os.remove(csv_path)

            columns = self.helper.pull_data(
                config=config,
                csv_path=csv_path,
                fetch_only_sample_data=True
            )

            # Validate the CSV file records
            self.validate_csv_file_records(
                csv_path, record_count=SAMPLE_CSV_ROW_COUNT
            )

            self.logger.debug(
                f"{self.log_prefix}: Successfully pulled sample data."
            )

            return {"columns": columns}
        except OracleDLPError as error:
            raise error
        except Exception as error:
            err_msg = "Error occurred while pulling sample data."
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                resolution=(
                    "Ensure the database connection is stable and the query "
                    "is valid."
                ),
                details=traceback.format_exc(),
            )
            raise OracleDLPError(
                value=error,
                message=err_msg,
            ) from error

    def sanitize(self, file_name="", sample_data: bool = False):
        """Sanitize CSV data and store good and bad files using run_sanitizer.

        Args:
            file_name (str, optional): The name of the output file.

        Raises:
            OracleDLPError: If an error occurs during
            the sanitization process.
        """
        try:
            self.logger.info(
                message=f"{self.log_prefix}: Sanitizing OracleDB data "
                f"for configuration '{self._name}'."
            )
            fields = self.configuration.get("sanity_inputs", {}).get(
                "sanitization_input", {}
            )

            exclude_stopwords = self.configuration.get(
                "sanity_inputs", {}
            ).get("exclude_stopwords", False)

            for field in fields:
                # strips spaces from front and end for all values.
                self.helper.strip_args(field)

            # Construct edm_data_config based on fields configuration
            edm_data_config = deepcopy(CONFIG_TEMPLATE)
            edm_data_config.update(
                {
                    "names": [
                        field.get("field", "")
                        for field in fields
                        if field.get("nameColumn", False)
                    ]
                }
            )

            if "stopwords" in edm_data_config and not exclude_stopwords:
                del edm_data_config["stopwords"]

            csv_path = self.storage.get("csv_path")
            output_path = self.storage.get("sanitization_data_path")
            file_path = f"{output_path}/{file_name}"

            if not os.path.isfile(csv_path):
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: Error occurred while performing "
                        "EDM sanitization. "
                        "OracleDB data file does not exist."
                    )
                )
                raise OracleDLPError(
                    message=(
                        "Error occurred while performing "
                        "OracleDB data sanitization."
                    )
                )

            # Remove existing sanitized and non-sanitized files if they exist
            for file_extension in ["good", "bad"]:
                existing_file = f"{file_path}.{file_extension}"
                if os.path.isfile(existing_file):
                    os.remove(existing_file)

            self.create_directory(dir_path=os.path.dirname(output_path))
            edm_data_config["remove-quotes"] = self.configuration.get(
                "configuration", {}
            ).get("remove_quotes", False)
            run_sanitizer(csv_path, file_path, edm_data_config)
            self.logger.info(
                message=(
                    f"{self.log_prefix}: Successfully sanitized OracleDB data."
                )
            )
            if not sample_data:
                if os.path.exists(csv_path):
                    os.remove(csv_path)
                if os.path.exists(f"{file_path}.bad"):
                    os.remove(f"{file_path}.bad")
        except Exception as error:
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Error occurred while performing "
                    "sanitization of OracleDB data."
                ),
                details=traceback.format_exc(),
            )
            raise OracleDLPError(
                value=error,
                message=(
                    "Error occurred while performing "
                    "sanitization of OracleDB data."
                ),
            ) from error

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
            raise OracleDLPError(
                message=(
                    "Error occurred while getting "
                    "indices from sanity input fields "
                    "based on normalization and sensitivity."
                )
            ) from error

    def remove_files(
        self, temp_edm_hash_dir_path, input_file_dir, output_path
    ):
        """Remove csv files and temp EDM hashes after EDM hash generation.

        Args:
            temp_edm_hash_dir_path (str): Temporary EDM Hash Path
            input_file_dir (str): Input CSV File Path
            output_path (str): Path where all CSV files are located

        Raises:
            OracleDLPError: If there's an issue removing files.
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
            err_msg = (
                "Error occurred while cleaning up temporary EDM hash and "
                "CSV files. Ensure the paths are accessible and have "
                "appropriate permissions."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=traceback.format_exc(),
            )
            raise OracleDLPError(value=error, message=err_msg) from error

    def generate_csv_edm_hash(self, csv_file):
        """Generate EDM Hashes from sanitized data.

        Raises:
            OracleDLPError: If an error occures while
            generating EDM hashes.
        """
        try:
            self.logger.info(
                message=(
                    f"{self.log_prefix}: Generating EDM Hashes."
                )
            )
            output_path = os.path.dirname(self.storage.get("csv_path"))

            good_csv_path = f"{output_path}/{csv_file}.good"
            input_file_dir = f"{output_path}/input"
            self.create_directory(dir_path=input_file_dir)
            input_csv_file = f"{input_file_dir}/{csv_file}.csv"
            shutil.move(good_csv_path, input_csv_file)

            if not os.path.isfile(input_csv_file):
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: Error occurred while generating "
                        f"EDM Hash. '.csv' file does not exist."
                    )
                )
                raise OracleDLPError(
                    message=(
                        "Error occurred while generating "
                        "EDM Hash of OracleDB EDM Plugin."
                    )
                )

            temp_edm_hash_dir_path = f"{output_path}/temp_edm_hashes"
            self.create_directory(dir_path=temp_edm_hash_dir_path)
            output_dir_path = temp_edm_hash_dir_path

            sanity_inputs = self.configuration.get("sanity_inputs", {})
            dict_cs, dict_cins, norm_num, norm_str = self.get_field_indices(
                sanity_inputs
            )

            # Get remove_quotes flag from configuration (default to False)
            remove_quotes = self.configuration.get("configuration", {}).get(
                "remove_quotes", False
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
                        f"{self.log_prefix}: Successfully generated EDM Hash."
                    )
                )
            else:
                self.storage["edm_hash_available"] = False
                raise OracleDLPError(
                    message=(
                        f"{self.log_prefix}: Error occurred while generating "
                        "EDM Hash."
                    )
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
                message=(
                    f"{self.log_prefix}: Error occurred while generating "
                    "EDM Hash for OracleDB data."
                ),
                details=traceback.format_exc(),
            )
            raise OracleDLPError(
                value=error,
                message=(
                    "Error occurred while generating "
                    "EDM Hash of OracleDB data."
                ),
            ) from error

    def delete_old_csv(self):
        """Delete old csv files at the start of pull method."""
        csv_path = self.storage.get("csv_path")
        if csv_path and os.path.exists(csv_path):
            os.remove(csv_path)

    def pull(self):
        """Pull data from OracleDB server and convert it to csv.

        Raises:
            OracleDLPError: If any error occurs while the data pulling.

        Returns:
            dict: returns success message
        """
        err_msg = (
            "Error occurred while pulling, sanitizing and generating "
            "EDM Hashes for OracleDB data."
        )
        try:
            base_name = f"{self.name}_data"
            base_name = (
                base_name.replace(" ", "_")
                .replace("\t", "_")
                .replace("-", "_")
                .replace("-", "_")
            )
            csv_name = f"{base_name}.csv"
            self.storage["csv_path"] = f"{FILE_PATH}/{self.name}/{csv_name}"
            self.storage["file_name"] = csv_name
            self.storage["sanitization_data_path"] = f"{FILE_PATH}/{self.name}"
            self.delete_old_csv()

            config = self.configuration.get("configuration", {})
            is_unsanitized_data = self.configuration.get(
                "sanity_results", {}
            ).get("is_unsanitized_data", True)

            csv_path = self.storage.get("csv_path")
            columns = self.helper.pull_oracledb_data(config, csv_path)
            # Validate column count - this is now handled in pull_data,
            # but keeping as a safeguard
            is_valid_columns, column_error_message = (
                self.helper.validate_column_count(columns)
            )
            if not is_valid_columns:
                self.logger.error(
                    message=f"{self.log_prefix}: {column_error_message}",
                )
                raise OracleDLPError(
                    message=f"{self.log_prefix}: {column_error_message}",
                )

            self.validate_csv_file_records(csv_path)
            if is_unsanitized_data:
                if os.path.exists(csv_path):
                    os.rename(
                        csv_path, f"{FILE_PATH}/{self.name}/{base_name}.good"
                    )
                    f"{self.log_prefix}: Sanitization skipped for file"
                    f" '{csv_name}' as Proceed Without Sanitization "
                    "is enabled."
                else:
                    error_message = f"Data file doesn't exist at {csv_path}."
                    self.logger.error(
                        message=f"{self.log_prefix}: {error_message}"
                    )
                    raise OracleDLPError(error_message)
            else:
                self.sanitize(file_name=base_name)
            self.generate_csv_edm_hash(csv_file=base_name)
            return {
                "message": "Data pulled and "
                "EDM Hashes successfully generated."
            }

        except OracleDLPError as error:
            self.logger.error(
                message=err_msg
            )
            raise error
        except Exception as error:
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=traceback.format_exc(),
            )
            raise OracleDLPError(
                value=error,
                message=err_msg,
            ) from error

    def push(self, indicators=None, action_dict=None):
        """Plugin is not push supported.

        Raises:
            NotImplementedError: If the method is not implemented.
        """
        raise NotImplementedError()

    def validate(self, configuration):
        """Validate the plugin configuration parameters.

        Args:
            configuration (dict): Dictionary containing
            the plugin configuration parameters.

        Returns:
            ValidationResult: ValidationResult
            object with success flag and message.
        """
        self.logger.debug(
            message=(
                f"{self.log_prefix}: Validating plugin configuration "
                "parameters."
            )
        )
        try:
            db_config = configuration.get("configuration", {})
            self.helper.strip_args(db_config)

            validation_result = self.helper.validate_configuration_parameters(
                db_config
            )
            if not validation_result.success:
                return validation_result

            verification_result = self.helper.verify_connection(db_config)
            if not verification_result.success:
                return verification_result

            try:
                input_path = f"{FILE_PATH}/{self.name}/{SAMPLE_CSV_FILE_NAME}"
                self.storage.update({"csv_path": input_path})
                self.pull_sample_data()
                self.logger.debug(
                    f"{self.log_prefix}: Successfully validated "
                    "configuration parameters."
                )
            except Exception as error:
                err_msg = str(error)
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: Validation error occurred. "
                        f"{err_msg}"
                        ),
                    resolution=(
                        "Ensure that the database host, port, username, "
                        "password, and database name are correct. Ensure the "
                        "database server is reachable and the query is valid."
                    ),
                )
                return ValidationResult(
                    success=False,
                    message=err_msg,
                )

            self.logger.debug(
                (
                    f"{self.log_prefix}: Successfully validated "
                    "configuration parameters."
                )
            )

            return verification_result
        except Exception:
            err_msg = (
                "Error occurred while connecting to the "
                "OracleDB database."
            )
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Validation error occurred. {err_msg}"
                    ),
                resolution=(
                    "Ensure that the database host, port, username, password, "
                    "and database name are correct. Ensure the database "
                    "server is reachable."
                ),
                details=traceback.format_exc(),
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )

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
                "Successfully validated hash generation and "
                "sanitization parameters."
            )
            self.logger.debug(
                f"{self.log_prefix}: {message}"
            )
            result = ValidationResult(
                success=True,
                message=message
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
                message=message
            )
        return result

    def get_fields(self, name: str, configuration: dict):
        """Get fields configuration based on the specified step name.

        Args:
            name (str): The name of the field configuration to retrieve
            configuration (dict): The configuration dictionary.

        Raises:
            NotImplementedError: If a field configuration with the specified
                name is not implemented.

        Returns:
            list: List of configuration parameters.
        """
        if name in ORACLE_EDM_FIELDS:
            fields = ORACLE_EDM_FIELDS[name]
            if name == "sanity_inputs":
                for field in fields:
                    if field.get("type") == "sanitization_input":
                        input_path = (
                            f"{FILE_PATH}/{self.name}/{SAMPLE_CSV_FILE_NAME}"
                        )
                        self.storage.update({
                            "csv_path": input_path
                        })
                        # Only get column names without
                        # validation for field config
                        columns_data = self._get_column_names_only(
                            input_path
                        )
                        field["default"] = columns_data
            elif name == "sanity_results":
                for field in fields:
                    if field.get("type") == "sanitization_preview":
                        field["default"] = {
                            "sanitizationStatus": True,
                            "message": "Sanitization Done Successfully",
                        }
            return fields
        raise NotImplementedError()
