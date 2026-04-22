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

MySQL will pull data and store it in CSV format.
"""


import csv
import os
import shutil
import time
import traceback
from copy import deepcopy
from typing import List

# Third-party libraries
from sqlalchemy import create_engine, text
from sqlalchemy.exc import InterfaceError, OperationalError, ProgrammingError


from netskope.integrations.edm.models import Action, ActionWithoutParams
from netskope.integrations.edm.plugin_base import PluginBase, ValidationResult
from netskope.integrations.edm.utils import CONFIG_TEMPLATE, FILE_PATH
from netskope.integrations.edm.utils import CustomException as MySQLDLPError
from netskope.integrations.edm.utils import run_sanitizer
from netskope.integrations.edm.utils.constants import EDM_HASH_CONFIG
from netskope.integrations.edm.utils.edm.hash_generator.edm_hash_generator import (  # noqa = E501
    generate_edm_hash,
)
from .utils.constants import (
    BATCH_SIZE,
    CONNECTION_TIMEOUT,
    MODULE_NAME,
    MYSQL_EDM_FIELDS,
    PLUGIN_NAME,
    PLUGIN_VERSION,
    SAMPLE_CSV_ROW_COUNT,
    SAMPLE_CSV_FILE_NAME,
)
from .utils.helper import MySQLPluginHelper


# User-Defined Wrapper ##


def retry(error_class, count=3, timeout=30):
    """
    Retry decorator used to retry a method if a specific exception is raised.

    Args:
        error_class (Exception): Any exception class.
        count (int, optional): Number of retries. Defaults to 3.
        timeout (int, optional): Time interval (in seconds)
                        between retries. Defaults to 30.
    """

    def retry_decorator(func):
        def wrapped_function(*args, **kwargs):
            nonlocal count
            while count > 0:
                try:
                    return func(*args, **kwargs)
                except error_class as error:
                    count -= 1
                    if count > 0:
                        time.sleep(timeout)
                    else:
                        raise error
                except Exception as error:
                    raise error

        return wrapped_function

    return retry_decorator


class MySQLPlugin(PluginBase):
    """
    MySQL EDM plugin is used to pull SQL data from configured SQL server.

    And store it in CSV format.
    """

    def __init__(
        self,
        name,
        *args,
        **kwargs,
    ):
        """
        MySQL EDM plugin initializer.

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

        self.helper_object = MySQLPluginHelper(
            self.logger, self.log_prefix
        )

    def _get_plugin_info(self) -> tuple:
        """Get plugin name and version from manifest.

        Returns:
            tuple: tuple of plugin's name and version fetched from manifest.
        """
        try:
            manifest_json = MySQLPlugin.metadata
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

    def create_directory(self, dir_path):
        """
        Create a directory at the specified path.

        Include all necessary parent directories.

        Args:
            dir_path (string): The path of the directory to be created.

        Raises:
            OSError: If there's an issue creating the directory.

        """
        try:
            if not os.path.exists(dir_path):
                os.makedirs(dir_path)
        except Exception as error:
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Error occurred while creating nested "
                    "directories to store sanitized data or EDM hashes."
                ),
                details=traceback.format_exc(),
            )
            raise error

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
                message=(
                    f"{self.log_prefix}: Error occurred while extracting "
                    f"column names. Error: {str(error)}"
                ),
                details=traceback.format_exc(),
            )
            # Return empty columns on error to allow plugin upgrade to continue
            return {"columns": []}

    def delete_old_csv(self):
        """Delete old csv files at the start of pull method."""
        csv_path = self.storage.get("csv_path")
        if os.path.exists(csv_path):
            os.remove(csv_path)

    def validate_column_count(self, columns):
        """
        Validate the number of columns in the query result is not more than 25.

        Args:
            columns (list): List of column names from the query result

        Returns:
            tuple: (is_valid, error_message) where is_valid is a
                boolean and error_message is a string
        """
        if columns and len(columns) > 25:
            error_message = (
                "Maximum 25 columns allowed. Reduce the number "
                "of columns in your query and try again."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {error_message}",
                resolution=(
                    "Ensure the number of columns in the source table or "
                    "query result is reduced to a maximum of 25 columns, "
                    "then try again."
                ),
            )
            return False, error_message
        return True, ""

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
            MySQLDLPError: If validation fails due to incorrect data or
            missing data.

        Returns:
            dict: A dictionary containing the header columns of the CSV file
                as a list.
        """
        encoding = "UTF-8"
        row_count = 0
        header = None
        # Stores (raw_bytes_line, parsed_row) tuples for the sample write-back.
        sample_raw_lines = []

        # Local generator: yields decoded text lines to csv.reader while
        # capturing each raw bytes line.
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
                cur_line_box[0] = line  # raw bytes for lossless write-back
                yield line.decode(encoding)

        try:
            with open(csv_file_path, "rb") as csv_file_object:
                # Read and store header raw bytes separately.
                hdr_raw = csv_file_object.readline()
                if not hdr_raw:
                    raise ValueError(
                        "Provided query should return atleast one record."
                    )

                # Parse header fields for validation.
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

                row_count = 1  # header counted

                # Stream data rows through csv.reader.
                csv_reader = csv.reader(
                    _char_encoder(csv_file_object),
                    quoting=remove_quotes,
                )

                for row in csv_reader:
                    row_count += 1

                    # Check if 'record_count' is specified and if the row count
                    # exceeds the limit.
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

                # Check if at least 1 record is present in the CSV file.
                if row_count < 2:
                    raise ValueError(
                        "Provided query should return atleast one record."
                    )

            # Keep only the records which has been validated
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
                    "Ensure to re-validate the query table provided in "
                    "configuration and try again. "
                    "\n• The table should contain at least 1 record in "
                    "addition to header row."
                    "\n• Column name in provided table should not "
                    "have an empty value."
                    "\n• Each row should contain the correct number of "
                    "columns as the header row."
                    "\n• Maximum 25 columns allowed."
                ),
                details=traceback.format_exc(),
            )
            raise MySQLDLPError(value=error, message=str(error)) from error

    def store_data_to_csv(self, mysql_data, csv_path):
        """
        Store fetched MySQL data to csv file.

        Args:
            mysql_data (list): sql data fetched from database.
            csv_path (string): location to store csv data file at.
        """
        try:
            self.create_directory(dir_path=os.path.dirname(csv_path))
            with open(csv_path, "a", encoding="UTF-8") as file_pointer:
                csv_pointer = csv.writer(file_pointer)
                for row in mysql_data:
                    csv_pointer.writerow(row)
        except Exception as error:
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Error occurred while "
                    "storing pulled MySQL data to CSV file."
                ),
                details=traceback.format_exc(),
            )
            raise error

    def pull_data(self, config, fetch_only_sample_data=False) -> list:
        """Create connection and fetch data from database.

        Args:
            config (dict): plugin configuration

        Returns:
            list: list of data fetched from database
        """
        try:
            connection_string = self.helper_object.create_connection_string(
                config
            )
            csv_path = self.storage.get("csv_path")
            eng = create_engine(
                connection_string,
                connect_args={"connect_timeout": CONNECTION_TIMEOUT},
            )  # creates connection with database.
            with eng.connect() as connection:
                # used to stop user from executing any database
                # modification query.
                result = connection.execute(
                    text("START TRANSACTION READ ONLY;")
                )
                query = text(config.get("query"))
                result = connection.execute(query)
                columns = list(result.keys())

                # Validate column count
                is_valid_columns, column_error_message = (
                    self.validate_column_count(columns)
                )
                if not is_valid_columns:
                    self.logger.error(
                        message=f"{self.log_prefix}: {column_error_message}",
                    )
                    raise MySQLDLPError(
                        message=column_error_message,
                    )
                self.store_data_to_csv([columns], csv_path)
                if fetch_only_sample_data:
                    rows = result.fetchmany(SAMPLE_CSV_ROW_COUNT)
                    self.store_data_to_csv(rows, csv_path)
                else:
                    while True:
                        rows = result.fetchmany(BATCH_SIZE)
                        if not rows:
                            break  # No more rows to fetch
                        self.store_data_to_csv(rows, csv_path)
            self.validate_csv_file_records(csv_path)
            return columns
        except (InterfaceError, OperationalError) as error:
            # Host unreachable, wrong port, server not running,
            # or credential issues at the connection level
            err_msg = (
                "Error occurred when connecting to MySQL database. "
                "Verify that the Server Hostname/IP, Username, "
                "Password, Port and Database Name are correct."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                resolution=(
                    "Ensure that the Server Hostname/IP, Username, Password, "
                    "Port and Database Name are correct and the MySQL server "
                    "is reachable."
                ),
                details=traceback.format_exc(),
            )
            raise MySQLDLPError(
                value=error,
                message=err_msg,
            ) from error
        except ProgrammingError as error:
            # With mysqlconnector, auth failures (errno 1045) and unknown
            # database (errno 1049) also surface as ProgrammingError.
            # Distinguish them from genuine SQL query errors.
            orig = getattr(error, "orig", None)
            errno = getattr(orig, "errno", None)
            if errno in (1045, 1049):
                err_msg = (
                    "Error occurred while connecting with remote server. "
                    "Verify that the Server Hostname/IP, Username, "
                    "Password, Port and Database Name are correct."
                )
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg}",
                    resolution=(
                        "Ensure that the Server Hostname/IP, Username, "
                        "Password, Port and Database Name are correct and "
                        "the MySQL server is reachable."
                    ),
                    details=traceback.format_exc(),
                )
            else:
                err_msg = (
                    "Error occurred while executing MySQL query."
                )
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg}",
                    resolution=(
                        "Ensure that the SQL query is valid, the specified "
                        "table and columns exist, and the user has sufficient "
                        "read permissions on the database."
                    ),
                    details=traceback.format_exc(),
                )
            raise MySQLDLPError(
                value=error,
                message=err_msg,
            ) from error
        except MySQLDLPError as error:
            raise error
        except Exception as error:
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Error occurred while "
                    "pulling MySQL data."
                ),
                details=traceback.format_exc(),
            )
            raise MySQLDLPError(
                value=error,
                message="Error occurred while pulling MySQL data.",
            ) from error

    @retry(error_class=InterfaceError)
    def pull_mysql_data(self, config) -> list:
        """
        Define the separate method since we need to retry.

        In case of pulling all data from MySQL.

        Args:
            config (dict): plugin configuration

        Returns:
            list: list of data fetched from database
        """
        try:
            self.logger.info(
                message=(f"{self.log_prefix}: Pulling MySQL data.")
            )
            data = self.pull_data(config=config, fetch_only_sample_data=False)
            self.logger.info(
                message=(
                    f"{self.log_prefix}: Successfully pulled MySQL data."
                )
            )
            return data
        except Exception as error:
            raise error

    def sanitize(self, file_name="", sample_data: bool = False):
        """Sanitizes csv data and store good and bad files using run_sanitizer.

        Args:
            file_name (str, optional): filename to use for generated good and
                bad csv. Defaults to "".
            sample_data (bool, optional): Whether this is sample data.
                Defaults to False.

        Raises:
            MySQLDLPError: Custom error class
        """
        try:
            self.logger.info(
                message=f"{self.log_prefix}: Sanitizing MySQL data."
            )
            fields = self.configuration.get("sanity_inputs", {}).get(
                "sanitization_input", {}
            )

            exclude_stopwords = self.configuration.get(
                "sanity_inputs", {}
            ).get("exclude_stopwords", False)

            for (
                field
            ) in fields:  # strips spaces from front and end for all values.
                self.helper_object.strip_args(field)

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
                error_message = (
                    "Error occurred while performing "
                    "EDM sanitization. MySQL data file does not exist."
                )
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: {error_message}"
                    ),
                    resolution=(
                        "Ensure a valid query is provided in the"
                        " configuration."
                    ),
                )
                raise MySQLDLPError(
                    message=error_message
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
                    f"{self.log_prefix}: Successfully sanitized MySQL data."
                )
            )
            if not sample_data:
                if os.path.exists(csv_path):
                    os.remove(csv_path)
                if os.path.exists(f"{file_path}.bad"):
                    os.remove(f"{file_path}.bad")
        except MySQLDLPError:
            raise
        except Exception as error:
            error_message = (
                "Error occurred while performing sanitization of MySQL data."
            )
            self.logger.error(
                message=(
                    f"{self.log_prefix}: {error_message}"
                ),
                details=traceback.format_exc(),
            )
            raise MySQLDLPError(
                value=error,
                message=error_message,
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
            error_message = (
                "Error occurred while getting indices from sanity input "
                "fields based on normalization and sensitivity."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {error_message}"
            )
            raise MySQLDLPError(
                message=error_message
            ) from error

    def remove_files(
        self,
        temp_edm_hash_dir_path=None,
        input_file_dir=None,
        output_path=None,
    ):
        """Remove csv files and temp EDM hashes after EDM hash generation.

        Args:
            temp_edm_hash_dir_path (str): Temporary EDM Hash Path
            input_file_dir (str): Input CSV File Path
            output_path (str): Path where all CSV files are located

        Raises:
            error: If there's an issue removing files.
        """
        try:
            if temp_edm_hash_dir_path and os.path.exists(
                temp_edm_hash_dir_path
            ):
                shutil.rmtree(temp_edm_hash_dir_path)
            if input_file_dir and os.path.exists(input_file_dir):
                shutil.rmtree(input_file_dir)
            if output_path and os.path.exists(output_path):
                for file in os.listdir(output_path):
                    file_path = os.path.join(output_path, file)
                    if os.path.isfile(file_path):
                        os.remove(file_path)
        except Exception as error:
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Error occurred while removing "
                    "csv files."
                ),
                details=traceback.format_exc(),
            )
            raise error

    def generate_csv_edm_hash(self, csv_file):
        """Generate EDM Hashes from sanitized data.

        Args:
            csv_file (str): The CSV file to generate EDM hashes from.

        Raises:
            MySQLDLPError: If an error occurs while generating EDM hashes.
        """
        try:
            self.logger.info(
                message=(f"{self.log_prefix}: Generating EDM Hashes.")
            )
            output_path = os.path.dirname(self.storage.get("csv_path"))

            good_csv_path = f"{output_path}/{csv_file}.good"
            input_file_dir = f"{output_path}/input"
            self.create_directory(dir_path=input_file_dir)
            input_csv_file = f"{input_file_dir}/{csv_file}.csv"
            shutil.move(good_csv_path, input_csv_file)

            if not os.path.isfile(input_csv_file):
                error_message = (
                    "Error occurred while generating "
                    "EDM Hash. Good file does not exist."
                )
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: {error_message}"
                    ),
                    resolution=(
                        "Ensure a valid query is provided in the "
                        "configuration."
                    ),
                )
                raise MySQLDLPError(
                    message=error_message
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
                    "input_csv": input_csv_file,
                    "norm_str": norm_str,
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
                raise MySQLDLPError(
                    message=(
                        "Plugin: MySQL EDM - Error occurred while "
                        "generating EDM Hash."
                    )
                )
        except MySQLDLPError:
            raise
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
            error_message = (
                "Error occurred while generating EDM Hash for MySQL data."
            )
            self.logger.error(
                message=(
                    f"{self.log_prefix}: {error_message}"
                ),
                details=traceback.format_exc(),
            )
            raise MySQLDLPError(
                value=error,
                message=error_message,
            ) from error

    def pull_sample_data(self):
        """
        Pull sample data from mysql database and store it in csv file.

        it only store records of sample size.

        Returns:
            list: list of column names from fetched data.
        """
        try:
            self.logger.debug(
                message=(
                    f"{self.log_prefix}: Pulling sample data."
                )
            )
            config = self.configuration.get("configuration", {})
            _ = self.storage.get("csv_path")
            self.delete_old_csv()
            mysql_data = self.pull_data(
                config=config, fetch_only_sample_data=True
            )

            # Validate column count
            is_valid_columns, column_error_message = (
                self.validate_column_count(mysql_data)
            )
            if not is_valid_columns:
                self.logger.error(
                    message=f"{self.log_prefix}: {column_error_message}",
                )
                raise MySQLDLPError(
                    message=column_error_message,
                )
            self.logger.debug(
                message=(
                    f"{self.log_prefix}: Successfully pulled sample data."
                )
            )

            return {"columns": mysql_data}
        except MySQLDLPError as error:
            raise error
        except Exception as error:
            error_message = "Error occurred while pulling data."
            self.logger.error(
                message=(
                    f"{self.log_prefix}: {error_message}"
                ),
                details=traceback.format_exc(),
            )
            raise MySQLDLPError(
                value=error, message=error_message
            ) from error

    def pull(self):
        """Pull data from MySQL Server and convert it to csv.

        Raises:
            error: _description_
            MySQLDLPError: _description_

        Returns:
            dict: returns success message
        """
        try:
            base_name = f"{self.name}_data"
            base_name = base_name.replace(" ", "_").replace("\t", "_")
            csv_name = f"{base_name}.csv"
            self.storage["csv_path"] = f"{FILE_PATH}/{self.name}/{csv_name}"
            self.storage["file_name"] = csv_name
            self.storage["sanitization_data_path"] = f"{FILE_PATH}/{self.name}"
            self.delete_old_csv()
            csv_file_path = self.storage.get("csv_path")
            config = self.configuration.get("configuration", {})
            is_unsanitized_data = self.configuration.get(
                "sanity_results", {}
            ).get("is_unsanitized_data", True)

            _ = self.pull_mysql_data(config)

            if is_unsanitized_data:
                if os.path.exists(csv_file_path):
                    os.rename(
                        csv_file_path,
                        f"{FILE_PATH}/{self.name}/{base_name}.good",
                    )
                    self.logger.debug(
                        message=(
                            f"{self.log_prefix}: Sanitization skipped for file"
                            f" '{csv_name}' as Proceed Without Sanitization "
                            "is enabled."
                        )
                    )
                else:
                    error_message = (
                        f"Data file doesn't exist at {csv_file_path}."
                    )
                    self.logger.error(
                        message=f"{self.log_prefix}: {error_message}",
                        resolution="Ensure a valid query is provided in"
                        " the configuration.",
                    )
                    raise MySQLDLPError(error_message)
            else:
                self.sanitize(base_name)
            self.generate_csv_edm_hash(csv_file=base_name)
            return {
                "message": "Data pulled and "
                "EDM Hash generated successfully."
            }

        except MySQLDLPError:
            raise
        except Exception as error:
            error_message = (
                "Error occurred while pulling, sanitizing and "
                "generating EDM Hash for MySQL data."
            )
            self.logger.error(
                message=(
                    f"{self.log_prefix}: {error_message}"
                ),
                details=traceback.format_exc(),
            )
            raise MySQLDLPError(
                value=error,
                message=error_message,
            ) from error

    def push(self, indicators=None, action_dict=None):
        """Plugin is not push supported.

        Raises:
            NotImplementedError: If the method is not implemented.
        """
        raise NotImplementedError()

    def validate(self, configuration):
        """
        Validate the plugin configuration parameters.

        Args:
            configuration (dict): Dictionary containing
            the plugin configuration parameters.

        Returns:
            ValidationResult: ValidationResult
            object with success flag and message.
        """
        self.logger.debug(
            message=(
                f"{self.log_prefix}: Validating configuration parameters."
            )
        )
        try:
            validation_result = (
                self.helper_object.validate_configuration_parameters(
                    configuration
                )
            )
            if not validation_result.success:
                return validation_result
            try:
                input_path = f"{FILE_PATH}/{self.name}/{SAMPLE_CSV_FILE_NAME}"
                self.storage.update({"csv_path": input_path})
                self.pull_sample_data()
                self.logger.debug(
                    message=(
                        f"{self.log_prefix}: Successfully validated "
                        "configuration parameters."
                    )
                )
            except MySQLDLPError as error:
                return ValidationResult(
                    success=False,
                    message=error.message,
                )
            except Exception:
                err_msg = (
                    "Error occurred while pulling sample data for validation."
                )
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: Validation error occurred. "
                        f"{err_msg}"
                    ),
                    resolution=(
                        "Ensure that the Server Hostname/IP, Username, "
                        "Password, Port and Database Name are correct and "
                        "the MySQL server is reachable."
                    ),
                    details=traceback.format_exc(),
                )
                return ValidationResult(
                    success=False,
                    message=err_msg,
                )
            self.logger.debug(
                message=(
                    f"{self.log_prefix}: Successfully validated "
                    "configuration parameters and connection with MySQL "
                    "database."
                )
            )
            return validation_result
        except Exception:
            error_message = (
                "Error occurred while establishing a connection to the "
                "database with the given parameters."
            )
            self.logger.error(
                message=(
                    f"{self.log_prefix}: {error_message}"
                ),
                resolution=(
                    "Ensure that the Server Hostname/IP, Username, Password, "
                    "Port and Database Name are correct and the MySQL server "
                    "is reachable."
                ),
                details=traceback.format_exc(),
            )
            return ValidationResult(
                success=False,
                message=error_message,
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
        self.logger.debug(
            message=f"{self.log_prefix}: Validation successful."
        )
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
        if name in MYSQL_EDM_FIELDS:
            fields = MYSQL_EDM_FIELDS[name]
            if name == "sanity_inputs":
                for field in fields:
                    if field["type"] == "sanitization_input":
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
                    if field["type"] == "sanitization_preview":
                        field["default"] = {
                            "sanitizationStatus": True,
                            "message": "Sanitization Done Successfully",
                        }
            return fields
        raise NotImplementedError()
