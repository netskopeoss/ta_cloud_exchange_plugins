"""Microsoft SQL EDM Plugin.

Microsoft SQL EDM Plugin is used to pull data from Microsoft SQL server, store
it in CSV format, perform sanitization and EDM Hash Generation from the same.
"""

import csv
import os
import re
import shutil
import time
import traceback
from copy import deepcopy
from typing import List

# Third-party libraries
from sqlalchemy import create_engine, text, URL
from sqlalchemy.exc import InterfaceError, ProgrammingError

from netskope.integrations.edm.models import Action, ActionWithoutParams
from netskope.integrations.edm.plugin_base import PluginBase, ValidationResult
from netskope.integrations.edm.utils import CONFIG_TEMPLATE, FILE_PATH
from netskope.integrations.edm.utils import CustomException as MicrosoftSQLDLPError
from netskope.integrations.edm.utils import run_sanitizer
from netskope.integrations.edm.utils.constants import EDM_HASH_CONFIG
from netskope.integrations.edm.utils.edm.hash_generator.edm_hash_generator import (
    generate_edm_hash,
)
from .utils.constants import (
    MICROSOFT_SQL_EDM_FIELDS,
    BATCH_SIZE,
    CONNECTION_TIMEOUT,
    MODULE_NAME,
    PLUGIN_NAME,
    PLUGIN_VERSION,
    SAMPLE_CSV_ROW_COUNT,
    SQL_MODIFICATION_KEYWORDS,
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


# User-Defined Wrapper ##
def retry(error_class: Exception, count: int = 3, timeout: int = 30) -> callable:
    """Retry executing a given function a specified number of times in case of a specific error.

    Args:
        error_class (Exception): Any exception class.
        count (int, optional): Number of retries. Defaults to 3.
        timeout (int, optional): Time interval (in seconds)
                        between retries. Defaults to 30.

    Raises:
        error_class: Any exception class.

    Returns:
        wrapped_function: Wrapped function.
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


class MSSQLPlugin(PluginBase):
    """Microsoft SQL EDM plugin is used to pull SQL data from configured \
    SQL server, store it in CSV format to perform sanitization \
    and EDM Hash Generation on pulled data."""

    def __init__(
        self,
        name,
        *args,
        **kwargs,
    ):
        """Microsoft SQL plugin initializer.

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
            manifest_json = MSSQLPlugin.metadata
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
        elif step == "sanity_results":
            result = ValidationResult(
                success=True,
                message="Step validated successfully.",
            )
        return result

    @staticmethod
    def strip_args(data: dict):
        """Strip arguments from left and right directions.

        Args:
            data (dict): Dict object having all the
            Plugin configuration parameters.
        """
        keys = data.keys()
        for key in keys:
            if isinstance(data[key], str):
                data[key] = data[key].strip()

    def create_directory(self, dir_path: str):
        """Create a directory at the specified path, including all necessary parent directories.

        Args:
            dir_path (string): The path of the directory to be created.

        Raises:
            Exception: If there's an issue creating the directory.
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

    def create_connection_string(self, config: dict) -> str:
        """Create a Microsoft SQL database connection string based on the provided configuration.

        Args:
            config (dict): A dictionary containing
                        database connection configuration parameters.
                        Requires 'username', 'password',
                        'host', 'port', and 'dbname' keys.

        Returns:
            str: The constructed Microsoft SQL database connection string.
        """
        self.strip_args(config)

        return URL.create(
            "mssql+pyodbc",
            username=config["username"],
            password=config["password"],
            host=config["host"],
            port=config["port"],
            database=config["dbname"],
            query={"driver": "ODBC Driver 18 for SQL Server"},
        )

    def delete_old_csv(self):
        """Delete old csv files at the start of pull method."""
        csv_path = self.storage["csv_path"]
        if os.path.exists(csv_path):
            os.remove(csv_path)

    def validate_port(self, port: str) -> bool:
        """Validate Provided port.

        Args:
            port (string): Provided port

        Returns:
            bool: True if port is between 0 and 65536 and False otherwise.
        """
        if 0 < int(port) < 65536:
            return True
        return False

    def validate_query_format(self, query: str) -> tuple:
        """Validate if the query is properly formatted and exists.

        Args:
            query (str): SQL query to validate

        Returns:
            tuple: (is_valid, error_message) where is_valid is a boolean and error_message is a string
        """
        if not query or not isinstance(query, str) or query.strip() == "":
            return False, "Invalid Query provided."
        return True, ""

    def validate_no_dml_in_query(self, query: str) -> tuple:
        """Validate that the query does not contain any DML operations.

        Args:
            query (str): SQL query to validate

        Returns:
            tuple: (is_valid, error_message) where is_valid is a boolean and error_message is a string
        """
        sql_query_pattern = re.compile(
            rf"""
            (?P<quoted_identifier> \[[^\]]+\] )
            | \b(?:{"|" .join(map(re.escape, SQL_MODIFICATION_KEYWORDS))})\b
        """,
            flags=re.IGNORECASE | re.VERBOSE,
        )

        if any(
            matched_word
            for matched_word in sql_query_pattern.finditer(query)
            if not matched_word.group("quoted_identifier")
        ):
            return False, (
                "Error: Provided query may contain "
                "database modification operation. Please use a read-only query."
            )
        return True, ""

    def validate_column_count(self, columns: list) -> tuple:
        """Validate that the number of columns in the query result is not more than 25.

        Args:
            columns (list): List of column names from the query result

        Returns:
            tuple: (is_valid, error_message) where is_valid is a boolean and error_message is a string
        """
        if columns and len(columns) > 25:
            error_message = (
                "Maximum 25 columns allowed. Please reduce the number "
                "of columns in your query and try again."
            )
            return False, error_message
        return True, ""

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
            MicrosoftSQLDLPError: If validation fails due to incorrect data or missing data.

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
                    raise ValueError("Provided query should return atleast one record.")

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
            raise MicrosoftSQLDLPError(value=error, message=str(error)) from error

    def store_data_to_csv(self, mssql_data: list, csv_path: str):
        """
        Store fetched Microsoft SQL data to csv file.

        Args:
            mssql_data (list): sql data fetched from database.
            csv_path (string): location to store csv data file at.

        Raises:
            Exception: If any error in storing data to CSV.
        """
        try:
            self.create_directory(dir_path=os.path.dirname(csv_path))
            with open(csv_path, "a", encoding="UTF-8") as file_pointer:
                csv_pointer = csv.writer(file_pointer)
                for row in mssql_data:
                    csv_pointer.writerow(row)
        except Exception as error:
            self.logger.error(
                message=(
                    f"{self.log_prefix} Error occurred while storing fetched "
                    "Microsoft SQL data to CSV file."
                ),
                details=traceback.format_exc(),
            )
            raise error

    def pull_data(self, config: dict, fetch_only_sample_data: bool = False) -> list:
        """Create connection and fetch data from database.

        Args:
            config (dict): plugin configuration
            fetch_only_sample_data (bool, optional):Flag for fetching sample data. \
                Defaults to False.

        Raises:
            InterfaceError: If there's an issue connecting to database.
            MicrosoftSQLDLPError: If there's an issue fetching data from database.

        Returns:
            list: list of data fetched from database
        """
        try:
            # Validate query format
            is_valid_query, query_error_message = self.validate_query_format(
                config.get("query", "")
            )
            if not is_valid_query:
                self.logger.error(message=f"{self.log_prefix} {query_error_message}")
                raise MicrosoftSQLDLPError(
                    message=f"{self.log_prefix} {query_error_message}"
                )

            # Validate no DML operations in query
            is_valid_dml, dml_error_message = self.validate_no_dml_in_query(
                config["query"]
            )
            if not is_valid_dml:
                self.logger.error(message=f"{self.log_prefix} {dml_error_message}")
                raise MicrosoftSQLDLPError(
                    message=f"{self.log_prefix} {dml_error_message}"
                )

            connection_string = self.create_connection_string(config)
            csv_path = self.storage["csv_path"]
            eng = create_engine(
                connection_string,
                connect_args={
                    "connect_timeout": CONNECTION_TIMEOUT,
                    "TrustServerCertificate": "yes",
                },
            )  # creates connection with database.
            with eng.connect() as connection:
                # used to stop user from executing any database modification query.
                query = text(config["query"])
                result = connection.execute(query)
                columns = list(result.keys())

                # Validate column count
                is_valid_columns, column_error_message = self.validate_column_count(
                    columns
                )
                if not is_valid_columns:
                    self.logger.error(
                        message=f"{self.log_prefix} {column_error_message}",
                    )
                    raise MicrosoftSQLDLPError(
                        message=f"{self.log_prefix} {column_error_message}",
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
        except InterfaceError as error:
            self.logger.error(
                message=(
                    f"{self.log_prefix} InterfaceError occurred when connecting to "
                    "Microsoft SQL Database."
                ),
                details=traceback.format_exc(),
            )
            raise error  # if there is any connection error
        except ProgrammingError as error:  # if there is any error while executing query
            self.logger.error(
                message=f"{self.log_prefix} ProgrammingError occurred while executing Microsoft SQL query.",
                details=traceback.format_exc(),
            )
            raise MicrosoftSQLDLPError(
                value=error,
                message="Error occurred while executing Microsoft SQL query.",
            ) from error
        except MicrosoftSQLDLPError as error:
            raise error
        except Exception as error:
            self.logger.error(
                message=f"{self.log_prefix} Error occurred while fetching Microsoft SQL data.",
                details=traceback.format_exc(),
            )
            raise MicrosoftSQLDLPError(
                value=error, message="Error occurred while fetching Microsoft SQL data."
            ) from error

    @retry(error_class=InterfaceError)
    def pull_mssql_data(self, config: dict) -> list:
        """Define the separate method since we need to retry in case of pulling all data from Microsoft SQL.

        Args:
            config (dict): plugin configuration

        Raises:
            Exception: If there's an issue fetching data from database.

        Returns:
            list: list of data fetched from database
        """
        try:
            self.logger.info(
                message=f"{self.log_prefix} Fetching Microsoft SQL data for configuration '{self._name}'."
            )
            data = self.pull_data(config=config, fetch_only_sample_data=False)
            self.logger.info(
                message=(
                    f"{self.log_prefix} Microsoft SQL data fetched"
                    + f" successfully for configuration '{self._name}'."
                )
            )
            return data
        except Exception as error:
            raise error

    def sanitize(self, file_name: str = "", sample_data: bool = False):
        """Sanitizes csv data and store good and bad files using run_sanitizer.

        Args:
            file_name (str, optional): filename to use for generated good and bad csv. Defaults to "".

        Raises:
            MicrosoftSQLDLPError: If an error occurs during
            the sanitization process.
        """
        try:
            self.logger.info(
                message=f"{self.log_prefix} Sanitizing Microsoft SQL data for configuration '{self._name}'."
            )
            fields = self.configuration.get("sanity_inputs", {}).get(
                "sanitization_input", {}
            )

            exclude_stopwords = self.configuration.get("sanity_inputs", {}).get(
                "exclude_stopwords", False
            )

            for field in fields:  # strips spaces from front and end for all values.
                self.strip_args(field)

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

            csv_path = self.storage["csv_path"]
            output_path = self.storage["sanitization_data_path"]
            file_path = f"{output_path}/{file_name}"

            if not os.path.isfile(csv_path):
                self.logger.error(
                    message=f"{self.log_prefix} Error occurred while performing EDM sanitization."
                    + "Microsoft SQL data file does not exist.",
                )
                raise MicrosoftSQLDLPError(
                    message="Error occurred while performing Microsoft SQL data sanitization."
                )

            # Remove existing sanitized and non-sanitized files if they exist
            for file_extension in ["good", "bad"]:
                existing_file = f"{file_path}.{file_extension}"
                if os.path.isfile(existing_file):
                    os.remove(existing_file)

            self.create_directory(dir_path=os.path.dirname(output_path))
            run_sanitizer(csv_path, file_path, edm_data_config)
            self.logger.info(
                message=(
                    f"{self.log_prefix} Microsoft SQL data sanitized successfully for "
                    f"configuration '{self._name}'."
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
                    f"{self.log_prefix} Error occurred while performing sanitization of "
                    "Microsoft SQL data."
                ),
                details=traceback.format_exc(),
            )
            raise MicrosoftSQLDLPError(
                value=error,
                message="Error occurred while performing sanitization of Microsoft SQL data.",
            ) from error

    def get_field_indices(self, sanity_inputs: dict) -> tuple:
        """Get the indices of fields based on normalization and sensitivity.

        Args:
            sanity_inputs (dict): Sanitization inputs with field info.

        Returns:
            tuple: A tuple containing the indices of string fields that are case-sensitive,
            indices of string fields that are case-insensitive, and indices of number fields.
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
            raise MicrosoftSQLDLPError(
                "Error occurred while getting "
                "indices from sanity input fields based on normalization and sensitivity."
            ) from error

    def remove_files(
        self,
        temp_edm_hash_dir_path: str = "",
        input_file_dir: str = "",
        output_path: str = "",
    ):
        """Remove csv files and temp EDM hashes after EDM hash generation.

        Args:
            temp_edm_hash_dir_path (str): Temporary EDM Hash Path
            input_file_dir (str): Input CSV File Path
            output_path (str): Path where all CSV files are located

        Raises:
            Exception: If there's an issue removing files.
        """
        try:
            if temp_edm_hash_dir_path and os.path.exists(temp_edm_hash_dir_path):
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
                message=f"{self.log_prefix} Error occurred while removing"
                + "csv files.",
                details=traceback.format_exc(),
            )
            raise error

    def generate_csv_edm_hash(self, csv_file: str):
        """Generate EDM Hashes from sanitized data.

        Args:
            csv_file (str): CSV file name.

        Raises:
            MicrosoftSQLDLPError: If an error occures while
            generating EDM hashes.
        """
        try:
            self.logger.info(
                message=f"{self.log_prefix} Generating EDM Hash "
                + f"for configuration '{self._name}' of Microsoft SQL EDM Plugin."
            )
            output_path = os.path.dirname(self.storage["csv_path"])

            good_csv_path = f"{output_path}/{csv_file}.good"
            input_file_dir = f"{output_path}/input"
            self.create_directory(dir_path=input_file_dir)
            input_csv_file = f"{input_file_dir}/{csv_file}.csv"
            shutil.move(good_csv_path, input_csv_file)

            if not os.path.isfile(input_csv_file):
                self.logger.error(
                    message=f"{self.log_prefix} Error occurred while generating "
                    "EDM Hash. Good file does not exist for "
                    + f"configuration '{self._name}' of Microsoft SQL EDM Plugin.",
                )
                raise MicrosoftSQLDLPError(
                    message="Error occurred while generating "
                    "EDM Hash of Microsoft SQL EDM Plugin."
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
                    message=f"{self.log_prefix} EDM Hash generated successfully "
                    + f"for configuration '{self._name}' of Microsoft SQL EDM Plugin."
                )
            else:
                self.storage["edm_hash_available"] = False
                raise MicrosoftSQLDLPError(
                    message="Plugin: Microsoft SQL EDM - Error occurred while generating EDM Hash "
                    + f"for configuration '{self._name}' of Microsoft SQL EDM Plugin."
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
                "EDM Hash for Microsoft SQL data.",
                details=traceback.format_exc(),
            )
            raise MicrosoftSQLDLPError(
                value=error,
                message="Error occurred while generating "
                "EDM Hash of Microsoft SQL data.",
            ) from error

    def pull_sample_data(self):
        """Pull sample data from Microsoft SQL database and store it in csv file.

        It only store records of sample size.

        Raises:
            MicrosoftSQLDLPError: If any error occurs in sample data pulling.

        Returns:
            list: list of column names from fetched data.
        """
        try:
            self.logger.debug(
                message=f"{self.log_prefix} Executing pull sample data method for Microsoft SQL EDM plugin."
            )
            config = self.configuration.get("configuration", {})
            _ = self.storage["csv_path"]
            self.delete_old_csv()
            mssql_data = self.pull_data(config=config, fetch_only_sample_data=True)

            # Validate column count
            is_valid_columns, column_error_message = self.validate_column_count(
                mssql_data
            )
            if not is_valid_columns:
                self.logger.error(
                    message=f"{self.log_prefix} {column_error_message}",
                )
                raise MicrosoftSQLDLPError(
                    message=f"{self.log_prefix} {column_error_message}",
                )

            self.logger.debug(
                message=f"{self.log_prefix} Executed pull sample data method for Microsoft SQL EDM plugin."
            )

            return {"columns": mssql_data}
        except MicrosoftSQLDLPError as error:
            raise error
        except Exception as error:
            self.logger.error(
                message=f"{self.log_prefix} Error occurred while pulling data.",
                details=traceback.format_exc(),
            )
            raise MicrosoftSQLDLPError(
                value=error, message="Error occurred while pulling data."
            ) from error

    def pull(self):
        """Pull data from Microsoft SQL Server and convert it to csv.

        Raises:
            MicrosoftSQLDLPError: If any error occurs while the data pulling.

        Returns:
            dict: returns success message
        """
        try:
            base_name = f"{self.name}_data"
            base_name = base_name.replace(" ", "_").replace("\t", "_").replace("-", "_")
            csv_name = f"{base_name}.csv"
            self.storage["csv_path"] = f"{FILE_PATH}/{self.name}/{csv_name}"
            self.storage["file_name"] = csv_name
            self.storage["sanitization_data_path"] = f"{FILE_PATH}/{self.name}"
            self.delete_old_csv()

            csv_file_path = self.storage["csv_path"]
            config = self.configuration.get("configuration", {})
            is_unsanitized_data = self.configuration.get("sanity_results", {}).get(
                "is_unsanitized_data", True
            )

            _ = self.pull_mssql_data(config)
            if is_unsanitized_data:
                if os.path.exists(csv_file_path):
                    os.rename(
                        csv_file_path, f"{FILE_PATH}/{self.name}/{base_name}.good"
                    )
                    self.logger.debug(
                        f"{self.log_prefix} Do not perform any data sanitization."
                    )
                else:
                    error_message = f"Data file doesn't exist at {csv_file_path}."
                    self.logger.error(message=f"{self.log_prefix} {error_message}")
                    raise MicrosoftSQLDLPError(error_message)
            else:
                self.sanitize(base_name)
            self.generate_csv_edm_hash(csv_file=base_name)
            return {"message": "Data pulled and " + "EDM Hash generated successfully."}

        except MicrosoftSQLDLPError as error:
            self.logger.error(
                message=f"{self.log_prefix} Error occurred while pulling, "
                "sanitizing and generating EDM Hash for Microsoft SQL data."
            )
            raise error
        except Exception as error:
            self.logger.error(
                message=f"{self.log_prefix} Error occurred while pulling, "
                "sanitizing and generating EDM Hash for Microsoft SQL data.",
                details=traceback.format_exc(),
            )
            raise MicrosoftSQLDLPError(
                value=error,
                message="Error occurred while pulling, "
                "sanitizing and generating EDM Hash for Microsoft SQL data.",
            ) from error

    def push(self, source_config_name: str = "", action_dict: dict = {}):
        """Plugin is not push supported.

        Args:
            source_config_name (str, optional): Source config name. Defaults to "".
            action_dict (dict, optional): Action dictionary. Defaults to {}.

        Raises:
            NotImplementedError: If the method is not implemented.
        """
        raise NotImplementedError()

    def validate(self, configuration: dict) -> ValidationResult:
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
            message=f"{self.log_prefix} Executing validate method for Microsoft SQL EDM plugin."
        )
        try:
            db_config = configuration.get("configuration", {})
            self.strip_args(db_config)

            if (
                ("host" not in db_config)
                or (not db_config["host"])
                or (not isinstance(db_config["host"], str))
                or (db_config["host"].strip() == "")
            ):
                self.logger.error(
                    f"{self.log_prefix} Validation error occurred for Microsoft SQL EDM plugin."
                    "Error: Invalid Database Host provided."
                )
                return ValidationResult(
                    success=False,
                    message="Invalid Host provided.",
                )

            if (
                ("username" not in db_config)
                or (not db_config["username"])
                or (not isinstance(db_config["username"], str))
                or db_config["username"].strip() == ""
            ):
                self.logger.error(
                    f"{self.log_prefix} Validation error occurred for Microsoft SQL EDM plugin."
                    "Error: Invalid Database Username provided."
                )
                return ValidationResult(
                    success=False,
                    message="Invalid Username provided.",
                )

            if (
                ("password" not in db_config)
                or (not db_config["password"])
                or (not isinstance(db_config["password"], str))
                or db_config["password"].strip() == ""
            ):
                self.logger.error(
                    f"{self.log_prefix} Validation error occurred for Microsoft SQL EDM plugin."
                    "Error: Invalid Database Password provided."
                )
                return ValidationResult(
                    success=False,
                    message="Invalid Password provided.",
                )

            # Validate query format
            is_valid_query, query_error_message = self.validate_query_format(
                db_config.get("query", "")
            )
            if not is_valid_query:
                self.logger.error(
                    f"{self.log_prefix} Validation error occurred for Microsoft SQL EDM plugin. "
                    f"Error: {query_error_message}"
                )
                return ValidationResult(
                    success=False,
                    message=query_error_message,
                )

            # Validate no DML operations in query
            is_valid_dml, dml_error_message = self.validate_no_dml_in_query(
                db_config["query"]
            )
            if not is_valid_dml:
                self.logger.error(
                    f"{self.log_prefix} Validation error occurred for Microsoft SQL EDM plugin. "
                    f"Error: {dml_error_message}"
                )
                return ValidationResult(
                    success=False,
                    message=dml_error_message,
                )

            if (
                ("dbname" not in db_config)
                or (not db_config["dbname"])
                or (not isinstance(db_config["dbname"], str))
                or db_config["dbname"].strip() == ""
            ):
                self.logger.error(
                    f"{self.log_prefix} Validation error occurred for Microsoft SQL EDM plugin."
                    "Error: Invalid Database Name provided."
                )
                return ValidationResult(
                    success=False,
                    message="Invalid Database Name provided.",
                )

            if not self.validate_port(db_config["port"]):
                self.logger.error(
                    f"{self.log_prefix} Validation error occurred for Microsoft SQL EDM plugin."
                    "Error: Invalid Port provided."
                )
                return ValidationResult(
                    success=False,
                    message="Invalid Port provided.",
                )

            try:
                connection_string = self.create_connection_string(db_config)
                eng = create_engine(
                    connection_string,
                    connect_args={
                        "connect_timeout": CONNECTION_TIMEOUT,
                        "TrustServerCertificate": "yes",
                    },
                )
                with eng.connect() as connection:
                    # Execute the query to validate column count
                    query = text(db_config["query"])
                    result = connection.execute(query)
                    columns = list(result.keys())

                    # Validate column count
                    is_valid_columns, column_error_message = self.validate_column_count(
                        columns
                    )
                    if not is_valid_columns:
                        self.logger.error(
                            f"{self.log_prefix} Validation error occurred for Microsoft SQL EDM plugin. "
                            f"Error: {column_error_message}"
                        )
                        return ValidationResult(
                            success=False,
                            message=column_error_message,
                        )
            except InterfaceError as error:
                error_message = f"Connection error: {str(error)}"
                self.logger.error(
                    f"{self.log_prefix} {error_message}",
                    details=traceback.format_exc(),
                )
                return ValidationResult(
                    success=False,
                    message=error_message,
                )
            except ProgrammingError as error:
                error_message = f"SQL query error: {str(error)}"
                self.logger.error(
                    f"{self.log_prefix} {error_message}",
                    details=traceback.format_exc(),
                )
                return ValidationResult(
                    success=False,
                    message=error_message,
                )

            self.logger.debug(
                message=(
                    f"{self.log_prefix} Executed validate method for "
                    "Microsoft SQL EDM plugin successfully."
                )
            )
            return ValidationResult(
                success=True,
                message="Connection with Microsoft SQL database verified successfully.",
            )
        except Exception:
            self.logger.error(
                message=f"{self.log_prefix} Couldn't establish a connection to"
                " the database with the given parameters",
                details=traceback.format_exc(),
            )
            return ValidationResult(
                success=False,
                message="Couldn't establish a connection to the database with the given parameters.",
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

    def get_fields(self, name: str, configuration: dict):
        """Get fields configuration based on the specified protocol.

        Args:
            name (str): The name of the field configuration to retrieve
            configuration (dict): Configuration parameters dictionary.

        Raises:
            NotImplementedError: If a field configuration with the specified name
                is not implemented.

        Returns:
            str: List of configuration parameters.
        """

        if name in MICROSOFT_SQL_EDM_FIELDS:
            fields = MICROSOFT_SQL_EDM_FIELDS[name]
            if name == "sanity_inputs":
                for field in fields:
                    if field["type"] == "sanitization_input":
                        input_path = f"{FILE_PATH}/{self.name}/sample.csv"
                        self.storage.update({"csv_path": input_path})
                        field["default"] = self.pull_sample_data()
            elif name == "sanity_results":
                for field in fields:
                    if field["type"] == "sanitization_preview":
                        input_path = f"{FILE_PATH}/{self.name}/sample.csv"
                        output_path = f"{FILE_PATH}/{self.name}"
                        self.storage.update(
                            {
                                "csv_path": input_path,
                                "sanitization_data_path": output_path,
                            }
                        )
                        self.sanitize(file_name="sample", sample_data=True)
                        field["default"] = {
                            "sanitizationStatus": True,
                            "message": "Sanitization Done Successfully",
                        }
            return fields
        raise NotImplementedError()
