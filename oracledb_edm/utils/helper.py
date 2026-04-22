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

OracleDB EDM Plugin Helper file.
"""

import csv
import os
import re
import time
import traceback
import urllib

from sqlalchemy import create_engine, text
from sqlalchemy.exc import InterfaceError, ProgrammingError

from netskope.integrations.edm.plugin_base import ValidationResult
from netskope.integrations.edm.utils import CustomException as OracleDLPError

from .constants import BATCH_SIZE, SAMPLE_CSV_ROW_COUNT, SQL_KEYWORDS_TO_CHECK


def retry(
    error_class: Exception, count: int = 3, timeout: int = 30
) -> callable:
    """
    Retry executing a given function a specified number of times.

    In case of a specific error.

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


class OracleDBHelper:
    """OracleDB EDM Plugin Helper Class."""

    def __init__(self, logger, log_prefix) -> None:
        """Initialize method for OracleDBHelper class.

        Args:
            logger: Logger object for logging.
            log_prefix: Prefix for log messages.
        """
        self.logger = logger
        self.log_prefix = log_prefix

    @staticmethod
    def strip_args(data: dict):
        """Strip arguments from left and right directions.

        Args:
            data (dict): Dict object having all the
            Plugin configuration parameters.
        """
        keys = data.keys()
        for key in keys:
            if key != "password" and isinstance(data.get(key), str):
                data[key] = data.get(key).strip()

    def validate_configuration_parameters(
        self, configuration: dict
    ) -> ValidationResult:
        """Validate the configuration parameters for OracleDB connection.

        Args:
            configuration (dict): Configuration parameters dictionary.

        Returns:
            ValidationResult: Validation result object.
        """
        # Validate host
        host = configuration.get("host")
        if not host:
            err_msg = (
                "Server IP/Hostname is a required configuration parameter."
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
        if not isinstance(host, str) or not host.strip():
            err_msg = (
                "Invalid value provided for the configuration parameter "
                "Host."
            )
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Validation error occurred. {err_msg}"
                ),
                resolution=(
                    "Ensure that the Server IP/Hostname is a valid non-empty "
                    "string value."
                    ),
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
                    f"{self.log_prefix}: Validation error occurred. {err_msg}"
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
                    f"{self.log_prefix}: Validation error occurred. {err_msg}"
                    ),
                resolution=(
                    "Ensure that the Username is a non-empty "
                    "string value."
                ),
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
                    f"{self.log_prefix}: Validation error occurred. {err_msg}"
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
                    f"{self.log_prefix}: Validation error occurred. {err_msg}"
                    ),
                resolution=(
                    "Ensure that the Password is a non-empty "
                    "string value."
                ),
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )

        # Validate database name
        dbname = configuration.get("dbname")
        if not dbname:
            err_msg = "SID is a required configuration parameter."
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Validation error occurred. {err_msg}"
                ),
                resolution="Ensure that a valid SID is provided.",
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        if not isinstance(dbname, str) or not dbname.strip():
            err_msg = (
                "Invalid value provided for the configuration parameter "
                "SID."
            )
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Validation error occurred. {err_msg}"
                ),
                resolution=(
                    "Ensure that the SID is a non-empty "
                    "string value."
                ),
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )

        # Validate port
        port = configuration.get("port")
        if port is not None and port != "":
            if not isinstance(port, int) or not (0 < port < 65536):
                err_msg = "Port should be an integer between 1 and 65535."
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: Validation error occurred. "
                        f"{err_msg}"
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

        # Validate query format
        query = configuration.get("query", "")
        is_valid_query, query_error_message = self.validate_query_format(query)
        if not is_valid_query:
            self.logger.error(
                message=f"{self.log_prefix}: Validation error occurred. "
                f"{query_error_message}",
                resolution="Ensure that a valid SQL query is provided.",
            )
            return ValidationResult(
                success=False,
                message=query_error_message,
            )

        # Validate no DML operations in query
        is_valid_dml, dml_error_message = self.validate_no_dml_in_query(query)
        if not is_valid_dml:
            self.logger.error(
                message=f"{self.log_prefix}: Validation error occurred. "
                f"{dml_error_message}",
                resolution=(
                    "Ensure that a read-only query without database "
                    "modification operations is provided."
                ),
            )
            return ValidationResult(
                success=False,
                message=dml_error_message,
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
        return ValidationResult(success=True, message=message)

    def validate_query_format(self, query: str) -> tuple:
        """Validate if the query is properly formatted and exists.

        Args:
            query (str): SQL query to validate

        Returns:
            tuple: (is_valid, error_message) where is_valid is a boolean
               and error_message is a string
        """
        if not query or not isinstance(query, str) or query.strip() == "":
            return False, "Invalid Query provided."
        return True, ""

    def validate_no_dml_in_query(self, query: str) -> tuple:
        """Validate that the query does not contain any DML operations.

        Args:
            query (str): SQL query to validate

        Returns:
            tuple: (is_valid, error_message) where is_valid is a boolean
                and error_message is a string
        """
        sql_query_pattern = re.compile(
            rf"""
            (?P<quoted_identifier> "[^"]+" )
            | \b(?:{"|" .join(map(re.escape, SQL_KEYWORDS_TO_CHECK))})\b
        """,
            flags=re.IGNORECASE | re.VERBOSE,
        )

        if any(
            matched_word
            for matched_word in sql_query_pattern.finditer(query)
            if not matched_word.group("quoted_identifier")
        ):
            return False, (
                "Provided query may contain "
                "database modification operation. "
                "Use a read-only query."
            )
        return True, ""

    def validate_column_count(self, columns: list) -> tuple:
        """
        Validate that the number of columns.

        The query result is not more than 25.

        Args:
            columns (list): List of column names from the query result

        Returns:
            tuple: (is_valid, error_message) where is_valid is a boolean
                and error_message is a string
        """
        if columns and len(columns) > 25:
            error_message = (
                "Maximum 25 columns allowed. Reduce the number "
                "of columns in your query and try again."
            )
            return False, error_message
        return True, ""

    def create_connection_string(self, config: dict) -> str:
        """
        Create a OracleDB database connection.

        Connection string is based on the provided configuration.

        Args:
            config (dict): A dictionary containing
                        database connection configuration parameters.
                        Requires 'username', 'password',
                        'host', 'port', and 'dbname' keys.

        Returns:
            str: The constructed OracleDB database connection string.
        """
        self.strip_args(config)

        port = f":{config.get('port', '')}" if config.get("port") else ""

        # Extract domain from host if user enters url
        host = re.findall(
            pattern=r"^(?:https?:\/\/)?(?:[^@\/\n]+@)?(?:www\.)?([^\:\/?\n]+)",
            string=config.get("host", ""),
        )[0]

        # Parsing special characters like '@', ':' in username and password
        username = urllib.parse.quote_plus(config.get("username", ""))
        password = urllib.parse.quote_plus(config.get("password", ""))

        conn_str = (
            f"oracle+oracledb://{username}:"
            f"{password}@{host}"
            f"{port}/{config.get('dbname', '')}"
        )
        return conn_str

    def verify_connection(self, configuration: dict) -> ValidationResult:
        """Verify the connection with OracleDB database.

        Args:
            configuration: parameter configuration dictionary.

        Returns:
            ValidationResult: Validation result object.
        """
        host = configuration.get("host", "")
        try:
            connection_string = self.create_connection_string(configuration)
            eng = create_engine(connection_string)
            with eng.connect() as connection:
                # Test connection with read-only transaction
                connection.execute(text("SELECT 1 FROM DUAL"))

            message = (
                f"Successfully verified connection "
                f"with the OracleDB database '{host}'."
            )
            self.logger.debug(message=f"{self.log_prefix}: {message}")
            return ValidationResult(
                success=True,
                message=message,
            )
        except Exception as error:
            error_message = (
                "Error occurred while connecting with remote server. "
                "Verify that the Server IP/Hostname, Username, "
                "Password, Port and SID are correct."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {error_message}",
                resolution=(
                    "Ensure that the Server IP/Hostname, Port, "
                    "Username, Password and SID are correct. "
                    "Ensure the database server is reachable and accessible."
                ),
                details=traceback.format_exc(),
            )
            return ValidationResult(
                success=False,
                message=error_message,
            )

    def store_data_to_csv(
        self, oracledb_data: list, csv_path: str, replace: bool = True
    ):
        """
        Store fetched OracleDB data to csv file.

        Args:
            oracledb_data (list): data fetched from Oracle database.
            csv_path (string): path where csv data file will be stored.
            replace (bool): Whether to replace existing file.

        Raises:
            OracleDLPError: If any error in storing data to CSV.
        """
        try:
            if replace and os.path.isfile(csv_path):
                os.remove(csv_path)

            # Create directory if it doesn't exist
            dir_path = os.path.dirname(csv_path)
            if not os.path.exists(dir_path):
                os.makedirs(dir_path)

            with open(
                csv_path, "w" if replace else "a", encoding="UTF-8"
            ) as file_pointer:
                csv_pointer = csv.writer(file_pointer)
                for row in oracledb_data:
                    csv_pointer.writerow(row)
        except OracleDBHelper:
            raise
        except Exception as error:
            err_msg = (
                "Error occurred while storing pulled OracleDB data to "
                "CSV file. Ensure the file path is valid and the directory "
                "has write permissions."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=traceback.format_exc(),
            )
            raise OracleDLPError(value=error, message=err_msg) from error

    def pull_data(
        self, config: dict, csv_path: str, fetch_only_sample_data: bool = False
    ) -> list:
        """Create connection and fetch data from database.

        Args:
            config (dict): plugin configuration
            csv_path (str): Path to store CSV file
            fetch_only_sample_data (bool, optional):
            Flag for fetching sample data. Defaults to False.

        Raises:
            InterfaceError: If there's an issue connecting to database.
            OracleDLPError: If there's an issue fetching
                data from database.

        Returns:
            list: list of column names from the query result
        """
        try:
            # Validate query format
            query = config.get("query", "")
            is_valid_query, query_error_message = self.validate_query_format(
                query
            )
            if not is_valid_query:
                err_msg = query_error_message
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg}",
                    resolution="Provide a valid SQL query.",
                )
                raise OracleDLPError(message=err_msg)

            # Validate no DML operations in query
            is_valid_dml, dml_error_message = self.validate_no_dml_in_query(
                query
            )
            if not is_valid_dml:
                err_msg = dml_error_message
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg}",
                    resolution=(
                        "Use a read-only query without database "
                        "modification operations."
                    ),
                )
                raise OracleDLPError(message=err_msg)

            connection_string = self.create_connection_string(config)
            if not csv_path:
                err_msg = "CSV path is not configured."
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg}",
                    resolution="Ensure the CSV path is properly configured.",
                )
                raise OracleDLPError(message=err_msg)

            eng = create_engine(connection_string)
            with eng.connect() as connection:
                # User is only able to execute read only queries
                connection.execute(text("SET TRANSACTION READ ONLY"))
                query_text = text(query.strip(";"))
                result = connection.execute(query_text)
                columns = list(result.keys())

                # Validate column count
                is_valid_columns, column_error_message = (
                    self.validate_column_count(columns)
                )
                if not is_valid_columns:
                    err_msg = column_error_message
                    self.logger.error(
                        message=f"{self.log_prefix}: {err_msg}",
                        resolution=(
                            "Reduce the number of columns in your query "
                            "to 25 or fewer."
                        ),
                    )
                    raise OracleDLPError(message=err_msg)

                self.store_data_to_csv([columns], csv_path)
                if fetch_only_sample_data:
                    rows = result.fetchmany(SAMPLE_CSV_ROW_COUNT)
                else:
                    rows = result.yield_per(BATCH_SIZE)
                self.store_data_to_csv(rows, csv_path, replace=False)
            return columns
        except InterfaceError as error:
            err_msg = (
                "Failed to connect to OracleDB database."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                resolution=(
                    "Ensure that the database host, port, username, "
                    "password and database name are correct and the "
                    "database server is reachable."
                ),
                details=traceback.format_exc(),
            )
            raise OracleDLPError(value=error, message=err_msg) from error
        except ProgrammingError as error:
            err_msg = (
                "Error occurred while executing Query."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                resolution=(
                    "Ensure the SQL query is valid and properly formatted."
                ),
                details=traceback.format_exc(),
            )
            raise OracleDLPError(
                value=error,
                message="Error occurred while executing Query.",
            ) from error
        except OracleDLPError as error:
            raise error
        except Exception as error:
            err_msg = "Error occurred while pulling OracleDB data."
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

    @retry(error_class=InterfaceError)
    def pull_oracledb_data(
        self, config: dict, csv_path: str, fetch_only_sample_data: bool = False
    ) -> list:
        """
        Pull data from OracleDB with retry logic.

        Args:
            config (dict): plugin configuration
            csv_path (str): Path to store CSV file
            fetch_only_sample_data (bool): Flag for fetching sample data

        Raises:
            OracleDLPError: If there's an issue fetching data from database.

        Returns:
            list: list of column names from the query result
        """
        try:
            if not fetch_only_sample_data:
                self.logger.info(f"{self.log_prefix}: Pulling OracleDB data.")
            data = self.pull_data(
                config=config,
                csv_path=csv_path,
                fetch_only_sample_data=fetch_only_sample_data,
            )
            if not fetch_only_sample_data:
                self.logger.info(
                    f"{self.log_prefix}: Successfully pulled OracleDB data."
                )
            return data
        except OracleDLPError:
            raise
        except Exception as error:
            err_msg = "Error occurred while pulling OracleDB data."
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=traceback.format_exc(),
            )
            raise OracleDLPError(value=error, message=err_msg) from error
