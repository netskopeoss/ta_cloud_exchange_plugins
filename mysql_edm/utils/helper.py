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

MySQL Plugin Helper file.
"""

# Built-in libraries
import urllib
import re
import traceback

from netskope.integrations.edm.plugin_base import ValidationResult
from ..utils.constants import SQL_KEYWORDS_TO_CHECK


class MySQLPluginHelper:
    """MySQL Plugin Class.

    This Class implements helper method to Pull & Validate the data from
    the sql server.
    """

    def __init__(self, logger, log_prefix) -> None:
        """Initialize method for MySQLPluginHelper class."""
        self.logger = logger
        self.log_prefix = log_prefix

    @staticmethod
    def strip_args(data):
        """Strip arguments from left and right directions.

        Args:
            data (dict): Dict object having all the
            Plugin configuration parameters.
        """
        keys = data.keys()
        for key in keys:
            if isinstance(data[key], str):
                data[key] = data[key].strip()

    def validate_configuration_parameters(
        self, configuration
    ) -> ValidationResult:
        """
        Validate the plugin configuration parameters.

        Args:
            configuration (dict): Dictionary containing
            the plugin configuration parameters.

        Returns:
            ValidationResult: ValidationResult
            object with success flag and message.
        """
        try:
            db_config = configuration.get("configuration", {})
            self.strip_args(db_config)

            # Validate host
            host = db_config.get("host")
            if not host:
                err_msg = (
                    "Server Hostname/IP is a required configuration parameter."
                )
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: Validation error occurred. "
                        f"{err_msg}"
                    ),
                    resolution=(
                        "Ensure that a valid Server Hostname/IP is provided."
                    ),
                )
                return ValidationResult(
                    success=False,
                    message=err_msg,
                )
            if not isinstance(host, str) or not host.strip():
                err_msg = (
                    "Server Hostname/IP should be a non-empty string value."
                )
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: Validation error occurred. "
                        f"{err_msg}"
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
            username = db_config.get("username")
            if not username:
                err_msg = (
                    "Username is a required configuration parameter."
                )
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: Validation error occurred. "
                        f"{err_msg}"
                    ),
                    resolution=(
                        "Ensure that a valid Username is provided."
                    ),
                )
                return ValidationResult(
                    success=False,
                    message=err_msg,
                )
            if not isinstance(username, str) or not username.strip():
                err_msg = (
                    "Username should be a non-empty string value."
                )
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: Validation error occurred. "
                        f"{err_msg}"
                    ),
                    resolution=(
                        "Ensure that the Username is a non-empty string value."
                    ),
                )
                return ValidationResult(
                    success=False,
                    message=err_msg,
                )

            # Validate password
            password = db_config.get("password")
            if not password:
                err_msg = (
                    "Password is a required configuration parameter."
                )
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: Validation error occurred. "
                        f"{err_msg}"
                    ),
                    resolution=(
                        "Ensure that a valid Password is provided."
                    ),
                )
                return ValidationResult(
                    success=False,
                    message=err_msg,
                )
            if not isinstance(password, str) or not password.strip():
                err_msg = (
                    "Password should be a non-empty string value."
                )
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: Validation error occurred. "
                        f"{err_msg}"
                    ),
                    resolution=(
                        "Ensure that the Password is a non-empty string value."
                    ),
                )
                return ValidationResult(
                    success=False,
                    message=err_msg,
                )

            # Validate query
            query = db_config.get("query", "")
            if not query:
                err_msg = (
                    "Query is a required configuration parameter."
                )
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: Validation error occurred. "
                        f"{err_msg}"
                    ),
                    resolution=(
                        "Ensure that a valid SQL SELECT query is provided."
                    ),
                )
                return ValidationResult(
                    success=False,
                    message=err_msg,
                )

            # Validate query format
            is_valid_query, query_error_message = self.validate_query_format(
                query
            )
            if not is_valid_query:
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: Validation error occurred. "
                        f"{query_error_message}"
                    ),
                    resolution=(
                        "Ensure that a valid non-empty SQL SELECT query "
                        "is provided."
                    ),
                )
                return ValidationResult(
                    success=False,
                    message=query_error_message,
                )

            # Validate no DML operations in query
            is_valid_dml, dml_error_message = self.validate_no_dml_in_query(
                query
            )
            if not is_valid_dml:
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: Validation error occurred. "
                        f"{dml_error_message}"
                    ),
                    resolution=(
                        "Ensure that the query contains only read-only "
                        "SELECT operations and no DML statements."
                    ),
                )
                return ValidationResult(
                    success=False,
                    message=dml_error_message,
                )

            # Validate dbname
            dbname = db_config.get("dbname")
            if not dbname:
                err_msg = (
                    "Database Name is a required configuration parameter."
                )
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: Validation error occurred. "
                        f"{err_msg}"
                    ),
                    resolution=(
                        "Ensure that a valid Database Name is provided."
                    ),
                )
                return ValidationResult(
                    success=False,
                    message=err_msg,
                )
            if not isinstance(dbname, str) or not dbname.strip():
                err_msg = (
                    "Database Name should be a non-empty string value."
                )
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: Validation error occurred. "
                        f"{err_msg}"
                    ),
                    resolution=(
                        "Ensure that the Database Name is a "
                        "non-empty string value."
                    ),
                )
                return ValidationResult(
                    success=False,
                    message=err_msg,
                )

            # Validate port
            port = db_config.get("port")
            if not self.validate_port(port):
                err_msg = (
                    "Port should be an integer between 1 and 65536."
                )
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: Validation error occurred. "
                        f"{err_msg}"
                    ),
                    resolution=(
                        "Ensure that the Port is an integer between "
                        "1 and 65536."
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
                        f"{self.log_prefix}: Validation error "
                        f"occurred. {err_msg}"
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

            return ValidationResult(
                success=True,
                message=(
                    "Connection with MySQL database verified successfully."
                ),
            )
        except Exception:
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Error occurred while establishing a "
                    "connection to the database with the given parameters."
                ),
                resolution=(
                    "Ensure that the Server Hostname/IP, Port, Username, "
                    "Password and Database Name are correct and the server "
                    "is reachable."
                ),
                details=traceback.format_exc(),
            )
            return ValidationResult(
                success=False,
                message=(
                    "Couldn't establish a connection to the database "
                    "with the given parameters."
                ),
            )

    def create_connection_string(self, config):
        """
        Create a MySQL database connection string based on the configuration.

        Args:
            config (dict): A dictionary containing
                        database connection configuration parameters.
                        Requires 'username', 'password',
                        'host', 'port', and 'dbname' keys.

        Returns:
            str: The constructed MySQL database connection string.
        """
        self.strip_args(config)
        if config.get("port"):
            port = f":{config.get('port')}"
        else:
            port = ""

        # parsing special characters like '@' , ':' in username and password.
        username = urllib.parse.quote_plus(config.get("username"))
        password = urllib.parse.quote_plus(config.get("password"))

        conn_str = (
            f"mysql+mysqlconnector://{username}:"
            + f"{password}@{config['host']}"
            + f"{port}/{config['dbname']}"
        )
        return conn_str

    def validate_query_format(self, query):
        """Validate if the query is properly formatted and exists.

        Args:
            query (str): SQL query to validate

        Returns:
            tuple: (is_valid, error_message) where is_valid is a
                boolean and error_message is a string
        """
        if not query or not isinstance(query, str) or query.strip() == "":
            return False, "Invalid Query provided."
        return True, ""

    def validate_no_dml_in_query(self, query):
        """Validate that the query does not contain any DML operations.

        Args:
            query (str): SQL query to validate

        Returns:
            tuple: (is_valid, error_message) where is_valid is a
                boolean and error_message is a string
        """
        sql_query_pattern = re.compile(
            rf"""
            (?P<quoted_identifier> `[^`]+` )
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

    def validate_port(self, port):
        """Validate Provided port.

        Args:
            port (string): Provided port

        Returns:
            bool: True if port is between 0 and 65536 and False otherwise.
        """
        if port is None or port == "" or 0 < int(port) <= 65536:
            return True
        return False
