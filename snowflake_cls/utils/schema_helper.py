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

Snowflake CLS Plugin schema introspection helper.
"""

import json
import re
import time
import traceback
from typing import Dict

from .constants import (
    STRUCTURED_OBJECT_TYPE,
    JSON_CONTENT_TYPE,
    OBJECT_DOES_NOT_EXIST_CODE,
    SHOW_COLUMNS_NAME_INDEX,
    SHOW_COLUMNS_TYPE_INDEX,
    PLATFORM_NAME,
    SCHEMA_INTROSPECTION_QUERY,
    SQL_API_ENDPOINT,
    SQL_API_MAX_POLL_ATTEMPTS,
    SQL_API_POLL_WAIT_SECONDS,
    SQL_API_STATUS_ENDPOINT,
    SQL_API_TIMEOUT_SECONDS,
)
from .exceptions import SnowflakePluginException
from .utilities import escape_sql_identifier, normalize_base_url


class SnowflakeSchemaHelper:
    """Reads a table's columns through the Snowflake SQL API.

    Runs one read-only SHOW COLUMNS command, which Snowflake treats as
    metadata and runs with no compute, so no warehouse is needed.

    The same call also tells us whether the plugin can reach Snowflake at
    all: a table that does not exist, or that the role cannot see, fails
    to compile with Snowflake's object-does-not-exist code, which is
    read here as "no columns".

    This class never issues DDL. The plugin does not create or alter
    tables under any configuration.
    """

    def __init__(self, logger, log_prefix, helper, auth_provider):
        """Wire up the helper.

        Args:
            logger: Logger object.
            log_prefix (str): Prefix put in front of every log message.
            helper (SnowflakePluginHelper): Makes the HTTP calls.
            auth_provider (SnowflakeAuthProvider): Builds auth headers.
        """
        self.logger = logger
        self.log_prefix = log_prefix
        self.helper = helper
        self.auth_provider = auth_provider

    @staticmethod
    def cache_key(configuration: Dict, table_name: str) -> str:
        """Build the storage key for one table's cached column list.

        Database, schema and table are kept exactly as given, not
        upper-cased - case is significant now (a quoted, mixed-case
        name is a different object from its upper-cased unquoted
        namesake), so two configurations differing only by case must
        not collapse onto the same cached column list.

        Args:
            configuration (Dict): Plugin configuration.
            table_name (str): Target table.

        Returns:
            str: Key identifying this account, database, schema and table.
        """
        return "|".join(
            [
                normalize_base_url(configuration.get("base_url", "")),
                str(configuration.get("database", "")).strip(),
                str(configuration.get("schema", "")).strip(),
                str(table_name).strip(),
            ]
        )

    @staticmethod
    def account_base_url(configuration: Dict) -> str:
        """Return the account URL the customer configured.

        Normalised rather than used raw, so the host is known to be a
        Snowflake one before the token is sent to it. validate()
        refuses to save a configuration this cannot read.

        Args:
            configuration (Dict): Plugin configuration.

        Returns:
            str: Account base URL, for example
                https://myorg-myaccount.snowflakecomputing.com
        """
        return normalize_base_url(configuration.get("base_url", ""))

    def _poll_statement(
        self,
        configuration: Dict,
        statement_handle: str,
        headers: Dict,
        logger_msg: str,
        verify: bool,
        proxies: Dict,
        is_validation: bool,
    ) -> Dict:
        """Wait for a statement that is still running to finish.

        The SQL API answers 202 when a statement has not finished yet.
        We poll the status endpoint until it returns a result or we run
        out of attempts.

        Args:
            configuration (Dict): Plugin configuration.
            statement_handle (str): Handle from the 202 response.
            headers (Dict): Request headers, including auth.
            logger_msg (str): What the plugin is doing.
            verify (bool): Verify the TLS certificate.
            proxies (Dict): Proxy settings.
            is_validation (bool): True when called from validate().

        Returns:
            Dict: The finished statement result.

        Raises:
            SnowflakePluginException: If it never finishes in time.
        """
        url = SQL_API_STATUS_ENDPOINT.format(
            base_url=self.account_base_url(configuration),
            statement_handle=statement_handle,
        )
        for attempt in range(SQL_API_MAX_POLL_ATTEMPTS):
            time.sleep(SQL_API_POLL_WAIT_SECONDS)
            response = self.helper.api_helper(
                logger_msg=f"{logger_msg} (checking if the query finished)",
                url=url,
                method="GET",
                headers=headers,
                verify=verify,
                proxies=proxies,
                is_handle_error_required=False,
                is_validation=is_validation,
            )
            if response.status_code == 202:
                self.logger.debug(
                    f"{self.log_prefix}: The query is still running."
                    f" Attempt {attempt + 1} of"
                    f" {SQL_API_MAX_POLL_ATTEMPTS}."
                )
                continue
            return self.helper.handle_error(
                response, logger_msg, is_validation
            )

        err_msg = (
            f"{PLATFORM_NAME} did not finish the query while"
            f" {logger_msg} within"
            f" {SQL_API_MAX_POLL_ATTEMPTS * SQL_API_POLL_WAIT_SECONDS}"
            " seconds."
        )
        self.logger.error(
            message=f"{self.log_prefix}: {err_msg}",
            resolution=(
                "Retry the operation. If it keeps happening, check the"
                " Snowflake service status."
            ),
        )
        raise SnowflakePluginException(err_msg)

    def introspect_columns(
        self,
        configuration: Dict,
        table_name: str,
        storage: Dict = None,
        verify: bool = True,
        proxies: Dict = None,
        is_validation: bool = True,
    ) -> Dict[str, str]:
        """Read a table's column names and types.

        Args:
            configuration (Dict): Plugin configuration.
            table_name (str): Target table.
            storage (Dict): Plugin storage, used as the token cache.
            verify (bool): Verify the TLS certificate.
            proxies (Dict): Proxy settings.
            is_validation (bool): True when called from validate().

        Returns:
            Dict[str, str]: Column name to Snowflake data type. Empty if
                the table does not exist or the role cannot see it.

        Raises:
            SnowflakePluginException: If the query fails.
        """
        database = str(configuration.get("database", "")).strip()
        schema = str(configuration.get("schema", "")).strip()
        table = str(table_name).strip()
        logger_msg = f"reading the columns of table '{table}'"

        statement = SCHEMA_INTROSPECTION_QUERY.format(
            database=escape_sql_identifier(database),
            schema=escape_sql_identifier(schema),
            table=escape_sql_identifier(table),
        )
        body = {
            "statement": statement,
            "timeout": SQL_API_TIMEOUT_SECONDS,
            "database": database,
            "schema": schema,
        }
        headers = self.auth_provider.get_auth_headers(
            configuration, storage=storage
        )
        headers["Content-Type"] = JSON_CONTENT_TYPE

        response = self.helper.api_helper(
            logger_msg=logger_msg,
            url=SQL_API_ENDPOINT.format(
                base_url=self.account_base_url(configuration)
            ),
            method="POST",
            json_body=body,
            headers=headers,
            verify=verify,
            proxies=proxies,
            is_handle_error_required=False,
            is_validation=is_validation,
        )

        if response.status_code == 202:
            result = self.helper.parse_response(
                response, logger_msg, is_validation
            )
            statement_handle = result.get("statementHandle")
            if not statement_handle:
                err_msg = (
                    f"{PLATFORM_NAME} said the query was still running"
                    " but did not return a statement handle."
                )
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg}",
                    details=f"API response: {response.text}",
                    resolution="Retry the operation.",
                )
                raise SnowflakePluginException(err_msg)
            result = self._poll_statement(
                configuration=configuration,
                statement_handle=statement_handle,
                headers=headers,
                logger_msg=logger_msg,
                verify=verify,
                proxies=proxies,
                is_validation=is_validation,
            )
        elif missing := self._missing_object(response):
            kind, detail = missing
            if kind == "table":
                # SHOW COLUMNS fails rather than returning nothing when
                # the table is not there. That is still the answer the
                # caller wants: no columns.
                self.logger.debug(
                    f"{self.log_prefix}: Table '{table}' does not"
                    " exist, or the role behind these credentials"
                    " cannot see it."
                )
                return {}
            # A missing database or schema is a different mistake, in a
            # different field. Reporting it as a missing table would
            # send the user looking in the wrong place, so pass
            # Snowflake's own wording straight through.
            self.logger.error(
                message=f"{self.log_prefix}: {detail}",
                details=f"API response: {response.text}",
                resolution=(
                    "Check Database and Schema in the configuration"
                    " parameters, and that the role behind these"
                    " credentials has USAGE on both."
                ),
            )
            raise SnowflakePluginException(detail, response.status_code)
        else:
            result = self.helper.handle_error(
                response, logger_msg, is_validation
            )

        return self._parse_columns(result, logger_msg)

    @staticmethod
    def _missing_object(response):
        """Say what Snowflake reported as missing, if anything.

        Snowflake answers with the same code whether the table, the
        schema or the database is the problem, so the message is read to
        tell them apart. Only a missing table means "no columns"; the
        other two are configuration mistakes in their own fields.

        Args:
            response: Response object.

        Returns:
            Optional[tuple]: ("table" | "schema" | "database" |
                "object", the message Snowflake sent), or None when this
                is not a does-not-exist error.
        """
        if response.status_code == 200:
            return None
        try:
            body = response.json()
        except Exception:
            return None
        if (
            not isinstance(body, dict)
            or body.get("code") != OBJECT_DOES_NOT_EXIST_CODE
        ):
            return None
        message = str(body.get("message", ""))
        detail = message.replace("SQL compilation error:", "").strip()
        match = re.search(r"\b(Database|Schema|Table)\s+'", message)
        kind = match.group(1).lower() if match else "object"
        return kind, (detail or "The object does not exist.")

    @staticmethod
    def _column_positions(result: Dict) -> tuple:
        """Find where the name and type sit in a SHOW COLUMNS row.

        Read from the response metadata so an extra column added to
        SHOW COLUMNS in a future release does not shift the parsing.

        Args:
            result (Dict): Parsed SQL API response.

        Returns:
            tuple: Index of the column name and of the data type.
        """
        try:
            names = [
                str(c.get("name", "")).lower()
                for c in result["resultSetMetaData"]["rowType"]
            ]
            return names.index("column_name"), names.index("data_type")
        except Exception:
            return SHOW_COLUMNS_NAME_INDEX, SHOW_COLUMNS_TYPE_INDEX

    @staticmethod
    def _read_type(raw) -> str:
        """Read the Snowflake type out of a SHOW COLUMNS cell.

        The cell holds JSON such as {"type":"TEXT","length":...}. Fall
        back to the raw value if it is ever plain text.

        Args:
            raw: The data_type cell.

        A structured object - OBJECT(a VARCHAR, b NUMBER) - reports the
        same "OBJECT" as a plain one and differs only by a "fields"
        key. It is named apart here because the two behave differently:
        an append to a structured column returns HTTP 200 and then
        drops the row.

        Returns:
            str: Uppercased Snowflake type, e.g. TEXT or VARIANT, or
                STRUCTURED OBJECT.
        """
        parsed = raw
        if isinstance(raw, str):
            try:
                parsed = json.loads(raw)
            except Exception:
                return raw.strip().upper()
        if isinstance(parsed, dict):
            name = str(parsed.get("type", "")).upper()
            if parsed.get("fields"):
                return STRUCTURED_OBJECT_TYPE
            return name
        return str(raw or "").upper()

    def _parse_columns(
        self, result: Dict, logger_msg: str
    ) -> Dict[str, str]:
        """Pull the column list out of a SHOW COLUMNS result.

        Args:
            result (Dict): Parsed SQL API response.
            logger_msg (str): What the plugin was doing.

        Returns:
            Dict[str, str]: Column name to Snowflake data type.

        Raises:
            SnowflakePluginException: If the result cannot be read.
        """
        try:
            name_at, type_at = self._column_positions(result)
            columns = {}
            for row in result.get("data") or []:
                if not row or len(row) <= max(name_at, type_at):
                    continue
                column_name = row[name_at]
                if column_name:
                    columns[str(column_name)] = self._read_type(
                        row[type_at]
                    )
            return columns
        except Exception as exp:
            err_msg = (
                f"Could not read the column list from {PLATFORM_NAME}"
                f" while {logger_msg}."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {exp}",
                details=traceback.format_exc(),
                resolution=(
                    "Retry the operation. If it keeps happening, check"
                    " logs for the full response."
                ),
            )
            raise SnowflakePluginException(err_msg)
