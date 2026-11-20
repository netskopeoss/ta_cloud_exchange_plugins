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

Snowflake CLS Plugin Snowpipe Streaming client and auth provider.
"""

import uuid
from typing import Dict, List

from .constants import (
    NDJSON_CONTENT_TYPE,
    PLATFORM_NAME,
    STREAMING_HOST_STORAGE_KEY,
    STREAMING_HOSTNAME_ENDPOINT,
    STREAMING_ROWS_ENDPOINT,
    TOKEN_TYPE_HEADER,
    TOKEN_TYPE_PAT,
)
from .exceptions import (
    SnowflakeAuthenticationError,
    SnowflakePluginException,
)
from .utilities import (
    build_ndjson_payload,
    normalize_base_url,
    quote_path_identifier,
    serialize_row,
)


class SnowflakeAuthProvider:
    """Builds the auth headers for every Snowflake call.

    A Programmatic Access Token is used exactly as the customer pasted
    it. There is no token to mint, cache or refresh, and no expiry for
    the plugin to track - when the token reaches the lifetime chosen at
    creation, Snowflake rejects it and the customer generates a new one.
    """

    def __init__(self, logger, log_prefix):
        """Store the logging details.

        Args:
            logger: Logger object.
            log_prefix (str): Prefix put in front of every log message.
        """
        self.logger = logger
        self.log_prefix = log_prefix

    def get_auth_headers(self, configuration: Dict, **_) -> Dict:
        """Build the Authorization headers for a Snowflake call.

        Args:
            configuration (Dict): Plugin configuration.

        Returns:
            Dict: Authorization and token-type headers.

        Raises:
            SnowflakeAuthenticationError: If no token is configured.
        """
        token = configuration.get("programmatic_access_token") or ""
        if not token:
            err_msg = (
                "Programmatic Access Token is a required configuration"
                " parameter."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                resolution=(
                    "Generate a token in Snowflake and paste it into the"
                    " configuration."
                ),
            )
            raise SnowflakeAuthenticationError(err_msg)

        return {
            "Authorization": f"Bearer {token}",
            TOKEN_TYPE_HEADER: TOKEN_TYPE_PAT,
        }


class SnowflakeStreamingClient:
    """Sends rows to Snowflake over the Snowpipe Streaming REST API.

    Uses the elastic channel, which needs no open or close call - rows
    are appended straight to a table.
    """

    def __init__(
        self,
        logger,
        log_prefix,
        helper,
        auth_provider,
    ):
        """Wire up the client.

        Args:
            logger: Logger object.
            log_prefix (str): Prefix put in front of every log message.
            helper (SnowflakePluginHelper): Makes the HTTP calls.
            auth_provider (SnowflakeJWTAuthProvider): Builds auth headers.
        """
        self.logger = logger
        self.log_prefix = log_prefix
        self.helper = helper
        self.auth_provider = auth_provider
        # Resolved once per plugin instance so a push() with many chunks
        # only looks the host up once.
        self._streaming_host = None

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

    def resolve_hostname(
        self,
        configuration: Dict,
        storage: Dict = None,
        verify: bool = True,
        proxies: Dict = None,
        is_validation: bool = False,
    ) -> str:
        """Look up the account's streaming ingest host.

        This host is different from the account host, so the call is
        required before any row can be appended. Snowflake answers with
        plain text, not JSON.

        Args:
            configuration (Dict): Plugin configuration.
            storage (Dict): Plugin storage, used as the token cache.
            verify (bool): Verify the TLS certificate.
            proxies (Dict): Proxy settings.
            is_validation (bool): True when called from validate().

        Returns:
            str: The streaming ingest host name.

        Raises:
            SnowflakePluginException: If the host cannot be resolved.
        """
        url = STREAMING_HOSTNAME_ENDPOINT.format(
            base_url=self.account_base_url(configuration)
        )
        headers = self.auth_provider.get_auth_headers(configuration)
        response = self.helper.api_helper(
            logger_msg="resolving the Snowflake streaming ingest hostname",
            url=url,
            method="GET",
            headers=headers,
            verify=verify,
            proxies=proxies,
            is_handle_error_required=False,
            is_validation=is_validation,
        )

        if response.status_code not in (200, 201):
            # Hand it to handle_error, which raises with a message the
            # user can act on.
            self.helper.handle_error(
                response,
                "resolving the Snowflake streaming ingest hostname",
                is_validation,
            )

        hostname = self._read_hostname(response)
        if not hostname:
            err_msg = (
                f"{PLATFORM_NAME} returned an empty streaming ingest"
                " hostname."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=f"API response: {response.text}",
                resolution=(
                    "Check the Account URL in the configuration"
                    " parameters."
                ),
            )
            raise SnowflakePluginException(err_msg)

        self._streaming_host = hostname
        self._store_streaming_host(configuration, hostname, storage)
        self.logger.debug(
            f"{self.log_prefix}: Streaming host is '{hostname}'."
        )
        return hostname

    @staticmethod
    def _read_hostname(response) -> str:
        """Pull the host out of the response body.

        Snowflake documents this endpoint as returning
        {"hostname": "..."}, but a live tenant answered with the bare
        host as plain text. Handle both so either shape works.

        Args:
            response: Response object.

        Returns:
            str: The host name, or an empty string.
        """
        try:
            body = response.json()
        except Exception:
            body = None
        if isinstance(body, dict):
            for key in ("hostname", "Hostname", "host"):
                value = body.get(key)
                if value:
                    return str(value).strip()
            return ""
        return (response.text or "").strip()

    @staticmethod
    def _host_cache_key(configuration: Dict) -> str:
        """Key the stored host by the account it belongs to.

        Args:
            configuration (Dict): Plugin configuration.

        Returns:
            str: Cache key.
        """
        return normalize_base_url(
            configuration.get("base_url", "")
        ).upper()

    def _store_streaming_host(
        self, configuration: Dict, hostname: str, storage: Dict = None
    ) -> None:
        """Keep the host in storage so a new plugin object can reuse it.

        Args:
            configuration (Dict): Plugin configuration.
            hostname (str): Host to store.
            storage (Dict): Plugin storage.
        """
        if storage is None:
            return
        storage[STREAMING_HOST_STORAGE_KEY] = {
            self._host_cache_key(configuration): hostname
        }
        self.logger.debug(
            f"{self.log_prefix}: Saved the streaming host to storage."
        )

    def _forget_streaming_host(
        self, configuration: Dict, storage: Dict = None
    ) -> None:
        """Drop the stored host so the next call looks it up again.

        Args:
            configuration (Dict): Plugin configuration.
            storage (Dict): Plugin storage.
        """
        self._streaming_host = None
        if storage is not None:
            storage.pop(STREAMING_HOST_STORAGE_KEY, None)
        self.logger.debug(
            f"{self.log_prefix}: Removed the streaming host from"
            " storage."
        )

    def get_streaming_host(
        self,
        configuration: Dict,
        storage: Dict = None,
        verify: bool = True,
        proxies: Dict = None,
    ) -> str:
        """Return the streaming host, resolving it on first use.

        Args:
            configuration (Dict): Plugin configuration.
            storage (Dict): Plugin storage, used as the token cache.
            verify (bool): Verify the TLS certificate.
            proxies (Dict): Proxy settings.

        Returns:
            str: The streaming ingest host name.
        """
        if self._streaming_host:
            return self._streaming_host

        if storage:
            cached = (storage.get(STREAMING_HOST_STORAGE_KEY) or {}).get(
                self._host_cache_key(configuration)
            )
            if cached:
                self._streaming_host = cached
                self.logger.debug(
                    f"{self.log_prefix}: Using the streaming host from"
                    " storage."
                )
                return cached

        self.resolve_hostname(
            configuration,
            storage=storage,
            verify=verify,
            proxies=proxies,
        )
        return self._streaming_host

    def append_rows(
        self,
        configuration: Dict,
        rows: List[Dict],
        table_name: str,
        lines: List[str] = None,
        body: bytes = None,
        content_encoding: str = None,
        storage: Dict = None,
        verify: bool = True,
        proxies: Dict = None,
        logger_msg: str = "appending rows to Snowflake",
    ) -> Dict:
        """Append one chunk of rows to a table.

        A 404 can mean the cached streaming host is stale, so the host
        is looked up again and the chunk sent once more with retryCount
        bumped. A rejected token is terminal - a Programmatic Access
        Token has nothing to refresh.

        Args:
            configuration (Dict): Plugin configuration.
            rows (List[Dict]): Rows to append.
            table_name (str): Target table.
            lines (List[str]): The NDJSON line for each row, when the
                caller has already built them. Saves serializing every
                row a second time. Built here when not supplied. Unused
                when body is given.
            body (bytes): A pre-built, already-compressed request body.
                Sent as-is instead of building one from rows/lines, so
                a chunk already gzipped by the caller is never
                compressed or serialized twice.
            content_encoding (str): Value for the Content-Encoding
                header, sent only when body is given.
            storage (Dict): Plugin storage, used as the token cache.
            verify (bool): Verify the TLS certificate.
            proxies (Dict): Proxy settings.
            logger_msg (str): What the plugin is doing.

        Returns:
            Dict: Parsed response body.

        Raises:
            SnowflakeAuthenticationError: If the credentials are rejected.
            SnowflakePluginException: On any other failure.
        """
        if not rows:
            return {}

        if body is not None:
            payload = body
        else:
            if lines is None:
                lines = [serialize_row(row) for row in rows]
            payload = build_ndjson_payload(lines)
        # One request id and one counter for this chunk, shared by
        # every send of it. api_helper raises retryCount in place each
        # time it resends after a 429 or 5xx, and the host retry below
        # carries on from whatever it reached. That pair is how the
        # elastic channel tells a resend from a new write.
        params = {"requestId": str(uuid.uuid4()), "retryCount": 0}
        host_retried = False

        # At most two tries: the first, and one after looking the host
        # up again. A rejected token is terminal - there is nothing to
        # refresh.
        for attempt in range(2):
            if attempt:
                params["retryCount"] += 1
            streaming_host = self.get_streaming_host(
                configuration,
                storage=storage,
                verify=verify,
                proxies=proxies,
            )
            url = STREAMING_ROWS_ENDPOINT.format(
                streaming_host=streaming_host,
                database=quote_path_identifier(
                    configuration.get("database", "")
                ),
                schema=quote_path_identifier(
                    configuration.get("schema", "")
                ),
                table=quote_path_identifier(table_name),
            )
            headers = self.auth_provider.get_auth_headers(configuration)
            headers["Content-Type"] = NDJSON_CONTENT_TYPE
            if content_encoding:
                headers["Content-Encoding"] = content_encoding
            try:
                response = self.helper.api_helper(
                    logger_msg=logger_msg,
                    url=url,
                    method="POST",
                    params=params,
                    data=payload,
                    headers=headers,
                    verify=verify,
                    proxies=proxies,
                )
            except SnowflakePluginException as err:
                # A 404 can mean the streaming host we have is no longer
                # the right one. Look it up again and send once more. If
                # the table is simply missing, the second try returns
                # 404 too and the error goes back to the caller.
                if err.status_code != 404 or host_retried:
                    raise
                host_retried = True
                self.logger.info(
                    message=(
                        f"{self.log_prefix}: Snowflake returned 404"
                        f" for host '{streaming_host}'. Looking up the"
                        " host again and retrying this batch."
                    )
                )
                self._forget_streaming_host(configuration, storage)
                continue

            self._check_response_status(response, logger_msg)
            return response

        # Not reachable - every branch above either returns or re-raises
        # once its one retry is used up.
        raise SnowflakePluginException(
            f"Could not append rows to table '{table_name}'."
        )

    def _check_response_status(self, response: Dict, logger_msg: str):
        """Fail the chunk if Snowflake reported an error in the body.

        A 200 can still carry a non-zero status_code, which means the
        rows were not accepted.

        Args:
            response (Dict): Parsed response body.
            logger_msg (str): What the plugin was doing.

        Raises:
            SnowflakePluginException: If status_code is not 0.
        """
        if not isinstance(response, dict):
            return
        status_code = response.get("status_code")
        if status_code in (None, 0):
            return
        err_msg = (
            f"{PLATFORM_NAME} did not accept the rows while"
            f" {logger_msg}. Status code: {status_code}."
            f" Message: {response.get('message', '')}"
        )
        self.logger.error(
            message=f"{self.log_prefix}: {err_msg}",
            details=f"API response: {response}",
            resolution=(
                "Check that the table columns match the data the plugin"
                " is sending, then re-save the configuration."
            ),
        )
        raise SnowflakePluginException(err_msg)
