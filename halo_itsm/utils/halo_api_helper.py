"""
BSD 3-Clause License

Copyright (c) 2021, Netskope OSS
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice,
   this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its contributors
   may be used to endorse or promote products derived from this software
   without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
POSSIBILITY OF SUCH DAMAGE.

HaloITSM Plugin helper module.
"""

import hashlib
import json
import time
import traceback
from typing import Any, Dict, Optional

import requests
from netskope.common.utils import add_user_agent

from .halo_constants import (
    ACCESS_TOKEN_KEY,
    AUTH_TOKEN_ENDPOINT,
    BASE_URL,
    CONFIG_HASH_KEY,
    DEFAULT_WAIT_TIME,
    MAX_RETRIES,
    MODULE_NAME,
    PLATFORM_NAME,
    TOKEN_EXPIRY_BUFFER,
    TOKEN_EXPIRY_KEY,
)
from .halo_exceptions import HaloITSMPluginException


class HaloPluginHelper:
    """Helper class for HaloITSM Plugin API interactions.

    Provides utilities for building authenticated headers, parsing
    responses, and making HTTP requests with retry logic.
    """

    def __init__(
        self,
        logger: Any,
        log_prefix: str,
        plugin_name: str,
        plugin_version: str,
        ssl_validation: bool,
        proxy: Dict,
    ) -> None:
        """Initialize HaloPluginHelper.

        Args:
            logger (Any): Logger object for recording messages.
            log_prefix (str): Prefix string for all log messages.
            plugin_name (str): Display name of the plugin.
            plugin_version (str): Version string of the plugin.
            ssl_validation (bool): Whether to verify SSL certificates.
            proxy (Dict): Proxy configuration dictionary.
        """
        self.log_prefix = log_prefix
        self.logger = logger
        self.plugin_name = plugin_name
        self.plugin_version = plugin_version
        self.ssl_validation = ssl_validation
        self.proxy = proxy

    def add_user_agent(self, headers: Dict) -> Dict:
        """Add a custom User-Agent header to the given headers dict.

        Skips the update when User-Agent is already present.

        Args:
            headers (Dict): Existing headers dictionary.

        Returns:
            Dict: Headers dictionary with User-Agent updated.
        """
        if headers and "User-Agent" in headers:
            return headers
        headers = add_user_agent(headers)
        ce_added_agent = headers.get("User-Agent", "netskope-ce")
        user_agent = "{}-{}-{}-v{}".format(
            ce_added_agent,
            MODULE_NAME.lower(),
            self.plugin_name.replace(" ", "-").lower(),
            self.plugin_version,
        )
        headers.update({"User-Agent": user_agent})
        return headers

    def get_config_params(
        self, configuration: Dict, step: str = "auth"
    ) -> Dict:
        """Extract configuration parameters for a given step.

        Args:
            configuration (Dict): Full plugin configuration dictionary.
            step (str): Configuration step name. Defaults to 'auth'.

        Returns:
            Dict: Parameters dictionary for the specified step.
        """
        return configuration.get(step, {})

    # ------------------------------------------------------------------
    # Token management
    # ------------------------------------------------------------------

    def _get_cached_token(self, storage: Dict) -> Optional[str]:
        """Return a cached OAuth2 token if still valid.

        Args:
            storage (Dict): CE persistent storage dictionary.

        Returns:
            Optional[str]: Cached access token, or None when absent/expired.
        """
        token = storage.get(ACCESS_TOKEN_KEY)
        expiry = storage.get(TOKEN_EXPIRY_KEY, 0)
        if token and time.time() < (expiry - TOKEN_EXPIRY_BUFFER):
            return token
        return None

    def _cache_token(self, token: str, expires_in: int, storage: Dict) -> None:
        """Store an access token in persistent storage with its expiry.

        Args:
            token (str): OAuth2 access token.
            expires_in (int): Token lifetime in seconds.
            storage (Dict): CE persistent storage dictionary.
        """
        storage[ACCESS_TOKEN_KEY] = token
        storage[TOKEN_EXPIRY_KEY] = time.time() + expires_in

    def _clear_cached_token(self, storage: Dict) -> None:
        """Remove the cached access token and config hash from storage.

        Args:
            storage (Dict): CE persistent storage dictionary.
        """
        storage.pop(ACCESS_TOKEN_KEY, None)
        storage.pop(TOKEN_EXPIRY_KEY, None)
        storage.pop(CONFIG_HASH_KEY, None)

    def _get_config_hash(self, configuration: Dict) -> str:
        """Return a SHA-256 hash of the auth credentials in configuration.

        Covers both auth methods so that any credential change is detected:
          client_credentials — tenant + auth_method + client_id + client_secret
          password — tenant + auth_method + client_id + username + password

        Args:
            configuration (Dict): Full plugin configuration dictionary.

        Returns:
            str: Hex-digest SHA-256 hash of the credential fields.
        """
        auth_params = self.get_config_params(configuration, "auth")
        auth_method = auth_params.get("auth_method", "")
        tenant = auth_params.get("tenantname", "").strip()
        client_id = auth_params.get("client_id", "").strip()
        if auth_method == "client_credentials":
            raw = (
                f"{tenant}{auth_method}{client_id}"
                f"{auth_params.get('client_secret', '')}"
            )
        else:
            raw = (
                f"{tenant}{auth_method}{client_id}"
                f"{auth_params.get('username', '').strip()}"
                f"{auth_params.get('password', '')}"
            )
        return hashlib.sha256(raw.encode()).hexdigest()

    def _generate_token(
        self,
        configuration: Dict,
        storage: Dict,
        is_from_validation: bool = False,
    ) -> str:
        """Generate and return an OAuth2 access token from HaloITSM.

        Always checks the cache first — a valid cached token is returned
        without a network call regardless of whether this is called from
        validation. New tokens are cached with the actual expires_in value
        from the API response.

        Args:
            configuration (Dict): Full plugin configuration dictionary.
            storage (Dict): CE persistent storage dictionary.
            is_from_validation (bool): Passed through to api_helper as
                is_validation to suppress retries and adjust error messages.

        Returns:
            str: Valid OAuth2 access token.

        Raises:
            HaloITSMPluginException: When token generation fails.
        """
        current_hash = self._get_config_hash(configuration)
        stored_hash = storage.get(CONFIG_HASH_KEY)

        if stored_hash == current_hash:
            cached = self._get_cached_token(storage)
            if cached:
                return cached

        # Credentials changed or token expired — clear stale state and
        # generate a fresh token using the current configuration.
        self._clear_cached_token(storage)

        auth_params = self.get_config_params(configuration, "auth")
        auth_method = auth_params.get("auth_method", "")
        tenant = auth_params.get("tenantname", "").strip()

        auth_body = {
            "client_id": auth_params.get("client_id", "").strip(),
            "grant_type": auth_method,
            "scope": "all",
        }
        if auth_method == "client_credentials":
            auth_body["client_secret"] = auth_params.get("client_secret", "")
        elif auth_method == "password":
            auth_body["username"] = auth_params.get("username", "").strip()
            auth_body["password"] = auth_params.get("password", "")

        try:
            response = self.api_helper(
                logger_msg="generating an access token",
                method="POST",
                url=f"{BASE_URL.format(tenant)}{AUTH_TOKEN_ENDPOINT}",
                headers={
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Accept": "application/json",
                },
                data=auth_body,
                verify=self.ssl_validation,
                proxies=self.proxy,
                is_validation=is_from_validation,
                regenerate_auth_token=False,
            )
            token = response.get("access_token", "")
            if not token:
                raise HaloITSMPluginException(
                    "Empty access token received. Token generation failed."
                )
            expires_in = int(response.get("expires_in", 3600))
            self._cache_token(token, expires_in, storage)
            storage[CONFIG_HASH_KEY] = current_hash
            return token
        except HaloITSMPluginException:
            raise
        except Exception as exp:
            raise HaloITSMPluginException(
                f"Unexpected error occurred while generating access"
                f" token from {PLATFORM_NAME}. Error: {exp}"
            )

    def _get_auth_headers(
        self,
        configuration: Dict,
        storage: Dict,
        force_refresh: bool = False,
    ) -> Dict:
        """Build and return authenticated request headers.

        On force_refresh the cached token is cleared before generating
        a new one — used by api_helper on 401 to recover from an expired
        token without propagating the callable to every call site.

        Args:
            configuration (Dict): Full plugin configuration dictionary.
            storage (Dict): CE persistent storage dictionary.
            force_refresh (bool): When True clears cache before generating.

        Returns:
            Dict: Headers dict with Bearer token and Content-Type.
        """
        if force_refresh:
            self._clear_cached_token(storage)
        token = self._generate_token(configuration, storage)
        return {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        }

    def _get_response_details(self, resp: requests.models.Response) -> str:
        """Return a log-safe representation of an HTTP response body.

        When the body is an HTML page (e.g., a reverse-proxy error page
        returned for an invalid tenant name) the raw HTML is replaced with
        a short description so it does not flood the CE log details panel.

        Args:
            resp (requests.models.Response): HTTP response object.

        Returns:
            str: Response body text, or a short HTML notice when the body
                is an HTML document.
        """
        content_type = resp.headers.get("Content-Type", "")
        text = resp.text.strip() if resp.text else ""
        if "text/html" in content_type or text.lower().startswith(
            ("<!doctype", "<html")
        ):
            return (
                f"HTML response received from server"
                f" (status code: {resp.status_code})."
                " This usually indicates an invalid Tenant Name."
            )
        max_len = 2000
        if len(text) > max_len:
            return text[:max_len] + f"... [truncated, total {len(text)} chars]"
        return text

    def parse_response(
        self,
        response: requests.models.Response,
        logger_msg: str,
    ) -> Any:
        """Parse and return JSON from an HTTP response object.

        Args:
            response (requests.models.Response): HTTP response object.
            logger_msg (str): Description of the action being performed.

        Returns:
            Any: Parsed JSON response body.

        Raises:
            HaloITSMPluginException: On JSON decode or parsing failure.
        """
        try:
            return response.json()
        except json.JSONDecodeError as err:
            err_msg = (
                f"Invalid JSON response received from API while"
                f" {logger_msg}. The response body may have been"
                f" truncated (received {len(response.content)} bytes)."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {err.msg}",
                details=(
                    f"JSONDecodeError at char {err.pos}:"
                    f" {err.msg}. Response size:"
                    f" {len(response.content)} bytes."
                ),
                resolution=(
                    "The HaloITSM API response exceeded the maximum"
                    " allowed size. Reduce the number of tracked tickets"
                    " or contact HaloITSM support to increase the"
                    " response size limit."
                ),
            )
            raise HaloITSMPluginException(err_msg) from None
        except Exception as exp:
            err_msg = (
                "Error occurred while parsing JSON response"
                f" while {logger_msg}."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {exp}",
                details=self._get_response_details(response),
                resolution=(
                    "Ensure that the Authentication parameters provided"
                    " in the configuration are correct."
                ),
            )
            raise HaloITSMPluginException(err_msg)

    def handle_error(
        self,
        resp: requests.models.Response,
        logger_msg: str,
        is_validation: bool = False,
        resolution_override: Optional[Dict] = None,
    ) -> Any:
        """Handle HTTP response codes and raise on non-success statuses.

        Args:
            resp (requests.models.Response): HTTP response object.
            logger_msg (str): Description of the action being performed.
            is_validation (bool): Whether the call is from a validation
                step; adjusts error messages shown to the user.

        Returns:
            Any: Parsed JSON body for 200/201 responses; empty dict for 204.

        Raises:
            HaloITSMPluginException: On any non-successful status code.
        """
        status_code = resp.status_code

        # Operational error messages (non-validation paths)
        error_dict = {
            400: "Received exit code 400, Bad Request",
            401: "Received exit code 401, Unauthorized",
            403: "Received exit code 403, Forbidden",
            404: "Received exit code 404, Resource not found",
            408: "Received exit code 408, Request Timeout",
            422: "Received exit code 422, Unprocessable Entity",
            429: (
                "Received exit code 429, Too Many Requests."
                " HaloITSM allows 700 requests per 300 seconds."
            ),
        }

        # Validation-specific messages surfaced directly in the CE UI
        validation_error_dict = {
            400: (
                "Received exit code 400, Bad Request."
                " Verify the Authentication parameters provided"
                " in the configuration."
            ),
            401: (
                "Received exit code 401, Unauthorized."
                " Verify the Client ID and credentials provided"
                " in the configuration."
            ),
            403: (
                "Received exit code 403, Forbidden."
                " The application does not have sufficient permissions."
            ),
            404: (
                "Received exit code 404, Resource not found."
                " Verify the Tenant Name provided in the configuration."
            ),
            408: (
                "Received exit code 408, Request Timeout."
                " Verify the Tenant Name and Authentication parameters"
                " provided in the configuration."
            ),
            422: (
                "Received exit code 422, Unprocessable Entity."
                " Verify the Authentication parameters provided"
                " in the configuration."
            ),
            429: (
                "Received exit code 429, Too Many Requests."
                " HaloITSM allows 700 requests per 300 seconds."
            ),
        }

        # Per-status resolution hints shown in the CE UI
        resolution_dict = {
            400: (
                "Ensure that the Authentication parameters provided"
                " in the configuration are correct."
            ),
            401: (
                "Ensure that the Client ID and credentials provided"
                " in the configuration are correct."
            ),
            403: (
                "Ensure that the application has sufficient permissions"
                " on HaloITSM."
            ),
            404: (
                "Ensure that the Tenant Name provided in the"
                " configuration is correct."
            ),
            408: (
                "Ensure that the server is reachable and the"
                " Authentication parameters are correct."
            ),
            422: (
                "Ensure that the Authentication parameters provided"
                " in the configuration are correct."
            ),
            429: (
                "Ensure that the request rate is within the HaloITSM"
                " limit of 700 requests per 300 seconds and retry"
                " after the indicated wait time."
            ),
        }

        # Try to extract a meaningful error detail from the response body.
        # Strip trailing punctuation to avoid double periods when appended.
        api_error_detail = ""
        try:
            resp_json = resp.json()
            if isinstance(resp_json, dict):
                api_error_detail = (
                    resp_json.get("error_description")
                    or resp_json.get("error")
                    or resp_json.get("message")
                    or resp_json.get("detail")
                    or ""
                )
                if api_error_detail:
                    api_error_detail = str(api_error_detail).rstrip(". ")
        except Exception:
            pass

        response_details = self._get_response_details(resp)

        if status_code in [200, 201]:
            return self.parse_response(resp, logger_msg)
        elif status_code == 204:
            return {}
        elif status_code in error_dict:
            resolution = (
                resolution_override.get(status_code)
                if resolution_override
                else None
            ) or resolution_dict.get(status_code)
            if is_validation:
                err_msg = validation_error_dict[status_code]
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: Validation error occurred."
                        f" {err_msg}"
                    ),
                    details=response_details,
                    resolution=resolution,
                )
            else:
                err_msg = f"{error_dict[status_code]} while {logger_msg}."
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg}",
                    details=response_details,
                    resolution=resolution,
                )
            raise HaloITSMPluginException(err_msg)
        else:
            err_type = (
                "HTTP Server Error"
                if 500 <= status_code <= 600
                else "HTTP Error"
            )
            if is_validation:
                if status_code == 500:
                    err_msg = (
                        f"Received exit code {status_code}, {err_type}."
                        " Verify the Tenant Name provided"
                        " in the configuration."
                    )
                    resolution = (
                        "Ensure that the Tenant Name provided in the"
                        " configuration is correct."
                    )
                else:
                    err_msg = f"Received exit code {status_code}, {err_type}."
                    resolution = (
                        "Ensure that the server is reachable and the"
                        " configuration is correct."
                    )
                if api_error_detail:
                    err_msg = f"{err_msg} API error: {api_error_detail}."
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: Validation error occurred."
                        f" {err_msg}"
                    ),
                    details=response_details,
                    resolution=resolution,
                )
            else:
                err_msg = (
                    f"Received exit code {status_code},"
                    f" {err_type} while {logger_msg}."
                )
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg}",
                    details=response_details,
                    resolution=(
                        "Ensure that the Tenant Name provided in the"
                        " configuration is correct."
                        if status_code == 500
                        else (
                            "Ensure that the server is reachable and the"
                            " configuration is correct."
                        )
                    ),
                )
            raise HaloITSMPluginException(err_msg)

    def api_helper(
        self,
        logger_msg: str,
        url: str,
        method: str,
        params: Optional[Dict] = None,
        data: Optional[Any] = None,
        json: Optional[Dict] = None,
        headers: Optional[Dict] = None,
        verify: bool = True,
        proxies: Optional[Dict] = None,
        is_handle_error_required: bool = True,
        is_validation: bool = False,
        resolution_override: Optional[Dict] = None,
        configuration: Optional[Dict] = None,
        storage: Optional[Dict] = None,
        regenerate_auth_token: bool = True,
    ) -> Any:
        """Perform an HTTP request with retry on transient errors.

        Retries up to MAX_RETRIES times on HTTP 429 and 5xx responses,
        honouring the Retry-After header when present and sleeping
        DEFAULT_WAIT_TIME seconds otherwise.

        On HTTP 401, when configuration and storage are provided the token
        is cleared, regenerated via _get_auth_headers, and the request is
        retried once (regenerate_auth_token=False on the recursive call
        prevents infinite loops — same pattern as Mimecast).

        Args:
            logger_msg (str): Human-readable description of the operation
                used in log messages.
            url (str): Target URL.
            method (str): HTTP method (GET, POST, etc.).
            params (Optional[Dict]): Query parameters.
            data (Optional[Any]): Form-encoded or raw body data.
            json (Optional[Dict]): JSON-serialisable body.
            headers (Optional[Dict]): Request headers.
            is_handle_error_required (bool): When False returns the raw
                response object instead of calling handle_error.
            is_validation (bool): Whether this is a validation call;
                suppresses retries and adjusts error messages.
            configuration (Optional[Dict]): Full plugin configuration,
                required for 401 token regeneration.
            storage (Optional[Dict]): CE persistent storage dict,
                required for 401 token regeneration.
            regenerate_auth_token (bool): When False skips the 401 retry
                to prevent infinite recursion. Defaults to True.

        Returns:
            Any: Parsed JSON response body, or raw response when
                is_handle_error_required is False.

        Raises:
            HaloITSMPluginException: On any unrecoverable request error.
        """
        try:
            headers = self.add_user_agent(headers or {})
            debug_msg = (
                f"{self.log_prefix}: API Request for {logger_msg}."
                f" Endpoint: {method} {url}"
            )
            if params:
                debug_msg += f", params: {params}."
            self.logger.debug(debug_msg)

            for retry_counter in range(MAX_RETRIES):
                response = requests.request(
                    method=method,
                    url=url,
                    params=params,
                    data=data,
                    json=json,
                    headers=headers,
                    verify=verify,
                    proxies=proxies,
                )
                status_code = response.status_code
                self.logger.debug(
                    f"{self.log_prefix}: Received API Response for"
                    f" {logger_msg}. Status Code={status_code}."
                )

                if (
                    status_code == 401
                    and regenerate_auth_token
                    and configuration is not None
                    and storage is not None
                    and not is_validation
                ):
                    fresh_headers = self._get_auth_headers(
                        configuration=configuration,
                        storage=storage,
                        force_refresh=True,
                    )
                    return self.api_helper(
                        logger_msg=logger_msg,
                        url=url,
                        method=method,
                        params=params,
                        data=data,
                        json=json,
                        headers=fresh_headers,
                        verify=verify,
                        proxies=proxies,
                        is_handle_error_required=is_handle_error_required,
                        is_validation=is_validation,
                        resolution_override=resolution_override,
                        configuration=configuration,
                        storage=storage,
                        regenerate_auth_token=False,
                    )

                if (
                    status_code == 429 or 500 <= status_code <= 600
                ) and not is_validation:
                    api_err_msg = self._get_response_details(response)
                    if status_code == 429:
                        log_err_msg = (
                            "API rate limit exceeded"
                            " (HaloITSM allows 700 requests per"
                            " 300 seconds)"
                        )
                    else:
                        log_err_msg = "HTTP server error occurred"
                    if retry_counter == MAX_RETRIES - 1:
                        err_msg = (
                            f"Received exit code {status_code},"
                            f" {log_err_msg} while {logger_msg}."
                            " Maximum retries exceeded."
                        )
                        self.logger.error(
                            message=f"{self.log_prefix}: {err_msg}",
                            details=api_err_msg,
                            resolution=(
                                "Ensure that the HaloITSM server is"
                                " reachable and the request rate is within"
                                " the allowed limit of 700 requests per"
                                " 300 seconds."
                            ),
                        )
                        raise HaloITSMPluginException(err_msg)
                    retry_after = int(
                        response.headers.get("Retry-After", DEFAULT_WAIT_TIME)
                    )
                    if retry_after > 300:
                        err_msg = (
                            f"Received exit code {status_code},"
                            f" {log_err_msg} while {logger_msg}."
                            f" Retry-After value ({retry_after}s) exceeds"
                            " the maximum wait time of 300 seconds."
                        )
                        self.logger.error(
                            message=f"{self.log_prefix}: {err_msg}",
                            details=api_err_msg,
                            resolution=(
                                "Ensure that the HaloITSM server is"
                                " responding within acceptable limits."
                                " The Retry-After header value must not"
                                " exceed 300 seconds."
                            ),
                        )
                        raise HaloITSMPluginException(err_msg)
                    retries_left = MAX_RETRIES - 1 - retry_counter
                    self.logger.error(
                        message=(
                            f"{self.log_prefix}: Received exit code"
                            f" {status_code}, {log_err_msg} while"
                            f" {logger_msg}. Retrying after"
                            f" {retry_after} second(s)."
                            f" {retries_left} retries remaining."
                        ),
                        details=api_err_msg,
                        resolution=(
                            "Ensure that the HaloITSM server is"
                            " reachable and the request rate is within"
                            " the allowed limit of 700 requests per"
                            " 300 seconds."
                        ),
                    )
                    time.sleep(retry_after)
                else:
                    return (
                        self.handle_error(
                            response,
                            logger_msg,
                            is_validation,
                            resolution_override,
                        )
                        if is_handle_error_required
                        else response
                    )

        except HaloITSMPluginException:
            raise
        except requests.exceptions.ReadTimeout as error:
            if is_validation:
                err_msg = (
                    "Read Timeout error occurred."
                    " Verify the Tenant Name provided in the configuration."
                )
            else:
                err_msg = f"Read Timeout error occurred while {logger_msg}."
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {error}.",
                details=traceback.format_exc(),
                resolution=(
                    "Ensure that the Tenant Name provided in the"
                    " configuration is correct and the server is reachable."
                ),
            )
            raise HaloITSMPluginException(err_msg)
        except requests.exceptions.ProxyError as error:
            if is_validation:
                err_msg = (
                    "Proxy error occurred."
                    " Verify the proxy configuration provided"
                    " in the plugin settings."
                )
            else:
                err_msg = f"Proxy error occurred while {logger_msg}."
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {error}.",
                details=traceback.format_exc(),
                resolution=(
                    "Ensure that the proxy configuration provided"
                    " in the plugin settings is correct."
                ),
            )
            raise HaloITSMPluginException(err_msg)
        except requests.exceptions.ConnectionError as error:
            if is_validation:
                err_msg = (
                    f"Unable to establish connection with"
                    f" {self.plugin_name}."
                    " Verify the Tenant Name provided in the configuration."
                )
            else:
                err_msg = (
                    f"Unable to establish connection with"
                    f" {self.plugin_name} while {logger_msg}."
                )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {error}.",
                details=traceback.format_exc(),
                resolution=(
                    "Ensure that the Tenant Name provided in the"
                    " configuration is correct and the server is reachable."
                ),
            )
            raise HaloITSMPluginException(err_msg)
        except requests.exceptions.HTTPError as err:
            if is_validation:
                err_msg = (
                    "HTTP error occurred."
                    " Verify the Authentication parameters provided"
                    " in the configuration."
                )
            else:
                err_msg = f"HTTP error occurred while {logger_msg}."
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {err}.",
                details=traceback.format_exc(),
                resolution=(
                    "Ensure that the Authentication parameters provided"
                    " in the configuration are correct."
                ),
            )
            raise HaloITSMPluginException(err_msg)
        except Exception as exp:
            if is_validation:
                err_msg = (
                    "Error occurred while performing"
                    f" API call to {self.plugin_name}."
                )
            else:
                err_msg = f"Error occurred while {logger_msg}."
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {exp}",
                details=traceback.format_exc(),
                resolution=(
                    "Ensure that the plugin configuration is correct."
                ),
            )
            raise HaloITSMPluginException(err_msg)
