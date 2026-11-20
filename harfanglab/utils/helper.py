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

CTE HarfangLab plugin helper module.
"""

import json
import time
import traceback
from typing import Dict, Union

import requests
from netskope.common.utils import add_user_agent

from .constants import (
    DEFAULT_WAIT_TIME,
    MAX_API_CALLS,
    MAX_WAIT_TIME,
    MODULE_NAME,
    PLATFORM_NAME,
    RETRACTION,
)


class HarfangLabPluginException(Exception):
    """HarfangLab plugin custom exception class."""

    pass


class HarfangLabPluginHelper(object):
    """Helper class for HarfangLab API operations."""

    def __init__(
        self,
        logger,
        log_prefix: str,
        plugin_name: str,
        plugin_version: str,
    ):
        """HarfangLabPluginHelper initializer.

        Args:
            logger: Logger object.
            log_prefix (str): Log prefix string.
            plugin_name (str): Plugin name.
            plugin_version (str): Plugin version.
        """
        self.log_prefix = log_prefix
        self.logger = logger
        self.plugin_name = plugin_name
        self.plugin_version = plugin_version

    def _add_user_agent(
        self, headers: Union[Dict, None] = None
    ) -> Dict:
        """Add User-Agent header for third-party requests.

        Args:
            headers (Dict): Existing headers dict.

        Returns:
            Dict: Headers dict with User-Agent added.
        """
        if headers and "User-Agent" in headers:
            return headers
        if headers is None:
            headers = {}
        headers = add_user_agent(headers)
        ce_added_agent = headers.get("User-Agent", "netskope-ce")
        user_agent = "{}-{}-{}-v{}".format(
            ce_added_agent,
            MODULE_NAME.lower(),
            self.plugin_name.lower().replace(" ", "-"),
            self.plugin_version,
        )
        headers.update({"User-Agent": user_agent})
        return headers

    def _get_retry_after(self, headers: Dict) -> int:
        """Parse Retry-After header, capped at MAX_WAIT_TIME.

        Args:
            headers (Dict): Response headers.

        Returns:
            int: Seconds to wait before retrying.
        """
        try:
            retry_after = int(headers.get("Retry-After", DEFAULT_WAIT_TIME))
            return min(retry_after, MAX_WAIT_TIME)
        except (ValueError, TypeError):
            return DEFAULT_WAIT_TIME

    def build_url(self, endpoint: str, configuration: Dict) -> str:
        """Construct full URL from base_url config and endpoint path.

        Args:
            endpoint (str): API endpoint path (e.g. /api/data/...).
            configuration (Dict): Plugin configuration dict.

        Returns:
            str: Full URL.
        """
        base_url = (
            configuration.get("fqdn", "").strip().rstrip("/")
        )
        return f"{base_url}{endpoint}"

    def api_helper(
        self,
        logger_msg: str,
        url: str,
        method: str,
        headers: Dict,
        verify: bool,
        payload=None,
        json_body=None,
        params: Dict = None,
        proxies=None,
        is_handle_error_required: bool = True,
        is_validation: bool = False,
        is_retraction: bool = False,
    ) -> Union[Dict, requests.Response]:
        """Perform an API request with retry logic.

        Args:
            logger_msg (str): Human-readable description for logging.
            url (str): Full request URL.
            method (str): HTTP method (GET, POST, DELETE, etc.).
            headers (Dict): Request headers.
            verify (bool): SSL verification flag.
            payload: Request body as raw data (mutually exclusive with
                json_body).
            json_body: Request body as JSON (serialised by requests).
            params (Dict): Query string parameters.
            proxies: Proxy configuration.
            is_handle_error_required (bool): Call handle_error on
                success; otherwise return raw Response.
            is_validation (bool): When True, do not retry on errors —
                fail fast so the user sees the issue immediately.
            is_retraction (bool): When True, append [Retraction] to
                log prefix.

        Returns:
            Union[Dict, Response]: Parsed JSON dict or raw Response.

        Raises:
            HarfangLabPluginException: On any unrecoverable error.
        """
        if is_retraction and f"[{RETRACTION}]" not in self.log_prefix:
            self.log_prefix = self.log_prefix + f" [{RETRACTION}]"

        self.logger.debug(
            f"{self.log_prefix}: API Request for {logger_msg}."
            f" Endpoint: {method} {url}, params: {params}"
        )

        headers = self._add_user_agent(headers)
        if params is None:
            params = {}

        try:
            for retry_count in range(MAX_API_CALLS):
                response = requests.request(
                    method,
                    url,
                    headers=headers,
                    params=params,
                    data=payload,
                    json=json_body,
                    verify=verify,
                    proxies=proxies,
                )
                self.logger.debug(
                    f"{self.log_prefix}: Received API Response"
                    f" for {logger_msg}."
                    f" Status Code={response.status_code}."
                )

                # Handle 429 Too Many Requests
                if response.status_code == 429 and not is_validation:
                    wait = self._get_retry_after(response.headers)
                    if retry_count == MAX_API_CALLS - 1:
                        err_msg = (
                            f"Received exit code 429, Too Many Requests"
                            f" while {logger_msg}. Max retries exceeded."
                        )
                        self.logger.error(
                            message=f"{self.log_prefix}: {err_msg}",
                            details=f"API response: {response.text}",
                            resolution=(
                                "Wait for the rate limit to reset"
                                " before retrying."
                                " Check HarfangLab API usage limits."
                            ),
                        )
                        raise HarfangLabPluginException(err_msg)
                    self.logger.error(
                        message=(
                            f"{self.log_prefix}: Received exit code 429,"
                            f" Too Many Requests while {logger_msg}."
                            f" Retrying after {wait} seconds."
                            f" {MAX_API_CALLS - 1 - retry_count}"
                            " retries remaining."
                        ),
                        details=f"API response: {response.text}",
                        resolution=(
                            f"Ensure that the {PLATFORM_NAME} platform is"
                            " reachable."
                        ),
                    )
                    time.sleep(wait)
                    continue

                # Handle 5xx Server Errors
                if (
                    500 <= response.status_code < 600
                    and not is_validation
                ):
                    try:
                        api_err_msg = str(
                            self.parse_response(
                                response=response,
                                logger_msg=logger_msg,
                            ).get("detail", response.text)
                        )
                    except HarfangLabPluginException:
                        api_err_msg = str(response.text)

                    if retry_count == MAX_API_CALLS - 1:
                        err_msg = (
                            f"Received exit code {response.status_code},"
                            f" HTTP Server Error while {logger_msg}."
                            " Max retries exceeded."
                        )
                        self.logger.error(
                            message=f"{self.log_prefix}: {err_msg}",
                            details=api_err_msg,
                            resolution=(
                                "Check HarfangLab service status and retry."
                                " If the issue persists, contact"
                                " HarfangLab support."
                            ),
                        )
                        raise HarfangLabPluginException(err_msg)
                    self.logger.error(
                        message=(
                            f"{self.log_prefix}: Received exit code"
                            f" {response.status_code}, HTTP Server Error"
                            f" while {logger_msg}. Retrying after"
                            f" {DEFAULT_WAIT_TIME} seconds."
                            f" {MAX_API_CALLS - 1 - retry_count}"
                            " retries remaining."
                        ),
                        details=api_err_msg,
                        resolution=(
                            f"Ensure that the {PLATFORM_NAME} platform is"
                            " reachable."
                        ),
                    )
                    time.sleep(DEFAULT_WAIT_TIME)
                    continue

                # Non-retryable response (success or client error)
                break

            if is_handle_error_required:
                return self.handle_error(
                    response, logger_msg, is_validation=is_validation
                )
            return response

        except HarfangLabPluginException:
            raise
        except requests.exceptions.ReadTimeout as error:
            err_msg = f"Read timeout occurred while {logger_msg}."
            if is_validation:
                err_msg = "Read Timeout error occurred."
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {error}",
                details=str(traceback.format_exc()),
                resolution=(
                    "Check network connectivity to HarfangLab and ensure"
                    " the Tenant URL is reachable."
                ),
            )
            raise HarfangLabPluginException(err_msg)
        except requests.exceptions.ProxyError as error:
            err_msg = (
                f"Proxy error occurred while {logger_msg}. "
                "Verify the proxy configuration."
            )
            if is_validation:
                err_msg = (
                    "Proxy error occurred. Verify the proxy"
                    " configuration provided."
                )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {error}",
                details=str(traceback.format_exc()),
                resolution=(
                    "Verify the proxy configuration in Netskope CE settings"
                    " and ensure the proxy can reach HarfangLab."
                ),
            )
            raise HarfangLabPluginException(err_msg)
        except requests.exceptions.ConnectionError as error:
            err_msg = (
                f"Unable to establish connection with {PLATFORM_NAME}"
                f" while {logger_msg}. {PLATFORM_NAME} server or proxy"
                " is not reachable."
            )
            if is_validation:
                err_msg = (
                    f"Unable to establish connection with {PLATFORM_NAME}"
                    f" platform. Proxy server or {PLATFORM_NAME}"
                    " server is not reachable."
                )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {error}",
                details=str(traceback.format_exc()),
                resolution=(
                    "Verify the Tenant URL is correct, the"
                    " HarfangLab server is reachable, and proxy"
                    " settings are configured correctly."
                ),
            )
            raise HarfangLabPluginException(err_msg)
        except requests.exceptions.InvalidHeader:
            err_msg = (
                "Invalid request header encountered while"
                f" {logger_msg}. Verify the API Token does not"
                " contain invalid or non-ASCII characters."
            )
            if is_validation:
                err_msg = (
                    "Invalid API Token provided. Verify the API Token"
                    " does not contain invalid characters."
                )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                resolution=(
                    "Navigate to HarfangLab Home > Personal Settings"
                    " and verify or regenerate the API Token."
                ),
            )
            raise HarfangLabPluginException(err_msg)
        except requests.HTTPError as error:
            err_msg = f"HTTP error occurred while {logger_msg}."
            if is_validation:
                err_msg = (
                    "HTTP error occurred. Verify configuration"
                    " parameters provided."
                )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {error}",
                details=str(traceback.format_exc()),
                resolution=(
                    "Check the HarfangLab API configuration and verify"
                    " the request parameters."
                ),
            )
            raise HarfangLabPluginException(err_msg)
        except Exception as error:
            err_msg = f"Unexpected error occurred while {logger_msg}."
            if is_validation:
                err_msg = (
                    "Unexpected error while performing API call to"
                    f" {PLATFORM_NAME}."
                )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {error}",
                details=str(traceback.format_exc()),
                resolution=(
                    "Check HarfangLab connectivity and configuration."
                    " Contact support if the issue persists."
                ),
            )
            raise HarfangLabPluginException(err_msg)

    def parse_response(
        self,
        response: requests.models.Response,
        logger_msg: str = "",
        is_validation: bool = False,
    ) -> Dict:
        """Parse JSON from an API response.

        Args:
            response: Response object.
            logger_msg (str): Context for error messages.
            is_validation (bool): Use validation-focused error message.

        Returns:
            Dict: Parsed JSON body.

        Raises:
            HarfangLabPluginException: On JSON decode failure.
        """
        try:
            return response.json()
        except json.JSONDecodeError as err:
            err_msg = (
                "Invalid JSON response received from API."
                f" Error: {err}"
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=f"API response: {response.text}",
                resolution=(
                    "Verify the Tenant URL is correct and the HarfangLab"
                    " API returns a valid JSON response."
                ),
            )
            if is_validation:
                err_msg = (
                    "Verify the Tenant URL provided in the configuration"
                    " parameters. Check logs for more details."
                )
            raise HarfangLabPluginException(err_msg)
        except Exception as err:
            err_msg = (
                "Unexpected error while parsing JSON response."
                f" Error: {err}"
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=f"API response: {response.text}",
                resolution=(
                    "Check the HarfangLab API response format and retry."
                ),
            )
            if is_validation:
                err_msg = (
                    "Unexpected error while parsing response from"
                    f" {PLATFORM_NAME}. Check logs for more details."
                )
            raise HarfangLabPluginException(err_msg)

    def handle_error(
        self,
        resp: requests.models.Response,
        logger_msg: str,
        is_validation: bool = False,
    ) -> Dict:
        """Handle HTTP response codes and raise on errors.

        Args:
            resp: Response object.
            logger_msg (str): Context for error messages.
            is_validation (bool): Use user-facing, config-focused
                messages when True.

        Returns:
            Dict: Parsed JSON for 200/201/202; empty dict for 204.

        Raises:
            HarfangLabPluginException: For all non-success status codes.
        """
        if resp.status_code in (200, 201, 202):
            return self.parse_response(
                response=resp,
                logger_msg=logger_msg,
                is_validation=is_validation,
            )
        if resp.status_code == 204:
            return {}

        # Build per-status messages and resolutions.
        error_dict = {
            400: (
                f"Received exit code 400, Bad Request while {logger_msg}."
            ),
            401: (
                "Received exit code 401, Unauthorized while"
                f" {logger_msg}. "
                + (
                    "Check the API Token provided."
                    if is_validation
                    else "Verify the API Token is still valid."
                )
            ),
            403: (
                "Received exit code 403, Forbidden while"
                f" {logger_msg}. "
                + (
                    "Verify the API Token has the required permissions."
                    if is_validation
                    else "API Token lacks required permissions."
                )
            ),
            404: (
                "Received exit code 404, Resource not found while"
                f" {logger_msg}. "
                + (
                    "Verify the Tenant URL provided."
                    if is_validation
                    else "The requested resource was not found."
                )
            ),
        }
        resolution_dict = {
            400: (
                "Review the request payload. Ensure all indicator"
                " values and parameters conform to"
                " HarfangLab API requirements."
            ),
            401: (
                "Navigate to Administration > Users, select your user,"
                " and verify the API Token value."
            ),
            403: (
                "Ensure the API Token has Read/Write permissions for"
                " IOC Sources, IOC Rules, and Driver Block List."
            ),
            404: (
                "Verify the Tenant URL is correct and includes the"
                " scheme (https://)."
            ),
        }

        if resp.status_code in error_dict:
            err_msg = error_dict[resp.status_code]
            try:
                resp_json = self.parse_response(
                    response=resp,
                    logger_msg=logger_msg,
                    is_validation=is_validation,
                )
                api_error = resp_json.get("detail", resp.text)
            except HarfangLabPluginException:
                api_error = resp.text
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=f"API response: {api_error}",
                resolution=resolution_dict.get(resp.status_code, ""),
            )
            raise HarfangLabPluginException(err_msg)

        if 400 <= resp.status_code < 500:
            err_msg = (
                f"Received exit code {resp.status_code}, HTTP Client"
                f" Error while {logger_msg}."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=f"API response: {resp.text}",
                resolution=(
                    "Check the request parameters and HarfangLab API"
                    " documentation for this endpoint."
                ),
            )
            raise HarfangLabPluginException(err_msg)

        if 500 <= resp.status_code < 600:
            err_msg = (
                f"Received exit code {resp.status_code}, HTTP Server"
                f" Error while {logger_msg}."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=f"API response: {resp.text}",
                resolution=(
                    "Check HarfangLab service status and retry."
                    " If the issue persists, contact HarfangLab support."
                ),
            )
            raise HarfangLabPluginException(err_msg)

        err_msg = (
            f"Received exit code {resp.status_code}, HTTP Error"
            f" while {logger_msg}."
        )
        self.logger.error(
            message=f"{self.log_prefix}: {err_msg}",
            details=f"API response: {resp.text}",
            resolution=(
                "Refer to HarfangLab API documentation for the response"
                " code and verify the request configuration."
            ),
        )
        raise HarfangLabPluginException(err_msg)
