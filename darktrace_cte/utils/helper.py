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

CTE Darktrace plugin helper module.
"""

import hashlib
import hmac
import json
import time
import traceback
from datetime import datetime
from typing import Any, Dict, Literal, Tuple, Union
from urllib.parse import urlencode, urlparse

import requests
from netskope.common.utils import add_user_agent

from .constants import (
    RETRY_ERROR_MSG,
    MAX_API_CALLS,
    NO_MORE_RETRIES_ERROR_MSG,
    MODULE_NAME,
    PLATFORM_NAME,
    RETRACTION,
    DEFAULT_WAIT_TIME,
)
from .exception import DarktracePluginException


class DarktracePluginHelper(object):
    """DarktracePluginHelper Class.

    Args:
        object (object): Object class.
    """

    def __init__(
        self,
        logger,
        log_prefix: str,
        plugin_name: str,
        plugin_version: str,
    ):
        """DarktracePluginHelper initializer.

        Args:
            logger (logger object): Logger object.
            log_prefix (str): Log prefix.
            plugin_name (str): Plugin name.
            plugin_version (str): Plugin version.
        """
        self.logger = logger
        self.log_prefix = log_prefix
        self.plugin_name = plugin_name
        self.plugin_version = plugin_version

    def _add_user_agent(self, headers: Union[Dict, None] = None) -> Dict:
        """Add User-Agent in the headers for third-party requests.
        Args:
            headers (Dict): Dictionary containing headers for any request.
        Returns:
            Dict: Dictionary after adding User-Agent.
        """
        if headers and "User-Agent" in headers:
            return headers

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

    def api_helper(
        self,
        logger_msg: str,
        url: str,
        method: str = "GET",
        params: Dict = {},
        data=None,
        files=None,
        headers: Dict = {},
        json=None,
        proxy: Any = None,
        verify: Any = None,
        is_handle_error_required=True,
        is_validation=False,
        is_retraction: bool = False,
    ):
        """Execute an HTTP request with retry and Darktrace-specific logging.

        Args:
            logger_msg (str): Context used in log messages.
            url (str): Full request URL.
            method (str, optional): HTTP method. Defaults to "GET".
            params (Dict, optional): Query parameters. Defaults to {}.
            data (Any, optional): Request body for non-JSON payloads.
            files (Any, optional): Files for multipart uploads.
            headers (Dict, optional): Request headers. Defaults to {}.
            json (Any, optional): JSON payload for the request.
            proxy (Any, optional): Proxy configuration passed to requests.
            verify (Any, optional): SSL verification flag/path.
            is_handle_error_required (bool, optional): When True, apply
                response code handling and parsing. Defaults to True.
            is_validation (bool, optional): When True, tailor error messages
                for validation flows. Defaults to False.
            is_retraction (bool, optional): When True, append retraction tag to
                log prefix. Defaults to False.

        Returns:
            Response | dict: Parsed response JSON when error handling is
            enabled; otherwise the raw ``requests.Response`` object.

        Raises:
            DarktracePluginException: On validation, HTTP, connectivity, or
                unexpected errors after exhausting retries.
        """
        try:
            if is_retraction and RETRACTION not in self.log_prefix:
                self.log_prefix = self.log_prefix + f" [{RETRACTION}] "
            headers = self._add_user_agent(headers)

            debug_log_msg = (
                f"{self.log_prefix}: API Request for {logger_msg}."
                f" Endpoint: {method} {url}, params: {params}"
            )

            self.logger.debug(debug_log_msg)
            for retry_count in range(MAX_API_CALLS):
                response = requests.request(
                    url=url,
                    method=method,
                    params=params,
                    data=data,
                    headers=headers,
                    verify=verify,
                    proxies=proxy,
                    json=json,
                    files=files,
                )
                status_code = response.status_code
                self.logger.debug(
                    f"{self.log_prefix}: Received API Response for "
                    f"{logger_msg}. Status Code={status_code}."
                )
                if not is_validation and (
                    status_code == 429 or 500 <= status_code <= 600
                ):
                    api_err_msg = str(response.text)
                    if retry_count == MAX_API_CALLS - 1:
                        err_msg = NO_MORE_RETRIES_ERROR_MSG.format(
                            status_code=status_code,
                            logger_msg=logger_msg,
                        )
                        self.logger.error(
                            message=f"{self.log_prefix}: {err_msg}"
                        )
                        raise DarktracePluginException(
                            err_msg
                        )
                    if status_code == 429:
                        error_reason = "API rate limit exceeded"
                    else:
                        error_reason = "HTTP server error occurred"
                    err_msg = RETRY_ERROR_MSG.format(
                        status_code=status_code,
                        error_reason=error_reason,
                        logger_msg=logger_msg,
                        wait_time=DEFAULT_WAIT_TIME,
                        retry_remaining=MAX_API_CALLS - 1 - retry_count,
                    )
                    self.logger.error(
                        message=f"{self.log_prefix}: {err_msg}",
                        details=api_err_msg,
                    )
                    time.sleep(DEFAULT_WAIT_TIME)
                else:
                    return (
                        self.handle_error(response, logger_msg, is_validation)
                        if is_handle_error_required
                        else response
                    )
        except DarktracePluginException:
            raise
        except requests.exceptions.ReadTimeout as error:
            err_msg = f"Read Timeout error occurred while {logger_msg}."
            if is_validation:
                err_msg = "Read Timeout error occurred."

            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {error}",
                details=traceback.format_exc(),
                resolution=(
                    "Ensure that your Darktrace platform server"
                    " is reachable."
                ),
            )
            raise DarktracePluginException(err_msg)
        except requests.exceptions.ProxyError as error:
            err_msg = (
                f"Proxy error occurred while {logger_msg}. Verify the "
                "proxy configuration provided."
            )
            if is_validation:
                err_msg = (
                    "Proxy error occurred. Verify the proxy configuration"
                    " provided."
                )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {error}",
                details=traceback.format_exc(),
                resolution=(
                    "Ensure that the proxy configuration provided is"
                    " correct and the proxy server is reachable."
                ),
            )
            raise DarktracePluginException(err_msg)
        except requests.exceptions.ConnectionError as error:
            err_msg = (
                f"Unable to establish connection with {PLATFORM_NAME} "
                f"platform while {logger_msg}. Proxy server or "
                f"{PLATFORM_NAME} server is not reachable."
            )
            if is_validation:
                err_msg = (
                    f"Unable to establish connection with {PLATFORM_NAME} "
                    f"platform. Proxy server or {PLATFORM_NAME} "
                    "server is not reachable."
                )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {error}",
                details=traceback.format_exc(),
                resolution=(
                    "Ensure that your Darktrace platform server is reachable."
                ),
            )
            raise DarktracePluginException(err_msg)
        except requests.HTTPError as error:
            err_msg = f"HTTP error occurred while {logger_msg}."
            if is_validation:
                err_msg = (
                    "HTTP error occurred. Verify configuration parameters"
                    " provided."
                )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {error}",
                details=traceback.format_exc(),
                resolution=(
                    "Ensure that the configuration parameters provided are"
                    " correct."
                ),
            )
            raise DarktracePluginException(err_msg)
        except Exception as error:
            err_msg = f"Unexpected error occurred while {logger_msg}."
            if is_validation:
                err_msg = (
                    "Unexpected error while performing API call to"
                    f" {PLATFORM_NAME}."
                )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {error}",
                details=traceback.format_exc(),
                resolution=(
                    "Ensure that the configuration parameters provided are"
                    " correct."
                )
            )
            raise DarktracePluginException(err_msg)

    def parse_response(
        self,
        response: requests.models.Response,
        is_validation: bool = False,
        logger_msg: str = None,
    ):
        """Parse and return JSON from a requests.Response object.

        Args:
            response (requests.models.Response): Response received from API.
            is_validation (bool, optional): Whether called during validation
                to tune error messaging. Defaults to False.
            logger_msg (str, optional): Context message for logging.

        Returns:
            Any: Parsed JSON content from the response.

        Raises:
            DarktracePluginException: If the response body is not valid JSON
                or parsing fails unexpectedly.
        """
        try:
            return response.json()
        except json.JSONDecodeError as err:
            err_msg = (
                f"Invalid JSON response received from API while "
                f"{logger_msg}. Error: {str(err)}"
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=f"API response: {response.text}",
            )
            if is_validation:
                err_msg = (
                    "Verify Base URL provided in the "
                    "configuration parameters. Check logs for more details."
                )
            raise DarktracePluginException(err_msg)
        except Exception as exp:
            err_msg = (
                "Unexpected error occurred while parsing"
                f" json response for {logger_msg}. Error: {exp}"
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=f"API response: {response.text}",
            )
            if is_validation:
                err_msg = (
                    "Unexpected validation error occurred, "
                    "Verify Base URL provided in the "
                    "configuration parameters. Check logs for more details."
                )
            raise DarktracePluginException(err_msg)

    def handle_error(
        self,
        response: requests.models.Response,
        logger_msg: str,
        is_validation: bool = False,
    ):
        """Handle HTTP status codes and return parsed responses.

        Args:
            response (requests.models.Response): Response object from the API
                call.
            logger_msg (str): Context message for logging.
            is_validation (bool, optional): Whether the call originates from a
                validation flow. Defaults to False.

        Returns:
            dict: Parsed JSON for success status codes (200/201/202) or an
                empty dict for 204 responses.

        Raises:
            DarktracePluginException: For client or server errors with
                descriptive messages tailored to validation state.
        """
        status_code = response.status_code
        validation_msg = "Validation error occurred, "
        error_dict = {
            400: "Received exit code 400, HTTP client error",
            403: "Received exit code 403, Forbidden",
            401: "Received exit code 401, Unauthorized access",
            404: "Received exit code 404, Resource not found",
        }
        resolution_dict = {
            400: (
                "Verify the Base URL, Public Token and Private Token"
                " provided in the configuration parameters."
            ),
            401: (
                "Verify Public Token and Private Token provided in the"
                " configuration parameters."
            ),
            403: (
                "Verify permission for Public Token and Private Token"
                " provided in the configuration parameters."
            ),
            404: (
                "Verify the resource you are trying to access is valid."
            ),
        }
        if is_validation:
            error_dict = {
                400: (
                    "Received exit code 400, Bad Request, Verify the "
                    " Base URL, Public Token and Private Token provided in the"
                    " configuration parameters."
                ),
                401: (
                    "Received exit code 401, Unauthorized, Verify "
                    "Public Token and Private Token provided in the "
                    "configuration parameters."
                ),
                403: (
                    "Received exit code 403, Forbidden, Verify API scopes "
                    " provided to Public Token and Private Token."
                ),
                404: (
                    "Received exit code 404, Resource not found, Verify "
                    "Base URL provided in the configuration parameters."
                ),
            }

        def _log_error_message(resolution: str = None):
            nonlocal err_msg
            if is_validation:
                log_err_msg = validation_msg + err_msg
                self.logger.error(
                    message=f"{self.log_prefix}: {log_err_msg}",
                    details=f"API response: {response.text}",
                    resolution=resolution,
                )
                raise DarktracePluginException(err_msg)
            else:
                err_msg = err_msg + " while " + logger_msg + "."
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg}",
                    details=f"API response: {response.text}",
                )
                raise DarktracePluginException(err_msg)

        if status_code in [200, 201, 202]:
            return self.parse_response(
                response=response,
                is_validation=is_validation,
                logger_msg=logger_msg,
            )
        elif status_code == 204:
            return {}
        elif status_code in error_dict:
            err_msg = error_dict[status_code]
            resolution_msg = resolution_dict[status_code]
            _log_error_message(resolution=resolution_msg)
        elif status_code >= 400 and status_code < 500:
            err_msg = "HTTP Client Error"
            _log_error_message()
        elif status_code >= 500 and status_code < 600:
            err_msg = "HTTP Server Error"
            _log_error_message()
        else:
            err_msg = "HTTP Error"
            _log_error_message()

    def get_configuration_parameters(
        self, configuration: Dict
    ) -> Tuple[str, str, str, str, str]:
        """Extract Darktrace configuration parameters.

        Args:
            configuration (Dict): Configuration dictionary from the plugin
                settings.

        Returns:
            Tuple[str, str, str, str, str]: Base URL, public token, private
            token, source name, and pull toggle flag.
        """
        base_url = configuration.get("base_url").strip().strip("/")
        public_token = configuration.get("public_token")
        private_token = configuration.get("private_token")
        source = configuration.get("source")
        is_pull_enabled = configuration.get("is_pull_required")
        return base_url, public_token, private_token, source, is_pull_enabled

    def get_auth_headers(
        self,
        public_token: str,
        private_token: str,
        endpoint: str,
        query_parameters: Dict = None,
        request_body: Dict = None,
        method: Literal["GET", "POST"] = "GET"
    ) -> Dict:
        """Generate Darktrace API authentication headers.

        Args:
            public_token (str): Public token for the Darktrace API.
            private_token (str): Private token used to sign the request.
            endpoint (str): API endpoint path (with or without leading "/").
            query_parameters (Dict, optional): Query parameters for the
                request. Defaults to None.
            request_body (Dict, optional): Request body for POST requests.
                Defaults to None.
            method (Literal["GET", "POST"], optional): HTTP method. Defaults
                to "GET".

        Returns:
            Dict: Headers including Accept, DTAPI-Token, DTAPI-Date, and
            DTAPI-Signature (and Content-Type for POST).
        """
        headers = {
            "Accept": "application/json"
        }
        if method == "POST":
            headers.update(
                {"Content-Type": "application/json"}
            )
        date_str = datetime.utcnow().strftime('%Y%m%dT%H%M%S') + 'Z'

        request_url = endpoint
        if not request_url.startswith('/'):
            request_url = '/' + request_url

        if query_parameters:
            query_string = urlencode(query_parameters)
            request_url += '?' + query_string

        auth_sig_string = request_url
        if request_body:
            if isinstance(request_body, dict):
                body_string = json.dumps(request_body)
            else:
                body_string = str(request_body)
            if body_string:
                if '?' not in request_url:
                    auth_sig_string += '?' + body_string
                else:
                    auth_sig_string += '&' + body_string

        hmac_source = (
            auth_sig_string + '\n' + public_token + '\n' + date_str
        )
        signature = hmac.new(
            private_token.encode('utf-8'),
            hmac_source.encode('utf-8'),
            hashlib.sha1
        ).hexdigest()

        headers.update(
            {
                "DTAPI-Token": public_token,
                "DTAPI-Date": date_str,
                "DTAPI-Signature": signature,
            }
        )
        return headers

    def calculate_ce_reputation(self, value: int):
        """Map Darktrace score to CE reputation bucket (1-10).

        Args:
            value (int): Darktrace score.

        Returns:
            int: CE reputation value.
        """
        ce_confidence = ((value - 1) // 10) + 1
        return int(ce_confidence)

    def calculate_darktrace_strength(self, value: int):
        """Convert CE reputation to Darktrace strength (0-100 scale).

        Args:
            value (int): CE reputation value.

        Returns:
            int: Darktrace strength value.
        """
        darktrace_strength = value * 10
        return int(darktrace_strength)

    def validate_url(self, url: str) -> bool:
        """Validate that a URL contains a scheme and network location.

        Args:
            url (str): URL to validate.

        Returns:
            bool: True if both scheme and netloc are non-empty; otherwise
                False.
        """
        parsed = urlparse(url)
        return parsed.scheme.strip() != "" and parsed.netloc.strip() != ""
