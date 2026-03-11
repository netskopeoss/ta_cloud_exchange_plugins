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

CTE Imperva Plugin constants.
"""

import json
import time
import traceback
import requests
from packaging import version
from typing import Dict, Tuple, Union

from netskope.common.api import __version__ as CE_VERSION
from netskope.common.utils import add_user_agent
from .constants import (
    MODULE_NAME,
    PLATFORM_NAME,
    DEFAULT_SLEEP_TIME,
    MAX_API_CALLS,
    RETRACTION,
    MAXIMUM_CE_VERSION
)


class ImpervaPluginException(Exception):
    """Imperva plugin custom exception class."""

    pass


class ImpervaPluginHelper:
    """Imperva plugin helper module."""

    def __init__(
        self,
        logger,
        log_prefix: str,
        plugin_name: str,
        plugin_version: str,
    ):
        """Imperva Plugin Helper initializer.

        Args:
            logger (logger object): Logger object.
            log_prefix (str): log prefix.
            plugin_name (str): Plugin name.
            plugin_version (str): Plugin version.
        """
        self.log_prefix = log_prefix
        self.logger = logger
        self.plugin_name = plugin_name
        self.plugin_version = plugin_version
        self.resolution_support = version.parse(CE_VERSION) > version.parse(
            MAXIMUM_CE_VERSION
        )
        # Patch logger methods to handle resolution parameter compatibility
        self._patch_logger_methods()

    def _patch_logger_methods(self):
        """Monkey patch logger methods to handle \
            resolution parameter compatibility."""
        # Store original methods
        original_error = self.logger.error

        def patched_error(
            message=None, details=None, resolution=None, **kwargs
        ):
            """Patched error method that handles resolution compatibility."""
            log_kwargs = {"message": message}
            if details:
                log_kwargs["details"] = details
            if resolution and self.resolution_support:
                log_kwargs["resolution"] = resolution
            log_kwargs.update(kwargs)
            return original_error(**log_kwargs)

        # Replace logger methods with patched versions
        self.logger.error = patched_error

    def _add_user_agent(self, headers: Union[Dict, None] = None) -> Dict:
        """Add User-Agent in the headers for third-party requests.

        Args:
            headers (Dict): Dictionary containing headers for any request.
        Returns:
            Dict: Dictionary after adding User-Agent.
        """
        if headers and "User-Agent" in headers:
            return headers

        headers = add_user_agent(header=headers)
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
        verify: bool = True,
        proxies: Dict = {},
        is_validation: bool = False,
        is_retraction: bool = False,
        is_handle_error_required: bool = True,
    ) -> Dict:
        """
        API helper to perform API request on ThirdParty platform and captures
        all the possible errors for requests.

        Args:
            logger_msg (str): Logger message.
            url (str): API Endpoint.
            method (str): Method for the endpoint.
            params (Dict): Request parameters dictionary.
            data (Any,optional): Data to be sent to API. Defaults to None.
            files (Any, optional): Files to be sent to API. Defaults to None.
            headers (Dict, optional): Headers for the request. Defaults to {}.
            json (optional): Json payload for request. Defaults to None.
            verify (bool, optional): Verify SSL. Defaults to True.
            proxies (Dict, optional): Proxies. Defaults to {}.
            is_validation (bool, optional): Does this request coming from
                validate method?. Defaults to False.
            is_retraction (bool, optional): Is this called from the retraction.
            is_handle_error_required (bool, optional): Is handling status code
                is required?. Defaults to True.

        Returns:
            Dict: Response dictionary.
        """
        if is_retraction and RETRACTION not in self.log_prefix:
            self.log_prefix = self.log_prefix + f" [{RETRACTION}]"
        headers = self._add_user_agent(headers)
        debug_log_msg = (
            f"{self.log_prefix}: API Request for {logger_msg}. "
            f"Endpoint: {method} {url}"
        )
        if params:
            debug_log_msg += f", params: {params}."
        self.logger.debug(debug_log_msg)

        try:
            for retry_counter in range(MAX_API_CALLS):
                response = requests.request(
                    method=method,
                    url=url,
                    params=params,
                    data=data,
                    files=files,
                    headers=headers,
                    json=json,
                    verify=verify,
                    proxies=proxies,
                )
                status_code = response.status_code
                self.logger.debug(
                    f"{self.log_prefix}: Received API Response for "
                    f"{logger_msg}. Status Code={status_code}."
                )

                if not is_validation and (
                    status_code == 429 or status_code in range(500, 601)
                ):
                    if retry_counter == MAX_API_CALLS - 1:
                        error_msg = (
                            f"Received exit code {status_code}, while"
                            f" {logger_msg}. Max retries limit "
                            "exceeded hence returning status"
                            f" code {status_code}."
                        )
                        self.logger.error(
                            message=f"{self.log_prefix}: {error_msg}",
                            details=f"API response: {response.text}",
                        )
                        raise ImpervaPluginException(error_msg)
                    self.logger.error(
                        message=(
                            f"{self.log_prefix}: Received exit code"
                            f" {status_code}, "
                            f"while {logger_msg}. Retrying after "
                            f"{DEFAULT_SLEEP_TIME} seconds. "
                            f"{MAX_API_CALLS - 1 - retry_counter} "
                            "retries remaining."
                        ),
                        details=f"API response: {response.text}",
                    )
                    time.sleep(DEFAULT_SLEEP_TIME)
                else:
                    return (
                        self._handle_error(
                            response=response,
                            logger_msg=logger_msg,
                            is_validation=is_validation,
                        )
                        if is_handle_error_required
                        else response
                    )
        except ImpervaPluginException:
            raise
        except requests.exceptions.ReadTimeout as error:
            err_msg = (
                f"Read Timeout error occurred while {logger_msg}."
            )
            if is_validation:
                err_msg = (
                    "Read Timeout error occurred. "
                    "Verify the 'API API Base URL' provided in the "
                    "configuration parameters."
                )

            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {error}",
                details=traceback.format_exc(),
            )
            raise ImpervaPluginException(err_msg)
        except requests.exceptions.ProxyError as error:
            err_msg = (
                f"Proxy error occurred while {logger_msg} when trying "
                f"to communicate with {PLATFORM_NAME} platform. "
                "Verify the proxy configuration provided."
            )
            if is_validation:
                err_msg = (
                    "Proxy error occurred when trying "
                    f"to communicate with {PLATFORM_NAME} platform. "
                    "Verify the proxy configuration provided."
                )

            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {error}",
                details=traceback.format_exc(),
            )
            raise ImpervaPluginException(err_msg)
        except requests.exceptions.ConnectionError as e:
            err_msg = (
                f"Unable to establish connection with {PLATFORM_NAME} "
                f"platform while {logger_msg}. Proxy server or "
                f"{PLATFORM_NAME} server is not reachable."
            )
            if is_validation:
                err_msg = (
                    f"Unable to establish connection with {PLATFORM_NAME} "
                    f"platform. Proxy server or {PLATFORM_NAME} server is "
                    "not reachable."
                )

            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {e}",
                details=traceback.format_exc(),
            )
            raise ImpervaPluginException(err_msg)
        except requests.HTTPError as e:
            err_msg = f"HTTP error occurred while {logger_msg}."
            if is_validation:
                err_msg = (
                    "HTTP error occurred. Verify configuration parameters "
                    "provided."
                )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {e}",
                details=traceback.format_exc(),
            )
            raise ImpervaPluginException(err_msg)
        except Exception as e:
            err_msg = f"Unexpected error occurred while {logger_msg}."
            if is_validation:
                err_msg = (
                    f"Unexpected error while performing API call to "
                    f"{PLATFORM_NAME}."
                )
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg} Error: {e}",
                    details=traceback.format_exc(),
                )
                raise ImpervaPluginException(
                    f"{err_msg} Check logs for more details."
                )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {e}",
                details=traceback.format_exc(),
            )
            raise ImpervaPluginException(err_msg)

    def _handle_error(
        self,
        response: requests.models.Response,
        logger_msg: str,
        is_validation: bool = False,
    ) -> Dict:
        """
        Handles the different HTTP response code.

        Args:
            response (requests.models.Response): Response object returned from
                API call.
            logger_msg (str): Logger message.
            is_validation (bool, optional): API call from validation method or
                not. Defaults to False.

        Returns:
            dict: Returns the dictionary of response JSON
                when the response code is 200, 201 or 202.
        """
        status_code = response.status_code
        validation_error_msg = "Validation error occurred, "
        error_dict = {
            400: "Received exit code 400 (Bad Request)",
            403: "Received exit code 403 (Forbidden)",
            401: "Received exit code 401 (Unauthorized access)",
            404: "Received exit code 404 (Resource not found)",
        }
        resolution_dict = {
            400: (
                "Ensure that the Account ID, API ID and API Key "
                "provided in the configuration parameters "
                "are valid, enabled and not expired."
            ),
            401: (
                "Ensure that the Account ID, API ID and API Key "
                "provided in the configuration parameters "
                "are valid, enabled and not expired."
            ),
            403: (
                "Ensure that the API ID and API Key has "
                "required permissions or roles."
            ),
            404: (
                "Ensure that the Imperva API Base URL is valid."
            ),
        }
        if is_validation:
            error_dict = {
                400: (
                    "Received exit code 400 (Bad Request), "
                    "Verify the Account ID, API ID and API Key "
                    "provided in the configuration parameters "
                    "are valid, enabled and not expired."
                ),
                401: (
                    "Received exit code 401 (Unauthorized), "
                    "Verify the Account ID, API ID and API Key "
                    "provided in the configuration parameters "
                    "are valid, enabled and not expired."
                ),
                403: (
                    "Received exit code 403 (Forbidden), "
                    "Verify the API ID and API Key has "
                    "required permissions or roles."
                ),
                404: (
                    "Received exit code 404 (Resource not found), "
                    "Verify Imperva API Base URL is valid."
                ),
            }
        if status_code in [200, 201, 202]:
            return self._parse_response(
                response=response,
                logger_msg=logger_msg,
                is_validation=is_validation,
            )
        elif status_code == 204:
            return {}

        elif error_msg := error_dict.get(status_code):
            if is_validation:
                log_error_msg = validation_error_msg + error_msg
                self.logger.error(
                    message=f"{self.log_prefix}: {log_error_msg}",
                    details=f"API response: {response.text}",
                    resolution=resolution_dict.get(status_code),
                )
                raise ImpervaPluginException(log_error_msg)
            else:
                err_msg = error_msg + " while " + logger_msg + "."
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg}",
                    details=f"API response: {response.text}",
                    resolution=resolution_dict.get(status_code),
                )
                raise ImpervaPluginException(err_msg)
        else:
            err_msg = (
                "HTTP Server Error"
                if (status_code >= 500 and status_code <= 600)
                else "HTTP Error"
            )
            if is_validation:
                err_msg = validation_error_msg + err_msg
            else:
                err_msg += " while " + logger_msg + "."
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Received exit code {status_code}, "
                    f"{err_msg} while {logger_msg}."
                ),
                details=f"API response: {response.text}",
            )
            raise ImpervaPluginException(err_msg)

    def _parse_response(
        self,
        response: requests.models.Response,
        logger_msg: str,
        is_validation: bool = False,
    ) -> Dict:
        """
        Parse Response will return JSON from response object.

        Args:
            response (response): Response object.
            logger_msg (str): Logger message
            is_validation: (bool): Check for validation

        Returns:
            Any: Response Json.
        """
        try:
            return response.json()
        except json.JSONDecodeError as err:
            err_msg = (
                f"Invalid JSON response received "
                f"from API while {logger_msg}. "
                f"Error: {str(err)}"
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=f"API response: {response.text}",
            )
            if is_validation:
                err_msg = (
                    "Verify Imperva API Base URL provided in the "
                    "configuration parameters. "
                    "Check logs for more details."
                )
            raise ImpervaPluginException(err_msg)
        except Exception as exp:
            err_msg = (
                "Unexpected error occurred while parsing "
                f"json response while {logger_msg}. Error: {exp}"
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=f"API response: {response.text}",
            )
            if is_validation:
                err_msg = (
                    "Unexpected validation error occurred, "
                    "Verify Imperva API Base URL provided in the "
                    "configuration parameters. "
                    "Check logs for more details."
                )
            raise ImpervaPluginException(err_msg)

    def get_configuration_parameters(
        self, configuration: Dict
    ) -> Tuple[str, str, str, str, str, str]:
        """
        Get configuration parameters from the configuration dictionary.

        Args:
            configuration (Dict): Dictionary containing the configuration
                parameters.

        Returns:
            Tuple[str, str, str, str, str, str]: Tuple containing \
                the configuration parameters.
        """
        return (
            configuration.get("account_id", "").strip(),
            configuration.get("api_id", ""),
            configuration.get("api_key", ""),
            configuration.get("enable_tagging", ""),
            configuration.get("retraction_interval", ""),
            configuration.get("initial_pull_range", ""),
        )

    def get_auth_headers(self, api_id: str, api_key: str) -> Dict:
        """
        Get the authentication headers for the Imperva plugin.

        Args:
            api_id (str): The API ID for the Imperva plugin.
            api_key (str): The API Key for the Imperva plugin.

        Returns:
            Dict: A dictionary containing the authentication headers.
        """
        return {
            "accept": "application/json",
            "x-API-Id": api_id,
            "x-API-Key": api_key
        }
