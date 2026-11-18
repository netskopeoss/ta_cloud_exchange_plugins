"""BSD 3-Clause License.

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

CTE Microsoft Defender for Cloud Apps plugin helper module.
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
    MODULE_NAME,
    PLUGIN_NAME,
    RETRACTION,
)


class MCASPluginException(Exception):
    """Microsoft Defender for Cloud Apps plugin custom exception class."""

    pass


class MCASPluginHelper(object):
    """MCASPluginHelper class.

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
        """MCAS Plugin Helper initializer.

        Args:
            logger (logger object): Logger object.
            log_prefix (str): Log prefix.
            plugin_name (str): Plugin name.
            plugin_version (str): Plugin version.
        """
        self.log_prefix = log_prefix
        self.logger = logger
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
        headers: Dict = {},
        json=None,
        verify: bool = True,
        proxies=None,
        is_handle_error_required: bool = True,
        is_validation: bool = False,
        is_retraction: bool = False,
    ):
        """API Helper to perform API request and handle errors.

        Args:
            logger_msg (str): Logger message.
            url (str): API Endpoint.
            method (str): Method for the endpoint.
            params (Dict, optional): Request parameters dictionary.
            data (Any, optional): Data to be sent to API.
            headers (Dict, optional): Headers for the request.
            json (optional): Json payload for request.
            verify (bool, optional): Verify SSL.
            proxies (Dict, optional): Proxies.
            is_handle_error_required (bool, optional): Handle status codes.
            is_validation (bool, optional): Is validation request.
            is_retraction (bool, optional): Is retraction request.

        Returns:
            Response|dict: Response object or JSON response.
        """
        try:
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

            for retry_counter in range(MAX_API_CALLS):
                response = requests.request(
                    url=url,
                    method=method,
                    params=params,
                    data=data,
                    headers=headers,
                    verify=verify,
                    proxies=proxies,
                    json=json,
                )
                status_code = response.status_code
                self.logger.debug(
                    f"{self.log_prefix}: Received API Response for "
                    f"{logger_msg}. Status Code={status_code}."
                )

                if (
                    status_code == 429 or 500 <= status_code <= 600
                ) and not is_validation:
                    api_err_msg = str(response.text)
                    if retry_counter == MAX_API_CALLS - 1:
                        err_msg = (
                            f"Received exit code {status_code}, "
                            f"while {logger_msg}. Max retries "
                            "exceeded hence returning status "
                            f"code {status_code}."
                        )
                        self.logger.error(
                            message=f"{self.log_prefix}: {err_msg}",
                            details=api_err_msg,
                            resolution=(
                                "Ensure that the API endpoint is accessible "
                                "and the server is not experiencing issues."
                            ),
                        )
                        raise MCASPluginException(err_msg)

                    if status_code == 429:
                        log_err_msg = "API rate limit exceeded"
                    else:
                        log_err_msg = "HTTP server error occurred"

                    self.logger.error(
                        message=(
                            f"{self.log_prefix}: Received exit code "
                            f"{status_code}, {log_err_msg} while "
                            f"{logger_msg}. Retrying after "
                            f"{DEFAULT_WAIT_TIME} seconds. "
                            f"{MAX_API_CALLS - 1 - retry_counter} "
                            "retries remaining."
                        ),
                        details=api_err_msg,
                    )
                    time.sleep(DEFAULT_WAIT_TIME)
                else:
                    return (
                        self.handle_error(response, logger_msg, is_validation)
                        if is_handle_error_required
                        else response
                    )

        except requests.exceptions.ReadTimeout as error:
            err_msg = f"Read timeout error occurred while {logger_msg}."
            if is_validation:
                err_msg = (
                    "Read timeout error occurred. Ensure that the provided "
                    "configuration parameters are correct."
                )

            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {error}",
                details=str(traceback.format_exc()),
                resolution=(
                    f"Ensure that your {PLUGIN_NAME} server is "
                    "reachable and the network connection is stable."
                ),
            )
            raise MCASPluginException(err_msg)

        except requests.exceptions.ProxyError as error:
            err_msg = f"Proxy error occurred while {logger_msg}."
            if is_validation:
                err_msg = (
                    "Proxy error occurred. Ensure that the proxy "
                    "configuration is correct."
                )

            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {error}",
                details=str(traceback.format_exc()),
                resolution=(
                    "Ensure that the proxy configuration provided is "
                    "correct and the proxy server is reachable."
                ),
            )
            raise MCASPluginException(err_msg)

        except requests.exceptions.ConnectionError as error:
            err_msg = (
                f"Unable to establish connection with {PLUGIN_NAME} "
                f"platform while {logger_msg}."
            )
            if is_validation:
                err_msg = (
                    f"Unable to establish connection with {PLUGIN_NAME} "
                    "platform. Ensure that the URL and network connectivity "
                    "are correct."
                )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {error}",
                details=str(traceback.format_exc()),
                resolution=(
                    f"Ensure that your {PLUGIN_NAME} server is reachable "
                    "and the proxy server configuration is correct."
                ),
            )
            raise MCASPluginException(err_msg)

        except requests.HTTPError as err:
            err_msg = f"HTTP error occurred while {logger_msg}."
            if is_validation:
                err_msg = (
                    "HTTP error occurred. Ensure that the configuration "
                    "parameters are correct."
                )

            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {err}",
                details=str(traceback.format_exc()),
                resolution=(
                    "Ensure that the configuration parameters provided are "
                    "correct and the API endpoint is valid."
                ),
            )
            raise MCASPluginException(err_msg)

        except MCASPluginException:
            raise

        except Exception as exp:
            err_msg = f"Unexpected error occurred while {logger_msg}."
            if is_validation:
                err_msg = (
                    "Unexpected error while "
                    f"performing API call to {PLUGIN_NAME}."
                )

            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {exp}",
                details=str(traceback.format_exc()),
                resolution=(
                    "Ensure that the configuration parameters provided "
                    "are correct."
                ),
            )
            raise MCASPluginException(err_msg)

    def parse_response(
        self, response: requests.models.Response, logger_msg: str,
        is_validation: bool = False
    ) -> Dict:
        """Parse Response will return JSON from response object.

        Args:
            response (requests.models.Response): Response object.
            logger_msg (str): Logger message.
            is_validation (bool): Check for validation.

        Returns:
            Dict: Response JSON.
        """
        try:
            return response.json()
        except json.JSONDecodeError as err:
            err_msg = (
                f"Invalid JSON response received "
                f"from API while {logger_msg}."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {err}",
                details=f"API response: {response.text}",
                resolution=(
                    "Ensure that the API endpoint and "
                    "configuration parameters are correct."
                ),
            )
            if is_validation:
                err_msg = (
                    "Ensure that the URL and API Token provided "
                    "in the configuration parameters are correct."
                )
            raise MCASPluginException(err_msg)

        except Exception as exp:
            err_msg = (
                f"Unexpected error occurred while parsing "
                f"JSON response while {logger_msg}."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {exp}",
                details=f"API response: {response.text}",
            )
            if is_validation:
                err_msg = (
                    "Unexpected validation error occurred. Ensure that the "
                    "URL and API Token provided in the "
                    "configuration parameters are correct."
                )
            raise MCASPluginException(err_msg)

    def handle_error(
        self,
        resp: requests.models.Response,
        logger_msg: str,
        is_validation: bool = False,
    ) -> Dict:
        """Handle different HTTP response codes.

        Args:
            resp (requests.models.Response): Response object.
            logger_msg (str): Logger message.
            is_validation (bool): API call from validation method or not.

        Returns:
            dict: Response JSON when response code is 200.

        Raises:
            MCASPluginException: When response code is not 200.
        """
        status_code = resp.status_code
        validation_msg = "Validation error occurred. "

        if status_code in [200, 201]:
            return self.parse_response(resp, logger_msg, is_validation)

        error_dict = {
            400: "Received exit code 400, Bad Request",
            401: "Received exit code 401, Unauthorized access",
            403: "Received exit code 403, Forbidden",
            404: "Received exit code 404, Resource not found",
        }

        if is_validation:
            error_dict = {
                400: (
                    "Received exit code 400, Bad Request. Ensure that the URL "
                    "and API Token provided in the configuration parameters "
                    "are correct."
                ),
                401: (
                    "Received exit code 401, Unauthorized. Ensure that the "
                    "API Token provided in the configuration parameters "
                    "is correct."
                ),
                403: (
                    "Received exit code 403, Forbidden. Ensure that the API "
                    "Token has the required permissions."
                ),
                404: (
                    "Received exit code 404, Resource not found. Ensure that "
                    "the URL provided in the configuration parameters "
                    "is correct."
                ),
            }

        resolution_dict = {
            400: (
                "Ensure that the URL and API Token provided in the "
                "configuration parameters are correct."
            ),
            401: (
                "Ensure that the API Token provided in the configuration "
                "parameters is correct."
            ),
            403: (
                "Ensure that the API Token has the required permissions."
            ),
            404: (
                "Ensure that the URL is correct and the resource exists."
            ),
        }

        if status_code in error_dict:
            err_msg = error_dict[status_code]
            resolution_msg = resolution_dict.get(status_code)

            if is_validation:
                log_err_msg = validation_msg + err_msg
                self.logger.error(
                    message=f"{self.log_prefix}: {log_err_msg}",
                    details=f"API response: {resp.text}",
                    resolution=resolution_msg,
                )
                raise MCASPluginException(err_msg)
            else:
                err_msg = err_msg + " while " + logger_msg + "."
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg}",
                    details=f"API response: {resp.text}",
                    resolution=resolution_msg,
                )
                raise MCASPluginException(err_msg)
        else:
            err = (
                "HTTP Server Error"
                if (500 <= status_code <= 600)
                else "HTTP Error"
            )
            err_msg = (
                f"Received exit code {status_code}, {err} "
                f"while {logger_msg}."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=str(resp.text),
                resolution=(
                    f"Ensure that the {PLUGIN_NAME} platform is accessible "
                    "and the URL and API Token provided in the configuration "
                    "parameters are correct."
                ),
            )
            raise MCASPluginException(err_msg)

    def get_config_params(self, configuration: Dict) -> tuple:
        """Get configuration parameters.

        Args:
            configuration (Dict): Configuration dictionary.

        Returns:
            tuple: Tuple of configuration parameters.
        """
        return (
            configuration.get("url", "").strip().rstrip("/"),
            configuration.get("token", ""),
            configuration.get("status") or [],
            configuration.get("enable_tagging", "yes"),
            configuration.get("add_wildcard_prefix", "no"),
            configuration.get("wildcard", "*").strip() or "*",
        )
