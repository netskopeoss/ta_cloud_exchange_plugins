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

CTE Abnormal Security Plugin helper module.
"""

import json
import time
import traceback
from typing import Dict, List, Tuple, Union

import requests
from netskope.common.utils import add_user_agent

from .constants import (
    DEFAULT_SLEEP_TIME,
    MAX_API_CALLS,
    MODULE_NAME,
    PLATFORM_NAME,
    RETRACTION,
)


class AbnormalSecurityPluginException(Exception):
    """Abnormal Security plugin custom exception class."""

    pass


class AbnormalSecurityPluginHelper(object):
    """Abnormal Security Plugin Helper class.

    Args:
        object (object): Object class.
    """

    def __init__(
        self, logger, log_prefix: str, plugin_name: str, plugin_version: str
    ):
        """Abnormal Security Plugin Helper initializer.

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
        is_validation=False,
        verify: bool = True,
        proxies: Dict = {},
        is_retraction: bool = False,
    ) -> Dict:
        """API Helper perform API request to ThirdParty platform
        and captures all the possible errors for requests.

        Args:
            logger_msg (str): Logger message.
            url (str): API Endpoint.
            method (str): Method for the endpoint.
            params (Dict, optional): Request parameters dictionary.
            Defaults to None.
            data (Any,optional): Data to be sent to API. Defaults to None.
            files(Any): Files to send, Defaults to None.
            headers (Dict, optional): Headers for the request. Defaults to {}.
            json (optional): Json payload for request. Defaults to None.
            should handle the status codes. Defaults to True.
            is_validation (bool, optional): Does this request coming from
            validate method?. Defaults to False.
            verify (bool): Perform SSL verification or not?
            proxies (Dict): Provide proxy dictionary to use.

        Returns:
            Response JSON: Returns response json.
        """
        try:
            if is_retraction and RETRACTION not in self.log_prefix:
                self.log_prefix = self.log_prefix + f" [{RETRACTION}]"
            headers = self._add_user_agent(headers)

            debug_log_msg = (
                f"{self.log_prefix} : API Request for {logger_msg}."
                f" Endpoint: {method} {url}"
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
                    files=files,
                )
                status_code = response.status_code
                self.logger.debug(
                    f"{self.log_prefix}: Received API Response for "
                    f"{logger_msg}. Status Code={status_code}."
                )

                if (
                    not is_validation and (
                        status_code == 429
                        or status_code in range(500, 601)
                    )
                ):
                    if retry_counter == MAX_API_CALLS - 1:
                        error_msg = (
                            f"Received exit code {status_code}, While"
                            f" {logger_msg}. Max retries limit "
                            "exceeded hence returning status"
                            f" code {status_code}."
                        )
                        self.logger.error(
                            message=f"{self.log_prefix}: {error_msg}",
                            details=f"API response: {response.text}",
                        )
                        raise AbnormalSecurityPluginException(error_msg)
                    self.logger.error(
                        message=(
                            f"{self.log_prefix}: Received exit code"
                            f" {status_code}, "
                            f"While {logger_msg}. Retrying after "
                            f"{DEFAULT_SLEEP_TIME} seconds. "
                            f"{MAX_API_CALLS - 1 - retry_counter} "
                            "retries left."
                        ),
                        details=f"API response: {response.text}",
                    )
                    time.sleep(DEFAULT_SLEEP_TIME)
                else:
                    return self._handle_error(
                        response=response,
                        logger_msg=logger_msg,
                        is_validation=is_validation,
                    )
        except AbnormalSecurityPluginException:
            raise
        except requests.exceptions.ReadTimeout as error:
            err_msg = (
                f"Read Timeout error occurred while {logger_msg} when trying "
                f"to communicate with {PLATFORM_NAME} platform."
                f"Please verify if the platform UI is up and running."
            )
            if is_validation:
                err_msg = (
                    "Read Timeout error occurred when trying "
                    f"to communicate with {PLATFORM_NAME} platform."
                    f"Please verify if the platform UI is up and running."
                )

            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {error}",
                details=traceback.format_exc(),
            )
            raise AbnormalSecurityPluginException(err_msg)
        except requests.exceptions.ProxyError as error:
            err_msg = (
                f"Proxy error occurred while {logger_msg} when trying "
                f"to communicate with {PLATFORM_NAME} platform."
                "Verify the proxy configuration provided."
            )
            if is_validation:
                err_msg = (
                    "Proxy error occurred when trying "
                    f"to communicate with {PLATFORM_NAME} platform."
                    "Verify the proxy configuration provided."
                )

            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {error}",
                details=traceback.format_exc(),
            )
            raise AbnormalSecurityPluginException(err_msg)
        except requests.exceptions.ConnectionError as e:
            err_msg = (
                f"Unable to establish connection with {PLATFORM_NAME} "
                f"platform while {logger_msg}."
                f"{PLATFORM_NAME} server is not reachable."
            )
            if is_validation:
                err_msg = (
                    f"Unable to establish connection with {PLATFORM_NAME} "
                    f"platform.{PLATFORM_NAME}"
                    " server is not reachable."
                )

            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {e}",
                details=traceback.format_exc(),
            )
            raise AbnormalSecurityPluginException(err_msg)
        except requests.HTTPError as e:
            err_msg = f"HTTP error occurred while {logger_msg}."
            if is_validation:
                err_msg = (
                    "HTTP error occurred. Verify configuration "
                    "parameters provided."
                )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {e}",
                details=traceback.format_exc(),
            )
            raise AbnormalSecurityPluginException(err_msg)
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
                raise AbnormalSecurityPluginException(
                    f"{err_msg} Check logs for more details."
                )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {e}",
                details=traceback.format_exc(),
            )
            raise AbnormalSecurityPluginException(err_msg)

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
            when the response code is 200.
        Raises:
            HTTPError: When the response code is not 200.
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
                "Verify the Base URL provided in the configuration"
                " parameters."
            ),
            401: (
                "Verify API Token provided in the configuration parameters."
            ),
            403: (
                "Verify Base URL and API Token provided in the configuration "
                "parameters and make sure your Cloud Exchange's public IP "
                "address is added to the IP Safelist in Abnormal Security's"
                " Rest API Integration."
            ),
            404: (
                "Verify the Base URL provided in the configuration"
                " parameters."
            ),
        }
        if is_validation:
            error_dict = {
                400: (
                    "Received exit code 400 (Bad Request), Verify the"
                    " Abnormal Security Base URL, and API Token provided in "
                    " the configuration parameters."
                ),
                401: (
                    "Received exit code 401 (Unauthorized), Verify "
                    "API Token provided in the configuration parameters."
                ),
                403: (
                    "Received exit code 403 (Forbidden), Verify Base URL and"
                    " API Token provided in the configuration parameters."
                ),
                404: (
                    "Received exit code 404 (Resource not found), Verify "
                    "Abnormal Security Base URL provided in the configuration "
                    "parameters."
                ),
            }
        if status_code in [200, 201, 202]:
            return self._parse_response(response, logger_msg, is_validation)
        if status_code == 204:
            return {}

        if error_msg := error_dict.get(status_code):
            if is_validation:
                log_error_msg = validation_error_msg + error_msg
                self.logger.error(
                    message=f"{self.log_prefix}: {log_error_msg}",
                    details=f"API response: {response.text}",
                    resolution=resolution_dict.get(status_code),
                )
                raise AbnormalSecurityPluginException(log_error_msg)
            else:
                err_msg = error_msg + " while " + logger_msg + "."
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg}",
                    details=f"API response: {response.text}",
                )
                raise AbnormalSecurityPluginException(err_msg)
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
            raise AbnormalSecurityPluginException(err_msg)

    def _parse_response(
        self,
        response: requests.models.Response,
        logger_msg: str,
        is_validation: bool = False,
    ) -> Dict:
        """Parse Response will return JSON from response object.

        Args:
            response (response): Response object.

        Returns:
            Any: Response Json.
        """
        try:
            return response.json()
        except json.JSONDecodeError as err:
            err_msg = (
                f"Invalid JSON response received from API while {logger_msg}. "
                f"Error: {str(err)}"
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=f"API response: {response.text}",
            )
            if is_validation:
                err_msg = (
                    "Verify Abnormal Security Base URL provided in the "
                    "configuration parameters. Check logs for more details."
                )
            raise AbnormalSecurityPluginException(err_msg)
        except Exception as exp:
            err_msg = (
                "Unexpected error occurred while parsing"
                f" json response while {logger_msg}. Error: {exp}"
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=f"API response: {response.text}",
            )
            if is_validation:
                err_msg = (
                    "Unexpected validation error occurred, "
                    "Verify Abnormal Security Base URL provided in the "
                    "configuration parameters. Check logs for more details."
                )
            raise AbnormalSecurityPluginException(err_msg)

    def get_configuration_data(
        self, configuration: Dict
    ) -> Tuple[str, str, List[str], str, int, int]:
        """Get Abnormal Security API Base URL, API Key, IoC Types,
        Enable Tagging, Retraction Interval, Initial Pull Range from the
        configuration.

        Args:
            configuration (Dict): Configuration dictionary.

        Returns:
            Tuple[str, str, List[str], str, int, int]: Tuple of Base URL,
                API Key, IoC Types, Enable Tagging, Retraction Interval,
                Initial Pull Range.
        """

        return (
            configuration.get("base_url", "").strip().strip("/"),
            configuration.get("api_key", ""),
            configuration.get("type", ""),
            configuration.get("enable_tagging", ""),
            configuration.get("retraction_interval", ""),
            configuration.get("initial_pull_range", ""),
        )

    def get_auth_headers(self, api_key: str) -> Dict:
        return {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}",
        }
