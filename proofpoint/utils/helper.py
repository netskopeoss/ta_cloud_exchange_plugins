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

CTE Proofpoint plugin helper module.
"""

import json
import re
import time
import traceback
import requests
from datetime import datetime
from typing import Dict, Union

from netskope.common.utils import add_user_agent
from netskope.integrations.cte.models import IndicatorType

from .constants import (
    DEFAULT_WAIT_TIME,
    MAX_API_CALLS,
    PLUGIN_NAME,
    MODULE_NAME,
    RETRACTION,
    DOMAIN_REGEX,
    DOMAIN_REGEX_2,
    FQDN_REGEX,
)


class ProofpointPluginException(Exception):
    """Proofpoint plugin custom exception class."""

    pass


class ProofpointPluginHelper(object):
    """ProofpointPluginHelper class.

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
        """Proofpoint Plugin Helper initializer.

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

    def get_config_params(self, configuration: dict) -> dict:
        """Fetch and return configuration parameters.

        Args:
            configuration (dict): Configuration dictionary.

        Returns:
            dict: Dictionary containing configuration parameters.
        """
        return {
            "base_url": configuration.get("base_url", ""),
            "username": configuration.get("username", ""),
            "password": configuration.get("password", ""),
            "hours": configuration.get("hours", ""),
            "event_types": configuration.get("event_types", []),
            "enable_tagging": configuration.get("enable_tagging", ""),
            "retraction_interval": configuration.get("retraction_interval"),
        }

    def get_interval_query(
        self, start_time: datetime, end_time: datetime
    ) -> str:
        """Generate interval query string from given start and end time.

        Args:
            start_time (datetime): Start of the query interval.
            end_time (datetime): End of the query interval.

        Returns:
            str: Interval query string in ISO 8601 format.
        """
        return (
            f"{start_time.replace(microsecond=0).isoformat()}Z/"
            f"{end_time.replace(microsecond=0).isoformat()}Z"
        )

    def determine_indicator_type(self, value: str) -> IndicatorType:
        """Determine indicator type using regex patterns.

        Args:
            value (str): Value to check.

        Returns:
            IndicatorType: Determined indicator type.
        """
        if re.match(FQDN_REGEX, value):
            return getattr(IndicatorType, "FQDN", IndicatorType.URL)
        elif re.match(DOMAIN_REGEX, value) or re.match(DOMAIN_REGEX_2, value):
            return getattr(IndicatorType, "DOMAIN", IndicatorType.URL)
        else:
            return IndicatorType.URL

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
        verify=True,
        proxies=None,
        is_handle_error_required=True,
        is_validation=False,
        auth=None,
        is_retraction=False,
    ):
        """API Helper to perform API requests to Proofpoint platform \
        and capture all possible errors for requests.

        Args:
            logger_msg (str): Logger message.
            url (str): API Endpoint.
            method (str): Method for the endpoint.
            params (Dict, optional): Request parameters dictionary.
                Defaults to {}.
            data (Any, optional): Data to be sent to API. Defaults to None.
            headers (Dict, optional): Headers for the request. Defaults to {}.
            json (optional): Json payload for request. Defaults to None.
            verify (bool, optional): Verify SSL. Defaults to True.
            proxies (Dict, optional): Proxies. Defaults to None.
            is_handle_error_required (bool, optional): Whether the API helper
                should handle the status codes. Defaults to True.
            is_validation (bool, optional): Whether this request is coming
                from the validate method. Defaults to False.
            auth (tuple, optional): Auth tuple for basic auth.
                Defaults to None.
            is_retraction (bool, optional): Whether this is a retraction call.
                Defaults to False.

        Returns:
            dict: Response dictionary.
        """
        if is_retraction and RETRACTION not in self.log_prefix:
            self.log_prefix = self.log_prefix + f" [{RETRACTION}]"
        try:
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
                    auth=auth,
                )
                status_code = response.status_code
                self.logger.debug(
                    f"{self.log_prefix}: Received API Response for "
                    f"{logger_msg}. Status Code={status_code}."
                )

                if (
                    status_code == 429
                    or 500 <= status_code <= 600
                ) and not is_validation:
                    api_err_msg = str(response.text)
                    if retry_counter == MAX_API_CALLS - 1:
                        err_msg = (
                            f"Received exit code {status_code}, "
                            f"API rate limit exceeded while {logger_msg}. "
                            "Max retries for rate limit handler exceeded "
                            f"hence returning status code {status_code}."
                        )
                        self.logger.error(
                            message=f"{self.log_prefix}: {err_msg}",
                            details=api_err_msg,
                        )
                        raise ProofpointPluginException(err_msg)
                    retry_after = DEFAULT_WAIT_TIME
                    if status_code == 429:
                        log_err_msg = "API rate limit exceeded"
                    else:
                        log_err_msg = "HTTP server error occurred"
                    self.logger.error(
                        message=(
                            f"{self.log_prefix}: Received exit code "
                            f"{status_code}, "
                            f"{log_err_msg} while {logger_msg}. "
                            f"Retrying after {retry_after} seconds. "
                            f"{MAX_API_CALLS - 1 - retry_counter} "
                            "retries remaining."
                        ),
                        details=api_err_msg,
                    )
                    time.sleep(retry_after)
                else:
                    return (
                        self.handle_error(response, logger_msg, is_validation)
                        if is_handle_error_required
                        else response
                    )
        except requests.exceptions.ReadTimeout as error:
            err_msg = (
                f"Read Timeout error occurred while {logger_msg}."
            )
            if is_validation:
                err_msg = (
                    "Read Timeout error occurred. "
                    "Verify the provided "
                    "configuration parameters."
                )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {error}",
                details=str(traceback.format_exc()),
                resolution=(
                    "Ensure that your Proofpoint platform server"
                    " is reachable and the network connection is stable."
                ),
            )
            raise ProofpointPluginException(err_msg)
        except requests.exceptions.ProxyError as error:
            err_msg = (
                f"Proxy error occurred while {logger_msg}. "
                "Verify the provided proxy configuration."
            )
            if is_validation:
                err_msg = (
                    "Proxy error occurred. Verify "
                    "the proxy configuration provided."
                )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {error}",
                details=str(traceback.format_exc()),
                resolution=(
                    "Ensure that the proxy configuration provided is"
                    " correct and the proxy server is reachable."
                ),
            )
            raise ProofpointPluginException(err_msg)
        except requests.exceptions.ConnectionError as error:
            err_msg = (
                f"Unable to establish connection with {PLUGIN_NAME} "
                f"platform while {logger_msg}. "
                f"Proxy server or {PLUGIN_NAME} "
                "server is not reachable."
            )
            if is_validation:
                err_msg = (
                    f"Unable to establish connection with {PLUGIN_NAME} "
                    f"platform. Proxy server or {PLUGIN_NAME} "
                    "server is not reachable."
                )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {error}",
                details=str(traceback.format_exc()),
                resolution=(
                    "Ensure that your Proofpoint platform server is reachable"
                    " and the proxy server configuration is correct."
                ),
            )
            raise ProofpointPluginException(err_msg)
        except requests.HTTPError as err:
            err_msg = f"HTTP Error occurred while {logger_msg}."
            if is_validation:
                err_msg = (
                    "HTTP error occurred. Verify "
                    "configuration parameters provided."
                )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {err}",
                details=str(traceback.format_exc()),
                resolution=(
                    "Ensure that the configuration parameters provided are"
                    " correct and the API endpoint is valid."
                ),
            )
            raise ProofpointPluginException(err_msg)
        except ProofpointPluginException as exp:
            raise ProofpointPluginException(exp)
        except Exception as exp:
            err_msg = f"Unexpected error occurred while {logger_msg}."
            if is_validation:
                err_msg = (
                    "Unexpected error while performing "
                    f"API call to {PLUGIN_NAME}."
                )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {exp}",
                details=str(traceback.format_exc()),
                resolution=(
                    "Ensure that the configuration parameters provided are"
                    " correct and check logs for more details."
                ),
            )
            raise ProofpointPluginException(err_msg)

    def parse_response(
        self,
        response: requests.models.Response,
        logger_msg,
        is_validation: bool = False,
    ):
        """Parse Response will return JSON from response object.

        Args:
            response (response): Response object.
            logger_msg (str): Logger message.
            is_validation (bool): Check for validation.

        Returns:
            Any: Response Json.
        """
        try:
            return response.json()
        except json.JSONDecodeError as err:
            response_text = response.text.strip()
            err_msg = (
                "Invalid JSON response received "
                f"from API while {logger_msg}."
            )
            resolution = (
                "Verify that the requested time range stays within the last "
                "7 days and try again."
            )

            if is_validation:
                err_msg = (
                    "Verify the credentials provided in the "
                    "configuration parameters. Check logs for more details."
                )
                resolution = (
                    "Ensure that the Base URL, Username, and Password "
                    "are correct and the account has API access permissions."
                )
            elif response_text:
                lower_text = response_text.lower()
                if "requested start time is too far" in lower_text:
                    err_msg = (
                        "Proofpoint API rejected the requested start time. "
                        "Requests for information up to 7 days are accepted."
                    )
                    resolution = (
                        "Reduce the Initial Range (in hours) or wait until "
                        "the checkpoint falls within the last 7 days before "
                        "running the pull again."
                    )

            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {err}",
                details=(
                    "API response: {} | JSON decode error: {}".format(
                        response_text or response.text, err
                    )
                ),
                resolution=resolution,
            )
            raise ProofpointPluginException(err_msg)
        except Exception as exp:
            err_msg = (
                "Unexpected error occurred while parsing "
                f"json response while {logger_msg}. Error: {exp}"
            )
            if is_validation:
                err_msg = (
                    "Unexpected validation error occurred, "
                    "Verify the credentials provided in the "
                    "configuration parameters. Check logs for more details."
                )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=f"API response: {response.text}",
            )
            raise ProofpointPluginException(err_msg)

    def handle_error(
        self,
        resp: requests.models.Response,
        logger_msg: str,
        is_validation: bool = False,
    ) -> Dict:
        """Handle the different HTTP response code.

        Args:
            resp (requests.models.Response): Response object
                returned from API call.
            logger_msg: logger message.
            is_validation: API call from validation method or not.
        Returns:
            dict: Returns the dictionary of response JSON
                when the response code is 200.
        Raises:
            ProofpointPluginException: When the response code is
                not 200.
        """
        status_code = resp.status_code
        validation_msg = "Validation error occurred, "
        if status_code in [200, 201, 202, 204]:
            return self.parse_response(resp, logger_msg, is_validation)

        error_dict = {
            400: "Received exit code 400, HTTP client error",
            403: "Received exit code 403, Forbidden",
            401: "Received exit code 401, Unauthorized access",
            404: "Received exit code 404, Resource not found",
        }
        if is_validation:
            error_dict = {
                400: (
                    "Received exit code 400, Bad Request, Verify the "
                    "Username and Password provided in the "
                    "configuration parameters."
                ),
                401: (
                    "Received exit code 401, Unauthorized, Verify "
                    "Username and Password provided in the "
                    "configuration parameters."
                ),
                403: (
                    "Received exit code 403, Forbidden, Verify permissions "
                    "provided to the Username and Password."
                ),
                404: (
                    "Received exit code 404, Resource not found, Verify "
                    "Base URL provided in the configuration parameters."
                ),
            }

        resolution_dict = {
            400: (
                "Ensure that the Base URL, Username, and Password"
                " provided in the configuration parameters are correct."
            ),
            401: (
                "Ensure that the Username and Password provided in the"
                " configuration parameters are valid."
            ),
            403: (
                "Ensure that the Username and Password provided in the"
                " configuration parameters have the required permissions."
            ),
            404: (
                "Ensure that the Base URL provided in the configuration"
                " parameters is correct and the resource is accessible."
            ),
        }
        if status_code in error_dict:
            err_msg = error_dict.get(status_code, "")
            resolution_msg = resolution_dict.get(status_code)
            if is_validation:
                log_err_msg = validation_msg + err_msg
                self.logger.error(
                    message=f"{self.log_prefix}: {log_err_msg}",
                    details=f"API response: {resp.text}",
                    resolution=resolution_msg
                )
                raise ProofpointPluginException(err_msg)
            else:
                err_msg = err_msg + " while " + logger_msg + "."
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg}",
                    details=f"API response: {resp.text}",
                    resolution=resolution_msg
                )
                raise ProofpointPluginException(err_msg)
        else:
            err = (
                "HTTP Server Error"
                if (status_code >= 500 and status_code <= 600)
                else "HTTP Error"
            )
            err_msg = (
                f"Received status code {status_code}, "
                f"{err} while {logger_msg}."
            )
            resolution = (
                "Verify that the Proofpoint Base URL, Username, and "
                "Password in the configuration are correct and that "
                "the account has API access permissions."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=f"API response: {resp.text}",
                resolution=resolution,
            )
            raise ProofpointPluginException(err_msg)
