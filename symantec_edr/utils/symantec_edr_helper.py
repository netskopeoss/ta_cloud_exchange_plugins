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

CTE Symantec EDR plugin helper module.
"""

import json
import traceback
import time
import requests
from typing import Dict, Union

from netskope.common.utils import add_user_agent

from .symantec_edr_constants import (
    DEFAULT_WAIT_TIME,
    MAX_API_CALLS,
    MODULE_NAME,
    VALIDATION_MSG
)


class SymantecEDRPluginException(Exception):
    """SymantecEDR plugin custom exception class."""

    pass


class SymantecEDRPluginHelper(object):
    """SymantecEDR PluginHelper class.

    Args:
        object (object): Object class.
    """

    def __init__(
        self,
        logger,
        log_prefix: str,
        plugin_name: str,
        plugin_version: str,
        ssl_validation,
        proxy,
    ):
        """SymantecEDR PluginHelper initializer.

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
        self.ssl_validation = ssl_validation
        self.proxy = proxy

    def _add_user_agent(self, headers: Union[Dict, None] = None) -> Dict:
        """Add User-Agent in the headers for third-party requests.

        Args:
            headers (Dict): Dictionary containing headers for any request.
        Returns:
            Dict: Dictionary after adding User-Agent.
        """
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

    def parse_response(self, response: requests.models.Response, is_validation: bool):
        """Parse Response will return JSON from response object.

        Args:
            response (response): Response object.
            is_validation (bool): Validation flag.

        Returns:
            Any: Response Json.
        """
        try:
            return response.json()
        except json.JSONDecodeError as err:
            err_msg = f"Invalid JSON response received from API. Error: {str(err)}"
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=f"API response: {response.text}",
            )
            if is_validation:
                err_msg = VALIDATION_MSG
            raise SymantecEDRPluginException(err_msg)
        except Exception as exp:
            err_msg = (
                "Unexpected error occurred while parsing"
                f" json response. Error: {exp}"
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=f"API Response: {response.text}",
            )
            if is_validation:
                err_msg = VALIDATION_MSG
            raise SymantecEDRPluginException(err_msg)

    def handle_error(self, resp: requests.models.Response, logger_msg, is_validation):
        """Handle the different HTTP response code.

        Args:
            resp (requests.models.Response): Response object
            returned from API call.
            logger_msg: logger message.
            is_validation : API call from validation method or not
        Returns:
            dict: Returns the dictionary of response JSON
            when the response code is 200.
        Raises:
            HTTPError: When the response code is not 200.
        """
        status_code = resp.status_code

        error_dict = {
            400: "400 Bad Request - Incorrect or invalid parameters",
            401: "401 Authentication error - Incorrect or invalid Client ID or Client Secret",
            403: "403 Forbidden - please provide valid Client ID and Client Secret",
            404: "404 Resource not found - invalid endpoint was called",
            408: "408 Timeout - Check Server URL/Port",
            410: "410 Gone - Access to the target resource is no longer available at the origin server",
            500: "500 Internal Server Error - please try again after some time",
            502: "502 Bad Gateway - Could not connect to the origin server",
            503: "503 Service Unavailable",
        }
        if status_code == 200:
            return self.parse_response(response=resp, is_validation=is_validation)
        elif status_code in error_dict:
            err_msg = error_dict[status_code]
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Received exit code {status_code}, "
                    f"{err_msg} while {logger_msg}."
                ),
                details=str(resp.text),
            )
            if is_validation:
                err_msg += ". " + VALIDATION_MSG
            raise SymantecEDRPluginException(err_msg)
        else:
            err_msg = (
                "HTTP Server Error."
                if (status_code >= 500 and status_code <= 600)
                else "HTTP Client Error"
            )
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Received exit code {status_code}, "
                    f"{err_msg} while {logger_msg}."
                ),
                details=str(resp.text),
            )
            if is_validation:
                err_msg = err_msg + ". " + VALIDATION_MSG
            raise SymantecEDRPluginException(err_msg)

    def api_helper(
        self,
        logger_msg: str,
        url,
        method,
        params=None,
        data=None,
        headers=None,
        is_validation=False,
    ):
        """API Helper perform API request to ThirdParty platform
        and captures all the possible errors for requests.

        Args:
            request (request): Requests object.
            code is required?. Defaults to True.
            is_validation : API call from validation method or not

        Returns:
            dict: Response dictionary.
        """
        try:

            debuglog_msg = (
                f"{self.log_prefix} : API Request for {logger_msg}. URL={url}"
            )
            if data:
                display_data = data
                if isinstance(data, dict):
                    display_data = {
                        k: v
                        for k, v in display_data.items()
                        if k not in {"client_secret"}
                    }

                debuglog_msg += f" Data={display_data}."

            self.logger.debug(debuglog_msg)
            for retry_counter in range(MAX_API_CALLS):
                response = requests.request(
                    url=url,
                    method=method,
                    params=params,
                    data=data,
                    headers=headers,
                    verify=self.ssl_validation,
                    proxies=self.proxy,
                )
                self.logger.debug(
                    f"{self.log_prefix} : Received API Response while "
                    f"{logger_msg}. Method={method}, "
                    f"Status Code={response.status_code}."
                )
                if not is_validation and (
                    response.status_code == 429
                    or (response.status_code >= 500 and response.status_code <= 600)
                ):
                    if retry_counter == MAX_API_CALLS - 1:
                        err_msg = (
                            "Received exit code {}, while"
                            " {}. Max retries for rate limit "
                            "handler exceeded hence returning status"
                            " code {}.".format(
                                response.status_code,
                                logger_msg,
                                response.status_code,
                            )
                        )
                        self.logger.error(
                            message=f"{self.log_prefix}: {err_msg}",
                            details=str(response.text),
                        )
                        raise SymantecEDRPluginException(err_msg)
                    self.logger.error(
                        message=(
                            "{}: Received exit code {}, "
                            "while {}. Retrying after {} "
                            "seconds. {} retries remaining.".format(
                                self.log_prefix,
                                response.status_code,
                                logger_msg,
                                DEFAULT_WAIT_TIME,
                                MAX_API_CALLS - 1 - retry_counter,
                            )
                        ),
                        details=str(response.text),
                    )
                    time.sleep(DEFAULT_WAIT_TIME)
                else:
                    return self.handle_error(response, logger_msg, is_validation)

        except requests.exceptions.ProxyError as error:
            err_msg = f"Proxy error occurred while {logger_msg}. Verify the provided proxy configuration."
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {error}",
                details=str(traceback.format_exc()),
            )
            raise SymantecEDRPluginException(err_msg)
        except requests.exceptions.ConnectionError as error:
            err_msg = (
                f"Unable to establish connection with {self.plugin_name} while {logger_msg}. "
                "Check Server URL provided in configuration parameter."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {error}",
                details=str(traceback.format_exc()),
            )
            raise SymantecEDRPluginException(err_msg)
        except requests.HTTPError as err:
            err_msg = f"HTTP Error occurred while {logger_msg}."
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {err}",
                details=str(traceback.format_exc()),
            )
            raise SymantecEDRPluginException(err_msg)
        except SymantecEDRPluginException:
            raise
        except Exception:
            err_msg = (
                "Unexpected error occurred while requesting "
                f"to {self.plugin_name} while {logger_msg}."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=str(traceback.format_exc()),
            )
            raise SymantecEDRPluginException(err_msg)
