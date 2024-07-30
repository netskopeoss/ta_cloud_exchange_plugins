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

CTE ThreatConnect plugin helper module.
"""

import json
import time
import requests
import traceback


from typing import Dict, Union


from netskope.common.utils import add_user_agent


from .constants import (
    DEFAULT_WAIT_TIME,
    MAX_RETRY,
    MODULE_NAME,
    PLUGIN_NAME,
)


class ThreatConnectException(Exception):
    """ThreatConnect plugin custom exception class."""
    pass


class ThreatConnectPluginHelper(object):
    """ThreatConnectPluginHelper Class.

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
        """ThreatConnectPluginHelper initializer.
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
        self.verify = ssl_validation
        self.proxies = proxy

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
        url,
        method,
        params=None,
        data=None,
        headers=None,
        json=None,
        is_handle_error_required=True,
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
            headers = self._add_user_agent(headers)

            log_header = {
                key: value
                for key, value in headers.items()
                if key not in {"Authorization", }
            }
            debug_log_msg = (
                f"{self.log_prefix}: API Request for {logger_msg}."
                f" URL={url}, headers={log_header}"
            )
            if params:
                debug_log_msg += f", params={params}"
            if data:
                debug_log_msg += f", data={data}."

            self.logger.debug(debug_log_msg)
            for retry_counter in range(MAX_RETRY):
                response = requests.request(
                    url=url,
                    method=method,
                    params=params,
                    data=data,
                    headers=headers,
                    verify=self.verify,
                    proxies=self.proxies,
                    json=json,
                )
                self.logger.debug(
                    f"{self.log_prefix}: Received API Response while "
                    f"{logger_msg}. Method={method}, "
                    f"Status Code={response.status_code}."
                )
                if (
                    response.status_code == 429
                    or 500 <= response.status_code <= 600
                ) and not is_validation:
                    if retry_counter == MAX_RETRY - 1:
                        err_msg = (
                            "Received exit code {}, HTTP Server Error while"
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
                        raise ThreatConnectException(err_msg)
                    self.logger.error(
                        message=(
                            "{}: Received exit code {}, HTTP Server Error "
                            "while {}. Retrying after {} "
                            "seconds. {} retries remaining.".format(
                                self.log_prefix,
                                response.status_code,
                                logger_msg,
                                DEFAULT_WAIT_TIME,
                                MAX_RETRY - 1 - retry_counter,
                            )
                        ),
                        details=str(response.text),
                    )
                    time.sleep(DEFAULT_WAIT_TIME)
                else:
                    return (
                        self.handle_error(
                            response, logger_msg, is_handle_error_required
                        )
                        if is_handle_error_required
                        else response
                    )

        except requests.exceptions.ProxyError as error:
            err_msg = (
                f"Proxy error occurred while {logger_msg}. Verify the "
                "provided proxy configuration."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {error}",
                details=str(traceback.format_exc()),
            )
            raise ThreatConnectException(err_msg)
        except requests.exceptions.ConnectionError as error:
            err_msg = (
                f"Unable to establish connection with {self.plugin_name} "
                f"while {logger_msg}."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {error}",
                details=str(traceback.format_exc()),
            )
            raise ThreatConnectException(err_msg)
        except requests.HTTPError as err:
            err_msg = f"HTTP Error occurred while {logger_msg}."
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {err}",
                details=str(traceback.format_exc()),
            )
            raise ThreatConnectException(err_msg)
        except ThreatConnectException:
            raise
        except Exception as exp:
            err_msg = (
                f"Unexpected error occurred while {logger_msg}."
                f" Error: {str(exp)}"
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=str(traceback.format_exc()),
            )
            raise ThreatConnectException(err_msg)

    def parse_response(
        self, response: requests.models.Response, is_validation: bool = False
    ):
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
                f"Invalid JSON response received from API. Error: {str(err)}"
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=f"API response: {response.text}",
            )
            if is_validation:
                err_msg = (
                    "Verify Base URL, Access ID or Secret Key provided "
                    f"in the {PLUGIN_NAME} configuration parameters."
                )
            raise ThreatConnectException(err_msg)
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
                err_msg = (
                    "Unexpected validation error occurred, Verify Base URL, "
                    f"Access ID, Secret Key provided in the {PLUGIN_NAME}"
                    " configuration parameters."
                )
            raise ThreatConnectException(err_msg)

    def handle_error(
        self,
        resp: requests.models.Response,
        logger_msg: str,
        is_validation: bool = False,
    ):
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
        validation_msg = (
            "Verify the Base URL, Access ID, Secret Key "
            " provided in configuration parameters."
        )
        error_dict = {
            400: "Bad Request",
            403: "Forbidden",
            401: "Unauthorized",
            409: "Concurrency found",
        }
        if status_code in [200, 201]:
            return self.parse_response(
                response=resp, is_validation=is_validation
            )
        elif status_code == 204:
            return {}
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
                err_msg = err_msg + "." + validation_msg
            raise ThreatConnectException(err_msg)
        else:
            err_msg = (
                "HTTP Server Error"
                if (status_code >= 500 and status_code <= 600)
                else "HTTP Error"
            )
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Received exit code {status_code}, "
                    f"{err_msg} while {logger_msg}."
                ),
                details=str(resp.text),
            )
            if is_validation:
                err_msg = err_msg + "." + validation_msg
            raise ThreatConnectException(err_msg)
