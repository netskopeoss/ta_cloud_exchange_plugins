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

Trend Vision One Plugin to push and pull the data from Trend Vision One Platform.
"""

import json
import traceback
import time

import requests
from netskope.common.utils import add_user_agent

from .trend_micro_constant import (
    MODULE_NAME,
    DEFAULT_WAIT_TIME,
    MAX_RETRIES,
)


class TrendMicroPluginException(Exception):
    """TrendMicro plugin custom exception class."""

    pass


class MaximumLimitExceededException(Exception):
    """TrendMicro plugin custom exception class for maximum limit exceeded."""

    pass


class TrendMicroPluginHelper(object):
    """TrendMicroPluginHelper class.

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
        """TrendMicroPluginHelper initializer.

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

    def _add_user_agent(self, headers) -> str:
        """Add User-Agent in the headers of any request.

        Returns:
            str: String containing the User-Agent.
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

    def parse_response(
        self, response: requests.models.Response, is_validation: bool
    ):
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
            err_msg = (
                f"Invalid JSON response received from API. Error: {str(err)}"
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=f"API response: {response.text}",
            )
            if is_validation:
                err_msg = "Verify Data Region and API Token provided in the configuration parameters."
            raise TrendMicroPluginException(err_msg)
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
                err_msg = "Verify Data Region and API Token provided in the configuration parameters."
            raise TrendMicroPluginException(err_msg)

    def handle_error(
        self, resp: requests.models.Response, logger_msg, is_validation
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
        validation_msg = "Verify Data Region and API Token provided in the configuration parameters."

        error_dict = {
            400: "Bad Request",
            403: "Forbidden",
            401: "Unauthorized",
            404: "Not Found",
            429: "Too Many Requests",
        }
        if status_code in [200, 201]:
            return self.parse_response(
                response=resp, is_validation=is_validation
            )
        elif status_code == 202:
            return {}
        elif status_code == 204:
            return {}
        elif status_code in error_dict:
            if (
                status_code == 400
                and "The number of objects exceeds the maximum limit"
                in str(resp.text)
            ):
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: Received exit code {status_code}, "
                        f"while {logger_msg}."
                    ),
                    details=str(resp.text),
                )
                raise MaximumLimitExceededException
            err_msg = error_dict[status_code]
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Received exit code {status_code}, "
                    f"{err_msg} while {logger_msg}."
                ),
                details=str(resp.text),
            )
            if is_validation:
                err_msg = err_msg + ". " + validation_msg
            raise TrendMicroPluginException(err_msg)
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
                err_msg = err_msg + "."
            raise TrendMicroPluginException(err_msg)

    def api_helper(
        self,
        logger_msg: str,
        url,
        method,
        params=None,
        data=None,
        headers=None,
        json=None,
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
            if params:
                debuglog_msg += f", params={params}"

            self.logger.debug(debuglog_msg)

            for retry_counter in range(MAX_RETRIES):
                response = requests.request(
                    method=method,
                    url=url,
                    params=params,
                    json=json,
                    headers=headers,
                    verify=self.ssl_validation,
                    proxies=self.proxy,
                )
                self.logger.debug(
                    f"{self.log_prefix} : Received API Response while "
                    f"{logger_msg}. Method={method}, "
                    f"Status Code={response.status_code}."
                )

                if not is_validation and response.status_code == 429:

                    if "Retry-After" in response.headers:
                        retry_after = response.headers.get("Retry-After", 60)
                        self.logger.info(
                            f"{self.log_prefix}: Recieved exit code for Trend Vision One, 429 Client Error - "
                            "Too Many Requests, Retrying after "
                            f"{retry_after} seconds"
                        )
                        time.sleep(int(retry_after))

                    if retry_counter == MAX_RETRIES - 1:
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
                        raise TrendMicroPluginException(err_msg)
                    self.logger.error(
                        message=(
                            "{}: Received exit code {}, while {}. "
                            "Retrying after {} seconds. {} "
                            "retries remaining.".format(
                                self.log_prefix,
                                response.status_code,
                                logger_msg,
                                DEFAULT_WAIT_TIME,
                                MAX_RETRIES - 1 - retry_counter,
                            )
                        ),
                        details=str(response.text),
                    )
                    time.sleep(DEFAULT_WAIT_TIME)
                elif not is_validation and (
                    response.status_code >= 500 and response.status_code <= 600
                ):
                    if retry_counter == MAX_RETRIES - 1:
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
                        raise TrendMicroPluginException(err_msg)
                    self.logger.error(
                        message=(
                            "{}: Received exit code {}, while {}. "
                            "Retrying after {} seconds. {} "
                            "retries remaining.".format(
                                self.log_prefix,
                                response.status_code,
                                logger_msg,
                                DEFAULT_WAIT_TIME,
                                MAX_RETRIES - 1 - retry_counter,
                            )
                        ),
                        details=str(response.text),
                    )
                    time.sleep(DEFAULT_WAIT_TIME)
                elif response.status_code != 207:
                    return self.handle_error(
                        response, logger_msg, is_validation
                    )
                else:
                    response_code = [
                        status["status"] for status in response.json()
                    ]
                    for status in response_code:
                        if status in [201, 202]:
                            return self.parse_response(
                                response=response, is_validation=is_validation
                            )
                        else:
                            return self.handle_error(
                                response, logger_msg, is_validation
                            )

        except requests.exceptions.ProxyError as error:
            err_msg = f"Proxy error occurred while {logger_msg}. Verify the provided proxy configuration."
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {error}.",
                details=str(traceback.format_exc()),
            )
            raise TrendMicroPluginException(err_msg)
        except requests.exceptions.ConnectionError as error:
            err_msg = (
                f"Unable to establish connection with {self.plugin_name} while "
                f"{logger_msg}. Check Data Region provided in configuration parameter."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {error}.",
                details=str(traceback.format_exc()),
            )
            raise TrendMicroPluginException(err_msg)
        except requests.HTTPError as err:
            err_msg = f"HTTP Error occurred while {logger_msg}."
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {err}.",
                details=str(traceback.format_exc()),
            )
            raise TrendMicroPluginException(err_msg)
        except TrendMicroPluginException:
            raise
        except MaximumLimitExceededException:
            raise
        except Exception as exp:
            err_msg = (
                "Unexpected error occurred while requesting "
                f"to {self.plugin_name} while {logger_msg}."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {str(exp)}",
                details=str(traceback.format_exc()),
            )
            raise TrendMicroPluginException(err_msg)
