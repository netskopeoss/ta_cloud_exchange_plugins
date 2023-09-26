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

CTE CrowdStrike plugin helper module.
"""

import json
import time
import traceback
from typing import Dict, Union

import requests
from netskope.common.utils import add_user_agent

from .crowdstrike_constants import (
    DEFAULT_WAIT_TIME,
    MAX_API_CALLS,
    MAX_WAIT_TIME,
    MODULE_NAME,
)


class CrowdstrikePluginException(Exception):
    """Crowdstrike plugin custom exception class."""

    pass


class CrowdStrikePluginHelper(object):
    """CrowdStrikePluginHelper class.

    Args:
        object (object): Object class.
    """

    def __init__(
        self, logger, log_prefix: str, plugin_name: str, plugin_version: str
    ):
        """CrowdStrikePluginHelper initializer.

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
        headers = add_user_agent(headers)
        ce_added_agent = headers.get("User-Agent", "netskope-ce")
        user_agent = "{}-{}-{}/{}".format(
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
        verify=True,
        proxies=None,
        json=None,
        is_handle_error_required=True,
    ):
        """API Helper perform API request to ThirdParty platform
        and captures all the possible errors for requests.

        Args:
            request (request): Requests object.
            logger_msg (str): Logger string.
            is_handle_error_required (bool, optional): Is handling status
            code is required?. Defaults to True.

        Returns:
            dict: Response dictionary.
        """
        try:
            for retry_counter in range(MAX_API_CALLS):
                response = requests.request(
                    url=url,
                    method=method,
                    params=params,
                    data=data,
                    headers=self._add_user_agent(headers),
                    verify=verify,
                    proxies=proxies,
                    json=json,
                )
                if response.status_code == 429:
                    resp_json = self.parse_response(response=response)
                    api_err_msg = str(
                        resp_json.get(
                            "errors",
                            str(response.text),
                        )
                    )
                    if retry_counter == MAX_API_CALLS - 1:
                        err_msg = (
                            "Received exit code {}, API rate limit "
                            "exceeded while {}. Max retries for rate limit "
                            "handler exceeded hence returning status"
                            " code {}.".format(
                                response.status_code,
                                logger_msg,
                                response.status_code,
                            )
                        )
                        self.logger.error(
                            message=f"{self.log_prefix}: {err_msg}",
                            details=api_err_msg,
                        )
                        raise CrowdstrikePluginException(err_msg)
                    retry_after = response.headers.get(
                        "X-Ratelimit-Retryafter"
                    )
                    if retry_after is None:
                        self.logger.info(
                            "{}: No X-Ratelimit-Retryafter value received from"
                            "API hence plugin will retry after {} "
                            "seconds.".format(
                                self.log_prefix, DEFAULT_WAIT_TIME
                            )
                        )
                        time.sleep(DEFAULT_WAIT_TIME)
                        continue
                    retry_after = int(retry_after)
                    diff_retry_after = round(abs(retry_after - time.time()), 2)
                    if diff_retry_after > MAX_WAIT_TIME:
                        err_msg = (
                            "'X-Ratelimit-Retryafter' value received from "
                            "response headers while {} is greater than {}  "
                            "seconds hence returning status code {}.".format(
                                logger_msg, MAX_WAIT_TIME, response.status_code
                            )
                        )
                        self.logger.error(
                            message=f"{self.log_prefix}: {err_msg}"
                        )
                        raise CrowdstrikePluginException(err_msg)
                    self.logger.error(
                        message=(
                            "{}: Received exit code {}, API rate limit"
                            " exceeded while {}. Retrying after {} "
                            "seconds. {} retries remaining.".format(
                                self.log_prefix,
                                response.status_code,
                                logger_msg,
                                diff_retry_after,
                                MAX_API_CALLS - 1 - retry_counter,
                            )
                        ),
                        details=api_err_msg,
                    )
                    time.sleep(diff_retry_after)

                elif (
                    response.status_code >= 500 and response.status_code <= 600
                ):
                    try:
                        resp_json = self.parse_response(response=response)
                        api_err_msg = str(
                            resp_json.get(
                                "errors",
                                str(response.text),
                            )
                        )
                    except CrowdstrikePluginException:
                        api_err_msg = str(response.text)

                    if retry_counter == MAX_API_CALLS - 1:
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
                            details=api_err_msg,
                        )
                        raise CrowdstrikePluginException(err_msg)
                    self.logger.error(
                        message=(
                            "{}: Received exit code {}, HTTP Server Error "
                            "while {}. Retrying after {} "
                            "seconds. {} retries remaining.".format(
                                self.log_prefix,
                                response.status_code,
                                logger_msg,
                                DEFAULT_WAIT_TIME,
                                MAX_API_CALLS - 1 - retry_counter,
                            )
                        ),
                        details=api_err_msg,
                    )
                    time.sleep(DEFAULT_WAIT_TIME)
                else:
                    return (
                        self.handle_error(response, logger_msg)
                        if is_handle_error_required
                        else response
                    )
        except requests.exceptions.ProxyError as error:
            err_msg = (
                "Proxy error occurred. Verify the provided "
                "proxy configuration."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {error}",
                details=traceback.format_exc(),
            )
            raise CrowdstrikePluginException(err_msg)
        except requests.exceptions.ConnectionError as error:
            err_msg = (
                "Unable to establish connection with {} "
                "platform. Proxy server or {}"
                " server is not reachable.".format(
                    self.plugin_name, self.plugin_name
                )
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {error}",
                details=traceback.format_exc(),
            )
            raise CrowdstrikePluginException(err_msg)
        except requests.HTTPError as err:
            err_msg = f"HTTP Error occurred while {logger_msg}."
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {err}",
                details=traceback.format_exc(),
            )
            raise CrowdstrikePluginException(err_msg)
        except CrowdstrikePluginException as exp:
            self.logger.error(
                message=f"{self.log_prefix}: {exp}",
                details=traceback.format_exc(),
            )
            raise CrowdstrikePluginException(exp)
        except Exception as exp:
            err_msg = (
                "Unexpected error occurred while requesting "
                f"to {self.plugin_name} server. Error: {exp}"
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=traceback.format_exc(),
            )
            raise CrowdstrikePluginException(err_msg)

    def parse_response(self, response: requests.models.Response):
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
            raise CrowdstrikePluginException(err_msg)
        except Exception as exp:
            err_msg = (
                "Unexpected error occurred while parsing"
                f" json response. Error: {exp}"
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=f"API Response: {response.text}",
            )
            raise CrowdstrikePluginException(err_msg)

    def handle_error(
        self, resp: requests.models.Response, logger_msg: str
    ) -> Dict:
        """Handle the different HTTP response code.

        Args:
            resp (requests.models.Response): Response object returned
                from API call.
            logger_msg: logger message.
        Returns:
            dict: Returns the dictionary of response JSON when the
                response code is 200.
        Raises:
            CrowdstrikeException: When the response code is
            not in 200 range.
        """
        if resp.status_code in [200, 201, 202]:
            return self.parse_response(response=resp)
        elif resp.status_code == 204:
            return {}
        elif resp.status_code == 403:
            err_msg = "Received exit code 403, Forbidden while {}.".format(
                logger_msg
            )
            resp_json = self.parse_response(response=resp)
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=str(resp_json.get("errors", str(resp.text))),
            )
            raise CrowdstrikePluginException(err_msg)
        elif resp.status_code == 404:
            err_msg = (
                "Received exit code 404, Resource not found while {}.".format(
                    logger_msg
                )
            )
            resp_json = self.parse_response(response=resp)
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=str(resp_json.get("errors", str(resp.text))),
            )
            raise CrowdstrikePluginException(err_msg)
        elif resp.status_code >= 400 and resp.status_code < 500:
            err_msg = (
                "Received exit code {}, HTTP client error while {}.".format(
                    resp.status_code, logger_msg
                )
            )
            resp_json = self.parse_response(response=resp)
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=str(resp_json.get("errors", str(resp.text))),
            )
            raise CrowdstrikePluginException(err_msg)
        elif resp.status_code >= 500 and resp.status_code < 600:
            err_msg = (
                "Received exit code {}. HTTP Server Error while {}.".format(
                    resp.status_code, logger_msg
                )
            )
            resp_json = self.parse_response(response=resp)
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=str(resp_json.get("errors", str(resp.text))),
            )
            raise CrowdstrikePluginException(err_msg)
        else:
            err_msg = "Received exit code {}. HTTP Error while {}.".format(
                resp.status_code, logger_msg
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=str(resp_json.get("errors", str(resp.text))),
            )
            raise CrowdstrikePluginException(err_msg)
