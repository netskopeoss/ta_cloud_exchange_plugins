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

from .harfanglab_constants import (
    DEFAULT_WAIT_TIME,
    MAX_API_CALLS,
    MODULE_NAME,
    PLATFORM_NAME,
)


class HarfangLabPluginException(Exception):
    """HarfangLabP plugin custom exception class."""

    pass


class HarfangLabPluginHelper(object):
    """HarfangLabPluginHelper class.

    Args:
        object (object): Object class.
    """

    def __init__(
            self,
            logger,
            log_prefix: str,
            plugin_name: str,
            plugin_version: str
    ):
        """HarfangLabPluginHelper initializer.

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
        headers,
        verify,
        payload={},
        params={},
        proxies=None,
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
            if "pushing indicator" not in logger_msg:
                debug_msg = f"API Endpoint for {logger_msg}: {url}"
                self.logger.debug(f"{self.log_prefix}: {debug_msg}")

            headers = self._add_user_agent(headers)
            for retry_counter in range(MAX_API_CALLS):
                response = requests.request(
                    method,
                    url,
                    headers=headers,
                    params=params,
                    data=payload,
                    verify=verify,
                    proxies=proxies,
                )
                debug_msg = (
                    f"API response for {logger_msg} - {response.status_code}."
                )
                self.logger.debug(f"{self.log_prefix}: {debug_msg}")

                if response.status_code >= 500 and response.status_code <= 600:
                    try:
                        resp_json = self.parse_response(response=response)
                        api_err_msg = str(
                            resp_json.get(
                                "detail",
                                str(response.text),
                            )
                        )
                    except HarfangLabPluginException:
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
                        raise HarfangLabPluginException(err_msg)
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
                    break
            return (
                self.handle_error(response, logger_msg)
                if is_handle_error_required
                else response
            )

        except requests.exceptions.ProxyError as error:
            err_msg = (
                f"Proxy error occurred while {logger_msg}. "
                "Verify the provided proxy configuration."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {error}",
                details=str(traceback.format_exc()),
            )
            raise HarfangLabPluginException(err_msg)
        except requests.exceptions.ConnectionError as error:
            err_msg = (
                f"Unable to establish connection with {PLATFORM_NAME} "
                f"platform while {logger_msg}. "
                f"Proxy server or {PLATFORM_NAME} "
                "server is not reachable."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {error}",
                details=str(traceback.format_exc()),
            )
            raise HarfangLabPluginException(err_msg)
        except requests.exceptions.InvalidHeader as err:
            err_msg = f"Error occurred while {logger_msg}."
            authorization = headers.get(
                "Authorization", "No value in Authorization"
            )
            redacted_msg = str(err).replace(authorization, "<API Token>")
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {redacted_msg}",
                details=str(traceback.format_exc()).replace(
                    authorization, "<API Token>"
                ),
            )
            raise HarfangLabPluginException(redacted_msg)
        except requests.HTTPError as err:
            err_msg = f"HTTP Error occurred while {logger_msg}."
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {err}",
                details=str(traceback.format_exc()),
            )
            raise HarfangLabPluginException(err_msg)
        except HarfangLabPluginException as exp:
            raise HarfangLabPluginException(exp)
        except Exception as exp:
            err_msg = f"Unexpected error occurred while {logger_msg}."
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {exp}",
                details=str(traceback.format_exc()),
            )
            raise HarfangLabPluginException(err_msg)

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
                f"Invalid JSON response received from API. "
                f"Error: {str(err)}"
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=f"API response: {response.text}",
            )
            raise HarfangLabPluginException(err_msg)
        except Exception as exp:
            err_msg = (
                "Unexpected error occurred while parsing"
                f" json response. Error: {exp}"
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=f"API Response: {response.text}",
            )
            raise HarfangLabPluginException(err_msg)

    def handle_error(
            self,
            resp: requests.models.Response,
            logger_msg: str
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
            HarfangLabException: When the response code is
            not in 200 range.
        """
        if resp.status_code in [200, 201]:
            return self.parse_response(response=resp)
        elif resp.status_code == 204:
            return {}
        elif resp.status_code == 401:
            err_msg = (
                f"Received exit code {resp.status_code}, "
                f"Unauthorized while {logger_msg}. "
                "Check the API Token provided."
            )
            resp_json = self.parse_response(response=resp)
            api_error_msg = resp_json.get("detail", str(resp.text))
            self.logger.error(
                f"{self.log_prefix}: {err_msg} "
                f"Error: {api_error_msg}"
            )
            raise HarfangLabPluginException(err_msg)
        elif resp.status_code == 403:
            err_msg = (
                f"Received exit code {resp.status_code}, "
                f"Forbidden while {logger_msg}. "
                "Verify that the API Token used has the required "
                "permissions attached."
            )
            resp_json = self.parse_response(response=resp)
            api_error_msg = resp_json.get("detail", str(resp.text))
            self.logger.error(
                f"{self.log_prefix}: {err_msg} "
                f"Error: {api_error_msg}"
            )
            raise HarfangLabPluginException(err_msg)
        elif resp.status_code == 404:
            err_msg = (
                f"Received exit code {resp.status_code}, "
                "Resource not found while {}."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=str(resp.text),
            )
            raise HarfangLabPluginException(err_msg)
        elif resp.status_code >= 400 and resp.status_code < 500:
            err_msg = (
                f"Received exit code {resp.status_code}, "
                f"HTTP client error while {logger_msg}."
            )
            resp_json = self.parse_response(response=resp)
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=resp_json.get("detail", str(resp.text)),
            )
            raise HarfangLabPluginException(err_msg)
        elif resp.status_code >= 500 and resp.status_code < 600:
            err_msg = (
                f"Received exit code {resp.status_code}. "
                f"HTTP Server Error while {logger_msg}."
            )
            resp_json = self.parse_response(response=resp)
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=resp_json.get("detail", str(resp.text)),
            )
            raise HarfangLabPluginException(err_msg)
        else:
            err_msg = "Received exit code {}. HTTP Error while {}.".format(
                resp.status_code, logger_msg
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=resp.get("detail", str(resp.text)),
            )
            raise HarfangLabPluginException(err_msg)
