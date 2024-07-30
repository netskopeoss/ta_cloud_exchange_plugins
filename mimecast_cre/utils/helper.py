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

URE Mimecast plugin helper module.
"""

import json
import time
import traceback
from typing import Dict, Union

import requests

from netskope.common.utils import add_user_agent

from .constants import MAX_API_CALLS, MODULE_NAME


class MimecastUREException(Exception):
    """Microsoft Azure AD exception class."""

    pass


class MimecastUREPluginHelper(object):
    """MimecastUREPluginHelper class.

    Args:
        object (object): Object class.
    """

    def __init__(self, logger, log_prefix: str, plugin_name: str, plugin_version: str):
        """MimecastUREPluginHelper initializer.

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
        """Add User-Agent in the headers of any request.

        Args:
            header: Headers needed to pass to the Third Party Platform.

        Returns:
            Dict: Dictionary containing the User-Agent.
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
        url,
        method,
        params=None,
        data=None,
        headers=None,
        verify=True,
        proxies=None,
        json=None,
        is_handle_error_required=True,
        is_validation=False,
    ):
        """API Helper perform API request to ThirdParty platform \
        and captures all the possible errors for requests.

        Args:
            request (request): Requests object.
            logger_msg (str): Logger string.
            is_handle_error_required (bool, optional): Is handling status
            code is required?. Defaults to True.

        Returns:
            dict: Response dictionary.
        """
        headers = self._add_user_agent(headers)
        try:
            self.logger.debug(
                f"{self.log_prefix}: API Request for {logger_msg}. "
                f'"Method= {method} URL={url}"'
            )
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
                debug_msg = f"API response for {logger_msg} - status code: {response.status_code}."
                self.logger.debug(f"{self.log_prefix}: {debug_msg}")
                if (
                    response.status_code == 429 or 500 <= response.status_code <= 600
                ) and not is_validation:
                    api_err_msg = str(response.text)
                    if retry_counter == MAX_API_CALLS - 1:
                        err_msg = (
                            "Received exit code {}, Max retries "
                            "exceeded for rate limit "
                            "handler in plugin while {}, hence returning status"
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
                        raise MimecastUREException(err_msg)
                    retry_after = int(response.headers.get("Retry-After", 60))
                    self.logger.error(
                        message=(
                            "{}: Received exit code {}, API rate limit"
                            " exceeded while {}. Retrying after {} "
                            "seconds. {} retries remaining.".format(
                                self.log_prefix,
                                response.status_code,
                                logger_msg,
                                retry_after,
                                MAX_API_CALLS - 1 - retry_counter,
                            )
                        ),
                        details=api_err_msg,
                    )
                    if retry_after > 300:
                        err_msg = (
                            "'Retry-After' value received from response "
                            "headers while {} is greater than 5 minutes hence"
                            " returning status code {}.".format(
                                logger_msg, response.status_code
                            )
                        )
                        self.logger.error(f"{self.log_prefix}: {err_msg}")
                        raise MimecastUREException(err_msg)
                    time.sleep(retry_after)
                else:
                    return (
                        self.handle_error(response, logger_msg, is_validation)
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
            raise MimecastUREException(err_msg)
        except requests.exceptions.ConnectionError as error:
            err_msg = (
                "Unable to establish connection with {} "
                "platform while {}. Proxy server or {}"
                " server is not reachable.".format(
                    self.plugin_name, logger_msg, self.plugin_name
                )
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {error}",
                details=str(traceback.format_exc()),
            )
            raise MimecastUREException(err_msg)
        except requests.HTTPError as err:
            err_msg = f"HTTP Error occurred while {logger_msg}."
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {err}",
                details=str(traceback.format_exc()),
            )
            raise MimecastUREException(err_msg)
        except MimecastUREException:
            raise
        except Exception as exp:
            err_msg = (
                "Unexpected error occurred while requesting to "
                f"{self.plugin_name} server while {logger_msg}. Error: {exp}"
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=str(traceback.format_exc()),
            )
            raise MimecastUREException(err_msg)

    def parse_response(self, response, is_validation=False):
        """Parse Response will return JSON from response object.

        Args:
            response (response): Response object.

        Returns:
            json: Response Json.
        """
        try:
            return response.json()
        except json.JSONDecodeError as err:
            err_msg = f"Invalid JSON response received from API. Error: {str(err)}"
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            if is_validation:
                err_msg = "Verify provided configuration parameters."
            raise MimecastUREException(err_msg)
        except Exception as exp:
            err_msg = (
                "Unexpected error occurred while parsing"
                " json response. Error: {}".format(exp)
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=traceback.format_exc(),
            )
            if is_validation:
                err_msg = "Verify provided configuration parameters."
            raise MimecastUREException(err_msg)

    def handle_error(
        self, resp: requests.models.Response, logger_msg: str, is_validation=False
    ) -> Dict:
        """Handle the different HTTP response code.

        Args:
            resp (requests.models.Response): Response object returned
                from API call.
            logger_msg
        Returns:
            dict: Returns the dictionary of response JSON when the
                response code is 200.
        Raises:
            MimecastUREException: When the response code is
            not 200,201 and 204.
        """
        if resp.status_code in [200, 201]:
            return self.parse_response(response=resp, is_validation=is_validation)
        elif resp.status_code == 204:
            return {}
        elif resp.status_code == 403:
            err_msg = "Received exit code 403, Forbidden user while {}.".format(
                logger_msg
            )
            resp_json = self.parse_response(response=resp, is_validation=is_validation)
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=str(resp_json),
            )
            raise MimecastUREException(err_msg)
        elif resp.status_code >= 400 and resp.status_code < 500:
            err_msg = "Received exit code {}, HTTP client error while {}.".format(
                resp.status_code, logger_msg
            )
            resp_json = self.parse_response(response=resp, is_validation=is_validation)
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=str(resp_json),
            )
            raise MimecastUREException(err_msg)
        elif resp.status_code >= 500 and resp.status_code < 600:
            err_msg = f"Received exit code {resp.status_code}. HTTP Server Error."
            resp_json = self.parse_response(response=resp, is_validation=is_validation)
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=str(resp_json),
            )
            raise MimecastUREException(err_msg)
        else:
            err_msg = f"Received exit code {resp.status_code}. HTTP Error."
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            raise MimecastUREException(err_msg)
