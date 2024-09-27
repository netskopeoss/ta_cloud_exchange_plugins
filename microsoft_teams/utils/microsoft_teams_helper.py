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

CTO Microsoft Teams Plugin helper module.
"""

import json
import requests
import time
import traceback
from typing import Dict, Union

from netskope.common.utils import add_user_agent

from .microsoft_teams_constants import (
    DEFAULT_WAIT_TIME,
    MAX_API_CALLS,
    MODULE_NAME,
    PLATFORM_NAME
)


class MicrosoftTeamsPluginException(Exception):
    """Microsoft Teams plugin custom exception class."""

    pass


class MicrosoftTeamsPluginHelper(object):
    """MicrosoftTeamsPluginHelper Class.

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
        """Microsoft Teams Plugin Helper initializer.

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
        files=None,
        headers: Dict = {},
        json=None,
        verify=True,
        proxies=None,
        is_handle_error_required=True,
        is_validation=False,
    ):
        """API Helper to perform API request on ThirdParty platform \
        and captures all the possible errors for requests.

        Args:
            logger_msg (str): Logger message.
            url (str): API Endpoint.
            method (str): Method for the endpoint.
            params (Dict, optional): Request parameters dictionary.
            Defaults to None.
            data (Any,optional): Data to be sent to API. Defaults to None.
            headers (Dict, optional): Headers for the request. Defaults to {}.
            json (optional): Json payload for request. Defaults to None.
            is_handle_error_required (bool, optional): Does the API helper
            should handle the status codes. Defaults to True.
            is_validation (bool, optional): Does this request coming from
            validate method?. Defaults to False.
            regenerate_auth_token (bool, optional): Is regenerating auth token
            required? Defaults to True.
            configuration (Dict): Configuration Dictionary.


        Returns:
            Response|Response JSON: Returns response json if
            is_handle_error_required is True otherwise returns Response object.
        """
        try:
            headers = self._add_user_agent(headers)

            debug_log_msg = (
                f"{self.log_prefix}: API Request for {logger_msg}."
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
                if status_code == 429 and not is_validation:
                    api_err_msg = str(response.text)
                    if retry_counter == MAX_API_CALLS - 1:
                        err_msg = (
                            f"Received exit code {status_code}, API rate "
                            f"limit exceeded while {logger_msg}. Max "
                            "retries for rate limit handler exceeded "
                            f"hence returning status code {status_code}."
                        )
                        self.logger.error(
                            message=f"{self.log_prefix}: {err_msg}",
                            details=api_err_msg,
                        )
                        raise MicrosoftTeamsPluginException(err_msg)
                    self.logger.error(
                        message=(
                            "{}: Received exit code 429, API rate limit"
                            " exceeded while {}. Retrying after {} "
                            "seconds. {} retries remaining.".format(
                                self.log_prefix,
                                logger_msg,
                                DEFAULT_WAIT_TIME,
                                MAX_API_CALLS - 1 - retry_counter,
                            )
                        ),
                        details=api_err_msg,
                    )
                    time.sleep(DEFAULT_WAIT_TIME)
                elif (500 <= status_code <= 600) and not is_validation:
                    api_err_msg = str(response.text)
                    if retry_counter == MAX_API_CALLS - 1:
                        err_msg = (
                            f"Received exit code {status_code}, while "
                            f" {logger_msg}. Max retries for rate limit "
                            "handler exceeded hence returning status"
                            f" code {status_code}. "
                            "Verify the Workflow URL provided "
                            "in the configuration parameters."
                        )
                        self.logger.error(
                            message=f"{self.log_prefix}: {err_msg}",
                            details=api_err_msg,
                        )
                        raise MicrosoftTeamsPluginException(err_msg)

                    self.logger.error(
                        message=(
                            f"{self.log_prefix}: Received exit code "
                            f"{status_code}, HTTP server error occurred while "
                            f"{logger_msg}. Retrying after {DEFAULT_WAIT_TIME}"
                            f" seconds. {MAX_API_CALLS - 1 - retry_counter}"
                            " retries remaining."
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
        except MicrosoftTeamsPluginException:
            raise
        except requests.exceptions.ProxyError as error:
            err_msg = (
                f"Proxy error occurred while {logger_msg}. Verify the"
                " proxy configuration provided."
            )
            if is_validation:
                err_msg = (
                    "Proxy error occurred. Verify "
                    "the proxy configuration provided."
                )

            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {error}",
                details=traceback.format_exc(),
            )
            raise MicrosoftTeamsPluginException(err_msg)
        except requests.exceptions.ConnectionError as error:
            err_msg = (
                f"Unable to establish connection with {PLATFORM_NAME} "
                f"platform while {logger_msg}. Proxy server or "
                f"{PLATFORM_NAME} server is not reachable."
            )
            if is_validation:
                err_msg = (
                    f"Unable to establish connection with {PLATFORM_NAME} "
                    f"platform. Proxy server or {PLATFORM_NAME}"
                    " server is not reachable."
                )

            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {error}",
                details=traceback.format_exc(),
            )
            raise MicrosoftTeamsPluginException(err_msg)
        except requests.HTTPError as err:
            err_msg = f"HTTP error occurred while {logger_msg}."
            if is_validation:
                err_msg = (
                    "HTTP error occurred. Verify"
                    " configuration parameters provided."
                )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {err}",
                details=traceback.format_exc(),
            )
            raise MicrosoftTeamsPluginException(err_msg)
        except Exception as exp:
            err_msg = f"Unexpected error occurred while {logger_msg}."
            if is_validation:
                err_msg = (
                    "Unexpected error while performing "
                    f"API call to {PLATFORM_NAME}."
                )
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg} Error: {exp}",
                    details=traceback.format_exc(),
                )
                raise MicrosoftTeamsPluginException(err_msg)
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {exp}",
                details=traceback.format_exc(),
            )
            raise MicrosoftTeamsPluginException(err_msg)

    def parse_response(
        self, response: requests.models.Response, logger_msg, is_validation: bool = False
    ):
        """Parse Response will return JSON from response object.

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
                f"Invalid JSON response received from API while {logger_msg}. Error: {str(err)}"
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=f"API response: {response.text}",
            )
            if is_validation:
                err_msg = (
                    "Verify Workflow URL provided in the "
                    "configuration parameters. Check logs for more details."
                )
            raise MicrosoftTeamsPluginException(err_msg)
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
                    "Verify Workflow URL provided in the "
                    "configuration parameters. Check logs for more details."
                )
            raise MicrosoftTeamsPluginException(err_msg)

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
        validation_msg = "Validation error occurred, "
        error_dict = {
            400: "Received exit code 400, Bad Request",
            403: "Received exit code 403, Forbidden",
            401: "Received exit code 401, Unauthorized access",
            404: "Received exit code 404, Resource not found",
        }
        if is_validation:
            error_dict = {
                400: (
                    "Received exit code 400, Bad Request, Verify the"
                    " Workflow URL provided in the configuration parameters."
                ),
                401: (
                    "Received exit code 401, Unauthorized, Verify the"
                    " Workflow URL provided in the configuration parameters."
                ),
                403: (
                    "Received exit code 403, Forbidden, Verify the"
                    " Workflow URL provided in the configuration parameters."
                ),
                404: (
                    "Received exit code 404, Resource not found, Verify the"
                    " Workflow URL provided in the configuration parameters."
                ),
            }

        if status_code in [200, 201]:
            return self.parse_response(
                response=resp,
                logger_msg=logger_msg,
                is_validation=is_validation
            )
        elif status_code == 204:
            return {}
        elif status_code == 202:
            return resp.text
        elif status_code in error_dict:
            err_msg = error_dict[status_code]
            if is_validation:
                log_err_msg = validation_msg + err_msg
                self.logger.error(
                    message=f"{self.log_prefix}: {log_err_msg}",
                    details=f"API response: {resp.text}",
                )
                raise MicrosoftTeamsPluginException(err_msg)
            else:
                err_msg = err_msg + " while " + logger_msg + "."
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: {err_msg} "
                        "Verify the Workflow URL provided "
                        "in the configuration parameters "
                        "and make sure provided workflow is enabled "
                        f"in {PLATFORM_NAME}."
                    ),
                    details=f"API response: {resp.text}",
                )
                raise MicrosoftTeamsPluginException(err_msg)

        else:
            err_msg = (
                "HTTP Server Error"
                if (status_code >= 500 and status_code <= 600)
                else "HTTP Error"
            )
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Received exit code {status_code}, "
                    f"{validation_msg+err_msg} while {logger_msg}."
                ),
                details=f"API response: {resp.text}",
            )
            raise MicrosoftTeamsPluginException(err_msg)
