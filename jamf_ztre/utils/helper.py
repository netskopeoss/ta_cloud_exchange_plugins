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
OF THIS SOFTWARE, EVEN IF IDVISED OF THE POSSIBILITY OF SUCH DAMAGE.

CRE Jamf plugin helper module.
"""

import json
import time
import traceback
import requests
from typing import Dict, Union
from requests.exceptions import ReadTimeout
from requests.auth import HTTPBasicAuth
from netskope.common.utils import add_user_agent

from .constants import (
    MAX_API_CALLS,
    MODULE_NAME,
    LOGIN_ENDPOINT,
    DEFAULT_RETRY_AFTER_TIME,
    PLATFORM_NAME,
)


class JamfPluginException(Exception):
    """Jamf exception class."""

    pass


class JamfPluginHelper(object):
    """JamfPluginHelper class.

    Args:
        object (object): Object class.
    """

    def __init__(
        self,
        logger,
        log_prefix: str,
        plugin_name: str,
        plugin_version: str,
        configuration: Dict,
    ):
        """Jamf Plugin Helper initializer.

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
        self.configuration = configuration

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
        regenerate_auth_token=True,
        auth=None,
    ):
        """API Helper to perform API request on ThirdParty platform \
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
            debug_log_msg = (
                f"{self.log_prefix}: API Request for {logger_msg}."
                f" Endpoint: {method} {url}"
            )
            if params:
                debug_log_msg += f", params: {params}"

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
                    (status_code == 401 or status_code == 403)
                    and regenerate_auth_token
                    and not is_validation
                ):
                    self.logger.error(
                        f"{self.log_prefix}: Received exit code {status_code} "
                        f"while {logger_msg}. Hence regenerating access token."
                        f"API Response: {response.text}"
                    )
                    base_url, username, password = self.get_credentials(
                        configuration=self.configuration
                    )
                    access_token = self.get_access_token(
                        headers,
                        base_url,
                        username,
                        password,
                    )
                    headers["Authorization"] = f"Bearer {access_token}"
                    return self.api_helper(
                        url=url,
                        method=method,
                        params=params,
                        headers=headers,
                        json=json,
                        data=data,
                        proxies=proxies,
                        verify=verify,
                        is_handle_error_required=is_handle_error_required,
                        is_validation=is_validation,
                        logger_msg=logger_msg,
                        regenerate_auth_token=False,
                        auth=auth,
                    )

                elif status_code == 429 and not is_validation:
                    api_err_msg = str(response.text)
                    if retry_counter == MAX_API_CALLS - 1:
                        err_msg = (
                            "Received exit code {}, Max retries "
                            "exceeded for rate limit "
                            "handler in plugin while {}, hence returning"
                            " status code {}.".format(
                                status_code,
                                logger_msg,
                                status_code,
                            )
                        )
                        self.logger.error(
                            message=f"{self.log_prefix}: {err_msg}",
                            details=api_err_msg,
                        )
                        raise JamfPluginException(err_msg)
                    retry_after = int(
                        response.headers.get(
                            "X-Rate-Limit-Retry-After-Milliseconds",
                            DEFAULT_RETRY_AFTER_TIME,
                        )
                    )
                    # converting milliseconds to seconds
                    retry_after = retry_after // 1000
                    if retry_after > 300:
                        err_msg = (
                            "'X-Rate-Limit-Retry-After-Milliseconds' "
                            "value received from response "
                            "headers while {} is greater than 5 minutes hence"
                            " returning status code {}.".format(
                                logger_msg, status_code
                            )
                        )
                        self.logger.error(f"{self.log_prefix}: {err_msg}")
                        raise JamfPluginException(err_msg)
                    self.logger.error(
                        message=(
                            "{}: Received exit code {}, API rate limit"
                            " exceeded while {}. Retrying after {} "
                            "seconds. {} retries remaining.".format(
                                self.log_prefix,
                                status_code,
                                logger_msg,
                                retry_after,
                                MAX_API_CALLS - 1 - retry_counter,
                            )
                        ),
                        details=api_err_msg,
                    )
                    time.sleep(retry_after)
                elif (500 <= status_code <= 600) and not is_validation:
                    default_sleep_time = int(DEFAULT_RETRY_AFTER_TIME // 1000)
                    resp_json = self.parse_response(response=response)
                    api_err_msg = str(resp_json.text)
                    if retry_counter == MAX_API_CALLS - 1:
                        err_msg = (
                            f"Received exit code {status_code}, while "
                            f" {logger_msg}. Max retries for rate limit "
                            "handler exceeded hence returning status"
                            f" code {status_code}."
                        )
                        self.logger.error(
                            message=f"{self.log_prefix}: {err_msg}",
                            details=api_err_msg,
                        )
                        raise JamfPluginException(err_msg)

                    self.logger.error(
                        message=(
                            f"{self.log_prefix}: Received exit code "
                            f"{status_code}, HTTP server error occurred while "
                            f"{logger_msg}. Retrying after"
                            f" {default_sleep_time} seconds. "
                            f"{MAX_API_CALLS - 1 - retry_counter} "
                            "retries remaining."
                        ),
                        details=api_err_msg,
                    )
                    time.sleep(default_sleep_time)
                else:
                    return (
                        self.handle_error(response, logger_msg, is_validation)
                        if is_handle_error_required
                        else response
                    )
        except ReadTimeout as error:
            err_msg = f"Read Timeout error occurred while {logger_msg}."
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} {error}",
                details=str(traceback.format_exc()),
            )
            raise JamfPluginException(err_msg)
        except requests.exceptions.ProxyError as error:
            err_msg = (
                f"Proxy error occurred while {logger_msg}. Verify the "
                "provided proxy configuration."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} {error}",
                details=str(traceback.format_exc()),
            )
            raise JamfPluginException(err_msg)
        except requests.exceptions.ConnectionError as error:
            err_msg = (
                "Unable to establish connection with {} "
                "platform while {}. Proxy server or {}"
                " server is not reachable.".format(
                    PLATFORM_NAME, logger_msg, PLATFORM_NAME
                )
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} {error}",
                details=str(traceback.format_exc()),
            )
            raise JamfPluginException(err_msg)
        except requests.HTTPError as err:
            err_msg = f"HTTP Error occurred while {logger_msg}."
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} {err}",
                details=str(traceback.format_exc()),
            )
            raise JamfPluginException(err_msg)
        except JamfPluginException:
            raise
        except Exception as exp:
            err_msg = (
                "Unexpected error occurred while requesting to "
                f"{PLATFORM_NAME} server while {logger_msg}. {exp}"
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=str(traceback.format_exc()),
            )
            raise JamfPluginException(err_msg)

    def parse_response(
        self, response: requests.models.Response, is_validation: bool = False
    ):
        """Parse Response will return JSON from response object.

        Args:
            response (response): Response object.
            is_validation (bool): Is validation required.
        Returns:
            Any: Response Json.
        """
        try:
            return response.json()
        except json.JSONDecodeError as err:
            err_msg = f"Invalid JSON response received from API. {str(err)}"
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=f"API response: {response.text}",
            )
            if is_validation:
                err_msg = (
                    "Verify Base URL provided in the "
                    "configuration parameters. Check logs for more details."
                )
            raise JamfPluginException(err_msg)
        except Exception as exp:
            err_msg = (
                "Unexpected error occurred while parsing"
                f" json response. Error: {exp}"
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=f"API response: {response.text}",
            )
            if is_validation:
                err_msg = (
                    "Unexpected validation error occurred, "
                    "Verify Base URL provided in the "
                    "configuration parameters. Check logs for more details."
                )
            raise JamfPluginException(err_msg)

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
            400: "Received exit code 400, HTTP client error",
            403: "Received exit code 403, Forbidden",
            401: "Received exit code 401, Unauthorized access",
            404: "Received exit code 404, Resource not found",
        }
        if is_validation:
            error_dict = {
                400: ("Received exit code 400, Bad Request"),
                401: (
                    "Received exit code 401, Unauthorized, Verify "
                    "Base URL, Application ID and Application Secret "
                    "provided in the "
                    "configuration parameters."
                ),
                403: (
                    "Received exit code 403, Unauthorized, Verify "
                    "Base URL, Application ID and Application"
                    " Secret provided in the "
                    "configuration parameters."
                ),
                404: (
                    "Received exit code 404, Resource not found, Verify "
                    "Base URL provided in the configuration parameters."
                ),
            }

        if status_code in [200, 201]:
            return self.parse_response(
                response=resp, is_validation=is_validation
            )
        elif status_code == 204:
            return {}
        elif status_code in error_dict:
            err_msg = error_dict[status_code]
            if is_validation:
                log_err_msg = validation_msg + err_msg
                self.logger.error(
                    message=f"{self.log_prefix}: {log_err_msg}",
                    details=f"API response: {resp.text}",
                )
                raise JamfPluginException(err_msg)
            else:
                err_msg += " while " + logger_msg + "."
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg}",
                    details=f"API response: {resp.text}",
                )
                raise JamfPluginException(err_msg)

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
            raise JamfPluginException(err_msg)

    def get_credentials(self, configuration) -> tuple:
        """Get credentials from the configuration.

        Returns:
            tuple: Credentials
        """
        base_url = configuration.get("base_url", "").strip().strip("/")
        username = configuration.get("application_id", "").strip()
        password = configuration.get("application_secret")

        return (base_url, username, password)

    def check_auth_json(self, auth_json: Dict) -> str:
        """Check the validity of auth token.

        Args:
            auth_json (Dict): Auth Json.

        Returns:
            str: Access token if valid else raise exception.
        """
        auth_token = auth_json.get("token")
        if not auth_token:
            err_msg = (
                f"Unable to get access token from {PLATFORM_NAME}."
                " Verify the provided configuration parameters."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=str(auth_json),
            )
            raise JamfPluginException(err_msg)

        return auth_token

    def get_access_token(
        self,
        headers,
        base_url,
        username,
        password,
        is_validation=False,
    ):
        """Get token from jamf platform using username and password.

        Args:
                headers (dict): Header dictionary.
                base_url (str): Base URL of jamf platform.
                username (str): Username that user wants
                password (str): Password that user wants
                log_msg (str): Log message.

        Returns:
            json: JSON response data in case of Success.
        """
        try:
            logger_msg = f"generating authentication token for {PLATFORM_NAME}"
            url = f"{base_url}/{LOGIN_ENDPOINT}"

            response_json = self.api_helper(
                url=url,
                method="POST",
                headers=headers,
                logger_msg=logger_msg,
                auth=HTTPBasicAuth(username, password),
                is_validation=is_validation,
            )

            return self.check_auth_json(auth_json=response_json)
        except JamfPluginException:
            raise
        except Exception as exp:
            if is_validation:
                err_msg = (
                    "Unexpected validation error occurred "
                    "while authenticating."
                )
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg} Error: {exp}",
                    details=traceback.format_exc(),
                )
                raise JamfPluginException(
                    f"{err_msg} Check logs for more details."
                )
            err_msg = "Unexpected error occurred while getting access token."
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {exp}",
                details=traceback.format_exc(),
            )
            raise JamfPluginException(err_msg)
