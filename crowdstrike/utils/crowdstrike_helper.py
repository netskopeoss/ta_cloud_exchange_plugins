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
from typing import Dict, Tuple, Union

import requests
from netskope.common.utils import add_user_agent

from .crowdstrike_constants import (
    DEFAULT_WAIT_TIME,
    MAX_API_CALLS,
    MAX_RETRY_AFTER_IN_MIN,
    MODULE_NAME,
    PLATFORM_NAME,
    PLUGIN_NAME,
    RETRACTION,
)


class CrowdstrikePluginException(Exception):
    """Crowdstrike plugin custom exception class."""

    pass


class CrowdStrikePluginHelper(object):
    """CrowdStrikePluginHelper Class.

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
        """CrowdStrikePluginHelper initializer.

        Args:
            logger (logger object): Logger object.
            log_prefix (str): Log prefix.
            plugin_name (str): Plugin name.
            plugin_version (str): Plugin version.
            ssl_validation : SSL Validation Flag.
            proxy : Proxy Configuration.
        """
        self.logger = logger
        self.log_prefix = log_prefix
        self.plugin_name = plugin_name
        self.plugin_version = plugin_version
        self.verify = ssl_validation
        self.proxy = proxy

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
        url: str,
        method: str = "GET",
        params: Dict = {},
        configuration: Dict = {},
        data=None,
        files=None,
        headers: Dict = {},
        json=None,
        is_handle_error_required=True,
        is_validation=False,
        regenerate_auth_token=True,
        is_retraction: bool = False,
        show_params: bool = True,
    ):
        """API Helper perform API request to ThirdParty platform
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
            if is_retraction and RETRACTION not in self.log_prefix:
                self.log_prefix = self.log_prefix + f" [{RETRACTION}] "
            headers = self._add_user_agent(headers)

            debug_log_msg = (
                f"{self.log_prefix}: API Request for {logger_msg}."
                f" Endpoint: {method} {url}"
            )
            if params and show_params:
                debug_log_msg += f", params: {params}."

            self.logger.debug(debug_log_msg)
            for retry_counter in range(MAX_API_CALLS):
                response = requests.request(
                    url=url,
                    method=method,
                    params=params,
                    data=data,
                    headers=headers,
                    verify=self.verify,
                    proxies=self.proxy,
                    json=json,
                    files=files,
                )
                status_code = response.status_code
                self.logger.debug(
                    f"{self.log_prefix}: Received API Response for "
                    f"{logger_msg}. Status Code={status_code}."
                )
                if (
                    status_code == 401
                    and regenerate_auth_token
                    and not is_validation
                ):
                    base_url, client_id, client_secret = self.get_credentials(
                        configuration=configuration
                    )
                    auth_header = self.get_auth_header(
                        client_id,
                        client_secret,
                        base_url,
                        is_retraction=is_retraction,
                    )
                    headers.update(auth_header)
                    return self.api_helper(
                        url=url,
                        method=method,
                        params=params,
                        headers=headers,
                        json=json,
                        files=files,
                        data=data,
                        is_handle_error_required=is_handle_error_required,
                        is_validation=is_validation,
                        logger_msg=logger_msg,
                        regenerate_auth_token=False,
                        is_retraction=is_retraction,
                    )

                elif status_code == 429 and not is_validation:
                    resp_json = self.parse_response(response=response)
                    api_err_msg = str(
                        resp_json.get(
                            "errors",
                            "No error details found in API response.",
                        )
                    )
                    if retry_counter == MAX_API_CALLS - 1:
                        err_msg = (
                            f"Received exit code {status_code}, API rate "
                            f"limit exceeded while {logger_msg}. Max "
                            "retries for rate limit handler exceeded "
                            "hence returning status code 429."
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
                            f"{self.log_prefix}: No X-Ratelimit-Retryafter"
                            f" value received from API hence plugin will "
                            f"retry after {DEFAULT_WAIT_TIME} seconds."
                        )
                        time.sleep(DEFAULT_WAIT_TIME)
                        continue
                    retry_after = int(retry_after)
                    diff_retry_after = abs(retry_after - time.time())
                    if diff_retry_after > 300:
                        err_msg = (
                            "'X-Ratelimit-Retryafter' value received from "
                            f"response headers while {logger_msg} is greater "
                            f" than {MAX_RETRY_AFTER_IN_MIN} minutes hence "
                            f"returning status code {status_code}."
                        )
                        self.logger.error(
                            message=f"{self.log_prefix}: {err_msg}"
                        )
                        raise CrowdstrikePluginException(err_msg)
                    self.logger.error(
                        message=(
                            "{}: Received exit code 429, API rate limit"
                            " exceeded while {}. Retrying after {} "
                            "seconds. {} retries remaining.".format(
                                self.log_prefix,
                                logger_msg,
                                diff_retry_after,
                                MAX_API_CALLS - 1 - retry_counter,
                            )
                        ),
                        details=api_err_msg,
                    )
                    time.sleep(diff_retry_after)
                elif (500 <= status_code <= 600) and not is_validation:
                    resp_json = self.parse_response(response=response)
                    api_err_msg = str(
                        resp_json.get(
                            "errors",
                            "No error details found in API response.",
                        )
                    )
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
                        raise CrowdstrikePluginException(err_msg)

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
        except CrowdstrikePluginException:
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
            raise CrowdstrikePluginException(err_msg)
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
            raise CrowdstrikePluginException(err_msg)
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
            raise CrowdstrikePluginException(err_msg)
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
                raise CrowdstrikePluginException(
                    f"{err_msg} Check logs for more details."
                )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {exp}",
                details=traceback.format_exc(),
            )
            raise CrowdstrikePluginException(err_msg)

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
                    "Verify Base URL provided in the "
                    "configuration parameters. Check logs for more details."
                )
            raise CrowdstrikePluginException(err_msg)
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
            raise CrowdstrikePluginException(err_msg)

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
                400: (
                    "Received exit code 400, Bad Request, Verify the "
                    " Base URL, Client ID and Client Secret provided in the"
                    " configuration parameters."
                ),
                401: (
                    "Received exit code 401, Unauthorized, Verify "
                    "Client ID and Client Secret provided in the "
                    "configuration parameters."
                ),
                403: (
                    "Received exit code 403, Forbidden, Verify API scopes "
                    " provided to Client ID and Client Secret."
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
                raise CrowdstrikePluginException(err_msg)
            else:
                err_msg = err_msg + " while " + logger_msg + "."
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg}",
                    details=f"API response: {resp.text}",
                )
                raise CrowdstrikePluginException(err_msg)

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
            raise CrowdstrikePluginException(err_msg)

    def get_auth_header(
        self,
        client_id,
        client_secret,
        base_url,
        is_validation=False,
        is_retraction=False,
    ):
        """Get the OAUTH2 Json object with access token from CrowdStrike
        platform.

        Args:
            client_id (str): Client ID required to generate OAUTH2 token.
            client_secret (str): Client Secret required to generate OAUTH2
            token.
            base_url (str): Base URL of CrowdStrike.
            is_validation (bool): Is this a validation call?
            is_retraction (bool): Is this a retraction call?
        Returns:
            json: JSON response data in case of Success.
        """
        if is_retraction and RETRACTION not in self.log_prefix:
            self.log_prefix = self.log_prefix + f" [{RETRACTION}]"
        auth_endpoint = f"{base_url}/oauth2/token"
        auth_params = {
            "grant_type": "client_credentials",
            "client_id": client_id,
            "client_secret": client_secret,
        }
        try:
            response = self.api_helper(
                method="POST",
                url=auth_endpoint,
                data=auth_params,
                logger_msg=f"getting auth token from {PLUGIN_NAME}",
                is_handle_error_required=False,
                is_validation=is_validation,
            )
            if response.status_code in [200, 201]:
                resp_json = self.parse_response(response, is_validation)
                # Check if auth JSON is valid or not.
                return self.check_auth_json(resp_json)
            else:
                return self.handle_error(response, "getting auth token", True)
        except CrowdstrikePluginException:
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
                raise CrowdstrikePluginException(
                    f"{err_msg} Check logs for more details."
                )
            err_msg = "Unexpected error occurred while getting auth token."
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {exp}",
                details=traceback.format_exc(),
            )
            raise CrowdstrikePluginException(err_msg)

    def get_credentials(self, configuration: Dict) -> Tuple:
        """Get API Credentials.

        Args:
            configuration (Dict): Configuration dictionary.

        Returns:
            Tuple: Tuple containing Base URL, Client ID and Client Secret.
        """
        return (
            configuration.get("base_url", "").strip(),
            configuration.get("client_id", "").strip(),
            configuration.get("client_secret"),
        )

    def check_auth_json(self, auth_json: Dict) -> str:
        """Check the validity of auth token.

        Args:
            auth_json (Dict): Auth Json.

        Returns:
            str: Access token if valid else raise exception.
        """
        auth_token = auth_json.get("access_token")
        if not auth_token:
            err_msg = (
                f"Unable to get auth token from {PLATFORM_NAME}."
                " Verify the provided configuration parameters."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=str(auth_json),
            )
            raise CrowdstrikePluginException(err_msg)

        return {
            "Authorization": f"Bearer {auth_token}",
            "Accept": "application/json",
        }
