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

CTE ExtraHop Reveal(x) 360 plugin helper module.
"""

import base64
import json
import time
import traceback
from typing import Dict, Union

import requests
from netskope.common.utils import add_user_agent

from .constants import (
    DEFAULT_WAIT_TIME,
    MAX_API_CALLS,
    MODULE_NAME,
    PLATFORM_NAME,
    RETRACTION,
)


class ExtraHopPluginException(Exception):
    """ExtraHop Reveal(x) 360 plugin custom exception class."""

    pass


class ExtraHopPluginHelper(object):
    """ExtraHopPluginHelper class.

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
        """ExtraHopPluginHelper initializer.

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

    def generate_auth_token(self, configuration, verify, proxies, logger_msg=""):
        """Generate auth token.

        Returns:
            str: auth token
        """
        if not logger_msg:
            logger_msg = "generating auth token"
        endpoint = f"{configuration.get('base_url').strip().rstrip('/')}/oauth2/token"
        token = (
            f"{configuration.get('client_id', '').strip()}:"
            f"{configuration.get('client_secret')}"
        )
        headers = {
            "Authorization": f"Basic {base64.b64encode(token.encode('utf-8')).decode('utf-8')}",
            "Content-Type": "application/x-www-form-urlencoded",
        }
        params = {"grant_type": "client_credentials"}
        resp = self.api_helper(
            url=endpoint,
            configuration=configuration,
            method="POST",
            params=params,
            headers=headers,
            logger_msg=logger_msg,
            verify=verify,
            proxies=proxies,
            is_handle_error_required=True,
            regenerate_auth_token=False,
        )
        return resp.get("access_token", "")

    def api_helper(
        self,
        configuration,
        logger_msg: str,
        url,
        method,
        params=None,
        data=None,
        headers=None,
        json=None,
        verify: bool = True,
        proxies: Dict = {},
        is_handle_error_required=True,
        regenerate_auth_token=True,
        is_retraction: bool = False,
        is_validation: bool = False,
    ):
        """
        API Helper perform API request to ThirdParty platform
        and captures all the possible errors for requests.

        Args:
            configuration (dict): Configuration dictionary.
            logger_msg (str): Logger message.
            url (str): URL for the API request.
            method (str): HTTP Method for the API request.
            params (Dict, optional): Parameters for the API request.
            data (Any, optional): Data to be sent to API. Defaults to None.
            headers (Dict, optional): Headers for the API request.
            json (dict): Json payload for request. Defaults to None.
            verify (bool): SSL verification.
            proxies (dict): Proxies for the API request.
            is_handle_error_required (bool): Is handling status
                code is required?
            regenerate_auth_token (bool): Should regenerate
                auth token if expired?
            is_retraction (bool): Is it a retraction call?
            is_validation (bool, optional): Does this request coming from
            validate method?. Defaults to False.

        Returns:
            dict: Response dictionary.
        """
        headers = self._add_user_agent(headers)
        if is_retraction and RETRACTION not in self.log_prefix:
            self.log_prefix = self.log_prefix + f" [{RETRACTION}]"
        try:
            for retry_counter in range(MAX_API_CALLS):
                debug_msg = f"API endpoint for {logger_msg}: {url}"
                if params:
                    debug_msg += f", API params: {params}"
                if data:
                    debug_msg += f", API data: {data}"
                if json:
                    debug_msg += f", API json body: {json}"
                self.logger.debug(f"{self.log_prefix}: {debug_msg}")
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
                self.logger.debug(
                    f"{self.log_prefix}: "
                    f"API response for {logger_msg}: {response.status_code}."
                )

                if (
                    (
                        (
                            response.status_code == 400
                            and response.text.strip()
                            and response.text.split()[0] == "invalid"
                        )
                        or (
                            response.status_code == 401
                            and response.text.strip()
                            and "Error getting user from bearer token" in response.text
                        )
                    )
                    and regenerate_auth_token
                    and not is_validation
                ):
                    # regenerate auth token
                    self.logger.info(
                        f"{self.log_prefix}: "
                        "The auth token used is expired hence regenerating "
                        "the auth token."
                    )
                    auth_token = self.generate_auth_token(
                        configuration, verify, proxies
                    )
                    if not auth_token:
                        err_msg = (
                            "Error occurred while generating auth token."
                            "Check the Client ID and Client Secret."
                        )
                        self.logger.error(f"{self.log_prefix}: {err_msg} ")
                        raise ExtraHopPluginException(err_msg)
                    headers["Authorization"] = f"Bearer {auth_token}"
                    return self.api_helper(
                        logger_msg=logger_msg,
                        url=url,
                        configuration=configuration,
                        method=method,
                        params=params,
                        data=data,
                        headers=headers,
                        json=json,
                        verify=verify,
                        proxies=proxies,
                        is_handle_error_required=is_handle_error_required,
                        regenerate_auth_token=False,
                    )
                if "authenticating" not in logger_msg and (
                    (response.status_code >= 500 and response.status_code <= 600)
                    or response.status_code == 429
                    and not is_validation
                ):
                    try:
                        resp_json = self.parse_response(
                            response=response,
                            logger_msg=logger_msg,
                            is_validation=is_validation,
                        )
                        api_error = resp_json.get("error")
                        api_error_message = resp_json.get("error_message")
                        api_error_detail = resp_json.get("detail")
                        combined_err_msg = (
                            f"Received exit code {response.status_code} "
                            f"for {logger_msg}."
                        )
                        if api_error:
                            combined_err_msg += " " + api_error
                        if api_error_message:
                            combined_err_msg += " " + api_error_message
                        if api_error_detail:
                            combined_err_msg += " " + api_error_detail

                    except ExtraHopPluginException:
                        combined_err_msg = str(response.text)

                    if retry_counter == MAX_API_CALLS - 1:
                        self.logger.error(
                            message=f"{self.log_prefix}: {combined_err_msg}",
                            details=str(response.text),
                        )
                        raise ExtraHopPluginException(combined_err_msg)
                    self.logger.error(
                        message=(
                            "{}: {} Retrying after {} "
                            "seconds. {} retries remaining.".format(
                                self.log_prefix,
                                combined_err_msg,
                                DEFAULT_WAIT_TIME,
                                MAX_API_CALLS - 1 - retry_counter,
                            )
                        ),
                        details=response.text,
                    )
                    time.sleep(DEFAULT_WAIT_TIME)
                else:
                    return (
                        self.handle_error(response, logger_msg, is_validation)
                        if is_handle_error_required
                        else response
                    )
        except requests.exceptions.ProxyError as error:
            err_msg = (
                f"Proxy error occurred while {logger_msg}. "
                "Verify the provided proxy configuration."
            )
            if is_validation:
                err_msg = (
                    "Proxy error occurred. Verify " "the proxy configuration provided."
                )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {error}",
                details=str(traceback.format_exc()),
            )
            raise ExtraHopPluginException(err_msg)
        except requests.exceptions.ConnectionError as error:
            err_msg = (
                f"Unable to establish connection with {PLATFORM_NAME} "
                f"platform while {logger_msg}. "
                f"Proxy server or {PLATFORM_NAME} "
                "server is not reachable."
            )
            if is_validation:
                err_msg = (
                    f"Unable to establish connection with {PLATFORM_NAME} "
                    f"platform. Proxy server or {PLATFORM_NAME} "
                    "server is not reachable."
                )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {error}",
                details=str(traceback.format_exc()),
            )
            raise ExtraHopPluginException(err_msg)
        except requests.exceptions.ReadTimeout as error:
            err_msg = f"Read Timeout error occurred while {logger_msg}."
            if is_validation:
                err_msg = (
                    "Read Timeout error occurred. "
                    "Verify the 'Base URL' provided in the "
                    "configuration parameters."
                )

            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {error}",
                details=traceback.format_exc(),
            )
            raise ExtraHopPluginException(err_msg)
        except requests.HTTPError as err:
            err_msg = f"HTTP Error occurred while {logger_msg}."
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {err}",
                details=str(traceback.format_exc()),
            )
            raise ExtraHopPluginException(err_msg)
        except ExtraHopPluginException as exp:
            raise ExtraHopPluginException(exp)
        except Exception as exp:
            err_msg = f"Unexpected error occurred while {logger_msg}."
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {exp}",
                details=str(traceback.format_exc()),
            )
            raise ExtraHopPluginException(err_msg)

    def parse_response(
        self, response: requests.models.Response, logger_msg: str, is_validation: bool
    ):
        """Parse Response will return JSON from response object.

        Args:
            response (response): Response object.
            logger_msg (str): Logger message.
            is_validation (bool): API call from validation method or not

        Returns:
            Any: Response Json.
        """
        try:
            return response.json()
        except json.JSONDecodeError as err:
            err_msg = (
                f"Invalid JSON response received from API while {logger_msg}."
                f"Error: {str(err)}"
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=f"API response: {response.text}",
            )
            if is_validation:
                err_msg = (
                    "Validation Error occurred. Invalid JSON response received from API"
                )
            raise ExtraHopPluginException(err_msg)
        except Exception as exp:
            err_msg = (
                "Unexpected error occurred while parsing "
                f"json response for {logger_msg}. Error: {exp}"
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=f"API Response: {response.text}",
            )
            if is_validation:
                err_msg = (
                    "Unexpected validation error occurred, Verify "
                    "Base URL, Client ID and Client Secret provided in the"
                    " configuration parameters. Check logs for more details."
                )
            raise ExtraHopPluginException(err_msg)

    def handle_error(
        self, resp: requests.models.Response, logger_msg: str, is_validation: bool
    ) -> Dict:
        """Handle the different HTTP response code.

        Args:
            resp (requests.models.Response): Response object returned
                from API call.
            logger_msg (str): logger message.
            is_validation (bool): API call from validation method or not
        Returns:
            dict: Returns the dictionary of response JSON when the
                response code is 200.
        Raises:
            ExtraHopException: When the response code is
            not in 200 range.
        """
        validation_error_msg = "Validation error occurred, "
        error_dict = {
            400: "Received exit code 400, HTTP client error",
            401: "Received exit code 401, Unauthorized error, check the Client Secret provided.",
            403: "Received exit code 403, Forbidden",
            404: "Received exit code 404, Resource not found",
        }
        if is_validation:
            error_dict = {
                400: (
                    "Received exit code 400, Bad Request, Verify the "
                    " Base URL provided in the configuration parameters."
                ),
                401: (
                    "Received exit code 401, Unauthorized, Verify "
                    "Client ID and Client Secret provided in the "
                    "configuration parameters."
                ),
                403: (
                    "Received exit code 403, Forbidden, Verify API scopes "
                    " provided to Token."
                ),
                404: (
                    "Received exit code 404, Resource not found, Verify "
                    "Base URL provided in the configuration parameters."
                ),
            }

        if resp.status_code in [200, 201, 202]:
            try:
                return self.parse_response(
                    response=resp, logger_msg=logger_msg, is_validation=is_validation
                )
            except Exception:
                err_msg = "Invalid response received. Check the Base URL provided."
                self.logger.error(f"{self.log_prefix}: {err_msg}")
                raise ExtraHopPluginException(err_msg)
        try:
            resp_json = self.parse_response(
                response=resp, logger_msg=logger_msg, is_validation=is_validation
            )
            api_error = resp_json.get("error")
            api_error_message = resp_json.get("error_message")
            api_error_detail = resp_json.get("detail")
            combined_err_msg = (
                f"Received exit code {resp.status_code} while {logger_msg}."
            )
            if api_error:
                combined_err_msg += " API error - " + api_error
            if api_error_message:
                combined_err_msg += " API error message - " + api_error_message
            if api_error_detail:
                combined_err_msg += " API error details - " + api_error_detail
        except Exception:
            combined_err_msg = resp.text

        if "invalid_client" in combined_err_msg:
            error_msg = (
                "Invalid client error occurred, "
                "check the Client ID and Secret provided."
            )
            self.logger.error(
                f"{self.log_prefix}: {combined_err_msg}", details=resp.text
            )
            raise ExtraHopPluginException(error_msg)
        elif resp.status_code == 204:
            return {}
        elif resp.status_code in error_dict:
            err_msg = error_dict.get(resp.status_code)
            if is_validation:
                err_msg = validation_error_msg + err_msg
            self.logger.error(
                f"{self.log_prefix}: {combined_err_msg} " f"{err_msg}",
                details=resp.text,
            )
            raise ExtraHopPluginException(err_msg)
        else:
            self.logger.error(
                message=f"{self.log_prefix}: {combined_err_msg}",
                details=resp.text,
            )
            raise ExtraHopPluginException(combined_err_msg)
