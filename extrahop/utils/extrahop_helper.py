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

import json
import time
import traceback
from typing import Dict, Union
import base64

import requests
from netskope.common.utils import add_user_agent

from .extrahop_constants import (
    DEFAULT_WAIT_TIME,
    MAX_API_CALLS,
    PLATFORM_NAME,
    MODULE_NAME,
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
        ssl_validation,
        proxy,
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
        self.verify = ssl_validation
        self.proxies = proxy

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

    def generate_auth_token(self, configuration, logger_msg=""):
        """Generate auth token.

        Returns:
            str: auth token
        """
        if not logger_msg:
            logger_msg = "generating auth token"
        endpoint = (
            f"{configuration.get('base_url').strip().rstrip('/')}"
            "/oauth2/token"
        )
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
        is_handle_error_required=True,
        regenerate_auth_token=True,
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
                    verify=self.verify,
                    proxies=self.proxies,
                    json=json,
                )
                self.logger.debug(
                    f"{self.log_prefix}: "
                    f"API response for {logger_msg}: {response.status_code}."
                )

                if (
                    (
                        response.status_code == 400
                        and response.text.strip()
                        and response.text.split()[0] == "invalid"
                    )
                    or (
                        response.status_code == 401
                        and response.text.strip()
                        and "Error getting user from bearer token"
                        in response.text
                    )
                ) and regenerate_auth_token:
                    # regenerate auth token
                    self.logger.info(
                        f"{self.log_prefix}: "
                        "The auth token used is expired hence regenerating "
                        "the auth token."
                    )
                    auth_token = self.generate_auth_token(configuration)
                    if not auth_token:
                        err_msg = (
                            "Error occurred while generating auth token."
                            "Check the Client ID and Client Secret."
                        )
                        self.logger.error(
                            f"{self.log_prefix}: {err_msg} "
                        )
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
                        is_handle_error_required=is_handle_error_required,
                        regenerate_auth_token=False,
                    )
                if "authenticating" not in logger_msg and (
                    (response.status_code >= 500 and response.status_code <= 600)
                    or response.status_code == 429
                ):
                    try:
                        resp_json = self.parse_response(response=response)
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
            raise ExtraHopPluginException(err_msg)
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
            raise ExtraHopPluginException(err_msg)
        except Exception as exp:
            err_msg = (
                "Unexpected error occurred while parsing"
                f" json response. Error: {exp}"
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=f"API Response: {response.text}",
            )
            raise ExtraHopPluginException(err_msg)

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
            ExtraHopException: When the response code is
            not in 200 range.
        """
        if resp.status_code in [200, 201, 202]:
            try:
                return self.parse_response(response=resp)
            except Exception:
                err_msg = (
                    "Invalid response received. "
                    "Check the API Base URL provided."
                )
                self.logger.error(
                    f"{self.log_prefix}: {err_msg}"
                )
                raise ExtraHopPluginException(err_msg)
        try:
            resp_json = self.parse_response(response=resp)
            api_error = resp_json.get("error")
            api_error_message = resp_json.get("error_message")
            api_error_detail = resp_json.get("detail")
            combined_err_msg = (
                f"Received exit code {resp.status_code} for {logger_msg}."
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
                f"{self.log_prefix}: {combined_err_msg}",
                details=resp.text
            )
            raise ExtraHopPluginException(error_msg)
        elif resp.status_code == 204:
            return {}
        elif resp.status_code == 401:
            err_msg = (
                "Unauthorized error, "
                "check the Client Secret provided."
            )
            self.logger.error(
                f"{self.log_prefix}: {combined_err_msg} "
                f"{err_msg}",
                details=resp.text,
            )
            raise ExtraHopPluginException(err_msg)
        elif resp.status_code == 403:
            err_msg = (
                "Forbidden error, "
                "verify that the user has the required "
                "permissions attached."
            )
            self.logger.error(
                f"{self.log_prefix}: {combined_err_msg} "
                f"{err_msg}",
                details=resp.text,
            )
            raise ExtraHopPluginException(err_msg)
        else:
            self.logger.error(
                message=f"{self.log_prefix}: {combined_err_msg}",
                details=resp.text,
            )
            raise ExtraHopPluginException(combined_err_msg)
