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

CRE ExtraHop plugin helper module.
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
)


class ExtraHopPluginException(Exception):
    """ExtraHop exception class."""

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
        """ExtraHop Plugin Helper initializer.

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
        auth_creds={},
        params=None,
        data=None,
        headers=None,
        json=None,
        verify=True,
        proxies=None,
        is_handle_error_required=True,
        regenerate_auth_token=True,
        is_validation=False,
        show_data=True,
    ):
        """API helper to perform API request on ThirdParty platform
         and captures all the possible errors for requests.

        Args:
            logger_msg (str): Logger message.
            url (str): API Endpoint.
            method (str): Method for the endpoint.
            auth_creds (Dict): Auth credentials dictionary.
            params (Dict, optional): Request parameters dictionary.
            Defaults to None.
            data (Any,optional): Data to be sent to API. Defaults to None.
            files (Any, optional): Files to be sent to API. Defaults to None.
            headers (Dict, optional): Headers for the request. Defaults to {}.
            json (optional): Json payload for request. Defaults to None.
            verify (bool, optional): Verify SSL. Defaults to True.
            proxies (Dict, optional): Proxies. Defaults to None.
            is_handle_error_required (bool, optional): Does the API helper
            should handle the status codes. Defaults to True.
            is_validation (bool, optional): Does this request coming from
            validate method?. Defaults to False.
            show_data (bool): Does the API helper show the data.
            Defaults to True.

        Returns:
            dict: Response dictionary.
        """
        try:
            headers = self._add_user_agent(headers)
            debug_msg = f"API request for {logger_msg}. Endpoint: {url}"
            if params:
                debug_msg += f", API params: {params}"
            if data and show_data:
                debug_msg += f", API data: {data}"
            if json and show_data:
                debug_msg += f", API json body: {json}"
            self.logger.debug(f"{self.log_prefix}: {debug_msg}")
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
                status_code = response.status_code
                self.logger.debug(
                    f"{self.log_prefix}: Received API response for "
                    f"{logger_msg}. Status Code={status_code}."
                )

                if (
                    (
                        (
                            status_code == 400
                            and response.text.strip()
                            and response.text.split()[0] == "invalid"
                        )
                        or (
                            status_code == 401
                            and response.text.strip()
                            and "Error getting user from bearer token"
                            in response.text
                        )
                    )
                    and regenerate_auth_token
                    and not is_validation
                ):
                    # regenerate auth token
                    self.logger.info(
                        f"{self.log_prefix}: "
                        "The auth token is expired hence regenerating "
                        "the auth token."
                    )
                    auth_token = self.generate_auth_token(
                        base_url=auth_creds.get("base_url"),
                        client_id=auth_creds.get("client_id"),
                        client_secret=auth_creds.get("client_secret"),
                        logger_msg=logger_msg,
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
                        auth_creds=auth_creds,
                        method=method,
                        params=params,
                        data=data,
                        headers=headers,
                        json=json,
                        is_handle_error_required=is_handle_error_required,
                        regenerate_auth_token=False,
                    )
                if "authenticating" not in logger_msg and (
                    (status_code >= 500 and status_code <= 600)
                    or status_code == 429
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
                            f"Received exit code {status_code} "
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
        except ExtraHopPluginException as exp:
            raise ExtraHopPluginException(exp)
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
        except requests.exceptions.ProxyError as error:
            err_msg = (
                f"Proxy error occurred while {logger_msg}. Verify the "
                "proxy configuration provided."
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
            raise ExtraHopPluginException(err_msg)
        except requests.exceptions.ConnectionError as error:
            err_msg = (
                f"Unable to establish connection with {PLATFORM_NAME} "
                f"platform while {logger_msg}. Proxy server or "
                f"{PLATFORM_NAME} server is not reachable."
            )
            if is_validation:
                err_msg = (
                    f"Unable to establish connection with {PLATFORM_NAME} "
                    f"platform. Proxy server or {PLATFORM_NAME} "
                    "server is not reachable."
                )

            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {error}",
                details=traceback.format_exc(),
            )
            raise ExtraHopPluginException(err_msg)
        except requests.HTTPError as err:
            err_msg = f"HTTP error occurred while {logger_msg}."
            if is_validation:
                err_msg = (
                    "HTTP error occurred. Verify "
                    "configuration parameters provided."
                )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {err}",
                details=traceback.format_exc(),
            )
            raise ExtraHopPluginException(err_msg)
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
                raise ExtraHopPluginException(err_msg)
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {exp}",
                details=traceback.format_exc(),
            )
            raise ExtraHopPluginException(err_msg)

    def parse_response(
        self,
        response: requests.models.Response,
        logger_msg,
        is_validation: bool = False,
    ):
        """Parse Response will return JSON from response object.

        Args:
            response (response): Response object.
            logger_msg (str): Logger message.
            is_validation (bool): Is validation required.
        Returns:
            Any: Response Json.
        """
        try:
            return response.json()
        except json.JSONDecodeError as err:
            err_msg = (
                "Invalid JSON response received "
                f"from API while {logger_msg}. Error: {str(err)}"
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=f"API response: {response.text}",
            )
            if is_validation:
                err_msg = (
                    "Verify Base URL, Client ID and Client Secret provided in "
                    "the configuration parameters. Check logs for more"
                    " details."
                )
            raise ExtraHopPluginException(err_msg)
        except Exception as exp:
            err_msg = (
                "Unexpected error occurred while parsing "
                f"json response for {logger_msg}. Error: {exp}"
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=f"API response: {response.text}",
            )
            if is_validation:
                err_msg = (
                    "Unexpected validation error occurred, Verify "
                    "Base URL, Client ID and Client Secret provided in the"
                    " configuration parameters. Check logs for more details."
                )
            raise ExtraHopPluginException(err_msg)

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
                    "Received exit code 400, HTTP client error. "
                    "Verify Base URL provided in the configuration "
                    "parameters."
                ),
                401: (
                    "Received exit code 401, Unauthorized, Verify "
                    "Client ID and Client Secret provided in the "
                    "configuration parameters."
                ),
                403: (
                    "Received exit code 403, Forbidden, Verify the permissions"
                    " provided to Client ID and Client Secret."
                ),
                404: (
                    "Received exit code 404, Resource not found, Verify "
                    "Base URL provided in the configuration parameters."
                ),
            }

        if status_code in [200, 201, 202]:
            return self.parse_response(
                response=resp,
                logger_msg=logger_msg,
                is_validation=is_validation,
            )
        elif status_code == 204:
            return {}
        try:
            resp_json = self.parse_response(
                response=resp,
                logger_msg=logger_msg,
                is_validation=is_validation,
            )
            api_error = resp_json.get("error")
            api_error_message = resp_json.get("error_message")
            api_error_detail = resp_json.get("detail")
            combined_err_msg = (
                f"Received exit code {status_code} for {logger_msg}."
            )
            if api_error:
                combined_err_msg += " API error - " + api_error
            if api_error_message:
                combined_err_msg += (
                    " API error message - " + api_error_message
                )
            if api_error_detail:
                combined_err_msg += " API error details - " + api_error_detail
        except ExtraHopPluginException:
            raise
        except Exception as exp:
            err_msg = "Unexpected error occurred while parsing json"
            if is_validation:
                err_msg = validation_msg + err_msg + "."
            else:
                err_msg += " for " + logger_msg + "."
            self.logger.error(
                f"{self.log_prefix}: {err_msg} Error: {exp}",
                details=traceback.format_exc(),
            )
            raise ExtraHopPluginException(err_msg)

        if "invalid_client" in combined_err_msg:
            err_msg = (
                "Invalid client error occurred, "
                "Verify the Client ID and Secret provided in the "
                "configuration parameters"
            )
            if is_validation:
                err_msg = validation_msg + err_msg + "."
            else:
                err_msg += " while " + logger_msg + "."
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=f"API response: {resp.text}",
            )
            raise ExtraHopPluginException(err_msg)
        elif status_code in error_dict:
            err_msg = error_dict[status_code]
            if is_validation:
                err_msg = validation_msg + err_msg
            else:
                err_msg += " while " + logger_msg + "."
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=f"API response: {resp.text}",
            )
            raise ExtraHopPluginException(err_msg)

        else:
            err_msg = (
                "HTTP Server Error"
                if (status_code >= 500 and status_code <= 600)
                else "HTTP Error"
            )
            if is_validation:
                err_msg = validation_msg + err_msg
            else:
                err_msg += " while " + logger_msg + "."
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Received exit code {status_code}, "
                    f"{err_msg}"
                ),
                details=f"API response: {resp.text}",
            )
            raise ExtraHopPluginException(err_msg)

    def get_credentials(self, configuration) -> tuple:
        """Get credentials from the configuration.

        Returns:
            tuple: Credentials
        """
        base_url = configuration.get("base_url", "").strip().rstrip("/")
        client_id = configuration.get("client_id", "").strip()
        client_secret = configuration.get("client_secret")

        return {
            "base_url": base_url,
            "client_id": client_id,
            "client_secret": client_secret,
        }

    def generate_auth_token(
        self,
        base_url: str,
        client_id: str,
        client_secret: str,
        logger_msg: str = "",
    ):
        """Generate auth token.

        Args:
            base_url (str): Base URL.
            client_id (str): Client ID.
            client_secret (str): Client Secret.
            logger_msg (str, optional): Logger Message. Defaults to "".

        Returns:
            auth_token: Authentication Token received from ExtraHop.
        """
        if not logger_msg:
            logger_msg = "generating auth token"
        endpoint = f"{base_url}/oauth2/token"
        token = f"{client_id}:{client_secret}"
        try:
            headers = {
                "Authorization": "Basic {}".format(
                    base64.b64encode(token.encode("utf-8")).decode("utf-8")
                ),
                "Content-Type": "application/x-www-form-urlencoded",
            }
            params = {"grant_type": "client_credentials"}
            resp = self.api_helper(
                url=endpoint,
                auth_creds={
                    "base_url": base_url,
                    "client_id": client_id,
                    "client_secret": client_secret,
                },
                method="POST",
                params=params,
                headers=headers,
                logger_msg=logger_msg,
                regenerate_auth_token=False,
            )
            auth_token = resp.get("access_token", "")
            if not auth_token:
                err_msg = (
                    f"Unable to get auth token from {PLATFORM_NAME}. "
                    "Verify the Base URL, Client ID and Client Secret provided"
                    " in the configuration parameters."
                )
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg}",
                    details=f"API response: {resp}",
                )
                raise ExtraHopPluginException(err_msg)
            return auth_token
        except ExtraHopPluginException:
            raise
        except Exception as exp:
            if "authenticating credentials" in logger_msg:
                err_msg = (
                    "Unexpected validation error occurred "
                    "while authenticating."
                )
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg} Error: {exp}",
                    details=traceback.format_exc(),
                )
                raise ExtraHopPluginException(
                    f"{err_msg} Check logs for more details."
                )
            err_msg = "Unexpected error occurred while generating auth token."
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {exp}",
                details=traceback.format_exc(),
            )
            raise ExtraHopPluginException(err_msg)
