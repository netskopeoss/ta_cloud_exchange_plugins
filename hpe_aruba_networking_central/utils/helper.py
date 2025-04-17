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

CRE Trial Plugin helper module.
"""

import json
import time
import traceback
from datetime import datetime
from typing import Dict, Tuple, Union

import requests
from netskope.common.utils import add_user_agent
from requests.models import CaseInsensitiveDict

from .constants import DEFAULT_WAIT_TIME, MAX_RETRIES, MODULE_NAME, PLATFORM_NAME, ONE


class HPECentralPluginException(Exception):
    pass


class HPECentralUnauthorizedException(Exception):
    pass


class HPECentralPluginHelper(object):
    def __init__(self, logger, log_prefix: str, plugin_name: str, plugin_version: str):
        self.log_prefix = log_prefix
        self.logger = logger
        self.plugin_name = plugin_name
        self.plugin_version = plugin_version

    def _add_user_agent(self, headers: Union[Dict, None] = None) -> Dict:
        """Add User-Agent in the headers for HPE Central requests.

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

    def get_configuration_parameters(
        self, configuration: Dict
    ) -> Tuple[str, str, str, str, str, str]:
        """
        Get the configuration parameters for the HPE Central plugin.

        Args:
            configuration (Dict): Dictionary containing the configuration parameters.

        Returns:
            Tuple[str, str, str, str, str, str]: A tuple containing the base_url, username,
            password, client_id, client_secret, and customer_id.
        """
        return (
            configuration.get("base_url", "").strip().strip("/"),
            configuration.get("username", "").strip(),
            configuration.get("password", ""),
            configuration.get("client_id", "").strip(),
            configuration.get("client_secret", ""),
            configuration.get("customer_id", "").strip(),
        )

    def generate_access_token(
        self,
        base_url: str,
        username: str,
        password: str,
        client_id: str,
        client_secret: str,
        customer_id: str,
        verify,
        proxies,
        logger_msg="",
        is_validation: bool = False,
    ) -> Union[Tuple[str, str, int], None]:
        """
        Generates a token for authentication.

        Parameters:
            base_url (str): The base URL of the HPE Central API.
            username (str): The username for authentication.
            password (str): The password for authentication.
            client_id (str): The client ID for authentication.
            client_secret (str): The client secret for authentication.
            customer_id (str): The customer ID for authentication.
            verify (bool): Whether to verify the SSL certificate.
            proxies (dict): The proxy server to use for the API call.
            logger_msg (str): The log prefix for the API call.
            is_validation (bool): Whether the request is from a validation process.

        Returns:
            Tuple[str, str, int]: The access token, refresh token, and expires at time.
        """
        try:
            # Step 1: Login and Obtain CSRF token
            step_msg = "Step 1: Login and Obtain CSRF token"
            step1_msg = logger_msg + " - " + step_msg

            url = f"{base_url}/oauth2/authorize/central/api/login?client_id={client_id}"
            _, response_headers = self.api_helper(
                logger_msg=step1_msg,
                url=url,
                method="POST",
                json={"username": username, "password": password},
                verify=verify,
                proxies=proxies,
                is_validation=is_validation,
                regenerate_auth_token=False,
            )
            set_cookie_values = response_headers.get("Set-Cookie", "").split(";")
            if not set_cookie_values:
                err_msg = "Unexpected error occurred while logging in to HPE Central."
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg}",
                    details=(
                        "Failed to login to HPE Central. Response Headers does"
                        "not contain Set-Cookie."
                    ),
                )
                raise HPECentralPluginException(err_msg)
            csrf_token = set_cookie_values[0].split("=")[1]
            session_token = set_cookie_values[2].split("session=")[1]
            time.sleep(ONE)

            # Step 2: Obtain Authorization Code
            step_msg = "Step 2: Obtain Authorization Code"
            step2_msg = logger_msg + " - " + step_msg

            url = (
                f"{base_url}/oauth2/authorize/central/api?client_id="
                f"{client_id}&response_type=code&scope=all"
            )
            headers = {
                "Content-Type": "application/json",
                "Cookie": f"session={session_token}",
                "X-CSRF-Token": csrf_token,
            }
            response, _ = self.api_helper(
                logger_msg=step2_msg,
                url=url,
                method="POST",
                headers=headers,
                json={"customer_id": customer_id},
                verify=verify,
                proxies=proxies,
                is_validation=is_validation,
                regenerate_auth_token=False,
            )
            authorization_code = response.get("auth_code", "")
            time.sleep(ONE)

            # Step 3: Acquire the Access Token
            step_msg = "Step 3: Acquire the Access Token"
            step3_msg = logger_msg + " - " + step_msg

            url = f"{base_url}/oauth2/token"
            response, _ = self.api_helper(
                logger_msg=step3_msg,
                url=url,
                method="POST",
                json={
                    "client_id": client_id,
                    "client_secret": client_secret,
                    "grant_type": "authorization_code",
                    "code": authorization_code,
                },
                verify=verify,
                proxies=proxies,
                is_validation=is_validation,
                regenerate_auth_token=False,
            )
            access_token = response.get("access_token", "")
            refresh_token = response.get("refresh_token", "")
            expires_at = int((datetime.now()).timestamp()) + int(
                response.get("expires_in", 7200)
            )
            return access_token, refresh_token, expires_at

        except HPECentralPluginException:
            raise
        except Exception as error:
            error_msg = "Unexpected error occurred while generating access token"
            self.logger.error(
                message=f"{self.log_prefix}: {error_msg}. Error: {error}",
                details=str(traceback.format_exc()),
            )
            raise HPECentralPluginException(error_msg)

    def regenerate_access_token(
        self, access_token, refresh_token, base_url, client_id, client_secret
    ):
        """
        Regenerates the access token using the refresh token.

        Parameters:
            access_token (str): The access token to use for authentication.
            refresh_token (str): The refresh token to use for authentication.
            base_url (str): The base URL of the HPE Central API.
            client_id (str): The client ID to use for authentication.
            client_secret (str): The client secret to use for authentication.

        Returns:
            Tuple[str, str, int]: The access token, refresh token, and expires at time.
        """
        logger_msg = "Regenerating Access Token"
        headers = self.get_auth_headers(access_token)
        response, _ = self.api_helper(
            logger_msg=logger_msg,
            url=f"{base_url}/oauth2/token",
            method="POST",
            params={
                "client_id": client_id,
                "client_secret": client_secret,
                "grant_type": "refresh_token",
                "refresh_token": refresh_token,
            },
            headers=headers,
            regenerate_auth_token=False,
        )
        access_token = response.get("access_token", "")
        refresh_token = response.get("refresh_token", "")
        expires_at = int((datetime.now()).timestamp()) + int(
            response.get("expires_in", 7200)
        )
        return access_token, refresh_token, expires_at

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
        regenerate_auth_token=True,
    ) -> Union[Tuple[Union[Dict, None], CaseInsensitiveDict[str]], None]:
        """
        Makes an API call to the specified URL with the given parameters.

        Parameters:
            logger_msg (str): The message to log during the API call.
            url (str): The URL of the API endpoint to call.
            method (str): The HTTP method to use for the API call.
            params (Dict): The query parameters to pass with the request.
            data: The data to send in the request body.
            files: The files to send in the request body.
            headers (Dict): The headers to send with the request.
            json: The JSON data to send in the request body.
            verify (bool): Whether to verify the SSL certificate of the API endpoint.
            proxies (Dict): The proxies to use when making the API call.
            is_handle_error_required (bool): Whether to handle errors from the API call.
            is_validation (bool): Whether the API call is for validation.
            regenerate_auth_token (bool): Whether to regenerate the access token if it is invalid or expired.

        Returns:
            Union[Tuple[Union[Dict, None], CaseInsensitiveDict[str]], None]: The response from the API call, or None if an error occurred.
        """
        headers = self._add_user_agent(headers)
        self.logger.debug(
            f"{self.log_prefix}: API Request for {logger_msg}. "
            f"Endpoint: {method} {url}"
        )
        try:
            for retry_count in range(MAX_RETRIES):
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
                self.logger.debug(
                    f"{self.log_prefix}: Received API response for "
                    f"{logger_msg}. Status Code={response.status_code}."
                )
                if response.status_code == 401 and regenerate_auth_token:
                    raise HPECentralUnauthorizedException(
                        "Access token is invalid or expired."
                    )
                if (
                    response.status_code == 429 or 500 <= response.status_code < 600
                ) and not is_validation:
                    error_msg = (
                        f"Received exit code {response.status_code} while {logger_msg}."
                    )
                    self.logger.error(
                        message=(
                            f"{self.log_prefix}: {error_msg} "
                            f"Retrying after {DEFAULT_WAIT_TIME} seconds."
                            f"Retries remaining: {MAX_RETRIES - 1 - retry_count}"
                        ),
                        details=response.text,
                    )
                    time.sleep(DEFAULT_WAIT_TIME)
                    if retry_count == MAX_RETRIES - 1:
                        self.logger.error(
                            message=(
                                f"{self.log_prefix}: Max retries exceeded "
                                f"while {logger_msg}."
                            ),
                            details=response.text,
                        )
                        raise HPECentralPluginException(error_msg)
                    continue
                if is_handle_error_required:
                    self.throttle_api_call_rate(response.headers)
                    return (
                        self.handle_error(
                            logger_msg=logger_msg,
                            response=response,
                            is_validation=is_validation,
                        ),
                        response.headers,
                    )
        except HPECentralUnauthorizedException:
            raise
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
            raise HPECentralPluginException(err_msg)
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
            raise HPECentralPluginException(err_msg)
        except requests.HTTPError as err:
            err_msg = f"HTTP Error occurred while {logger_msg}."
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {err}",
                details=str(traceback.format_exc()),
            )
            raise HPECentralPluginException(err_msg)
        except HPECentralPluginException as exp:
            raise HPECentralPluginException(exp)
        except Exception as exp:
            err_msg = f"Unexpected error occurred while {logger_msg}."
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {exp}",
                details=str(traceback.format_exc()),
            )
            raise HPECentralPluginException(err_msg)

    def handle_error(
        self,
        logger_msg: str,
        response: requests.Response,
        is_validation: bool,
    ) -> Union[Dict, None]:
        """
        Handle the different HTTP response code.

        Args:
            logger_msg (str): logger message.
            response (requests.Response): Response object returned from API call.
            is_validation (bool): API call from validation method or not

        Returns:
            dict: Returns the dictionary of response JSON when the response code is 200.
        Raises:
            HPECentralPluginException: When the response code is not 200, 201 or 204.
        """
        status_code = response.status_code
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
                    "Received exit code 400, Bad Request, "
                    "Verify the API Base URL, Username, Password,"
                    " Client ID, Client Secret and Customer ID"
                    " provided in the configuration parameters."
                ),
                401: (
                    "Received exit code 401, Unauthorized, "
                    "Verify Username, Password, Client ID,"
                    " Client Secret and Customer ID provided in "
                    "the configuration parameters."
                ),
                403: (
                    "Received exit code 403, Forbidden, "
                    "Verify permission for Username provided in "
                    "the configuration parameters."
                ),
                404: (
                    "Received exit code 404, Resource not found, "
                    "Verify the API Base URL provided in "
                    "the configuration parameters."
                ),
            }

        if status_code in [200, 201]:
            return self.parse_response(
                response=response, logger_msg=logger_msg, is_validation=is_validation
            )
        elif status_code == 204:
            return {}
        elif status_code in error_dict:
            err_msg = error_dict[status_code]
            if is_validation:
                log_err_msg = validation_msg + err_msg
                self.logger.error(
                    message=f"{self.log_prefix}: {log_err_msg}",
                    details=f"API response: {response.text}",
                )
                raise HPECentralPluginException(err_msg)
            else:
                err_msg = err_msg + " while " + logger_msg + "."
                if status_code == 401:
                    err_msg = (
                        f"{err_msg} Check Client ID and Client Secret provided"
                        " in configuration parameters is expired or not."
                    )
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg}",
                    details=f"API response: {response.text}",
                )
                raise HPECentralPluginException(err_msg)
        elif status_code == 429:
            err_msg = "Received exit code 429, API rate limit exceeded"
            error_msg = err_msg + ". Please retry after 30 minutes."
            self.logger.error(
                message=(
                    f"{self.log_prefix}: {err_msg} while {logger_msg}."
                    f" Please retry after 30 minutes."
                ),
                details=f"API response: {response.text}",
            )
            raise HPECentralPluginException(error_msg)
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
                details=f"API response: {response.text}",
            )
            raise HPECentralPluginException(err_msg)

    def parse_response(
        self, response: requests.Response, logger_msg: str, is_validation: bool
    ) -> Dict:
        """Parse Response will return JSON from response object.

        Args:
            response (response): Response object.
            logger_msg (str): Logger message
            is_validation: (bool): Check for validation

        Returns:
            Tuple[Dict, CaseInsensitiveDict[str]]: A tuple containing the response JSON as a dictionary
            and the response headers.
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
                    "Verify API Base URL provided in the "
                    "configuration parameters. Check logs for more details."
                )
            raise HPECentralPluginException(err_msg)
        except Exception as exp:
            err_msg = (
                "Unexpected error occurred while parsing "
                f"json response while {logger_msg}. Error: {exp}"
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=f"API response: {response.text}",
            )
            if is_validation:
                err_msg = (
                    "Unexpected validation error occurred, "
                    "Verify API Base URL provided in the "
                    "configuration parameters. Check logs for more details."
                )
            raise HPECentralPluginException(err_msg)

    def throttle_api_call_rate(self, headers: CaseInsensitiveDict[str]) -> None:
        """
        Throttles the API call rate to prevent hitting the per second rate limit.
        Looks for the "X-RateLimit-Remaining-second" header in the response and
        if it's 1, puts the plugin to sleep for 1 second before calling the API
        again.
        """
        if (
            headers.get("X-RateLimit-Remaining-second")
            and int(headers.get("X-RateLimit-Remaining-second")) == 1
        ):
            time.sleep(ONE)

    def get_auth_headers(self, access_token: str):
        return {
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json",
        }
