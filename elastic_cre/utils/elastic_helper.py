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

CRE Elastic Plugin helper module.
"""

import json
import requests
import time
import traceback
from base64 import b64encode
from typing import Dict, Union

from netskope.common.utils import add_user_agent

from .elastic_constants import (
    DEFAULT_WAIT_TIME,
    MAX_API_CALLS,
    MODULE_NAME,
    PLATFORM_NAME
)


class ElasticPluginException(Exception):
    """Elastic plugin custom exception class."""

    pass


class ElasticPluginHelper(object):
    """ElasticPluginHelper class.

    Args:
        object (object): Object class.
    """

    def __init__(
        self, logger, log_prefix: str, plugin_name: str, plugin_version: str
    ):
        """Elastic Plugin Helper initializer.

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
        """Add User-Agent in the headers for Elastic requests.

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
        configuration: Dict = {},
        data=None,
        files=None,
        headers: Dict = {},
        json=None,
        verify=True,
        proxies=None,
        is_handle_error_required=True,
        is_validation=False,
        regenerate_auth_token=True,
    ):
        """API helper to perform API request on ThirdParty platform \
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
                if (
                    status_code == 401
                    and regenerate_auth_token
                    and not is_validation
                ):
                    (
                        base_url,
                        auth_method,
                        auth_creds,
                        _
                    ) = self.get_config_params(configuration=configuration)
                    headers = self.get_auth_token(
                        verify=verify,
                        proxy=proxies,
                        base_url=base_url,
                        auth_method=auth_method,
                        auth_creds=auth_creds,
                    )
                    headers.update(headers)
                    return self.api_helper(
                        url=url,
                        method=method,
                        params=params,
                        headers=headers,
                        json=json,
                        files=files,
                        data=data,
                        verify=verify,
                        proxies=proxies,
                        is_handle_error_required=is_handle_error_required,
                        is_validation=is_validation,
                        logger_msg=logger_msg,
                        regenerate_auth_token=False,
                    )

                elif (
                    status_code == 429
                    or 500 <= status_code <= 600
                ) and not is_validation:
                    api_err_msg = str(response.text)
                    if retry_counter == MAX_API_CALLS - 1:
                        err_msg = (
                            f"Received exit code {status_code}, API rate limit "
                            f"exceeded while {logger_msg}. Max retries for rate limit "
                            "handler exceeded hence returning status "
                            f"code {status_code}."
                        )
                        self.logger.error(
                            message=f"{self.log_prefix}: {err_msg}",
                            details=api_err_msg,
                        )
                        raise ElasticPluginException(err_msg)
                    if status_code == 429:
                        log_err_msg = "API rate limit exceeded"
                    else:
                        log_err_msg = "HTTP server error occurred"
                    self.logger.error(
                        message=(
                            f"{self.log_prefix}: Received exit code {status_code}, "
                            f"{log_err_msg} while {logger_msg}. "
                            f"Retrying after {DEFAULT_WAIT_TIME} seconds. "
                            f"{MAX_API_CALLS - 1 - retry_counter} retries remaining."
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
        except ElasticPluginException:
            raise
        except requests.exceptions.ReadTimeout as error:
            err_msg = (
                f"Read Timeout error occurred while {logger_msg}."
            )
            if is_validation:
                err_msg = "Read Timeout error occurred."

            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {error}",
                details=traceback.format_exc(),
            )
            raise ElasticPluginException(err_msg)
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
            raise ElasticPluginException(err_msg)
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
            raise ElasticPluginException(err_msg)
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
            raise ElasticPluginException(err_msg)
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
                raise ElasticPluginException(err_msg)
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {exp}",
                details=traceback.format_exc(),
            )

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
                    "Verify Base URL provided in the "
                    "configuration parameters. Check logs for more details."
                )
            raise ElasticPluginException(err_msg)
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
                    "Verify Base URL provided in the "
                    "configuration parameters. Check logs for more details."
                )
            raise ElasticPluginException(err_msg)

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
                    "Received exit code 400, Bad Request, "
                    "Verify the Base URL provided in "
                    "the configuration parameters."
                ),
                401: (
                    "Received exit code 401, Unauthorized, "
                    "Verify Username/Password or API Key "
                    "provided in the configuration parameters."
                ),
                403: (
                    "Received exit code 403, Forbidden, "
                    "Verify API Scope assigned to the user "
                    "or API Key provided in the configuration parameters."
                ),
                404: (
                    "Received exit code 404, Resource not found, "
                    "Verify the Base URL provided in "
                    "the configuration parameters."
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
        elif status_code in error_dict:
            err_msg = error_dict[status_code]
            if is_validation:
                log_err_msg = validation_msg + err_msg
                self.logger.error(
                    message=f"{self.log_prefix}: {log_err_msg}",
                    details=f"API response: {resp.text}",
                )
                raise ElasticPluginException(err_msg)
            else:
                err_msg = err_msg + " while " + logger_msg + "."
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg}",
                    details=f"API response: {resp.text}",
                )
                raise ElasticPluginException(err_msg)

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
            raise ElasticPluginException(err_msg)

    def get_auth_token(
        self,
        verify,
        proxy,
        auth_method: str,
        base_url: str,
        auth_creds: Dict,
        is_validation: bool = False,
    ) -> str:
        """Get auth token from Elastic platform.

        Args:
            verify (bool): SSL verification.
            proxy (str): Proxy URL.
            auth_method (str): Authentication method.
            base_url (str): Base URL for Elastic platform.
            auth_creds (Dict): Authentication credentials.
            is_validation (bool, optional): Is validation. Defaults to False.
        Returns:
            dict: Headers with auth token.
        """
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        if auth_method == "basic_auth":
            username = auth_creds.get("username", "").strip()
            password = auth_creds.get("password")
            headers["Authorization"] = self.basic_auth(username, password)
        elif auth_method == "api_key_auth":
            api_key = auth_creds.get("api_key")
            headers["Authorization"] = f"ApiKey {api_key}"
        else:
            err_msg = (
                f"Invalid authentication method found {auth_method}."
                " Supported authentication methods are "
                "Basic Authentication and API Key Authentication."
            )
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            raise ElasticPluginException(err_msg)

        api_endpoint = f"{base_url}/_security/oauth2/token"
        body = {
            "grant_type": "client_credentials",
        }
        logger_msg = f"getting auth token from {PLATFORM_NAME} platform"
        try:
            response = self.api_helper(
                url=api_endpoint,
                method="POST",
                json=body,
                headers=headers,
                verify=verify,
                proxies=proxy,
                logger_msg=logger_msg,
                is_validation=is_validation,
                is_handle_error_required=False,
                regenerate_auth_token=False,
            )
            if response.status_code in [200, 201]:
                resp_json = self.parse_response(response, logger_msg, is_validation)
                # Check if auth JSON is valid or not.
                return self.check_auth_json(resp_json)
            else:
                return self.handle_error(response, "getting auth token", is_validation)
        except ElasticPluginException as exp:
            err_msg = "Error occurred while fetching auth token."
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {exp}",
                details=str(traceback.format_exc()),
            )
            raise ElasticPluginException(exp)
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
                raise ElasticPluginException(err_msg)
            err_msg = "Unexpected error occurred while fetching auth token."
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {exp}",
                details=str(traceback.format_exc()),
            )
            raise ElasticPluginException(err_msg)

    def get_config_params(self, configuration: Dict) -> Dict:
        """Get Configuration params.

        Args:
            configuration (Dict): Configuration parameter dictionary.

        Returns:
            Tuple: Tuple containing Base URL, Authentication Method and
            Authentication Credentials.
        """
        return (
            configuration.get("base_url", "").strip().strip("/"),
            configuration.get("authentication_method", "").strip(),
            {
                "username": configuration.get("username", "").strip(),
                "password": configuration.get("password"),
            }
            if configuration.get("authentication_method", "").strip()
            == "basic_auth"
            else {"api_key": configuration.get("api_key")},
            configuration.get("days")
        )

    def check_auth_json(self, auth_json: Dict) -> str:
        """Check the validity of auth token.

        Args:
            auth_json (Dict): Auth Json.

        Returns:
            str: Access token if valid else raise exception.
        """
        auth_token = auth_json.get("access_token", "")
        if not auth_token:
            err_msg = (
                f"Unable to get access token or OAuth2 token from {PLATFORM_NAME}."
                " Verify the provided configuration parameters."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=str(auth_json),
            )
            raise ElasticPluginException(err_msg)

        return {
            "Authorization": f"Bearer {auth_token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

    def basic_auth(self, username, password):
        """Generate Basic Auth token.

        Args:
            username (str): Username.
            password (str): Password.

        Returns:
            str: Basic Auth token.
        """
        try:
            token = b64encode(f"{username}:{password}".encode("utf-8")).decode(
                "ascii"
            )
            return f"Basic {token}"
        except Exception as exp:
            err_msg = "Error occurred while generating basic auth token."
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {exp}",
                details=str(traceback.format_exc()),
            )
            raise ElasticPluginException(err_msg)
