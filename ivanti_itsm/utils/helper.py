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

CTO Ivanti plugin helper module.
"""

import json
import time
from urllib.parse import urlparse
import requests
import traceback


from typing import Dict, Union


from netskope.common.utils import add_user_agent

from .constants import (
    DEFAULT_WAIT_TIME,
    MAX_API_CALLS,
    MODULE_NAME,
    PLATFORM_NAME,
)


class IvantiPluginException(Exception):
    """Ivanti plugin custom exception class."""

    pass


class IvantiPluginHelper(object):
    """IvantiPluginHelper Class.

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
        configuration: Dict,
    ):
        """IvantiPluginHelper initializer.

        Args:
            logger (logger object): Logger object.
            log_prefix (str): Log prefix.
            plugin_name (str): Plugin name.
            plugin_version (str): Plugin version.
            ssl_validation : SSL Validation Flag.
            proxy : Proxy Configuration.
            configuration (Dict): Configuration parameters dictionary.
        """
        self.logger = logger
        self.log_prefix = log_prefix
        self.plugin_name = plugin_name
        self.plugin_version = plugin_version
        self.verify = ssl_validation
        self.proxies = proxy
        self.configuration = configuration

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
        headers: Dict = {},
        json=None,
        is_handle_error_required=True,
        is_validation=False,
        regenerate_auth_token=True,
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


        Returns:
            Response|Response JSON: Returns response json if
            is_handle_error_required is True otherwise returns Response object.
        """
        try:
            headers = self._add_user_agent(headers)

            debug_log_msg = (
                f"{self.log_prefix} : API Request for {logger_msg}."
                f" Endpoint: {method} {url}"
            )
            if params:
                debug_log_msg += f", params: {params}"
            if data:
                debug_log_msg += f", data: {data}."

            self.logger.debug(debug_log_msg)
            for retry_counter in range(MAX_API_CALLS):
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
                    f"{self.log_prefix} : Received API Response for "
                    f"{logger_msg}. Status Code={response.status_code}."
                )

                if (
                    response.status_code == 429
                    or 500 <= response.status_code <= 600
                ) and not is_validation:
                    if retry_counter == MAX_API_CALLS - 1:
                        err_msg = (
                            f"Received exit code {response.status_code}, While"
                            f" {logger_msg}. Max retries for rate limit "
                            "handler exceeded hence returning status"
                            f" code {response.status_code}."
                        )
                        self.logger.error(
                            message=f"{self.log_prefix}: {err_msg}",
                            details=f"API response: {response.text}",
                        )
                        raise IvantiPluginException(err_msg)
                    self.logger.error(
                        message=(
                            "{}: Received exit code {}, While"
                            " {}. Retrying after {} "
                            "seconds. {} retries remaining.".format(
                                self.log_prefix,
                                response.status_code,
                                logger_msg,
                                DEFAULT_WAIT_TIME,
                                MAX_API_CALLS - 1 - retry_counter,
                            )
                        ),
                        details=f"API response: {response.text}",
                    )
                    time.sleep(DEFAULT_WAIT_TIME)
                elif response.status_code == 401 and regenerate_auth_token:
                    auth_params = self.get_auth_params(self.configuration)
                    if auth_params.get("auth_method") == "api_key_auth":
                        return (
                            self.handle_error(
                                response, logger_msg, is_validation
                            )
                            if is_handle_error_required
                            else response
                        )
                    else:
                        token = self.get_auth_token(auth_params)
                        headers = self.get_authorization_header(
                            auth_params.get("auth_method"),
                            token,
                            auth_params.get("tenant"),
                            headers=headers,
                        )
                        return self.api_helper(
                            url=url,
                            method=method,
                            params=params,
                            headers=headers,
                            json=json,
                            data=data,
                            is_handle_error_required=is_handle_error_required,
                            is_validation=is_validation,
                            logger_msg=logger_msg,
                            regenerate_auth_token=False,
                        )

                else:
                    return (
                        self.handle_error(response, logger_msg, is_validation)
                        if is_handle_error_required
                        else response
                    )

        except requests.exceptions.ProxyError as error:
            err_msg = (
                "Proxy error occurred. Verify the provided "
                "proxy configuration."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {error}",
                details=str(traceback.format_exc()),
            )
            raise IvantiPluginException(err_msg)
        except requests.exceptions.ConnectionError as error:
            err_msg = (
                f"Unable to establish connection with {PLATFORM_NAME}. Verify"
                " Ivanti Tenant URL provided in configuration parameters."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {error}",
                details=str(traceback.format_exc()),
            )
            raise IvantiPluginException(err_msg)
        except requests.HTTPError as err:
            err_msg = (
                "HTTP Error occurred. Verify Ivanti Tenant URL "
                "provided in configuration parameters."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {err}",
                details=str(traceback.format_exc()),
            )
            raise IvantiPluginException(err_msg)
        except IvantiPluginException:
            raise
        except Exception as exp:
            err_msg = (
                "Unexpected error occurred while requesting "
                f"to {PLATFORM_NAME}."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {str(exp)}",
                details=str(traceback.format_exc()),
            )
            raise IvantiPluginException(err_msg)

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
                    "Verify Ivanti Tenant URL provided in the "
                    "configuration parameters. Check logs for more details."
                )
            raise IvantiPluginException(err_msg)
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
                    "Verify Ivanti Tenant URL provided in the "
                    "configuration parameters. Check logs for more details."
                )
            raise IvantiPluginException(err_msg)

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
            400: "Received exit code 400, HTTP Client Error",
            403: "Received exit code 403, Forbidden",
            401: (
                "Received exit code 401, Unauthorized access, Invalid API"
                " Key/Session Key found in API call."
            ),
            404: "Received exit code 404, Resource not found",
        }
        if is_validation:
            error_dict = {
                400: (
                    "Received exit code 400, Bad Request, Verify Ivanti Tenant"
                    " URL, Username, Password, Ivanti User Role and Employee"
                    " Record ID provided in the configuration parameters."
                ),
                401: (
                    "Received exit code 401, Forbidden, Verify API Key "
                    "provided in the configuration parameters."
                ),
                403: (
                    "Received exit code 403, Unauthorized, Verify permissions"
                    " attached to User/API Key provided in the "
                    "configuration parameters."
                ),
                404: (
                    "Received exit code 404, Resource Not Found, "
                    "Verify Ivanti Tenant URL provided in the "
                    "configuration parameters."
                ),
            }

        if status_code in [200, 201]:
            return self.parse_response(
                response=resp, is_validation=is_validation
            )
        elif status_code == 204:
            err_msg = (
                f"Received exit code 204, No Content while {logger_msg}. "
                "Check if the platform has incidents or any fields "
                "were deleted in the Business Objects."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=f"API response: {resp.text}",
            )
            raise IvantiPluginException(err_msg)
        elif status_code in error_dict:
            err_msg = error_dict[status_code]
            if is_validation:
                err_msg = validation_msg + err_msg
            else:
                err_msg = err_msg + " while " + logger_msg + "."
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=f"API response: {resp.text}",
            )
            raise IvantiPluginException(err_msg)
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
            raise IvantiPluginException(err_msg)

    def extract_domain(self, url: str) -> str:
        """Extract domain from URL.

        Args:
            url (str): Tenant URL.

        Returns:
            str: Extracted domain from URL.
        """
        parsed_url = urlparse(url)
        domain = parsed_url.netloc
        return domain

    def get_auth_params(self, configuration: Dict) -> Dict:
        """Get auth parameters from configuration.

        Args:
            params (Dict): Parameters dictionary.

        Returns:
            Dict: Dictionary containing extracted params.
        """

        auth_method = (
            configuration.get("auth", {})
            .get("authentication_method", "")
            .strip()
        )
        employee_rec_id = (
            configuration.get("auth", {}).get("employee_rec_id", "").strip()
        )
        tenant = (
            configuration.get("auth", {})
            .get("tenant_url", "")
            .strip()
            .strip("/")
        )
        param_dict = {
            "tenant": tenant,
            "auth_method": auth_method,
            "employee_rec_id": employee_rec_id,
        }
        params = configuration.get("params", {})
        if auth_method == "basic_auth":
            param_dict.update(
                {
                    "username": params.get("username", "").strip(),
                    "password": params.get("password", ""),
                    "role": params.get("user_role").strip(),
                }
            )
        elif auth_method == "api_key_auth":
            param_dict.update({"api_key": params.get("api_key", "")})
        return param_dict

    def get_authorization_header(
        self, auth_method: str, token: str, tenant_url: str, headers: Dict
    ) -> Dict:
        """Get authorization headers.

        Args:
            auth_method (str): Authorization method.
            token (str): Auth token.
            tenant_url (str): Tenant URL.
            headers (Dict): Headers dictionary.

        Returns:
            Dict: Headers with auth token.
        """
        tenant = self.extract_domain(tenant_url)
        if auth_method == "basic_auth":
            if tenant in token:
                headers.update({"Authorization": token})
                return headers
            else:
                headers.update({"Authorization": f"Bearer {token}"})
                return headers
        elif auth_method == "api_key_auth":
            headers.update({"Authorization": f"rest_api_key={token}"})
            return headers
        else:
            err_msg = (
                "Invalid Authentication Method provided in the "
                "configuration parameters. Allowed values are Basic "
                "Authentication and API Key Authentication."
            )
            self.logger.error(err_msg)
            raise IvantiPluginException(err_msg)

    def get_auth_token(
        self, auth_params: Dict, is_validation: bool = False
    ) -> str:
        """Get auth token from Ivanti server.

        Args:
            auth_params (Dict): Authorization parameters.
            is_validation (bool): Is request coming from validate method?

        Returns:
            str: Auth token.
        """
        auth_method = auth_params.get("auth_method")
        tenant_url = auth_params.get("tenant")
        if auth_method == "api_key_auth":
            return auth_params.get("api_key")
        else:
            endpoint = f"{tenant_url}/api/rest/authentication/login"
            payload = {
                "tenant": self.extract_domain(tenant_url),
                "username": auth_params.get("username"),
                "password": auth_params.get("password"),
                "role": auth_params.get("role"),
            }
            logger_msg = f"getting auth token from {PLATFORM_NAME}"
            try:
                auth_token = self.api_helper(
                    method="POST",
                    url=endpoint,
                    headers=self.get_headers(),
                    json=payload,
                    logger_msg=logger_msg,
                    is_validation=is_validation,
                )
                return str(auth_token)

            except IvantiPluginException:
                raise
            except Exception as exp:
                err_msg = (
                    "Unexpected error occurred while fetching Session "
                    "key/Bearer token."
                )
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg}. Error: {exp}",
                    details=str(traceback.format_exc()),
                )
                raise IvantiPluginException(err_msg)

    def get_headers(self) -> Dict:
        """Get basic request headers.

        Returns:
            Dict: Headers dictionary.
        """
        return {
            "Accept": "application/json",
            "Content-Type": "application/json",
        }
