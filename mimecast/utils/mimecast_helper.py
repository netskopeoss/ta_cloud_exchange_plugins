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

CTE Mimecast  plugin helper module.
"""

import json
import requests
import time
import traceback
from typing import Dict, Union

from netskope.common.utils import add_user_agent

from .mimecast_constants import (
    DEFAULT_WAIT_TIME,
    GET_BEARER_TOKEN_ENDPOINT,
    MAX_API_CALLS,
    PLUGIN_NAME,
    MODULE_NAME,
    BASE_URL,
    RETRACTION
)


class MimecastPluginException(Exception):
    """Mimecast plugin custom exception class."""

    pass


class QuotaNotAvailableException(Exception):
    """Mimecast plugin custom exception class."""

    pass


class MimecastPluginHelper(object):
    """MimecastPluginHelper class.

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
        """Mimecast Plugin Helper initializer.

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
        configuration=None,
        is_retraction: bool = False,
        is_handle_error_required=True,
        is_validation=False,
        regenerate_auth_token=True,
    ):
        """API Helper perform API request to ThirdParty platform \
        and captures all the possible errors for requests.

        Args:
            logger_msg (str): Logger message.
            url (str): API Endpoint.
            method (str): Method for the endpoint.
            params (Dict, optional): Request parameters dictionary.
            Defaults to None.
            data (Any,optional): Data to be sent to API. Defaults to None.
            files (Any, optional): Files to be sent to API. Defaults to None.
            headers (Dict, optional): Headers for the request. Defaults to {}.
            json (optional): Json payload for request. Defaults to None.
            verify (bool, optional): Verify SSL. Defaults to True.
            proxies (Dict, optional): Proxies. Defaults to None.
            configuration (Any, optional): Configuration. Defaults to None.
            is_retraction (bool, optional): Is this called from the retraction.
            is_handle_error_required (bool, optional): Does the API helper
            should handle the status codes. Defaults to True.
            is_validation (bool, optional): Does this request coming from
            validate method?. Defaults to False.
            is_handle_error_required (bool, optional): Is handling status
            code is required?. Defaults to True.

        Returns:
            dict: Response dictionary.
        """

        try:
            if is_retraction and RETRACTION not in self.log_prefix:
                self.log_prefix = self.log_prefix + f" [{RETRACTION}]"
            headers = self._add_user_agent(headers)
            base_url = configuration.get("base_url", BASE_URL).strip().strip("/")
            url = base_url + url
            debug_log_msg = (
                f"{self.log_prefix}: API Request for {logger_msg}. "
                f"Endpoint: {method} {url}"
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
                    err_msg = (
                        f"Received exit code {status_code} while"
                        f" {logger_msg}. Hence regenerating access token."
                    )
                    self.logger.error(
                        message=f"{self.log_prefix}: {err_msg}",
                        details=f"API response: {str(response.text)}",
                    )
                    auth_header = self._get_auth_headers(configuration)
                    headers.update(auth_header)
                    return self.api_helper(
                        url=url,
                        method=method,
                        params=params,
                        headers=headers,
                        json=json,
                        files=files,
                        data=data,
                        proxies=proxies,
                        verify=verify,
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
                            f"Received exit code {status_code}, "
                            f"API rate limit exceeded while {logger_msg}. "
                            "Max retries for rate limit handler exceeded "
                            f"hence returning status code {status_code}."
                        )
                        self.logger.error(
                            message=f"{self.log_prefix}: {err_msg}",
                            details=api_err_msg,
                        )
                        raise MimecastPluginException(err_msg)
                    retry_after = int(
                        response.headers.get(
                            "X-Rate-Limit-Reset", DEFAULT_WAIT_TIME
                        )
                    )
                    retry_after = retry_after // 1000
                    if retry_after > 300:
                        err_msg = (
                            "'X-Rate-Limit-Reset' value received from "
                            f"response headers while {logger_msg} is "
                            "greater than 5 minutes hence returning "
                            f"status code {status_code}."
                        )
                        self.logger.error(f"{self.log_prefix}: {err_msg}")
                        raise MimecastPluginException(err_msg)
                    if status_code == 429:
                        log_err_msg = "API rate limit exceeded"
                    else:
                        log_err_msg = "HTTP server error occurred"
                    self.logger.error(
                        message=(
                            f"{self.log_prefix}: Received exit code "
                            f"{status_code}, "
                            f"{log_err_msg} while {logger_msg}. "
                            f"Retrying after {retry_after} seconds. "
                            f"{MAX_API_CALLS - 1 - retry_counter} "
                            "retries remaining."
                        ),
                        details=api_err_msg,
                    )
                    time.sleep(retry_after)
                else:
                    return (
                        self.handle_error(response, logger_msg, is_validation)
                        if is_handle_error_required
                        else response
                    )
        except requests.exceptions.ReadTimeout as error:
            err_msg = (
                f"Read Timeout error occurred while {logger_msg}."
            )
            if is_validation:
                err_msg = (
                    "Read Timeout error occurred. "
                    "Verify the provided "
                    "configuration parameters."
                )

            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {error}",
                details=str(traceback.format_exc()),
            )
            raise MimecastPluginException(err_msg)
        except requests.exceptions.ProxyError as error:
            err_msg = (
                f"Proxy error occurred while {logger_msg}. "
                "Verify the provided proxy configuration."
            )
            if is_validation:
                err_msg = (
                    "Proxy error occurred. Verify "
                    "the proxy configuration provided."
                )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {error}",
                details=str(traceback.format_exc()),
            )
            raise MimecastPluginException(err_msg)
        except requests.exceptions.ConnectionError as error:
            err_msg = (
                f"Unable to establish connection with {PLUGIN_NAME} "
                f"platform while {logger_msg}. "
                f"Proxy server or {PLUGIN_NAME} "
                "server is not reachable."
            )
            if is_validation:
                err_msg = (
                    f"Unable to establish connection with {PLUGIN_NAME} "
                    f"platform. Proxy server or {PLUGIN_NAME} "
                    "server is not reachable."
                )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {error}",
                details=str(traceback.format_exc()),
            )
            raise MimecastPluginException(err_msg)
        except requests.HTTPError as err:
            err_msg = f"HTTP Error occurred while {logger_msg}."
            if is_validation:
                err_msg = (
                    "HTTP error occurred. Verify "
                    "configuration parameters provided."
                )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {err}",
                details=str(traceback.format_exc()),
            )
            raise MimecastPluginException(err_msg)
        except MimecastPluginException as exp:
            raise MimecastPluginException(exp)
        except Exception as exp:
            err_msg = f"Unexpected error occurred while {logger_msg}."
            if is_validation:
                err_msg = (
                    "Unexpected error while performing "
                    f"API call to {PLUGIN_NAME}."
                )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {exp}",
                details=str(traceback.format_exc()),
            )
            raise MimecastPluginException(err_msg)

    def _get_auth_headers(
        self,
        proxy,
        verify,
        configuration: dict,
        is_validation=False,
        is_retraction: bool = False,
    ) -> str:
        """Generate the Mimecast authentication headers.

        Args:
            proxy (str): The proxy server address.
            verify (bool): Verify the SSL certificate of the server.
            configuration (dict): The plugin configuration.
            is_validation (bool, optional): Is this called from the validation.
                Defaults to False.
            is_retraction (bool, optional): Is this called from the retraction.
                Defaults to False.

        Returns:
            str: The authentication headers.
        """
        try:
            client_id, client_secret = self._get_auth_params(configuration)

            data = {
                "grant_type": "client_credentials",
                "client_id": client_id,
                "client_secret": client_secret,
            }
            headers = {
                'Content-Type': 'application/x-www-form-urlencoded'
            }
            logger_msg = f"generating authentication token from {PLUGIN_NAME}"

            response = self.api_helper(
                url=GET_BEARER_TOKEN_ENDPOINT,
                method="POST",
                data=data,
                proxies=proxy,
                verify=verify,
                is_validation=is_validation,
                configuration=configuration,
                regenerate_auth_token=False,
                logger_msg=logger_msg,
                is_retraction=is_retraction
            )
            bearer_token = response.get("access_token", "")

            if not bearer_token:
                err_msg = (
                    "Bearer Token not found. "
                    "Verify Client ID and "
                    "Client Secret provided in the "
                    "configuration parameters. "
                )
                if is_validation:
                    err_msg = (
                        "Validation error occurred. "
                        "Verify Client ID and "
                        "Client Secret provided in the "
                        "configuration parameters."
                    )
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg}",
                    details=f"API Response: {str(response)}",
                )
                raise MimecastPluginException(err_msg)
            headers = {
                "Authorization": f"Bearer {bearer_token}",
            }
            return headers
        except MimecastPluginException:
            raise
        except Exception as exp:
            err_msg = (
                f"Unexpected error occurred while {logger_msg}."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {exp}",
                details=str(traceback.format_exc()),
            )
            raise MimecastPluginException(err_msg)

    def _get_auth_params(self, configuration: Dict) -> Dict:
        """Get auth params.

        Args:
            configuration (Dict): Configuration parameter dictionary.

        Returns:
            Tuple: Tuple containing Client ID and Client Secret.
        """
        return (
            configuration.get("client_id", "").strip(),
            configuration.get("client_secret")
        )

    def parse_response(
        self,
        response: requests.models.Response,
        logger_msg,
        is_validation: bool = False
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
                "Invalid JSON response received "
                f"from API while {logger_msg}. Error: {str(err)}"
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=f"API response: {response.text}",
            )
            if is_validation:
                err_msg = (
                    "Verify Client ID and Client Secret provided in the "
                    "configuration parameters. Check logs for more details."
                )
            raise MimecastPluginException(err_msg)
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
                    "Verify Client ID and Client Secret provided in the "
                    "configuration parameters. Check logs for more details."
                )
            raise MimecastPluginException(err_msg)

    def handle_error(
        self,
        resp: requests.models.Response,
        logger_msg: str,
        is_validation: bool = False,
    ) -> Dict:
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
            MimecastPluginException: When the response code is not 200.
        """
        status_code = resp.status_code
        validation_msg = "Validation error occurred, "
        if status_code in [200, 201, 202]:
            # Hash API is giving csv file in response
            # Hence returning response object as is.
            if "pulling file hash" in logger_msg:
                return resp
            else:
                return self.parse_response(resp, logger_msg, is_validation)

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
                    "Client ID and Client Secret provided in the "
                    "configuration parameters."
                ),
                401: (
                    "Received exit code 401, Unauthorized, Verify "
                    "Client ID and Client Secret provided in the "
                    "configuration parameters."
                ),
                403: (
                    "Received exit code 403, Forbidden, Verify permissions "
                    "provided to Client ID and Client Secret."
                ),
                404: (
                    "Received exit code 404, Resource not found, Verify "
                    "provided in the configuration parameters."
                ),
            }
        api_error_message = ""
        try:
            json_response = self.parse_response(resp, logger_msg)
            fail_list = json_response.get("fail", [])
            if "fetching file hash" in logger_msg:
                if fail_list:
                    api_error_message = fail_list.get('message', '')
            else:
                error_list = fail_list[0].get("errors", [])
                if fail_list and error_list:
                    api_error_message = error_list[0].get("message", "")
        except Exception:
            api_error_message = resp.text
        if status_code in error_dict:
            err_msg = error_dict[status_code]
            if is_validation:
                log_err_msg = validation_msg + err_msg
                self.logger.error(
                    message=f"{self.log_prefix}: {log_err_msg}",
                    details=f"API response: {resp.text}",
                )
                raise MimecastPluginException(err_msg)
            else:
                err_msg = err_msg + " while " + logger_msg + "."
                if status_code == 401:
                    err_msg = (
                        f"{err_msg} Check API Token provided in configuration "
                        "parameters is expired or not."
                    )
                if api_error_message:
                    err_msg += f" Error Message: {api_error_message}."
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg}",
                    details=f"API response: {resp.text}",
                )
                raise MimecastPluginException(err_msg)
        else:
            err = (
                "HTTP Server Error"
                if (status_code >= 500 and status_code <= 600)
                else "HTTP Error"
            )
            err_msg = (
                f"{self.log_prefix}: Received status code {status_code}, "
                f"{err} while {logger_msg}."
            )
            self.logger.error(
                message=err_msg,
                details=str(resp.text),
            )
            raise MimecastPluginException(err_msg)
