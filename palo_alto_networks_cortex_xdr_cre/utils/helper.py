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

CTE Palo Alto Networks Cortex XDR plugin helper module.
"""

import hashlib
import json
import secrets
import string
import time
import traceback
from datetime import datetime, timezone
from typing import Dict, Literal, Tuple, Union

import requests
from netskope.common.utils import add_user_agent

from .constants import (
    ADVANCED,
    DEFAULT_WAIT_TIME,
    MAX_API_CALLS,
    MODULE_NAME,
    STANDARD,
    ONE,
    PLATFORM_NAME,
)


class PaloAltoNetworksCortexXDRPluginException(Exception):
    """Palo Alto Networks Cortex XDR plugin custom exception class."""

    pass


class PaloAltoNetworksCortexXDRPluginHelper(object):
    """Palo Alto Networks Cortex XDR Plugin Helper class.

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
        """PaloAltoCortexXDRPluginHelper initializer.

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
        self.api_call_count = 0

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
        params=None,
        data: dict = None,
        headers: dict = None,
        verify=True,
        proxies=None,
        json: dict = None,
        is_validation: bool = False,
        is_handle_error_required=True,
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
        headers = self._add_user_agent(headers)
        try:
            self.logger.debug(
                f"{self.log_prefix}: API Endpoint for {logger_msg}. "
                f'"{method} {url}"'
            )
            for retry_counter in range(MAX_API_CALLS):
                self.throttle_api_calls()
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
                    f"{self.log_prefix}: Received API Response for"
                    f" {logger_msg}. Status Code={status_code}."
                )
                if not is_validation and (
                    status_code == 429 or 500 <= status_code <= 600
                ):
                    api_err_msg = str(response.text)
                    if "can't create group action id for" in api_err_msg:
                        api_err_msg_lower = api_err_msg.lower()
                        if "unisolate" in api_err_msg_lower:
                            err_msg = (
                                "Failed to un-isolate endpoint(s). The"
                                " endpoint(s) might already be in an"
                                " un-isolated state."
                            )
                        elif "isolate" in api_err_msg_lower:
                            err_msg = (
                                "Failed to isolate endpoint(s). The"
                                " endpoint(s) might already be in an"
                                " isolated state."
                            )
                        elif "abort_scan" in api_err_msg_lower:
                            err_msg = (
                                "Failed to cancel scan on endpoint(s). The"
                                " endpoint(s) might not have a scan running."
                            )
                        elif "scan" in api_err_msg_lower:
                            err_msg = (
                                "Failed to run the scan on endpoint(s). The"
                                " endpoint(s) might already have a"
                                " scan running."
                            )
                        else:
                            err_msg = (
                                "Failed to perform action on endpoint"
                                f" with error: {api_err_msg}"
                            )
                        self.logger.error(
                            message=f"{self.log_prefix}: {err_msg}",
                            details=f"API response: {response.text}",
                        )
                        raise PaloAltoNetworksCortexXDRPluginException(err_msg)
                    no_retry_err_msg = (
                        "Received exit code {status_code}, {error_reason}"
                        " while {logger_msg}. Max retries for rate limit "
                        "handler exceeded hence returning status "
                        "code {status_code}."
                    )
                    retry_err_msg = (
                        "Received exit code {status_code}, {error_reason}"
                        " while {logger_msg}. Retrying after {wait_time} "
                        "seconds. {retry_remaining} retries remaining."
                    )
                    if status_code == 429:
                        no_retry_err_msg = no_retry_err_msg.format(
                            status_code=status_code,
                            error_reason="API Rate Limit exceeded",
                            logger_msg=logger_msg,
                        )
                        retry_err_msg = retry_err_msg.format(
                            status_code=status_code,
                            error_reason="API Rate Limit exceeded",
                            logger_msg=logger_msg,
                            wait_time=DEFAULT_WAIT_TIME,
                            retry_remaining=(MAX_API_CALLS - 1 - retry_counter),
                        )
                    elif 500 <= status_code <= 600:
                        no_retry_err_msg = no_retry_err_msg.format(
                            status_code=status_code,
                            error_reason="HTTP server error occurred",
                            logger_msg=logger_msg,
                        )
                        retry_err_msg = retry_err_msg.format(
                            status_code=status_code,
                            error_reason="HTTP server error occurred",
                            logger_msg=logger_msg,
                            wait_time=DEFAULT_WAIT_TIME,
                            retry_remaining=(MAX_API_CALLS - 1 - retry_counter),
                        )
                    if retry_counter == MAX_API_CALLS - 1:
                        self.logger.error(
                            message=f"{self.log_prefix}: {no_retry_err_msg}",
                            details=api_err_msg,
                        )
                        raise PaloAltoNetworksCortexXDRPluginException(no_retry_err_msg)
                    self.logger.error(
                        message=f"{self.log_prefix}: {retry_err_msg}",
                        details=api_err_msg,
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
                f"Proxy error occurred while {logger_msg}. Verify the "
                "proxy configuration provided."
            )
            if is_validation:
                err_msg = (
                    "Proxy error occurred. Verify the proxy"
                    " configuration provided."
                )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {error}",
                details=str(traceback.format_exc()),
            )
            raise PaloAltoNetworksCortexXDRPluginException(err_msg)
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
                details=str(traceback.format_exc()),
            )
            raise PaloAltoNetworksCortexXDRPluginException(err_msg)
        except requests.exceptions.ReadTimeout as error:
            err_msg = f"Read Timeout error occurred while {logger_msg}."
            if is_validation:
                err_msg = (
                    "Read Timeout error occurred. "
                    "Verify the 'API Base URL' provided in the "
                    "configuration parameters."
                )

            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {error}",
                details=traceback.format_exc(),
            )
            raise PaloAltoNetworksCortexXDRPluginException(err_msg)
        except requests.HTTPError as err:
            err_msg = f"HTTP error occurred while {logger_msg}."
            if is_validation:
                err_msg = (
                    "HTTP error occurred. Verify the configuration"
                    " parameters provided."
                )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {err}",
                details=str(traceback.format_exc()),
            )
            raise PaloAltoNetworksCortexXDRPluginException(err_msg)
        except PaloAltoNetworksCortexXDRPluginException:
            raise
        except Exception as exp:
            err_msg = f"Unexpected error occurred while {logger_msg}."
            if is_validation:
                err_msg = (
                    f"Unexpected error while performing API call to"
                    f" {PLATFORM_NAME}."
                )
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg} Error: {exp}",
                    details=traceback.format_exc(),
                )
                raise PaloAltoNetworksCortexXDRPluginException(err_msg)
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {exp}",
                details=traceback.format_exc(),
            )
            raise PaloAltoNetworksCortexXDRPluginException(err_msg)

    def parse_response(
        self,
        response: requests.models.Response,
        logger_msg: str,
        is_validation: bool,
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
                    "configuration parameters. Check logs"
                    " for more details."
                )
            raise PaloAltoNetworksCortexXDRPluginException(err_msg)
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
                    "configuration parameters. Check logs"
                    " for more details."
                )
            raise PaloAltoNetworksCortexXDRPluginException(err_msg)

    def handle_error(
        self,
        resp: requests.models.Response,
        logger_msg: str,
        is_validation: bool,
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
            PaloAltoCortexXDRException: When the response code is
            not in 200 range.
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
                    "Received exit code 400, Bad Request, "
                    "Verify the API Base URL provided in "
                    "the configuration parameters."
                ),
                401: (
                    "Received exit code 401, Unauthorized, "
                    "Verify API Key and API Key ID provided in "
                    "the configuration parameters."
                ),
                403: (
                    "Received exit code 403, Forbidden, "
                    "Verify permission for API Key provided in "
                    "the configuration parameters."
                ),
                404: (
                    "Received exit code 404, Resource not found, "
                    "Verify the API Base URL provided in "
                    "the configuration parameters."
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
        elif status_code in error_dict:
            err_msg = error_dict[status_code]
            if is_validation:
                log_err_msg = validation_msg + err_msg
                self.logger.error(
                    message=f"{self.log_prefix}: {log_err_msg}",
                    details=f"API response: {resp.text}",
                )
                raise PaloAltoNetworksCortexXDRPluginException(err_msg)
            else:
                err_msg = err_msg + " while " + logger_msg + "."
                if status_code == 401:
                    err_msg = (
                        f"{err_msg} Check API Key provided in configuration "
                        "parameters is expired or not."
                    )
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg}",
                    details=f"API response: {resp.text}",
                )
                raise PaloAltoNetworksCortexXDRPluginException(err_msg)
        elif status_code >= 400 and status_code < 500:
            err_msg = "HTTP Client Error"
            if is_validation:
                log_err_msg = validation_msg + err_msg
                self.logger.error(
                    message=f"{self.log_prefix}: {log_err_msg}",
                    details=f"API response: {resp.text}",
                )
                raise PaloAltoNetworksCortexXDRPluginException(err_msg)
            else:
                err_msg = err_msg + " while " + logger_msg + "."
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg}",
                    details=f"API response: {resp.text}",
                )
                raise PaloAltoNetworksCortexXDRPluginException(err_msg)
        elif status_code >= 500 and status_code < 600:
            err_msg = "HTTP Server Error"
            if is_validation:
                log_err_msg = validation_msg + err_msg
                self.logger.error(
                    message=f"{self.log_prefix}: {log_err_msg}",
                    details=f"API response: {resp.text}",
                )
                raise PaloAltoNetworksCortexXDRPluginException(err_msg)
            else:
                err_msg = err_msg + " while " + logger_msg + "."
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg}",
                    details=f"API response: {resp.text}",
                )
        else:
            err_msg = "HTTP Error"
            if is_validation:
                log_err_msg = validation_msg + err_msg
                self.logger.error(
                    message=f"{self.log_prefix}: {log_err_msg}",
                    details=f"API response: {resp.text}",
                )
                raise PaloAltoNetworksCortexXDRPluginException(err_msg)
            else:
                err_msg = err_msg + " while " + logger_msg + "."
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg}",
                    details=f"API response: {resp.text}",
                )
            raise PaloAltoNetworksCortexXDRPluginException(err_msg)

    def get_configuration_parameters(
        self, configuration: Dict
    ) -> Tuple[str, str, str, str]:
        """
        This function retrieves the configuration parameters from the
        configuration dictionary.

        Args:
        - configuration (Dict): The dictionary containing the configuration
            parameters.

        Returns:
        - A tuple containing the configuration parameters in the following
            order: base_url, api_key, api_key_id, auth_method.
        """
        return (
            configuration.get("base_url").strip().strip("/"),
            configuration.get("api_key"),
            configuration.get("api_key_id"),
            configuration.get("auth_method", "").lower(),
        )

    def get_auth_headers(
        self,
        api_key_id: str,
        api_key: str,
        auth_method: Literal["standard", "advanced"],
    ) -> Dict[str, str]:
        if auth_method == STANDARD:
            return {
                "Content-Type": "application/json",
                "x-xdr-auth-id": str(api_key_id),
                "Authorization": api_key,
            }
        elif auth_method == ADVANCED:
            nonce = "".join(
                [
                    secrets.choice(string.ascii_letters + string.digits)
                    for _ in range(64)
                ]
            )
            timestamp = int(datetime.now(timezone.utc).timestamp()) * 1000
            auth_key = "%s%s%s" % (api_key, nonce, timestamp)
            auth_key = auth_key.encode("utf-8")
            api_key_hash = hashlib.sha256(auth_key).hexdigest()
            return {
                "x-xdr-timestamp": str(timestamp),
                "x-xdr-nonce": nonce,
                "x-xdr-auth-id": str(api_key_id),
                "Authorization": api_key_hash,
            }
        else:
            err_msg = f"Invalid authentication method: {auth_method}"
            self.logger.error(message=f"{self.log_prefix}: {err_msg}")
            raise PaloAltoNetworksCortexXDRPluginException(err_msg)

    def throttle_api_calls(self):
        """
        Throttles API calls to Cortex XDR by sleeping for 1 second after
        every 9th API call. This is to prevent hitting the rate limit of
        10 API calls per second.

        This method should be called before each API call.
        """
        if self.api_call_count == 9:
            self.logger.debug(
                message=(
                    f"{self.log_prefix}: Throttling API calls for"
                    " 1 second."
                ),
                details=(
                    "Palo Alto Networks Cortex XDR API allows 10 api calls"
                    " per second, hence throttling api calls for 1 second"
                    " after every 9 api calls."
                ),
            )
            time.sleep(ONE)
            self.api_call_count = 0
        self.api_call_count += 1
