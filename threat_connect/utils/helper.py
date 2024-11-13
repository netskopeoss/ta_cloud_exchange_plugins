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

CTE ThreatConnect plugin helper module.
"""

import base64
import hashlib
import hmac
import json
import time
import traceback
from typing import Dict, Tuple, Union

import requests
from netskope.common.utils import add_user_agent
from requests.exceptions import ReadTimeout

from .constants import (
    DEFAULT_WAIT_TIME,
    MAX_RETRY,
    MODULE_NAME,
    PLATFORM_NAME,
    PLUGIN_NAME,
)


class ThreatConnectException(Exception):
    """ThreatConnect plugin custom exception class."""

    pass


class ThreatConnectPluginHelper(object):
    """ThreatConnectPluginHelper Class.

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
        """ThreatConnectPluginHelper initializer.
        Args:
            logger (logger object): Logger object.
            log_prefix (str): Log prefix.
            plugin_name (str): Plugin name.
            plugin_version (str): Plugin version.
        """
        self.logger = logger
        self.log_prefix = log_prefix
        self.plugin_name = plugin_name
        self.plugin_version = plugin_version
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
        url,
        method,
        params=None,
        data=None,
        headers=None,
        json=None,
        is_handle_error_required=True,
        is_validation=False,
        verify: bool = True,
        regenerate_auth_token: bool = True,
        proxies: Dict = {},
    ):
        """API Helper perform API request to ThirdParty platform
        and captures all the possible errors for requests.

        Args:
            request (request): Requests object.
            code is required?. Defaults to True.
            is_validation : API call from validation method or not

        Returns:
            dict: Response dictionary.
        """
        try:
            headers = self._add_user_agent(headers)

            log_header = {
                key: value
                for key, value in headers.items()
                if key
                not in {
                    "Authorization",
                }
            }
            debug_log_msg = (
                f"{self.log_prefix}: API Request for {logger_msg}."
                f" URL={url}, headers={log_header}"
            )
            if params:
                debug_log_msg += f", params={params}"
            if data:
                debug_log_msg += f", data={data}."

            self.logger.debug(debug_log_msg)
            for retry_counter in range(MAX_RETRY):
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
                    f"{self.log_prefix}: Received API Response while "
                    f"{logger_msg}. Method={method}, "
                    f"Status Code={response.status_code}."
                )
                if (
                    response.status_code == 401
                    and regenerate_auth_token
                    and not is_validation
                ):
                    self.logger.debug(
                        f"{self.log_prefix}: Received exit code 401, "
                        f"Unauthorized access. Regenerating API Token."
                    )
                    (base_url, access_id, secret_key) = self.get_credentials(
                        self.configuration
                    )
                    auth_header = self.get_headers_for_auth(
                        api_path=url.replace(base_url, ""),
                        access_id=access_id,
                        secret_key=secret_key,
                        request_type=method,
                    )
                    headers.update(auth_header)
                    return self.api_helper(
                        logger_msg=logger_msg,
                        url=url,
                        method=method,
                        params=params,
                        headers=headers,
                        json=json,
                        is_handle_error_required=is_handle_error_required,
                        is_validation=is_validation,
                        verify=verify,
                        regenerate_auth_token=False,
                        proxies=proxies,
                    )

                if (
                    response.status_code == 429
                    or 500 <= response.status_code <= 600
                ) and not is_validation:
                    if retry_counter == MAX_RETRY - 1:
                        err_msg = (
                            "Received exit code {}, HTTP Server Error while"
                            " {}. Max retries for rate limit "
                            "handler exceeded hence returning status"
                            " code {}.".format(
                                response.status_code,
                                logger_msg,
                                response.status_code,
                            )
                        )
                        self.logger.error(
                            message=f"{self.log_prefix}: {err_msg}",
                            details=f"API Response: {response.text}",
                        )
                        raise ThreatConnectException(err_msg)
                    self.logger.error(
                        message=(
                            "{}: Received exit code {}, HTTP Server Error "
                            "while {}. Retrying after {} "
                            "seconds. {} retries remaining.".format(
                                self.log_prefix,
                                response.status_code,
                                logger_msg,
                                DEFAULT_WAIT_TIME,
                                MAX_RETRY - 1 - retry_counter,
                            )
                        ),
                        details=f"API Response: {response.text}",
                    )
                    time.sleep(DEFAULT_WAIT_TIME)
                else:
                    return (
                        self.handle_error(
                            response,
                            logger_msg,
                            is_validation,
                        )
                        if is_handle_error_required
                        else response
                    )

        except ThreatConnectException:
            raise
        except ReadTimeout as error:
            err_msg = f"Read Timeout error occurred while {logger_msg}."
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {error}",
                details=str(traceback.format_exc()),
            )
            raise ThreatConnectException(err_msg)
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
            raise ThreatConnectException(err_msg)
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
            raise ThreatConnectException(err_msg)
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
            raise ThreatConnectException(err_msg)
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
                raise ThreatConnectException(
                    f"{err_msg} Check logs for more details."
                )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {exp}",
                details=traceback.format_exc(),
            )
            raise ThreatConnectException(err_msg)

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
                    "Verify Base URL, Access ID or Secret Key provided "
                    f"in the {PLUGIN_NAME} configuration parameters."
                )
            raise ThreatConnectException(err_msg)
        except Exception as exp:
            err_msg = (
                "Unexpected error occurred while parsing"
                f" json response. Error: {exp}"
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=f"API Response: {response.text}",
            )
            if is_validation:
                err_msg = (
                    "Unexpected validation error occurred, Verify Base URL, "
                    f"Access ID, Secret Key provided in the {PLUGIN_NAME}"
                    " configuration parameters."
                )
            raise ThreatConnectException(err_msg)

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

        validation_msg = (
            "Verify the Base URL, Access ID, Secret Key "
            " provided in configuration parameters."
        )
        error_dict = {
            400: "Bad Request",
            403: "Forbidden",
            401: "Unauthorized",
            409: "Concurrency found",
        }
        if status_code in [200, 201]:
            return self.parse_response(
                response=resp, is_validation=is_validation
            )
        elif status_code == 204:
            return {}
        elif status_code in error_dict:
            err_msg = error_dict[status_code]
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Received exit code {status_code}, "
                    f"{err_msg} while {logger_msg}."
                ),
                details=f"API Response: {resp.text}",
            )
            if is_validation:
                err_msg = err_msg + "." + validation_msg
            raise ThreatConnectException(err_msg)
        else:
            err_msg = (
                "HTTP Server Error"
                if (status_code >= 500 and status_code <= 600)
                else "HTTP Error"
            )
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Received exit code {status_code}, "
                    f"{err_msg} while {logger_msg}."
                ),
                details=f"API Response: {resp.text}",
            )
            if is_validation:
                err_msg = err_msg + "." + validation_msg
            raise ThreatConnectException(err_msg)

    def get_credentials(self, configuration: Dict) -> Tuple:
        """Get API Credentials.
        Args:
            configuration (Dict): Configuration Dictionary.
        Returns:
            Tuple: Tuple containing Base URL, Access ID, Secret Key.
        """
        return (
            configuration.get("base_url", "").strip().strip("/"),
            configuration.get("access_id", "").strip(),
            configuration.get("secret_key", ""),
        )

    def get_headers_for_auth(
        self, api_path: str, access_id: str, secret_key: str, request_type: str
    ) -> Dict:
        """Return header for authentication.

        Args:
            - api_path (str): API path.
            - access_id (str): Access ID.
            - secret_key (str): Secret key.
            - request_type (str): Request type.

        Returns:
            - dict: Header for authentication.
        """
        unix_epoch_time = int(time.time())
        api_path = f"{api_path}:{request_type}:{unix_epoch_time}"
        bytes_api_path = bytes(api_path, "utf-8")
        bytes_secret_key = bytes(secret_key, "utf-8")

        # HMAC-SHA256
        dig = hmac.new(
            bytes_secret_key, msg=bytes_api_path, digestmod=hashlib.sha256
        ).digest()

        # BASE64 ENCODE
        hmac_sha256 = base64.b64encode(dig).decode()
        signature = f"TC {access_id}:{hmac_sha256}"
        header = {
            "Authorization": str(signature),
            "Timestamp": str(unix_epoch_time),
        }
        return header
