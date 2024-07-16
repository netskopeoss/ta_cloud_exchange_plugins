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
import time
import traceback
from typing import Dict, Union
import base64
from datetime import datetime
import uuid
import hashlib
import hmac

import requests
from netskope.common.utils import add_user_agent

from .mimecast_constants import (
    DEFAULT_WAIT_TIME,
    MAX_API_CALLS,
    PLUGIN_NAME,
    MODULE_NAME,
)


class MimecastPluginException(Exception):
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
        configuration: Dict,
        plugin_name: str,
        plugin_version: str,
        ssl_validation,
        proxy,
    ):
        """MimecastPluginHelper initializer.

        Args:
            logger (logger object): Logger object.
            log_prefix (str): log prefix.
            plugin_name (str): Plugin name.
            plugin_version (str): Plugin version.
        """
        self.log_prefix = log_prefix
        self.logger = logger
        self.configuration = configuration
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

    def api_helper(
        self,
        logger_msg: str,
        url_endpoint,
        method,
        configuration=None,
        retry=True,
        params=None,
        data=None,
        headers=None,
        json_params=None,
        is_handle_error_required=True,
        skewed_retry=True
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
            if not self.configuration:
                self.configuration = configuration
            url = self.configuration.get("url", "").strip().rstrip('/') + url_endpoint
            display_headers = {
                k: v for k, v in headers.items() if k not in {"Authorization"}
            }
            debug_msg = f"API endpoint for {logger_msg}: {url}, Headers: {display_headers}"
            if params:
                debug_msg += f", API params: {params}"
            if data and "hashlist" not in logger_msg:
                debug_msg += f", API data: {data}"
            if json_params and "decoding" not in logger_msg and "pushing URL" not in logger_msg:
                debug_msg += f", API json body: {json_params}"
            self.logger.debug(f"{self.log_prefix}: {debug_msg}")
            for retry_counter in range(MAX_API_CALLS):
                response = requests.request(
                    url=url,
                    method=method,
                    params=params,
                    data=data,
                    headers=headers,
                    verify=self.verify,
                    proxies=self.proxies,
                    json=json_params,
                )
                self.logger.debug(
                    f"{self.log_prefix}: "
                    f"API response status code for {logger_msg}: {response.status_code}."
                )
                if response.status_code == 401 and "Date Header Too Skewed" in response.text and skewed_retry:
                    self.logger.error(
                        f"{self.log_prefix}: Received 401 status code - "
                        "'Date Header Too Skewed'. Retrying by generating new "
                        "authorization header."
                    )
                    headers_temp = self._get_auth_headers(self.configuration, url_endpoint)
                    headers.update(headers_temp)
                    skewed_retry = False
                    continue

                if retry and (
                    (response.status_code >= 500 and response.status_code <= 600)
                    or response.status_code == 429
                ):
                    if retry_counter == MAX_API_CALLS - 1:
                        err_msg = (
                            "Received exit code {}, while"
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
                            details=str(response.text),
                        )
                        raise MimecastPluginException(err_msg)
                    x_rate_limit_reset = int(response.headers.get("X-RateLimit-Reset", 0))
                    if x_rate_limit_reset:
                        retry_after = int((x_rate_limit_reset/1000) % 60)
                    else:
                        retry_after = DEFAULT_WAIT_TIME
                    if retry_after > 300:
                        err_msg = (
                            "Received response code {}, 'X-RateLimit_Reset' value "
                            "received from response headers while {} is "
                            "greater than 5 minutes. Hence exiting.".format(
                                response.status_code,
                                logger_msg,
                            )
                        )
                        self.logger.error(
                            message=f"{self.log_prefix}: {err_msg}",
                            details=f"{response.text}",
                        )
                        raise MimecastPluginException(err_msg)
                    self.logger.error(
                        message=(
                            "{}: Received exit code {}, while {}. "
                            "Retrying after {} seconds. "
                            "Retries remaining - {}.".format(
                                self.log_prefix,
                                response.status_code,
                                logger_msg,
                                retry_after,
                                MAX_API_CALLS - 1 - retry_counter,
                            )
                        ),
                        details=str(response.text),
                    )
                    time.sleep(retry_after)
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
            raise MimecastPluginException(err_msg)
        except requests.exceptions.ConnectionError as error:
            err_msg = (
                f"Unable to establish connection with {PLUGIN_NAME} "
                f"platform while {logger_msg}. "
                f"Proxy server or {PLUGIN_NAME} "
                "server is not reachable."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {error}",
                details=str(traceback.format_exc()),
            )
            raise MimecastPluginException(err_msg)
        except requests.HTTPError as err:
            err_msg = f"HTTP Error occurred while {logger_msg}."
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {err}",
                details=str(traceback.format_exc()),
            )
            raise MimecastPluginException(err_msg)
        except MimecastPluginException as exp:
            raise MimecastPluginException(exp)
        except Exception as exp:
            err_msg = f"Unexpected error occurred while {logger_msg}."
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {exp}",
                details=str(traceback.format_exc()),
            )
            raise MimecastPluginException(err_msg)

    def _get_auth_headers(
        self, configuration: dict, endpoint: str
    ) -> str:
        """Generate the Mimecast authentication headers."""
        request_id = str(uuid.uuid4())
        request_datetime = (
            datetime.utcnow().strftime("%a, %d %b %Y %H:%M:%S") + " UTC"
        )

        # Create the HMAC SHA1 of the Base64 decoded secret key for the
        # Authorization header
        try:
            hmac_sha1 = hmac.new(
                base64.b64decode(configuration.get("secret_key")),
                ":".join(
                    [
                        request_datetime,
                        request_id,
                        endpoint,
                        configuration.get("app_key"),
                    ]
                ).encode("utf-8"),
                digestmod=hashlib.sha1,
            ).digest()
        except Exception as err:
            error_msg = (
                "Invalid Secret Key provided in the configuration parameters."
            )
            self.logger.error(
                f"{self.log_prefix}: Error occurred while generating Auth headers."
                f"{error_msg}, Error: {err}",
                details=traceback.format_exc()
            )
            raise MimecastPluginException(error_msg)

        # Use the HMAC SHA1 value to sign hmac_sha1
        sig = base64.b64encode(hmac_sha1).rstrip()

        # Create request headers
        headers = {
            "Authorization": "MC "
            + configuration.get("access_key")
            + ":"
            + sig.decode("utf-8"),
            "x-mc-app-id": configuration.get("app_id"),
            "x-mc-date": request_datetime,
            "x-mc-req-id": request_id,
            "Content-Type": "application/json",
        }
        headers = self._add_user_agent(headers)
        return headers

    def parse_response(self, response: requests.models.Response, logger_msg):
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
            toast_msg = (
                f"Error occurred while {logger_msg}. Check the credentials provided. Check the logs for details."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=f"API response: {response.text}",
            )
            raise MimecastPluginException(toast_msg)
        except Exception as exp:
            err_msg = (
                "Unexpected error occurred while parsing"
                f" json response. Error: {exp}"
            )
            toast_msg = (
                f"Error occurred while {logger_msg}. Check the credentials provided. Check the logs for details."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=f"API Response: {response.text}",
            )
            raise MimecastPluginException(toast_msg)

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
            MimecastPluginException: When the response code is
            not in 200 range.
        """
        if resp.status_code in [200, 201, 202]:
            if "hashes" in logger_msg:
                return resp
            else:
                return self.parse_response(resp, logger_msg)

        error_dict = {
            400: "Bad Request",
            403: "Forbidden, access is denied to the requested resource. The user may not have enough permission to perform the action",
            401: "Unauthorized, invalid Application keys provided",
            404: "Not Found",
            409: "Conflict, the current status of the relying data does not match what is defined in the request",
            418: "Binding Expired, the TTL of the access key and secret key issued on successful login has lapsed and the binding should be refreshed as described in the Authentication guide"
        }
        try:
            json_response = self.parse_response(resp, logger_msg)
            fail_list = json_response.get("fail", [])
            if "hashes" in logger_msg:
                if fail_list:
                    api_error_message = fail_list.get('message', '')
            else:
                error_list = fail_list[0].get("errors", [])
                if fail_list and error_list:
                    api_error_message = error_list[0].get("message", "")
        except Exception:
            api_error_message = resp.text
        if resp.status_code in error_dict:
            error_msg = (
                f"{self.log_prefix}: Received status code {resp.status_code} - "
                f"{error_dict.get(resp.status_code)} while {logger_msg}."
            )
            if api_error_message:
                error_msg += f" Error Message: {api_error_message}."
            self.logger.error(
                error_msg,
                details=str(resp.text)
            )
            raise MimecastPluginException(error_msg)
        else:
            err = (
                "HTTP Server Error"
                if (resp.status_code >= 500 and resp.status_code <= 600)
                else "HTTP Error"
            )
            err_msg = (
                f"{self.log_prefix}: Received status code {resp.status_code} - {err} "
                f"while {logger_msg}."
            )
            self.logger.error(
                message=err_msg,
                details=str(resp.text),
            )
            raise MimecastPluginException(err_msg)

