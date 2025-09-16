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

CRE Silverfort plugin helper module.
"""

# Standard import
import json
import time
import traceback
from typing import Dict, Union
from urllib.parse import urlparse
import requests
import re

# Netskope import
from netskope.common.utils import add_user_agent
from netskope.integrations.cls.plugin_base import ValidationResult

# Local import
from . import constants as CONST


class SilverfortPluginException(Exception):
    """Silverfort exception class."""

    pass


class SilverfortPluginHelper(object):
    """Silverfort Plugin Helper class.

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
        """Silverfort Plugin Helper initializer.

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
            CONST.MODULE_NAME.lower(),
            self.plugin_name.lower().replace(" ", "-"),
            self.plugin_version,
        )
        headers.update(
            {
                "User-Agent": user_agent,
            }
        )
        return headers

    def handle_and_raise(
        self,
        err: str = "",
        err_msg: str = "",
        details_msg: str = "",
        exc_type: Exception = SilverfortPluginException,
        if_raise: bool = True,
        return_validation_result: bool = False,
        log_error_msg: str = "",
        validation_msg: str = "",
        log_type: str = "error",
    ):
        """Handle and raise an exception.

        Args:
            err (Exception): Exception object.
            err_msg (str): Error message.
            details_msg (str): Details message.
            exc_type (Exception, optional): Exception type. Defaults to
                AWSD2CProviderException.
            if_raise (bool, optional): Whether to raise the exception.
                Defaults to True.
            return_validation_result (bool, optional): Whether to return
                validation result. Defaults to False.
            log_error_msg (str, optional): Log error message. Defaults to "".
            validation_msg (str, optional): Validation message. Defaults to "".
        """
        if log_type == "error":
            if err:
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: {validation_msg if validation_msg else ''}"  # noqa
                        f"{log_error_msg if log_error_msg else err_msg}"  # noqa
                        f" Error: {err}"
                    ),
                    details=details_msg,
                )
            else:
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg}",
                    details=details_msg,
                )
        if log_type == "info":
            self.logger.info(f"{self.log_prefix}: {err_msg}")
        if if_raise:
            raise exc_type(err_msg)
        if return_validation_result:
            return ValidationResult(
                success=False,
                message=err_msg,
            )

    def api_helper(
        self,
        logger_msg: str,
        url,
        method,
        params=None,
        auth=None,
        data=None,
        headers=None,
        json=None,
        verify=True,
        proxies=None,
        is_handle_error_required=True,
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
            api_data = "Request body:"
            if params:
                debug_msg += f", API params: {params}"
            if data and show_data:
                api_data += f" {data}"
            if json and show_data:
                api_data += f" {json}"
            self.logger.debug(
                message=f"{self.log_prefix}: {debug_msg}",
                details=str(api_data),
            )
            for retry_counter in range(CONST.MAX_API_CALLS):
                response = requests.request(
                    url=url,
                    method=method,
                    auth=auth,
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
                if not is_validation and (
                    (status_code >= 500 and status_code <= 600)
                    or status_code == 429
                ):
                    if retry_counter == CONST.MAX_API_CALLS - 1:
                        err_msg = (
                            f"Received exit code {status_code}, while"
                            f" {logger_msg}. Max retries for rate limit "
                            "handler exceeded hence returning status"
                            f" code {status_code}."
                        )
                        self.handle_and_raise(
                            err_msg=err_msg,
                            details_msg=f"API response: {response.text}",
                        )
                    err_msg = (
                        "Received exit code {}, while"
                        " {}. Retrying after {} "
                        "seconds. {} retries remaining.".format(
                            status_code,
                            logger_msg,
                            CONST.DEFAULT_WAIT_TIME,
                            CONST.MAX_API_CALLS - 1 - retry_counter,
                        )
                    )
                    self.handle_and_raise(
                        err_msg=err_msg,
                        details_msg=f"API response: {response.text}",
                        if_raise=False,
                    )
                    time.sleep(CONST.DEFAULT_WAIT_TIME)
                else:
                    return (
                        self.handle_error(response, logger_msg, is_validation)
                        if is_handle_error_required
                        else response
                    )
        except SilverfortPluginException:
            raise
        except requests.exceptions.ReadTimeout as error:
            err_msg = f"Read Timeout error occurred while {logger_msg}."
            if is_validation:
                err_msg = (
                    "Read Timeout error occurred. "
                    "Verify the Silverfort instance is up and running."
                )
            self.handle_and_raise(
                err=str(error),
                err_msg=err_msg,
                details_msg=str(traceback.format_exc()),
                return_validation_result=is_validation,
            )
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
            self.handle_and_raise(
                err=str(error),
                err_msg=err_msg,
                details_msg=str(traceback.format_exc()),
                return_validation_result=is_validation,
            )
        except requests.exceptions.ConnectionError as error:
            err_msg = (
                f"Unable to establish connection with {CONST.PLATFORM_NAME} "
                f"platform while {logger_msg}. Proxy server or "
                f"{CONST.PLATFORM_NAME} server is not reachable."
            )
            if is_validation:
                err_msg = (
                    f"Unable to establish connection with"
                    f" {CONST.PLATFORM_NAME} platform. Proxy "
                    f"server or {CONST.PLATFORM_NAME} "
                    "server is not reachable."
                )
            self.handle_and_raise(
                err=str(error),
                err_msg=err_msg,
                details_msg=str(traceback.format_exc()),
                return_validation_result=is_validation,
            )
        except requests.HTTPError as err:
            err_msg = f"HTTP error occurred while {logger_msg}."
            if is_validation:
                err_msg = (
                    "HTTP error occurred. Verify "
                    "configuration parameters provided."
                )
            self.handle_and_raise(
                err=str(err),
                err_msg=err_msg,
                details_msg=str(traceback.format_exc()),
                return_validation_result=is_validation,
            )
        except Exception as exp:
            err_msg = f"Unexpected error occurred while {logger_msg}."
            if is_validation:
                err_msg = (
                    "Unexpected error while performing "
                    f"API call to {CONST.PLATFORM_NAME}."
                )
            self.handle_and_raise(
                err=str(exp),
                err_msg=err_msg,
                details_msg=str(traceback.format_exc()),
                return_validation_result=is_validation,
            )

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
            if response.text.strip():
                data = response.json()
                return data
            else:
                return None
        except json.JSONDecodeError as err:
            err_msg = ""
            log_err_msg = (
                "Invalid JSON response received "
                f"from API while {logger_msg}."
            )
            if is_validation:
                err_msg = (
                    "Verify User API Token provided in "
                    "the configuration parameters. Check logs for more"
                    " details."
                )
            self.handle_and_raise(
                err=str(err),
                err_msg=err_msg,
                details_msg=f"API response: {response.text}",
                return_validation_result=is_validation,
                log_error_msg=log_err_msg,
            )
        except Exception as exp:
            err_msg = ""
            log_err_msg = (
                "Unexpected error occurred while parsing "
                f"json response for {logger_msg}. Error: {exp}"
            )
            if is_validation:
                err_msg = (
                    "Unexpected validation error occurred, Verify "
                    "User API Token provided in the configuration "
                    "parameters. Check logs for more details."
                )
            self.handle_and_raise(
                err=str(exp),
                err_msg=err_msg,
                details_msg=f"API response: {response.text}",
                return_validation_result=is_validation,
                log_error_msg=log_err_msg,
            )

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
        validation_msg = "Validation error occurred. "
        error_dict = {
            400: "Received exit code 400 (HTTP client error)",
            403: "Received exit code 403 (Forbidden)",
            401: "Received exit code 401 (Unauthorized access)",
            404: "Received exit code 404 (Resource not found)",
        }
        if is_validation:
            error_dict = {
                400: (
                    "Received exit code 400 (Bad Request). "
                    "Verify Silverfort Base URL, Auth ID and Webhook ID"
                    " provided in the configuration "
                    "parameters."
                ),
                401: (
                    "Received exit code 401 (Unauthorized). Verify "
                    "Silverfort Auth ID and Webhook"
                    " ID provided in the "
                    "configuration parameters."
                ),
                403: (
                    "Received exit code 403 (Forbidden). Verify the "
                    "permissions for the user whose Auth ID and"
                    " Webhook ID is used in the configuration."
                ),
                404: (
                    "Received exit code 404 (Resource not found), Verify"
                    " Silverfort Base URL provided in"
                    " the configuration parameters."
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
                err_msg = validation_msg + err_msg
            else:
                err_msg = err_msg + " while " + logger_msg + "."
            self.handle_and_raise(
                err_msg=err_msg,
                details_msg=f"API response: {resp.text}",
                return_validation_result=is_validation,
                validation_msg=validation_msg,
            )
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
            self.handle_and_raise(
                err_msg=err_msg,
                details_msg=f"API response: {resp.text}",
                validation_msg=validation_msg,
                return_validation_result=is_validation,
            )

    def get_credentials(self, configuration) -> tuple:
        """Get credentials from the configuration.

        Returns:
            tuple: Credentials
        """
        return (
            configuration.get("base_url", "").strip().strip("/"),
            configuration.get("auth_id", ""),
            configuration.get("webhook_id", ""),
        )

    def validate_email(self, email: str) -> bool:
        """Validate email.

        Args:
            email (str): Email to validate.

        Returns:
            bool: True if email is valid, False otherwise.
        """
        if re.match(CONST.EMAIL_REGEX, email):
            return True
        return False

    def validate_url(self, url: str) -> bool:
        """Validate URL.

        Args:
            url (str): URL to validate.

        Returns:
            bool: True if URL is valid, False otherwise.
        """
        parsed_url = urlparse(url.strip())
        return parsed_url.scheme and parsed_url.netloc
