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

URE CyberArk plugin helper module.
"""

import json
import time
import traceback
from typing import Dict, Union

import requests
from netskope.common.utils import add_user_agent
from requests.exceptions import ReadTimeout

from .constants import (
    DEFAULT_WAIT_TIME,
    MAX_API_CALLS,
    PLATFORM_NAME,
    MODULE_NAME,
)


class CyberArkPluginException(Exception):
    """CyberArk plugin custom exception class."""

    pass


class CyberArkPluginHelper(object):
    """CyberArkPluginHelper class.

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
        """CyberArk Plugin Helper initializer.

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
        retry=True,
        params=None,
        data=None,
        headers=None,
        json_params=None,
        verify=True,
        proxies=None,
        is_handle_error_required=True,
        regenerate_auth_token=True,
        is_validation=False,
        configuration=None,
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
            headers = self._add_user_agent(headers)
            for retry_counter in range(MAX_API_CALLS):
                debug_msg = f"API endpoint for {logger_msg}: {url}"
                if params:
                    debug_msg += f", API params: {params}"
                if data and "auth token" not in logger_msg:
                    debug_msg += f", API data: {data}"
                if json_params:
                    debug_msg += f", API json body: {json_params}"
                self.logger.debug(f"{self.log_prefix}: {debug_msg}")
                response = requests.request(
                    url=url,
                    method=method,
                    params=params,
                    data=data,
                    headers=headers,
                    verify=verify,
                    proxies=proxies,
                    json=json_params,
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
                    or (response.status_code == 401)
                ) and regenerate_auth_token:
                    # regenerate auth token
                    self.logger.info(
                        f"{self.log_prefix}: "
                        "The access token used is expired hence regenerating "
                        "the auth token."
                    )
                    auth_header = self.get_protected_cyberark_headers(  # noqa
                        logger_msg,
                        ssl_validation=verify,
                        proxies=proxies,
                        configuration=configuration,
                        regenerate_auth_token=False,
                        is_retry=True
                    )
                    headers["Authorization"] = auth_header.get("Authorization")
                    return self.api_helper(
                        logger_msg=logger_msg,
                        url=url,
                        method=method,
                        params=params,
                        data=data,
                        headers=headers,
                        json_params=json_params,
                        verify=verify,
                        proxies=proxies,
                        is_handle_error_required=is_handle_error_required,
                        regenerate_auth_token=False,
                        is_validation=is_validation,
                        configuration=configuration,
                    )
                if (
                    "auth token" not in logger_msg
                    and retry
                    and (
                        (
                            response.status_code >= 500
                            and response.status_code <= 600
                        )
                        or response.status_code == 429
                    )
                ):
                    try:
                        resp_json = self.parse_response(
                            response, logger_msg, is_validation
                        )
                        api_error = resp_json.get("error", "")
                        api_error_description = resp_json.get(
                            "error_description", ""
                        )
                        combined_err_msg = (
                            f"Received exit code {response.status_code} "
                            f"for {logger_msg}."
                        )
                        if api_error:
                            combined_err_msg += (
                                " API error - " + api_error + "."
                            )
                        if api_error_description:
                            combined_err_msg += (
                                " API error description - "
                                + api_error_description
                            )

                    except CyberArkPluginException:
                        combined_err_msg = (
                            "Received exit code "
                            f"{response.status_code} for {logger_msg}."
                        )

                    if retry_counter == MAX_API_CALLS - 1:
                        self.logger.error(
                            message=f"{self.log_prefix}: {combined_err_msg}",
                            details=f"API response: {str(response.text)}",
                        )
                        raise CyberArkPluginException(combined_err_msg)
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
                        details=f"API response: {response.text}",
                    )
                    time.sleep(DEFAULT_WAIT_TIME)
                else:
                    return (
                        self.handle_error(response, logger_msg, is_validation)
                        if is_handle_error_required
                        else response
                    )
        except ReadTimeout as error:
            err_msg = f"Read Timeout error occurred while {logger_msg}."
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {error}",
                details=str(traceback.format_exc()),
            )
            raise CyberArkPluginException(err_msg)
        except requests.exceptions.ProxyError as error:
            err_msg = (
                f"Proxy error occurred while {logger_msg}. "
                "Verify the provided proxy configuration."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {error}",
                details=str(traceback.format_exc()),
            )
            raise CyberArkPluginException(err_msg)
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
            raise CyberArkPluginException(err_msg)
        except requests.HTTPError as err:
            err_msg = f"HTTP Error occurred while {logger_msg}."
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {err}",
                details=str(traceback.format_exc()),
            )
            raise CyberArkPluginException(err_msg)
        except CyberArkPluginException as err:
            raise CyberArkPluginException(err)
        except Exception as exp:
            err_msg = f"Unexpected error occurred while {logger_msg}."
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {exp}",
                details=str(traceback.format_exc()),
            )
            raise CyberArkPluginException(err_msg)

    def get_protected_cyberark_headers(
        self,
        logger_msg,
        ssl_validation,
        proxies,
        configuration: Dict = None,
        regenerate_auth_token=True,
        is_retry=False,
    ):
        """Get protected CyberArk headers."""

        # check if configuration is present. Configuration will be received in
        # case when the method is called form validate method.
        cyberark_service_user = configuration.get(
            "service_user", ""
        ).strip()
        cyberark_service_password = configuration.get("service_password")
        url_endpoint = "/oauth2/platformtoken"
        url = self.build_url(
            configuration,
            url_endpoint
        )
        body = {
            "grant_type": "client_credentials",
            "scope": "all",
            "client_id": cyberark_service_user,
            "client_secret": cyberark_service_password,
        }
        cyberark_oauth_headers = {
            "Accept": "application/json",
            "Content-Type": "application/x-www-form-urlencoded",
        }
        if not is_retry:
            logger_msg = "generating auth token for " + logger_msg
        try:
            rest_response = self.api_helper(
                logger_msg=logger_msg,
                url=url,
                method="GET",
                headers=cyberark_oauth_headers,
                is_handle_error_required=True,
                data=body,
                verify=ssl_validation,
                proxies=proxies,
                regenerate_auth_token=regenerate_auth_token,
                configuration=configuration
            )
            if not rest_response.get("access_token", ""):
                err_msg = (
                    "Error occurred while generating access token."
                    f"Check the {PLATFORM_NAME} Tenant URL, "
                    "Username and Password."
                )
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg}",
                    details=str(rest_response)
                )
                raise CyberArkPluginException(err_msg)
            cyberark_protected_headers = {
                "Authorization": "Bearer {0}".format(
                    rest_response.get("access_token", "")
                )
            }
            return cyberark_protected_headers
        except CyberArkPluginException as err:
            raise err
        except Exception as err:
            error_msg = f"Unexpected Error occurred while {logger_msg}."
            self.logger.error(
                message=f"{self.log_prefix}: {error_msg} " f"Error: {err}",
                details=str(traceback.format_exc())
            )
            raise CyberArkPluginException(
                f"{error_msg} Check logs for details."
            )

    def parse_response(
        self,
        response: requests.models.Response,
        logger_msg: str,
        is_validation=False,
    ):
        """
        Parse Response will return JSON from response object.

        Args:
            response (response): Response object returned from API call.
            logger_msg (str): logger message.
            is_validation (bool, optional): Validation flag. Defaults to False.

        Returns:
            Any: Response Json.

        Raises:
            CyberArkPluginException: When the response code is not in 200
            range.
        """
        try:
            return response.json()
        except json.JSONDecodeError as err:
            err_msg = (
                f"Invalid JSON response received from API while "
                f"{logger_msg}. Error: {str(err)}"
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=f"API response: {response.text}",
            )
            if is_validation:
                err_msg = (
                    "Verify Tenant URL provided in the "
                    "configuration parameters. Check logs for more details."
                )
            raise CyberArkPluginException(err_msg)
        except Exception as exp:
            err_msg = (
                "Unexpected error occurred while parsing"
                f" json response while {logger_msg}. Error: {exp}"
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=f"API Response: {response.text}",
            )
            if is_validation:
                err_msg = (
                    "Unexpected validation error occurred, "
                    "Verify Tenant URL, Username and Password provided in the "
                    "configuration parameters. Check logs for more details."
                )
            raise CyberArkPluginException(err_msg)

    def build_url(self, configuration, url_endpoint):
        """
        Build CyberArk URL.

        Args:
            configuration (dict): Configuration parameters.
            url_endpoint (str): URL Endpoint.

        Returns:
            str: Built URL.
        """
        url = (
            f"{configuration.get('url').strip().rstrip('/')}"
            f"{url_endpoint}"
        )
        return url

    def handle_error(
        self,
        resp: requests.models.Response,
        logger_msg: str,
        is_validation: bool = False,
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
            CyberArkException: When the response code is
            not in 200 range.
        """
        if resp.status_code in [200, 201, 202]:
            parsed_resp = self.parse_response(resp, logger_msg, is_validation)
            if "generating auth token" in logger_msg:
                return parsed_resp
            elif (
                parsed_resp.get("success", True) == True  # noqa
            ):
                return parsed_resp
        try:
            resp_json = self.parse_response(resp, logger_msg, is_validation)
            api_error = resp_json.get("error", "")
            api_error_description = resp_json.get("error_description", "")
            combined_err_msg = (
                f"Received failure response for {logger_msg}."
            )
            if api_error:
                combined_err_msg += " API error - " + api_error + "."
            if api_error_description:
                combined_err_msg += (
                    " API error description - " + api_error_description + "."
                )

        except Exception:
            combined_err_msg = (
                "Received failure response with "
                f"exit code {resp.status_code} for {logger_msg}."
            )

        if "access_denied" in combined_err_msg:
            error_msg = (
                f"Access denied while {logger_msg}, verify the "
                "Tenant URL, Username and Password."
            )
            self.logger.error(
                f"{self.log_prefix}: {combined_err_msg}",
                details=f"API response: {resp.text}",
            )
            raise CyberArkPluginException(error_msg)
        elif resp.status_code == 204:
            return {}
        elif resp.status_code == 401:
            err_msg = (
                "Unauthorized error, "
                "check the Username and Password provided."
            )
            self.logger.error(
                f"{self.log_prefix}: {combined_err_msg} " f"{err_msg}",
                details=f"API response: {resp.text}",
            )
            raise CyberArkPluginException(err_msg)
        elif resp.status_code == 403:
            err_msg = (
                "Forbidden error, "
                "verify that the user has the required "
                "permissions attached."
            )
            self.logger.error(
                f"{self.log_prefix}: {combined_err_msg} " f"{err_msg}",
                details=f"API response: {resp.text}",
            )
            raise CyberArkPluginException(err_msg)
        else:
            self.logger.error(
                message=f"{self.log_prefix}: {combined_err_msg}",
                details=f"API response: {resp.text}",
            )
            raise CyberArkPluginException(combined_err_msg)
