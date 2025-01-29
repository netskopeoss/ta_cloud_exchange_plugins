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

CRE Mimecast plugin helper module.
"""

import json
import time
import traceback
from typing import Dict, Union
from requests.exceptions import ReadTimeout
import requests

from netskope.common.utils import add_user_agent

from .constants import (
    MAX_API_CALLS,
    MODULE_NAME,
    DEFAULT_RETRY_AFTER_TIME,
    PLATFORM_NAME,
    BASE_URL,
    GET_BEARER_TOKEN_ENDPOINT,
)


class MimecastPluginException(Exception):
    """Mimecast plugin exception class."""

    pass


class MimecastPluginHelper(object):
    """MimecastPluginHelper class.

    Args:
        object (object): Object class.
    """

    def __init__(
        self, logger, log_prefix: str, plugin_name: str, plugin_version: str
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
        params=None,
        data=None,
        headers=None,
        verify=True,
        proxies=None,
        json=None,
        is_handle_error_required=True,
        is_validation=False,
        regenerate_auth_token=True,
        configuration=None,
    ):
        """API Helper to perform API request on ThirdParty platform \
        and captures all the possible errors for requests.

        Args:
            logger_msg (str): Logger string.
            url (str): URL of the endpoint.
            method (str): Method of the endpoint.
            params (dict, optional): Parameters for the endpoint.
            data (dict, optional): Data for the endpoint.
            headers (dict, optional): Headers for the endpoint.
            verify (bool, optional): Verify the SSL certificate.
            proxies (dict, optional): Proxies for the endpoint.
            json (dict, optional): JSON data for the endpoint.
            is_handle_error_required (bool, optional): Is handling status
            code is required?.
            is_validation (bool, optional): Is validation required?
            regenerate_auth_token (bool, optional): Regenerate auth token?
            configuration (dict, optional): Configuration parameters.

        Returns:
            dict: Response dictionary.
        """
        headers = self._add_user_agent(headers)
        try:
            debug_log_msg = (
                f"{self.log_prefix}: API Request for {logger_msg}."
                f" Endpoint: {method} {url}"
            )
            if params:
                debug_log_msg += f", params: {params}"

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
                )
                status_code = response.status_code
                self.logger.debug(
                    f"{self.log_prefix}: Received API response for "
                    f"{logger_msg}. Status Code={status_code}."
                )
                if (
                    (status_code == 401)
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

                    headers = self.get_headers(
                        configuration=configuration,
                        is_handle_error_required=is_handle_error_required,
                        proxy=proxies,
                        verify=verify,
                    )
                    return self.api_helper(
                        url=url,
                        method=method,
                        params=params,
                        headers=headers,
                        json=json,
                        data=data,
                        proxies=proxies,
                        verify=verify,
                        is_handle_error_required=is_handle_error_required,
                        is_validation=is_validation,
                        logger_msg=logger_msg,
                        regenerate_auth_token=False,
                    )
                elif (
                    status_code == 429 or 500 <= status_code <= 600
                ) and not is_validation:
                    api_err_msg = str(response.text)
                    retry_after = DEFAULT_RETRY_AFTER_TIME // 1000
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
                    if status_code == 429:
                        log_err_msg = "API rate limit exceeded"
                        retry_after = int(
                            response.headers.get(
                                "X-RateLimit-Reset",
                                DEFAULT_RETRY_AFTER_TIME,
                            )
                        )
                        retry_after = retry_after // 1000
                        if (retry_after) > 300:
                            err_msg = (
                                "'Retry-After' value received from response "
                                "headers while {} is greater than 5 minutes "
                                "hence returning status code {}.".format(
                                    logger_msg, status_code
                                )
                            )
                            self.logger.error(f"{self.log_prefix}: {err_msg}")
                            raise MimecastPluginException(err_msg)
                    else:
                        log_err_msg = "HTTP server error occurred"
                    self.logger.error(
                        message=(
                            f"{self.log_prefix}: Received exit code "
                            f"{status_code}, "
                            f"{log_err_msg} while {logger_msg}. "
                            f"Retrying after {retry_after}"
                            f" seconds. {MAX_API_CALLS - 1 - retry_counter} "
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
        except ReadTimeout as error:
            err_msg = f"Read Timeout error occurred while {logger_msg}."
            if is_validation:
                err_msg = (
                    "Read Timeout occurred. Verify the "
                    f"{PLATFORM_NAME} server is up and running."
                )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} {error}",
                details=str(traceback.format_exc()),
            )
            raise MimecastPluginException(err_msg)
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
            raise MimecastPluginException(err_msg)
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
            raise MimecastPluginException(err_msg)
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
            raise MimecastPluginException(err_msg)
        except MimecastPluginException:
            raise
        except Exception as exp:
            err_msg = f"Unexpected error occurred while {logger_msg}."
            if is_validation:
                err_msg = (
                    "Validation error occurred while performing "
                    f"API call to {PLATFORM_NAME}."
                )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {exp}",
                details=traceback.format_exc(),
            )
            raise MimecastPluginException(err_msg)

    def parse_response(self, response, logger_msg, is_validation=False):
        """Parse Response will return JSON from response object.

        Args:
            response (response): Response object.

        Returns:
            json: Response Json.
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
                    "Verify Client ID or Client Secret provided in the "
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
                    "Verify Client ID or Client Secret provided in the "
                    "configuration parameters. Check logs for more details."
                )
            raise MimecastPluginException(err_msg)

    def handle_error(
        self,
        resp: requests.models.Response,
        logger_msg: str,
        is_validation=False,
    ) -> Dict:
        """Handle the different HTTP response code.

        Args:
            resp (requests.models.Response): Response object returned
                from API call.
            logger_msg
        Returns:
            dict: Returns the dictionary of response JSON when the
                response code is 200.
        Raises:
            MimecastPluginException: When the response code is
            not 200,201 and 204.
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
                400: ("Received exit code 400, Bad Request"),
                401: (
                    "Received exit code 401, Unauthorized, Verify "
                    "Client ID and Client Secret "
                    "provided in the configuration parameters."
                ),
                403: (
                    "Received exit code 403, Forbidden, Verify "
                    "Client ID and Client Secret "
                    "provided configuration parameters."
                ),
                404: "Received exit code 404, Resource not found.",
            }
        if resp.status_code in [200, 201]:
            return self.parse_response(
                response=resp,
                logger_msg=logger_msg,
                is_validation=is_validation,
            )
        elif resp.status_code == 204:
            return {}
        elif status_code in error_dict:
            err_msg = error_dict[status_code]
            if is_validation:
                log_err_msg = validation_msg + err_msg
                self.logger.error(
                    message=f"{self.log_prefix}: {log_err_msg}",
                    details=f"API response: {resp.text}",
                )
                raise MimecastPluginException(err_msg)
            else:
                err_msg += " while " + logger_msg + "."
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg}",
                    details=f"API response: {resp.text}",
                )
                raise MimecastPluginException(err_msg)

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
            raise MimecastPluginException(err_msg)

    def get_credentials(self, configuration) -> tuple:
        """Get credentials from the configuration.

        Returns:
            tuple: Credentials
        """
        client_id = configuration.get("client_id", "").strip()
        client_secret = configuration.get("client_secret")

        return (client_id, client_secret)

    def get_headers(
        self,
        configuration,
        is_handle_error_required=True,
        regenerate_auth_token=False,
        is_validation=False,
        proxy=None,
        verify=True,
    ):
        """Get headers with additional fields.

        Args:
            configuration (Dict): Configuration parameters.
            regenerate_auth_token (bool): Regenerate auth token.
            is_validation (bool): Validation flag.
            is_handle_error_required (bool): Handle error flag.

        Returns:
            headers: headers with additional fields.
        """
        bearer_token = self._get_bearer_token(
            configuration=configuration,
            is_handle_error_required=is_handle_error_required,
            regenerate_auth_token=regenerate_auth_token,
            is_validation=is_validation,
            proxy=proxy,
            verify=verify,
        )
        headers = {
            "Authorization": f"Bearer {bearer_token}",
        }

        return headers

    def _get_bearer_token(
        self,
        configuration,
        is_handle_error_required,
        regenerate_auth_token,
        is_validation,
        proxy,
        verify,
    ) -> str:
        """Get bearer token.

        Args:
            configuration (Dict): Configuration parameters.
            regenerate_auth_token (bool): Regenerate auth token.
            is_validation (bool): Validation flag.
            is_handle_error_required (bool): Handle error flag.

        Returns:
            str: Bearer token.
        """
        try:
            client_id, client_secret = self.get_credentials(configuration)

            url = f"{BASE_URL}/{GET_BEARER_TOKEN_ENDPOINT}"
            data = {
                "grant_type": "client_credentials",
                "client_id": client_id,
                "client_secret": client_secret,
            }
            logger_msg = f"getting authentication token from {PLATFORM_NAME}"

            response = self.api_helper(
                logger_msg=logger_msg,
                url=url,
                data=data,
                method="POST",
                proxies=proxy,
                verify=verify,
                is_handle_error_required=is_handle_error_required,
                regenerate_auth_token=regenerate_auth_token,
                is_validation=is_validation,
                configuration=configuration,
            )

            return response.get("access_token")
        except MimecastPluginException:
            raise
        except Exception as exp:
            err_msg = (
                "Unexpected error occurred while getting "
                f"authentication token from {PLATFORM_NAME}."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {exp}",
                details=str(traceback.format_exc()),
            )
            raise MimecastPluginException(err_msg)
