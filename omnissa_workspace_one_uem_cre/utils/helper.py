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

CRE Omnissa Workspace One UEM Plugin helper module.
"""

import base64
import hashlib
import time
import traceback
from datetime import datetime
from typing import Dict, Literal, Tuple, Union  # type: ignore

import requests
from netskope.common.utils import add_user_agent
from requests.models import Response

from .constants import (
    DEFAULT_SLEEP_TIME,
    GENERATE_ACCESS_TOKEN_ENDPOINT,
    MAX_RETRIES,
    MODULE_NAME,
    NO_MORE_RETRIES_ERROR_MSG,
    ONE,
    PLATFORM_NAME,
    POST,
    RETRY_ERROR_MSG,
)
from .exceptions import OmnissaWorkspaceOneUEMPluginException


class OmnissaWorkspaceOneUEMHelper:
    """Omnissa Workspace One UEM Plugin Helper class.

    Args:
        object (object): Object class.
    """

    def __init__(
        self,
        logger,
        log_prefix: str,
        plugin_name: str,
        plugin_version: str,
        parser,
    ):
        """OmnissaWorkspaceOneUEMHelper initializer.

        Args:
            logger (logger object): Logger object.
            log_prefix (str): log prefix.
            plugin_name (str): Plugin name.
            plugin_version (str): Plugin version.
            parser (OmnissaWorkspaceOneUEMParser object): Parser object.
        """
        self.logger = logger
        self.log_prefix = log_prefix
        self.plugin_name = plugin_name
        self.plugin_version = plugin_version
        self.parser = parser

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
        data: Dict = None,
        headers: Dict = None,
        verify=True,
        proxies=None,
        json: Dict = None,
        storage: Dict = {},
        configuration: Dict = {},
        is_validation: bool = False,
        is_handle_error_required=True,
        regenerate_access_token: bool = True,
    ) -> Union[Response, Dict]:
        headers = self._add_user_agent(headers)
        debug_log_msg = (
            f"{self.log_prefix}: API Request for {logger_msg}. "
            f"Endpoint: {method} {url}"
        )
        if params:
            debug_log_msg += f", params: {params}."
        self.logger.debug(debug_log_msg)
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
                )
                status_code = response.status_code
                # Token regeneration logic
                if status_code == 401 and regenerate_access_token:
                    _, oauth_url, client_id, client_secret, _ = (
                        self.get_configuration_parameters(
                            configuration
                        )
                    )
                    regenerated_access_token = (
                        self.generate_access_token_and_update_storage(
                            oauth_url,
                            client_id,
                            client_secret,
                            verify,
                            proxies,
                            storage,
                        )
                    )
                    headers.update(
                        {"Authorization": f"Bearer {regenerated_access_token}"}
                    )
                    return self.api_helper(
                        logger_msg=logger_msg,
                        url=url,
                        method=method,
                        headers=headers,
                        params=params,
                        data=data,
                        verify=verify,
                        proxies=proxies,
                        json=json,
                        storage=storage,
                        configuration=configuration,
                        is_validation=is_validation,
                        is_handle_error_required=is_handle_error_required,
                        regenerate_access_token=False,
                    )
                # Handle Rate limit (429) and 5xx errors
                if not is_validation and (
                    status_code == 429 or 500 <= status_code <= 600
                ):
                    api_err_msg = str(response.text)
                    if retry_count == MAX_RETRIES - 1:
                        err_msg = NO_MORE_RETRIES_ERROR_MSG.format(
                            status_code=status_code,
                            logger_msg=logger_msg,
                        )
                        self.logger.error(
                            message=f"{self.log_prefix}: {err_msg}"
                        )
                        raise OmnissaWorkspaceOneUEMPluginException(err_msg)
                    if status_code == 429:
                        error_reason = "API rate limit exceeded"
                    else:
                        error_reason = "HTTP server error occurred"
                    retry_after = self._get_retry_after(response.headers)
                    err_msg = RETRY_ERROR_MSG.format(
                        status_code=status_code,
                        error_reason=error_reason,
                        logger_msg=logger_msg,
                        wait_time=retry_after,
                        retry_remaining=MAX_RETRIES - 1 - retry_count,
                    )
                    self.logger.error(
                        message=f"{self.log_prefix}: {err_msg}",
                        details=api_err_msg,
                    )
                    self._handle_rate_limit(retry_after)
                else:
                    return (
                        self.handle_error(
                            resp=response,
                            logger_msg=logger_msg,
                            is_validation=is_validation,
                        ) if is_handle_error_required else response
                    )
        except OmnissaWorkspaceOneUEMPluginException:
            raise
        except requests.exceptions.ReadTimeout as error:
            err_msg = f"Read Timeout error occurred while {logger_msg}."
            if is_validation:
                err_msg = "Read Timeout error occurred."

            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {error}",
                details=traceback.format_exc(),
                resolution=(
                    "Please check if the API Base URL/OAuth URL provided is"
                    " correct and the server is reachable."
                ),
            )
            raise OmnissaWorkspaceOneUEMPluginException(err_msg)
        except requests.exceptions.ProxyError as error:
            err_msg = (
                f"Proxy error occurred while {logger_msg}. Verify the "
                "proxy configuration provided."
            )
            if is_validation:
                err_msg = (
                    "Proxy error occurred. Verify the proxy configuration"
                    " provided."
                )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {error}",
                details=traceback.format_exc(),
                resolution=(
                    "Please check if the proxy configuration provided is"
                    " correct and the proxy server is reachable."
                ),
            )
            raise OmnissaWorkspaceOneUEMPluginException(err_msg)
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
                resolution=(
                    "Please check if the API Base URL/OAuth URL provided is"
                    " correct and the server is reachable."
                ),
            )
            raise OmnissaWorkspaceOneUEMPluginException(err_msg)
        except requests.HTTPError as error:
            err_msg = f"HTTP error occurred while {logger_msg}."
            if is_validation:
                err_msg = (
                    "HTTP error occurred. Verify configuration parameters"
                    " provided."
                )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {error}",
                details=traceback.format_exc(),
                resolution=(
                    "Please verify the configuration parameters provided."
                ),
            )
            raise OmnissaWorkspaceOneUEMPluginException(err_msg)
        except Exception as error:
            err_msg = f"Unexpected error occurred while {logger_msg}."
            if is_validation:
                err_msg = (
                    "Unexpected error while performing API call to"
                    f" {PLATFORM_NAME}."
                )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {error}",
                details=traceback.format_exc(),
                resolution=(
                    "Please verify the configuration parameters provided."
                )
            )
            raise OmnissaWorkspaceOneUEMPluginException(err_msg)

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
            OmnissaWorkspaceOneUEMPluginException: When the response code is
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
        resolution_dict = {
            400: (
                "Verify the API Base URL provided in the configuration"
                " parameters."
            ),
            401: (
                "Verify Client ID and Client Secret provided in the"
                " configuration parameters."
            ),
            403: (
                "Verify permission for Client ID and Client Secret provided"
                " in the configuration parameters."
            ),
            404: (
                "Verify the API Base URL provided in the configuration"
                " parameters."
            ),
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
                    "Verify Client ID and Client Secret provided in "
                    "the configuration parameters."
                ),
                403: (
                    "Received exit code 403, Forbidden, "
                    "Verify permission for Client ID and Client "
                    "Secret provided in the configuration parameters."
                ),
                404: (
                    "Received exit code 404, Resource not found, "
                    "Verify the API Base URL provided in "
                    "the configuration parameters."
                ),
            }

        def _log_error_message(resolution: str = None):
            nonlocal err_msg
            if is_validation:
                log_err_msg = validation_msg + err_msg
                self.logger.error(
                    message=f"{self.log_prefix}: {log_err_msg}",
                    details=f"API response: {resp.text}",
                    resolution=resolution,
                )
                raise OmnissaWorkspaceOneUEMPluginException(err_msg)
            else:
                err_msg = err_msg + " while " + logger_msg + "."
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg}",
                    details=f"API response: {resp.text}",
                )
                raise OmnissaWorkspaceOneUEMPluginException(err_msg)

        if status_code in [200, 201, 202]:
            return self.parser.parse_response(
                response=resp,
                logger_msg=logger_msg,
                is_validation=is_validation,
            )
        elif status_code == 204:
            return {}
        elif status_code in error_dict:
            err_msg = error_dict[status_code]
            _log_error_message(resolution=resolution_dict[status_code])
        elif status_code >= 400 and status_code < 500:
            err_msg = "HTTP Client Error"
            _log_error_message()
        elif status_code >= 500 and status_code < 600:
            err_msg = "HTTP Server Error"
            _log_error_message()
        else:
            err_msg = "HTTP Error"
            _log_error_message()

    def _get_retry_after(self, headers: Dict) -> int:
        """
        This function returns the retry after time for the API calls.

        Args:
            headers (Dict): Dictionary containing the headers.

        Returns:
            int: Retry after time in seconds.
        """
        retry_after = headers.get("X-RateLimit-Reset", None)
        if retry_after:
            retry_after = int(retry_after) - int(datetime.now().timestamp())
        else:
            retry_after = DEFAULT_SLEEP_TIME
        return retry_after

    def _handle_rate_limit(self, retry_after: int):
        """
        This function handles the rate limit for the API calls.

        Args:
            retry_after (int): Time to wait before retrying the API call.
        """
        time.sleep(retry_after)

    def get_auth_headers(
        self,
        access_token: str,
        api_version: int = ONE,
    ) -> Dict:
        """
        This function returns the authorization headers for the API calls.

        Args:
            access_token (str): Access token for the API calls.
            api_version (int): API version.

        Returns:
            Dict: Dictionary containing the authorization headers.
        """
        return {
            "Authorization": f"Bearer {access_token}",
            "Accept": f"application/json;version={api_version}",
            "Content-Type": "application/json",
        }

    def get_configuration_parameters(
        self,
        configuration: Dict,
    ) -> Tuple[str, str, str, str, Literal["yes", "no"]]:
        """
        This function retrieves the configuration parameters from the
        configuration dictionary.

        Args:
            configuration (Dict): The dictionary containing the configuration
                parameters.

        Returns:
            A tuple containing the configuration parameters in the following
                order: api_base_url, oauth_url, client_id, client_secret,
                pull_device_tags.
        """
        api_base_url = configuration.get("api_base_url").strip().strip("/")
        oauth_url = configuration.get("oauth_url").strip().strip("/")
        client_id = configuration.get("client_id")
        client_secret = configuration.get("client_secret")
        pull_device_tags = configuration.get("pull_device_tags")
        return (
            api_base_url,
            oauth_url,
            client_id,
            client_secret,
            pull_device_tags
        )

    def generate_access_token_and_update_storage(
        self,
        oauth_url: str,
        client_id: str,
        client_secret: str,
        verify: any,
        proxies: any,
        storage: Dict,
    ) -> str:
        logger_msg = f"generating access token for {PLATFORM_NAME} platform"
        try:
            url = GENERATE_ACCESS_TOKEN_ENDPOINT.format(
                base_url=oauth_url
            )
            auth_string = f"{client_id}:{client_secret}"
            auth_string = base64.b64encode(auth_string.encode()).decode()
            headers = {
                "Authorization": f"Basic {auth_string}",
                "Content-Type": "application/x-www-form-urlencoded",
            }
            response = self.api_helper(
                logger_msg=logger_msg,
                url=url,
                method=POST,
                headers=headers,
                data={
                    "grant_type": "client_credentials",
                },
                verify=verify,
                proxies=proxies,
                storage=storage,
                configuration={
                    "oauth_url": oauth_url,
                    "client_id": client_id,
                    "client_secret": client_secret,
                },
                is_validation=False,
                is_handle_error_required=True,
                regenerate_access_token=False,
            )
            access_token = response.get("access_token")
            storage.update({"access_token": access_token})
            return access_token
        except OmnissaWorkspaceOneUEMPluginException:
            raise
        except Exception as err:
            err_msg = (
                f"Unexpected error occurred while generating access token."
                f" Error: {err}"
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=traceback.format_exc(),
            )
            raise OmnissaWorkspaceOneUEMPluginException(err_msg)

    def generate_config_hash(self, config_string: str):
        """
        This function generates a hash of the configuration string.

        Args:
            config_string (str): The configuration string.

        Returns:
            str: The hash of the configuration string.
        """
        return hashlib.sha256(config_string.encode()).hexdigest()
