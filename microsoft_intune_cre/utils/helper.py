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

CRE Microsoft Intune Plugin helper module
"""

import hashlib
import time
import traceback
from datetime import datetime
from typing import Any, Dict, Tuple, Union

import requests
from netskope.common.utils import add_user_agent
from requests.models import Response

from .constants import (
    DATETIME_FORMAT,
    DEFAULT_SLEEP_TIME,
    MAX_RETRIES,
    MODULE_NAME,
    NO_MORE_RETRIES_ERROR_MSG,
    OAUTH_SCOPE,
    OAUTH_URL,
    PLATFORM_NAME,
    RETRY_ERROR_MSG,
)
from .exceptions import MicrosoftIntunePluginException, exception_handler
from .parser import MicrosoftIntuneParser


class MicrosoftIntuneHelper:
    def __init__(
        self,
        logger,
        log_prefix: str,
        plugin_name: str,
        plugin_version: str,
        parser: MicrosoftIntuneParser,
    ):
        """MicrosoftIntuneHelper initializer.

        Args:
            logger (logger object): Logger object.
            log_prefix (str): log prefix.
            plugin_name (str): Plugin name.
            plugin_version (str): Plugin version.
            parser (MicrosoftIntuneParser): Parser object.
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
    ):
        """
        Make API call to Microsoft Intune.

        Args:
            logger_msg (str): Logger message.
            url (str): URL.
            method (str, optional): HTTP method. Defaults to "GET".
            params (Any, optional): Parameters. Defaults to None.
            data (Dict, optional): Data. Defaults to None.
            headers (Dict, optional): Headers. Defaults to None.
            verify (Any, optional): Verify. Defaults to True.
            proxies (Any, optional): Proxies. Defaults to None.
            json (Dict, optional): JSON. Defaults to None.
            storage (Dict, optional): Storage. Defaults to {}.
            configuration (Dict, optional): Configuration. Defaults to {}.
            is_validation (bool, optional): Is validation. Defaults to False.
            is_handle_error_required (bool, optional): Is handle error
                required. Defaults to True.
            regenerate_access_token (bool, optional): Regenerate access token.
                Defaults to True.

        Returns:
            Any: Response.
        """
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
                self.logger.debug(
                    f"{self.log_prefix}: Received API Response for "
                    f"{logger_msg}. Status Code={status_code}."
                )
                # Token regeneration logic
                if status_code == 401 and regenerate_access_token:
                    tenant_id, client_id, client_secret = (
                        self.get_configuration_parameters(
                            configuration
                        )
                    )
                    regenerated_access_token = (
                        self.generate_access_token(
                            client_id=client_id,
                            client_secret=client_secret,
                            tenant_id=tenant_id,
                            verify=verify,
                            proxies=proxies,
                            is_validation=is_validation,
                            context={}
                        )
                    )
                    storage.update(
                        {
                            "access_token": regenerated_access_token,
                        }
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
                        raise MicrosoftIntunePluginException(err_msg)
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
                            response=response,
                            logger_msg=logger_msg,
                            is_validation=is_validation,
                        ) if is_handle_error_required else response
                    )
        except MicrosoftIntunePluginException:
            raise
        except requests.exceptions.ReadTimeout as error:
            err_msg = f"Read Timeout error occurred while {logger_msg}."
            if is_validation:
                err_msg = "Read Timeout error occurred."

            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {error}",
                details=traceback.format_exc(),
                resolution=(
                    "Please check if your Microsoft Intune platform server"
                    " is reachable."
                ),
            )
            raise MicrosoftIntunePluginException(err_msg)
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
            raise MicrosoftIntunePluginException(err_msg)
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
                    "Please check if your Microsoft Intune platform server"
                    " is reachable."
                ),
            )
            raise MicrosoftIntunePluginException(err_msg)
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
            raise MicrosoftIntunePluginException(err_msg)
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
            raise MicrosoftIntunePluginException(err_msg)

    @exception_handler
    def generate_access_token(
        self,
        client_id: str,
        client_secret: str,
        tenant_id: str,
        verify: Any,
        proxies: Any,
        is_validation: bool,
        context: Dict = {}
    ) -> str:
        """
        Generate access token.

        Args:
            client_id (str): Client ID.
            client_secret (str): Client secret.
            tenant_id (str): Tenant ID.
            verify (Any): Verify.
            proxies (Any): Proxies.
            is_validation (bool): Is validation.
            context (Dict, optional): Context. Defaults to {}.

        Returns:
            str: Access token.
        """
        logger_msg = "generating access token"
        context["logger_msg"] = logger_msg
        response = self.api_helper(
            logger_msg=logger_msg,
            url=OAUTH_URL.format(tenant_id=tenant_id),
            method="POST",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            data={
                "grant_type": "client_credentials",
                "client_id": client_id,
                "client_secret": client_secret,
                "scope": OAUTH_SCOPE,
            },
            verify=verify,
            proxies=proxies,
            is_validation=is_validation,
            is_handle_error_required=True,
            regenerate_access_token=False,
        )
        return response.get("access_token", "")

    def handle_error(
        self,
        response: Response,
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
            MicrosoftIntunePluginException: When the response code is
            not in 200 range.
        """
        status_code = response.status_code
        validation_msg = "Validation error occurred, "
        error_dict = {
            400: "Received exit code 400, Bad Request",
            403: "Received exit code 403, Forbidden",
            401: "Received exit code 401, Unauthorized access",
            404: "Received exit code 404, Resource not found",
        }
        resolution_dict = {
            400: (
                "Verify the Tenant ID, Client ID and Client Secret provided"
                " in the configuration parameters."
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
                "Verify the resource you are trying to access is valid."
            ),
        }
        if is_validation:
            error_dict = {
                400: (
                    "Received exit code 400, Bad Request, "
                    "Verify the Tenant ID, Client ID and Client Secret"
                    " provided in the configuration parameters."
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
                    "Verify the resource you are trying to access is "
                    " valid."
                ),
            }

        def _log_error_message(resolution: str = None):
            nonlocal err_msg
            if is_validation:
                log_err_msg = validation_msg + err_msg
                self.logger.error(
                    message=f"{self.log_prefix}: {log_err_msg}",
                    details=f"API response: {response.text}",
                    resolution=resolution,
                )
                raise MicrosoftIntunePluginException(err_msg)
            else:
                err_msg = err_msg + " while " + logger_msg + "."
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg}",
                    details=f"API response: {response.text}",
                )
                raise MicrosoftIntunePluginException(err_msg)

        if status_code in [200, 201, 202]:
            return self.parser.parse_response(
                response=response,
                logger_msg=logger_msg,
                is_validation=is_validation,
            )
        elif status_code == 204:
            return {}
        elif status_code in error_dict:
            err_msg = error_dict[status_code]
            resolution_msg = resolution_dict[status_code]
            err_msg, resolution_msg = self._provide_resolution(
                response, err_msg, resolution_msg
            )
            _log_error_message(resolution=resolution_msg)
        elif status_code >= 400 and status_code < 500:
            err_msg = "HTTP Client Error"
            _log_error_message()
        elif status_code >= 500 and status_code < 600:
            err_msg = "HTTP Server Error"
            _log_error_message()
        else:
            err_msg = "HTTP Error"
            _log_error_message()

    def _provide_resolution(
        self, response: Response, err_msg: str, resolution: str
    ) -> Tuple[str, str]:
        """
        Provide resolution for the error.

        Args:
            response (Response): Response object.
            err_msg (str): Error message.
            resolution (str): Resolution.

        Returns:
            Tuple[str, str]: Error message and resolution.
        """
        text_response = response.text
        if "90002" in text_response:
            err_msg = (
                "Received exit code 400, Bad Request,"
                " Verify the Tenant ID provided in the"
                " configuration parameters."
            )
            resolution = (
                "Please provide a valid Tenant ID in the configuration"
                " parameters."
            )
        elif "700016" in text_response:
            err_msg = (
                "Received exit code 400, Bad Request,"
                " Verify the Client ID provided in the"
                " configuration parameters."
            )
            resolution = (
                "Please provide a valid Client ID in the configuration"
                " parameters."
            )
        elif "7000215" in text_response:
            err_msg = (
                "Received exit code 400, Bad Request,"
                " Verify the Client Secret provided in the"
                " configuration parameters."
            )
            resolution = (
                "Please provide a valid Client Secret in the configuration"
                " parameters."
            )
        return err_msg, resolution

    def _get_retry_after(self, headers) -> int:
        """
        Get the retry after value from the headers.

        Args:
            headers (Dict): Headers.

        Returns:
            int: Retry after value.
        """
        return int(headers.get("Retry-After", DEFAULT_SLEEP_TIME))

    def _handle_rate_limit(self, retry_after: int) -> None:
        """
        This function handles the rate limit for the API calls.

        Args:
            retry_after (int): Time to wait before retrying the API call.
        """
        time.sleep(retry_after)

    def get_configuration_parameters(
        self, configuration: Dict
    ) -> Tuple[str, str, str]:
        """
        Get the configuration parameters.

        Args:
            configuration (Dict): Configuration.

        Returns:
            Tuple[str, str, str]: Tenant ID, Client ID, Client Secret.
        """
        tenant_id = configuration.get("tenant_id")
        client_id = configuration.get("client_id")
        client_secret = configuration.get("client_secret")
        return tenant_id, client_id, client_secret

    def get_headers(self, access_token: str) -> Dict[str, str]:
        """Get the headers for the API call."""
        return {"Authorization": f"Bearer {access_token}"}

    def hash_string(self, string: str) -> str:
        """Hash the string."""
        return hashlib.sha256(string.encode()).hexdigest()

    def get_time_filter_parameter(
        self, query_params: Dict, datetime_object: Union[datetime, None]
    ) -> Dict:
        """
        Get the time filter parameter.

        Args:
            query_params (Dict): Query parameters.
            datetime_object (Union[datetime, None]): Datetime object.

        Returns:
            Dict: Query parameters.
        """
        if datetime_object:
            formatted_datetime_str = datetime.strftime(
                datetime_object, DATETIME_FORMAT
            )
            query_params[
                "$filter"
            ] = f"lastSyncDateTime ge {formatted_datetime_str}"
        return query_params
