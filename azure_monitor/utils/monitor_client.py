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

Microsoft Azure Monitor Client.
"""


import hashlib
import requests
import traceback
import json
import time
from typing import Dict, Tuple, Union

from netskope.common.utils import add_user_agent
from requests.models import Response
from .monitor_exceptions import (
    MicrosoftAzureMonitorPluginException,
)
from .monitor_constants import (
    API_SCOPE,
    GENERATE_TOKEN_BASE_URL,
    GRANT_TYPE,
    MODULE_NAME,
    MAX_RETRIES,
    PLUGIN_NAME,
    RETRY_SLEEP_TIME,
    MAX_WAIT_TIME,
    RETRY_ERROR_MSG,
    NO_MORE_RETRIES_ERROR_MSG,
)


class AzureMonitorClient:
    """Microsoft Azure Monitor Client Class."""

    def __init__(
        self,
        logger,
        verify_ssl,
        proxy,
        log_prefix,
        plugin_name,
        plugin_version,
    ):
        """Initialize."""
        self.logger = logger
        self.verify_ssl = verify_ssl
        self.proxy = proxy
        self.log_prefix = log_prefix
        self.plugin_name = plugin_name
        self.plugin_version = plugin_version

        if str(self.verify_ssl).lower() == "true":
            self.verify_ssl = True
        else:
            self.verify_ssl = False

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
        configuration: Dict = None,
        data: Dict = None,
        headers: Dict = None,
        storage: Dict = None,
        verify=True,
        proxies=None,
        json: Dict = None,
        is_validation: bool = False,
        is_handle_error_required: bool = True,
        regenerate_auth_token=True,
    ):
        """API Helper perform API request to ThirdParty platform
        and captures all the possible errors for requests.

        Args:
            logger_msg (str): Logger message.
            url (str): URL.
            method (str, optional): HTTP method. Defaults to "GET".
            params (Any, optional): Parameters. Defaults to None.
            configuration (Dict, optional): Configuration. Defaults to None.
            data (Dict, optional): Data. Defaults to None.
            headers (Dict, optional): Headers. Defaults to None.
            storage (Dict, optional): Storage. Defaults to None.
            verify (bool, optional): Verify. Defaults to True.
            proxies (dict, optional): Proxies. Defaults to None.
            json (dict, optional): JSON. Defaults to None.
            is_validation (bool, optional): Is validation. Defaults to False.
            is_handle_error_required (bool, optional): Does the API helper
                should handle the status codes? Defaults to True.
            regenerate_auth_token (bool, optional): Is regenerating auth token
                required? Defaults to True.

        Returns:
            dict: Response dictionary.
        """
        try:
            headers = self._add_user_agent(headers)
            debug_log_msg = (
                f"{self.log_prefix}: API Request for {logger_msg}. "
                f"Endpoint: {method} {url}"
            )
            if params:
                debug_log_msg += f", params: {params}."
            self.logger.debug(debug_log_msg)
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
                if (
                    status_code == 401
                    and regenerate_auth_token
                ):
                    (
                        tenant_id,
                        app_id,
                        app_secret,
                        *_
                    ) = self.get_configuration_parameters(configuration)

                    auth_header = self.generate_auth_token(
                        tenant_id=tenant_id,
                        app_id=app_id,
                        app_secret=app_secret,
                        is_validation=is_validation,
                    )
                    storage.update(
                        {
                            "auth_header": auth_header,
                        }
                    )
                    headers.update(auth_header)
                    return self.api_helper(
                        url=url,
                        method=method,
                        params=params,
                        headers=headers,
                        json=json,
                        data=data,
                        verify=verify,
                        proxies=proxies,
                        storage=storage,
                        configuration=configuration,
                        is_handle_error_required=is_handle_error_required,
                        is_validation=is_validation,
                        logger_msg=logger_msg,
                        regenerate_auth_token=False,
                    )
                elif not is_validation and (
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
                        raise MicrosoftAzureMonitorPluginException(
                            err_msg
                        )
                    if status_code == 429:
                        error_reason = "API rate limit exceeded"
                    else:
                        error_reason = "HTTP server error occurred"
                    retry_after = self._get_retry_after(
                        headers=response.headers
                    )
                    if retry_after is None:
                        self.logger.info(
                            f"{self.log_prefix}: No Retry-After value "
                            f"received from API hence plugin will "
                            f"retry after {RETRY_SLEEP_TIME} seconds."
                        )
                        time.sleep(RETRY_SLEEP_TIME)
                        continue
                    diff_retry_after = round(abs(retry_after - time.time()), 2)
                    if diff_retry_after > MAX_WAIT_TIME:
                        err_msg = (
                            f"'Retry-After' value received from "
                            f"response headers while {logger_msg} "
                            f"is greater than {MAX_WAIT_TIME} "
                            f"seconds hence returning status code "
                            f"{status_code}."
                        )
                        self.logger.error(
                            message=f"{self.log_prefix}: {err_msg}"
                        )
                        raise MicrosoftAzureMonitorPluginException(err_msg)
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
                    time.sleep(diff_retry_after)
                else:
                    return (
                        self.handle_error(
                            response=response,
                            logger_msg=logger_msg,
                            is_validation=is_validation,
                        ) if is_handle_error_required else response
                    )

        except MicrosoftAzureMonitorPluginException:
            raise
        except requests.exceptions.ReadTimeout as error:
            err_msg = f"Read Timeout error occurred while {logger_msg}."
            if is_validation:
                err_msg = "Read Timeout error occurred."

            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {error}",
                details=str(traceback.format_exc()),
                resolution=(
                    f"Ensure that {PLUGIN_NAME} is reachable."
                ),
            )
            raise MicrosoftAzureMonitorPluginException(err_msg)
        except requests.exceptions.ProxyError as error:
            err_msg = (
                f"Proxy error occurred while {logger_msg}. Verify the "
                "proxy configuration provided."
            )
            if is_validation:
                err_msg = (
                    "Proxy error occurred. Verify the proxy configuration "
                    "provided."
                )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {error}",
                details=str(traceback.format_exc()),
                resolution=(
                    "Ensure that the proxy configuration provided is "
                    "correct and the proxy server is reachable."
                ),
            )
            raise MicrosoftAzureMonitorPluginException(err_msg)
        except requests.exceptions.ConnectionError as error:
            err_msg = (
                f"Unable to establish connection with {PLUGIN_NAME} "
                f"while {logger_msg}. Proxy server or "
                f"{PLUGIN_NAME} is not reachable."
            )
            if is_validation:
                err_msg = (
                    f"Unable to establish connection with {PLUGIN_NAME} "
                    f"while {logger_msg}. Proxy server or {PLUGIN_NAME} "
                    "is not reachable."
                )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {error}",
                details=str(traceback.format_exc()),
                resolution=(
                    "Ensure that the DCE URI provided in "
                    "configuration parameter is correct."
                ),
            )
            raise MicrosoftAzureMonitorPluginException(err_msg)
        except requests.HTTPError as error:
            err_msg = f"HTTP error occurred while {logger_msg}."
            if is_validation:
                err_msg = (
                    "HTTP error occurred. Verify configuration parameters "
                    "provided."
                )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {error}",
                details=str(traceback.format_exc()),
                resolution=(
                    "Ensure that the provided configuration parameters "
                    "are correct."
                ),
            )
            raise MicrosoftAzureMonitorPluginException(err_msg)
        except Exception as error:
            err_msg = f"Unexpected error occurred while {logger_msg}."
            if is_validation:
                err_msg = (
                    "Unexpected error while performing API call to"
                    f" {PLUGIN_NAME}."
                )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {error}",
                details=str(traceback.format_exc()),
                resolution=(
                    "Ensure that the provided configuration parameters "
                    "are correct."
                )
            )
            raise MicrosoftAzureMonitorPluginException(err_msg)

    def parse_response(
        self,
        response: Response,
        logger_msg: str,
        is_validation: bool,
    ):
        """
        Parse API Response will return JSON from response object.

        Args:
            response (response): Response object.
            logger_msg (str): Logger message.
            is_validation (bool): Is validation.

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
                    "Verify the configuration parameters provided. "
                    "Check logs for more details."
                )
            raise MicrosoftAzureMonitorPluginException(err_msg)
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
                    "Unexpected validation error occurred. "
                    "Verify the configuration parameters provided. "
                    "Check logs for more details."
                )
            raise MicrosoftAzureMonitorPluginException(err_msg)

    def handle_error(
        self,
        response: Response,
        logger_msg: str,
        is_validation: bool,
    ) -> Dict:
        """Handle the different HTTP response code.

        Args:
            response (requests.models.Response): Response object returned
                from API call.
            logger_msg (str): Logger message.
            is_validation (bool): Is validation.
        Returns:
            dict: Returns the dictionary of response JSON when the
                response code is 200.
        Raises:
            MicrosoftAzureMonitorPluginException: When the response code
            is not in 200 range.
        """
        status_code = response.status_code
        validation_msg = "Validation error occurred, "
        error_dict = {
            400: "Received exit code 400, Bad Request. ",
            403: "Received exit code 403, Forbidden. ",
            401: "Received exit code 401, Unauthorized access. ",
            404: "Received exit code 404, Resource not found. ",
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
                raise MicrosoftAzureMonitorPluginException(err_msg)
            else:
                err_msg = err_msg + " while " + logger_msg + "."
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg}",
                    details=f"API response: {response.text}",
                    resolution=resolution,
                )
                raise MicrosoftAzureMonitorPluginException(err_msg)

        if status_code in [200, 201, 202]:
            return self.parse_response(
                response=response,
                logger_msg=logger_msg,
                is_validation=is_validation,
            )
        elif status_code == 204:
            return {}
        elif status_code in error_dict:
            error_response = self.parse_response(
                response=response,
                logger_msg=logger_msg,
                is_validation=is_validation,
            )
            error_val = error_response.get("error", {})
            err_msg = error_dict[status_code]
            if isinstance(error_val, dict):
                err_code = error_val.get("code")
                err_message = error_val.get("message")
                if err_code == "InvalidStream":
                    err_msg = err_msg + "Invalid Custom Log Table Name found."
                    resolution_msg = (
                        "Ensure that the Custom Log Table Name exists "
                        "in your Log Analytics Workspace."
                    )
                elif err_code == "NotFound":
                    err_msg = err_msg + "Invalid DCR Immutable ID found."
                    resolution_msg = (
                        "Ensure that the DCR Immutable ID provided in "
                        "the configuration parameters is correct for "
                        "data collection rule."
                    )
                elif err_code == "InvalidDcrImmutableId":
                    err_msg = err_msg + "Invalid DCR Immutable ID found."
                    resolution_msg = (
                        "Ensure that the DCE URI and DCR Immutable ID "
                        "are in the same region."
                    )
                elif err_code == "OperationFailed":
                    err_msg = err_msg + "Operation Failed."
                    resolution_msg = (
                        "Ensure that you have the correct permissions "
                        "for your application to the DCR and the permissions "
                        "are assigned to the same application for which the "
                        "Application credentials are provided."
                    )
                elif err_message:
                    err_msg = err_msg + err_message
                    resolution_msg = None
                else:
                    err_msg = err_msg + (
                        "Verify the configuration parameters provided. "
                        "Check logs for more details."
                    )
                    resolution_msg = None
            elif isinstance(error_val, str):
                text_response = response.text
                if "90002" in text_response:
                    err_msg = err_msg + (
                        "Invalid Directory (tenant) ID provided in "
                        "the configuration parameters."
                    )
                    resolution_msg = (
                        "Ensure that the Directory (tenant) ID provided in "
                        "the configuration parameters is correct."
                    )
                elif "700016" in text_response:
                    err_msg = err_msg + (
                        "Invalid Application (client) ID provided in "
                        "the configuration parameters."
                    )
                    resolution_msg = (
                        "Ensure that the Application (client) ID provided in "
                        "the configuration parameters is correct."
                    )
                elif "7000215" in text_response:
                    err_msg = err_msg + (
                        "Invalid Client Secret provided in "
                        "the configuration parameters."
                    )
                    resolution_msg = (
                        "Ensure that the Client Secret provided in "
                        "the configuration parameters is correct."
                    )
                else:
                    err_msg = err_msg + (
                        "Invalid Directory (tenant) ID, "
                        "Application (client) ID, or Client Secret provided "
                        "in the configuration parameters."
                    )
                    resolution_msg = (
                        "Ensure that the Directory (tenant) ID, "
                        "Application (client) ID, or Client Secret "
                        "provided in the configuration parameters is correct."
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

    def generate_auth_token(
        self,
        tenant_id: str,
        app_id: str,
        app_secret: str,
        is_validation: bool = False,
    ) -> Dict:
        """
        Generate authentication header for Microsoft Azure Monitor.

        Args:
            tenant_id (str): Tenant ID.
            app_id (str): App ID.
            app_secret (str): App secret.
            is_validation (bool): Is validation.

        Returns:
            dict: Authentication header.
        """
        try:
            url = GENERATE_TOKEN_BASE_URL.format(tenant_id=tenant_id)
            body = {
                "client_id": app_id,
                "client_secret": app_secret,
                "scope": API_SCOPE,
                "grant_type": GRANT_TYPE,
            }
            headers = {
                "Content-Type": "application/x-www-form-urlencoded",
            }
            logger_msg = "generating access token"
            response = self.api_helper(
                method="POST",
                url=url,
                headers=headers,
                data=body,
                verify=self.verify_ssl,
                proxies=self.proxy,
                logger_msg=logger_msg,
                is_validation=is_validation,
                regenerate_auth_token=False,
            )
            auth_token = response.get("access_token")
            if not auth_token:
                err_msg = (
                    f"Unable to get access token from {PLUGIN_NAME}. "
                    "Verify the provided configuration parameters."
                )
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg}",
                    details=str(response.text),
                )
                raise MicrosoftAzureMonitorPluginException(err_msg)
            return {
                "Authorization": f"Bearer {auth_token}",
                "Content-Type": "application/json"
            }
        except MicrosoftAzureMonitorPluginException:
            raise
        except Exception as exp:
            err_msg = (
                "Unexpected error occurred while generating access token."
            )
            if is_validation:
                err_msg = (
                    "Unexpected validation error occurred "
                    "while generating access token."
                )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {exp}",
                details=str(traceback.format_exc()),
            )
            raise MicrosoftAzureMonitorPluginException(err_msg)

    def _get_retry_after(self, headers: Dict) -> int:
        """
        Get the retry after value from the headers.

        Args:
            headers (Dict): Headers.

        Returns:
            int: Retry after value.
        """
        return int(headers.get("Retry-After", RETRY_SLEEP_TIME))

    def get_configuration_parameters(
        self, configuration: Dict
    ) -> Tuple[str, str, str, str, str, str]:
        """
        Get the configuration parameters.

        Args:
            configuration (Dict): Configuration.

        Returns:
            Tuple[str, str, str, str, str, str]: Tenant ID, App ID, \
                App Secret, DCE URI, DCR Immutable ID, \
                Custom Log Table Name, Log Source Identifier.
        """
        tenant_id = configuration.get("tenantid").strip()
        app_id = configuration.get("appid").strip()
        app_secret = configuration.get("appsecret")
        dce_uri = configuration.get("dce_uri").strip()
        dcr_immutable_id = configuration.get("dcr_immutable_id").strip()
        custom_log_table_name = configuration.get(
            "custom_log_table_name"
        ).strip()
        log_source_identifier = configuration.get(
            "log_source_identifier"
        ).strip()
        return (
            tenant_id,
            app_id,
            app_secret,
            dce_uri,
            dcr_immutable_id,
            custom_log_table_name,
            log_source_identifier,
        )

    def hash_string(self, string: str) -> str:
        """Hash the string using SHA-256.
        Args:
            string (str): String to hash.

        Returns:
            str: Hashed string.
        """
        return hashlib.sha256(string.encode()).hexdigest()
