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

Microsoft Azure Log Analytics Client.
"""


import hashlib
import re
import requests
import traceback
import json
import time
from typing import Dict, Tuple, Union

from netskope.common.utils import add_user_agent
from requests.models import Response
from .log_analytics_exception import (
    MicrosoftAzureLogAnalyticsPluginException,
)
from .log_analytics_helper import (
    normalize_authority_host,
    normalize_token_scope,
)
from .log_analytics_constants import (
    AADSTS_CODE_RE,
    AADSTS_CROSS_CLOUD_CODES,
    AADSTS_INVALID_APP_CODE,
    AADSTS_INVALID_SECRET_CODE,
    AADSTS_INVALID_TENANT_CODES,
    AADSTS_TENANT_NOT_FOUND_CODE,
    AZURE_CLOUD_CUSTOM,
    AZURE_CLOUD_ENVIRONMENTS,
    AZURE_CLOUD_PUBLIC,
    CONFIG_CUSTOM_AUTHORITY_HOST,
    CONFIG_CUSTOM_TOKEN_SCOPE,
    GENERATE_TOKEN_BASE_URL,
    GRANT_TYPE,
    MODULE_NAME,
    MAX_RETRIES,
    PLUGIN_NAME,
    RETRY_SLEEP_TIME,
    MAX_WAIT_TIME,
    RETRY_ERROR_MSG,
    NO_MORE_RETRIES_ERROR_MSG,
    INGESTION_MODE_SINGLE_TABLE,
    INGESTION_MODE_PER_DATA_TYPE,
    SUPPORTED_DATA_TYPES,
    PER_DATA_TYPE_TABLE_KEY,
    CONFIG_DATA_TYPES,
)


class AzureLogAnalyticsClient:
    """Microsoft Azure LogAnalytics Client Class."""

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
                    parsed_config = self.get_configuration_parameters(
                        configuration
                    )
                    auth_header = self.generate_auth_token(
                        parsed_config=parsed_config,
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
                        raise MicrosoftAzureLogAnalyticsPluginException(
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
                    if retry_after > MAX_WAIT_TIME:
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
                        raise MicrosoftAzureLogAnalyticsPluginException(
                            err_msg
                        )
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
                    time.sleep(retry_after)
                else:
                    return (
                        self.handle_error(
                            response=response,
                            logger_msg=logger_msg,
                            is_validation=is_validation,
                        ) if is_handle_error_required else response
                    )

        except MicrosoftAzureLogAnalyticsPluginException:
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
            raise MicrosoftAzureLogAnalyticsPluginException(err_msg)
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
            raise MicrosoftAzureLogAnalyticsPluginException(err_msg)
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
            raise MicrosoftAzureLogAnalyticsPluginException(err_msg)
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
            raise MicrosoftAzureLogAnalyticsPluginException(err_msg)
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
            raise MicrosoftAzureLogAnalyticsPluginException(err_msg)

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
            raise MicrosoftAzureLogAnalyticsPluginException(err_msg)
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
            raise MicrosoftAzureLogAnalyticsPluginException(err_msg)

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
            MicrosoftAzureLogAnalyticsPluginException: When the response code
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
                raise MicrosoftAzureLogAnalyticsPluginException(err_msg)
            else:
                err_msg = err_msg + " while " + logger_msg + "."
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg}",
                    details=f"API response: {response.text}",
                    resolution=resolution,
                )
                raise MicrosoftAzureLogAnalyticsPluginException(err_msg)

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
            resolution_msg = None
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
                aadsts_code = self._get_aadsts_code(
                    error_response, response.text
                )
                if aadsts_code in AADSTS_CROSS_CLOUD_CODES:
                    err_msg = err_msg + (
                        "The Microsoft Entra ID application does not belong "
                        "to the selected Azure Cloud."
                    )
                    resolution_msg = (
                        "Ensure that the 'Azure Cloud' matches the cloud in "
                        "which the Microsoft Entra ID application is "
                        "registered. Select 'Custom Cloud' if your Azure "
                        "cloud is not listed."
                    )
                elif aadsts_code == AADSTS_TENANT_NOT_FOUND_CODE:
                    err_msg = err_msg + (
                        "Directory (tenant) ID not found in the selected "
                        "Azure Cloud."
                    )
                    resolution_msg = (
                        "Ensure that the Directory (tenant) ID provided in "
                        "the configuration parameters is correct and the "
                        "'Azure Cloud' matches the cloud in which the "
                        "tenant exists."
                    )
                elif aadsts_code in AADSTS_INVALID_TENANT_CODES:
                    err_msg = err_msg + (
                        "Invalid Directory (tenant) ID provided in "
                        "the configuration parameters."
                    )
                    resolution_msg = (
                        "Ensure that the Directory (tenant) ID provided in "
                        "the configuration parameters is correct."
                    )
                elif aadsts_code == AADSTS_INVALID_APP_CODE:
                    err_msg = err_msg + (
                        "Invalid Application (client) ID provided in "
                        "the configuration parameters."
                    )
                    resolution_msg = (
                        "Ensure that the Application (client) ID provided in "
                        "the configuration parameters is correct."
                    )
                elif aadsts_code == AADSTS_INVALID_SECRET_CODE:
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
                        "provided in the configuration parameters is correct "
                        "and the 'Azure Cloud' matches the cloud in which "
                        "the Microsoft Entra ID application is registered."
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

    @staticmethod
    def _get_aadsts_code(
        error_response: Union[Dict, None], response_text: str
    ) -> Union[str, None]:
        """Extract the Microsoft Entra ID error code (AADSTS<code>) from
        the token endpoint error response.

        Args:
            error_response (dict): Parsed error response.
            response_text (str): Raw error response.

        Returns:
            str: The numeric code (e.g. "900382"), None if not found.
        """
        description = (
            error_response.get("error_description")
            if isinstance(error_response, dict)
            else None
        )
        for text in (description, response_text):
            match = re.search(AADSTS_CODE_RE, str(text or ""))
            if match:
                return match.group(1)
        return None

    def get_cloud_endpoints(self, parsed_config: Dict) -> Tuple[str, str]:
        """Resolve the Microsoft Entra ID authority host and the token
        scope for the configured Azure cloud.

        Args:
            parsed_config (Dict): Output of
                :meth:`get_configuration_parameters`.

        Returns:
            Tuple[str, str]: (authority host, token scope).

        Raises:
            MicrosoftAzureLogAnalyticsPluginException: If the Azure cloud is
                unknown or the custom cloud values are invalid.
        """
        azure_cloud = parsed_config["azure_cloud"]
        if azure_cloud == AZURE_CLOUD_CUSTOM:
            login_host = normalize_authority_host(
                parsed_config.get(CONFIG_CUSTOM_AUTHORITY_HOST)
            )
            scope = normalize_token_scope(
                parsed_config.get(CONFIG_CUSTOM_TOKEN_SCOPE)
            )
            if not (login_host and scope):
                err_msg = (
                    "Invalid 'Custom Authority Host' or 'Custom Token Scope' "
                    "provided in the configuration parameters."
                )
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg}",
                    resolution=(
                        "Ensure that 'Custom Authority Host' is a valid "
                        "hostname and 'Custom Token Scope' is a valid https "
                        "URL."
                    ),
                )
                raise MicrosoftAzureLogAnalyticsPluginException(err_msg)
            return login_host, scope

        cloud = AZURE_CLOUD_ENVIRONMENTS.get(azure_cloud)
        if not cloud:
            err_msg = (
                "Invalid value provided for the configuration parameter "
                "'Azure Cloud'."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                resolution="Select a valid value for 'Azure Cloud'.",
            )
            raise MicrosoftAzureLogAnalyticsPluginException(err_msg)
        return cloud["login_host"], cloud["scope"]

    def generate_auth_token(
        self,
        parsed_config: Dict,
        is_validation: bool = False,
    ) -> Dict:
        """
        Generate authentication header for Microsoft Azure LogAnalytics.

        The access token is requested from the Microsoft Entra ID endpoint
        of the configured Azure cloud.

        Args:
            parsed_config (Dict): Output of
                :meth:`get_configuration_parameters`.
            is_validation (bool): Is validation.

        Returns:
            dict: Authentication header.
        """
        try:
            login_host, scope = self.get_cloud_endpoints(parsed_config)
            url = GENERATE_TOKEN_BASE_URL.format(
                login_host=login_host, tenant_id=parsed_config["tenant_id"]
            )
            body = {
                "client_id": parsed_config["app_id"],
                "client_secret": parsed_config["app_secret"],
                "scope": scope,
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
                    details=str(response),
                )
                raise MicrosoftAzureLogAnalyticsPluginException(err_msg)
            return {
                "Authorization": f"Bearer {auth_token}",
                "Content-Type": "application/json"
            }
        except MicrosoftAzureLogAnalyticsPluginException:
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
            raise MicrosoftAzureLogAnalyticsPluginException(err_msg)

    def _get_retry_after(self, headers: Dict):
        """
        Get the retry after value from the headers.

        Args:
            headers (Dict): Headers.

        Returns:
            int | None: Seconds to wait, or None if header is absent.
        """
        value = headers.get("Retry-After", RETRY_SLEEP_TIME)
        if value is None:
            return None
        try:
            return int(value)
        except (ValueError, TypeError):
            return RETRY_SLEEP_TIME

    @staticmethod
    def _safe_str(value) -> str:
        """Return a stripped string, treating None as empty."""
        if value is None:
            return ""
        if isinstance(value, str):
            return value.strip()
        return value

    def get_configuration_parameters(self, configuration: Dict) -> Dict:
        """
        Parse the plugin configuration into a normalized dictionary.

        Returns:
            dict with keys:
                tenant_id, app_id, app_secret, azure_cloud,
                custom_authority_host, custom_token_scope (custom cloud
                only), dce_uri (without trailing slash), dcr_immutable_id,
                log_source_identifier, ingestion_mode,
                single_table_name (str, single_table mode only),
                data_types (list[str], per_data_type mode only; the data
                types selected in 'Data Types to Ingest'),
                tables (dict[data_type -> table_name], per_data_type only).
        """
        configuration = configuration or {}
        ingestion_mode = self._safe_str(
            configuration.get("ingestion_mode")
        ) or INGESTION_MODE_SINGLE_TABLE

        dce_uri = self._safe_str(configuration.get("dce_uri"))
        if isinstance(dce_uri, str):
            dce_uri = dce_uri.rstrip("/")
        azure_cloud = self._safe_str(
            configuration.get("azure_cloud")
        ) or AZURE_CLOUD_PUBLIC

        parsed = {
            "tenant_id": self._safe_str(configuration.get("tenantid")),
            "app_id": self._safe_str(configuration.get("appid")),
            "app_secret": configuration.get("appsecret"),
            "azure_cloud": azure_cloud,
            CONFIG_CUSTOM_AUTHORITY_HOST: "",
            CONFIG_CUSTOM_TOKEN_SCOPE: "",
            "dce_uri": dce_uri,
            "dcr_immutable_id": self._safe_str(
                configuration.get("dcr_immutable_id")
            ),
            "log_source_identifier": self._safe_str(
                configuration.get("log_source_identifier")
            ) or "Netskope CE",
            "ingestion_mode": ingestion_mode,
            "single_table_name": "",
            "data_types": [],
            "tables": {},
        }

        # The custom cloud values are ignored for the other Azure clouds.
        if azure_cloud == AZURE_CLOUD_CUSTOM:
            for key in (
                CONFIG_CUSTOM_AUTHORITY_HOST, CONFIG_CUSTOM_TOKEN_SCOPE
            ):
                parsed[key] = self._safe_str(configuration.get(key))

        if ingestion_mode == INGESTION_MODE_PER_DATA_TYPE:
            parsed["tables"] = {
                dt: self._safe_str(configuration.get(key))
                for dt, key in PER_DATA_TYPE_TABLE_KEY.items()
            }
            selected = configuration.get(CONFIG_DATA_TYPES) or []
            if isinstance(selected, str):
                selected = [selected]
            parsed["data_types"] = [
                dt for dt in SUPPORTED_DATA_TYPES if dt in selected
            ]
        else:
            parsed["single_table_name"] = self._safe_str(
                configuration.get("custom_log_table_name")
            )

        return parsed

    def table_name_for(self, parsed_config: Dict, data_type: str) -> str:
        """Resolve the destination custom log table name for a data_type
        given the parsed configuration dict.

        Returns an empty string if no table is configured for this data_type
        (e.g. per_data_type mode with no table name provided for it).
        """
        if parsed_config.get("ingestion_mode") == INGESTION_MODE_PER_DATA_TYPE:
            return parsed_config.get("tables", {}).get(data_type, "")
        return parsed_config.get("single_table_name", "")

    def config_hash_input(self, parsed_config: Dict) -> str:
        """Build the deterministic string used to detect configuration drift
        for cached auth headers. All configured table names participate so
        that changing any of them invalidates the cached token."""
        tables = parsed_config.get("tables") or {}
        return (
            f"{parsed_config.get('tenant_id','')}"
            f"{parsed_config.get('app_id','')}"
            f"{parsed_config.get('app_secret','')}"
            f"{parsed_config.get('azure_cloud','')}"
            f"{parsed_config.get(CONFIG_CUSTOM_AUTHORITY_HOST, '')}"
            f"{parsed_config.get(CONFIG_CUSTOM_TOKEN_SCOPE, '')}"
            f"{parsed_config.get('dce_uri','')}"
            f"{parsed_config.get('dcr_immutable_id','')}"
            f"{parsed_config.get('ingestion_mode','')}"
            f"{parsed_config.get('single_table_name','')}"
            f"{tables.get('alerts','')}"
            f"{tables.get('events','')}"
            f"{tables.get('webtx','')}"
        )

    def hash_string(self, string: str) -> str:
        """Hash the string using SHA-256.
        Args:
            string (str): String to hash.

        Returns:
            str: Hashed string.
        """
        return hashlib.sha256(string.encode()).hexdigest()

    def get_or_refresh_auth_header(
        self,
        parsed_config: Dict,
        storage: Union[Dict, None] = None,
        is_validation: bool = False,
    ):
        """Return a cached auth header (or regenerate it) alongside the
        ``storage`` dict it lives on.

        The cache is invalidated whenever any of the auth parameters,
        the ingestion mode, or any configured table name changes — see
        :meth:`config_hash_input`.

        Args:
            parsed_config (Dict): Output of
                :meth:`get_configuration_parameters`.
            storage (Dict, optional): The plugin-level storage dict.
                Mutated in place when the cache is refreshed. A fresh
                dict is created if ``None``.
            is_validation (bool): Whether this call originates from
                ``validate``; controls error-message phrasing.

        Returns:
            Tuple[Dict, Dict]: ``(auth_header, storage)``.
        """
        if storage is None:
            storage = {}
        current_config_hash = self.hash_string(
            self.config_hash_input(parsed_config)
        )
        auth_header = storage.get("auth_header")
        if auth_header and storage.get("config_hash") == current_config_hash:
            return auth_header, storage
        auth_header = self.generate_auth_token(
            parsed_config=parsed_config,
            is_validation=is_validation,
        )
        storage.update(
            {
                "auth_header": auth_header,
                "config_hash": current_config_hash,
            }
        )
        return auth_header, storage
