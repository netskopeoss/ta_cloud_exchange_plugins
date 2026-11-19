"""
BSD 3-Clause License.

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

ServiceNow ITSM Plugin helper module.
"""

import json
import time
import traceback
from base64 import b64encode
from collections import namedtuple
from typing import Callable, Dict, List, Optional, Tuple, Union
from urllib.parse import urlparse

import requests
from netskope.common.utils import add_user_agent
from netskope.integrations.itsm.plugin_base import ValidationResult

from .constants import (
    CUSTOM_TABLE,
    DEFAULT_ASSIGNEE_FIELD,
    DEFAULT_ASSIGNMENT_GROUP_FIELD,
    DEFAULT_SEVERITY_FIELD,
    DEFAULT_STATUS_FIELD,
    DEFAULT_UPDATE_FIELD,
    DEFAULT_WAIT_TIME,
    MANAGER_LOOKUP_FIELDS,
    MAX_API_CALLS,
    MAX_RESPONSE_DETAILS_LENGTH,
    MAX_RETRY_AFTER,
    MODULE_NAME,
    PLATFORM_NAME,
    SYS_USER_ENDPOINT,
)
from .exceptions import ServiceNowITSMPluginException

# Resolved field names for the configured destination table.
TableConfig = namedtuple(
    "TableConfig",
    [
        "table",
        "status_field",
        "severity_field",
        "assignee_field",
        "assignment_group_field",
        "update_field",
    ],
)


class ServiceNowITSMPluginHelper(object):
    """ServiceNowITSMPluginHelper class.

    Provides reusable utilities for the ServiceNow ITSM plugin: building
    authenticated request headers, performing API requests with retry
    handling, parsing responses, validating configuration parameters, and
    resolving table/user metadata.
    """

    def __init__(
        self, logger, log_prefix: str, plugin_name: str, plugin_version: str
    ):
        """Initialize ServiceNowITSMPluginHelper.

        Args:
            logger (logger object): Logger object.
            log_prefix (str): Log prefix.
            plugin_name (str): Plugin name.
            plugin_version (str): Plugin version.
        """
        self.log_prefix = log_prefix
        self.logger = logger
        self.plugin_name = plugin_name
        self.plugin_version = plugin_version

    def _add_user_agent(self, headers: Union[Dict, None] = None) -> Dict:
        """Add User-Agent to the headers for ServiceNow requests.

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

    def _get_response_details(
        self, response: requests.models.Response
    ) -> str:
        """Return a log-safe representation of an HTTP response body.

        HTML error pages (e.g. a reverse-proxy page returned for an
        invalid instance URL) are replaced with a short notice, and large
        bodies are truncated so they do not flood the log details panel.

        Args:
            response (requests.models.Response): HTTP response object.

        Returns:
            str: Log-safe response body description.
        """
        content_type = response.headers.get("Content-Type", "")
        text = response.text.strip() if response.text else ""
        if "text/html" in content_type or text.lower().startswith(
            ("<!doctype", "<html")
        ):
            return (
                f"HTML response received from server (status code: "
                f"{response.status_code}). This usually indicates an "
                "invalid Instance URL."
            )
        if len(text) > MAX_RESPONSE_DETAILS_LENGTH:
            text = (
                text[:MAX_RESPONSE_DETAILS_LENGTH]
                + f"... [truncated, total {len(text)} chars]"
            )
        return f"API response: {text}"

    def _get_api_error_detail(
        self, response: requests.models.Response
    ) -> str:
        """Extract the specific error reason from a ServiceNow response.

        ServiceNow returns error responses in the form
        ``{"error": {"message": "...", "detail": "..."}, "status": ...}``.
        This method extracts that message/detail so the actual reason (e.g.
        an invalid field name or an ACL failure) is surfaced instead of only
        the HTTP status code.

        Args:
            response (requests.models.Response): HTTP response object.

        Returns:
            str: The API error detail with trailing punctuation stripped,
                or an empty string when none can be extracted.
        """
        try:
            body = response.json()
        except Exception:
            return ""
        if not isinstance(body, dict):
            return ""
        error = body.get("error")
        if isinstance(error, dict):
            detail = error.get("message") or error.get("detail") or ""
        elif isinstance(error, str):
            detail = error
        else:
            detail = body.get("message") or body.get("detail") or ""
        return str(detail).strip().rstrip(". ") if detail else ""

    def api_helper(
        self,
        logger_msg: str,
        url: str,
        method: str = "GET",
        params: Optional[Dict] = None,
        data=None,
        files=None,
        headers: Optional[Dict] = None,
        json=None,
        verify=True,
        proxies=None,
        is_handle_error_required=True,
        is_validation=False,
    ):
        """Perform an API request and capture all possible request errors.

        Retries up to MAX_API_CALLS times on HTTP 429 and 5xx responses,
        honouring the 'Retry-After' header when present.

        Args:
            logger_msg (str): Logger message describing the operation.
            url (str): API endpoint.
            method (str): HTTP method for the endpoint. Defaults to "GET".
            params (Dict, optional): Request query parameters. Defaults
                to {}.
            data (Any, optional): Data to be sent to API. Defaults to None.
            files (Any, optional): Files to be sent to API. Defaults to
                None.
            headers (Dict, optional): Headers for the request. Defaults
                to {}.
            json (optional): JSON payload for the request. Defaults to
                None.
            verify (bool, optional): Verify SSL. Defaults to True.
            proxies (Dict, optional): Proxies. Defaults to None.
            is_handle_error_required (bool, optional): Whether the helper
                should handle the status codes. Defaults to True.
            is_validation (bool, optional): Whether this request is coming
                from a validation method. Defaults to False.

        Returns:
            dict: Response dictionary, or the raw response object when
                is_handle_error_required is False.
        """
        try:
            params = params or {}
            headers = self._add_user_agent(headers or {})

            debug_log_msg = (
                f"{self.log_prefix}: API Request for {logger_msg}. "
                f"Endpoint: {method} {url}"
            )
            if params:
                debug_log_msg += f", params: {params}."
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
                    files=files,
                )
                status_code = response.status_code
                self.logger.debug(
                    f"{self.log_prefix}: Received API Response for "
                    f"{logger_msg}. Status Code={status_code}."
                )
                if (
                    status_code == 429 or 500 <= status_code <= 600
                ) and not is_validation:
                    api_err_msg = self._get_response_details(response)
                    if retry_counter == MAX_API_CALLS - 1:
                        err_msg = (
                            f"Received exit code {status_code}. Maximum "
                            f"retries exceeded while {logger_msg}. Hence, "
                            f"returning status code {status_code}."
                        )
                        self.logger.error(
                            message=f"{self.log_prefix}: {err_msg}",
                            details=api_err_msg,
                            resolution=(
                                f"Ensure that the {PLATFORM_NAME} server is "
                                "reachable and the request rate is within "
                                "the allowed limit."
                            ),
                        )
                        raise ServiceNowITSMPluginException(err_msg)
                    retry_after = int(
                        response.headers.get(
                            "Retry-After", DEFAULT_WAIT_TIME
                        )
                    )
                    if retry_after > MAX_RETRY_AFTER:
                        err_msg = (
                            "'Retry-After' value received from the response "
                            f"headers while {logger_msg} is greater than "
                            "5 minutes. Hence, returning status code "
                            f"{status_code}."
                        )
                        self.logger.error(
                            message=f"{self.log_prefix}: {err_msg}",
                            details=api_err_msg,
                        )
                        raise ServiceNowITSMPluginException(err_msg)
                    if status_code == 429:
                        log_err_msg = "API rate limit exceeded"
                    else:
                        log_err_msg = "HTTP server error occurred"
                    retries_left = MAX_API_CALLS - 1 - retry_counter
                    self.logger.error(
                        message=(
                            f"{self.log_prefix}: Received exit code "
                            f"{status_code}, {log_err_msg} while "
                            f"{logger_msg}. Retrying after {retry_after} "
                            f"second(s). {retries_left} retries remaining."
                        ),
                        details=api_err_msg,
                    )
                    time.sleep(retry_after)
                else:
                    return (
                        self.handle_error(
                            response, logger_msg, is_validation
                        )
                        if is_handle_error_required
                        else response
                    )
        except ServiceNowITSMPluginException:
            raise
        except requests.exceptions.ReadTimeout as error:
            err_msg = f"Read Timeout error occurred while {logger_msg}."
            if is_validation:
                err_msg = (
                    "Read Timeout error occurred. Verify the 'Instance "
                    "URL' provided in the configuration parameters."
                )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {error}",
                details=traceback.format_exc(),
            )
            raise ServiceNowITSMPluginException(err_msg)
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
                details=traceback.format_exc(),
            )
            raise ServiceNowITSMPluginException(err_msg)
        except requests.exceptions.ConnectionError as error:
            err_msg = (
                f"Unable to establish connection with {PLATFORM_NAME} "
                f"platform while {logger_msg}. Proxy server or "
                f"{PLATFORM_NAME} server is not reachable."
            )
            if is_validation:
                err_msg = (
                    f"Unable to establish connection with {PLATFORM_NAME} "
                    f"platform. Proxy server or {PLATFORM_NAME} server is "
                    "not reachable."
                )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {error}",
                details=traceback.format_exc(),
            )
            raise ServiceNowITSMPluginException(err_msg)
        except requests.HTTPError as error:
            err_msg = f"HTTP error occurred while {logger_msg}."
            if is_validation:
                err_msg = (
                    "HTTP error occurred. Verify the configuration "
                    "parameters provided."
                )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {error}",
                details=traceback.format_exc(),
            )
            raise ServiceNowITSMPluginException(err_msg)
        except Exception as exp:
            err_msg = f"Unexpected error occurred while {logger_msg}."
            if is_validation:
                err_msg = (
                    "Unexpected error occurred while performing an API "
                    f"call to {PLATFORM_NAME}."
                )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {exp}",
                details=traceback.format_exc(),
            )
            raise ServiceNowITSMPluginException(err_msg)

    def parse_response(
        self,
        response: requests.models.Response,
        logger_msg: str,
        is_validation: bool = False,
    ):
        """Parse and return JSON from a response object.

        Args:
            response (requests.models.Response): Response object.
            logger_msg (str): Logger message describing the operation.
            is_validation (bool): Whether the call is from a validation
                method. Defaults to False.

        Returns:
            Any: Parsed JSON response body.

        Raises:
            ServiceNowITSMPluginException: On JSON decode or parsing
                failure.
        """
        try:
            return response.json()
        except json.JSONDecodeError as err:
            err_msg = (
                "Invalid JSON response received from API while "
                f"{logger_msg}. Error: {err}"
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=self._get_response_details(response),
            )
            if is_validation:
                err_msg = (
                    "Verify the Instance URL provided in the configuration "
                    "parameters. Check logs for more details."
                )
            raise ServiceNowITSMPluginException(err_msg)
        except Exception as exp:
            err_msg = (
                "Unexpected error occurred while parsing the JSON response "
                f"while {logger_msg}. Error: {exp}"
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=self._get_response_details(response),
            )
            if is_validation:
                err_msg = (
                    "Unexpected validation error occurred. Verify the "
                    "Instance URL provided in the configuration parameters. "
                    "Check logs for more details."
                )
            raise ServiceNowITSMPluginException(err_msg)

    def handle_error(
        self,
        resp: requests.models.Response,
        logger_msg: str,
        is_validation: bool = False,
    ):
        """Handle the different HTTP response codes.

        Args:
            resp (requests.models.Response): Response object returned from
                the API call.
            logger_msg (str): Logger message describing the operation.
            is_validation (bool): Whether the call is from a validation
                method. Defaults to False.

        Returns:
            dict: Parsed JSON response body for 2xx responses.

        Raises:
            ServiceNowITSMPluginException: When the response code is not
                a success code.
        """
        status_code = resp.status_code
        validation_msg = "Validation error occurred, "
        error_dict = {
            400: "Received exit code 400, Bad Request",
            401: "Received exit code 401, Unauthorized access",
            403: "Received exit code 403, Forbidden",
            404: "Received exit code 404, Resource not found",
        }
        if is_validation:
            error_dict = {
                400: (
                    "Received exit code 400, Bad Request. Verify the "
                    "Instance URL provided in the configuration parameters."
                ),
                401: (
                    "Received exit code 401, Unauthorized. Verify the "
                    "Username and Password provided in the configuration "
                    "parameters."
                ),
                403: (
                    "Received exit code 403, Forbidden. Verify the "
                    "permission for the Username provided in the "
                    "configuration parameters."
                ),
                404: (
                    "Received exit code 404, Resource not found. Verify "
                    "the Instance URL provided in the configuration "
                    "parameters."
                ),
            }
        resolution_dict = {
            400: (
                "Ensure that the configuration parameters provided are "
                "correct."
            ),
            401: (
                "Ensure that the Username and Password provided in the "
                "configuration parameters are correct."
            ),
            403: (
                "Ensure that the Username provided in the configuration "
                f"parameters has sufficient permissions on {PLATFORM_NAME}."
            ),
            404: (
                "Ensure that the Instance URL provided in the "
                "configuration parameters is correct."
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

        # Extract the specific error reason returned by ServiceNow (e.g. an
        # invalid field name or an ACL failure) so it is surfaced in the
        # error message instead of only the HTTP status.
        api_error_detail = self._get_api_error_detail(resp)

        if status_code in error_dict:
            err_msg = error_dict[status_code]
            resolution = resolution_dict.get(status_code)
            if is_validation:
                if api_error_detail:
                    err_msg = f"{err_msg} API error: {api_error_detail}."
                self.logger.error(
                    message=f"{self.log_prefix}: {validation_msg}{err_msg}",
                    details=self._get_response_details(resp),
                    resolution=resolution,
                )
                raise ServiceNowITSMPluginException(err_msg)
            else:
                err_msg = f"{err_msg} while {logger_msg}."
                if status_code == 401:
                    err_msg = (
                        f"{err_msg} Verify the Username and Password "
                        "provided in the configuration parameters."
                    )
                if api_error_detail:
                    err_msg = f"{err_msg} API error: {api_error_detail}."
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg}",
                    details=self._get_response_details(resp),
                    resolution=resolution,
                )
                raise ServiceNowITSMPluginException(err_msg)
        else:
            err_type = (
                "HTTP Server Error"
                if 500 <= status_code <= 600
                else "HTTP Error"
            )
            err_msg = err_type
            if api_error_detail:
                err_msg = f"{err_type}. API error: {api_error_detail}."
            # Only prefix with the validation notice for validation calls.
            log_prefix_msg = validation_msg if is_validation else ""
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Received exit code {status_code}, "
                    f"{log_prefix_msg}{err_type} while {logger_msg}."
                ),
                details=self._get_response_details(resp),
                resolution=(
                    "Ensure that the configuration parameters provided are "
                    f"correct and the {PLATFORM_NAME} server is reachable."
                ),
            )
            raise ServiceNowITSMPluginException(err_msg)

    def get_auth_params(self, configuration: Dict) -> Tuple[str, str, str]:
        """Extract authentication parameters from the configuration.

        Args:
            configuration (Dict): Configuration parameter dictionary.

        Returns:
            Tuple[str, str, str]: Instance URL, Username and Password.
        """
        auth_params = configuration.get("auth", {})
        return (
            auth_params.get("url", "").strip().strip("/"),
            auth_params.get("username", "").strip(),
            auth_params.get("password"),
        )

    def basic_auth(self, username: str, password: str) -> Dict:
        """Generate a Basic Auth header.

        Args:
            username (str): Username.
            password (str): Password.

        Returns:
            Dict: Dictionary containing the Authorization header.

        Raises:
            ServiceNowITSMPluginException: When the token cannot be
                generated.
        """
        try:
            token = b64encode(
                f"{username}:{password}".encode("utf-8")
            ).decode("ascii")
            return {"Authorization": f"Basic {token}"}
        except Exception as exp:
            err_msg = "Error occurred while generating basic auth token."
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {exp}",
                details=traceback.format_exc(),
            )
            raise ServiceNowITSMPluginException(err_msg)

    def get_headers(
        self, username: str, password: str, with_content_type: bool = False
    ) -> Dict:
        """Build authenticated request headers.

        Args:
            username (str): Username.
            password (str): Password.
            with_content_type (bool): When True, adds a JSON Content-Type
                header (required for POST/PATCH requests).

        Returns:
            Dict: Headers dictionary with the Authorization header.
        """
        headers = self.basic_auth(username, password)
        if with_content_type:
            headers.update({"Content-Type": "application/json"})
        return headers

    def _validate_url(self, url: str) -> bool:
        """Validate the given URL.

        Args:
            url (str): URL to validate.

        Returns:
            bool: True if the URL is valid, else False.
        """
        parsed = urlparse(url.strip())
        return bool(parsed.scheme and parsed.netloc)

    def validate_parameters(
        self,
        field_name: str,
        field_value,
        field_type: type,
        parameter_type: str = "Configuration",
        allowed_values: Optional[List] = None,
        custom_validation_func: Optional[Callable] = None,
        is_required: bool = True,
        validation_err_msg: str = "Validation error occurred.",
    ) -> Optional[ValidationResult]:
        """Validate a single configuration parameter.

        Returns a ValidationResult on failure and None on success, so
        callers can use the walrus operator:
        ``if result := validate_parameters(...): return result``.

        Args:
            field_name (str): Human-readable parameter name used in
                messages.
            field_value: Value to validate.
            field_type (type): Expected Python type (str, int, ...).
            parameter_type (str): Parameter category used in messages
                (e.g. "Authentication" or "Configuration").
            allowed_values (Optional[List]): When provided, the value must
                be one of these.
            custom_validation_func (Optional[Callable]): Custom validator;
                should return True when valid, or False/an error message
                string when invalid.
            is_required (bool): When True, an empty/None value is an error.
            validation_err_msg (str): Prefix logged before the field-level
                error.

        Returns:
            Optional[ValidationResult]: ValidationResult on failure,
                None on success.
        """
        if field_type is str and isinstance(field_value, str):
            field_value = field_value.strip()

        # Required check. Integers (including 0) are treated as provided.
        if (
            is_required
            and not isinstance(field_value, int)
            and not field_value
        ):
            err_msg = (
                f"{field_name} is a required {parameter_type} parameter."
            )
            self.logger.error(
                f"{self.log_prefix}: {validation_err_msg} {err_msg}"
            )
            return ValidationResult(success=False, message=err_msg)

        # Type check.
        if field_value and not isinstance(field_value, field_type):
            err_msg = (
                f"Invalid value provided for the {parameter_type} "
                f"parameter '{field_name}'."
            )
            self.logger.error(
                f"{self.log_prefix}: {validation_err_msg} {err_msg}"
            )
            return ValidationResult(success=False, message=err_msg)

        # Custom validation.
        if custom_validation_func and field_value:
            outcome = custom_validation_func(field_value)
            if outcome is not True:
                err_msg = (
                    outcome
                    if isinstance(outcome, str)
                    else (
                        f"Invalid value provided for the {parameter_type} "
                        f"parameter '{field_name}'."
                    )
                )
                self.logger.error(
                    f"{self.log_prefix}: {validation_err_msg} {err_msg}"
                )
                return ValidationResult(success=False, message=err_msg)

        # Allowed values check.
        if (
            allowed_values
            and field_type is str
            and field_value not in allowed_values
        ):
            err_msg = (
                f"Invalid value provided for the {parameter_type} "
                f"parameter '{field_name}'. Allowed values are "
                f"{', '.join(str(v) for v in allowed_values)}."
            )
            self.logger.error(
                f"{self.log_prefix}: {validation_err_msg} {err_msg}"
            )
            return ValidationResult(success=False, message=err_msg)

        return None

    def get_table_config(self, configuration: Dict) -> TableConfig:
        """Resolve the destination table and its field names.

        For the standard tables the default field names are used. For the
        custom table the field names configured in the Configuration
        Parameters are used (falling back to the standard defaults).

        Args:
            configuration (Dict): Full plugin configuration dictionary.

        Returns:
            TableConfig: Resolved table and field names.
        """
        auth_params = configuration.get("auth", {})
        config_params = configuration.get("params", {})
        table = auth_params.get("table", "")
        if table == CUSTOM_TABLE:
            return TableConfig(
                table=config_params.get("custom_table_name", "").strip(),
                status_field=config_params.get(
                    "custom_status", DEFAULT_STATUS_FIELD
                ).strip(),
                severity_field=config_params.get(
                    "custom_severity", DEFAULT_SEVERITY_FIELD
                ).strip(),
                assignee_field=config_params.get(
                    "custom_assignee", DEFAULT_ASSIGNEE_FIELD
                ).strip(),
                assignment_group_field=config_params.get(
                    "custom_group", DEFAULT_ASSIGNMENT_GROUP_FIELD
                ).strip(),
                update_field=config_params.get(
                    "custom_update", DEFAULT_UPDATE_FIELD
                ).strip(),
            )
        return TableConfig(
            table=table,
            status_field=DEFAULT_STATUS_FIELD,
            severity_field=DEFAULT_SEVERITY_FIELD,
            assignee_field=DEFAULT_ASSIGNEE_FIELD,
            assignment_group_field=DEFAULT_ASSIGNMENT_GROUP_FIELD,
            update_field=DEFAULT_UPDATE_FIELD,
        )

    def _get_first_sys_user(
        self,
        configuration: Dict,
        email: str,
        sysparm_fields: str,
        logger_msg: str,
        verify=True,
        proxies=None,
    ) -> Optional[Dict]:
        """Fetch the first sys_user record matching the given email.

        This method never raises. On any failure (user not found or an API
        error) it logs the reason and returns None so that ticket creation
        is never blocked.

        Args:
            configuration (Dict): Full plugin configuration dictionary.
            email (str): User's email address.
            sysparm_fields (str): Comma-separated fields to fetch.
            logger_msg (str): Logger message describing the operation.
            verify (bool): Verify SSL. Defaults to True.
            proxies (Dict): Proxy configuration. Defaults to None.

        Returns:
            Optional[Dict]: The first matched record, or None.
        """
        url, username, password = self.get_auth_params(configuration)
        endpoint = f"{url}{SYS_USER_ENDPOINT}"
        headers = self.get_headers(username, password)
        params = {
            "sysparm_query": f"email={email}",
            "sysparm_fields": sysparm_fields,
            "sysparm_limit": 1,
        }
        try:
            response = self.api_helper(
                url=endpoint,
                method="GET",
                headers=headers,
                params=params,
                verify=verify,
                proxies=proxies,
                logger_msg=logger_msg,
            )
            results = response.get("result", [])
            if not results:
                self.logger.info(
                    f"{self.log_prefix}: No user found with email "
                    f"'{email}' on {PLATFORM_NAME}."
                )
                return None
            return results[0]
        except Exception as exp:
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Error occurred while {logger_msg}. "
                    f"Error: {exp}"
                ),
                details=traceback.format_exc(),
            )
            return None

    def fetch_manager_sys_id(
        self, configuration: Dict, email: str, verify=True, proxies=None
    ) -> Optional[str]:
        """Fetch the manager's sys_id for a user's email address.

        Queries the sys_user table by email and returns the value of
        'manager.sys_id' from the matched record. No caching is performed:
        a user's manager can change at any time, so the manager is resolved
        fresh on every call. Returns None when it cannot be resolved.

        Args:
            configuration (Dict): Plugin configuration dictionary.
            email (str): Acting user's email address.
            verify (bool): Verify SSL. Defaults to True.
            proxies (Dict): Proxy configuration. Defaults to None.

        Returns:
            Optional[str]: Manager's sys_id, or None when it cannot be
                resolved.
        """
        record = self._get_first_sys_user(
            configuration=configuration,
            email=email,
            sysparm_fields=MANAGER_LOOKUP_FIELDS,
            logger_msg=(
                f"fetching manager details for user '{email}' "
                f"from {PLATFORM_NAME}"
            ),
            verify=verify,
            proxies=proxies,
        )
        if not record:
            return None
        manager_sys_id = str(record.get("manager.sys_id", "")).strip()
        if not manager_sys_id:
            self.logger.info(
                f"{self.log_prefix}: User '{email}' does not have a "
                f"manager configured on {PLATFORM_NAME}."
            )
            return None
        self.logger.debug(
            f"{self.log_prefix}: Successfully resolved manager sys_id for "
            f"user '{email}' from {PLATFORM_NAME}."
        )
        return manager_sys_id

    def fetch_user_sys_id(
        self, configuration: Dict, email: str, verify=True, proxies=None
    ) -> Optional[str]:
        """Fetch a user's own sys_id for their email address.

        Queries the sys_user table by email and returns the matched
        record's sys_id. Required because the ServiceNow assignee field is
        a reference field that only accepts a sys_id, not an email. Returns
        None when it cannot be resolved.

        Args:
            configuration (Dict): Plugin configuration dictionary.
            email (str): User's email address.
            verify (bool): Verify SSL. Defaults to True.
            proxies (Dict): Proxy configuration. Defaults to None.

        Returns:
            Optional[str]: The user's sys_id, or None when it cannot be
                resolved.
        """
        record = self._get_first_sys_user(
            configuration=configuration,
            email=email,
            sysparm_fields="sys_id,email",
            logger_msg=(
                f"fetching user details for '{email}' from {PLATFORM_NAME}"
            ),
            verify=verify,
            proxies=proxies,
        )
        if not record:
            return None
        return str(record.get("sys_id", "")).strip() or None

    def fetch_user_emails(
        self,
        configuration: Dict,
        sys_ids: List[str],
        verify=True,
        proxies=None,
    ) -> Dict[str, str]:
        """Fetch a mapping of sys_id to email for the given user sys_ids.

        Args:
            configuration (Dict): Full plugin configuration dictionary.
            sys_ids (List[str]): List of sys_user sys_ids to resolve.
            verify (bool): Verify SSL. Defaults to True.
            proxies (Dict): Proxy configuration. Defaults to None.

        Returns:
            Dict[str, str]: Mapping of sys_id to email address. Empty when
                no valid sys_ids are provided.

        Raises:
            ServiceNowITSMPluginException: When the API call fails.
        """
        ids = [sys_id for sys_id in sys_ids if sys_id]
        if not ids:
            return {}

        url, username, password = self.get_auth_params(configuration)
        endpoint = f"{url}{SYS_USER_ENDPOINT}"
        headers = self.get_headers(username, password)
        params = {
            "sysparm_fields": "sys_id,email",
            "sysparm_query": f"sys_idIN{','.join(ids)}",
        }
        response = self.api_helper(
            url=endpoint,
            method="GET",
            headers=headers,
            params=params,
            verify=verify,
            proxies=proxies,
            logger_msg=f"fetching assignee(s) from {PLATFORM_NAME} platform",
        )
        return {
            result["sys_id"]: result.get("email", "")
            for result in response.get("result", [])
            if result.get("sys_id")
        }
