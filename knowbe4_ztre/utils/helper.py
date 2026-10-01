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

CRE KnowBe4 Plugin helper.
"""

import json
import time
import traceback
from datetime import datetime
from typing import Any, Callable, Dict, Generator, List, Optional, Tuple

import requests
from netskope.common.utils import add_user_agent
from netskope.integrations.crev2.plugin_base import ValidationResult

from .constants import (
    ACTION_ADD_TO_GROUP,
    ACTION_REMOVE_FROM_GROUP,
    ADD_TO_GROUPS_MUTATION,
    CLIENT_ERROR_MSG,
    CLIENT_ERROR_RESOLUTION_MESSAGE,
    CONFIG_CUSTOM_REGION_URL,
    CONFIG_KSAT_TOKEN,
    CONFIG_PASSWORDIQ_TOKEN,
    CONFIG_PULL_ADDITIONAL_DETAILS,
    CONFIG_PULL_ARCHIVED_USERS,
    CONFIG_REGION,
    CONFIG_SECURITYCOACH_TOKEN,
    DEFAULT_WAIT_TIME,
    EMPTY_ERROR_MESSAGE,
    ENROLL_USER_MUTATION,
    ENROLLMENTS_ALIAS_BLOCK,
    ENRICHMENT_BATCH_SIZE,
    ERROR_MESSAGE_MAP,
    FIELD_USER_STATUS_ACTIVE,
    FIELD_USER_STATUS_ARCHIVED,
    GENERIC_ERROR_MSG,
    GRAPHQL_ERROR_MSG,
    GROUP_CREATE_MUTATION,
    GROUP_STATUS_ACTIVE,
    GROUP_TYPE_CONSOLE,
    GROUP_VALUE_SEPARATOR,
    GROUPS_QUERY,
    INVALID_VALUE_ERROR_MESSAGE,
    MAX_API_CALLS,
    MAX_NORMALIZED_SCORE,
    MAX_RETRY_AFTER,
    MAX_RISK_SCORE,
    MIN_NORMALIZED_SCORE,
    MIN_RISK_SCORE,
    MODULE_NAME,
    MUTATION_RESPONSE_KEYS,
    NO_MORE_RETRIES_ERROR_MSG,
    PAGE_SIZE,
    PASSWORDIQ_QUERY,
    PIQ_DETECTIONS,
    PIQ_DETECTION_LABELS,
    PIQ_PAGE_SIZE,
    PIQ_USER_TYPE,
    PLATFORM_NAME,
    REGION_CUSTOM_VALUE,
    REMOVE_FROM_GROUP_MUTATION,
    RESOLUTION_MESSAGE_MAP,
    RETRY_ERROR_MSG,
    SECURITY_COACH_FIELD_MAPPING,
    SECURITY_COACH_PAGE_SIZE,
    SECURITY_COACH_QUERY,
    SERVER_ERROR_MSG,
    SERVER_ERROR_RESOLUTION_MESSAGE,
    TOGGLE_NO,
    TOGGLE_YES,
    TRAINING_CAMPAIGN_STATUSES,
    TRAINING_CAMPAIGNS_QUERY,
    TYPE_ERROR_MESSAGE,
    USER_EDIT_MUTATION,
    USER_STATUS_ACTIVE,
    USER_STATUS_ALL,
    USERS_QUERY,
    USERS_QUERY_WITH_CUSTOM_FIELDS,
    VALIDATION_ERROR_MESSAGE,
)
from .exceptions import (
    KnowBe4AuthenticationException,
    KnowBe4PluginException,
    KnowBe4RateLimitException,
)

# KnowBe4's customDate1/customDate2 are the GraphQL 'ISO8601Date'
# scalar - confirmed against a live tenant to be date-only, e.g.
# '2026-09-01', with no time component.
DATETIME_FORMATS = ["%Y-%m-%d"]


class KnowBe4PluginHelper(object):
    """Helper class for the KnowBe4 CRE plugin.

    Wraps the KnowBe4 GraphQL API: request execution with retries,
    GraphQL error checking, pagination, field extraction, score
    normalization, and one method per pull or action operation.
    """

    def __init__(
        self,
        logger,
        log_prefix: str,
        plugin_name: str,
        plugin_version: str,
    ):
        """Initialize KnowBe4PluginHelper.

        ssl_validation and proxy are deliberately not accepted here.
        The platform can refresh either between calls (e.g. a proxy
        change) without recreating the plugin, so every method that
        reaches api_helper() takes them as arguments instead of
        caching them at construction time.

        Args:
            logger: Logger object.
            log_prefix (str): Log prefix used on every log message.
            plugin_name (str): Plugin name.
            plugin_version (str): Plugin version.
        """
        self.logger = logger
        self.log_prefix = log_prefix
        self.plugin_name = plugin_name
        self.plugin_version = plugin_version

    # ------------------------------------------------------------------
    # Headers and configuration
    # ------------------------------------------------------------------

    def _add_user_agent(self, headers: Optional[Dict] = None) -> Dict:
        """Add the User-Agent header to a request.

        Args:
            headers (Dict): Existing request headers.

        Returns:
            Dict: Headers with the User-Agent set.
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

    def get_auth_headers(self, token: str) -> Dict:
        """Build the KnowBe4 authentication headers for a product token.

        Args:
            token (str): Product API token.

        Returns:
            Dict: Headers with the bearer token and content type.
        """
        return {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

    def get_config_params(self, configuration: Dict) -> Tuple:
        """Extract the plugin configuration parameters.

        API tokens are returned as provided. They are password fields
        and must not be stripped.

        Args:
            configuration (Dict): Plugin configuration.

        Returns:
            Tuple: (region, ksat_token, additional_details,
                passwordiq_token, securitycoach_token,
                pull_archived_users). 'region' is already resolved to
                the actual GraphQL endpoint URL: when the 'Base URL'
                choice is REGION_CUSTOM_VALUE, the 'Custom Region URL'
                value is substituted in; either way, 'Base URL' (fixed
                choice or custom) only ever holds the tenant's bare
                base URL, so '/graphql' is appended here, once, so
                every caller can use 'region' directly without knowing
                about the custom-region indirection or the path.
                PasswordIQ and SecurityCoach detail are enabled by
                including 'passwordiq' and 'securitycoach' in
                additional_details.
        """
        configuration = configuration or {}
        region = configuration.get(CONFIG_REGION, "")
        if region == REGION_CUSTOM_VALUE:
            region = configuration.get(CONFIG_CUSTOM_REGION_URL, "")
        if isinstance(region, str):
            region = region.strip().rstrip("/")
            if region and not region.endswith("/graphql"):
                region = f"{region}/graphql"
        additional_details = (
            configuration.get(CONFIG_PULL_ADDITIONAL_DETAILS) or []
        )
        if isinstance(additional_details, str):
            additional_details = [additional_details]
        pull_archived_users = configuration.get(
            CONFIG_PULL_ARCHIVED_USERS, TOGGLE_NO
        )
        if isinstance(pull_archived_users, str):
            pull_archived_users = pull_archived_users.strip()
        return (
            region,
            configuration.get(CONFIG_KSAT_TOKEN, ""),
            additional_details,
            configuration.get(CONFIG_PASSWORDIQ_TOKEN, ""),
            configuration.get(CONFIG_SECURITYCOACH_TOKEN, ""),
            pull_archived_users,
        )

    def get_user_status_filter(self, pull_archived_users: str) -> str:
        """Map the 'Pull Archived Users' toggle to an API filter.

        Args:
            pull_archived_users (str): Yes or No.

        Returns:
            str: ALL when archived users are also pulled, else ACTIVE.
        """
        if str(pull_archived_users).strip() == TOGGLE_YES:
            return USER_STATUS_ALL
        return USER_STATUS_ACTIVE

    # ------------------------------------------------------------------
    # Validation helpers
    # ------------------------------------------------------------------

    def validate_entity(self, entity: str, supported: List) -> None:
        """Check that the requested entity is supported.

        Args:
            entity (str): Entity name requested by the platform.
            supported (List): Entity names this plugin supports.

        Raises:
            KnowBe4PluginException: When the entity is not supported.
        """
        if entity not in supported:
            err_msg = (
                f"Invalid entity '{entity}' found. This plugin only"
                f" supports {', '.join(supported)} entity."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                resolution=(
                    "Select one of the supported entities in the entity"
                    " mappings of the plugin configuration."
                ),
            )
            raise KnowBe4PluginException(err_msg)

    def validate_parameters(
        self,
        field_name: str,
        field_value: Any,
        field_type: type,
        parameter_type: str,
        allowed_values: Optional[List] = None,
        custom_validation_func: Optional[Callable] = None,
        is_required: bool = True,
        check_dollar: bool = False,
    ) -> Optional[ValidationResult]:
        """Validate one configuration or action parameter.

        Args:
            field_name (str): Parameter label used in messages.
            field_value (Any): Parameter value.
            field_type (type): Expected Python type.
            parameter_type (str): 'configuration' or 'action'.
            allowed_values (List): Values the parameter may hold.
            custom_validation_func (Callable): Extra check. Returns
                True when valid, or False or an error message.
            is_required (bool): Whether the parameter is mandatory.
            check_dollar (bool): When True, a Source field value is
                left for execution time.

        Returns:
            ValidationResult: On failure, else None.
        """
        if field_type is str and isinstance(field_value, str):
            field_value = field_value.strip()

        invalid_value_resolution = (
            f"Provide a valid value for the '{field_name}'"
            f" {parameter_type} parameter."
        )

        if (
            check_dollar
            and isinstance(field_value, str)
            and field_value.startswith("$")
        ):
            self.logger.debug(
                f"{self.log_prefix}: '{field_name}' contains the Source"
                " Field, hence validation for this field will be"
                " performed while executing the action."
            )
            return None

        is_empty = (
            field_value is None
            or field_value == ""
            or (isinstance(field_value, (list, dict)) and not field_value)
        )
        if isinstance(field_value, (int, float)) and not isinstance(
            field_value, bool
        ):
            is_empty = False

        if is_empty:
            if not is_required:
                return None
            return self._validation_failure(
                EMPTY_ERROR_MESSAGE.format(
                    field_name=field_name, parameter_type=parameter_type
                ),
                resolution=(
                    f"Provide a value for the '{field_name}'"
                    f" {parameter_type} parameter."
                ),
            )

        if not isinstance(field_value, field_type):
            return self._validation_failure(
                TYPE_ERROR_MESSAGE.format(
                    field_name=field_name, parameter_type=parameter_type
                ),
                resolution=invalid_value_resolution,
            )

        if custom_validation_func:
            outcome = custom_validation_func(field_value)
            if outcome is not True:
                err_msg = (
                    outcome
                    if isinstance(outcome, str)
                    else TYPE_ERROR_MESSAGE.format(
                        field_name=field_name,
                        parameter_type=parameter_type,
                    )
                )
                return self._validation_failure(
                    err_msg, resolution=invalid_value_resolution
                )

        if allowed_values:
            values_to_check = (
                field_value
                if isinstance(field_value, list)
                else [field_value]
            )
            invalid = [
                value
                for value in values_to_check
                if value not in allowed_values
            ]
            if invalid:
                return self._validation_failure(
                    INVALID_VALUE_ERROR_MESSAGE.format(
                        invalid_values=invalid,
                        field_name=field_name,
                        parameter_type=parameter_type,
                        allowed_values=allowed_values,
                    ),
                    resolution=(
                        "Select a value from the allowed values for the"
                        f" '{field_name}' {parameter_type} parameter."
                    ),
                )

        return None

    def _validation_failure(
        self, err_msg: str, resolution: str
    ) -> ValidationResult:
        """Log a validation failure and build its result.

        Args:
            err_msg (str): Error message shown to the user.
            resolution (str): Corrective action for the user.

        Returns:
            ValidationResult: Failure result carrying err_msg.
        """
        self.logger.error(
            message=f"{self.log_prefix}: {VALIDATION_ERROR_MESSAGE}"
            f" {err_msg}",
            resolution=resolution,
        )
        return ValidationResult(success=False, message=err_msg)

    # ------------------------------------------------------------------
    # HTTP and GraphQL transport
    # ------------------------------------------------------------------

    def api_helper(
        self,
        logger_msg: str,
        url: str,
        ssl_validation,
        proxy,
        method: str = "POST",
        headers: Optional[Dict] = None,
        json_data: Optional[Dict] = None,
        is_validation: bool = False,
        is_handle_error_required: bool = True,
    ):
        """Send a request to KnowBe4 and handle transport errors.

        Retries on HTTP 429 and 5xx up to MAX_API_CALLS times. The
        retry loop is skipped during validation so a bad configuration
        fails fast.

        Args:
            logger_msg (str): What the call is doing, used in logs.
            url (str): Request URL.
            ssl_validation: SSL verification flag from the platform,
                read fresh from the plugin on every call so a change
                takes effect without recreating the helper.
            proxy: Proxy configuration from the platform, read fresh
                for the same reason.
            method (str): HTTP method.
            headers (Dict): Request headers.
            json_data (Dict): JSON request body.
            is_validation (bool): Called from validate().
            is_handle_error_required (bool): Pass the response through
                handle_error() before returning it.

        Returns:
            Dict or Response: Parsed body, or the raw response when
                is_handle_error_required is False.

        Raises:
            KnowBe4PluginException: On any request failure.
        """
        headers = self._add_user_agent(headers)
        self.logger.debug(
            f"{self.log_prefix}: API Request for {logger_msg}."
            f" Endpoint: {method} {url}"
        )
        try:
            for retry_count in range(MAX_API_CALLS):
                response = requests.request(
                    url=url,
                    method=method,
                    json=json_data,
                    headers=headers,
                    verify=ssl_validation,
                    proxies=proxy,
                )
                status_code = response.status_code
                self.logger.debug(
                    f"{self.log_prefix}: Received API Response for"
                    f" {logger_msg}. Status Code={status_code}."
                )
                if not is_validation and (
                    status_code == 429 or 500 <= status_code < 600
                ):
                    if retry_count == MAX_API_CALLS - 1:
                        err_msg = NO_MORE_RETRIES_ERROR_MSG.format(
                            status_code=status_code,
                            logger_msg=logger_msg,
                        )
                        self.logger.error(
                            message=f"{self.log_prefix}: {err_msg}",
                            details=f"API response: {response.text}",
                            resolution=SERVER_ERROR_RESOLUTION_MESSAGE,
                        )
                        if status_code == 429:
                            raise KnowBe4RateLimitException(err_msg)
                        raise KnowBe4PluginException(err_msg)
                    error_reason = (
                        "API rate limit exceeded"
                        if status_code == 429
                        else "HTTP server error occurred"
                    )
                    retry_after = self._get_retry_after(response.headers)
                    self.logger.error(
                        message=(
                            f"{self.log_prefix}: "
                            + RETRY_ERROR_MSG.format(
                                status_code=status_code,
                                error_reason=error_reason,
                                logger_msg=logger_msg,
                                wait_time=retry_after,
                                retry_remaining=(
                                    MAX_API_CALLS - 1 - retry_count
                                ),
                            )
                        ),
                        details=f"API response: {response.text}",
                        resolution=SERVER_ERROR_RESOLUTION_MESSAGE,
                    )
                    time.sleep(retry_after)
                else:
                    return (
                        self.handle_error(
                            response=response,
                            logger_msg=logger_msg,
                            is_validation=is_validation,
                        )
                        if is_handle_error_required
                        else response
                    )
        except KnowBe4PluginException:
            raise
        except requests.exceptions.ReadTimeout as error:
            err_msg = f"Read timeout error occurred while {logger_msg}."
            if is_validation:
                err_msg = "Read timeout error occurred."
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {error}",
                details=traceback.format_exc(),
                resolution=(
                    f"Verify that the {PLATFORM_NAME} API server is"
                    " reachable."
                ),
            )
            raise KnowBe4PluginException(err_msg)
        except requests.exceptions.ProxyError as error:
            err_msg = (
                f"Proxy error occurred while {logger_msg}. Verify the"
                " proxy configuration provided."
            )
            if is_validation:
                err_msg = (
                    "Proxy error occurred. Verify the proxy"
                    " configuration provided."
                )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {error}",
                details=traceback.format_exc(),
                resolution=(
                    "Verify that the proxy configuration provided is"
                    " correct and the proxy server is reachable."
                ),
            )
            raise KnowBe4PluginException(err_msg)
        except requests.exceptions.ConnectionError as error:
            err_msg = (
                f"Unable to connect while {logger_msg}. The proxy"
                f" server or the {PLATFORM_NAME} server is not"
                " reachable."
            )
            if is_validation:
                err_msg = (
                    "Unable to connect. The proxy server or the"
                    f" {PLATFORM_NAME} server is not reachable."
                )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {error}",
                details=traceback.format_exc(),
                resolution=(
                    f"Verify that the {PLATFORM_NAME} API server is"
                    " reachable."
                ),
            )
            raise KnowBe4PluginException(err_msg)
        except requests.HTTPError as error:
            err_msg = f"HTTP error occurred while {logger_msg}."
            if is_validation:
                err_msg = (
                    "HTTP error occurred. Verify the configuration"
                    " parameters provided."
                )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {error}",
                details=traceback.format_exc(),
                resolution=(
                    "Verify the configuration parameters provided."
                ),
            )
            raise KnowBe4PluginException(err_msg)
        except Exception as error:
            err_msg = f"Unexpected error occurred while {logger_msg}."
            if is_validation:
                err_msg = (
                    "Unexpected error occurred while connecting to"
                    f" {PLATFORM_NAME}."
                )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {error}",
                details=traceback.format_exc(),
                resolution=(
                    "Verify the configuration parameters provided."
                ),
            )
            raise KnowBe4PluginException(err_msg)

    def _get_retry_after(self, headers) -> int:
        """Read how long to wait before the next retry.

        Args:
            headers: Response headers.

        Returns:
            int: Wait time in seconds, capped at MAX_RETRY_AFTER.
        """
        value = headers.get("Retry-After") or headers.get("retry-after")
        try:
            wait = int(value) if value else DEFAULT_WAIT_TIME
        except (TypeError, ValueError):
            wait = DEFAULT_WAIT_TIME
        return min(max(wait, 0), MAX_RETRY_AFTER)

    def parse_response(
        self,
        response: requests.models.Response,
        logger_msg: str,
        is_validation: bool = False,
    ) -> Dict:
        """Parse the JSON body of a response.

        Args:
            response (Response): Response object.
            logger_msg (str): What the call is doing, used in logs.
            is_validation (bool): Called from validate().

        Returns:
            Dict: Parsed JSON body.

        Raises:
            KnowBe4PluginException: When the body is not valid JSON.
        """
        try:
            return response.json()
        except ValueError as error:
            err_msg = (
                f"Invalid JSON response received while {logger_msg}."
            )
            if is_validation:
                err_msg = (
                    "Invalid JSON response received from"
                    f" {PLATFORM_NAME}."
                )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {error}",
                details=f"API response: {response.text}",
                resolution=(
                    f"Verify that the {PLATFORM_NAME} API server is"
                    " returning a valid JSON response."
                ),
            )
            raise KnowBe4PluginException(err_msg)
        except Exception as error:
            err_msg = (
                "Unexpected error occurred while parsing the response"
                f" received while {logger_msg}."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {error}",
                details=f"API response: {response.text}",
                resolution=(
                    "Verify the configuration parameters provided."
                ),
            )
            raise KnowBe4PluginException(err_msg)

    def handle_error(
        self,
        response: requests.models.Response,
        logger_msg: str,
        is_validation: bool = False,
    ) -> Dict:
        """Check the HTTP status code and parse the body.

        Args:
            response (Response): Response object.
            logger_msg (str): What the call is doing, used in logs.
            is_validation (bool): Called from validate().

        Returns:
            Dict: Parsed body for 200, 201 and 202, or {} for 204.

        Raises:
            KnowBe4PluginException: For any other status code.
        """
        status_code = response.status_code
        if status_code in (200, 201, 202):
            return self.parse_response(
                response=response,
                logger_msg=logger_msg,
                is_validation=is_validation,
            )
        if status_code == 204:
            return {}

        if status_code in ERROR_MESSAGE_MAP:
            err_msg = ERROR_MESSAGE_MAP[status_code]
            resolution = RESOLUTION_MESSAGE_MAP.get(
                status_code, CLIENT_ERROR_RESOLUTION_MESSAGE
            )
        elif 400 <= status_code < 500:
            err_msg = CLIENT_ERROR_MSG.format(status_code=status_code)
            resolution = CLIENT_ERROR_RESOLUTION_MESSAGE
        elif 500 <= status_code < 600:
            err_msg = SERVER_ERROR_MSG.format(status_code=status_code)
            resolution = SERVER_ERROR_RESOLUTION_MESSAGE
        else:
            err_msg = GENERIC_ERROR_MSG.format(status_code=status_code)
            resolution = CLIENT_ERROR_RESOLUTION_MESSAGE

        log_msg = (
            f"{VALIDATION_ERROR_MESSAGE} {err_msg}"
            if is_validation
            else f"{err_msg} Error occurred while {logger_msg}."
        )
        self.logger.error(
            message=f"{self.log_prefix}: {log_msg}",
            details=f"API response: {response.text}",
            resolution=resolution,
        )
        if status_code in (401, 403):
            raise KnowBe4AuthenticationException(err_msg)
        raise KnowBe4PluginException(err_msg)

    def graphql_request(
        self,
        logger_msg: str,
        url: str,
        token: str,
        query: str,
        ssl_validation,
        proxy,
        variables: Optional[Dict] = None,
        is_validation: bool = False,
    ) -> Dict:
        """Run one GraphQL operation and return its data block.

        KnowBe4 answers with HTTP 200 even when the operation failed,
        so the errors list in the body is always checked.

        Args:
            logger_msg (str): What the call is doing, used in logs.
            url (str): Region GraphQL endpoint.
            token (str): Product API token.
            query (str): GraphQL document.
            ssl_validation: SSL verification flag from the platform.
            proxy: Proxy configuration from the platform.
            variables (Dict): GraphQL variables.
            is_validation (bool): Called from validate().

        Returns:
            Dict: The data block of the GraphQL response.

        Raises:
            KnowBe4PluginException: On transport or GraphQL errors.
        """
        body = {"query": query}
        if variables:
            body["variables"] = variables
        response = self.api_helper(
            logger_msg=logger_msg,
            url=url,
            ssl_validation=ssl_validation,
            proxy=proxy,
            method="POST",
            headers=self.get_auth_headers(token),
            json_data=body,
            is_validation=is_validation,
        )
        if not isinstance(response, dict):
            response = {}
        errors = response.get("errors")
        if errors:
            err_msg = GRAPHQL_ERROR_MSG.format(logger_msg=logger_msg)
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=f"API response: {response}",
                resolution=(
                    "Verify the API token(s), the Region and the"
                    " permissions granted to the token in KnowBe4."
                ),
            )
            raise KnowBe4PluginException(err_msg)
        return response.get("data") or {}

    def graphql_request_allow_errors(
        self,
        logger_msg: str,
        url: str,
        token: str,
        query: str,
        ssl_validation,
        proxy,
        variables: Optional[Dict] = None,
    ) -> Tuple[Dict, List]:
        """Run one GraphQL operation without raising on GraphQL errors.

        Used by callers that can act on a partial result, e.g. a
        batched, per-user aliased query where one alias's error (a
        user deleted since the last pull) must not discard the data
        returned for every other alias in the same response.

        Args:
            logger_msg (str): What the call is doing, used in logs.
            url (str): Region GraphQL endpoint.
            token (str): Product API token.
            query (str): GraphQL document.
            ssl_validation: SSL verification flag from the platform.
            proxy: Proxy configuration from the platform.
            variables (Dict): GraphQL variables.

        Returns:
            Tuple: The data block (possibly partial) and the errors
                list (empty when there were none).

        Raises:
            KnowBe4PluginException: On a transport-level failure.
                Never raised for a GraphQL `errors` entry.
        """
        body = {"query": query}
        if variables:
            body["variables"] = variables
        response = self.api_helper(
            logger_msg=logger_msg,
            url=url,
            ssl_validation=ssl_validation,
            proxy=proxy,
            method="POST",
            headers=self.get_auth_headers(token),
            json_data=body,
        )
        if not isinstance(response, dict):
            response = {}
        return response.get("data") or {}, response.get("errors") or []

    def format_graphql_errors(self, errors: Any) -> str:
        """Turn a GraphQL errors list into one readable string.

        Args:
            errors (Any): Errors list from a GraphQL response.

        Returns:
            str: Comma separated error messages.
        """
        if not isinstance(errors, list):
            return str(errors)
        messages = []
        for error in errors:
            if isinstance(error, dict):
                message = error.get("message") or error.get("reason")
                field = error.get("field")
                if message and field:
                    messages.append(f"{field}: {message}")
                elif message:
                    messages.append(str(message))
                else:
                    messages.append(str(error))
            else:
                messages.append(str(error))
        return ", ".join(messages)

    def paginate(
        self,
        logger_msg: str,
        url: str,
        token: str,
        query: str,
        variables: Dict,
        response_key: str,
        ssl_validation,
        proxy,
    ) -> Generator[Tuple[Dict, int], None, None]:
        """Walk a page based GraphQL list query.

        Args:
            logger_msg (str): What the call is doing, used in logs.
                Must not include the trailing 'from {PLATFORM_NAME}'
                clause — this method appends the page number before
                it.
            url (str): Region GraphQL endpoint.
            token (str): Product API token.
            query (str): GraphQL document.
            variables (Dict): Variables without the page number.
            response_key (str): Query field name in the response.
            ssl_validation: SSL verification flag from the platform.
            proxy: Proxy configuration from the platform.

        Yields:
            Tuple: The response block and its page number.
        """
        page = 1
        while True:
            page_variables = dict(variables or {})
            page_variables["page"] = page
            data = self.graphql_request(
                logger_msg=(
                    f"{logger_msg} for page {page} from"
                    f" {PLATFORM_NAME}"
                ),
                url=url,
                token=token,
                query=query,
                ssl_validation=ssl_validation,
                proxy=proxy,
                variables=page_variables,
            )
            block = data.get(response_key) or {}
            yield block, page
            pagination = block.get("pagination") or {}
            total_pages = pagination.get("pages") or 0
            if page >= total_pages:
                break
            page += 1

    # ------------------------------------------------------------------
    # Field extraction helpers
    # ------------------------------------------------------------------

    def _extract_field_from_event(
        self,
        key: str,
        event: Dict,
        default: Any = None,
        transformation: Optional[str] = None,
    ) -> Any:
        """Read a dot separated key path out of a response node.

        Args:
            key (str): Dot separated key path.
            event (Dict): Response node.
            default (Any): Value returned when the key is missing.
            transformation (str): Name of a transformation method or
                one of string, integer and float.

        Returns:
            Any: Extracted value.
        """
        value = event
        for part in key.split("."):
            if not isinstance(value, dict) or part not in value:
                return default
            value = value.get(part)
        if value is None:
            return default
        if transformation:
            if hasattr(self, transformation):
                return getattr(self, transformation)(value)
            if transformation == "string":
                return str(value)
            if transformation == "integer":
                return int(value)
            if transformation == "float":
                return float(value)
        return value

    def _format_user_status(self, archived: Any) -> str:
        """Turn the raw 'archived' boolean into a 'User Status' value.

        Args:
            archived (Any): Raw 'archived' value from the User node.

        Returns:
            str: 'Archived' when true, 'Active' otherwise.
        """
        return (
            FIELD_USER_STATUS_ARCHIVED
            if archived
            else FIELD_USER_STATUS_ACTIVE
        )

    def _extract_group_names(self, groups: Any) -> List:
        """Read group names out of a user's groups list.

        Args:
            groups (Any): Groups list from a user node.

        Returns:
            List: Group names.
        """
        if not isinstance(groups, list):
            return []
        return [
            group.get("name")
            for group in groups
            if isinstance(group, dict) and group.get("name")
        ]

    def add_field(
        self, fields_dict: Dict, field_name: str, value: Any
    ) -> None:
        """Add a value to the extracted fields dictionary.

        Empty dictionaries and lists are stored as None so they are
        not persisted as empty containers. Numbers, including 0, and
        booleans, including False, are always stored.

        Args:
            fields_dict (Dict): Dictionary to update.
            field_name (str): Field name to set.
            value (Any): Value to store.
        """
        if isinstance(value, bool):
            fields_dict[field_name] = value
            return
        if isinstance(value, (dict, list)) and not value:
            fields_dict[field_name] = None
            return
        if isinstance(value, (int, float)):
            fields_dict[field_name] = value
            return
        if value:
            fields_dict[field_name] = value

    def extract_entity_fields(self, event: Dict, mapping: Dict) -> Dict:
        """Map one API node onto the plugin's entity fields.

        Args:
            event (Dict): Response node.
            mapping (Dict): Entity field name to extraction details.

        Returns:
            Dict: Extracted entity fields.
        """
        extracted_fields = {}
        for field_name, field_details in mapping.items():
            self.add_field(
                extracted_fields,
                field_name,
                self._extract_field_from_event(
                    key=field_details.get("key"),
                    event=event,
                    default=field_details.get("default"),
                    transformation=field_details.get("transformation"),
                ),
            )
        return extracted_fields

    def normalize_risk_score(
        self, risk_score: Any, identifier: Optional[str] = None
    ) -> Optional[int]:
        """Convert a KnowBe4 risk score to the Netskope score range.

        KnowBe4 scores run from 0, least risky, to 100, most risky.
        Netskope scores run from 0, most risky, to 1000, least risky.

        Args:
            risk_score (Any): KnowBe4 SmartRisk score.
            identifier (str): User ID or email, used only in the
                debug log when the score is missing, not numeric, or
                out of the expected range.

        Returns:
            int: Normalized score, or None when the input is missing
                or not a number.
        """
        who = f" for user '{identifier}'" if identifier else ""
        if risk_score is None or isinstance(risk_score, bool):
            self.logger.debug(
                f"{self.log_prefix}: Skipped calculating the"
                f" Netskope Normalized Score{who} because the Risk"
                f" Score '{risk_score}' is missing or not numeric."
            )
            return None
        try:
            score = float(risk_score)
        except (TypeError, ValueError):
            self.logger.debug(
                f"{self.log_prefix}: Skipped calculating the"
                f" Netskope Normalized Score{who} because the Risk"
                f" Score '{risk_score}' is missing or not numeric."
            )
            return None
        clamped_score = max(MIN_RISK_SCORE, min(MAX_RISK_SCORE, score))
        if clamped_score != score:
            self.logger.debug(
                f"{self.log_prefix}: Risk Score '{score}'{who} is"
                f" outside the expected {MIN_RISK_SCORE}-"
                f"{MAX_RISK_SCORE} range. Clamped to"
                f" '{clamped_score}' before calculating the Netskope"
                " Normalized Score."
            )
        normalized = int(
            round(
                MAX_NORMALIZED_SCORE
                - (
                    clamped_score
                    * (MAX_NORMALIZED_SCORE - MIN_NORMALIZED_SCORE)
                    / (MAX_RISK_SCORE - MIN_RISK_SCORE)
                )
            )
        )
        return max(
            MIN_NORMALIZED_SCORE, min(MAX_NORMALIZED_SCORE, normalized)
        )

    def parse_datetime(self, value: Any) -> Optional[datetime]:
        """Convert an API timestamp into a datetime object.

        Args:
            value (Any): Timestamp string from the API.

        Returns:
            datetime: Parsed timestamp, or None when it cannot be
                parsed.
        """
        if not value or not isinstance(value, str):
            return None
        for date_format in DATETIME_FORMATS:
            try:
                return datetime.strptime(value, date_format)
            except ValueError:
                continue
        return None

    def get_stripped_param(self, parameters: Dict, key: str) -> str:
        """Read an action parameter as a stripped string.

        Every action parameter is expected to resolve to a single
        scalar value, never a list — including 'Target User', whose
        'User ID' source field must be mapped with the Overwrite merge
        strategy (see its description in get_action_params()), not
        Append. The value never changes between pulls, so Append
        would only accumulate duplicate values into a list, which
        this parameter is not designed to handle.

        Args:
            parameters (Dict): Resolved action parameters.
            key (str): Parameter key.

        Returns:
            str: Stripped value, or an empty string.
        """
        value = (parameters or {}).get(key, "")
        if value is None:
            return ""
        return str(value).strip()

    def to_int(self, value: Any) -> Optional[int]:
        """Convert a value to an integer identifier.

        Args:
            value (Any): Value to convert.

        Returns:
            int: Converted value, or None when it is not numeric.
        """
        if value is None or isinstance(value, bool):
            return None
        try:
            return int(str(value).strip())
        except (TypeError, ValueError):
            return None

    def chunk_list(self, items: List, size: int) -> List:
        """Split a list into fixed size chunks.

        Args:
            items (List): Items to split.
            size (int): Maximum items per chunk.

        Returns:
            List: List of chunks.
        """
        return [
            items[index:index + size]
            for index in range(0, len(items), size)
        ]

    def build_group_value(self, group_id: Any, group_name: str) -> str:
        """Pack a group's ID and name into one dropdown choice value.

        Carrying the name lets execute_actions() log the group's name
        without an extra API call, since the mutations only ever
        return user information, never the group's.

        Args:
            group_id (Any): KnowBe4 group ID.
            group_name (str): Group name.

        Returns:
            str: '{group_id}{GROUP_VALUE_SEPARATOR}{group_name}'.
        """
        return f"{group_id}{GROUP_VALUE_SEPARATOR}{group_name}"

    def split_group_value(self, value: str) -> Tuple[Optional[int], str]:
        """Split a packed 'Group' dropdown value into ID and name.

        Args:
            value (str): Value built by build_group_value().

        Returns:
            Tuple: (group_id, group_name). group_id is None when the
                leading part is not numeric. group_name is '' when
                the separator is absent.
        """
        group_id_part, _, group_name = value.partition(
            GROUP_VALUE_SEPARATOR
        )
        return self.to_int(group_id_part), group_name

    def build_campaign_value(
        self, campaign_id: Any, campaign_name: str
    ) -> str:
        """Pack a campaign's ID and name into one dropdown value.

        Carrying the name lets execute_actions() log the campaign's
        name without an extra API call, since the enrollment mutation
        only ever returns user information, never the campaign's. The
        same separator used for the 'Group' dropdown is reused here;
        it is chosen to be vanishingly unlikely to appear in either a
        real group or a real campaign name.

        Args:
            campaign_id (Any): KnowBe4 training campaign ID.
            campaign_name (str): Training campaign name.

        Returns:
            str: '{campaign_id}{GROUP_VALUE_SEPARATOR}{campaign_name}'.
        """
        return f"{campaign_id}{GROUP_VALUE_SEPARATOR}{campaign_name}"

    def split_campaign_value(
        self, value: str
    ) -> Tuple[Optional[int], str]:
        """Split a packed 'Training Campaign' value into ID and name.

        Args:
            value (str): Value built by build_campaign_value().

        Returns:
            Tuple: (campaign_id, campaign_name). campaign_id is None
                when the leading part is not numeric. campaign_name
                is '' when the separator is absent.
        """
        campaign_id_part, _, campaign_name = value.partition(
            GROUP_VALUE_SEPARATOR
        )
        return self.to_int(campaign_id_part), campaign_name

    # ------------------------------------------------------------------
    # Pull operations
    # ------------------------------------------------------------------

    def fetch_user_pages(
        self,
        url: str,
        token: str,
        status: str,
        ssl_validation,
        proxy,
        include_custom_fields: bool = False,
    ) -> Generator[Tuple[List, int], None, None]:
        """Walk the KnowBe4 user roster page by page.

        Args:
            url (str): Region GraphQL endpoint.
            token (str): KSAT API token.
            status (str): User status filter, ACTIVE or ALL.
            ssl_validation: SSL verification flag from the platform.
            proxy: Proxy configuration from the platform.
            include_custom_fields (bool): Whether to also request the
                6 custom fields on the user node.

        Yields:
            Tuple: The user nodes of a page and the page number.
        """
        query = (
            USERS_QUERY_WITH_CUSTOM_FIELDS
            if include_custom_fields
            else USERS_QUERY
        )
        for block, page in self.paginate(
            logger_msg="fetching user records",
            url=url,
            token=token,
            query=query,
            variables={"per": PAGE_SIZE, "status": status},
            response_key="users",
            ssl_validation=ssl_validation,
            proxy=proxy,
        ):
            yield block.get("nodes") or [], page

    def _alias_index(self, alias: Any) -> Optional[int]:
        """Parse an enrollments alias key (e.g. 'u3') into its index.

        Args:
            alias (Any): Alias key from a GraphQL error's `path`.

        Returns:
            int: Index into the batch, or None when `alias` is not a
                'u{index}' alias key.
        """
        if not isinstance(alias, str) or not alias.startswith("u"):
            return None
        return self.to_int(alias[1:])

    def _log_partial_enrollment_errors(
        self, errors: List, batch: List, batch_number: int
    ) -> set:
        """Log and identify which users a batched query failed for.

        A GraphQL error is scoped to the alias named in its `path`
        (e.g. a user deleted since the last pull errors only on that
        user's alias); the enrollment data returned for every other
        alias in the same response is still valid and must not be
        discarded.

        Args:
            errors (List): GraphQL errors list, possibly empty.
            batch (List): KnowBe4 user IDs queried in this batch, in
                alias order (alias 'u{i}' is batch[i]).
            batch_number (int): Current batch number, used in logs.

        Returns:
            set: Indexes within `batch` whose alias reported an error;
                the caller must skip these when reading `data`.
        """
        failed_indexes = set()
        if not errors:
            return failed_indexes
        for error in errors:
            if not isinstance(error, dict):
                continue
            path = error.get("path") or []
            index = self._alias_index(path[0] if path else None)
            if index is not None and index < len(batch):
                failed_indexes.add(index)
        if failed_indexes:
            failed_user_ids = [
                batch[index] for index in sorted(failed_indexes)
            ]
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Error occurred while fetching"
                    f" the training details of {len(failed_user_ids)}"
                    f" user(s) in batch {batch_number} from"
                    f" {PLATFORM_NAME}."
                ),
                details=json.dumps(
                    {
                        "User IDs": failed_user_ids,
                        "Error(s)": self.format_graphql_errors(errors),
                    }
                ),
                resolution=(
                    "Verify that these user(s) still exist in"
                    " KnowBe4. Their training fields will not be"
                    " updated on this sync."
                ),
            )
        return failed_indexes

    def fetch_training_details(
        self,
        url: str,
        token: str,
        user_ids: List,
        ssl_validation,
        proxy,
    ) -> Dict:
        """Collect training counts and past due names per user.

        Enrollments are read in batches. Each batch asks for several
        users in one query by giving every user its own alias, which
        keeps the call count low without crossing the query cost cap.
        A GraphQL error on one user's alias (e.g. a user deleted since
        the last pull) only skips that user; every other user in the
        batch is still processed from the same response.

        Args:
            url (str): Region GraphQL endpoint.
            token (str): KSAT API token.
            user_ids (List): KnowBe4 user IDs to read.
            ssl_validation: SSL verification flag from the platform.
            proxy: Proxy configuration from the platform.

        Returns:
            Dict: User ID to training details. A user is absent when
                their alias failed.
        """
        training_details = {}
        batches = self.chunk_list(user_ids, ENRICHMENT_BATCH_SIZE)
        total_batches = len(batches)
        users_attempted = 0
        for batch_number, batch in enumerate(batches, start=1):
            blocks = "".join(
                ENROLLMENTS_ALIAS_BLOCK.format(
                    index=index, user_id=user_id, per=PAGE_SIZE, page=1
                )
                for index, user_id in enumerate(batch)
            )
            data, errors = self.graphql_request_allow_errors(
                logger_msg=(
                    f"fetching training details for {len(batch)}"
                    f" user(s) in batch {batch_number} from"
                    f" {PLATFORM_NAME}"
                ),
                url=url,
                token=token,
                query="query {" + blocks + "}",
                ssl_validation=ssl_validation,
                proxy=proxy,
            )
            failed_indexes = self._log_partial_enrollment_errors(
                errors, batch, batch_number
            )
            for index, user_id in enumerate(batch):
                if index in failed_indexes:
                    continue
                block = data.get(f"u{index}") or {}
                nodes = list(block.get("nodes") or [])
                pagination = block.get("pagination") or {}
                total_pages = pagination.get("pages") or 1
                if total_pages > 1:
                    nodes.extend(
                        self._fetch_remaining_enrollments(
                            url,
                            token,
                            user_id,
                            total_pages,
                            ssl_validation,
                            proxy,
                        )
                    )
                training_details[user_id] = self._summarize_enrollments(
                    nodes
                )
            users_attempted += len(batch)
            self.logger.info(
                f"{self.log_prefix}: Successfully fetched training"
                f" details for {len(batch)} user(s) in batch"
                f" {batch_number} of {total_batches}. Total fetched:"
                f" {users_attempted}."
            )
        return training_details

    def _fetch_remaining_enrollments(
        self,
        url: str,
        token: str,
        user_id: int,
        total_pages: int,
        ssl_validation,
        proxy,
    ) -> List:
        """Read the enrollment pages after the first one for a user.

        A failure on a later page stops paging for this user only and
        returns whatever pages were already read, instead of raising
        and losing the training details of every other user in the
        run.

        Args:
            url (str): Region GraphQL endpoint.
            token (str): KSAT API token.
            user_id (int): KnowBe4 user ID.
            total_pages (int): Number of enrollment pages.
            ssl_validation: SSL verification flag from the platform.
            proxy: Proxy configuration from the platform.

        Returns:
            List: Enrollment nodes from page 2 onwards, possibly
                incomplete when a later page could not be fetched.
        """
        nodes = []
        for page in range(2, total_pages + 1):
            block = ENROLLMENTS_ALIAS_BLOCK.format(
                index=0, user_id=user_id, per=PAGE_SIZE, page=page
            )
            try:
                data = self.graphql_request(
                    logger_msg=(
                        f"fetching training details for user ID"
                        f" '{user_id}' for page {page} from"
                        f" {PLATFORM_NAME}"
                    ),
                    url=url,
                    token=token,
                    query="query {" + block + "}",
                    ssl_validation=ssl_validation,
                    proxy=proxy,
                )
            except KnowBe4PluginException:
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: Skipping the remaining"
                        " enrollment page(s) of user ID"
                        f" '{user_id}' because page {page} could not"
                        " be fetched."
                    ),
                    resolution=(
                        "Verify that this user still exists in"
                        " KnowBe4. Their past due training count and"
                        " names may be incomplete for this sync."
                    ),
                )
                break
            nodes.extend((data.get("u0") or {}).get("nodes") or [])
        return nodes

    def _summarize_enrollments(self, nodes: List) -> Dict:
        """Roll enrollment rows up into the training fields.

        Args:
            nodes (List): Enrollment nodes for one user.

        Returns:
            Dict: Past due count and past due names.
        """
        past_due_names = []
        past_due_count = 0
        for node in nodes:
            if not isinstance(node, dict):
                continue
            if node.get("pastDue"):
                past_due_count += 1
                name = self._extract_field_from_event(
                    "enrollmentItem.title", node
                ) or self._extract_field_from_event(
                    "trainingCampaign.name", node
                )
                if name:
                    past_due_names.append(name)
        return {
            "past_due_count": past_due_count,
            "past_due_names": past_due_names,
        }

    def fetch_passwordiq_states(
        self, url: str, token: str, ssl_validation, proxy
    ) -> Dict:
        """Read PasswordIQ detections for every mapped KSAT user.

        The PasswordIQ query has no per user filter, so the full list
        is read once and joined on the KSAT user ID.

        Args:
            url (str): Region GraphQL endpoint.
            token (str): PasswordIQ API token.
            ssl_validation: SSL verification flag from the platform.
            proxy: Proxy configuration from the platform.

        Returns:
            Dict: KSAT user ID to the list of AD violation detection
                types currently active and unresolved for that user.
        """
        states = {}
        page = 1
        users_attempted = 0
        while True:
            data = self.graphql_request(
                logger_msg=(
                    f"fetching PasswordIQ detections for page {page}"
                    f" from {PLATFORM_NAME}"
                ),
                url=url,
                token=token,
                query=PASSWORDIQ_QUERY,
                ssl_validation=ssl_validation,
                proxy=proxy,
                variables={
                    "detection": PIQ_DETECTIONS,
                    "userType": PIQ_USER_TYPE,
                    "pagination": {"per": PIQ_PAGE_SIZE, "page": page},
                },
            )
            block = data.get("passwordIqUserStates") or {}
            page_users = block.get("users") or []
            for node in page_users:
                kmsat_id = self.to_int((node or {}).get("kmsatId"))
                if kmsat_id is None:
                    continue
                states[kmsat_id] = self._summarize_piq_events(
                    node.get("events") or []
                )
            pagination = block.get("pagination") or {}
            total_pages = pagination.get("pages") or 0
            users_attempted += len(page_users)
            self.logger.info(
                f"{self.log_prefix}: Successfully fetched PasswordIQ"
                f" detections for {len(page_users)} user(s) in page"
                f" {page} of {total_pages}. Total fetched:"
                f" {users_attempted}."
            )
            if page >= total_pages:
                break
            page += 1
        return states

    def _summarize_piq_events(self, events: List) -> List:
        """Collect the AD violation types detected for one user.

        Args:
            events (List): PasswordIQ event nodes for one user.

        Returns:
            List: Human-readable labels (see PIQ_DETECTION_LABELS) for
                the detection types currently detected and unresolved
                for the user, in the order the API returned them.
        """
        detections = []
        for event in events:
            if not isinstance(event, dict):
                continue
            if (
                not event.get("detected")
                or event.get("resolved")
                or str(event.get("status")).lower() == "resolved"
            ):
                continue
            name = self._extract_field_from_event(
                "detectionType.name", event
            )
            if name not in PIQ_DETECTIONS:
                continue
            label = PIQ_DETECTION_LABELS.get(name, name)
            if label not in detections:
                detections.append(label)
        return detections

    def fetch_security_coach_scores(
        self, url: str, token: str, ssl_validation, proxy
    ) -> Tuple[Dict, Dict]:
        """Read SecurityCoach sub scores for every mapped user.

        The SecurityCoach query has no per user filter, so the full
        list is read once and joined on email and on user ID.

        Args:
            url (str): Region GraphQL endpoint.
            token (str): SecurityCoach API token.
            ssl_validation: SSL verification flag from the platform.
            proxy: Proxy configuration from the platform.

        Returns:
            Tuple: Scores by lower case email, and scores by user ID.
        """
        by_email = {}
        by_id = {}
        start = 0
        draw = 1
        while True:
            row_offset = start
            data = self.graphql_request(
                logger_msg=(
                    "fetching SecurityCoach scores starting at row"
                    f" {start} from {PLATFORM_NAME}"
                ),
                url=url,
                token=token,
                query=SECURITY_COACH_QUERY,
                ssl_validation=ssl_validation,
                proxy=proxy,
                variables={
                    "search": "",
                    "draw": draw,
                    "start": start,
                    "length": SECURITY_COACH_PAGE_SIZE,
                },
            )
            block = data.get("securityCoachListMappedUsers") or {}
            rows = block.get("data") or []
            for row in rows:
                if not isinstance(row, dict):
                    continue
                scores = {
                    field_name: row.get(source)
                    for field_name, source in (
                        SECURITY_COACH_FIELD_MAPPING.items()
                    )
                }
                email = row.get("email")
                if email:
                    by_email[str(email).lower()] = scores
                user_id = self.to_int(row.get("id"))
                if user_id is not None:
                    by_id[user_id] = scores
            start += len(rows)
            draw += 1
            total = block.get("recordsTotal") or 0
            self.logger.info(
                f"{self.log_prefix}: Successfully fetched"
                f" SecurityCoach scores for {len(rows)} user(s)"
                f" starting at row {row_offset}. Total fetched:"
                f" {start} of {total}."
            )
            if not rows or start >= total:
                break
        return by_email, by_id

    # ------------------------------------------------------------------
    # Action parameter sources
    # ------------------------------------------------------------------

    def fetch_groups(
        self, url: str, token: str, ssl_validation, proxy
    ) -> List:
        """Read the console groups available for group actions.

        Args:
            url (str): Region GraphQL endpoint.
            token (str): KSAT API token.
            ssl_validation: SSL verification flag from the platform.
            proxy: Proxy configuration from the platform.

        Returns:
            List: Group nodes with their ID and name.
        """
        groups = []
        for block, _ in self.paginate(
            logger_msg="fetching groups",
            url=url,
            token=token,
            query=GROUPS_QUERY,
            variables={
                "per": PAGE_SIZE,
                "status": GROUP_STATUS_ACTIVE,
                "type": GROUP_TYPE_CONSOLE,
            },
            response_key="groups",
            ssl_validation=ssl_validation,
            proxy=proxy,
        ):
            groups.extend(block.get("nodes") or [])
        return groups

    def fetch_training_campaigns(
        self, url: str, token: str, ssl_validation, proxy
    ) -> List:
        """Read the training campaigns users can be enrolled into.

        Args:
            url (str): Region GraphQL endpoint.
            token (str): KSAT API token.
            ssl_validation: SSL verification flag from the platform.
            proxy: Proxy configuration from the platform.

        Returns:
            List: Training campaign nodes with their ID and name.
        """
        campaigns = []
        for block, _ in self.paginate(
            logger_msg="fetching training campaigns",
            url=url,
            token=token,
            query=TRAINING_CAMPAIGNS_QUERY,
            variables={
                "per": PAGE_SIZE,
                "statuses": TRAINING_CAMPAIGN_STATUSES,
            },
            response_key="trainingCampaigns",
            ssl_validation=ssl_validation,
            proxy=proxy,
        ):
            campaigns.extend(block.get("nodes") or [])
        return campaigns

    # ------------------------------------------------------------------
    # Action operations
    # ------------------------------------------------------------------

    def _check_mutation_errors(
        self, payload: Dict, logger_msg: str
    ) -> None:
        """Raise when a mutation payload reports errors.

        Args:
            payload (Dict): Mutation payload from the response.
            logger_msg (str): What the call is doing, used in logs.

        Raises:
            KnowBe4PluginException: When the payload holds errors.
        """
        errors = (payload or {}).get("errors")
        if not errors:
            return
        err_msg = GRAPHQL_ERROR_MSG.format(logger_msg=logger_msg)
        self.logger.error(
            message=f"{self.log_prefix}: {err_msg}",
            details=f"API response: {payload}",
            resolution=(
                "Verify that the target user(s) and the value selected"
                " in the action configuration still exist in KnowBe4."
            ),
        )
        raise KnowBe4PluginException(err_msg)

    def _run_bulk_mutation(
        self,
        logger_msg: str,
        url: str,
        token: str,
        query: str,
        variables: Dict,
        operation: str,
        ssl_validation,
        proxy,
    ) -> set:
        """Run a mutation that accepts several user IDs at once.

        Args:
            logger_msg (str): What the call is doing, used in logs.
            url (str): Region GraphQL endpoint.
            token (str): KSAT API token.
            query (str): Mutation document.
            variables (Dict): Mutation variables.
            operation (str): 'Operation' value the mutation performs,
                used to find the mutation's field name in the
                response.
            ssl_validation: SSL verification flag from the platform.
            proxy: Proxy configuration from the platform.

        Returns:
            set: User IDs KnowBe4 confirmed in its response.

        Raises:
            KnowBe4PluginException: When the mutation reports errors.
        """
        data = self.graphql_request(
            logger_msg=logger_msg,
            url=url,
            token=token,
            query=query,
            ssl_validation=ssl_validation,
            proxy=proxy,
            variables=variables,
        )
        payload = data.get(MUTATION_RESPONSE_KEYS[operation]) or {}
        self._check_mutation_errors(payload, logger_msg)
        node = payload.get("node") or []
        if isinstance(node, dict):
            node = [node]
        confirmed = set()
        for entry in node:
            user_id = self.to_int((entry or {}).get("id"))
            if user_id is not None:
                confirmed.add(user_id)
        return confirmed

    def find_group_by_name(
        self, url: str, token: str, group_name: str, ssl_validation, proxy
    ) -> Optional[int]:
        """Find an existing group by its name.

        Args:
            url (str): Region GraphQL endpoint.
            token (str): KSAT API token.
            group_name (str): Group name to look for.
            ssl_validation: SSL verification flag from the platform.
            proxy: Proxy configuration from the platform.

        Returns:
            int: ID of the matching group, or None when no group has
                that name.
        """
        wanted = str(group_name).strip().lower()
        for group in self.fetch_groups(
            url=url, token=token, ssl_validation=ssl_validation, proxy=proxy
        ):
            name = group.get("name")
            if name and str(name).strip().lower() == wanted:
                return self.to_int(group.get("id"))
        return None

    def create_group(
        self, url: str, token: str, group_name: str, ssl_validation, proxy
    ) -> int:
        """Create a new group in KnowBe4.

        Args:
            url (str): Region GraphQL endpoint.
            token (str): KSAT API token.
            group_name (str): Name of the group to create.
            ssl_validation: SSL verification flag from the platform.
            proxy: Proxy configuration from the platform.

        Returns:
            int: ID of the created group.

        Raises:
            KnowBe4PluginException: When the group is not created.
        """
        logger_msg = f"creating group '{group_name}' in {PLATFORM_NAME}"
        data = self.graphql_request(
            logger_msg=logger_msg,
            url=url,
            token=token,
            query=GROUP_CREATE_MUTATION,
            ssl_validation=ssl_validation,
            proxy=proxy,
            variables={"attributes": {"name": group_name}},
        )
        payload = data.get("groupCreate") or {}
        self._check_mutation_errors(payload, logger_msg)
        group_id = self.to_int((payload.get("node") or {}).get("id"))
        if group_id is None:
            err_msg = (
                f"Unable to create group '{group_name}' in"
                f" {PLATFORM_NAME}."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=f"API response: {payload}",
                resolution=(
                    "Verify that the KSAT API token has write"
                    " permission and that the group name is not"
                    " already in use."
                ),
            )
            raise KnowBe4PluginException(err_msg)
        return group_id

    def add_users_to_group(
        self,
        url: str,
        token: str,
        user_ids: List,
        group_id: int,
        group_name: str,
        batch_number: int,
        ssl_validation,
        proxy,
    ) -> set:
        """Add users to a group.

        Args:
            url (str): Region GraphQL endpoint.
            token (str): KSAT API token.
            user_ids (List): KnowBe4 user IDs.
            group_id (int): Target group ID.
            group_name (str): Target group name, used in log
                messages so the customer sees a name instead of an
                internal ID.
            batch_number (int): Current batch number, used in log
                messages.
            ssl_validation: SSL verification flag from the platform.
            proxy: Proxy configuration from the platform.

        Returns:
            set: User IDs KnowBe4 confirmed.
        """
        return self._run_bulk_mutation(
            logger_msg=(
                f"adding {len(user_ids)} user(s) to group"
                f" '{group_name}' in batch {batch_number} from"
                f" {PLATFORM_NAME}"
            ),
            url=url,
            token=token,
            query=ADD_TO_GROUPS_MUTATION,
            variables={"userIds": user_ids, "groupIds": [group_id]},
            operation=ACTION_ADD_TO_GROUP,
            ssl_validation=ssl_validation,
            proxy=proxy,
        )

    def remove_users_from_group(
        self,
        url: str,
        token: str,
        user_ids: List,
        group_id: int,
        group_name: str,
        batch_number: int,
        ssl_validation,
        proxy,
    ) -> set:
        """Remove users from a group.

        Args:
            url (str): Region GraphQL endpoint.
            token (str): KSAT API token.
            user_ids (List): KnowBe4 user IDs.
            group_id (int): Target group ID.
            group_name (str): Target group name, used in log
                messages so the customer sees a name instead of an
                internal ID.
            batch_number (int): Current batch number, used in log
                messages.
            ssl_validation: SSL verification flag from the platform.
            proxy: Proxy configuration from the platform.

        Returns:
            set: User IDs KnowBe4 confirmed.
        """
        return self._run_bulk_mutation(
            logger_msg=(
                f"removing {len(user_ids)} user(s) from group"
                f" '{group_name}' in batch {batch_number} from"
                f" {PLATFORM_NAME}"
            ),
            url=url,
            token=token,
            query=REMOVE_FROM_GROUP_MUTATION,
            variables={"userIds": user_ids, "groupId": group_id},
            operation=ACTION_REMOVE_FROM_GROUP,
            ssl_validation=ssl_validation,
            proxy=proxy,
        )

    def enroll_user_in_training(
        self,
        url: str,
        token: str,
        campaign_id: int,
        campaign_name: str,
        user_id: int,
        ssl_validation,
        proxy,
    ) -> None:
        """Enroll one user into a training campaign.

        Args:
            url (str): Region GraphQL endpoint.
            token (str): KSAT API token.
            campaign_id (int): Training campaign ID.
            campaign_name (str): Training campaign name, used in log
                messages so the customer sees a name instead of an
                internal ID.
            user_id (int): KnowBe4 user ID.
            ssl_validation: SSL verification flag from the platform.
            proxy: Proxy configuration from the platform.

        Raises:
            KnowBe4PluginException: When the enrollment fails.
        """
        logger_msg = (
            f"enrolling user ID '{user_id}' into training campaign"
            f" '{campaign_name}' in {PLATFORM_NAME}"
        )
        data = self.graphql_request(
            logger_msg=logger_msg,
            url=url,
            token=token,
            query=ENROLL_USER_MUTATION,
            ssl_validation=ssl_validation,
            proxy=proxy,
            variables={
                "trainingCampaignId": campaign_id,
                "userId": user_id,
            },
        )
        payload = data.get("trainingCampaignAddUser") or {}
        self._check_mutation_errors(payload, logger_msg)
        if payload.get("node") is not True:
            err_msg = (
                f"Unable to enroll user ID '{user_id}' into training"
                f" campaign ID '{campaign_id}' in {PLATFORM_NAME}."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=f"API response: {payload}",
                resolution=(
                    "Verify that the user and the training campaign"
                    " still exist in KnowBe4 and that the campaign"
                    " accepts new users."
                ),
            )
            raise KnowBe4PluginException(err_msg)

    def update_user_custom_field(
        self,
        url: str,
        token: str,
        user_id: int,
        field_slot: str,
        field_value: str,
        ssl_validation,
        proxy,
    ) -> None:
        """Write a custom field value on one user.

        Args:
            url (str): Region GraphQL endpoint.
            token (str): KSAT API token.
            user_id (int): KnowBe4 user ID.
            field_slot (str): Custom field name, customField1 to
                customField4.
            field_value (str): Value to write.
            ssl_validation: SSL verification flag from the platform.
            proxy: Proxy configuration from the platform.

        Raises:
            KnowBe4PluginException: When the update fails.
        """
        logger_msg = (
            f"updating '{field_slot}' of user ID '{user_id}' in"
            f" {PLATFORM_NAME}"
        )
        data = self.graphql_request(
            logger_msg=logger_msg,
            url=url,
            token=token,
            query=USER_EDIT_MUTATION,
            ssl_validation=ssl_validation,
            proxy=proxy,
            variables={
                "userId": user_id,
                "attributes": {field_slot: field_value},
            },
        )
        payload = data.get("userEdit") or {}
        self._check_mutation_errors(payload, logger_msg)
        if not (payload.get("node") or {}).get("id"):
            err_msg = (
                f"Unable to update '{field_slot}' of user ID"
                f" '{user_id}' in {PLATFORM_NAME}."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=f"API response: {payload}",
                resolution=(
                    "Verify that the user exists in KnowBe4 and that"
                    " the KSAT API token has write permission."
                ),
            )
            raise KnowBe4PluginException(err_msg)
