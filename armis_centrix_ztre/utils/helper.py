"""CRE Armis Centrix plugin helper module.

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
"""

import base64
import copy
import hashlib
import json
import math
import re
import time
import traceback
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import (
    Any,
    Dict,
    Generator,
    Iterable,
    Iterator,
    List,
    NamedTuple,
    Optional,
    Tuple,
)
from urllib.parse import urlparse

import requests

from netskope.common.utils import add_user_agent

from . import constants as CONST
from .exceptions import (
    ArmisAPIException,
    ArmisAuthenticationException,
    ArmisPluginException,
    ArmisValidationException,
)


class ArmisConfiguration(NamedTuple):
    """Configuration parameters of the plugin, cleaned for use."""

    api_base_url: str
    tenant_url: str
    client_id: str
    client_secret: str
    vendor_id: str
    scopes: List[str]
    pull_custom_properties: str
    custom_properties: List[str]


class ArmisPluginHelper:
    """Armis API calls, token cache, record building and value checks."""

    def __init__(
        self,
        logger,
        log_prefix: str,
        plugin_name: str,
        plugin_version: str,
        ssl_validation: bool = True,
        proxy: Optional[Dict] = None,
    ):
        """Initialize the helper.

        Args:
            logger: Cloud Exchange logger.
            log_prefix (str): Prefix of every log message.
            plugin_name (str): Plugin name.
            plugin_version (str): Plugin version.
            ssl_validation (bool): Verify the TLS certificate of Armis.
            proxy (Optional[Dict]): Proxy settings of Cloud Exchange.
        """
        self.logger = logger
        self.log_prefix = log_prefix
        self.plugin_name = plugin_name
        self.plugin_version = plugin_version
        self.ssl_validation = ssl_validation
        self.proxy = proxy
        # True while a UI-driven call runs (see single_attempt()); every
        # request is then sent once, without retry or wait.
        self._single_attempt = False
        self._transformations = {
            CONST.TRANSFORM_DEVICE_ID: self._to_device_id,
            CONST.TRANSFORM_STRING: self._to_string,
            CONST.TRANSFORM_LIST: self._to_list,
            CONST.TRANSFORM_NUMBER: self._to_number,
            CONST.TRANSFORM_SITE: self._to_site,
            CONST.TRANSFORM_DATETIME: self.parse_datetime,
        }
        self._value_coercions = {
            CONST.PROPERTY_TYPE_STRING: self._coerce_string,
            CONST.PROPERTY_TYPE_ENUM: self._coerce_string,
            CONST.PROPERTY_TYPE_INTEGER: self._coerce_integer,
            CONST.PROPERTY_TYPE_BOOLEAN: self._to_boolean,
            CONST.PROPERTY_TYPE_EXTERNAL_LINK: self._coerce_link,
            CONST.PROPERTY_TYPE_TIMESTAMP: self._coerce_timestamp,
        }

    # ------------------------------------------------------------------
    # HTTP
    # ------------------------------------------------------------------
    def _add_user_agent(self, headers: Optional[Dict] = None) -> Dict:
        """Add the plugin User-Agent to the request headers.

        Args:
            headers (Optional[Dict]): Request headers.

        Returns:
            Dict: Headers with the User-Agent.
        """
        if headers and CONST.HEADER_USER_AGENT in headers:
            return headers
        headers = add_user_agent(header=headers)
        ce_added_agent = headers.get(
            CONST.HEADER_USER_AGENT, CONST.DEFAULT_CE_USER_AGENT
        )
        headers[CONST.HEADER_USER_AGENT] = CONST.USER_AGENT_FORMAT.format(
            ce_agent=ce_added_agent,
            module=CONST.MODULE_NAME.lower(),
            plugin=self.plugin_name.lower().replace(
                CONST.USER_AGENT_SPACE, CONST.USER_AGENT_SPACE_REPLACEMENT
            ),
            version=self.plugin_version,
        )
        return headers

    def api_helper(
        self,
        logger_msg: str,
        url: str,
        method: str,
        configuration: Optional[Dict] = None,
        storage: Optional[Dict] = None,
        params: Optional[Dict] = None,
        json_body: Any = None,
        is_token_call: bool = False,
        is_validation: bool = False,
        regenerate_auth_token: bool = True,
        is_handle_error_required: bool = True,
    ):
        """Call the Armis API with retries and error handling.

        Args:
            logger_msg (str): Operation, used in the log messages.
            url (str): Endpoint URL.
            method (str): HTTP method.
            configuration (Optional[Dict]): Configuration parameters,
                used to get the access token.
            storage (Optional[Dict]): Storage holding the token cache.
            params (Optional[Dict]): Query parameters.
            json_body (Any): JSON body of the request.
            is_token_call (bool): The request generates the token.
            is_validation (bool): The request is made by validate();
                no retry and no wait.
            regenerate_auth_token (bool): Renew the token once on 401.
            is_handle_error_required (bool): Return the parsed JSON
                instead of the response object.

        Returns:
            Any: Parsed JSON response, or the response object.
        """
        headers = self._build_headers(
            configuration, storage, json_body, is_token_call, is_validation
        )
        debug_msg = CONST.DEBUG_API_REQUEST.format(
            logger_msg=logger_msg, method=method, url=url
        )
        self.logger.debug(message=f"{self.log_prefix}: {debug_msg}")
        try:
            response = self._send_with_retry(
                logger_msg, url, method, headers, params, json_body,
                is_validation,
            )
        except ArmisPluginException:
            raise
        except requests.exceptions.ReadTimeout as error:
            self._raise_request_error(error, logger_msg, is_token_call)
        except requests.exceptions.ProxyError as error:
            self._raise_request_error(error, logger_msg, is_token_call)
        except requests.exceptions.ConnectionError as error:
            self._raise_request_error(error, logger_msg, is_token_call)
        except requests.HTTPError as error:
            self._raise_request_error(error, logger_msg, is_token_call)
        except Exception as error:
            self._raise_unexpected_error(error, logger_msg)

        status_code = response.status_code
        if status_code == CONST.UNAUTHORIZED_STATUS and not is_token_call:
            self._check_token_renewal(
                response, logger_msg, regenerate_auth_token
            )
            self.get_access_token(
                configuration,
                storage,
                force_refresh=True,
                is_validation=is_validation,
            )
            return self.api_helper(
                logger_msg=logger_msg,
                url=url,
                method=method,
                configuration=configuration,
                storage=storage,
                params=params,
                json_body=json_body,
                is_validation=is_validation,
                regenerate_auth_token=False,
                is_handle_error_required=is_handle_error_required,
            )
        if status_code in CONST.RETRY_STATUS_CODES:
            self._raise_retry_exhausted(response, logger_msg, is_validation)
        if not is_handle_error_required:
            return response
        return self.handle_error(
            response, logger_msg, is_validation, is_token_call
        )

    def _build_headers(
        self,
        configuration: Optional[Dict],
        storage: Optional[Dict],
        json_body: Any,
        is_token_call: bool,
        is_validation: bool,
    ) -> Dict:
        """Build the request headers.

        Args:
            configuration (Optional[Dict]): Configuration parameters.
            storage (Optional[Dict]): Storage holding the token cache.
            json_body (Any): JSON body of the request.
            is_token_call (bool): The request generates the token.
            is_validation (bool): The request is made by validate().

        Returns:
            Dict: Request headers.
        """
        headers = {CONST.HEADER_ACCEPT: CONST.MIME_JSON}
        if json_body is not None:
            headers[CONST.HEADER_CONTENT_TYPE] = CONST.MIME_JSON
        if not is_token_call:
            access_token = self.get_access_token(
                configuration, storage, is_validation=is_validation
            )
            headers[CONST.HEADER_AUTHORIZATION] = CONST.BEARER_FORMAT.format(
                token=access_token
            )
        return self._add_user_agent(headers)

    @contextmanager
    def single_attempt(self) -> Generator[None, None, None]:
        """Send every request once, without retry or wait.

        Used by the UI-driven calls (validate, dynamic fields, entities,
        action parameters and action validation), so that the UI never
        waits on retries. Pull, refresh and action execution keep their
        retries.

        Yields:
            None: While the block runs.
        """
        previous = self._single_attempt
        self._single_attempt = True
        try:
            yield
        finally:
            self._single_attempt = previous

    def _is_single_attempt(self, is_validation: bool) -> bool:
        """Check whether a request must be sent once only.

        Args:
            is_validation (bool): The request is made by validate().

        Returns:
            bool: True for validation and UI-driven calls.
        """
        return is_validation or self._single_attempt

    def _send_with_retry(
        self,
        logger_msg: str,
        url: str,
        method: str,
        headers: Dict,
        params: Optional[Dict],
        json_body: Any,
        is_validation: bool,
    ) -> requests.models.Response:
        """Send a request, retrying 429, 5xx, timeouts and lost connections.

        Args:
            logger_msg (str): Operation, used in the log messages.
            url (str): Endpoint URL.
            method (str): HTTP method.
            headers (Dict): Request headers.
            params (Optional[Dict]): Query parameters.
            json_body (Any): JSON body of the request.
            is_validation (bool): Send once, without retry.

        Returns:
            requests.models.Response: Last response received.
        """
        for retry_counter in range(CONST.MAX_API_CALLS):
            is_last_attempt = (
                self._is_single_attempt(is_validation)
                or retry_counter == CONST.MAX_API_CALLS - 1
            )
            try:
                response = requests.request(
                    method=method,
                    url=url,
                    headers=headers,
                    params=params,
                    json=json_body,
                    verify=self.ssl_validation,
                    proxies=self.proxy,
                    timeout=CONST.REQUEST_TIMEOUT,
                )
            except requests.exceptions.ProxyError:
                raise
            except (
                requests.exceptions.Timeout,
                requests.exceptions.ConnectionError,
            ) as error:
                if is_last_attempt:
                    raise
                reason = CONST.RETRY_REASON_ERROR.format(
                    error=type(error).__name__
                )
                self._wait_before_retry(reason, logger_msg, {}, retry_counter)
                continue
            debug_msg = CONST.DEBUG_API_RESPONSE.format(
                logger_msg=logger_msg, status_code=response.status_code
            )
            self.logger.debug(message=f"{self.log_prefix}: {debug_msg}")
            if (
                response.status_code not in CONST.RETRY_STATUS_CODES
                or is_last_attempt
            ):
                return response
            reason = CONST.RETRY_REASON_STATUS.format(
                status_code=response.status_code
            )
            self._wait_before_retry(
                reason, logger_msg, response.headers, retry_counter
            )

    def _wait_before_retry(
        self,
        reason: str,
        logger_msg: str,
        headers: Dict,
        retry_counter: int,
    ):
        """Log the retry and wait before the next attempt.

        Args:
            reason (str): Why the request is retried.
            logger_msg (str): Operation, used in the log message.
            headers (Dict): Response headers.
            retry_counter (int): Index of the failed attempt.
        """
        wait_time = self._get_retry_wait(headers, retry_counter)
        message = CONST.MSG_RETRY.format(
            reason=reason,
            logger_msg=logger_msg,
            wait=wait_time,
            remaining=CONST.MAX_API_CALLS - 1 - retry_counter,
        )
        self.logger.info(message=f"{self.log_prefix}: {message}")
        time.sleep(wait_time)

    def _get_retry_wait(self, headers: Dict, retry_counter: int) -> float:
        """Get the wait before a retry.

        A numeric Retry-After header is used as is; otherwise the wait
        is DEFAULT_WAIT_TIME doubled for each retry. Both are capped at
        MAX_WAIT_TIME.

        Args:
            headers (Dict): Response headers.
            retry_counter (int): Index of the failed attempt.

        Returns:
            float: Seconds to wait.
        """
        wait_time = None
        retry_after = (headers or {}).get(CONST.HEADER_RETRY_AFTER)
        if retry_after is not None:
            try:
                wait_time = float(retry_after)
            except (TypeError, ValueError):
                wait_time = None
        if wait_time is None or not math.isfinite(wait_time) or (
            wait_time < 0
        ):
            wait_time = CONST.DEFAULT_WAIT_TIME * (
                CONST.BACKOFF_FACTOR ** retry_counter
            )
        return min(wait_time, CONST.MAX_WAIT_TIME)

    def _check_token_renewal(
        self,
        response: requests.models.Response,
        logger_msg: str,
        regenerate_auth_token: bool,
    ):
        """Allow one token renewal after a 401 response.

        Args:
            response (requests.models.Response): The 401 response.
            logger_msg (str): Operation, used in the log messages.
            regenerate_auth_token (bool): A renewal is still allowed.

        Raises:
            ArmisAuthenticationException: The renewed token was rejected.
        """
        if not regenerate_auth_token:
            message = CONST.ERR_AUTH_05.format(logger_msg=logger_msg)
            self.logger.error(
                message=f"{self.log_prefix}: {message}",
                details=self.sanitize_text(response.text),
                resolution=CONST.RES_AUTH_05,
            )
            raise ArmisAuthenticationException(
                message,
                resolution=CONST.RES_AUTH_05,
                status_code=response.status_code,
            )
        message = CONST.MSG_TOKEN_REJECTED.format(logger_msg=logger_msg)
        self.logger.info(message=f"{self.log_prefix}: {message}")

    def _raise_retry_exhausted(
        self,
        response: requests.models.Response,
        logger_msg: str,
        is_validation: bool,
    ):
        """Raise for a 429 or 5xx response left after the retries.

        Args:
            response (requests.models.Response): Last response.
            logger_msg (str): Operation, used in the log message.
            is_validation (bool): The request was sent once only.

        Raises:
            ArmisAPIException: Always.
        """
        status_code = response.status_code
        if status_code == CONST.TOO_MANY_REQUESTS_STATUS:
            retries = (
                0 if self._is_single_attempt(is_validation)
                else CONST.MAX_API_CALLS - 1
            )
            message = CONST.ERR_API_01.format(
                logger_msg=logger_msg, retries=retries
            )
            resolution = CONST.RES_API_01
        else:
            message = CONST.ERR_API_02.format(
                logger_msg=logger_msg, status_code=status_code
            )
            resolution = CONST.RES_API_02
        message = self._add_api_message(message, response)
        self.logger.error(
            message=f"{self.log_prefix}: {message}",
            details=self.sanitize_text(response.text),
            resolution=resolution,
        )
        raise ArmisAPIException(
            message, resolution=resolution, status_code=status_code
        )

    def _raise_request_error(
        self, error: Exception, logger_msg: str, is_token_call: bool
    ):
        """Raise for a request that failed without a response.

        Args:
            error (Exception): Timeout, proxy, connection or HTTP error.
            logger_msg (str): Operation, used in the log message.
            is_token_call (bool): The request generates the token.

        Raises:
            ArmisPluginException: Always.
        """
        error_text = self.sanitize_text(error)
        if is_token_call:
            message = CONST.ERR_AUTH_04.format(error=error_text)
            resolution = CONST.RES_AUTH_04
            exception_class = ArmisAuthenticationException
        else:
            message = CONST.ERR_API_03.format(
                logger_msg=logger_msg,
                status_code=type(error).__name__,
                text=error_text,
            )
            resolution = CONST.RES_API_03
            exception_class = ArmisAPIException
        self.logger.error(
            message=f"{self.log_prefix}: {message}",
            details=traceback.format_exc(),
            resolution=resolution,
        )
        raise exception_class(message, resolution=resolution)

    def _raise_unexpected_error(self, error: Exception, logger_msg: str):
        """Raise for an unexpected error of a request.

        Args:
            error (Exception): Unexpected error.
            logger_msg (str): Operation, used in the log message.

        Raises:
            ArmisAPIException: Always.
        """
        message = CONST.ERR_GEN_02.format(
            logger_msg=logger_msg, error=self.sanitize_text(error)
        )
        self.logger.error(
            message=f"{self.log_prefix}: {message}",
            details=traceback.format_exc(),
            resolution=CONST.RES_GEN_02,
        )
        raise ArmisAPIException(message, resolution=CONST.RES_GEN_02)

    def handle_error(
        self,
        response: requests.models.Response,
        logger_msg: str,
        is_validation: bool = False,
        is_token_call: bool = False,
    ) -> Any:
        """Return the JSON of a successful response, else raise.

        Args:
            response (requests.models.Response): API response.
            logger_msg (str): Operation, used in the log message.
            is_validation (bool): The request is made by validate().
            is_token_call (bool): The request generates the token.

        Returns:
            Any: Parsed JSON, or {} for 204.

        Raises:
            ArmisPluginException: For any other status code.
        """
        status_code = response.status_code
        if status_code in CONST.SUCCESS_STATUS_CODES:
            return self.parse_response(
                response, logger_msg, is_validation, is_token_call
            )
        if status_code == CONST.NO_CONTENT_STATUS:
            return {}
        # The API message of the response body is added to the message (also
        # shown in the UI, for example the validation toast); the whole body
        # goes in the details.
        if is_token_call and status_code in CONST.TOKEN_ERRORS:
            message, resolution = CONST.TOKEN_ERRORS[status_code]
            exception_class = ArmisAuthenticationException
        elif status_code in CONST.API_ERRORS:
            message_format, resolution = CONST.API_ERRORS[status_code]
            message = message_format.format(logger_msg=logger_msg)
            exception_class = ArmisAPIException
        else:
            message = CONST.ERR_API_08.format(
                logger_msg=logger_msg, status_code=status_code
            )
            resolution = CONST.RES_API_03
            exception_class = ArmisAPIException
        message = self._add_api_message(message, response)
        self.logger.error(
            message=f"{self.log_prefix}: {message}",
            details=self.sanitize_text(response.text),
            resolution=resolution,
        )
        raise exception_class(
            message, resolution=resolution, status_code=status_code
        )

    def _extract_api_message(self, body: Any) -> str:
        """Get the API message of a decoded error response body.

        Args:
            body (Any): Decoded JSON body.

        Returns:
            str: The first non-empty value of CONST.API_MESSAGE_KEYS (a
                nested message or a list of messages is flattened), else
                "".
        """
        if isinstance(body, str):
            return body.strip()
        if isinstance(body, list):
            texts = [self._extract_api_message(item) for item in body[:3]]
            return "; ".join(text for text in texts if text)
        if isinstance(body, dict):
            for key in CONST.API_MESSAGE_KEYS:
                if text := self._extract_api_message(body.get(key)):
                    return text
            if text := self._extract_api_message(body.get("errors")):
                return text
        return ""

    def _add_api_message(
        self, message: str, response: requests.models.Response
    ) -> str:
        """Add the API message of an error response to a message.

        Args:
            message (str): Message of the error.
            response (requests.models.Response): Error response.

        Returns:
            str: The message, followed by the API message when the body is
                JSON and has one (cleaned, without tokens and truncated to
                CONST.MAX_API_MESSAGE_LENGTH characters).
        """
        try:
            api_message = self._extract_api_message(response.json())
        except ValueError:
            return message
        api_message = self.sanitize_text(" ".join(api_message.split()))
        if not api_message:
            return message
        if len(api_message) > CONST.MAX_API_MESSAGE_LENGTH:
            api_message = api_message[: CONST.MAX_API_MESSAGE_LENGTH] + "..."
        if not api_message.endswith((".", "!", "?")):
            api_message += "."
        return message + CONST.MSG_API_MESSAGE.format(text=api_message)

    def parse_response(
        self,
        response: requests.models.Response,
        logger_msg: str,
        is_validation: bool = False,
        is_token_call: bool = False,
    ) -> Any:
        """Parse the JSON body of a response.

        Args:
            response (requests.models.Response): API response.
            logger_msg (str): Operation, used in the log message.
            is_validation (bool): The request is made by validate().
            is_token_call (bool): The request generates the token.

        Returns:
            Any: Parsed JSON.

        Raises:
            ArmisPluginException: The body is not valid JSON.
        """
        try:
            return response.json()
        except ValueError:
            if is_token_call:
                message = CONST.ERR_AUTH_03
                resolution = CONST.RES_AUTH_03
                exception_class = ArmisAuthenticationException
            else:
                message = CONST.ERR_API_04.format(logger_msg=logger_msg)
                resolution = CONST.RES_API_04
                exception_class = ArmisAPIException
            self.logger.error(
                message=f"{self.log_prefix}: {message}",
                details=self.sanitize_text(response.text),
                resolution=resolution,
            )
            raise exception_class(
                message,
                resolution=resolution,
                status_code=response.status_code,
            )

    def sanitize_text(self, text: Any) -> str:
        """Remove tokens from a text and truncate it for the logs.

        Args:
            text (Any): Response text, error or value to log.

        Returns:
            str: Text without tokens, at most MAX_RESPONSE_TEXT_LENGTH
                characters long.
        """
        text = "" if text is None else str(text)
        text = re.sub(
            CONST.ACCESS_TOKEN_REDACTION_PATTERN,
            CONST.ACCESS_TOKEN_REDACTION_REPLACEMENT,
            text,
        )
        text = re.sub(CONST.JWT_REDACTION_PATTERN, CONST.REDACTED, text)
        text = re.sub(CONST.BEARER_REDACTION_PATTERN, CONST.REDACTED, text)
        return text[: CONST.MAX_RESPONSE_TEXT_LENGTH]

    # ------------------------------------------------------------------
    # Configuration
    # ------------------------------------------------------------------
    def _get_text(self, configuration: Dict, key: str) -> str:
        """Get a stripped text parameter.

        Args:
            configuration (Dict): Configuration or action parameters.
            key (str): Parameter key.

        Returns:
            str: Stripped value, or "" when it is not a string.
        """
        value = (configuration or {}).get(key)
        return value.strip() if isinstance(value, str) else ""

    def get_config_params(
        self, configuration: Optional[Dict]
    ) -> ArmisConfiguration:
        """Get the configuration parameters, cleaned for use.

        Args:
            configuration (Optional[Dict]): Configuration parameters.

        Returns:
            ArmisConfiguration: Stripped text values (the Client Secret
                as is), the Tenant URL with a trailing slash and the
                parsed Scopes and Custom Properties.
        """
        configuration = configuration or {}
        client_secret = configuration.get(CONST.CONFIG_CLIENT_SECRET)
        return ArmisConfiguration(
            api_base_url=self._get_text(
                configuration, CONST.CONFIG_API_BASE_URL
            ).rstrip(CONST.URL_PATH_SEPARATOR),
            tenant_url=self.normalize_tenant_url(
                self._get_text(configuration, CONST.CONFIG_TENANT_URL)
            ),
            client_id=self._get_text(configuration, CONST.CONFIG_CLIENT_ID),
            client_secret=(
                client_secret if isinstance(client_secret, str) else ""
            ),
            vendor_id=self._get_text(configuration, CONST.CONFIG_VENDOR_ID),
            scopes=self.get_scopes(configuration),
            pull_custom_properties=self._get_text(
                configuration, CONST.CONFIG_PULL_CUSTOM_PROPERTIES
            ),
            custom_properties=self.get_selected_properties(configuration),
        )

    def normalize_tenant_url(self, tenant_url: str) -> str:
        """Add the trailing slash Armis expects on the Tenant URL.

        Args:
            tenant_url (str): Stripped Tenant URL.

        Returns:
            str: Tenant URL ending with a slash, or "" when empty.
        """
        if tenant_url and not tenant_url.endswith(CONST.URL_PATH_SEPARATOR):
            return tenant_url + CONST.URL_PATH_SEPARATOR
        return tenant_url

    def parse_scopes(self, scopes: Any) -> List[str]:
        """Split comma-separated permissions.

        Args:
            scopes (Any): Custom Permissions parameter.

        Returns:
            List[str]: Non-empty scopes, without duplicates, in order.
        """
        if not isinstance(scopes, str):
            return []
        items = [
            scope.strip() for scope in scopes.split(CONST.SCOPES_SEPARATOR)
        ]
        return list(dict.fromkeys(scope for scope in items if scope))

    def get_selected_scopes(self, configuration: Optional[Dict]) -> List:
        """Get the values selected in the Scopes multichoice.

        Args:
            configuration (Optional[Dict]): Configuration parameters.

        Returns:
            List: Selected values, stripped, without duplicates, in
                order; [] when Scopes is not a list.
        """
        selected = (configuration or {}).get(CONST.CONFIG_SCOPES)
        if not isinstance(selected, list):
            return []
        items = [
            item.strip() if isinstance(item, str) else item
            for item in selected
        ]
        return list(dict.fromkeys(item for item in items if item))

    def is_custom_scope_selected(self, configuration: Optional[Dict]) -> bool:
        """Check whether 'Custom Permissions' is selected in Scopes.

        Args:
            configuration (Optional[Dict]): Configuration parameters.

        Returns:
            bool: True when the Custom Permissions field applies.
        """
        return CONST.SCOPE_CUSTOM in self.get_selected_scopes(configuration)

    def get_scopes(self, configuration: Optional[Dict]) -> List[str]:
        """Get the scopes requested for the access token.

        Args:
            configuration (Optional[Dict]): Configuration parameters.

        Returns:
            List[str]: Armis permissions of the selected Scopes options,
                plus the Custom Permissions when 'Custom Permissions' is
                selected, without duplicates.
        """
        selected = self.get_selected_scopes(configuration)
        scopes = []
        for option in selected:
            scopes.extend(CONST.SCOPE_GROUPS.get(option, ()))
        if CONST.SCOPE_CUSTOM in selected:
            scopes.extend(
                self.parse_scopes(
                    (configuration or {}).get(CONST.CONFIG_CUSTOM_PERMISSIONS)
                )
            )
        return list(dict.fromkeys(scopes))

    def get_scope_groups(self, permissions: Iterable[str]) -> List[str]:
        """Get the Scopes options whose permissions are all included.

        An option counts whether it was selected or its permissions
        were provided in Custom Permissions.

        Args:
            permissions (Iterable[str]): Armis permissions.

        Returns:
            List[str]: Scopes option values, in SCOPE_GROUPS order.
        """
        permissions = set(permissions)
        return [
            group
            for group, group_permissions in CONST.SCOPE_GROUPS.items()
            if set(group_permissions) <= permissions
        ]

    def get_scope_labels(self, groups: Iterable[str]) -> str:
        """Format Scopes options for a message.

        Args:
            groups (Iterable[str]): Scopes option values.

        Returns:
            str: Quoted labels, comma-separated.
        """
        return CONST.LIST_VALUE_SEPARATOR.join(
            CONST.QUOTED_VALUE_FORMAT.format(value=CONST.SCOPE_LABELS[group])
            for group in groups
        )

    def is_devices_entity_mapped(self, mapped_entities: Any) -> bool:
        """Check whether the Devices entity is mapped.

        Args:
            mapped_entities (Any): mappedEntities set by Cloud Exchange.

        Returns:
            bool: True when a mapping of the Devices entity has fields.
        """
        if not isinstance(mapped_entities, list):
            return False
        return any(
            isinstance(mapped_entity, dict)
            and mapped_entity.get(CONST.MAPPING_ENTITY_KEY)
            == CONST.ENTITY_DEVICES
            and mapped_entity.get(CONST.MAPPING_FIELDS_KEY)
            for mapped_entity in mapped_entities
        )

    def is_valid_scope_selection(self, selected: Any) -> bool:
        """Check that the Scopes are selected from the available options.

        Args:
            selected (Any): Scopes parameter.

        Returns:
            bool: True when every item is one of SCOPE_VALUES.
        """
        return (
            isinstance(selected, list)
            and bool(selected)
            and all(item in CONST.SCOPE_VALUES for item in selected)
        )

    def is_valid_custom_permissions(self, permissions: Any) -> bool:
        """Check that the Custom Permissions are permission names.

        Args:
            permissions (Any): Custom Permissions parameter.

        Returns:
            bool: True when every permission matches SCOPE_PATTERN.
        """
        parsed = self.parse_scopes(permissions)
        return bool(parsed) and all(
            re.match(CONST.SCOPE_PATTERN, scope) for scope in parsed
        )

    def build_pull_custom_properties_field(self) -> Dict:
        """Build the Pull Custom Properties configuration field.

        Returns:
            Dict: Choice field definition, itself a dynamic field trigger.
        """
        return copy.deepcopy(CONST.PULL_CUSTOM_PROPERTIES_FIELD)

    def build_custom_permissions_field(self) -> Dict:
        """Build the Custom Permissions configuration field.

        Returns:
            Dict: Text field definition.
        """
        return copy.deepcopy(CONST.CUSTOM_PERMISSIONS_FIELD)

    def get_selected_properties(self, configuration: Optional[Dict]) -> List:
        """Get the custom property names selected in the configuration.

        Args:
            configuration (Optional[Dict]): Configuration parameters.

        Returns:
            List: Stripped names, without duplicates, in order.
        """
        selected = (configuration or {}).get(CONST.CONFIG_CUSTOM_PROPERTIES)
        if not isinstance(selected, list):
            return []
        names = [
            name.strip()
            for name in selected
            if isinstance(name, str) and name.strip()
        ]
        return list(dict.fromkeys(names))

    def is_pull_custom_properties_enabled(
        self, configuration: Optional[Dict]
    ) -> bool:
        """Check whether Pull Custom Properties is 'Yes'.

        Args:
            configuration (Optional[Dict]): Configuration parameters.

        Returns:
            bool: True when custom properties are pulled.
        """
        return (
            self._get_text(configuration, CONST.CONFIG_PULL_CUSTOM_PROPERTIES)
            == CONST.PULL_CUSTOM_PROPERTIES_YES
        )

    def has_credentials(self, configuration: Optional[Dict]) -> bool:
        """Check that every parameter needed for a token is present.

        Args:
            configuration (Optional[Dict]): Configuration parameters.

        Returns:
            bool: True when a token can be requested.
        """
        config = self.get_config_params(configuration)
        return all(
            (
                config.api_base_url,
                config.tenant_url,
                config.client_id,
                config.client_secret,
                config.vendor_id,
                config.scopes,
            )
        )

    def is_valid_url(self, url: Any) -> bool:
        """Check that a value is an http or https URL with a host.

        Args:
            url (Any): Value to check.

        Returns:
            bool: True for a valid URL.
        """
        return self._is_url(url, CONST.URL_SCHEMES)

    def _is_url(self, url: Any, schemes: Tuple) -> bool:
        """Check that a value is a URL with one of the schemes and a host.

        Args:
            url (Any): Value to check.
            schemes (Tuple): Accepted schemes.

        Returns:
            bool: True for a valid URL.
        """
        if not isinstance(url, str):
            return False
        try:
            parsed = urlparse(url.strip())
            return parsed.scheme in schemes and bool(parsed.hostname)
        except ValueError:
            return False

    def is_valid_property_selection(self, selected: Any) -> bool:
        """Check the Custom Properties parameter.

        Args:
            selected (Any): Custom Properties parameter.

        Returns:
            bool: True for a list of non-empty strings.
        """
        return isinstance(selected, list) and all(
            isinstance(name, str) and name.strip() for name in selected
        )

    # ------------------------------------------------------------------
    # Access token
    # ------------------------------------------------------------------
    def get_credentials_hash(self, config: ArmisConfiguration) -> str:
        """Hash the parameters that identify the access token.

        Args:
            config (ArmisConfiguration): Configuration parameters.

        Returns:
            str: SHA-256 hex digest.
        """
        parts = [
            config.api_base_url,
            config.tenant_url,
            config.client_id,
            config.vendor_id,
            CONST.SCOPES_SEPARATOR.join(sorted(config.scopes)),
            config.client_secret,
        ]
        return hashlib.sha256(
            CONST.HASH_SEPARATOR.join(parts).encode(CONST.TEXT_ENCODING)
        ).hexdigest()

    def get_access_token(
        self,
        configuration: Optional[Dict],
        storage: Optional[Dict],
        force_refresh: bool = False,
        is_validation: bool = False,
    ) -> str:
        """Get a valid access token, from the cache or from Armis.

        A new token is requested when none is cached, when it expires
        within TOKEN_REFRESH_MARGIN seconds, when the configuration
        changed or when force_refresh is set.

        Args:
            configuration (Optional[Dict]): Configuration parameters.
            storage (Optional[Dict]): Storage holding the token cache.
            force_refresh (bool): Request a new token.
            is_validation (bool): The request is made by validate().

        Returns:
            str: Access token.
        """
        storage = storage if storage is not None else {}
        config = self.get_config_params(configuration)
        credentials_hash = self.get_credentials_hash(config)
        if not force_refresh and self._is_cached_token_valid(
            storage, credentials_hash
        ):
            self.logger.debug(
                message=f"{self.log_prefix}: {CONST.DEBUG_TOKEN_REUSED}"
            )
            return storage[CONST.STORAGE_ACCESS_TOKEN]
        access_token, expires_in = self.request_token(config, is_validation)
        storage[CONST.STORAGE_ACCESS_TOKEN] = access_token
        storage[CONST.STORAGE_TOKEN_EXPIRY] = self._now() + expires_in
        storage[CONST.STORAGE_CREDENTIALS_HASH] = credentials_hash
        debug_msg = CONST.DEBUG_TOKEN_GENERATED.format(expires_in=expires_in)
        self.logger.debug(message=f"{self.log_prefix}: {debug_msg}")
        return access_token

    def _is_cached_token_valid(
        self, storage: Dict, credentials_hash: str
    ) -> bool:
        """Check whether the cached token can be used.

        Args:
            storage (Dict): Storage holding the token cache.
            credentials_hash (str): Hash of the current configuration.

        Returns:
            bool: True when the cached token is usable.
        """
        access_token = storage.get(CONST.STORAGE_ACCESS_TOKEN)
        token_expiry = storage.get(CONST.STORAGE_TOKEN_EXPIRY)
        if not access_token or (
            storage.get(CONST.STORAGE_CREDENTIALS_HASH) != credentials_hash
        ):
            return False
        if isinstance(token_expiry, bool) or not isinstance(
            token_expiry, (int, float)
        ):
            return False
        return token_expiry - self._now() >= CONST.TOKEN_REFRESH_MARGIN

    def request_token(
        self, config: ArmisConfiguration, is_validation: bool = False
    ) -> Tuple[str, float]:
        """Request a new access token from Armis.

        Args:
            config (ArmisConfiguration): Configuration parameters.
            is_validation (bool): The request is made by validate().

        Returns:
            Tuple[str, float]: Access token and lifetime in seconds.

        Raises:
            ArmisAuthenticationException: No token could be generated.
        """
        url = CONST.URL_FORMAT.format(
            base_url=config.api_base_url, endpoint=CONST.TOKEN_ENDPOINT
        )
        body = {
            CONST.TOKEN_AUDIENCE_KEY: config.tenant_url,
            CONST.TOKEN_GRANT_TYPE_KEY: CONST.GRANT_TYPE_CLIENT_CREDENTIALS,
            CONST.TOKEN_CLIENT_ID_KEY: config.client_id,
            CONST.TOKEN_CLIENT_SECRET_KEY: config.client_secret,
            CONST.TOKEN_VENDOR_ID_KEY: config.vendor_id,
            CONST.TOKEN_SCOPES_KEY: config.scopes,
        }
        response = self.api_helper(
            logger_msg=CONST.LOGGER_MSG_TOKEN,
            url=url,
            method=CONST.METHOD_POST,
            json_body=body,
            is_token_call=True,
            is_validation=is_validation,
        )
        access_token = (
            response.get(CONST.ACCESS_TOKEN_KEY)
            if isinstance(response, dict)
            else None
        )
        if not access_token or not isinstance(access_token, str):
            self.logger.error(
                message=f"{self.log_prefix}: {CONST.ERR_AUTH_03}",
                details=self.sanitize_text(response),
                resolution=CONST.RES_AUTH_03,
            )
            raise ArmisAuthenticationException(
                CONST.ERR_AUTH_03, resolution=CONST.RES_AUTH_03
            )
        return access_token, self._get_expires_in(response)

    def _get_expires_in(self, response: Dict) -> float:
        """Get the token lifetime from the token response.

        Args:
            response (Dict): Token response.

        Returns:
            float: Lifetime in seconds; DEFAULT_TOKEN_EXPIRES_IN when it
                is missing or invalid.
        """
        expires_in = response.get(CONST.EXPIRES_IN_KEY)
        if (
            isinstance(expires_in, bool)
            or not isinstance(expires_in, (int, float))
            or not math.isfinite(expires_in)
            or expires_in <= 0
        ):
            return CONST.DEFAULT_TOKEN_EXPIRES_IN
        return expires_in

    def get_token_scopes(self, access_token: Any) -> Optional[List[str]]:
        """Read the granted scopes from the JWT payload.

        The signature is not checked; no network call is made.

        Args:
            access_token (Any): Access token.

        Returns:
            Optional[List[str]]: Granted scopes, or None when they cannot
                be read.
        """
        if not isinstance(access_token, str):
            return None
        segments = access_token.split(CONST.JWT_SEGMENT_SEPARATOR)
        if len(segments) < CONST.JWT_MIN_SEGMENTS:
            return None
        payload_segment = segments[1]
        padding = CONST.BASE64_PADDING * (
            -len(payload_segment) % CONST.BASE64_BLOCK_SIZE
        )
        try:
            payload = json.loads(
                base64.urlsafe_b64decode(payload_segment + padding).decode(
                    CONST.TEXT_ENCODING
                )
            )
        except (TypeError, ValueError):
            return None
        if not isinstance(payload, dict):
            return None
        claim = payload.get(CONST.JWT_SCOPE_CLAIM)
        if isinstance(claim, str):
            return claim.split()
        if isinstance(claim, list):
            return [str(scope) for scope in claim]
        return None

    def is_scope_missing(self, storage: Dict, scope: str) -> bool:
        """Check whether the cached token lacks a scope.

        Args:
            storage (Dict): Storage holding the token cache.
            scope (str): Scope to look for.

        Returns:
            bool: True only when the granted scopes can be read and do
                not include the scope.
        """
        scopes = self.get_token_scopes(
            (storage or {}).get(CONST.STORAGE_ACCESS_TOKEN)
        )
        return scopes is not None and scope not in scopes

    def _now(self) -> float:
        """Return the current time as epoch seconds."""
        return time.time()

    # ------------------------------------------------------------------
    # Armis API calls
    # ------------------------------------------------------------------
    def _build_url(self, configuration: Optional[Dict], endpoint: str) -> str:
        """Build the URL of an endpoint.

        Args:
            configuration (Optional[Dict]): Configuration parameters.
            endpoint (str): Endpoint path.

        Returns:
            str: Endpoint URL.
        """
        return CONST.URL_FORMAT.format(
            base_url=self.get_config_params(configuration).api_base_url,
            endpoint=endpoint,
        )

    def get_items(self, response: Any) -> List:
        """Get the 'items' list of a response.

        Args:
            response (Any): Parsed response.

        Returns:
            List: Items, or [] when missing.
        """
        items = (
            response.get(CONST.ITEMS_KEY) if isinstance(response, dict)
            else None
        )
        return items if isinstance(items, list) else []

    def list_custom_properties(
        self, configuration: Optional[Dict], storage: Optional[Dict]
    ) -> List[Dict]:
        """List the custom properties of the tenant.

        Args:
            configuration (Optional[Dict]): Configuration parameters.
            storage (Optional[Dict]): Storage holding the token cache.

        Returns:
            List[Dict]: Properties that have a name.
        """
        response = self.api_helper(
            logger_msg=CONST.LOGGER_MSG_LIST_PROPERTIES,
            url=self._build_url(
                configuration, CONST.CUSTOM_PROPERTIES_ENDPOINT
            ),
            method=CONST.METHOD_GET,
            configuration=configuration,
            storage=storage,
        )
        return [
            item
            for item in self.get_items(response)
            if isinstance(item, dict)
            and isinstance(item.get(CONST.PROPERTY_NAME_KEY), str)
            and item.get(CONST.PROPERTY_NAME_KEY)
        ]

    def create_custom_property(
        self,
        configuration: Optional[Dict],
        storage: Optional[Dict],
        name: str,
        description: str,
        prop_type: str,
        allowed_values: List[str],
    ) -> Any:
        """Create a custom property.

        Args:
            configuration (Optional[Dict]): Configuration parameters.
            storage (Optional[Dict]): Storage holding the token cache.
            name (str): Property name.
            description (str): Property description; sent when set.
            prop_type (str): Property type.
            allowed_values (List[str]): Allowed values; sent for enum.

        Returns:
            Any: Parsed response.
        """
        body = {CONST.PROPERTY_NAME_KEY: name}
        if description:
            body[CONST.PROPERTY_DESCRIPTION_KEY] = description
        body[CONST.PROPERTY_TYPE_KEY] = prop_type
        if prop_type == CONST.PROPERTY_TYPE_ENUM:
            body[CONST.PROPERTY_ALLOWED_VALUES_KEY] = allowed_values
        return self.api_helper(
            logger_msg=CONST.LOGGER_MSG_CREATE_PROPERTY.format(name=name),
            url=self._build_url(
                configuration, CONST.CUSTOM_PROPERTIES_ENDPOINT
            ),
            method=CONST.METHOD_POST,
            configuration=configuration,
            storage=storage,
            json_body=body,
        )

    def search_devices_page(
        self,
        configuration: Optional[Dict],
        storage: Optional[Dict],
        fields: List[str],
        after: int,
        page: int,
    ) -> Dict:
        """Pull one page of devices with full visibility.

        Args:
            configuration (Optional[Dict]): Configuration parameters.
            storage (Optional[Dict]): Storage holding the token cache.
            fields (List[str]): Fields to return.
            after (int): Paging cursor.
            page (int): Page number, used in the log messages.

        Returns:
            Dict: Parsed response.
        """
        body = {
            CONST.BODY_ASSET_TYPE: CONST.ASSET_TYPE_DEVICE,
            CONST.BODY_FIELDS: list(fields),
            CONST.BODY_FILTER: {
                CONST.BODY_OPERATOR: CONST.FILTER_OPERATOR_EQUALS,
                CONST.BODY_FILTER_CRITERIA: CONST.FILTER_CRITERIA_VISIBILITY,
                CONST.BODY_VISIBILITY: CONST.VISIBILITY_FULL,
                CONST.BODY_LIMIT: CONST.PAGE_SIZE,
                CONST.BODY_AFTER: after,
            },
        }
        response = self.api_helper(
            logger_msg=CONST.LOGGER_MSG_SEARCH_PAGE.format(page=page),
            url=self._build_url(configuration, CONST.SEARCH_ASSETS_ENDPOINT),
            method=CONST.METHOD_POST,
            configuration=configuration,
            storage=storage,
            json_body=body,
        )
        return response if isinstance(response, dict) else {}

    def bulk_update(
        self,
        configuration: Optional[Dict],
        storage: Optional[Dict],
        items: List[Dict],
        logger_msg: str,
    ) -> Dict:
        """Set or clear a custom property on devices.

        Args:
            configuration (Optional[Dict]): Configuration parameters.
            storage (Optional[Dict]): Storage holding the token cache.
            items (List[Dict]): Bulk items, at most BULK_BATCH_SIZE.
            logger_msg (str): Operation, used in the log messages.

        Returns:
            Dict: Parsed multi-status response.
        """
        body = {
            CONST.BODY_ASSET_TYPE: CONST.ASSET_TYPE_DEVICE,
            CONST.BODY_ASSET_ID_SOURCE: CONST.ASSET_ID_SOURCE,
            CONST.BODY_ITEMS: items,
        }
        response = self.api_helper(
            logger_msg=logger_msg,
            url=self._build_url(configuration, CONST.BULK_ASSETS_ENDPOINT),
            method=CONST.METHOD_POST,
            configuration=configuration,
            storage=storage,
            json_body=body,
        )
        return response if isinstance(response, dict) else {}

    def get_next_cursor(self, response: Dict, after: int) -> Optional[int]:
        """Get the cursor of the next page.

        Args:
            response (Dict): Parsed search response.
            after (int): Cursor of the current page.

        Returns:
            Optional[int]: Next cursor, or None on the last page (no
                'next', or 'next' is null).

        Raises:
            ArmisAPIException: 'next' is not a whole number, or does not
                move forward; the pull fails instead of stopping early
                and reporting a partial pull as complete.
        """
        next_after = response.get(CONST.NEXT_KEY)
        if next_after is None:
            return None
        if isinstance(next_after, str) and next_after.strip().isdigit():
            next_after = int(next_after.strip())
        if (
            isinstance(next_after, bool)
            or not isinstance(next_after, int)
            or next_after <= after
        ):
            message = CONST.ERR_PUL_06.format(next=next_after, after=after)
            self.logger.error(
                message=f"{self.log_prefix}: {message}",
                details=self.sanitize_text(json.dumps(response, default=str)),
                resolution=CONST.RES_PUL_06,
            )
            raise ArmisAPIException(message, resolution=CONST.RES_PUL_06)
        return next_after

    # ------------------------------------------------------------------
    # Records
    # ------------------------------------------------------------------
    def build_search_fields(self, properties: List[Dict]) -> List[str]:
        """Build the fields requested from the _search API.

        Args:
            properties (List[Dict]): Custom properties to pull.

        Returns:
            List[str]: Standard fields plus one 'custom.<name>' field
                per property.
        """
        return list(CONST.STANDARD_SEARCH_FIELDS) + [
            CONST.CUSTOM_FIELD_PREFIX + prop[CONST.PROPERTY_NAME_KEY]
            for prop in properties
        ]

    def build_records_from_items(
        self, items: List, properties: List[Dict]
    ) -> Tuple[List[Dict], int, int]:
        """Build the records of one page of devices.

        Args:
            items (List): Items of the search response.
            properties (List[Dict]): Custom properties to pull.

        Returns:
            Tuple[List[Dict], int, int]: Records, number of devices
                skipped because the device ID is missing and number of
                devices pulled.
        """
        records = []
        skipped = 0
        for item in items:
            device_records = self.build_device_records(item, properties)
            if device_records is None:
                skipped += 1
                continue
            records.extend(device_records)
        return records, skipped, len(items) - skipped

    def build_device_records(
        self, item: Any, properties: List[Dict]
    ) -> Optional[List[Dict]]:
        """Build the records of one device, one per serial number.

        Args:
            item (Any): Item of the search response.
            properties (List[Dict]): Custom properties to pull.

        Returns:
            Optional[List[Dict]]: Records, or None when the device ID is
                missing. A device without serial number gives one record
                whose Serial Number is None.
        """
        fields = self._get_item_fields(item)
        if fields is None:
            return None
        record = self.build_base_record(fields, properties)
        if not record.get(CONST.FIELD_DEVICE_ID):
            return None
        serial_numbers = self.get_serial_numbers(
            fields.get(CONST.API_SERIAL_NUMBERS)
        )
        if not serial_numbers:
            record[CONST.FIELD_SERIAL_NUMBER] = None
            return [record]
        return [
            {**record, CONST.FIELD_SERIAL_NUMBER: serial_number}
            for serial_number in serial_numbers
        ]

    def _get_item_fields(self, item: Any) -> Optional[Dict]:
        """Get the 'fields' of a search item.

        Args:
            item (Any): Item of the search response.

        Returns:
            Optional[Dict]: Fields, or None when missing.
        """
        fields = (
            item.get(CONST.FIELDS_KEY) if isinstance(item, dict) else None
        )
        return fields if isinstance(fields, dict) else None

    def build_base_record(
        self, fields: Dict, properties: List[Dict]
    ) -> Dict:
        """Map the device fields to the entity fields.

        Args:
            fields (Dict): Fields of a search item.
            properties (List[Dict]): Custom properties to pull.

        Returns:
            Dict: Record without the Serial Number.
        """
        record = {}
        for field_name, spec in CONST.DEVICE_FIELD_MAPPING.items():
            transformation = self._transformations.get(
                spec[CONST.MAPPING_TRANSFORMATION]
            )
            if transformation is None:
                continue
            value = transformation(fields.get(spec[CONST.MAPPING_API_KEY]))
            self._add_field(record, field_name, value)
        for prop in properties:
            name = prop[CONST.PROPERTY_NAME_KEY]
            value = self.coerce_pulled_custom_value(
                fields.get(CONST.CUSTOM_FIELD_PREFIX + name),
                prop.get(CONST.PROPERTY_TYPE_KEY),
            )
            self._add_field(
                record, CONST.CUSTOM_ENTITY_FIELD_PREFIX + name, value
            )
        return record

    def _add_field(self, record: Dict, field_name: str, value: Any):
        """Add a value to a record.

        The field is always set, so that every pull overwrites the value
        stored in Cloud Exchange, including a value cleared in Armis.
        Empty text, lists and dicts become None; numbers and booleans
        are kept, including 0 and False.

        Args:
            record (Dict): Record to update.
            field_name (str): Entity field name.
            value (Any): Value.
        """
        if isinstance(value, (dict, list, str)) and not value:
            value = None
        record[field_name] = value

    def get_serial_numbers(self, value: Any) -> List[str]:
        """Get the distinct serial numbers of a device.

        Args:
            value (Any): 'serial_numbers' field.

        Returns:
            List[str]: Non-empty serial numbers, in order.
        """
        if isinstance(value, (str, int)) and not isinstance(value, bool):
            value = [value]
        if not isinstance(value, list):
            return []
        serial_numbers = []
        for serial_number in value:
            if serial_number is None or isinstance(
                serial_number, (bool, dict, list)
            ):
                continue
            text = str(serial_number).strip()
            if text:
                serial_numbers.append(text)
        return list(dict.fromkeys(serial_numbers))

    def _get_device_id_key(self, value: Any) -> Optional[int]:
        """Convert a Device ID to an integer.

        Args:
            value (Any): Device ID.

        Returns:
            Optional[int]: Integer, or None when not a whole number.
        """
        try:
            return self.parse_device_id(value)
        except ArmisValidationException:
            return None

    # ------------------------------------------------------------------
    # Field transformations
    # ------------------------------------------------------------------
    def _to_device_id(self, value: Any) -> Optional[str]:
        """Convert the Armis device ID to a string.

        Args:
            value (Any): 'device_id' field.

        Returns:
            Optional[str]: Device ID, or None when missing.
        """
        if isinstance(value, bool):
            return None
        if isinstance(value, int):
            return str(value)
        if isinstance(value, float) and value.is_integer():
            return str(int(value))
        if isinstance(value, str) and value.strip():
            return value.strip()
        return None

    def _to_string(self, value: Any) -> Optional[str]:
        """Convert a scalar to a string.

        Args:
            value (Any): Field value.

        Returns:
            Optional[str]: Text, or None for empty values, lists and
                dicts.
        """
        if isinstance(value, str):
            return value if value.strip() else None
        if isinstance(value, (bool, int, float)):
            return str(value)
        return None

    def _to_list(self, value: Any) -> List:
        """Convert a value to a list.

        Args:
            value (Any): Field value.

        Returns:
            List: Values that are not None; a scalar becomes a one-item
                list.
        """
        if isinstance(value, list):
            return [item for item in value if item is not None]
        if isinstance(value, (str, int, float)) and value != "":
            return [value]
        return []

    def _to_number(self, value: Any) -> Optional[float]:
        """Convert a value to a number.

        Args:
            value (Any): Field value.

        Returns:
            Optional[float]: Integer or float, or None when not numeric.
        """
        if isinstance(value, bool):
            return None
        if isinstance(value, (int, float)):
            return value if math.isfinite(value) else None
        if isinstance(value, str) and value.strip():
            text = value.strip()
            if re.match(CONST.INTEGER_PATTERN, text):
                return int(text)
            try:
                number = float(text)
            except ValueError:
                return None
            return number if math.isfinite(number) else None
        return None

    def _to_site(self, value: Any) -> Optional[str]:
        """Get the site name.

        Args:
            value (Any): 'site' field, an object or a name.

        Returns:
            Optional[str]: Site name, or None.
        """
        if isinstance(value, dict):
            value = value.get(CONST.SITE_NAME_KEY)
        if isinstance(value, str) and value.strip():
            return value
        return None

    def _to_boolean(self, value: Any) -> Optional[bool]:
        """Convert a value to a boolean.

        Args:
            value (Any): Value.

        Returns:
            Optional[bool]: Boolean for a bool or 'true'/'false' in any
                case, else None.
        """
        if isinstance(value, bool):
            return value
        if isinstance(value, str):
            text = value.strip().lower()
            if text == CONST.BOOLEAN_TRUE:
                return True
            if text == CONST.BOOLEAN_FALSE:
                return False
        return None

    def parse_datetime(self, value: Any) -> Optional[datetime]:
        """Convert an ISO 8601 date-time to a timezone-aware UTC datetime.

        Args:
            value (Any): Date-time text or datetime.

        Returns:
            Optional[datetime]: UTC datetime, or None when invalid.
        """
        if isinstance(value, datetime):
            parsed = value
        elif isinstance(value, str) and value.strip():
            text = value.strip()
            if text[-1:].upper() == CONST.UTC_SUFFIX:
                text = text[:-1] + CONST.UTC_OFFSET
            try:
                parsed = datetime.fromisoformat(text)
            except ValueError:
                return None
        else:
            return None
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)

    def coerce_pulled_custom_value(self, value: Any, prop_type: Any) -> Any:
        """Convert a pulled custom property value to its field type.

        Args:
            value (Any): 'custom.<name>' field.
            prop_type (Any): Armis type of the property.

        Returns:
            Any: Boolean, number, UTC datetime or text; None when the
                value does not match the type.
        """
        if prop_type == CONST.PROPERTY_TYPE_BOOLEAN:
            return self._to_boolean(value)
        if prop_type == CONST.PROPERTY_TYPE_INTEGER:
            return self._to_number(value)
        if prop_type == CONST.PROPERTY_TYPE_TIMESTAMP:
            return self.parse_datetime(value)
        return self._to_string(value)

    # ------------------------------------------------------------------
    # Custom properties
    # ------------------------------------------------------------------
    def find_property(
        self, properties: List[Dict], name: str
    ) -> Optional[Dict]:
        """Find a custom property by its exact name.

        Args:
            properties (List[Dict]): Custom properties.
            name (str): Property name.

        Returns:
            Optional[Dict]: Property, or None.
        """
        return next(
            (
                prop
                for prop in properties or []
                if prop.get(CONST.PROPERTY_NAME_KEY) == name
            ),
            None,
        )

    def get_property_names(self, properties: List[Dict]) -> List[str]:
        """Get the names of the custom properties.

        Args:
            properties (List[Dict]): Custom properties.

        Returns:
            List[str]: Names.
        """
        return [prop[CONST.PROPERTY_NAME_KEY] for prop in properties or []]

    def match_properties(
        self, selected: List[str], properties: List[Dict]
    ) -> Tuple[List[Dict], List[str]]:
        """Match the selected names with the custom properties of Armis.

        Args:
            selected (List[str]): Selected names.
            properties (List[Dict]): Custom properties of Armis.

        Returns:
            Tuple[List[Dict], List[str]]: Matched properties, in the
                selection order, and names missing from Armis.
        """
        resolved = []
        missing = []
        for name in selected:
            prop = self.find_property(properties, name)
            if prop is None:
                missing.append(name)
            else:
                resolved.append(prop)
        return resolved, missing

    def get_custom_field_types(
        self, selected: List[str], properties: Optional[List[Dict]]
    ) -> List[Tuple[str, str]]:
        """Get the entity field type of each selected custom property.

        Args:
            selected (List[str]): Selected names.
            properties (Optional[List[Dict]]): Custom properties of
                Armis, or None when they could not be read.

        Returns:
            List[Tuple[str, str]]: (name, EntityFieldType value) per
                property. Every selected property is a string when the
                list could not be read; a property missing from Armis
                is left out.
        """
        if properties is None:
            return [(name, CONST.FIELD_TYPE_STRING) for name in selected]
        resolved, _ = self.match_properties(selected, properties)
        return [
            (
                prop[CONST.PROPERTY_NAME_KEY],
                CONST.CUSTOM_PROPERTY_FIELD_TYPES.get(
                    prop.get(CONST.PROPERTY_TYPE_KEY), CONST.FIELD_TYPE_STRING
                ),
            )
            for prop in resolved
        ]

    def build_property_choices(self, properties: List[Dict]) -> List[Dict]:
        """Build dropdown choices from the custom properties.

        Args:
            properties (List[Dict]): Custom properties.

        Returns:
            List[Dict]: One choice per property, sorted by name.
        """
        names = sorted(
            set(self.get_property_names(properties)), key=str.lower
        )
        return [{CONST.CHOICE_KEY: name, CONST.CHOICE_VALUE: name}
                for name in names]

    def build_dynamic_field(self, properties: List[Dict]) -> Dict:
        """Build the Custom Properties configuration field.

        Args:
            properties (List[Dict]): Custom properties.

        Returns:
            Dict: Multichoice field definition.
        """
        field = copy.deepcopy(CONST.CUSTOM_PROPERTIES_FIELD)
        field[CONST.FIELD_CHOICES_KEY] = self.build_property_choices(
            properties
        )
        return field

    def build_action_params(self, properties: List[Dict]) -> List[Dict]:
        """Build the parameters of the Set Custom Property Value action.

        Args:
            properties (List[Dict]): Custom properties.

        Returns:
            List[Dict]: Parameter definitions; the Custom Property choice
                lists the properties and the create option, and defaults
                to the first property (the create option when there is
                none).
        """
        params = copy.deepcopy(CONST.SET_CUSTOM_PROPERTY_PARAMS)
        choices = self.build_property_choices(properties) + [
            {
                CONST.CHOICE_KEY: CONST.CREATE_PROPERTY_LABEL,
                CONST.CHOICE_VALUE: CONST.CREATE_PROPERTY_VALUE,
            }
        ]
        for param in params:
            if param[CONST.FIELD_KEY_KEY] == CONST.PARAM_CUSTOM_PROPERTY:
                param[CONST.FIELD_CHOICES_KEY] = choices
                param[CONST.FIELD_DEFAULT_KEY] = choices[0][
                    CONST.CHOICE_VALUE
                ]
        return params

    def build_remove_action_params(
        self, properties: List[Dict]
    ) -> List[Dict]:
        """Build the parameters of the Remove Custom Property Value action.

        Args:
            properties (List[Dict]): Custom properties.

        Returns:
            List[Dict]: Parameter definitions; the Custom Property choice
                lists the existing properties only.
        """
        params = copy.deepcopy(CONST.REMOVE_CUSTOM_PROPERTY_PARAMS)
        choices = self.build_property_choices(properties)
        for param in params:
            if param[CONST.FIELD_KEY_KEY] == CONST.PARAM_CUSTOM_PROPERTIES:
                param[CONST.FIELD_CHOICES_KEY] = choices
        return params

    def parse_allowed_values(self, value: Any) -> List[str]:
        """Split the comma-separated Allowed Values.

        Args:
            value (Any): Allowed Values parameter.

        Returns:
            List[str]: Non-empty values, without duplicates, in order.
        """
        if isinstance(value, list):
            items = [str(item).strip() for item in value if item is not None]
        elif isinstance(value, str):
            items = [
                item.strip()
                for item in value.split(CONST.ALLOWED_VALUES_SEPARATOR)
            ]
        else:
            return []
        return list(dict.fromkeys(item for item in items if item))

    def has_allowed_values(self, value: Any) -> bool:
        """Check that at least one allowed value is given.

        Args:
            value (Any): Allowed Values parameter.

        Returns:
            bool: True when one value or more is given.
        """
        return bool(self.parse_allowed_values(value))

    def is_valid_property_name(self, name: Any) -> bool:
        """Check a new custom property name.

        Args:
            name (Any): New Property Name.

        Returns:
            bool: True for 1 to 40 letters, digits and underscores.
        """
        return (
            isinstance(name, str)
            and 0 < len(name) <= CONST.PROPERTY_NAME_MAX_LENGTH
            and re.match(CONST.PROPERTY_NAME_PATTERN, name) is not None
        )

    def is_valid_property_description(self, description: Any) -> bool:
        """Check a new custom property description.

        Args:
            description (Any): Description.

        Returns:
            bool: True for at most 250 characters.
        """
        return (
            isinstance(description, str)
            and len(description) <= CONST.PROPERTY_DESCRIPTION_MAX_LENGTH
        )

    def get_property_for_create(
        self, params: Dict, properties: List[Dict]
    ) -> Dict:
        """Get the property targeted by the create option.

        Args:
            params (Dict): Action parameters.
            properties (List[Dict]): Custom properties of Armis.

        Returns:
            Dict: The existing property with the New Property Name, else
                the property described by the action parameters.
        """
        name = self.get_text_param(params, CONST.PARAM_NEW_PROPERTY_NAME)
        existing = self.find_property(properties, name)
        if existing is not None:
            return existing
        return {
            CONST.PROPERTY_NAME_KEY: name,
            CONST.PROPERTY_DESCRIPTION_KEY: self.get_text_param(
                params, CONST.PARAM_NEW_PROPERTY_DESCRIPTION
            ),
            CONST.PROPERTY_TYPE_KEY: self.get_text_param(
                params, CONST.PARAM_NEW_PROPERTY_TYPE
            ),
            CONST.PROPERTY_ALLOWED_VALUES_KEY: self.parse_allowed_values(
                params.get(CONST.PARAM_NEW_PROPERTY_ALLOWED_VALUES)
            ),
        }

    # ------------------------------------------------------------------
    # Action values
    # ------------------------------------------------------------------
    def get_text_param(self, params: Dict, key: str) -> str:
        """Get a stripped action parameter.

        Args:
            params (Dict): Action parameters.
            key (str): Parameter key.

        Returns:
            str: Stripped value, or "" when it is not a string.
        """
        return self._get_text(params, key)

    def get_action_properties(self, value: Any) -> List[str]:
        """Get the custom properties selected in an action.

        Args:
            value (Any): Custom Properties parameter; a single name is
                accepted as well as a list.

        Returns:
            List[str]: Stripped names, without duplicates, in order.
        """
        if isinstance(value, str):
            value = [value]
        if not isinstance(value, list):
            return []
        names = [item.strip() for item in value if isinstance(item, str)]
        return list(dict.fromkeys(name for name in names if name))

    def get_param_properties(self, params: Dict) -> List[str]:
        """Get the custom properties an action targets.

        Set Custom Property Value has one Custom Property; Remove Custom
        Property Value has several Custom Properties.

        Args:
            params (Dict): Action parameters.

        Returns:
            List[str]: Property names (or the create option), in order.
        """
        if CONST.PARAM_CUSTOM_PROPERTY in params:
            return self.get_action_properties(
                params.get(CONST.PARAM_CUSTOM_PROPERTY)
            )
        return self.get_action_properties(
            params.get(CONST.PARAM_CUSTOM_PROPERTIES)
        )

    def get_action_parameters(self, action_dict: Dict) -> Dict:
        """Get the parameters of an action passed to execute_actions().

        Args:
            action_dict (Dict): {"params": Action, "id": str}.

        Returns:
            Dict: Action parameters.
        """
        action = action_dict.get(CONST.ACTION_PARAMS_KEY)
        return (action.parameters if action is not None else None) or {}

    def is_source_value(self, value: Any) -> bool:
        """Check whether an action parameter is a Source Field.

        Args:
            value (Any): Action parameter.

        Returns:
            bool: True for a Source Field reference, which Cloud Exchange
                marks with a leading '$' (a '$' elsewhere is plain text).
        """
        if isinstance(value, str):
            return value.strip().startswith(CONST.SOURCE_FIELD_MARKER)
        if isinstance(value, list) and value:
            return all(
                isinstance(item, str)
                and item.strip().startswith(CONST.SOURCE_FIELD_MARKER)
                for item in value
            )
        return False

    def display_value(self, value: Any) -> str:
        """Format an action value for a message.

        Args:
            value (Any): Value.

        Returns:
            str: Text of the value; "" for None.
        """
        if value is None:
            return ""
        if isinstance(value, list):
            return CONST.LIST_VALUE_SEPARATOR.join(
                self.display_value(item) for item in value
            )
        return str(value).strip()

    def parse_device_id(self, value: Any) -> int:
        """Convert a Device ID to the integer Armis expects.

        Args:
            value (Any): Device ID. A list, as an append-aggregated
                Source Field gives, is reduced to its latest (last
                non-empty) value.

        Returns:
            int: Device ID.

        Raises:
            ArmisValidationException: The value is not a whole number.
        """
        candidate = value
        if isinstance(candidate, list):
            non_empty = [
                item for item in candidate
                if item is not None and str(item).strip() != ""
            ]
            candidate = non_empty[-1] if non_empty else None
        if isinstance(candidate, bool):
            candidate = None
        if isinstance(candidate, int):
            return candidate
        if isinstance(candidate, float) and candidate.is_integer():
            return int(candidate)
        if isinstance(candidate, str) and re.match(
            CONST.INTEGER_PATTERN, candidate.strip()
        ):
            return int(candidate.strip())
        raise ArmisValidationException(
            CONST.ERR_ACT_01.format(value=self.display_value(value)),
            resolution=CONST.RES_ACT_01,
        )

    def is_valid_device_id(self, value: Any) -> bool:
        """Check that a Device ID is a whole number.

        Args:
            value (Any): Device ID.

        Returns:
            bool: True for a whole number.
        """
        return self._get_device_id_key(value) is not None

    def coerce_action_value(self, value: Any, prop: Dict) -> Any:
        """Convert an action value to what Armis expects for the type.

        Args:
            value (Any): Value parameter; a list is accepted when it has
                one item, or several items for a string property.
            prop (Dict): Target custom property.

        Returns:
            Any: Text, integer or boolean to send.

        Raises:
            ArmisValidationException: The value does not match the type.
        """
        prop_type = prop.get(CONST.PROPERTY_TYPE_KEY)
        candidate = self._get_single_value(value, prop_type)
        coercion = self._value_coercions.get(prop_type, self._coerce_string)
        result = coercion(candidate)
        if result is None or (
            prop_type == CONST.PROPERTY_TYPE_ENUM
            and result not in self._get_allowed_values(prop)
        ):
            message, resolution = self.get_value_error(value, prop)
            raise ArmisValidationException(message, resolution=resolution)
        return result

    def is_valid_action_value(self, value: Any, prop: Dict) -> bool:
        """Check an action value against the property type.

        Args:
            value (Any): Value parameter.
            prop (Dict): Target custom property.

        Returns:
            bool: True when the value is valid.
        """
        try:
            self.coerce_action_value(value, prop)
        except ArmisValidationException:
            return False
        return True

    def get_value_error(self, value: Any, prop: Dict) -> Tuple[str, str]:
        """Get the error message and resolution for an invalid value.

        Args:
            value (Any): Value parameter.
            prop (Dict): Target custom property.

        Returns:
            Tuple[str, str]: E-ACT-04 for a non-empty enum value, else
                E-ACT-03.
        """
        text = self.display_value(value)
        name = prop.get(CONST.PROPERTY_NAME_KEY)
        prop_type = prop.get(CONST.PROPERTY_TYPE_KEY)
        if prop_type == CONST.PROPERTY_TYPE_ENUM and text:
            allowed_values = CONST.LIST_VALUE_SEPARATOR.join(
                self._get_allowed_values(prop)
            )
            return (
                CONST.ERR_ACT_04.format(value=text, name=name),
                CONST.RES_ACT_04.format(allowed_values=allowed_values),
            )
        return (
            CONST.ERR_ACT_03.format(value=text, type=prop_type, name=name),
            CONST.RES_ACT_03,
        )

    def _get_allowed_values(self, prop: Dict) -> List[str]:
        """Get the allowed values of an enum property.

        Args:
            prop (Dict): Custom property.

        Returns:
            List[str]: Allowed values.
        """
        allowed_values = prop.get(CONST.PROPERTY_ALLOWED_VALUES_KEY)
        if not isinstance(allowed_values, list):
            return []
        return [str(item) for item in allowed_values if item is not None]

    def _get_single_value(self, value: Any, prop_type: Any) -> Any:
        """Reduce a list value to one value.

        Args:
            value (Any): Value parameter.
            prop_type (Any): Armis type of the property.

        Returns:
            Any: The only item, the items joined for a string property,
                else the value; None for other lists.
        """
        if not isinstance(value, list):
            return value
        if len(value) == 1:
            return value[0]
        if value and prop_type == CONST.PROPERTY_TYPE_STRING:
            return CONST.LIST_VALUE_SEPARATOR.join(
                self.display_value(item) for item in value
            )
        return None

    def _coerce_string(self, value: Any) -> Optional[str]:
        """Convert a value to non-empty text.

        Args:
            value (Any): Value.

        Returns:
            Optional[str]: Stripped text, or None when empty.
        """
        if isinstance(value, datetime):
            return value.isoformat()
        if isinstance(value, (str, bool, int, float)):
            text = str(value).strip()
            return text or None
        return None

    def _coerce_integer(self, value: Any) -> Optional[int]:
        """Convert a value to a whole number.

        Args:
            value (Any): Value.

        Returns:
            Optional[int]: Integer, or None.
        """
        if isinstance(value, bool):
            return None
        if isinstance(value, int):
            return value
        if isinstance(value, float) and value.is_integer():
            return int(value)
        if isinstance(value, str) and re.match(
            CONST.INTEGER_PATTERN, value.strip()
        ):
            return int(value.strip())
        return None

    def _coerce_link(self, value: Any) -> Optional[str]:
        """Check an http or https URL.

        Args:
            value (Any): Value.

        Returns:
            Optional[str]: Stripped URL, or None.
        """
        if self.is_valid_url(value):
            return value.strip()
        return None

    def _coerce_timestamp(self, value: Any) -> Optional[str]:
        """Check an ISO 8601 date-time.

        Args:
            value (Any): Value.

        Returns:
            Optional[str]: The text as given (stripped), or None.
        """
        if isinstance(value, datetime):
            return value.isoformat()
        if isinstance(value, str) and self.parse_datetime(value) is not None:
            return value.strip()
        return None

    # ------------------------------------------------------------------
    # Bulk actions
    # ------------------------------------------------------------------
    def build_action_buckets(
        self, actions: List[Dict], by_name: bool
    ) -> Dict[str, List[Dict]]:
        """Group the actions by target custom property.

        Cloud Exchange batches actions only by configuration and action
        value, so one batch can target several properties. An action
        with several Custom Properties is added to the bucket of each.

        Args:
            actions (List[Dict]): {"params": Action, "id": str} items.
            by_name (bool): Key by property name (Remove); otherwise
                the create option of Set is keyed 'create:<name>'.

        Returns:
            Dict[str, List[Dict]]: Actions per property. An action
                without Custom Properties is keyed "".
        """
        buckets = {}
        for action_dict in actions:
            params = self.get_action_parameters(action_dict)
            if by_name:
                keys = self.get_action_property_names(params)
            else:
                keys = self._get_set_bucket_keys(params)
            for key in keys or [""]:
                buckets.setdefault(key, []).append(action_dict)
        return buckets

    def _get_set_bucket_keys(self, params: Dict) -> List[str]:
        """Get the bucket keys of a set action.

        Args:
            params (Dict): Action parameters.

        Returns:
            List[str]: Property names, with 'create:<name>' for the
                create option.
        """
        keys = []
        for name in self.get_param_properties(params):
            if name == CONST.CREATE_PROPERTY_VALUE:
                name = CONST.CREATE_BUCKET_FORMAT.format(
                    name=self.get_text_param(
                        params, CONST.PARAM_NEW_PROPERTY_NAME
                    )
                )
            keys.append(name)
        return list(dict.fromkeys(keys))

    def is_create_bucket_key(self, key: str) -> bool:
        """Check whether a set bucket key is the create option.

        Args:
            key (str): Bucket key.

        Returns:
            bool: True for 'create:<name>'.
        """
        return key.startswith(CONST.CREATE_BUCKET_FORMAT.format(name=""))

    def get_action_property_names(self, params: Dict) -> List[str]:
        """Get the names of the properties an action targets.

        Args:
            params (Dict): Action parameters.

        Returns:
            List[str]: Custom Properties, with the New Property Name in
                place of the create option.
        """
        names = []
        for name in self.get_param_properties(params):
            if name == CONST.CREATE_PROPERTY_VALUE:
                name = self.get_text_param(
                    params, CONST.PARAM_NEW_PROPERTY_NAME
                )
            names.append(name)
        return list(dict.fromkeys(names))

    def get_action_ids(self, actions: List[Dict]) -> List:
        """Get the distinct ids of the actions.

        Args:
            actions (List[Dict]): {"params": Action, "id": str} items.

        Returns:
            List: Action ids, in order.
        """
        return list(
            dict.fromkeys(
                action_dict.get(CONST.ACTION_ID_KEY)
                for action_dict in actions
                if action_dict.get(CONST.ACTION_ID_KEY) is not None
            )
        )

    def build_set_items(
        self, bucket: List[Dict], prop: Dict
    ) -> Tuple[List[Dict], List[List], List]:
        """Build the SET items of one property.

        Args:
            bucket (List[Dict]): Actions targeting the property.
            prop (Dict): Target custom property.

        Returns:
            Tuple[List[Dict], List[List], List]: Bulk items, action ids
                per item (one item per distinct device and value) and
                ids of the actions with an invalid Device ID or Value.
        """
        key = CONST.CUSTOM_FIELD_PREFIX + prop[CONST.PROPERTY_NAME_KEY]
        positions = {}
        items = []
        item_action_ids = []
        failed_ids = []
        invalid_messages = []
        for action_dict in bucket:
            action_id = action_dict.get(CONST.ACTION_ID_KEY)
            params = self.get_action_parameters(action_dict)
            try:
                asset_id = self.parse_device_id(
                    params.get(CONST.PARAM_DEVICE_ID)
                )
                value = self.coerce_action_value(
                    params.get(CONST.PARAM_VALUE), prop
                )
            except ArmisValidationException as error:
                invalid_messages.append(error.message)
                failed_ids.append(action_id)
                continue
            position = positions.get((asset_id, value))
            if position is None:
                positions[(asset_id, value)] = len(items)
                items.append(
                    {
                        CONST.BODY_ASSET_ID: asset_id,
                        CONST.BODY_OPERATION: CONST.BULK_OPERATION_SET,
                        CONST.BODY_KEY: key,
                        CONST.BODY_VALUE: value,
                    }
                )
                item_action_ids.append([action_id])
            else:
                item_action_ids[position].append(action_id)
        self._log_invalid_inputs(invalid_messages)
        return items, item_action_ids, failed_ids

    def build_unset_items(
        self, bucket: List[Dict], property_name: str
    ) -> Tuple[List[Dict], List[List], List]:
        """Build the UNSET items that remove one property value.

        Args:
            bucket (List[Dict]): Remove actions of the property.
            property_name (str): Property to clear.

        Returns:
            Tuple[List[Dict], List[List], List]: Bulk items, action ids
                per item (one item per distinct device) and ids of the
                actions with an invalid Device ID.
        """
        key = CONST.CUSTOM_FIELD_PREFIX + property_name
        positions = {}
        items = []
        item_action_ids = []
        failed_ids = []
        invalid_messages = []
        for action_dict in bucket:
            action_id = action_dict.get(CONST.ACTION_ID_KEY)
            params = self.get_action_parameters(action_dict)
            try:
                asset_id = self.parse_device_id(
                    params.get(CONST.PARAM_DEVICE_ID)
                )
            except ArmisValidationException as error:
                invalid_messages.append(error.message)
                failed_ids.append(action_id)
                continue
            position = positions.get(asset_id)
            if position is None:
                positions[asset_id] = len(items)
                items.append(
                    {
                        CONST.BODY_ASSET_ID: asset_id,
                        CONST.BODY_OPERATION: CONST.BULK_OPERATION_UNSET,
                        CONST.BODY_KEY: key,
                    }
                )
                item_action_ids.append([action_id])
            else:
                item_action_ids[position].append(action_id)
        self._log_invalid_inputs(invalid_messages)
        return items, item_action_ids, failed_ids

    def _log_invalid_inputs(self, messages: List[str]):
        """Log the invalid Device IDs and Values of a batch once.

        Args:
            messages (List[str]): One validation message per action that
                was not sent; the distinct ones go in the details.
        """
        if not messages:
            return
        message = CONST.ERR_ACT_20.format(count=len(messages))
        self.logger.error(
            message=f"{self.log_prefix}: {message}",
            details=json.dumps(
                {CONST.DETAILS_ERRORS_KEY: list(dict.fromkeys(messages))}
            ),
            resolution=CONST.RES_ACT_20,
        )

    def evaluate_bulk_results(
        self,
        chunk: List[Dict],
        chunk_action_ids: List[List],
        results: List,
    ) -> Tuple[List, List, List]:
        """Read the multi-status results of a bulk call.

        Result i is the result of item i (Armis returns them in order).

        Args:
            chunk (List[Dict]): Bulk items sent.
            chunk_action_ids (List[List]): Action ids per item.
            results (List): Items of the 207 response.

        Returns:
            Tuple[List, List, List]: Device ID and custom property of the
                values updated and of the values that failed, and ids of
                the failed actions.
        """
        succeeded = []
        failed_devices = []
        failed_ids = []
        for item, action_ids, result in zip(chunk, chunk_action_ids, results):
            device_id = item.get(CONST.BODY_ASSET_ID)
            property_name = str(item.get(CONST.BODY_KEY, ""))[
                len(CONST.CUSTOM_FIELD_PREFIX):
            ]
            entry = {
                CONST.DETAILS_DEVICE_ID_KEY: device_id,
                CONST.DETAILS_PROPERTY_KEY: property_name,
            }
            result = result if isinstance(result, dict) else {}
            status = result.get(CONST.STATUS_KEY)
            if status in CONST.BULK_ITEM_SUCCESS_STATUSES:
                succeeded.append(entry)
                continue
            # Reported once per batch by the caller, not per item.
            entry[CONST.DETAILS_STATUS_KEY] = status
            entry[CONST.DETAILS_ERROR_KEY] = self.sanitize_text(
                result.get(CONST.ERROR_KEY)
            )
            failed_devices.append(entry)
            failed_ids.extend(action_ids)
        return succeeded, failed_devices, failed_ids

    def chunk(self, items: List, size: int) -> Iterator[List]:
        """Split a list into slices.

        Args:
            items (List): Items.
            size (int): Maximum slice size.

        Yields:
            List: Slice of at most size items.
        """
        for start in range(0, len(items), size):
            yield items[start:start + size]
