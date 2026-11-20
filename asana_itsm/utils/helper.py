"""
BSD 3-Clause License

Copyright (c) 2021, Netskope OSS
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice,
   this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its contributors
   may be used to endorse or promote products derived from this software
   without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
POSSIBILITY OF SUCH DAMAGE.

Asana CTO plugin API helper.
"""

import json
import time
import traceback
from typing import Any, Dict, List, Optional, Tuple, Union
from urllib.parse import urlparse

import requests
from netskope.common.utils import add_user_agent
from netskope.integrations.itsm.models import (
    Alert,
    Event,
    Queue,
    Task,
    TaskStatus,
)

from .constants import (
    ASANA_ERROR_HINTS,
    BATCH_ENDPOINT,
    CONNECTION_RESOLUTION,
    CUSTOM_FIELD_PREFIX,
    DEFAULT_WAIT_TIME,
    ERROR_REASONS,
    EXPIRED_CURSOR_MESSAGES,
    FATAL_STATUS_CODES,
    MAX_DETAILS_LENGTH,
    MAX_PAGES,
    MAX_RETRIES,
    MAX_WAIT_TIME,
    MODULE_NAME,
    PAGE_LIMIT,
    PLATFORM_NAME,
    PROXY_RESOLUTION,
    RESOLUTIONS,
    VALIDATION_CONNECTION_MESSAGE,
    VALIDATION_ERROR_MESSAGES,
    VALIDATION_INVALID_RESPONSE_MESSAGE,
    VALIDATION_PROXY_MESSAGE,
    VALIDATION_SERVER_ERROR_MESSAGE,
    VALIDATION_TIMEOUT_MESSAGE,
    WORKSPACE_CUSTOM_FIELDS_ENDPOINT,
    WORKSPACE_CUSTOM_FIELDS_OPT_FIELDS,
    WORKSPACES_ENDPOINT,
    WORKSPACES_OPT_FIELDS,
)
from .custom_fields import find_named_fields, get_named_value
from .exceptions import AsanaMappingException, AsanaPluginException


class AsanaPluginHelper:
    """Helper class for Asana API calls.

    Builds the request headers, sends requests with retry on HTTP 429 and
    5xx, converts Asana error bodies to messages, and implements the shared
    pagination and batch logic.
    """

    def __init__(
        self,
        logger: Any,
        log_prefix: str,
        plugin_name: str,
        plugin_version: str,
        ssl_validation: bool,
        proxy: Dict,
    ) -> None:
        """Initialize AsanaPluginHelper.

        Args:
            logger (Any): CE logger.
            log_prefix (str): Prefix of every log message.
            plugin_name (str): Plugin name from the manifest.
            plugin_version (str): Plugin version from the manifest.
            ssl_validation (bool): Whether to verify SSL certificates.
            proxy (Dict): Proxy configuration.
        """
        self.logger = logger
        self.log_prefix = log_prefix
        self.plugin_name = plugin_name
        self.plugin_version = plugin_version
        self.verify = ssl_validation
        self.proxies = proxy

    # ------------------------------------------------------------------
    # Headers and configuration
    # ------------------------------------------------------------------

    def _add_user_agent(self, headers: Optional[Dict] = None) -> Dict:
        """Add the plugin User-Agent to the headers.

        Format: <ce user agent>-cto-asana-v<plugin version>.

        Args:
            headers (Optional[Dict]): Request headers.

        Returns:
            Dict: Headers with the User-Agent added.
        """
        headers = dict(headers or {})
        if "User-Agent" in headers:
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

    @staticmethod
    def get_auth_params(configuration: Dict) -> Tuple[str, str]:
        """Return the API Base URL and the Token.

        The URL is trimmed and its trailing "/" removed. The Token is
        returned unchanged.

        Args:
            configuration (Dict): Plugin configuration.

        Returns:
            Tuple[str, str]: (base_url, token).
        """
        auth = configuration.get("auth", {}) or {}
        base_url = str(auth.get("base_url") or "").strip().rstrip("/")
        token = auth.get("token") or ""
        return base_url, token

    @staticmethod
    def get_config_params(configuration: Dict, step: str = "auth") -> Dict:
        """Return the parameters of a configuration step.

        Args:
            configuration (Dict): Plugin configuration.
            step (str): Step name ("auth" or "params"), or another top-level
                key of the configuration such as "mapping_config".

        Returns:
            Dict: Parameters of the step; empty when it is missing.
        """
        return (configuration or {}).get(step, {}) or {}

    @staticmethod
    def get_headers(token: str) -> Dict:
        """Return the headers of an authenticated request.

        Args:
            token (str): Asana Personal Access Token.

        Returns:
            Dict: Request headers.
        """
        return {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

    # ------------------------------------------------------------------
    # Response helpers
    # ------------------------------------------------------------------

    @staticmethod
    def join_error_messages(body: Any) -> str:
        """Join every error message of an Asana error body.

        The user_message is used when present, otherwise the message. The
        constant help URL is not included.

        Args:
            body (Any): Parsed JSON body.

        Returns:
            str: Messages joined with "; ", or an empty string.
        """
        if not isinstance(body, dict):
            return ""
        messages = []
        for error in body.get("errors") or []:
            if not isinstance(error, dict):
                continue
            message = error.get("user_message") or error.get("message")
            if message and message not in messages:
                messages.append(str(message))
        return "; ".join(messages)

    @staticmethod
    def _get_error_phrases(body: Any) -> List[str]:
        """Return the "phrase" values of an Asana error body.

        Asana support asks for the phrase of HTTP 500 errors.

        Args:
            body (Any): Parsed JSON body.

        Returns:
            List[str]: Phrases found in the errors.
        """
        if not isinstance(body, dict):
            return []
        return [
            str(error.get("phrase"))
            for error in body.get("errors") or []
            if isinstance(error, dict) and error.get("phrase")
        ]

    @staticmethod
    def explain_api_errors(api_msg: str) -> str:
        """Return explanations of the fields named in Asana error messages.

        Asana starts a field error with the field name, for example
        "enum_value: Not a recognized ID: Urgent".

        Args:
            api_msg (str): Joined API error messages.

        Returns:
            str: Explanations separated by spaces, or an empty string.
        """
        hints = []
        for message in api_msg.split("; "):
            field = message.split(":", 1)[0].strip().lower()
            hint = ASANA_ERROR_HINTS.get(field)
            if ":" in message and hint and hint not in hints:
                hints.append(hint)
        return " ".join(hints)

    def _extract_api_errors(
        self, response: requests.models.Response
    ) -> Tuple[str, str]:
        """Return the joined API error messages and the log details.

        Args:
            response (requests.models.Response): HTTP response.

        Returns:
            Tuple[str, str]: (messages, details for the log).
        """
        try:
            body = response.json()
        except Exception:
            body = None
        messages = self.join_error_messages(body)
        details = []
        phrases = self._get_error_phrases(body)
        if phrases:
            details.append(f"Asana error phrase: {', '.join(phrases)}.")
        text = (response.text or "").strip()
        if len(text) > MAX_DETAILS_LENGTH:
            text = f"{text[:MAX_DETAILS_LENGTH]}... [truncated]"
        details.append(f"API response: {text}")
        return messages, " ".join(details)

    def _get_retry_after(self, response: requests.models.Response) -> int:
        """Return the wait time before the next retry.

        Args:
            response (requests.models.Response): HTTP 429 or 5xx response.

        Returns:
            int: Value of the Retry-After header in seconds, or
                DEFAULT_WAIT_TIME when the header is missing or invalid.
        """
        retry_after = (response.headers or {}).get("Retry-After")
        try:
            wait_time = int(float(retry_after))
        except (TypeError, ValueError):
            return DEFAULT_WAIT_TIME
        return wait_time if wait_time >= 0 else DEFAULT_WAIT_TIME

    def parse_response(
        self,
        response: requests.models.Response,
        logger_msg: str,
        is_validation: bool = False,
    ) -> Dict:
        """Parse the JSON body of a response.

        Args:
            response (requests.models.Response): HTTP response.
            logger_msg (str): Operation in progress, for example
                "creating a task on Asana".
            is_validation (bool): True when called from validation.

        Returns:
            Dict: Parsed JSON body.

        Raises:
            AsanaPluginException: When the body is not valid JSON.
        """
        try:
            return response.json()
        except json.JSONDecodeError as error:
            if is_validation:
                err_msg = VALIDATION_INVALID_RESPONSE_MESSAGE
            else:
                err_msg = (
                    f"Error occurred while {logger_msg}. Invalid JSON"
                    " response received from Asana."
                )
            _, details = self._extract_api_errors(response)
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {error}",
                details=details,
                resolution=CONNECTION_RESOLUTION,
            )
            raise AsanaPluginException(err_msg)
        except Exception as error:
            err_msg = (
                f"Error occurred while {logger_msg}. Unable to parse the"
                " response received from Asana."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {error}",
                details=traceback.format_exc(),
            )
            raise AsanaPluginException(err_msg)

    def _get_validation_message(self, status_code: int, api_msg: str) -> str:
        """Return the validation message of an HTTP status code.

        Args:
            status_code (int): HTTP status code.
            api_msg (str): Joined API error messages.

        Returns:
            str: Message shown in the configuration screen.
        """
        if status_code in VALIDATION_ERROR_MESSAGES:
            return VALIDATION_ERROR_MESSAGES[status_code]
        if 500 <= status_code < 600:
            return VALIDATION_SERVER_ERROR_MESSAGE.format(
                status_code=status_code
            )
        reason = ERROR_REASONS.get(status_code, "HTTP client error")
        message = f"Received exit code {status_code}, {reason}."
        if api_msg:
            message = f"{message} Error: {api_msg}"
        return message

    def handle_error(
        self,
        response: requests.models.Response,
        logger_msg: str,
        is_validation: bool = False,
        error_context: Optional[str] = None,
    ) -> Dict:
        """Return the parsed body of a success, or log and raise an error.

        Args:
            response (requests.models.Response): HTTP response.
            logger_msg (str): Operation in progress.
            is_validation (bool): True when called from validation; the
                exception then carries the validation message.
            error_context (Optional[str]): Text appended to the message of
                a client error, for example the fields that were sent.

        Returns:
            Dict: Parsed body for 200, 201 and 202; empty dict for 204.

        Raises:
            AsanaPluginException: For every other status code.
        """
        status_code = response.status_code
        if status_code in (200, 201, 202):
            return self.parse_response(response, logger_msg, is_validation)
        if status_code == 204:
            return {}

        api_msg, details = self._extract_api_errors(response)
        if 500 <= status_code < 600:
            reason = "HTTP server error occurred"
        else:
            reason = ERROR_REASONS.get(status_code, "HTTP client error")
        resolution = RESOLUTIONS.get(status_code)
        if is_validation:
            err_msg = self._get_validation_message(status_code, api_msg)
            log_msg = f"Error occurred while {logger_msg}. {err_msg}"
        else:
            err_msg = (
                f"Error occurred while {logger_msg}. Received exit code"
                f" {status_code}, {reason}."
            )
            if api_msg:
                err_msg = f"{err_msg} Error: {api_msg}"
                hints = self.explain_api_errors(api_msg)
                if hints:
                    err_msg = f"{err_msg} {hints}"
            if error_context and 400 <= status_code < 500:
                err_msg = f"{err_msg} {error_context}"
            log_msg = err_msg
        log_kwargs = {
            "message": f"{self.log_prefix}: {log_msg}",
            "details": details,
        }
        if resolution:
            log_kwargs["resolution"] = resolution
        self.logger.error(**log_kwargs)
        raise AsanaPluginException(err_msg, status_code=status_code)

    # ------------------------------------------------------------------
    # Requests
    # ------------------------------------------------------------------

    def _handle_retry(
        self,
        response: requests.models.Response,
        logger_msg: str,
        retry_counter: int,
    ) -> int:
        """Log a retryable response and return the wait time.

        Args:
            response (requests.models.Response): HTTP 429 or 5xx response.
            logger_msg (str): Operation in progress.
            retry_counter (int): Index of the attempt that just failed.

        Returns:
            int: Seconds to wait before the next attempt.

        Raises:
            AsanaPluginException: When the retries are exhausted or the
                Retry-After value is greater than the maximum wait time.
        """
        status_code = response.status_code
        reason = (
            "Rate limit exceeded"
            if status_code == 429
            else "HTTP server error occurred"
        )
        base_msg = (
            f"Error occurred while {logger_msg}. Received exit code"
            f" {status_code}, {reason}."
        )
        _, details = self._extract_api_errors(response)
        if retry_counter == MAX_RETRIES - 1:
            err_msg = f"{base_msg} Maximum retries exceeded."
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}", details=details
            )
            raise AsanaPluginException(err_msg, status_code=status_code)

        wait_time = self._get_retry_after(response)
        if wait_time > MAX_WAIT_TIME:
            err_msg = (
                f"{base_msg} The Retry-After value of {wait_time} second(s)"
                f" is greater than the maximum wait time of {MAX_WAIT_TIME}"
                " second(s)."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}", details=details
            )
            raise AsanaPluginException(err_msg, status_code=status_code)

        retries_left = MAX_RETRIES - 1 - retry_counter
        self.logger.error(
            message=(
                f"{self.log_prefix}: {base_msg} Retrying after {wait_time}"
                f" second(s). {retries_left} retries remaining."
            ),
            details=details,
        )
        return wait_time

    def _raise_request_error(
        self,
        err_msg: str,
        error: Exception,
        resolution: Optional[str] = None,
        with_traceback: bool = False,
    ) -> None:
        """Log a request exception and raise AsanaPluginException.

        Args:
            err_msg (str): Message without the log prefix.
            error (Exception): Caught exception.
            resolution (Optional[str]): Resolution for errors the user can
                fix.
            with_traceback (bool): Add the traceback for unexpected errors.

        Raises:
            AsanaPluginException: Always.
        """
        log_kwargs = {
            "message": f"{self.log_prefix}: {err_msg} Error: {error}"
        }
        if with_traceback:
            log_kwargs["details"] = traceback.format_exc()
        if resolution:
            log_kwargs["resolution"] = resolution
        self.logger.error(**log_kwargs)
        raise AsanaPluginException(err_msg)

    def api_helper(
        self,
        logger_msg: str,
        url: str,
        method: str,
        headers: Optional[Dict] = None,
        params: Optional[Dict] = None,
        json_data: Optional[Dict] = None,
        is_handle_error_required: bool = True,
        is_validation: bool = False,
        error_context: Optional[str] = None,
    ) -> Any:
        """Send an API request with retry on HTTP 429 and 5xx.

        Args:
            logger_msg (str): Operation in progress, for example
                "creating a task for Alert ID '1' on Asana".
            url (str): Request URL.
            method (str): HTTP method.
            headers (Optional[Dict]): Request headers.
            params (Optional[Dict]): Query parameters.
            json_data (Optional[Dict]): JSON body.
            is_handle_error_required (bool): When False the raw response is
                returned (after the retries) instead of the parsed body.
            is_validation (bool): True for validation calls; they are never
                retried and use the validation messages.
            error_context (Optional[str]): Text appended to the message of
                a client error, for example the fields that were sent.

        Returns:
            Any: Parsed body, or the raw response when
                is_handle_error_required is False.

        Raises:
            AsanaPluginException: When the request fails.
        """
        try:
            headers = self._add_user_agent(headers)
            debug_msg = (
                f"{self.log_prefix}: API Request for {logger_msg}."
                f" Endpoint: {method} {url}"
            )
            if params:
                debug_msg = f"{debug_msg}, params: {params}"
            self.logger.debug(f"{debug_msg}.")

            for retry_counter in range(MAX_RETRIES):
                response = requests.request(
                    method=method,
                    url=url,
                    headers=headers,
                    params=params,
                    json=json_data,
                    verify=self.verify,
                    proxies=self.proxies,
                )
                status_code = response.status_code
                self.logger.debug(
                    f"{self.log_prefix}: Received API Response for"
                    f" {logger_msg}. Status Code={status_code}."
                )
                if not is_validation and (
                    status_code == 429 or 500 <= status_code < 600
                ):
                    time.sleep(
                        self._handle_retry(response, logger_msg, retry_counter)
                    )
                    continue
                if not is_handle_error_required:
                    return response
                return self.handle_error(
                    response, logger_msg, is_validation, error_context
                )
        except AsanaPluginException:
            raise
        except requests.exceptions.ReadTimeout as error:
            self._raise_request_error(
                (
                    VALIDATION_TIMEOUT_MESSAGE
                    if is_validation
                    else (
                        f"Error occurred while {logger_msg}. Read timeout"
                        " error occurred."
                    )
                ),
                error,
                CONNECTION_RESOLUTION,
            )
        except requests.exceptions.ProxyError as error:
            self._raise_request_error(
                (
                    VALIDATION_PROXY_MESSAGE
                    if is_validation
                    else (
                        f"Error occurred while {logger_msg}. Proxy error"
                        " occurred."
                    )
                ),
                error,
                PROXY_RESOLUTION,
            )
        except requests.exceptions.ConnectionError as error:
            self._raise_request_error(
                (
                    VALIDATION_CONNECTION_MESSAGE
                    if is_validation
                    else (
                        f"Error occurred while {logger_msg}. Unable to"
                        f" establish connection with {PLATFORM_NAME}."
                    )
                ),
                error,
                CONNECTION_RESOLUTION,
            )
        except requests.exceptions.HTTPError as error:
            self._raise_request_error(
                f"Error occurred while {logger_msg}. HTTP error occurred.",
                error,
                with_traceback=True,
            )
        except Exception as error:
            self._raise_request_error(
                f"Error occurred while {logger_msg}.",
                error,
                with_traceback=True,
            )

    # ------------------------------------------------------------------
    # Pagination and batch
    # ------------------------------------------------------------------

    def _is_expired_cursor(self, response: requests.models.Response) -> bool:
        """Check whether a 400 response reports an expired cursor.

        Args:
            response (requests.models.Response): HTTP 400 response.

        Returns:
            bool: True when the error says that the request timed out or
                that the pagination token is not valid anymore.
        """
        try:
            body = response.json()
        except Exception:
            return False
        messages = self.join_error_messages(body).lower()
        return any(marker in messages for marker in EXPIRED_CURSOR_MESSAGES)

    def paginate(
        self,
        logger_msg: str,
        url: str,
        headers: Dict,
        params: Optional[Dict] = None,
        is_validation: bool = False,
    ) -> List[Dict]:
        """Read every page of an Asana list endpoint.

        Sends limit=100 and the offset of the previous page until next_page
        is null. Restarts from page 1 once when the cursor expired, and
        stops at MAX_PAGES pages.

        Args:
            logger_msg (str): Operation in progress, for example
                "fetching workspaces from Asana".
            url (str): List endpoint URL.
            headers (Dict): Request headers.
            params (Optional[Dict]): Query parameters other than limit and
                offset.
            is_validation (bool): True for validation calls.

        Returns:
            List[Dict]: Objects of every page.

        Raises:
            AsanaPluginException: When a page cannot be read.
        """
        base_params = {**(params or {}), "limit": PAGE_LIMIT}
        items: List[Dict] = []
        offset = None
        page = 1
        restarted = False
        while True:
            page_params = dict(base_params)
            if offset:
                page_params["offset"] = offset
            self.logger.debug(
                f"{self.log_prefix}: Fetching page {page} while {logger_msg}."
            )
            response = self.api_helper(
                logger_msg=logger_msg,
                url=url,
                method="GET",
                headers=headers,
                params=page_params,
                is_handle_error_required=False,
                is_validation=is_validation,
            )
            if (
                response.status_code == 400
                and offset
                and not restarted
                and self._is_expired_cursor(response)
            ):
                self.logger.info(
                    f"{self.log_prefix}: The pagination cursor expired while"
                    f" {logger_msg}. Reading the list again from page 1."
                )
                restarted, items, offset, page = True, [], None, 1
                continue

            body = self.handle_error(response, logger_msg, is_validation)
            data = body.get("data") if isinstance(body, dict) else None
            if isinstance(data, list):
                items.extend(data)
            next_page = body.get("next_page") if isinstance(body, dict) else {}
            offset = (next_page or {}).get("offset")
            if not offset:
                return items
            if page >= MAX_PAGES:
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: Error occurred while"
                        f" {logger_msg}. Reached the maximum page limit of"
                        f" {MAX_PAGES}. Only the first {len(items)}"
                        " object(s) will be used."
                    ),
                )
                return items
            page += 1

    def execute_batch(
        self,
        logger_msg: str,
        base_url: str,
        headers: Dict,
        actions: List[Dict],
    ) -> List[Dict]:
        """Send up to 10 actions in one POST /batch request.

        Args:
            logger_msg (str): Operation in progress.
            base_url (str): API Base URL.
            headers (Dict): Request headers.
            actions (List[Dict]): Batch actions.

        Returns:
            List[Dict]: One result per action, in the order of the actions.

        Raises:
            AsanaPluginException: When the request fails or the number of
                results differs from the number of actions.
        """
        body = self.api_helper(
            logger_msg=logger_msg,
            url=f"{base_url}{BATCH_ENDPOINT}",
            method="POST",
            headers=headers,
            json_data={"data": {"actions": actions}},
        )
        results = body.get("data") if isinstance(body, dict) else None
        if not isinstance(results, list) or len(results) != len(actions):
            count = len(results) if isinstance(results, list) else 0
            err_msg = (
                f"Error occurred while {logger_msg}. Received {count}"
                f" result(s) for {len(actions)} action(s)."
            )
            self.logger.error(message=f"{self.log_prefix}: {err_msg}")
            # The batch itself returned HTTP 200, so only this group is lost.
            raise AsanaPluginException(err_msg, status_code=200)
        return results

    # ------------------------------------------------------------------
    # Logging
    # ------------------------------------------------------------------

    def log_mapping_error(
        self, logger_msg: str, error: AsanaMappingException
    ) -> AsanaPluginException:
        """Log a queue mapping error and return the exception to raise.

        Args:
            logger_msg (str): Operation in progress.
            error (AsanaMappingException): Mapping error.

        Returns:
            AsanaPluginException: Exception carrying the full message.
        """
        err_msg = f"Error occurred while {logger_msg}. {error}"
        self.logger.error(
            message=f"{self.log_prefix}: {err_msg}",
            resolution=error.resolution,
        )
        return AsanaPluginException(err_msg)

    def log_unexpected_error(
        self, logger_msg: str, error: Exception
    ) -> AsanaPluginException:
        """Log an unexpected exception and return the exception to raise.

        Args:
            logger_msg (str): Operation in progress.
            error (Exception): Caught exception.

        Returns:
            AsanaPluginException: Exception carrying the message.
        """
        err_msg = f"Error occurred while {logger_msg}."
        self.logger.error(
            message=f"{self.log_prefix}: {err_msg} Error: {error}",
            details=traceback.format_exc(),
        )
        return AsanaPluginException(err_msg)

    def get_action_error(self, result: Dict) -> str:
        """Return the error message of a failed batch action.

        Args:
            result (Dict): Batch result.

        Returns:
            str: Status code and the API messages.
        """
        status_code = result.get("status_code")
        api_msg = self.join_error_messages(result.get("body"))
        message = f"Received exit code {status_code}."
        if not api_msg:
            return message
        message = f"{message} Error: {api_msg}"
        hints = self.explain_api_errors(api_msg)
        return f"{message} {hints}" if hints else message

    def log_action_error(
        self, logger_msg: str, result: Dict, suffix: str = ""
    ) -> str:
        """Log a failed batch action.

        A resolution is added only for status codes the user can fix.

        Args:
            logger_msg (str): Operation of the action.
            result (Dict): Batch result.
            suffix (str): Text appended to the message.

        Returns:
            str: The error message without the log prefix.
        """
        err_msg = (
            f"Error occurred while {logger_msg}."
            f" {self.get_action_error(result)}{suffix}"
        )
        log_kwargs = {"message": f"{self.log_prefix}: {err_msg}"}
        resolution = RESOLUTIONS.get(result.get("status_code"))
        if resolution:
            log_kwargs["resolution"] = resolution
        self.logger.error(**log_kwargs)
        return err_msg

    # ------------------------------------------------------------------
    # Workspace lookups
    # ------------------------------------------------------------------

    def fetch_workspaces(
        self, base_url: str, headers: Dict, is_validation: bool = False
    ) -> List[Dict]:
        """Return every workspace the token user can access.

        Args:
            base_url (str): API Base URL.
            headers (Dict): Request headers.
            is_validation (bool): True when called from validation.

        Returns:
            List[Dict]: Workspaces that have a gid and a name.
        """
        workspaces = self.paginate(
            logger_msg=f"fetching workspaces from {PLATFORM_NAME}",
            url=f"{base_url}{WORKSPACES_ENDPOINT}",
            headers=headers,
            params={"opt_fields": WORKSPACES_OPT_FIELDS},
            is_validation=is_validation,
        )
        return [
            workspace
            for workspace in workspaces
            if isinstance(workspace, dict)
            and workspace.get("gid")
            and workspace.get("name")
        ]

    def fetch_workspace_custom_fields(
        self,
        base_url: str,
        headers: Dict,
        workspace_gid: str,
        is_validation: bool = False,
    ) -> List[Dict]:
        """Return every custom field of a workspace (all pages).

        Args:
            base_url (str): API Base URL.
            headers (Dict): Request headers.
            workspace_gid (str): Workspace gid.
            is_validation (bool): True when called from validation.

        Returns:
            List[Dict]: Custom field objects.
        """
        endpoint = WORKSPACE_CUSTOM_FIELDS_ENDPOINT.format(
            workspace_gid=workspace_gid
        )
        return self.paginate(
            logger_msg=f"fetching custom fields from {PLATFORM_NAME}",
            url=f"{base_url}{endpoint}",
            headers=headers,
            params={"opt_fields": WORKSPACE_CUSTOM_FIELDS_OPT_FIELDS},
            is_validation=is_validation,
        )

    # ------------------------------------------------------------------
    # Values and messages
    # ------------------------------------------------------------------

    @staticmethod
    def validate_url(url: str) -> bool:
        """Check that a URL is an https URL with a host and no query.

        Args:
            url (str): URL to check.

        Returns:
            bool: True when the URL is valid.
        """
        try:
            parsed = urlparse(url)
        except ValueError:
            return False
        return (
            parsed.scheme == "https"
            and bool(parsed.hostname)
            and not parsed.query
        )

    @staticmethod
    def get_event_label(alert: Union[Alert, Event]) -> str:
        """Return "Event" for an event and "Alert" for an alert.

        Args:
            alert (Union[Alert, Event]): Alert or event.

        Returns:
            str: "Event" or "Alert".
        """
        return "Event" if hasattr(alert, "eventType") else "Alert"

    @staticmethod
    def get_project_label(queue: Queue, project_gid: str) -> str:
        """Return the project name of a queue for messages.

        Args:
            queue (Queue): Queue selected for the task.
            project_gid (str): Project gid of the queue.

        Returns:
            str: For example "'Netskope Project' (gid '1219245697468891')",
                or the quoted gid when the queue has no name.
        """
        name = str(getattr(queue, "label", "") or "").strip()
        if name and name != project_gid:
            return f"'{name}' (gid '{project_gid}')"
        return f"'{project_gid}'"

    @staticmethod
    def get_event_value(
        item: Union[Alert, Event, None], key: str
    ) -> Optional[str]:
        """Return a value of the raw data of an alert or event.

        CE converts the status and severity of the alert or event to the
        Asana values of the Status and Severity Mapping before it calls
        create_task and update_task.

        Args:
            item (Union[Alert, Event, None]): Alert or event.
            key (str): Raw data key, for example "status" or "assignee".

        Returns:
            Optional[str]: The value, or None when it is missing or empty.
        """
        raw_data = getattr(item, "rawData", None)
        value = raw_data.get(key) if isinstance(raw_data, dict) else None
        return value if value not in (None, "") else None

    def read_named_value(
        self,
        custom_fields: List[Dict],
        field_name: str,
        fallback: Union[str, TaskStatus, None],
        task_id: str = "",
    ) -> Union[str, TaskStatus, None]:
        """Read the Status or Severity value of a task.

        Without a field name the field is not read. A field without a value
        is treated like a missing field. CE has no mapping for "other" and
        would show New or Low (and push it to the Netskope incident), so the
        fallback keeps the known value instead.

        Args:
            custom_fields (List[Dict]): custom_fields array of the task.
            field_name (str): Exact name of the Status or Severity field;
                empty when it is not provided.
            fallback (Union[str, TaskStatus, None]): Value used when the
                field is not read or has no value.
            task_id (str): Task gid, for the logs.

        Returns:
            Union[str, TaskStatus, None]: The Asana value or the fallback.
        """
        if not field_name:
            return fallback
        matches = find_named_fields(custom_fields, field_name)
        if len(matches) > 1:
            self.logger.debug(
                f"{self.log_prefix}: Found {len(matches)} custom fields"
                f" named '{field_name}' on task '{task_id}'. The first one"
                " with a value is used."
            )
        return get_named_value(matches) or fallback

    @staticmethod
    def get_value_mapping(
        mapping_config: Any, event_field: str
    ) -> Dict[str, str]:
        """Return the CE value to Asana value mapping of a section.

        Reads the Status or Severity section of the Mapping Configuration
        that CE stores in the configuration ("mapping_config"). It is the
        reverse of what CE core does to a returned task in
        plugin_to_ce_task_map (netskope/integrations/itsm/utils/
        custom_mapping_utils.py), so it has to be checked on every CE
        version that is supported.

        Args:
            mapping_config (Any): "mapping_config" of the configuration.
            event_field (str): "status" or "severity".

        Returns:
            Dict[str, str]: CE value mapped to the Asana value; values
                without an Asana value are left out.
        """
        if not isinstance(mapping_config, dict):
            return {}
        value_map = {}
        for section in mapping_config.values():
            if not isinstance(section, dict):
                continue
            if section.get("event_field") != event_field:
                continue
            for item in section.get("mappings") or []:
                if not isinstance(item, dict):
                    continue
                for ce_value, asana_value in item.items():
                    if ce_value and asana_value:
                        value_map.setdefault(ce_value, asana_value)
        return value_map

    @staticmethod
    def describe_sent_values(
        data: Dict, mappings: Dict, project_gid: str, fields: Dict
    ) -> str:
        """Describe the values sent to Asana, for error messages.

        The task name and notes are named but their text is not included.

        Args:
            data (Dict): Body data of the request.
            mappings (Dict): Queue mapping values.
            project_gid (str): Project gid of the queue.
            fields (Dict): Custom field entries of the project, keyed by
                field gid.

        Returns:
            str: For example "Values sent to Asana: project '1', name,
                assignee, custom field 'Severity' (enum) = 'High'.", or an
                empty string.
        """
        parts = []
        if data.get("projects"):
            parts.append(f"project '{project_gid}'")
        parts.extend(key for key in ("name", "notes") if data.get(key))
        if data.get("assignee"):
            parts.append("assignee")
        for field_gid in (data.get("custom_fields") or {}).keys():
            entry = fields.get(field_gid) or {}
            value = mappings.get(f"{CUSTOM_FIELD_PREFIX}{field_gid}")
            parts.append(
                f"custom field '{entry.get('name') or field_gid}'"
                f" ({entry.get('type', '')}) = '{value}'"
            )
        return f"Values sent to Asana: {', '.join(parts)}." if parts else ""

    @staticmethod
    def describe_update(update_data: Dict, fields: Dict) -> str:
        """Describe the fields sent in a task update, for the logs.

        Args:
            update_data (Dict): Body data of PUT /tasks/{gid}.
            fields (Dict): Custom field entries of the project, keyed by
                field gid.

        Returns:
            str: For example "the assignee and the custom field(s)
                'Severity'".
        """
        parts = []
        if update_data.get("assignee"):
            parts.append("the assignee")
        field_gids = list((update_data.get("custom_fields") or {}).keys())
        if field_gids:
            names = ", ".join(
                f"'{(fields.get(gid) or {}).get('name') or gid}'"
                for gid in field_gids
            )
            parts.append(f"the custom field(s) {names}")
        return " and ".join(parts)

    @staticmethod
    def is_deleted(task: Task) -> bool:
        """Check whether a task is already marked deleted.

        CE stores the mapped label ("Deleted"), so the check ignores case.

        Args:
            task (Task): CE task.

        Returns:
            bool: True when the task is deleted.
        """
        status = getattr(task.status, "value", task.status)
        return str(status or "").lower() == TaskStatus.DELETED.value

    @staticmethod
    def stops_sync(error: AsanaPluginException) -> bool:
        """Check whether a failed batch makes the next batches fail too.

        A token, plan, legal or rate limit error, a server error that is
        still there after the retries, and a network error would repeat for
        every following batch, so the sync stops. Any other error belongs to
        its own batch only.

        Args:
            error (AsanaPluginException): Error of the batch.

        Returns:
            bool: True when the remaining batches should be skipped.
        """
        status_code = error.status_code
        return (
            status_code is None
            or status_code in FATAL_STATUS_CODES
            or status_code >= 500
        )
