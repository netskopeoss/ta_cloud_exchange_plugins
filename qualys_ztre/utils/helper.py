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

CRE Qualys plugin helper.
"""

import hashlib
import time
import traceback
from typing import Any, Dict, Literal, List, Tuple, Union
from urllib.parse import urlparse

import requests
from netskope.common.utils import add_user_agent
from requests.auth import HTTPBasicAuth
from requests.models import Response

from .constants import (
    DEFAULT_SLEEP_TIME,
    MAX_RETRIES,
    MODULE_NAME,
    NO_MORE_RETRIES_ERROR_MSG,
    PLATFORM_NAME,
    RETRY_ERROR_MSG,
    TAG_NAME_LENGTH,
    VALIDATION_ERROR_MESSAGE,
)
from .exceptions import QualysPluginException, exception_handler
from .parser import QualysParser


class QualysHelper:
    def __init__(
        self,
        logger,
        log_prefix: str,
        plugin_name: str,
        plugin_version: str,
        parser: QualysParser,
    ):
        """QualysHelper initializer.

        Args:
            logger (logger object): Logger object.
            log_prefix (str): log prefix.
            plugin_name (str): Plugin name.
            plugin_version (str): Plugin version.
            parser (any): Parser object.
        """
        self.logger = logger
        self.log_prefix = log_prefix
        self.plugin_name = plugin_name
        self.plugin_version = plugin_version
        self.parser = parser

    def _add_user_agent(
        self,
        headers: Union[Dict, None] = None,
        key_to_add: Literal["User-Agent", "X-Requested-With"] = "User-Agent",
    ) -> Dict:
        """Add User-Agent in the headers for third-party requests.

        Args:
            headers (Dict): Dictionary containing headers for any request.
        Returns:
            Dict: Dictionary after adding User-Agent.
        """
        if headers and key_to_add in headers:
            return headers
        if key_to_add == "User-Agent":
            headers = add_user_agent(headers)
        ce_added_agent = headers.get(key_to_add, "netskope-ce")
        user_agent = "{}-{}-{}-v{}".format(
            ce_added_agent,
            MODULE_NAME.lower(),
            self.plugin_name.lower().replace(" ", "-"),
            self.plugin_version,
        )
        headers.update({key_to_add: user_agent})
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
        basic_auth: HTTPBasicAuth = None,
        response_format: Literal["json", "xml", "plain"] = "json",
    ):
        """
        Make API call to Qualys.

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
        headers = self._add_user_agent(
            headers=headers, key_to_add="User-Agent"
        )
        debug_log_msg = (
            f"{self.log_prefix}: API Request for {logger_msg}. "
            f"Endpoint: {method} {url}"
        )
        if params:
            debug_log_msg += f", params: {params}."
        self.logger.debug(debug_log_msg)
        try:
            for retry_count in range(MAX_RETRIES):
                response = self._api_call(
                    url=url,
                    method=method,
                    params=params,
                    data=data,
                    headers=headers,
                    verify=verify,
                    proxies=proxies,
                    json=json,
                    basic_auth=basic_auth,
                )
                status_code = response.status_code
                self.logger.debug(
                    f"{self.log_prefix}: Received API Response for "
                    f"{logger_msg}. Status Code={status_code}."
                )
                # Token regeneration logic
                if (
                    status_code == 401
                    and regenerate_access_token
                    and not basic_auth
                ):
                    _, api_gateway_url, username, password, _, _ = (
                        self.get_configuration_parameters(configuration)
                    )
                    regenerated_access_token = (
                        self.generate_access_token(
                            gateway_url=api_gateway_url,
                            password=password,
                            username=username,
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
                        basic_auth=None,
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
                        raise QualysPluginException(
                            err_msg
                        )
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
                            response_format=response_format
                        ) if is_handle_error_required else response
                    )
        except QualysPluginException:
            raise
        except requests.exceptions.ReadTimeout as error:
            err_msg = f"Read Timeout error occurred while {logger_msg}."
            if is_validation:
                err_msg = "Read Timeout error occurred."

            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {error}",
                details=traceback.format_exc(),
                resolution=(
                    "Ensure that your Qualys platform server"
                    " is reachable."
                ),
            )
            raise QualysPluginException(err_msg)
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
                    "Ensure that the proxy configuration provided is"
                    " correct and the proxy server is reachable."
                ),
            )
            raise QualysPluginException(err_msg)
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
                    "Ensure that your Qualys platform server is reachable."
                ),
            )
            raise QualysPluginException(err_msg)
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
                    "Ensure that the configuration parameters provided are"
                    " correct."
                ),
            )
            raise QualysPluginException(err_msg)
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
                    "Ensure that the configuration parameters provided are"
                    " correct."
                )
            )
            raise QualysPluginException(err_msg)

    def _api_call(
        self,
        url: str,
        method: str = "GET",
        params=None,
        data: Dict = None,
        headers: Dict = None,
        verify=True,
        proxies=None,
        json: Dict = None,
        basic_auth: HTTPBasicAuth = None,
    ) -> Response:
        if basic_auth:
            response = requests.request(
                url=url,
                method=method,
                auth=basic_auth,
                params=params,
                data=data,
                headers=headers,
                verify=verify,
                proxies=proxies,
                json=json,
            )
        else:
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
        return response

    def _get_retry_after(self, response_headers: Dict) -> int:
        retry_after = None
        if value := response_headers.get("X-RateLimit-ToWait-Sec"):
            retry_after = int(value)
        elif value := response_headers.get("Retry-After"):
            retry_after = int(value)
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

    def handle_error(
        self,
        response: Response,
        logger_msg: str,
        is_validation: bool,
        response_format: Literal["json", "xml" "plain"],
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
            QualysPluginException: When the response code is
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
                "Verify the API Server URL, API Gateway URL, Username and"
                " Password provided in the configuration parameters."
            ),
            401: (
                "Verify Username and Password provided in the"
                " configuration parameters."
            ),
            403: (
                "Verify permission for Username and Password provided"
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
                    "Verify the API Server URL, API Gateway URL, Username"
                    " and Password provided in the configuration parameters."
                ),
                401: (
                    "Received exit code 401, Unauthorized, "
                    "Verify Username and Password provided in the"
                    " configuration parameters."
                ),
                403: (
                    "Received exit code 403, Forbidden, "
                    "Verify permission for Username and Password "
                    "provided in the configuration parameters."
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
                raise QualysPluginException(err_msg)
            else:
                err_msg = err_msg + " while " + logger_msg + "."
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg}",
                    details=f"API response: {response.text}",
                )
                raise QualysPluginException(err_msg)

        if status_code in [200, 201, 202]:
            return self.parser.parse_response(
                response=response,
                logger_msg=logger_msg,
                is_validation=is_validation,
                response_format=response_format,
            )
        elif status_code == 204:
            return {}
        elif status_code in error_dict:
            err_msg = error_dict[status_code]
            resolution_msg = resolution_dict[status_code]
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

    @exception_handler
    def generate_access_token(
        self,
        gateway_url: str,
        username: str,
        password: str,
        verify: Any,
        proxies: Any,
        is_validation: bool,
        context={}
    ):
        logger_msg = "generating access token"
        context["logger_msg"] = logger_msg
        url = f"{gateway_url}/auth"
        response = self.api_helper(
            logger_msg=logger_msg,
            url=url,
            method="POST",
            headers={
                "Content-Type": "application/x-www-form-urlencoded"
            },
            data={
                "username": username,
                "password": password,
                "token": True,
            },
            verify=verify,
            proxies=proxies,
            is_validation=is_validation,
            is_handle_error_required=True,
            regenerate_access_token=False,
            response_format="plain"
        )
        return response

    def get_configuration_parameters(
        self, configuration: Dict
    ) -> Tuple[str, str, str, str, str, str, str]:
        api_server_url = (
            configuration.get(
                "api_server_url",
                "",
            )
            .strip()
            .strip("/")
        )
        api_gateway_url = (
            configuration.get(
                "api_gateway_url",
                "",
            )
            .strip()
            .strip("/")
        )
        username = configuration.get("username")
        password = configuration.get("password")
        pull_asset_vulnerabilities = configuration.get(
            "pull_asset_vulnerabilities"
        )
        pull_webapp_findings = configuration.get("pull_webapp_findings")

        return (
            api_server_url,
            api_gateway_url,
            username,
            password,
            pull_asset_vulnerabilities,
            pull_webapp_findings,
        )

    def get_headers(
        self,
        access_token: str = None,
        request_response_type: Literal["xml", "json"] = "json",
        x_requested_header: bool = True,
    ) -> Dict:
        headers = {}
        if access_token:
            headers.update(
                {
                    "Authorization": f"Bearer {access_token}",
                }
            )
        if request_response_type == "json":
            headers.update(
                {
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                }
            )
        if request_response_type == "xml":
            headers.update(
                {
                    "Content-Type": "application/x-www-form-urlencoded",
                }
            )
        if x_requested_header:
            headers = self._add_user_agent(
                headers=headers, key_to_add="X-Requested-With"
            )
        return headers

    def hash_string(self, string: str) -> str:
        return hashlib.sha256(string.encode()).hexdigest()

    def _validate_url(self, url: str) -> bool:
        """Validate the URL using parsing.

        Args:
            url (str): Given URL.

        Returns:
            bool: True or False { Valid or not Valid URL }.
        """
        parsed = urlparse(url)
        return parsed.scheme.strip() != "" and parsed.netloc.strip() != ""

    def validate_tags_string(self, tags: str) -> bool:
        """Ensure every comma-separated tag contains non-empty content.

        The validation trims whitespace around each tag and fails if any tag is
        left blank (for example, consecutive commas or trailing commas). Use
        this as a lightweight guard before running the more expensive
        ``validate_tags`` method.

        Args:
            tags: Comma-separated string of tag names supplied by the user.

        Returns:
            bool: ``True`` when all tags are non-empty after stripping, else
                ``False``.
        """
        for tag in tags.split(","):
            if not tag.strip():
                return False
        return True

    def validate_tags(self, tags: str) -> bool:
        """
        Validate a comma-separated string of tags against length constraints.

        This method checks if the provided tags string contains valid tags and
        ensures that each tag doesn't exceed the maximum allowed length.

        Args:
            tags (str): A comma-separated string of tag names to validate

        Returns:
            bool: True if all tags are valid, False otherwise
        """
        if isinstance(tags, List):
            tags_list = tags
        else:
            tags_list = tags.split(",")
        long_tags = [tag for tag in tags_list if len(tag) > TAG_NAME_LENGTH]
        if long_tags:
            self.logger.error(
                message=(
                    f"{self.log_prefix}: {VALIDATION_ERROR_MESSAGE} Found"
                    f" {len(long_tags)} tag(s) with length greater than"
                    f" {TAG_NAME_LENGTH} characters. Please ensure tag"
                    f" length is less than {TAG_NAME_LENGTH}"
                    " characters."
                ),
                details=(
                    f"Tags with length greater than "
                    f"{TAG_NAME_LENGTH}: {', '.join(long_tags)}"
                ),
            )
            return False
        return True
