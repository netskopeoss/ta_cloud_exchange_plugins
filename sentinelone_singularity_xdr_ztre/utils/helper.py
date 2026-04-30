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

3. Neither the name of the copyright holder nor the names of its
   contributors may be used to endorse or promote products derived from
   this software without specific prior written permission.

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

CRE SentinelOne Singularity XDR plugin helper module.
"""

import json
import time
import traceback
from typing import Dict, Generator, List, Tuple, Union
from urllib.parse import urlparse

import requests
from dateutil import parser
from netskope.common.utils import add_user_agent

from .constants import (
    BATCH_SIZE,
    DEFAULT_WAIT_TIME,
    MAX_RETRIES,
    MODULE_NAME,
    NO_MORE_RETRIES_ERROR_MSG,
    PLATFORM_NAME,
    RETRY_ERROR_MSG,
)
from .exceptions import SentinelOneSingularityXDRPluginException


class SentinelOnePluginHelper(object):
    """SentinelOnePluginHelper Class.

    Args:
        object (object): Object class.
    """

    def __init__(
        self,
        logger,
        log_prefix: str,
        plugin_name: str,
        plugin_version: str,
    ):
        """SentinelOnePluginHelper initializer.

        Args:
            logger: Logger object.
            log_prefix (str): Log prefix.
            plugin_name (str): Plugin name.
            plugin_version (str): Plugin version.
        """
        self.logger = logger
        self.log_prefix = log_prefix
        self.plugin_name = plugin_name
        self.plugin_version = plugin_version

    def _add_user_agent(
        self, headers: Union[Dict, None] = None
    ) -> Dict:
        """Add User-Agent in the headers for third-party requests.

        Args:
            headers (Dict): Dictionary containing headers for any
                request.

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
        params: Dict = {},
        data=None,
        headers: Dict = {},
        json=None,
        is_handle_error_required: bool = True,
        is_validation: bool = False,
        ssl_validation=True,
        proxy=None,
    ):
        """API Helper performs API request to SentinelOne platform
        and captures all the possible errors for requests.

        Args:
            logger_msg (str): Logger message.
            url (str): API Endpoint.
            method (str): Method for the endpoint.
            params (Dict, optional): Request parameters dictionary.
            data: Data to be sent to API.
            headers (Dict, optional): Headers for the request.
            json: JSON payload for request.
            is_handle_error_required (bool, optional): Whether the API
                helper should handle the status codes.
            is_validation (bool, optional): Is this call from validate?
            ssl_validation: SSL Validation Flag.
            proxy: Proxy Configuration.

        Returns:
            Response|Response JSON: Returns response json if
            is_handle_error_required is True otherwise returns Response.
        """
        try:
            headers = self._add_user_agent(headers)

            debug_log_msg = (
                f"{self.log_prefix}: API Request for {logger_msg}."
                f" Endpoint: {method} {url}"
            )
            if params:
                debug_log_msg += f", params: {params}"
            self.logger.debug(debug_log_msg)

            for retry_counter in range(MAX_RETRIES):
                response = requests.request(
                    url=url,
                    method=method,
                    params=params,
                    data=data,
                    headers=headers,
                    verify=ssl_validation,
                    proxies=proxy,
                    json=json,
                )
                status_code = response.status_code
                self.logger.debug(
                    f"{self.log_prefix}: Received API Response for "
                    f"{logger_msg}. Status Code={status_code}.",
                )

                if not is_validation and (
                    status_code == 429 or 500 <= status_code <= 600
                ):
                    api_err_msg = str(response.text)
                    if retry_counter == MAX_RETRIES - 1:
                        err_msg = NO_MORE_RETRIES_ERROR_MSG.format(
                            status_code=status_code,
                            logger_msg=logger_msg,
                        )
                        self.logger.error(
                            message=f"{self.log_prefix}: {err_msg}"
                        )
                        raise SentinelOneSingularityXDRPluginException(
                            err_msg
                        )
                    if status_code == 429:
                        error_reason = "API rate limit exceeded"
                    else:
                        error_reason = "HTTP server error occurred"
                    err_msg = RETRY_ERROR_MSG.format(
                        status_code=status_code,
                        error_reason=error_reason,
                        logger_msg=logger_msg,
                        wait_time=DEFAULT_WAIT_TIME,
                        retry_remaining=MAX_RETRIES - 1 - retry_counter,
                    )
                    self.logger.error(
                        message=f"{self.log_prefix}: {err_msg}",
                        details=api_err_msg,
                    )
                    time.sleep(DEFAULT_WAIT_TIME)
                else:
                    return (
                        self.handle_error(
                            response, logger_msg, is_validation
                        )
                        if is_handle_error_required
                        else response
                    )

        except SentinelOneSingularityXDRPluginException:
            raise
        except requests.exceptions.ReadTimeout as error:
            err_msg = f"Read Timeout error occurred while {logger_msg}."
            if is_validation:
                err_msg = "Read Timeout error occurred."

            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {error}",
                details=traceback.format_exc(),
                resolution=(
                    "Ensure that your SentinelOne platform server"
                    " is reachable."
                ),
            )
            raise SentinelOneSingularityXDRPluginException(err_msg)
        except requests.exceptions.ProxyError as error:
            err_msg = (
                f"Proxy error occurred while {logger_msg}. Verify the"
                " proxy configuration provided."
            )
            if is_validation:
                err_msg = (
                    "Proxy error occurred. Verify "
                    "the proxy configuration provided."
                )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {error}",
                resolution=(
                    "Ensure that the proxy configuration provided"
                    " is correct."
                ),
                details=traceback.format_exc(),
            )
            raise SentinelOneSingularityXDRPluginException(err_msg)
        except requests.exceptions.ConnectionError as error:
            err_msg = (
                f"Unable to establish connection with {PLATFORM_NAME}"
                f" platform while {logger_msg}. Proxy server or "
                f"{PLATFORM_NAME} server is not reachable."
            )
            if is_validation:
                err_msg = (
                    f"Unable to establish connection with {PLATFORM_NAME}"
                    f" platform. Proxy server or {PLATFORM_NAME}"
                    " server is not reachable."
                )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {error}",
                details=traceback.format_exc(),
            )
            raise SentinelOneSingularityXDRPluginException(err_msg)
        except requests.HTTPError as err:
            err_msg = f"HTTP error occurred while {logger_msg}."
            if is_validation:
                err_msg = (
                    "HTTP error occurred. Verify"
                    " configuration parameters provided."
                )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {err}",
                details=traceback.format_exc(),
            )
            raise SentinelOneSingularityXDRPluginException(err_msg)
        except Exception as exp:
            err_msg = (
                f"Unexpected error occurred while {logger_msg}."
            )
            if is_validation:
                err_msg = (
                    "Unexpected error while performing "
                    f"API call to {PLATFORM_NAME}."
                )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {exp}",
                details=traceback.format_exc(),
            )
            raise SentinelOneSingularityXDRPluginException(err_msg)

    def parse_response(
        self,
        response: requests.models.Response,
        is_validation: bool = False,
    ):
        """Parse Response will return JSON from response object.

        Args:
            response (response): Response object.
            is_validation (bool): Is this a validation call?

        Returns:
            Any: Response Json.
        """
        try:
            return response.json()
        except json.JSONDecodeError as err:
            err_msg = (
                "Invalid JSON response received from API."
                f" Error: {str(err)}"
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=f"API response: {response.text}",
            )
            if is_validation:
                err_msg = (
                    "Verify Base URL provided in the "
                    "configuration parameters. Check logs for"
                    " more details."
                )
            raise SentinelOneSingularityXDRPluginException(err_msg)
        except Exception as exp:
            err_msg = (
                "Unexpected error occurred while parsing"
                f" json response. Error: {exp}"
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=f"API response: {response.text}",
            )
            if is_validation:
                err_msg = (
                    "Unexpected validation error occurred, "
                    "Verify Base URL provided in the "
                    "configuration parameters. Check logs for"
                    " more details."
                )
            raise SentinelOneSingularityXDRPluginException(err_msg)

    def handle_error(
        self,
        resp: requests.models.Response,
        logger_msg: str,
        is_validation: bool = False,
    ):
        """Handle the different HTTP response codes.

        Args:
            resp (requests.models.Response): Response object.
            logger_msg (str): Logger message.
            is_validation (bool): Is this a validation call?

        Returns:
            dict: Response JSON when status code is 200/201/202.

        Raises:
            SentinelOneSingularityXDRPluginException: For non-200 status codes.
        """
        status_code = resp.status_code
        validation_msg = "Validation error occurred, "
        error_dict = {
            400: "Received exit code 400, HTTP client error",
            401: "Received exit code 401, Unauthorized access",
            403: "Received exit code 403, Forbidden access",
            404: "Received exit code 404, Resource not found",
        }
        resolution_dict = {
            400: (
                "Ensure that the Base URL and API Token provided in"
                " the configuration parameters are correct."
            ),
            401: (
                "Ensure that the API Token provided in the"
                " configuration parameters is correct."
            ),
            403: (
                "Ensure that the API Token has the required"
                " permissions/scopes."
            ),
            404: (
                "Ensure that the Base URL provided in the"
                " configuration parameters is correct."
            ),
        }

        if is_validation:
            error_dict = {
                400: (
                    "Received exit code 400, Bad Request, Verify the"
                    " Base URL and API Token provided in the"
                    " configuration parameters."
                ),
                401: (
                    "Received exit code 401, Unauthorized, Verify the"
                    " API Token provided in the configuration parameters."
                ),
                403: (
                    "Received exit code 403, Forbidden access, Verify"
                    " the API Token has the required permissions."
                ),
                404: (
                    "Received exit code 404, Resource not found, Verify"
                    " the Base URL provided in the configuration parameters."
                ),
            }

        if status_code in [200, 201, 202]:
            return self.parse_response(
                response=resp, is_validation=is_validation
            )
        elif status_code == 204:
            return {}
        elif status_code in error_dict:
            err_msg = error_dict[status_code]
            resolution = resolution_dict.get(status_code)
            if is_validation:
                log_err_msg = validation_msg + err_msg
                self.logger.error(
                    message=f"{self.log_prefix}: {log_err_msg}",
                    resolution=resolution,
                    details=f"API response: {resp.text}",
                )
                raise SentinelOneSingularityXDRPluginException(err_msg)
            else:
                err_msg = err_msg + " while " + logger_msg + "."
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg}",
                    resolution=resolution,
                    details=f"API response: {resp.text}",
                )
                raise SentinelOneSingularityXDRPluginException(err_msg)
        else:
            err_msg = (
                "HTTP Server Error"
                if (500 <= status_code <= 600)
                else "HTTP Error"
            )
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Received exit code"
                    f" {status_code}, "
                    f"{validation_msg + err_msg if is_validation else err_msg}"
                    f" while {logger_msg}."
                ),
                details=f"API response: {resp.text}",
            )
            raise SentinelOneSingularityXDRPluginException(err_msg)

    def get_configuration_parameters(self, configuration: Dict) -> Tuple:
        """Get configuration parameters.

        Args:
            configuration (Dict): Configuration dictionary.

        Returns:
            Tuple: Tuple containing Base URL, API Token, and Site Name.
        """
        return (
            configuration.get("base_url", "").strip().rstrip("/"),
            configuration.get("api_token"),
            configuration.get("site_name", "").strip(),
        )

    def get_auth_header(self, api_token: str) -> Dict:
        """Get the Authorization header for SentinelOne API.

        Args:
            api_token (str): API token for authentication.

        Returns:
            Dict: Authorization header dictionary.
        """
        return {"Authorization": f"ApiToken {api_token}"}

    def _add_field(
        self, fields_dict: dict, field_name: str, value
    ):
        """Add field to the extracted_fields dictionary.

        Empty dicts/lists are stored as None (MongoDB safety).
        Integers/floats (including 0) are always stored.

        Args:
            fields_dict (dict): Field dictionary to update.
            field_name (str): Field name to add.
            value: Field value to add.
        """
        if (
            isinstance(value, (dict, list)) and not value
        ):
            fields_dict[field_name] = None
            return

        if isinstance(value, (int, float)):
            fields_dict[field_name] = value
            return

        if value:
            fields_dict[field_name] = value

    def _extract_field_from_event(
        self,
        key: str,
        event: dict,
        default,
        transformation=None,
    ):
        """
        Extract field from event.

        Args:
            key (str): Key to fetch.
            event (dict): Event dictionary.
            default (str,None): Default value to set.
            transformation (str, None, optional): Transformation
                function to perform on the event value. Defaults to None.

        Returns:
            Any: Value of the key from event.
        """
        keys = key.split(".")
        while keys:
            k = keys.pop(0)
            if k not in event and default is not None:
                return default
            if k not in event:
                return default
            if not isinstance(event, dict):
                return default
            event = event.get(k)
        if transformation and transformation == "string":
            return str(event)
        if transformation:
            transformation_func = getattr(self, transformation)
            return transformation_func(event)
        return event

    def extract_entity_fields(
        self,
        event: dict,
        entity_field_mapping: Dict,
        entity_name: str,
    ) -> dict:
        """Extract required entity fields from the event payload.

        Args:
            event (dict): Event payload.
            entity_field_mapping (Dict): Mapping of entity fields to
                their corresponding keys in the event payload.

        Returns:
            dict: Dictionary containing the extracted entity fields.
        """
        extracted_fields = {}
        for field_name, field_value in entity_field_mapping.items():
            key = field_value.get("key")
            default = field_value.get("default")
            transformation = field_value.get("transformation")
            self._add_field(
                extracted_fields,
                field_name,
                self._extract_field_from_event(
                    key, event, default, transformation
                ),
            )
        if entity_name in ["endpoints", "identity"]:
            if tag_objects := extracted_fields.get("Tags", []):
                tags = []
                for tag_obj in tag_objects:
                    if tag_value := tag_obj.get("key_value"):
                        tags.append(tag_value)
                extracted_fields["Tags"] = tags
        return extracted_fields

    def _parse_datetime(
        self,
        datetime_str: str,
    ):
        """Parse datetime string into datetime object.

        Args:
            datetime_str (str): Datetime string to parse.

        Returns:
            datetime: Parsed datetime object.
        """
        try:
            return parser.parse(datetime_str)
        except Exception:
            return None

    def _parse_ids(self, raw_value) -> list:
        """Parse a raw ID value into a list of non-empty stripped strings.

        Handles both list values and comma-separated strings.

        Args:
            raw_value: A list or a comma-separated string of IDs.

        Returns:
            List[str]: List of non-empty stripped ID strings.
        """
        if isinstance(raw_value, list):
            return [str(a).strip() for a in raw_value if str(a).strip()]
        return [a.strip() for a in str(raw_value).split(",") if a.strip()]

    def _parse_tags(self, tags: Union[str, List[str]]) -> List[str]:
        """Parse tags into a list of non-empty stripped strings.

        Handles both list values and comma-separated strings.

        Args:
            tags: A list or a comma-separated string of tags.

        Returns:
            List[str]: List of non-empty stripped tag strings.
        """
        if isinstance(tags, list):
            return [str(t).strip() for t in tags if str(t).strip()]
        return [t.strip() for t in str(tags).split(",") if t.strip()]

    def _validate_tag_not_empty(self, value: str) -> bool:
        """Validate that no comma-separated part of a tag field is empty.

        Args:
            value (str): The tag field value to validate.

        Returns:
            bool: True if all parts are non-empty after stripping, else False.
        """
        for part in value.split(","):
            if not part.strip():
                return False
        return True

    def _validate_tag_string(self, field_name: str, value: str) -> bool:
        """Validate tag field length constraints.

        For 'Tag Key', checks the full value does not exceed 500 characters.
        For 'Tag Value', splits on commas and checks each part does not
        exceed 500 characters.

        Args:
            field_name (str): 'Tag Key' or 'Tag Value'.
            value (str): The field value to validate.

        Returns:
            bool: True if valid, False otherwise.
        """
        if field_name == "Tag Key":
            if isinstance(value, str) and len(value) > 500:
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: '{field_name}' must not"
                        f" exceed 500 characters. Provided value has"
                        f" {len(value)} characters."
                    ),
                )
                return False
        else:
            for part in value.split(","):
                if len(part.strip()) > 500:
                    self.logger.error(
                        message=(
                            f"{self.log_prefix}: '{field_name}' must not"
                            f" exceed 500 characters per tag. Tag"
                            f" '{part.strip()}' has {len(part.strip())}"
                            f" characters."
                        ),
                    )
                    return False
        return True

    def _validate_tag_no_colon(self, field_name: str, value: str) -> bool:
        """Validate that a tag field does not contain a colon character.

        For 'Tag Key', checks the full value. For 'Tag Value', splits on
        commas and checks each part.

        Args:
            field_name (str): 'Tag Key' or 'Tag Value'.
            value (str): The field value to validate.

        Returns:
            bool: True if valid, False otherwise.
        """
        if field_name == "Tag Key":
            if isinstance(value, str) and ":" in value:
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: '{field_name}' must not"
                        f" contain the character ':'."
                    ),
                )
                return False
        else:
            for part in value.split(","):
                if ":" in part.strip():
                    self.logger.error(
                        message=(
                            f"{self.log_prefix}: '{field_name}' must not"
                            f" contain the character ':'. Tag"
                            f" '{part.strip()}' contains ':'."
                        ),
                    )
                    return False
        return True

    def _validate_group_name(self, value: str) -> bool:
        """Validate that a group name does not contain angular brackets."""
        if "<" in value or ">" in value:
            self.logger.error(
                message=(
                    f"{self.log_prefix}: 'Create Group' must not"
                    f" contain angular brackets (< or >)."
                ),
            )
            return False
        return True

    def _batch_ids(
        self, ids: List[str]
    ) -> Generator[Tuple[List[str], int], None, None]:
        """Yield successive batches from a list of IDs with a batch number.

        Args:
            ids (List[str]): Full list of IDs to batch.

        Yields:
            Tuple[List[str], int]: (batch, batch_number) where batch_number
                starts at 1 and increments for each successive batch.
        """
        batch_number = 1
        for i in range(0, len(ids), BATCH_SIZE):
            yield ids[i: i + BATCH_SIZE], batch_number
            batch_number += 1

    def _validate_url(self, url: str) -> bool:
        """Validate the URL using parsing.

        Args:
            url (str): Given URL.

        Returns:
            bool: True or False { Valid or not Valid URL }.
        """
        parsed_url = urlparse(url)
        return parsed_url.scheme and parsed_url.netloc
