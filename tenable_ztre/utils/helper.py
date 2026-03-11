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

CRE Tenable Plugin helper module.
"""

import time
import traceback
from typing import Any, Dict, Tuple, Union

import requests
from netskope.common.utils import add_user_agent
from requests.models import Response

from .constants import (
    ASSET_FIELD_MAPPING,
    DEFAULT_SLEEP_TIME,
    EXPORT_STATUS_CANCELLED,
    EXPORT_STATUS_ERROR,
    EXPORT_STATUS_FINISHED,
    FINDINGS_FIELD_MAPPING,
    MAX_RETRIES,
    MODULE_NAME,
    NO_MORE_RETRIES_ERROR_MSG,
    PLATFORM_NAME,
    RETRY_ERROR_MSG,
    STATUS_CHECK_SLEEP_TIME,
    BASE_URL,
    TAGS_CATEGORIES_ENDPOINT,
    TAGS_VALUES_ENDPOINT,
    TAGS_ASSIGNMENTS_ENDPOINT,
    TAGS_API_LIMIT,
)
from .exceptions import (
    TenablePluginException,
)


class TenableHelper:
    def __init__(
        self,
        logger,
        log_prefix: str,
        plugin_name: str,
        plugin_version: str,
        parser: any,
    ):
        """TenableHelper initializer.

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
        is_validation: bool = False,
        is_handle_error_required=True,
    ):
        """
        Make API call to Tenable.

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
            is_validation (bool, optional): Is validation. Defaults to False.
            is_handle_error_required (bool, optional): Is handle error
                required. Defaults to True.

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
                        raise TenablePluginException(
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
                    time.sleep(retry_after)
                else:
                    return (
                        self.handle_error(
                            response=response,
                            logger_msg=logger_msg,
                            is_validation=is_validation,
                        ) if is_handle_error_required else response
                    )
        except TenablePluginException:
            raise
        except requests.exceptions.ReadTimeout as error:
            err_msg = f"Read Timeout error occurred while {logger_msg}."
            if is_validation:
                err_msg = "Read Timeout error occurred."

            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {error}",
                details=traceback.format_exc(),
                resolution=(
                    "Please check if your Tenable platform server"
                    " is reachable."
                ),
            )
            raise TenablePluginException(err_msg)
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
            raise TenablePluginException(err_msg)
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
                    "Please check if your Tenable platform server"
                    " is reachable."
                ),
            )
            raise TenablePluginException(err_msg)
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
            raise TenablePluginException(err_msg)
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
            raise TenablePluginException(err_msg)

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
            TenablePluginException: When the response code
            is not in 200 range.
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
                "Ensure that the configuration parameters or "
                "action parameters are valid."
            ),
            401: (
                "Ensure that the Access Key and Secret Key "
                "provided in the configuration parameters "
                "are valid."
            ),
            403: (
                "Ensure that the user has sufficient permissions "
                "to access the Assets, Findings and Tags."
            ),
            404: (
                "Ensure that the Tenable API Base URL is valid."
            ),
        }
        if is_validation:
            error_dict = {
                400: (
                    "Received exit code 400, Bad Request, "
                    "Verify the configuration parameters or "
                    "action parameters are valid."
                ),
                401: (
                    "Received exit code 401, Unauthorized, "
                    "Verify Access Key and Secret Key provided in "
                    "the configuration parameters."
                ),
                403: (
                    "Received exit code 403, Forbidden, "
                    "Verify the user has sufficient permissions "
                    "to access the Assets, Findings and Tags."
                ),
                404: (
                    "Received exit code 404, Resource not found, "
                    "Verify the resource you are trying to access is "
                    "valid."
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
                raise TenablePluginException(err_msg)
            else:
                err_msg = err_msg + " while " + logger_msg + "."
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg}",
                    details=f"API response: {response.text}",
                    resolution=resolution,
                )
                raise TenablePluginException(err_msg)

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

    def _get_retry_after(self, headers) -> int:
        """
        Get the retry after value from the headers.

        Args:
            headers (Dict): Headers.

        Returns:
            int: Retry after value.
        """
        return int(headers.get("retry-after", DEFAULT_SLEEP_TIME))

    def get_configuration_parameters(
        self, configuration: Dict
    ) -> Tuple[str, str, str, int]:
        """
        Get the configuration parameters.

        Args:
            configuration (Dict): Configuration.

        Returns:
            Tuple[str, str, str, int]: Access Key, Secret Key,
                Initial Range.
        """
        access_key = configuration.get("access_key")
        secret_key = configuration.get("secret_key")
        initial_range = configuration.get("initial_range")
        no_of_retries = configuration.get("no_of_retries")
        return access_key, secret_key, initial_range, no_of_retries

    def get_auth_headers(
        self,
        access_key: str,
        secret_key: str
    ) -> Dict[str, str]:
        """Get the headers for the API call.

        Args:
            access_key (str): Access key.
            secret_key (str): Secret key.

        Returns:
            Dict[str, str]: Headers.
        """
        return {
            "accept": "application/json",
            "content-type": "application/json",
            "X-ApiKeys": f"accessKey={access_key}; secretKey={secret_key};"
        }

    def initiate_export(
        self,
        endpoint: str,
        body: Dict,
        headers: Dict,
        entity_type: str,
        verify: Any,
        proxies: Any,
        is_validation: bool = False,
    ) -> str:
        """Initiate export request to Tenable.

        Args:
            endpoint (str): Export endpoint URL.
            body (Dict): Request body.
            headers (Dict): Headers.
            entity_type (str): Entity type (assets/findings).
            verify (Any): Verify.
            proxies (Any): Proxies.
            is_validation (bool): Whether this is for validation.

        Returns:
            str: Export UUID.
        """
        logger_msg = f"initiating {entity_type} export"

        response = self.api_helper(
            logger_msg=logger_msg,
            url=endpoint,
            method="POST",
            headers=headers,
            json=body,
            verify=verify,
            proxies=proxies,
            is_validation=is_validation,
        )

        export_uuid = response.get("export_uuid")
        if not export_uuid:
            err_msg = (
                f"Unable to get export_uuid from {entity_type} "
                "export response."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=f"API response: {response}",
            )
            raise TenablePluginException(err_msg)

        time.sleep(1)
        self.logger.debug(
            f"{self.log_prefix}: Successfully initiated {entity_type} "
            f"export with UUID: {export_uuid}."
        )
        return export_uuid

    def check_export_status(
        self,
        status_endpoint: str,
        headers: Dict,
        export_uuid: str,
        entity_type: str,
        no_of_retries: int,
        verify: Any,
        proxies: Any,
        is_validation: bool = False,
    ) -> Dict:
        """Check export status and wait until it's finished.

        Args:
            status_endpoint (str): Status endpoint URL.
            headers (Dict): Headers.
            export_uuid (str): Export UUID.
            entity_type (str): Entity type (assets/findings).
            no_of_retries (int): Number of retries.
            verify (Any): Verify.
            proxies (Any): Proxies.
            is_validation (bool): Whether this is for validation.

        Returns:
            Dict: Status response containing chunks_available.
        """
        logger_msg = f"checking {entity_type} export status"

        for retry_count in range(no_of_retries + 1):
            response = self.api_helper(
                logger_msg=logger_msg,
                url=status_endpoint,
                method="GET",
                headers=headers,
                verify=verify,
                proxies=proxies,
                is_validation=is_validation,
            )

            status = response.get("status")
            if not status:
                err_msg = (
                    f"No status field in export status response for "
                    f"{entity_type} (UUID: {export_uuid})."
                )
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg}",
                    details=f"API response: {str(response)}",
                )
                raise TenablePluginException(err_msg)

            self.logger.debug(
                f"{self.log_prefix}: Export status for {entity_type} "
                f"(UUID: {export_uuid}): {status}."
            )

            if status == EXPORT_STATUS_FINISHED:
                chunks_available = response.get("chunks_available", [])
                if not chunks_available:
                    self.logger.info(
                        f"{self.log_prefix}: No chunks available for "
                        f"{entity_type} export (UUID: {export_uuid})."
                    )
                return response

            elif status == EXPORT_STATUS_CANCELLED:
                err_msg = (
                    f"Export request for {entity_type} was cancelled "
                    f"(UUID: {export_uuid})."
                )
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg}",
                )
                raise TenablePluginException(err_msg)

            elif status == EXPORT_STATUS_ERROR:
                err_msg = (
                    f"Error occurred while processing {entity_type} "
                    f"export request (UUID: {export_uuid})."
                )
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg}",
                )
                raise TenablePluginException(err_msg)

            if retry_count < no_of_retries:
                retry_remaining = no_of_retries - retry_count
                self.logger.info(
                    f"{self.log_prefix}: Export status is {status}. "
                    f"Waiting {STATUS_CHECK_SLEEP_TIME} seconds before "
                    f"checking again. {retry_remaining} retries remaining."
                )
                time.sleep(STATUS_CHECK_SLEEP_TIME)

        err_msg = (
            f"Export status check timed out for {entity_type} "
            f"(UUID: {export_uuid}). Max retries exceeded."
        )
        self.logger.error(
            message=f"{self.log_prefix}: {err_msg}",
        )
        raise TenablePluginException(err_msg)

    def fetch_chunks(
        self,
        chunk_endpoint_template: str,
        headers: Dict,
        export_uuid: str,
        chunk_ids: list,
        entity_type: str,
        verify: Any,
        proxies: Any,
        is_validation: bool = False,
    ) -> list:
        """Fetch data from all chunks.

        Args:
            chunk_endpoint_template (str): Chunk endpoint template.
            headers (Dict): Headers.
            export_uuid (str): Export UUID.
            chunk_ids (list): List of chunk IDs.
            entity_type (str): Entity type (assets/findings).
            verify (Any): Verify.
            proxies (Any): Proxies.
            is_validation (bool): Whether this is for validation.

        Returns:
            list: List of records from all chunks.
        """
        all_records = []
        total_skipped_count = 0
        entity_field_mapping = FINDINGS_FIELD_MAPPING
        id_field = "finding_id"
        if entity_type == "assets":
            entity_field_mapping = ASSET_FIELD_MAPPING
            id_field = "id"

        total_chunks = len(chunk_ids)
        self.logger.debug(
            f"{self.log_prefix}: Fetching {total_chunks} chunk(s) "
            f"for {entity_type}. (Export UUID: {export_uuid})."
        )

        for idx, chunk_id in enumerate(chunk_ids, start=1):
            chunk_endpoint = chunk_endpoint_template.format(
                base_url=BASE_URL,
                export_uuid=export_uuid,
                chunk_id=chunk_id
            )
            logger_msg = (
                f"fetching {entity_type} chunk {idx} "
                f"(Chunk ID: {chunk_id})"
            )

            try:
                response = self.api_helper(
                    logger_msg=logger_msg,
                    url=chunk_endpoint,
                    method="GET",
                    headers=headers,
                    verify=verify,
                    proxies=proxies,
                    is_validation=is_validation,
                )
                if is_validation:
                    return []

                if isinstance(response, list):
                    page_count = 0
                    page_skipped_count = 0
                    for record in response:
                        try:
                            record_id = record.get(id_field)
                            if not record_id:
                                page_skipped_count += 1
                                continue

                            extracted_fields = self.parser.extract_entity_fields(
                                event=record,
                                entity_field_mapping=entity_field_mapping,
                                entity=entity_type,
                            )
                            if extracted_fields:
                                all_records.append(extracted_fields)
                                page_count += 1
                            else:
                                page_skipped_count += 1
                        except Exception as exp:
                            err_msg = (
                                "Unable to extract fields from "
                                f"{entity_type} record from chunk {idx}."
                            )
                            self.logger.error(
                                message=(
                                    f"{self.log_prefix}: {err_msg} "
                                    f"Error: {exp}."
                                ),
                                details=traceback.format_exc(),
                            )
                            page_skipped_count += 1
                    if page_skipped_count > 0:
                        self.logger.debug(
                            f"{self.log_prefix}: Skipped "
                            f"{page_skipped_count} "
                            f"{entity_type} record(s) in chunk {idx}."
                        )
                    self.logger.info(
                        f"{self.log_prefix}: Successfully fetched "
                        f"{page_count} {entity_type} record(s) from "
                        f"chunk {idx}. Total records fetched: "
                        f"{len(all_records)}"
                    )
                    total_skipped_count += page_skipped_count
                else:
                    self.logger.error(
                        f"{self.log_prefix}: Unexpected response format "
                        f"for chunk {idx}. Expected list."
                    )
            except Exception as exp:
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: Unexpected error occurred "
                        f"while fetching {entity_type} chunk {idx} "
                        f"(Chunk ID: {chunk_id}). "
                        f"Error: {exp}"
                    ),
                    details=traceback.format_exc(),
                )
                if is_validation:
                    raise

        logger_msg = (
            "Successfully fetched total "
            f"{len(all_records)} {entity_type} record(s) from "
            f"{total_chunks} chunk(s) from {PLATFORM_NAME} platform"
        )

        if total_skipped_count > 0:
            logger_msg += (
                f" and skipped {total_skipped_count} "
                f"{entity_type} record(s) because they either do not "
                f"have an '{entity_type.capitalize()} ID' "
                "or fields could not be extracted from the asset record"
            )

        self.logger.info(f"{self.log_prefix}: {logger_msg}.")
        return all_records

    def get_all_categories(
        self,
        verify: Any,
        proxies: Any,
        headers: dict
    ) -> list[dict]:
        """Get all tag categories from Tenable.

        Args:
            verify (Any): Verify.
            proxies (Any): Proxies.
            headers (dict): API Headers.

        Returns:
            list: List of tag categories.
        """
        categories = []
        offset = 0

        logger_msg = (
            "fetching tag categories"
        )
        while True:
            endpoint = TAGS_CATEGORIES_ENDPOINT.format(base_url=BASE_URL)
            params = {
                "limit": TAGS_API_LIMIT,
                "offset": offset,
                "sort": "name:asc"
            }

            response = self.api_helper(
                url=endpoint,
                method="GET",
                params=params,
                headers=headers,
                verify=verify,
                proxies=proxies,
                logger_msg=logger_msg
            )

            if not response or not isinstance(response, dict):
                break

            page_categories = response.get("categories", [])
            if not page_categories:
                break

            categories.extend(page_categories)

            if len(page_categories) < TAGS_API_LIMIT:
                break

            offset += TAGS_API_LIMIT

        return categories

    def get_all_tags(
        self,
        verify: Any,
        proxies: Any,
        headers: dict
    ) -> list[dict]:
        """Get all tag values from Tenable.

        Args:
            verify (Any): Verify.
            proxies (Any): Proxies.
            headers (dict): API Headers.

        Returns:
            list: List of tag values.
        """
        tags = []
        offset = 0

        logger_msg = (
            "fetching all tags"
        )
        while True:
            endpoint = TAGS_VALUES_ENDPOINT.format(base_url=BASE_URL)
            params = {
                "limit": TAGS_API_LIMIT,
                "offset": offset
            }

            response = self.api_helper(
                url=endpoint,
                method="GET",
                params=params,
                headers=headers,
                verify=verify,
                proxies=proxies,
                logger_msg=logger_msg
            )

            if not response or not isinstance(response, dict):
                break

            page_tags = response.get("values", [])
            if not page_tags:
                break

            tags.extend(page_tags)

            if len(page_tags) < TAGS_API_LIMIT:
                break

            offset += TAGS_API_LIMIT

        return tags

    def create_tag_value(
        self,
        category_name: str,
        tag_value: str,
        verify: Any,
        proxies: Any,
        headers: dict
    ) -> dict:
        """Create a new tag value in Tenable.

        Args:
            category_name (str): Name of the category.
            tag_value (str): Value of the tag.
            verify (Any): Verify.
            proxies (Any): Proxies.
            headers (dict): API Headers.

        Returns:
            dict: Created tag response.
        """
        endpoint = TAGS_VALUES_ENDPOINT.format(base_url=BASE_URL)
        body = {
            "category_name": category_name,
            "value": tag_value
        }

        logger_msg = (
            f"creating a tag '{tag_value}' "
            f"in category '{category_name}'"
        )
        return self.api_helper(
            url=endpoint,
            method="POST",
            json=body,
            headers=headers,
            verify=verify,
            proxies=proxies,
            logger_msg=logger_msg
        )

    def assign_remove_tags(
        self,
        action: str,
        asset_uuids: list,
        tag_uuids: list,
        headers: dict,
        verify: Any,
        proxies: Any,
        logger_msg: str
    ) -> dict:
        """Assign or remove tags from assets.

        Args:
            action (str): 'add' or 'remove'.
            asset_uuids (list): List of asset UUIDs.
            tag_uuids (list): List of tag UUIDs.
            headers (dict): API Headers.
            verify (Any): Verify.
            proxies (Any): Proxies.
            logger_msg (str): Logger message.

        Returns:
            dict: API response.
        """
        endpoint = TAGS_ASSIGNMENTS_ENDPOINT.format(base_url=BASE_URL)
        body = {
            "action": action,
            "assets": asset_uuids,
            "tags": tag_uuids
        }

        return self.api_helper(
            logger_msg=logger_msg,
            url=endpoint,
            method="POST",
            json=body,
            headers=headers,
            verify=verify,
            proxies=proxies
        )
