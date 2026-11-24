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

Palo Alto Networks Cortex XDR Plugin helper.
"""

import gzip
import json
import time
import traceback
from typing import Dict, List, NamedTuple, Tuple, Union

import requests
from netskope.common.utils import add_user_agent

from . import constants as CONST
from .exceptions import (
    CortexXDRPluginException,
    CortexXDRRequestRejectedException,
    MappingValidationError,
)


class Chunk(NamedTuple):
    """One request worth of serialized records.

    Attributes:
        records (List[str]): JSON lines of the request.
        indexes (List[int]): Indexes, in the pushed list, of the records
            of this request.
    """

    records: List[str]
    indexes: List[int]

    @property
    def start(self) -> int:
        """Index of the first record of this request.

        Records before it were sent by the earlier requests or skipped.
        """
        return self.indexes[0]


class SplitResult(NamedTuple):
    """Result of :func:`split_into_size`.

    Attributes:
        chunks (List[Chunk]): Requests to send.
        oversized (List[dict]): Records larger than the per record limit.
        failed (List): Records that could not be converted to JSON.
        skipped_indexes (List[int]): Indexes, in the pushed list, of the
            oversized and failed records.
    """

    chunks: List[Chunk]
    oversized: List[dict]
    failed: List
    skipped_indexes: List[int]

    @property
    def not_sent(self) -> List:
        """Return the records that can never be sent."""
        return self.oversized + self.failed


def is_soft_time_limit(error: BaseException) -> bool:
    """Return True for Celery's SoftTimeLimitExceeded.

    It must reach Cloud Exchange unchanged, so that the task is
    rescheduled instead of failing.

    Args:
        error (BaseException): Caught error.

    Returns:
        bool: True for SoftTimeLimitExceeded.
    """
    return type(error).__name__ == CONST.SOFT_TIME_LIMIT_ERROR_NAME


def is_json_format(configuration: dict) -> bool:
    """Return True when the JSON format is selected.

    Cloud Exchange 5.1.2 and older pass a boolean, where True means
    "transform the data". Newer versions pass the format name.

    Args:
        configuration (dict): Plugin configuration.

    Returns:
        bool: True for the JSON format.
    """
    transform_data = configuration.get(
        CONST.CONFIG_TRANSFORM_DATA, CONST.FORMAT_JSON
    )
    if isinstance(transform_data, bool):
        return not transform_data
    return str(transform_data).strip().lower() == CONST.FORMAT_JSON


def get_cortex_xdr_mappings(mappings: dict) -> dict:
    """Return the JSON taxonomy of the mapping.

    The mapping is received parsed while data is shared, and as the
    stored record with a ``jsonData`` string otherwise, so both are
    handled.

    Args:
        mappings (dict): Mapping received from Cloud Exchange.

    Returns:
        dict: Data type keyed JSON taxonomy.

    Raises:
        MappingValidationError: When the mapping can not be read.
    """
    resolved = mappings or {}
    try:
        if (
            CONST.MAPPING_TAXONOMY not in resolved
            and CONST.MAPPING_JSON_DATA in resolved
        ):
            resolved = json.loads(resolved[CONST.MAPPING_JSON_DATA])
        taxonomy = resolved[CONST.MAPPING_TAXONOMY][CONST.MAPPING_JSON]
    except (KeyError, TypeError, ValueError) as err:
        raise MappingValidationError(str(err)) from err
    if not isinstance(taxonomy, dict):
        raise MappingValidationError(CONST.MAPPING_RESOLUTION)
    return taxonomy


def get_nested_field_value(data: dict, field_path: str) -> Tuple:
    """Return the value of a dot notation path in a record.

    Args:
        data (dict): Record.
        field_path (str): Field path, for example ``host_info.device``.

    Returns:
        Tuple: ``(value, True)`` when the path exists, else
            ``(None, False)``.
    """
    current = data
    for part in field_path.split(CONST.NESTED_FIELD_SEPARATOR):
        if isinstance(current, dict) and part in current:
            current = current[part]
        else:
            return None, False
    return current, True


def serialize_record(record: dict) -> str:
    """Convert a record to one JSON line.

    Args:
        record (dict): Record.

    Returns:
        str: JSON line.
    """
    return json.dumps(record, ensure_ascii=False, default=str)


def split_into_size(records: List) -> SplitResult:
    """Split the records into requests of about 1 MB.

    Cortex XDR accepts up to 10 MiB per request and recommends 1 MiB, and
    rejects a record larger than 5 MB.

    Args:
        records (List): Records to send.

    Returns:
        SplitResult: The requests, and the records that can not be sent:
            oversized ones and ones that could not be converted to JSON.
    """
    chunks, oversized, failed, skipped_indexes = [], [], [], []
    current, current_indexes, current_size = [], [], 0
    separator_size = len(CONST.RECORD_SEPARATOR.encode(CONST.ENCODING))
    for index, record in enumerate(records):
        try:
            line = serialize_record(record)
        except (TypeError, ValueError):
            failed.append(record)
            skipped_indexes.append(index)
            continue
        size = len(line.encode(CONST.ENCODING))
        if size > CONST.MAX_RECORD_SIZE_IN_BYTES:
            oversized.append(record)
            skipped_indexes.append(index)
            continue
        if (
            current
            and current_size + separator_size + size
            > CONST.MAX_PAYLOAD_CHUNK_SIZE_IN_BYTES
        ):
            chunks.append(Chunk(current, current_indexes))
            current, current_indexes, current_size = [], [], 0
        current.append(line)
        current_indexes.append(index)
        current_size += size + separator_size
    if current:
        chunks.append(Chunk(current, current_indexes))
    return SplitResult(chunks, oversized, failed, skipped_indexes)


def gzip_compress(payload: str) -> bytes:
    """Gzip-compress a request body.

    Args:
        payload (str): Newline delimited JSON records.

    Returns:
        bytes: Compressed body.
    """
    return gzip.compress(payload.encode(CONST.ENCODING))


def build_validation_record(log_source_identifier: str) -> dict:
    """Build the record sent to verify the configuration.

    Args:
        log_source_identifier (str): Log Source Identifier; the field is
            left out when it is empty.

    Returns:
        dict: Validation record.
    """
    record = dict(CONST.VALIDATION_RECORD)
    record[CONST.VALIDATION_TIMESTAMP_FIELD] = int(time.time() * 1000)
    if log_source_identifier:
        record[CONST.LOG_SOURCE_IDENTIFIER_FIELD] = log_source_identifier
    return record


class CortexXDRPluginHelper:
    """Send requests to the Cortex XDR HTTP Log Collector."""

    def __init__(
        self,
        logger,
        log_prefix: str,
        plugin_name: str,
        plugin_version: str,
    ):
        """Initialize.

        Args:
            logger: Cloud Exchange logger.
            log_prefix (str): Log prefix.
            plugin_name (str): Plugin name.
            plugin_version (str): Plugin version.
        """
        self.logger = logger
        self.log_prefix = log_prefix
        self.plugin_name = plugin_name
        self.plugin_version = plugin_version

    def _log_error(
        self, message: str, resolution: str = None, details: str = None
    ):
        """Log an error with the log prefix.

        Args:
            message (str): Message, starting with "Error occurred while".
            resolution (str): Resolution, when the user can fix the cause.
            details (str): Details; defaults to the current traceback.
        """
        log_kwargs = {
            "message": CONST.LOG_MESSAGE_TEMPLATE.format(
                self.log_prefix, message
            ),
            "details": (
                details
                if details is not None
                else str(traceback.format_exc())
            ),
        }
        if resolution:
            log_kwargs["resolution"] = resolution
        self.logger.error(**log_kwargs)

    def _raise_error(
        self,
        message: str,
        resolution: str = None,
        details: str = None,
        exception_class: type = CortexXDRPluginException,
    ):
        """Log an error and raise it.

        Args:
            message (str): Message, starting with "Error occurred while".
            resolution (str): Resolution, when the user can fix the cause.
            details (str): Details; defaults to the current traceback.
            exception_class (type): Exception to raise.

        Raises:
            CortexXDRPluginException: Always, or the given subclass.
        """
        self._log_error(message, resolution, details)
        raise exception_class(message)

    def _add_user_agent(self, headers: Union[Dict, None] = None) -> Dict:
        """Add the User-Agent header.

        Args:
            headers (Dict): Request headers.

        Returns:
            Dict: Headers with the User-Agent.
        """
        if headers and CONST.HEADER_USER_AGENT in headers:
            return headers
        headers = add_user_agent(headers or {})
        ce_agent = headers.get(
            CONST.HEADER_USER_AGENT, CONST.DEFAULT_USER_AGENT
        )
        headers[CONST.HEADER_USER_AGENT] = CONST.USER_AGENT_TEMPLATE.format(
            ce_agent=ce_agent,
            module=CONST.MODULE_NAME.lower(),
            plugin=self.plugin_name.lower().replace(" ", "-"),
            version=f"v{self.plugin_version}",
        )
        return headers

    @staticmethod
    def _is_retryable(status_code: int) -> bool:
        """Return True for the status codes that are retried.

        Args:
            status_code (int): HTTP status code.

        Returns:
            bool: True for 429 and the 5xx codes other than 500.
        """
        return status_code == CONST.HTTP_TOO_MANY_REQUESTS or (
            CONST.SERVER_ERROR_RANGE[0]
            < status_code
            <= CONST.SERVER_ERROR_RANGE[1]
        )

    def _get_wait_time(
        self, response: requests.Response, logger_msg: str
    ) -> int:
        """Return the seconds to wait before the next retry.

        Args:
            response (requests.Response): Response to retry.
            logger_msg (str): Operation, for the log message.

        Returns:
            int: Seconds to wait.

        Raises:
            CortexXDRPluginException: When Retry-After is too long.
        """
        retry_after = response.headers.get(CONST.HEADER_RETRY_AFTER)
        try:
            wait_time = max(int(retry_after), 0)
        except (TypeError, ValueError):
            return CONST.DEFAULT_WAIT_TIME
        if wait_time > CONST.MAX_WAIT_TIME:
            self._raise_error(
                CONST.RETRY_AFTER_EXCEEDED_MESSAGE.format(
                    logger_msg=logger_msg, maximum=CONST.MAX_WAIT_TIME
                ),
                CONST.RETRY_EXCEEDED_RESOLUTION,
                details=CONST.API_RESPONSE_DETAILS.format(
                    response=response.text
                ),
            )
        return wait_time

    def parse_response(
        self,
        response: requests.Response,
        logger_msg: str,
    ):
        """Return the JSON body of a response.

        Args:
            response (requests.Response): Response.
            logger_msg (str): Operation, for the log message.

        Returns:
            Parsed JSON body.

        Raises:
            CortexXDRPluginException: When the body is not JSON.
        """
        details = CONST.API_RESPONSE_DETAILS.format(response=response.text)
        try:
            return response.json()
        except ValueError:
            self._raise_error(
                CONST.INVALID_RESPONSE_MESSAGE.format(logger_msg=logger_msg),
                CONST.INVALID_RESPONSE_RESOLUTION,
                details=details,
            )
        except Exception:
            self._raise_error(
                CONST.UNEXPECTED_ERROR_MESSAGE.format(logger_msg=logger_msg),
                CONST.UNEXPECTED_ERROR_RESOLUTION,
            )

    @staticmethod
    def _get_response_error(response: requests.Response) -> str:
        """Return the error text of a Cortex XDR response body.

        Args:
            response (requests.Response): Response.

        Returns:
            str: The "error" value of the body, or an empty string.
        """
        try:
            body = response.json()
        except Exception:
            return ""
        if isinstance(body, dict):
            error = body.get(CONST.RESPONSE_ERROR_KEY)
            if error not in CONST.RESPONSE_SUCCESS_VALUES and error:
                return str(error)
        return ""

    @staticmethod
    def _get_resolution(response_error: str, default: str) -> str:
        """Return the resolution matching the error text of Cortex XDR.

        Args:
            response_error (str): The "error" value of the response body.
            default (str): Resolution used when no keyword matches.

        Returns:
            str: Resolution.
        """
        lowered = response_error.lower()
        for keyword, resolution in CONST.RESPONSE_ERROR_RESOLUTIONS:
            if keyword in lowered:
                return resolution
        return default

    def handle_error(
        self,
        response: requests.Response,
        logger_msg: str,
    ):
        """Return the body of a successful response or raise the error.

        Args:
            response (requests.Response): Response.
            logger_msg (str): Operation, for the log message.

        Returns:
            Parsed JSON body.

        Raises:
            CortexXDRRequestRejectedException: When Cortex XDR rejects
                the content of the request (400, 413, or a success code
                with an error in the body).
            CortexXDRPluginException: For any other error response.
        """
        status_code = response.status_code
        details = CONST.API_RESPONSE_DETAILS.format(response=response.text)
        if status_code in CONST.HTTP_SUCCESS_CODES:
            body = self.parse_response(response, logger_msg)
            error = self._get_response_error(response)
            if error:
                self._raise_error(
                    CONST.REJECTED_RESPONSE_MESSAGE.format(
                        logger_msg=logger_msg, error=error
                    ),
                    self._get_resolution(
                        error, CONST.REJECTED_RESPONSE_RESOLUTION
                    ),
                    details=details,
                    exception_class=CortexXDRRequestRejectedException,
                )
            return body
        if status_code == CONST.HTTP_NO_CONTENT:
            return {}

        if status_code in CONST.STATUS_CODE_ERRORS:
            error, resolution = CONST.STATUS_CODE_ERRORS[status_code]
        elif (
            CONST.SERVER_ERROR_RANGE[0]
            <= status_code
            <= CONST.SERVER_ERROR_RANGE[1]
        ):
            error = CONST.SERVER_ERROR_MESSAGE.format(status_code=status_code)
            resolution = CONST.STATUS_CODE_RESOLUTION
        else:
            error = CONST.CLIENT_ERROR_MESSAGE.format(status_code=status_code)
            resolution = CONST.STATUS_CODE_RESOLUTION
        response_error = self._get_response_error(response)
        if response_error:
            error = CONST.API_ERROR_CAUSE_TEMPLATE.format(
                error, response_error
            )
            resolution = self._get_resolution(response_error, resolution)
        self._raise_error(
            CONST.API_ERROR_MESSAGE.format(logger_msg=logger_msg, error=error),
            resolution,
            details=details,
            exception_class=(
                CortexXDRRequestRejectedException
                if status_code in CONST.HTTP_REJECTED_CODES
                else CortexXDRPluginException
            ),
        )

    def api_helper(
        self,
        logger_msg: str,
        url: str,
        method: str,
        data=None,
        headers: Dict = None,
        verify: bool = True,
        proxies: Dict = None,
        is_handle_error_required: bool = True,
        is_validation: bool = False,
    ):
        """Send a request to Cortex XDR, retrying 429 and 5xx responses.

        A validation request is sent once, so that saving the
        configuration does not wait for the retries.

        Args:
            logger_msg (str): Operation, for the log messages.
            url (str): Endpoint.
            method (str): HTTP method.
            data: Request body.
            headers (Dict): Request headers.
            verify (bool): Verify the SSL certificate.
            proxies (Dict): Proxies.
            is_handle_error_required (bool): Return the parsed body when
                True, the raw response otherwise.
            is_validation (bool): Whether the call validates the
                configuration.

        Returns:
            Parsed JSON body, or the response.

        Raises:
            CortexXDRPluginException: When the request fails.
        """
        try:
            headers = self._add_user_agent(headers)
            self.logger.debug(
                CONST.LOG_MESSAGE_TEMPLATE.format(
                    self.log_prefix,
                    CONST.API_REQUEST_MESSAGE.format(
                        logger_msg=logger_msg, method=method, url=url
                    ),
                )
            )
            max_retries = 1 if is_validation else CONST.MAX_RETRY_COUNT
            for retry_counter in range(max_retries):
                response = requests.request(
                    method=method,
                    url=url,
                    data=data,
                    headers=headers,
                    verify=verify,
                    proxies=proxies,
                )
                status_code = response.status_code
                self.logger.debug(
                    CONST.LOG_MESSAGE_TEMPLATE.format(
                        self.log_prefix,
                        CONST.API_RESPONSE_MESSAGE.format(
                            logger_msg=logger_msg, status_code=status_code
                        ),
                    )
                )
                if not is_validation and self._is_retryable(status_code):
                    if retry_counter == max_retries - 1:
                        self._raise_error(
                            CONST.RETRY_EXCEEDED_MESSAGE.format(
                                logger_msg=logger_msg,
                                status_code=status_code,
                            ),
                            CONST.RETRY_EXCEEDED_RESOLUTION,
                            details=CONST.API_RESPONSE_DETAILS.format(
                                response=response.text
                            ),
                        )
                    wait_time = self._get_wait_time(response, logger_msg)
                    self.logger.info(
                        CONST.LOG_MESSAGE_TEMPLATE.format(
                            self.log_prefix,
                            CONST.RETRY_MESSAGE.format(
                                status_code=status_code,
                                logger_msg=logger_msg,
                                wait_time=wait_time,
                                remaining=max_retries - 1 - retry_counter,
                            ),
                        )
                    )
                    time.sleep(wait_time)
                    continue
                return (
                    self.handle_error(response, logger_msg)
                    if is_handle_error_required
                    else response
                )
        except CortexXDRPluginException:
            raise
        except requests.exceptions.ReadTimeout:
            self._raise_error(
                CONST.READ_TIMEOUT_MESSAGE.format(logger_msg=logger_msg),
                CONST.READ_TIMEOUT_RESOLUTION,
            )
        except requests.exceptions.ProxyError:
            self._raise_error(
                CONST.PROXY_ERROR_MESSAGE.format(logger_msg=logger_msg),
                CONST.PROXY_ERROR_RESOLUTION,
            )
        except requests.exceptions.SSLError:
            self._raise_error(
                CONST.SSL_ERROR_MESSAGE.format(logger_msg=logger_msg),
                CONST.SSL_ERROR_RESOLUTION,
            )
        except requests.exceptions.ConnectionError:
            self._raise_error(
                CONST.CONNECTION_ERROR_MESSAGE.format(logger_msg=logger_msg),
                CONST.CONNECTION_ERROR_RESOLUTION,
            )
        except requests.HTTPError:
            self._raise_error(
                CONST.HTTP_ERROR_MESSAGE.format(logger_msg=logger_msg),
                CONST.STATUS_CODE_RESOLUTION,
            )
        except Exception as err:
            if is_soft_time_limit(err):
                raise
            self._raise_error(
                CONST.UNEXPECTED_ERROR_MESSAGE.format(logger_msg=logger_msg),
                CONST.UNEXPECTED_ERROR_RESOLUTION,
            )
