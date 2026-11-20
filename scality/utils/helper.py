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


Scality Plugin Helper.
"""

import gzip
import json
import os
import sys
import threading
import traceback
import uuid
from datetime import datetime
from typing import Any, Dict, Iterable, NamedTuple, NoReturn, Optional, Tuple

from botocore.exceptions import (
    ClientError,
    ConnectTimeoutError,
    EndpointConnectionError,
    ProxyConnectionError,
    ReadTimeoutError,
    SSLError,
)
from botocore.exceptions import ConnectionError as BotoConnectionError
from netskope.common.utils import add_user_agent

from . import constants as CONST
from .exceptions import ScalityException

class ScalityConfig(NamedTuple):
    """The configuration parameters of the plugin, read null-safe.

    Attributes:
        endpoint_url: Scality endpoint URL, without a trailing slash.
        access_key: Access Key of the Scality user.
        secret_access_key: Secret Access Key, never stripped or logged.
        bucket_name: Name of the target bucket.
    """

    endpoint_url: Any
    access_key: Any
    secret_access_key: Any
    bucket_name: Any

    def __repr__(self) -> str:
        """Describe the configuration without its credentials.

        A named tuple prints every field, so logging one by accident
        would write the Secret Access Key to the log.

        Returns:
            str: The representation with the credentials masked.
        """
        return (
            f"ScalityConfig(endpoint_url={self.endpoint_url!r}, "
            f"access_key={CONST.MASK!r}, secret_access_key={CONST.MASK!r}, "
            f"bucket_name={self.bucket_name!r})"
        )


class SerializeResult(NamedTuple):
    """Counts returned by :func:`serialize_webtx_records`.

    Attributes:
        written (int): Records written to the object file.
        skipped (int): Empty or unsupported records that were skipped.
        failed (int): Records that could not be serialized.
    """

    written: int
    skipped: int
    failed: int


def _describe_client_error(error) -> Tuple[str, Optional[str]]:
    """Describe a botocore ``ClientError``.

    Args:
        error (ClientError): The error raised by boto3.

    Returns:
        Tuple[str, Optional[str]]: The cause to log and the matching
            resolution, or None when the error code is not recognized.
    """
    response = getattr(error, "response", None) or {}
    details = response.get("Error", {}) if isinstance(response, dict) else {}
    cause = details.get("Message") or str(error)
    code = str(details.get("Code", ""))
    if code in CONST.CREDENTIAL_ERROR_CODES:
        return cause, CONST.CREDENTIALS_RESOLUTION
    if code in CONST.PERMISSION_ERROR_CODES:
        return cause, CONST.PERMISSION_RESOLUTION
    if code in CONST.BUCKET_ERROR_CODES:
        return cause, CONST.BUCKET_RESOLUTION
    return cause, None


def describe_boto_error(error) -> Tuple[str, Optional[str]]:
    """Describe what a boto3 error means for the plugin user.

    The same call can fail because the endpoint URL cannot be parsed or
    does not resolve, because the proxy refuses the connection or
    because the credentials are wrong, and each of those needs a
    different resolution.

    Args:
        error (BaseException): The error raised by boto3 or botocore.

    Returns:
        Tuple[str, Optional[str]]: The cause to log and the matching
            resolution, or None when the error says nothing specific
            and the caller's own resolution should be used.
    """
    if isinstance(error, ProxyConnectionError):
        return str(error), CONST.PROXY_RESOLUTION
    if isinstance(error, SSLError):
        return str(error), CONST.SSL_RESOLUTION
    if isinstance(error, ReadTimeoutError):
        return f"Read timed out. {error}", CONST.TIMEOUT_RESOLUTION
    if isinstance(error, ConnectTimeoutError):
        return f"Connection timed out. {error}", CONST.TIMEOUT_RESOLUTION
    if isinstance(error, EndpointConnectionError):
        return str(error), CONST.ENDPOINT_RESOLUTION
    if isinstance(error, ClientError):
        return _describe_client_error(error)
    if isinstance(error, BotoConnectionError):
        return str(error), CONST.ENDPOINT_RESOLUTION
    if isinstance(error, ValueError) and "endpoint" in str(error).lower():
        # boto3 rejects an endpoint URL it cannot parse with
        # ``ValueError: Invalid endpoint: <url>``.
        return str(error), CONST.ENDPOINT_RESOLUTION
    return str(error), None


def build_error_message(action: str, cause: str = "") -> str:
    """Build an error message following the plugin logging contract.

    Args:
        action (str): What was being done, e.g. ``"pushing log(s)"``.
        cause (str): Optional specific reason.

    Returns:
        str: ``Error occurred while <action>. <cause>``.
    """
    message = f"{CONST.ERROR_MESSAGE_LEAD} {action}."
    if cause:
        message = f"{message} {cause}"
    return message


def log_error(
    logger,
    log_prefix: str,
    action: str,
    resolution: str,
    cause: str = "",
    details: Optional[str] = None,
) -> str:
    """Log an error following the plugin logging contract.

    Every message starts with ``Error occurred while`` and every log
    carries a resolution starting with ``Ensure that``.

    Args:
        logger: Cloud Exchange logger object.
        log_prefix (str): Log prefix of the plugin configuration.
        action (str): What was being done.
        resolution (str): Resolution starting with ``Ensure that``.
        cause (str): Optional specific reason.
        details (Optional[str]): Error details. Defaults to the current
            traceback when an exception is being handled, else the
            message itself.

    Returns:
        str: The logged message without the log prefix.
    """
    message = build_error_message(action, cause)
    if details is None:
        details = traceback.format_exc() if sys.exc_info()[0] else message
    logger.error(
        message=f"{log_prefix}: {message}",
        details=details,
        resolution=resolution,
    )
    return message


def log_and_raise(
    logger,
    log_prefix: str,
    action: str,
    resolution: str,
    cause: str = "",
    details: Optional[str] = None,
) -> NoReturn:
    """Log an error and raise ``ScalityException`` with its message.

    Args:
        logger: Cloud Exchange logger object.
        log_prefix (str): Log prefix of the plugin configuration.
        action (str): What was being done.
        resolution (str): Resolution starting with ``Ensure that``.
        cause (str): Optional specific reason.
        details (Optional[str]): Error details (see :func:`log_error`).

    Raises:
        ScalityException: Always.
    """
    raise ScalityException(
        log_error(logger, log_prefix, action, resolution, cause, details)
    )


def get_mappings(mappings: Dict, data_type: str) -> Dict:
    """Return the subtype keyed mapping dict for the given data type.

    Args:
        mappings (Dict): Full mappings dict parsed from mappings.json.
        data_type (str): Data type - ``alerts``, ``events`` or
            ``webtx``.

    Returns:
        Dict: Subtype keyed mapping dict for the given data type.
    """
    return mappings[CONST.TAXONOMY_KEY][CONST.JSON_FORMAT][data_type]


def get_nested_field_value(data: Dict, field_path: str) -> Tuple:
    """Extract a value from a nested dict using a dot notation path.

    Args:
        data (Dict): The data dictionary.
        field_path (str): Dot separated field path, for example
            ``host_info.device_make``.

    Returns:
        Tuple: ``(value, True)`` when the path resolves, else
            ``(None, False)``.
    """
    current = data
    for part in field_path.split("."):
        if isinstance(current, dict) and part in current:
            current = current[part]
        else:
            return None, False
    return current, True


def map_json_data(mappings, data: Dict) -> Dict:
    """Filter raw Netskope data to the fields listed in the mapping.

    Supports flat keys as well as dot notation nested field paths.

    Args:
        mappings: List of field names to retain, or ``[]`` to keep
            every field.
        data (Dict): Raw record received from Netskope.

    Returns:
        Dict: Record containing only the mapped fields, or the record
            as received when the mapping is empty.
    """
    if mappings == [] or not data:
        return data

    mapped_dict = {}
    data_keys = data.keys()
    for key in mappings:
        if key in data_keys:
            mapped_dict[key] = data[key]
        else:
            value, field_exist = get_nested_field_value(data, key)
            if field_exist:
                mapped_dict[key] = value
    return mapped_dict


def serialize_webtx_records(
    records: Iterable[Any], fileobj
) -> SerializeResult:
    """Write WebTx records into a gzip file object.

    * ``dict`` records become one compact JSON line each and ``str``
      records become one line each, all in one gzip member.
    * Empty or blank records and unsupported types are skipped. A
      ``dict`` that cannot be converted to JSON is counted as failed.

    Args:
        records (Iterable[Any]): Records received by ``push``.
        fileobj: Binary file object opened for writing. It is not
            closed by this function.

    Returns:
        SerializeResult: Counts of written, skipped and failed records.
    """
    written = skipped = failed = 0
    member = None
    for record in records:
        if isinstance(record, dict):
            if not record:
                skipped += 1
                continue
            try:
                line = json.dumps(
                    record,
                    separators=CONST.JSON_SEPARATORS,
                    default=str,
                    ensure_ascii=False,
                )
            except (TypeError, ValueError):
                failed += 1
                continue
        elif isinstance(record, str):
            if not record.strip():
                skipped += 1
                continue
            line = record[:-1] if record.endswith("\n") else record
        else:
            skipped += 1
            continue
        if member is None:
            member = gzip.GzipFile(filename="", fileobj=fileobj, mode="wb")
        member.write(f"{line}\n".encode(CONST.TEXT_ENCODING))
        written += 1
    if member is not None:
        member.close()
    return SerializeResult(written, skipped, failed)


def build_object_key(
    data_type: str,
    subtype: str,
    now: Optional[datetime] = None,
    thread_id: Optional[int] = None,
) -> str:
    """Build the object key of a file pushed to the Scality bucket.

    The file name is ``<epoch>_<thread_id>_<uuid>``. The random uuid
    keeps two files pushed in the same second from overwriting each
    other. The partition folders use the local time of the
    host, like the other S3 style plugins.

    Args:
        data_type (str): ``alerts``, ``events`` or ``webtx``.
        subtype (str): Feed name of the pushed logs.
        now (Optional[datetime]): Time to use. Defaults to the local
            time of the host.
        thread_id (Optional[int]): Thread id. Defaults to the current
            thread id.

    Returns:
        str: ``<data_type>/feedname=<subtype>/year=Y/month=M/day=D/
            hour=H/<epoch>_<thread_id>_<uuid><extension>``.
    """
    now = now or datetime.now()
    thread_id = thread_id or threading.get_ident()
    extension = (
        CONST.GZIP_EXTENSION
        if data_type == CONST.WEBTX_DATA_TYPE
        else CONST.ALERTS_EVENTS_EXTENSION
    )
    name = CONST.OBJECT_NAME_TEMPLATE.format(
        epoch=int(now.timestamp()),
        thread_id=thread_id,
        uuid=uuid.uuid4().hex,
        extension=extension,
    )
    parts = CONST.PARTITION_TEMPLATE.format(
        year=now.year, month=now.month, day=now.day, hour=now.hour
    )
    feedname = CONST.FEEDNAME_TEMPLATE.format(subtype=subtype)
    return f"{data_type}/{feedname}/{parts}/{name}"


def remove_local_file(path: Optional[str]) -> None:
    """Remove a local file, ignoring a missing file and OS errors.

    Args:
        path (Optional[str]): File path to remove.
    """
    if not path:
        return
    try:
        if os.path.isfile(path):
            os.remove(path)
    except OSError:
        pass


def scality_add_user_agent() -> str:
    """Build the user agent sent with every Scality request.

    Returns:
        str: ``<CE user agent>-cls-scality-v<plugin version>``, the
            format version 1.0.0 already used.
    """
    headers = add_user_agent(header=None)
    ce_added_agent = headers.get(
        CONST.USER_AGENT_HEADER, CONST.DEFAULT_USER_AGENT
    )
    return CONST.USER_AGENT_TEMPLATE.format(
        ce_agent=ce_added_agent,
        module=CONST.MODULE_NAME.lower(),
        plugin=CONST.PLUGIN_NAME.lower().replace(" ", "-"),
        version=CONST.PLUGIN_VERSION,
    )
