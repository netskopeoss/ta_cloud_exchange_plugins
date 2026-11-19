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

AWS S3 WebTx plugin helper functions.
"""

import gzip
import json
import os
import re
import sys
import threading
import traceback
import uuid
from datetime import datetime
from typing import Any, BinaryIO, Iterable, NamedTuple, NoReturn, Optional

from . import constants as CONST
from .exceptions import AWSS3WebTxException


class SerializeResult(NamedTuple):
    """Counters of a ``serialize_records`` call."""

    written: int
    skipped: int
    failed: int


def get_effective_region(configuration: dict) -> str:
    """Get the region used for every AWS call (single source of truth).

    Args:
        configuration (dict): Plugin configuration parameters.

    Returns:
        str: The trimmed, lower case AWS Custom Region when the region
            dropdown is set to ``custom`` (region codes are lower case, so
            the Roles Anywhere host is built correctly for any input case),
            else the trimmed dropdown value. Empty when the
            value is missing or not a string.
    """
    selected = (configuration or {}).get(CONST.REGION_NAME_KEY)
    selected = selected.strip() if isinstance(selected, str) else ""
    if selected == CONST.CUSTOM_REGION_VALUE:
        custom = configuration.get(CONST.CUSTOM_REGION_NAME_KEY)
        return custom.strip().lower() if isinstance(custom, str) else ""
    return selected


def get_roles_anywhere_host(region: str) -> str:
    """Build the IAM Roles Anywhere endpoint host of a region.

    Args:
        region (str): Region code.

    Returns:
        str: ``rolesanywhere.<region>.amazonaws.com`` (``.com.cn`` for the
            China regions).
    """
    domain = (
        CONST.ROLES_ANYWHERE_CN_DOMAIN
        if region.startswith(CONST.CN_REGION_PREFIX)
        else CONST.ROLES_ANYWHERE_DOMAIN
    )
    return CONST.ROLES_ANYWHERE_HOST_FORMAT.format(
        region=region, domain=domain
    )


def get_arn_region(value: Any) -> Optional[str]:
    """Read the region field of an ARN.

    An ARN is ``arn:partition:service:region:account:resource``. Nothing is
    validated here and the function never raises.

    Args:
        value (Any): The ARN.

    Returns:
        Optional[str]: The region, or None when the value is not a string,
            is not an ARN or has an empty region.
    """
    if not isinstance(value, str):
        return None
    fields = value.strip().split(":")
    if len(fields) < CONST.ARN_MIN_FIELDS or fields[0] != CONST.ARN_PREFIX:
        return None
    return fields[CONST.ARN_REGION_INDEX].strip() or None


def normalize_externally_provisioned(value: Any) -> Any:
    """Normalize the Externally Provisioned Bucket value.

    A missing or empty value (configurations saved by 1.2.0) means ``no``.

    Args:
        value (Any): Configured value.

    Returns:
        Any: The stripped lower case string, ``no`` when empty, or the
            value unchanged when it is not a string (rejected by the
            validation).
    """
    if value is None:
        return CONST.EP_DEFAULT
    if isinstance(value, str):
        return value.strip().lower() or CONST.EP_DEFAULT
    return value


def redact_sensitive_text(text: Any) -> str:
    """Remove secret looking parts from a text.

    Args:
        text (Any): Text that may contain an original error or traceback.

    Returns:
        str: Text without PEM blocks, credential or signature values, user
            info of URLs and query strings.
    """
    text = str(text)
    for pattern, replacement in CONST.SENSITIVE_TEXT_PATTERNS:
        text = re.sub(pattern, replacement, text, flags=re.DOTALL)
    return text


def sanitize_error_text(text: Any) -> str:
    """Make an original error text safe to log and show.

    Args:
        text (Any): Original error text.

    Returns:
        str: Redacted text on a single line, truncated to
            ``MAX_ERROR_TEXT_LENGTH`` characters.
    """
    text = " ".join(redact_sensitive_text(text).split())
    if len(text) > CONST.MAX_ERROR_TEXT_LENGTH:
        text = text[:CONST.MAX_ERROR_TEXT_LENGTH] + "..."
    return text


def safe_error_text(error: BaseException) -> str:
    """Get the sanitized text of a boto3, botocore or requests error.

    Args:
        error (BaseException): The raised exception.

    Returns:
        str: ``<code>: <message>`` for an AWS ``ClientError``, else the
            exception text; always sanitized.
    """
    response = getattr(error, "response", None)
    if isinstance(response, dict) and isinstance(
        response.get(CONST.ERROR_KEY), dict
    ):
        details = response[CONST.ERROR_KEY]
        code = details.get(CONST.ERROR_CODE_KEY, "")
        message = details.get(CONST.ERROR_MESSAGE_KEY, "")
        return sanitize_error_text(f"{code}: {message}")
    return sanitize_error_text(str(error) or type(error).__name__)


def build_error_message(action: str, cause: str = "") -> str:
    """Build an error message that starts with "Error occurred while".

    Args:
        action (str): What was being done, e.g. "validating configuration
            parameters".
        cause (str): Optional specific reason appended to the message.

    Returns:
        str: ``Error occurred while <action>. <cause>``. A cause that
            already starts with the lead is returned unchanged.
    """
    if cause and cause.startswith(CONST.ERROR_MESSAGE_LEAD):
        return cause
    message = f"{CONST.ERROR_MESSAGE_LEAD} {action}."
    if cause:
        message = f"{message} {cause}"
    return message


def log_error(
    logger: Any,
    log_prefix: str,
    action: str,
    resolution: str,
    cause: str = "",
    details: Optional[str] = None,
) -> str:
    """Log an error following the plugin logging contract.

    Args:
        logger: CE logger object.
        log_prefix (str): Log prefix.
        action (str): What was being done.
        resolution (str): Resolution starting with "Ensure that".
        cause (str): Optional specific reason.
        details (Optional[str]): Error details. Defaults to the redacted
            traceback when an exception is being handled, else the message.

    Returns:
        str: The logged message without the log prefix.
    """
    message = build_error_message(action, cause)
    if details is None:
        details = traceback.format_exc() if sys.exc_info()[0] else message
    logger.error(
        message=f"{log_prefix}: {message}",
        details=redact_sensitive_text(details),
        resolution=resolution,
    )
    return message


def log_and_raise(
    logger: Any,
    log_prefix: str,
    action: str,
    resolution: str,
    cause: str = "",
    details: Optional[str] = None,
    err: Optional[BaseException] = None,
) -> NoReturn:
    """Log an error and raise ``AWSS3WebTxException`` with its message.

    Args:
        logger: CE logger object.
        log_prefix (str): Log prefix.
        action (str): What was being done.
        resolution (str): Resolution starting with "Ensure that".
        cause (str): Optional specific reason.
        details (Optional[str]): Error details (see ``log_error``).
        err (Optional[BaseException]): Original exception to chain.

    Raises:
        AWSS3WebTxException: Always.
    """
    message = log_error(
        logger, log_prefix, action, resolution, cause, details
    )
    raise AWSS3WebTxException(message) from err


def serialize_records(
    records: Iterable[Any], fileobj: BinaryIO
) -> SerializeResult:
    """Write the WebTx records into a gzip file object as JSON lines.

    * ``dict`` records (parsed WebTx) become one compact JSON line each.
    * Empty records are skipped.
    * A record that is not a ``dict``, or a ``dict`` that cannot be
      converted to JSON, is counted as failed.

    Args:
        records (Iterable[Any]): Records received by ``push``.
        fileobj: Binary file object opened for writing. It is not closed.

    Returns:
        SerializeResult: Counts of written, skipped and failed records.
    """
    written = skipped = failed = 0
    with gzip.GzipFile(filename="", fileobj=fileobj, mode="wb") as member:
        for record in records:
            if not record:
                skipped += 1
                continue
            if not isinstance(record, dict):
                failed += 1
                continue
            try:
                line = json.dumps(
                    record,
                    separators=(",", ":"),
                    default=str,
                    ensure_ascii=False,
                    allow_nan=False,
                )
            except (TypeError, ValueError):
                failed += 1
                continue
            member.write(f"{line}\n".encode(CONST.TEXT_ENCODING))
            written += 1
    return SerializeResult(written, skipped, failed)


def build_object_key(
    subtype: Optional[str],
    now: Optional[datetime] = None,
    thread_id: Optional[int] = None,
) -> str:
    """Build the S3 object key of a pushed WebTx file.

    Args:
        subtype (Optional[str]): WebTx subtype (feed name), e.g. ``v2``.
        now (Optional[datetime]): Time to use. Defaults to now.
        thread_id (Optional[int]): Thread id. Defaults to the current one.

    Returns:
        str: ``webtx/feedname=<subtype>/year=Y/month=M/day=D/hour=H/``
            ``<epoch>_<thread_id>_<uuid>.gz``.
    """
    now = now or datetime.now()
    thread_id = thread_id or threading.get_ident()
    name = CONST.OBJECT_NAME_FORMAT.format(
        epoch=int(now.timestamp()),
        thread_id=thread_id,
        uuid=uuid.uuid4().hex,
        extension=CONST.OBJECT_EXTENSION,
    )
    folders = CONST.OBJECT_FOLDERS_FORMAT.format(
        year=now.year, month=now.month, day=now.day, hour=now.hour
    )
    return CONST.OBJECT_KEY_FORMAT.format(
        prefix=CONST.OBJECT_KEY_PREFIX,
        subtype=subtype,
        folders=folders,
        name=name,
    )


def remove_local_file(path: Optional[str]) -> None:
    """Remove a local file, ignoring a missing file and OS errors.

    Args:
        path (Optional[str]): File path.
    """
    if not path:
        return
    try:
        if os.path.isfile(path):
            os.remove(path)
    except OSError:
        pass
