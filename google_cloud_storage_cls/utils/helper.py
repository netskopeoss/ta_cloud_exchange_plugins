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
Google Cloud Storage plugin helper functions.
"""

import datetime
import gzip
import json
import os
import re
import sys
import threading
import traceback
import uuid
from typing import Any, BinaryIO, Dict, Iterable, NamedTuple, NoReturn, Optional

from netskope.common.utils import add_user_agent

from . import constants as CONST
from .exceptions import GCPStorageException


class SerializeResult(NamedTuple):
    """Counters of a ``serialize_records`` call.

    ``rejected`` holds the empty and failed records, so that they can be
    returned to Cloud Exchange and not be counted as ingested.
    """

    written: int
    skipped: int
    failed: int
    rejected: list


def get_user_agent(plugin_name: str, plugin_version: str) -> str:
    """Build the User-Agent of the requests sent to Google Cloud.

    Args:
        plugin_name (str): Plugin name from the manifest.
        plugin_version (str): Plugin version from the manifest.

    Returns:
        str: ``netskope-ce-<ce_version>-<module>-<plugin_name>-<version>``.
    """
    ce_agent = add_user_agent().get("User-Agent", "netskope-ce")
    return "{}-{}-{}-{}".format(
        ce_agent,
        CONST.MODULE_NAME.lower(),
        plugin_name.lower().replace(" ", "-"),
        plugin_version,
    )


def get_location(configuration: dict) -> str:
    """Get the bucket location (the custom one when selected).

    Args:
        configuration (dict): Plugin configuration parameters.

    Returns:
        str: Upper case location, empty when missing or not a string.
    """
    selected = (configuration or {}).get(CONST.LOCATION_KEY)
    selected = selected.strip() if isinstance(selected, str) else ""
    if selected == CONST.CUSTOM_LOCATION_VALUE:
        custom = configuration.get(CONST.CUSTOM_LOCATION_KEY)
        selected = custom.strip() if isinstance(custom, str) else ""
    return selected.upper()


def redact_sensitive_text(text: Any) -> str:
    """Remove secret looking parts (keys, tokens) from a text.

    Args:
        text (Any): Text that may contain an original error or traceback.

    Returns:
        str: Redacted text.
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
        str: Redacted single line text, truncated to the maximum length.
    """
    text = " ".join(redact_sensitive_text(text).split())
    if len(text) > CONST.MAX_ERROR_TEXT_LENGTH:
        text = text[: CONST.MAX_ERROR_TEXT_LENGTH] + "..."
    return text


def build_error_message(action: str, cause: str = "") -> str:
    """Build an error message starting with "Error occurred while".

    Args:
        action (str): What was being done.
        cause (str): Optional specific reason appended to the message.

    Returns:
        str: ``Error occurred while <action>. <cause>``.
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
    """Log an error with its resolution and a redacted traceback.

    Args:
        logger: CE logger object.
        log_prefix (str): Log prefix.
        action (str): What was being done.
        resolution (str): Resolution starting with "Ensure that".
        cause (str): Optional specific reason.
        details (Optional[str]): Error details. Defaults to the traceback
            when an exception is being handled, else the message.

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
    """Log an error and raise ``GCPStorageException`` with its message.

    Args:
        logger: CE logger object.
        log_prefix (str): Log prefix.
        action (str): What was being done.
        resolution (str): Resolution starting with "Ensure that".
        cause (str): Optional specific reason.
        details (Optional[str]): Error details (see ``log_error``).
        err (Optional[BaseException]): Original exception to chain.

    Raises:
        GCPStorageException: Always.
    """
    message = log_error(
        logger, log_prefix, action, resolution, cause, details
    )
    raise GCPStorageException(message) from err


def get_subtype_mapping(mappings: Dict[str, Any], subtype: str) -> Any:
    """Return the field list of a subtype, ignoring the case.

    Args:
        mappings (dict): Mappings of a data type.
        subtype (str): Subtype.

    Returns:
        list: Field names of the subtype.

    Raises:
        KeyError: When the subtype has no mapping.
    """
    lowered = {str(key).lower(): value for key, value in mappings.items()}
    return lowered[str(subtype).lower()]


def map_json_data(fields: list, record: dict) -> dict:
    """Keep only the listed fields of a record.

    Args:
        fields (list): Field names, dot separated for nested fields.
        record (dict): Record.

    Returns:
        dict: Record with the listed fields only.
    """
    mapped = {}
    for field in fields:
        if field in record:
            mapped[field] = record[field]
            continue
        current = record
        for part in field.split(CONST.NESTED_FIELD_SEPARATOR):
            if isinstance(current, dict) and part in current:
                current = current[part]
            else:
                break
        else:
            mapped[field] = current
    return mapped


def serialize_records(
    records: Iterable[Any], fileobj: BinaryIO, compress: bool = True
) -> SerializeResult:
    """Write the Netskope records into a file object as JSON lines.

    * ``dict`` records (parsed records) become one compact JSON line each.
    * Empty records are skipped.
    * A record that is not a ``dict``, or one that cannot be converted to
      JSON, is counted as failed.

    Args:
        records (Iterable[Any]): Records received by ``push``.
        fileobj: Binary file object opened for writing. It is not closed.
        compress (bool): Whether to gzip-compress the output.

    Returns:
        SerializeResult: Counts of written, skipped and failed records,
            and the records that were not written.
    """
    written = skipped = failed = 0
    rejected = []
    member = (
        gzip.GzipFile(filename="", fileobj=fileobj, mode="wb")
        if compress
        else fileobj
    )
    try:
        for record in records:
            if not record:
                skipped += 1
                rejected.append(record)
                continue
            if not isinstance(record, dict):
                failed += 1
                rejected.append(record)
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
                rejected.append(record)
                continue
            member.write(f"{line}\n".encode(CONST.TEXT_ENCODING))
            written += 1
    finally:
        if compress:
            member.close()
    return SerializeResult(written, skipped, failed, rejected)


def build_object_name(
    prefix: str,
    data_type: str,
    subtype: Optional[str],
    compress: bool = True,
) -> str:
    """Build the name of a pushed object, including its folders.

    Args:
        prefix (str): Object Prefix configuration parameter.
        data_type (str): Data type, ``alerts``, ``events`` or ``webtx``.
        subtype (Optional[str]): Subtype, e.g. ``v2`` or ``dlp``.
        compress (bool): Whether the object is gzip-compressed.

    Returns:
        str: ``<prefix>/<data_type>/feedname=<subtype>/year=<Y>/month=<M>/
            day=<D>/hour=<H>/<epoch>_<thread>_<uuid>`` (UTC) ending with
            ``.json.gz`` or ``.json``.
    """
    now = datetime.datetime.now(datetime.timezone.utc)
    folder = CONST.OBJECT_FOLDER_FORMAT.format(
        prefix=prefix.strip().strip("/"),
        data_type=data_type,
        subtype=re.sub(r"[^A-Za-z0-9_-]+", "_", subtype).strip("_")
        if subtype
        else "none",
        year=now.year,
        month=now.month,
        day=now.day,
        hour=now.hour,
    )
    name = CONST.OBJECT_NAME_FORMAT.format(
        epoch=int(now.timestamp()),
        thread_id=threading.get_ident(),
        uuid=uuid.uuid4().hex,
        extension=CONST.OBJECT_EXTENSION_GZIP
        if compress
        else CONST.OBJECT_EXTENSION_JSON,
    )
    return f"{folder}/{name}"


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


def parse_key_file(key_file: Any) -> Dict[str, Any]:
    """Parse the Service Account key file.

    Args:
        key_file (Any): Key File configuration parameter.

    Returns:
        dict: The parsed key file.

    Raises:
        ValueError: When the value is not a JSON object.
    """
    if not isinstance(key_file, str):
        raise ValueError("Key File must be a string.")
    parsed = json.loads(key_file)
    if not isinstance(parsed, dict):
        raise ValueError("Key File must be a JSON object.")
    return parsed
