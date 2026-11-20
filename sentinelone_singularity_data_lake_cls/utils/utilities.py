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

SentinelOne Singularity Data Lake CLS plugin utilities.
"""

import json
import math
import re
from datetime import datetime, timezone
from typing import Any, Dict, Iterator, List, Optional, Tuple, Union
from urllib.parse import urlparse

from .constants import (
    DATA_TYPE_WEBTX,
    FLOAT_TRANSFORMATION,
    INTEGER_TRANSFORMATION,
    MAX_PAYLOAD_CHUNK_SIZE_IN_BYTES,
    MAX_SAFE_INTEGER_DIGITS,
    MAX_SAFE_JSON_INTEGER,
    NETSKOPE_FIELD_PREFIX,
    NUMERIC_TRANSFORMATIONS,
    RESERVED_FIELDS,
    SOFT_TIME_LIMIT_ERROR_NAME,
    SUBTYPE_SOURCE_FIELD,
    TIMESTAMP_FIELDS,
    WEBTX_DATE_FIELD,
    WEBTX_EVENT_TYPE,
    WEBTX_TIME_FIELD,
)

# ASCII digits only. \d would also accept digits from other scripts.
INTEGER_RE = re.compile(r"[+-]?[0-9]+")
FLOAT_RE = re.compile(
    r"[+-]?(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)(?:[eE][+-]?[0-9]+)?"
)


def serialize_item(item: Union[Dict, str]) -> str:
    """Turn one transformed record into the text sent to HEC.

    A dict (JSON mode) becomes compact JSON. A string (CEF mode) is used
    as it is. NaN and Infinity are refused: they are not valid JSON, and
    HEC can drop a whole batch it cannot parse while still answering
    200.

    Args:
        item (Union[Dict, str]): HEC event body or CEF line.

    Returns:
        str: Serialized record.

    Raises:
        ValueError: If the record holds NaN or Infinity.
    """
    if isinstance(item, str):
        return item
    return json.dumps(
        item, separators=(",", ":"), default=str, allow_nan=False
    )


def split_into_size(
    items: List[Union[Dict, str]],
    max_bytes: int = MAX_PAYLOAD_CHUNK_SIZE_IN_BYTES,
) -> Iterator[Tuple[List[Union[Dict, str]], List[str]]]:
    """Split records into chunks that stay under max_bytes.

    Size is the UTF-8 length of each serialized record plus one byte for
    a possible delimiter. sys.getsizeof() is not used: it measures the
    Python object, not the bytes sent.

    A chunk ends when the next record would push it past max_bytes. A
    record bigger than max_bytes gets a chunk of its own. The last
    chunk is always returned, never dropped, and no chunk is ever empty.

    Each record is serialized once. The serialized text is returned next
    to the record so the caller does not serialize it again.

    Args:
        items (List[Union[Dict, str]]): Records from transform().
        max_bytes (int): Most bytes allowed in one chunk.

    Yields:
        Tuple[List, List[str]]: Records in the chunk, and their
            serialized text.
    """
    chunk = []
    chunk_lines = []
    chunk_bytes = 0
    for item in items:
        line = serialize_item(item)
        size = len(line.encode("utf-8")) + 1
        if chunk and chunk_bytes + size > max_bytes:
            yield chunk, chunk_lines
            chunk = []
            chunk_lines = []
            chunk_bytes = 0
        chunk.append(item)
        chunk_lines.append(line)
        chunk_bytes += size
    if chunk:
        yield chunk, chunk_lines


def namespace_reserved(record: Dict) -> Dict:
    """Rename fields that collide with Singularity Data Lake attributes.

    Only the names in RESERVED_FIELDS are renamed, to netskope_<name>.
    Every other field is kept as it is. A new dict is returned; the
    input is not changed.

    Args:
        record (Dict): Netskope record after mapping.

    Returns:
        Dict: Record with reserved names prefixed.
    """
    renamed = {}
    for key, value in record.items():
        if key in RESERVED_FIELDS:
            renamed[f"{NETSKOPE_FIELD_PREFIX}{key}"] = value
        else:
            renamed[key] = value
    return renamed


def get_nested_value(data: Dict, path: str) -> Tuple[Any, bool]:
    """Read a value from a record. Supports dot paths.

    A key that contains dots is tried as it is first. Then the path is
    walked one key at a time. Never raises when a key is missing.

    Args:
        data (Dict): Record to read from.
        path (str): Field name, or a dot-separated path such as
            "host_info.hostname".

    Returns:
        Tuple[Any, bool]: The value, and whether it was found.
    """
    if not isinstance(data, dict) or not path:
        return None, False
    if path in data:
        return data[path], True
    current = data
    for part in str(path).split("."):
        if isinstance(current, dict) and part in current:
            current = current[part]
        else:
            return None, False
    return current, True


def _to_epoch_seconds(value: Any) -> Optional[float]:
    """Convert a timestamp value to epoch seconds.

    Args:
        value (Any): Number or numeric string.

    Returns:
        Optional[float]: Epoch seconds, or None if the value is not a
            usable positive number.
    """
    if value is None or isinstance(value, bool):
        return None
    try:
        seconds = float(value)
    except (TypeError, ValueError):
        return None
    if not math.isfinite(seconds) or seconds <= 0:
        return None
    return seconds


def _webtx_date_time_to_epoch(record: Dict) -> Optional[float]:
    """Build epoch seconds from the WebTx "date" and "time" fields.

    WebTx logs carry date (YYYY-MM-DD) and time (HH:MM:SS) in UTC.

    Args:
        record (Dict): WebTx record.

    Returns:
        Optional[float]: Epoch seconds, or None if they cannot be read.
    """
    date_value = record.get(WEBTX_DATE_FIELD)
    time_value = record.get(WEBTX_TIME_FIELD)
    if not isinstance(date_value, str) or not isinstance(time_value, str):
        return None
    try:
        parsed = datetime.fromisoformat(
            f"{date_value.strip()}T{time_value.strip()}"
        )
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return _to_epoch_seconds(parsed.timestamp())


def resolve_event_time(record: Dict, data_type: str) -> Optional[float]:
    """Find the event time of a Netskope record.

    Tries TIMESTAMP_FIELDS in order. For WebTx it then tries date and
    time. Returns None when nothing usable is found; the caller then
    uses the current time.

    Args:
        record (Dict): Original Netskope record (before mapping).
        data_type (str): "alerts", "events" or "webtx".

    Returns:
        Optional[float]: Epoch seconds rounded to milliseconds, or None.
    """
    if not isinstance(record, dict):
        return None
    for field in TIMESTAMP_FIELDS:
        seconds = _to_epoch_seconds(record.get(field))
        if seconds is not None:
            return round(seconds, 3)
    if data_type == DATA_TYPE_WEBTX:
        seconds = _webtx_date_time_to_epoch(record)
        if seconds is not None:
            return round(seconds, 3)
    return None


def resolve_event_type(record: Dict, data_type: str, subtype: str) -> str:
    """Find the value for the event.type attribute.

    Alerts use alert_type and events use event_type from the record.
    If the record has none, the subtype from Cloud Exchange is used.
    WebTx has no such field and always uses "webtx".

    Args:
        record (Dict): Original Netskope record.
        data_type (str): "alerts", "events" or "webtx".
        subtype (str): Subtype from Cloud Exchange.

    Returns:
        str: Event type.
    """
    if data_type == DATA_TYPE_WEBTX:
        return WEBTX_EVENT_TYPE
    field = SUBTYPE_SOURCE_FIELD.get(data_type)
    if field and isinstance(record, dict):
        value = record.get(field)
        if value not in (None, ""):
            return str(value)
    return str(subtype)


def is_soft_time_limit(error: BaseException) -> bool:
    """Check if an error is Celery's soft time limit.

    It must be raised again, never counted as one bad log: Cloud
    Exchange needs it to stop and reschedule the task.

    Args:
        error (BaseException): Caught error.

    Returns:
        bool: True for SoftTimeLimitExceeded.
    """
    return type(error).__name__ == SOFT_TIME_LIMIT_ERROR_NAME


def build_numeric_field_map(cef_subtype_mapping: Any) -> Dict[str, str]:
    """List the Netskope fields that the CEF mapping marks as numbers.

    The CEF mapping gives each Netskope field a "transformation" (for
    example Integer). A field is kept only when every CEF entry that
    reads it agrees on a numeric type.

    Args:
        cef_subtype_mapping (Any): CEF mapping of one subtype, with
            "header" and "extension". Anything else gives {}.

    Returns:
        Dict[str, str]: Netskope field name to "Integer" or
            "Floating Point".
    """
    if not isinstance(cef_subtype_mapping, dict):
        return {}
    types = {}
    conflicting = set()
    for section in ("header", "extension"):
        definitions = cef_subtype_mapping.get(section)
        if not isinstance(definitions, dict):
            continue
        for definition in definitions.values():
            if not isinstance(definition, dict):
                continue
            field = definition.get("mapping_field")
            if not field or definition.get("is_json_path"):
                continue
            transformation = definition.get("transformation", "String")
            if field in types and types[field] != transformation:
                conflicting.add(field)
            types.setdefault(field, transformation)
    return {
        field: transformation
        for field, transformation in types.items()
        if transformation in NUMERIC_TRANSFORMATIONS
        and field not in conflicting
    }


def coerce_numeric_fields(record: Dict, numeric_fields: Dict) -> Dict:
    """Turn numeric strings into JSON numbers.

    Only fields in numeric_fields are touched, and only when the value is
    a string that is a clean number. Anything else (for example "-") is
    kept as it is. A new dict is returned; the input is not changed.

    An integer bigger than MAX_SAFE_JSON_INTEGER stays a string. Many
    JSON readers store numbers as 64-bit floats, which would change the
    last digits of large IDs such as the WebTx x-transaction-id. As a
    string the value stays exact.

    Args:
        record (Dict): Mapped Netskope record.
        numeric_fields (Dict): Output of build_numeric_field_map().

    Returns:
        Dict: Record with numeric strings converted.
    """
    if not numeric_fields:
        return record
    coerced = dict(record)
    for field, transformation in numeric_fields.items():
        value = coerced.get(field)
        if not isinstance(value, str):
            continue
        text = value.strip()
        if transformation == INTEGER_TRANSFORMATION:
            # More than 16 digits is always over the limit. Checking the
            # length first also keeps int() away from huge strings.
            if (
                INTEGER_RE.fullmatch(text)
                and len(text.lstrip("+-")) <= MAX_SAFE_INTEGER_DIGITS
            ):
                number = int(text)
                if abs(number) <= MAX_SAFE_JSON_INTEGER:
                    coerced[field] = number
        elif transformation == FLOAT_TRANSFORMATION:
            if FLOAT_RE.fullmatch(text):
                number = float(text)
                if math.isfinite(number):
                    coerced[field] = number
    return coerced


def validate_hec_base_url(url: str) -> bool:
    """Check that a URL can be used as an HEC base URL.

    It must be https, have a host, and have no path, query or fragment.
    A trailing slash should be removed before calling this.

    Args:
        url (str): URL to check.

    Returns:
        bool: True if the URL is usable.
    """
    if not isinstance(url, str) or not url:
        return False
    try:
        parsed = urlparse(url)
        # Reading .port raises ValueError for a bad port.
        _ = parsed.port
    except ValueError:
        return False
    return (
        parsed.scheme == "https"
        and bool(parsed.hostname)
        and parsed.path in ("", "/")
        and not parsed.query
        and not parsed.fragment
        and not parsed.params
    )
