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

Snowflake CLS Plugin chunking and payload utilities.
"""

import gzip
import json
import re
from typing import Dict, Iterator, List, Optional, Tuple
from urllib.parse import urlparse

from .constants import (
    GZIP_COMPRESSION_LEVEL,
    MAX_PAYLOAD_CHUNK_SIZE_IN_BYTES,
    SNOWFLAKE_ACCOUNT_LABEL_RE,
    SNOWFLAKE_HOST_SUFFIX,
)


def serialize_row(row: Dict) -> str:
    """Turn one row into the NDJSON line Snowflake expects.

    Args:
        row (Dict): Row to serialize.

    Returns:
        str: One JSON object on a single line.
    """
    return json.dumps(row, default=str)


def row_size_in_bytes(row: Dict) -> int:
    """Measure how many bytes a row takes on the wire.

    Counts the serialized row plus the one newline that separates it from
    the next row in the NDJSON body.

    Args:
        row (Dict): Row to measure.

    Returns:
        int: Size in bytes.
    """
    return len(serialize_row(row).encode("utf-8")) + 1


def build_ndjson_payload(lines: List[str]) -> bytes:
    """Join already-serialized rows into one NDJSON body.

    Takes the lines produced by split_into_size() so each row is turned
    into JSON once per push, not once for sizing and again for sending.

    Args:
        lines (List[str]): One JSON object per entry.

    Returns:
        bytes: The request body, UTF-8 encoded.
    """
    return "\n".join(lines).encode("utf-8")


def split_into_size(
    data_list: List[Dict],
    max_bytes: int = MAX_PAYLOAD_CHUNK_SIZE_IN_BYTES,
) -> Iterator[Tuple[List[Dict], List[str]]]:
    """Split rows into chunks small enough for one API call.

    Size is the only limit, because that is the only limit Snowflake
    has. A chunk ends when adding the next row would push the body past
    max_bytes. The last partial chunk is always yielded, never dropped.

    A single row bigger than max_bytes still gets its own chunk and is
    sent on its own. Snowflake rejects it with a 413, and push() stops
    the whole push there - it does not send the batches after it, so
    Cloud Exchange retries rather than losing those rows quietly.

    Each row is serialized once here. The resulting line is yielded
    alongside the row so the caller can build the request body without
    serializing it a second time.

    Args:
        data_list (List[Dict]): Rows to split.
        max_bytes (int): Most bytes allowed in one chunk.

    Yields:
        Tuple[List[Dict], List[str]]: The rows in the chunk, and the
            NDJSON line for each of them.
    """
    chunk = []
    chunk_lines = []
    chunk_bytes = 0

    for row in data_list:
        line = serialize_row(row)
        size = len(line.encode("utf-8")) + 1
        if chunk and chunk_bytes + size > max_bytes:
            yield chunk, chunk_lines
            chunk = []
            chunk_lines = []
            chunk_bytes = 0
        chunk.append(row)
        chunk_lines.append(line)
        chunk_bytes += size

    if chunk:
        yield chunk, chunk_lines


def try_compress_whole_batch(
    data_list: List[Dict],
    max_bytes: int = MAX_PAYLOAD_CHUNK_SIZE_IN_BYTES,
) -> Optional[bytes]:
    """Gzip the entire batch as a single request body.

    push() calls this first so a batch that compresses small enough
    goes out as one call instead of several. The NDJSON bytes gzipped
    here are byte-for-byte what split_into_size() + build_ndjson_payload()
    would have sent uncompressed, so this is purely a transport choice.

    Args:
        data_list (List[Dict]): Rows to compress.
        max_bytes (int): Most bytes allowed in one request.

    Returns:
        Optional[bytes]: The gzip-compressed body, or None if it does
            not fit in one request - the caller falls back to
            split_into_size().
    """
    lines = [serialize_row(row) for row in data_list]
    payload = build_ndjson_payload(lines)
    compressed = gzip.compress(payload, compresslevel=GZIP_COMPRESSION_LEVEL)
    return compressed if len(compressed) <= max_bytes else None


def normalize_base_url(value: str) -> str:
    """Clean up the Account URL and check it points at Snowflake.

    Every request built from this value carries the customer's token,
    so the host is pinned to Snowflake's own domain. Anything that
    could send the token somewhere else - another host, a different
    scheme, a userinfo part, a port - is refused rather than repaired.

    A value typed without a scheme gets "https://" put in front of it,
    and a trailing slash is dropped. Those are the two things people
    get wrong that have only one sensible reading.

    Args:
        value (str): What the customer entered.

    Returns:
        str: The cleaned URL, or "" when it cannot be used.
    """
    if not value or not isinstance(value, str):
        return ""
    url = value.strip().rstrip("/")
    if not url:
        return ""
    if "://" not in url:
        url = f"https://{url}"
    try:
        parsed = urlparse(url)
        port = parsed.port
    except ValueError:
        # urlparse raises on a malformed port.
        return ""
    if parsed.scheme != "https":
        return ""
    if parsed.username or parsed.password or port is not None:
        return ""
    if parsed.path or parsed.params or parsed.query or parsed.fragment:
        return ""
    host = (parsed.hostname or "").lower()
    if not host.endswith(SNOWFLAKE_HOST_SUFFIX):
        return ""
    account = host[: -len(SNOWFLAKE_HOST_SUFFIX)]
    if not re.match(SNOWFLAKE_ACCOUNT_LABEL_RE, account):
        return ""
    return f"https://{host}"


def escape_sql_identifier(value: str) -> str:
    """Escape a name going inside a double-quoted SQL identifier.

    Doubles every double quote, which is the character that would end
    the identifier early. Checked against a live account:

      "WEIRD""NAME"   resolves to the table named WEIRD"NAME
      "WEIRD"NAME"    is a syntax error

    A single quote is an ordinary character here and must be left
    alone. This used to double single quotes instead, which was not
    merely useless: a table named O'BRIEN would have been looked up as
    O''BRIEN and reported as not found.

    Second line of defence only - database, schema and table names are
    already checked against SNOWFLAKE_IDENTIFIER_RE during validate(),
    which allows neither quote character.

    Args:
        value (str): Name to escape.

    Returns:
        str: The name, safe to place inside double quotes.
    """
    return str(value).replace('"', '""')


def quote_path_identifier(value: str) -> str:
    """Quote a name for a Snowpipe Streaming REST API URL path segment.

    Confirmed live (2026-10-07): the rows endpoint resolves an unquoted
    database/schema/table path segment the way Snowflake resolves an
    unquoted SQL identifier - folded to upper case - so it 404s against
    an object whose real stored name is not pure upper case, regardless
    of what case is typed. Wrapping the segment in literal double
    quotes (sent URL-encoded as %22...%22) makes it resolve exactly
    like a quoted SQL identifier instead: matched case-sensitively
    against the name Snowflake actually stores. This is safe for an
    ordinary, unquoted-created (upper-case-stored) object too, since a
    quoted lookup for its exact stored case matches it just the same -
    which is why SHOW COLUMNS already always quotes.

    Args:
        value (str): Name to quote.

    Returns:
        str: The name wrapped in double quotes, ready to go straight
            into a URL path segment.
    """
    return f'"{escape_sql_identifier(value)}"'
