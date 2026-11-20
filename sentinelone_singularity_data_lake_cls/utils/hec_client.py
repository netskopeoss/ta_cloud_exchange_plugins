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

SentinelOne Singularity Data Lake HTTP Event Collector (HEC) client.

The two HEC endpoints want OPPOSITE batch delimiters. Both mistakes
return 200 Success and lose data without any error:

- /services/collector/event: JSON objects joined with NOTHING between
  them. A newline between objects makes HEC drop the whole batch.
- /services/collector/raw: one CEF line per line, joined with a
  newline. Joining with nothing merges every line into one event.

Do not change either join to match the other.
"""

import gzip
from typing import Any, Dict, List

from .constants import (
    GZIP_COMPRESSION_LEVEL,
    HEC_EVENT_PATH,
    HEC_RAW_PATH,
)


def build_event_body(
    event: Dict,
    host: str,
    source: str,
    sourcetype: str,
    time_value: float,
) -> Dict:
    """Build one HEC /event body.

    "source" must be a body field here. On /event a "source" query
    parameter is ignored without any error.

    Args:
        event (Dict): Log record, already mapped and renamed.
        host (str): Source value. Shown under the Sources tab.
        source (str): Log File Name. Left out when empty.
        sourcetype (str): Parser name.
        time_value (float): Event time, epoch seconds.

    Returns:
        Dict: HEC event body.
    """
    body = {
        "time": time_value,
        "event": event,
        "host": host,
        "sourcetype": sourcetype,
    }
    # An empty Log File name means the key is left out rather than sent
    # empty. HEC accepts that and stores the log with no logfile.
    if source:
        body["source"] = source
    return body


def build_event_payload(lines: List[str]) -> bytes:
    """Join serialized /event bodies and gzip them.

    Joined with NOTHING between objects ("".join). See module docstring.

    Args:
        lines (List[str]): Serialized HEC event bodies.

    Returns:
        bytes: gzip-compressed request body.
    """
    return gzip.compress(
        "".join(lines).encode("utf-8"),
        compresslevel=GZIP_COMPRESSION_LEVEL,
    )


def build_raw_payload(lines: List[str]) -> bytes:
    """Join CEF lines with a newline and gzip them.

    One CEF line per line, joined with a newline. See module docstring.

    Args:
        lines (List[str]): CEF lines.

    Returns:
        bytes: gzip-compressed request body.
    """
    return gzip.compress(
        "\n".join(lines).encode("utf-8"),
        compresslevel=GZIP_COMPRESSION_LEVEL,
    )


def build_raw_params(
    source: str,
    sourcetype: str,
    host: str,
    data_source_vendor: str,
    data_source_name: str,
    data_source_category: str,
) -> Dict:
    """Build the query parameters for /raw.

    /raw takes these as query parameters, not body fields. CEF lines
    carry no dataSource.* of their own, so all three dataSource values
    go here. Without dataSource.category the logs do not show in the
    XDR view.

    Args:
        source (str): Log File Name. Left out when empty.
        sourcetype (str): Parser name.
        host (str): Source value, sent as serverHost.
        data_source_vendor (str): dataSource.vendor value.
        data_source_name (str): dataSource.name value.
        data_source_category (str): dataSource.category value.

    Returns:
        Dict: Query parameters.
    """
    params = {
        "sourcetype": sourcetype,
        "serverHost": host,
        "dataSource.vendor": data_source_vendor,
        "dataSource.name": data_source_name,
        "dataSource.category": data_source_category,
    }
    # Same as /event: an empty Log File name is left out entirely.
    if source:
        params["source"] = source
    return params


def _auth_headers(api_token: str, content_type: str) -> Dict:
    """Build the request headers.

    The key is used as it is - never stripped. No S1-Scope header is
    sent: a Log Access Write Key carries its own scope.

    Args:
        api_token (str): Log Access Write Key.
        content_type (str): Content-Type value.

    Returns:
        Dict: Request headers.
    """
    return {
        "Authorization": f"Bearer {api_token}",
        "Content-Type": content_type,
        "Content-Encoding": "gzip",
    }


def send_events(
    helper: Any,
    base_url: str,
    api_token: str,
    body: bytes,
    verify: bool,
    proxies: Dict,
    logger_msg: str,
    is_validation: bool = False,
) -> Any:
    """Send a gzipped batch of HEC event bodies to /event.

    Args:
        helper (Any): SentinelOneSDLPluginHelper.
        base_url (str): HEC base URL, no trailing slash.
        api_token (str): Log Access Write Key.
        body (bytes): Output of build_event_payload().
        verify (bool): Verify the TLS certificate.
        proxies (Dict): Proxy settings.
        logger_msg (str): What the plugin is doing, for logs.
        is_validation (bool): True when called from validate().

    Returns:
        Any: Parsed HEC response.
    """
    return helper.api_helper(
        logger_msg=logger_msg,
        url=f"{base_url}{HEC_EVENT_PATH}",
        method="POST",
        headers=_auth_headers(api_token, "application/json"),
        data=body,
        verify=verify,
        proxies=proxies,
        is_validation=is_validation,
    )


def send_raw(
    helper: Any,
    base_url: str,
    api_token: str,
    body: bytes,
    params: Dict,
    verify: bool,
    proxies: Dict,
    logger_msg: str,
) -> Any:
    """Send a gzipped batch of CEF lines to /raw.

    Args:
        helper (Any): SentinelOneSDLPluginHelper.
        base_url (str): HEC base URL, no trailing slash.
        api_token (str): Log Access Write Key.
        body (bytes): Output of build_raw_payload().
        params (Dict): Output of build_raw_params().
        verify (bool): Verify the TLS certificate.
        proxies (Dict): Proxy settings.
        logger_msg (str): What the plugin is doing, for logs.

    Returns:
        Any: Parsed HEC response.
    """
    return helper.api_helper(
        logger_msg=logger_msg,
        url=f"{base_url}{HEC_RAW_PATH}",
        method="POST",
        params=params,
        headers=_auth_headers(api_token, "text/plain"),
        data=body,
        verify=verify,
        proxies=proxies,
    )
