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

Helper functions for STIX/TAXII plugin."""

from datetime import datetime
from typing import Dict, Any, Union
from netskope.common.utils import add_user_agent
import pytz
from .constants import (
    STIX_VERSION_1,
    USER_AGENT_FORMAT,
    USER_AGENT_KEY,
    DEFAULT_USER_AGENT,
    MODULE_NAME,
    PLUGIN_VERSION,
    PLATFORM_NAME,
    DATE_FORMAT_STRING,
)


class STIXTAXIIException(Exception):
    """Exception class for STIX/TAXII plugin."""

    pass


def get_configuration_parameters(
    configuration: Dict[str, Any],
    is_validation: bool = False,
    keys: list = []
):
    """
    Get configuration parameters.

    Args:
        configuration (Dict[str, Any]): Configuration dictionary.
        is_validation (bool): Whether this is for validation.
        keys (list, optional): List of specific keys to return. If provided,
            returns tuple of only those values in the order specified.

    Returns:
        tuple: Tuple of configuration parameters.
            If keys is specified, returns only those values.

    Available keys:
        version, discovery_url, username, password, collection_names,
        pagination_method, days, delay, type_to_pull, severity,
        reputation, batch_size, retraction_interval
    """
    version = configuration.get(
        "version", STIX_VERSION_1 if not is_validation else ""
    ).strip()
    discovery_url = configuration.get("discovery_url", "").strip()
    username = configuration.get("username", "").strip()
    password = configuration.get("password", "").strip()
    collection_names = configuration.get("collection_names", "").strip()
    pagination_method = configuration.get(
        "pagination_method", "next" if not is_validation else ""
    ).strip()
    days = configuration.get("days", 7 if not is_validation else None)
    delay = configuration.get("delay", 0 if not is_validation else None)
    type_to_pull = configuration.get(
        "type",
        (
            ["sha256", "md5", "url", "ipv4", "ipv6", "domain"]
            if not is_validation
            else []
        ),
    )
    severity = configuration.get("severity", [])
    reputation = configuration.get(
        "reputation", 5 if not is_validation else None
    )
    batch_size = configuration.get(
        "batch_size", 1000 if not is_validation else None
    )
    retraction_interval = configuration.get(
        "retraction_interval",
        0 if not is_validation else None
    )

    all_params = {
        "version": version,
        "discovery_url": discovery_url,
        "username": username,
        "password": password,
        "collection_names": collection_names,
        "pagination_method": pagination_method,
        "days": days,
        "delay": delay,
        "type_to_pull": type_to_pull,
        "severity": severity,
        "reputation": reputation,
        "batch_size": batch_size,
        "retraction_interval": retraction_interval,
    }

    if keys:
        return tuple(all_params[key] for key in keys)

    return (
        version,
        discovery_url,
        username,
        password,
        collection_names,
        pagination_method,
        days,
        delay,
        type_to_pull,
        severity,
        reputation,
        batch_size,
        retraction_interval,
    )

def ensure_utc_aware(dt) -> datetime:
    """Ensure datetime is UTC-aware (timezone-aware, converted to UTC).

    Args:
        dt (datetime): A datetime object, either naive or aware.

    Returns:
        datetime: A timezone-aware datetime object in UTC.
    """
    if dt is None:
        return pytz.utc.localize(datetime.now())
    # If dt is timezone-naive, assume UTC. If it is already timezone-aware,
    # normalize it to UTC for consistent comparisons and serialization.
    if dt.tzinfo is None or dt.tzinfo.utcoffset(dt) is None:
        return pytz.utc.localize(dt)
    # If dt is timezone aware, ensure it is converted to UTC.
    return dt.astimezone(pytz.utc)

def str_to_datetime(
    string: str,
    date_format: str = DATE_FORMAT_STRING,
    replace_dot: bool = True,
    return_now_on_error: bool = True,
) -> datetime:
    """Convert ISO formatted string to datetime object.

    Args:
        string (str): ISO formatted string.

    Returns:
        datetime: Converted datetime object.
    """
    try:
        return datetime.strptime(
            string.replace(".", "") if replace_dot else string, date_format
        )
    except ValueError:
        return datetime.now() if return_now_on_error else None

def add_ce_user_agent(
    headers: Union[Dict, None] = None,
    plugin_name: str = PLATFORM_NAME,
    plugin_version: str = PLUGIN_VERSION,
) -> Dict:
    """Add User-Agent in the headers for third-party requests.
    Args:
        headers (Dict): Dictionary containing headers for any request.
    Returns:
        Dict: Dictionary after adding User-Agent.
    """
    if headers and USER_AGENT_KEY in headers:
        return headers

    headers = add_user_agent(headers)
    ce_added_agent = headers.get(USER_AGENT_KEY, DEFAULT_USER_AGENT)
    user_agent = USER_AGENT_FORMAT.format(
        ce_added_agent,
        MODULE_NAME.lower(),
        plugin_name.lower().replace(" ", "-"),
        plugin_version,
    )
    headers.update({USER_AGENT_KEY: user_agent})
    return headers
