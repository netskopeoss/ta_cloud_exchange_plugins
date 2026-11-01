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

Azure Log Analytics Plugin Helper."""


import ipaddress
import json
import re
import sys
from typing import List, Union
from urllib.parse import ParseResult, urlparse
from jsonschema import validate

from .log_analytics_exception import (
    MappingValidationError,
)
from .log_analytics_constants import (
    HOSTNAME_LABEL_RE,
    MAX_CHUNK_SIZE_BYTES,
    PLUGIN_NAME,
    TOKEN_SCOPE_SUFFIX,
)
from jsonschema.exceptions import ValidationError as JsonSchemaValidationError


def validate_extension(instance):
    """Define JSON schema for validating mapped Azure Log
    Analytics extension fields.

    Args:
        instance: JSON instance to be validated
    """
    schema = {"type": "object", "minProperties": 0}

    validate(instance=instance, schema=schema)


def validate_header_extension_subdict(instance):
    """Validate sub dict of header and extension \
        having fields "mapping" and "default".

    Args:
        instance: JSON instance to be validated
    """
    # If both are empty
    if (
        "mapping_field" in instance
        and "default_value" in instance
        and (not instance["mapping_field"] and not instance["default_value"])
    ):
        raise JsonSchemaValidationError(
            'Both "mapping" and "default" can not be empty.'
        )

    # If only one is there and it is empty, that's not valid
    if (
        "mapping_field" in instance
        and "default_value" not in instance
        and (not instance["mapping_field"])
    ):
        raise JsonSchemaValidationError(
            '"mapping" field can not be empty as no "default" is provided.'
        )

    # If only one is there and it is empty, that's not valid
    if (
        "default_value" in instance
        and "mapping_field" not in instance
        and (not instance["default_value"])
    ):
        raise JsonSchemaValidationError(
            '"default" field can not be empty as no "mapping" is provided.'
        )


def validate_header(instance):
    """Define JSON schema for validating mapped Azure Log
    Analytics header fields.

    Args:
        instance: JSON instance to be validated
    """
    properties_schema = {
        "default_value": {"type": "string"},
        "mapping_field": {"type": "string"},
        "transformation": {"type": "string"},
    }

    one_of_sub_schema = [
        # both empty are not allowed. So schema will be:
        # one of (one of (both), both)
        {
            "oneOf": [
                {"required": ["mapping_field"]},
                {"required": ["default_value"]},
            ]
        },
        {
            "allOf": [
                {"required": ["mapping_field"]},
                {"required": ["default_value"]},
            ]
        },
    ]

    header_sub_schema = {
        "type": "object",
        "properties": properties_schema,
        "minProperties": 0,
        "maxProperties": 3,
        "oneOf": one_of_sub_schema,
    }

    schema = {
        "type": "object",
        "properties": {
            "Device Product": header_sub_schema,
            "Device Vendor": header_sub_schema,
            "Device Version": header_sub_schema,
            "Device Event Class ID": header_sub_schema,
            "Name": header_sub_schema,
            "Severity": header_sub_schema,
        },
    }

    validate(instance=instance, schema=schema)

    # After validating schema, validate the "mapping" and "default" fields
    # for each header fields
    for field in instance:
        validate_header_extension_subdict(instance[field])


def validate_extension_field(instance):
    """Define JSON schema for validating each extension fields.

    Args:
        instance: JSON instance to be validated
    """
    schema = {
        "type": "object",
        "properties": {
            "mapping_field": {"type": "string"},
            "default_value": {"type": "string"},
            "transformation": {"type": "string"},
            "is_json_path": {"type": "boolean"},
        },
        "minProperties": 0,
        "maxProperties": 4,
        "oneOf": [  # both empty are not allowed. So schema will be: one of (one of (both), both)  # noqa
            {
                "oneOf": [
                    {"required": ["mapping_field"]},
                    {"required": ["default_value"]},
                ]
            },
            {
                "allOf": [
                    {"required": ["mapping_field"]},
                    {"required": ["default_value"]},
                ]
            },
        ],
    }

    validate(instance=instance, schema=schema)
    validate_header_extension_subdict(instance)


def validate_log_analytics_mappings(mappings, data_type):
    """Read mapping json and return the dict of mappings \
        to be applied to raw_data.

    Args:
        data_type (str): Data type (alert/event) for which the mappings \
            are to be fetched
        mappings: Attribute mapping json string

    Returns:
        mapping delimiter, cef_version, log_analytics_mappings
    """
    data_type_specific_mapping = mappings["taxonomy"][data_type]

    if data_type == "json":
        return

    # Validate the headers of each mapped subtype
    for subtype, subtype_map in data_type_specific_mapping.items():
        subtype_header = subtype_map["header"]
        try:
            validate_header(subtype_header)
        except JsonSchemaValidationError as err:
            raise MappingValidationError(
                f'Error occurred while validating {PLUGIN_NAME} '
                f'header for type "{subtype}". Error: {err}.'
            )

    # Validate the extension for each mapped subtype
    for subtype, subtype_map in data_type_specific_mapping.items():
        subtype_extension = subtype_map["extension"]
        try:
            validate_extension(subtype_extension)
        except JsonSchemaValidationError as err:
            raise MappingValidationError(
                f'Error occurred while validating {PLUGIN_NAME} '
                f'extension for type "{subtype}". Error: {err}.'
            )

        # Validate each extension
        for cef_field, ext_dict in subtype_extension.items():
            try:
                validate_extension_field(ext_dict)
            except JsonSchemaValidationError as err:
                raise MappingValidationError(
                    f'Error occurred while validating {PLUGIN_NAME} '
                    f'extension field "{cef_field}" for type "{subtype}". '
                    f'Error: {err}.'
                )


def get_log_analytics_mappings(mappings):
    """Read mapping json and return the dict of mappings
    to be applied to raw_data.

    Args:
        mappings (dict): Attribute mapping json file.

    Returns:
        mapping delimiter, cef_version, log_analytics_mappings
    """
    return (
        mappings.get("delimiter", ""),
        mappings.get("cef_version", ""),
        mappings.get("taxonomy", {}),
    )


def extract_subtypes(mappings, data_type):
    """Extract subtypes of given data types. e.g: for data type "alert", \
        possible subtypes are "dlp", "policy" etc.

    Args:
        data_type (str): Data type (alert/event) for which the mappings \
            are to be fetched
        mappings: Attribute mapping json string

    Returns:
        extracted sub types
    """
    taxonomy = mappings["taxonomy"][data_type]
    return [subtype for subtype in taxonomy]


def split_into_size(data_list):
    """
    Split a list into parts, each approximately with a target size in MB.

    The size is a fast in-memory estimate. It can be lower than the actual
    request body for non-ASCII data, so the caller re-splits a part with
    :func:`split_by_json_size` when its body exceeds the API limit.

    Parameters:
    - data_list: The list of data to be split.

    Returns:
    A list of parts, each with a total size approximately equal to \
        the target size.
    """
    result = []
    current_part = []
    current_size_mb = 0

    for item in data_list:
        item_size_mb = sys.getsizeof(f"{item}") / (1024 * 1024)  # Convert bytes to MB  # noqa
        if current_size_mb + item_size_mb <= 1:
            current_part.append(item)
            current_size_mb += item_size_mb
        else:
            if current_part:
                result.append(current_part)
            current_part = [item]
            current_size_mb = item_size_mb

    if current_part:
        result.append(current_part)

    return result


def split_by_json_size(
    data_list: List, max_bytes: int = MAX_CHUNK_SIZE_BYTES
) -> List:
    """
    Split a list into parts so that the JSON request body of each part
    stays within ``max_bytes``.

    Used as a fallback for a part from :func:`split_into_size` whose
    actual request body exceeds the API limit. The size of every item is
    measured on its serialized JSON form, the same way the request body is
    built (``json.dumps``), so non-ASCII data, which is escaped to
    ``\\uXXXX`` in the body, is accounted for.

    Parameters:
    - data_list: The list of data to be split.
    - max_bytes: Maximum size in bytes of the JSON body of a part.

    Returns:
    A list of parts. A single item larger than ``max_bytes`` is placed in
    a part of its own.
    """
    result = []
    current_part = []
    current_size = 2  # enclosing "[" and "]"

    for item in data_list:
        # default=str keeps the size estimate from raising on a value that
        # is not JSON serializable; such a part then fails on its own when
        # the request body is built, as before.
        item_size = len(json.dumps(item, default=str)) + 2  # item and ", "
        if current_part and current_size + item_size > max_bytes:
            result.append(current_part)
            current_part = []
            current_size = 2
        current_part.append(item)
        current_size += item_size

    if current_part:
        result.append(current_part)

    return result


def _is_valid_hostname(host: str) -> bool:
    """Check that the host is a DNS name (not an IP address)."""
    if not host or len(host) > 253:
        return False
    try:
        ipaddress.ip_address(host)
        return False
    except ValueError:
        pass
    labels = host.split(".")
    return len(labels) > 1 and all(
        re.match(HOSTNAME_LABEL_RE, label) for label in labels
    )


def _parse_https_url(
    value, strict_hostname: bool = True
) -> Union[ParseResult, None]:
    """Parse an https URL without userinfo, query or fragment.

    Args:
        value: Value to parse. Anything other than a string is invalid.
        strict_hostname (bool): Require a DNS hostname (not an IP address
            or a single label); otherwise any non-empty hostname is
            accepted.

    Returns:
        ParseResult: Parsed URL, or None if invalid.
    """
    if not isinstance(value, str):
        return None
    try:
        parsed = urlparse(value.strip())
        parsed.port  # raises ValueError for an invalid port
    except ValueError:
        return None
    hostname = parsed.hostname or ""
    if (
        parsed.scheme != "https"
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
        or not hostname
        or (strict_hostname and not _is_valid_hostname(hostname))
    ):
        return None
    return parsed


def normalize_authority_host(value: Union[str, None]) -> str:
    """Normalize the Microsoft Entra ID authority host of a custom cloud.

    Accepts a bare hostname or an https URL of the host (e.g.
    ``login.microsoftonline.us`` or ``https://login.microsoftonline.us/``).

    Args:
        value (str): Value provided by the user.

    Returns:
        str: Lowercase hostname, or an empty string if the value is not a
            valid https hostname (e.g. http scheme, port, userinfo, path
            or an IP address).
    """
    if not isinstance(value, str) or not value.strip():
        return ""
    value = value.strip()
    if "://" not in value:
        value = f"https://{value}"
    parsed = _parse_https_url(value)
    if not parsed or parsed.port or parsed.path.strip("/") or parsed.params:
        return ""
    return parsed.hostname


def normalize_token_scope(value: Union[str, None]) -> str:
    """Normalize the token scope (audience) of a custom cloud.

    ``/.default`` is appended when it is not already present, so both
    ``https://monitor.azure.us`` and ``https://monitor.azure.us/.default``
    are accepted.

    Args:
        value (str): Value provided by the user.

    Returns:
        str: Scope, or an empty string if the value is not a valid https
            URL.
    """
    if not _parse_https_url(value):
        return ""
    scope = value.strip().rstrip("/")
    if scope.endswith(TOKEN_SCOPE_SUFFIX):
        return scope
    return scope + TOKEN_SCOPE_SUFFIX


def is_valid_dce_uri(value: Union[str, None]) -> bool:
    """Check that the DCE URI is an https URL with a hostname.

    The hostname format itself is not restricted, so that any endpoint
    host accepted by Azure keeps working.

    Args:
        value (str): DCE URI.

    Returns:
        bool: True if valid.
    """
    return _parse_https_url(value, strict_hostname=False) is not None
