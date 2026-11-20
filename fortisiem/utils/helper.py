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

FortiSIEM Plugin helper."""

import time

from jsonschema.validators import validator_for

from . import constants as CONST
from .exceptions import MappingValidationError


def compile_schema(schema):
    """Return a reusable validator for a JSON schema.

    jsonschema.validate() checks the schema again on every call, which is
    slow for a mapping with hundreds of fields.

    Args:
        schema (dict): JSON schema.

    Returns:
        Validator instance.
    """
    return validator_for(schema)(schema)


def get_nested_value(data, field_path):
    """Read a value from a dictionary using a dot separated path.

    Args:
        data (dict): Record.
        field_path (str): Dot separated path, e.g. "host_info.hostname".

    Returns:
        tuple: (value, exists). ``exists`` is False when a part of the
            path is missing.
    """
    current = data
    for part in field_path.split(CONST.NESTED_FIELD_SEPARATOR):
        if isinstance(current, dict) and part in current:
            current = current[part]
        else:
            return None, False
    return current, True


def build_syslog_header(
    log_source_identifier, exclude_timestamp, exclude_identifier
):
    """Build the Syslog header added in front of a JSON record.

    Args:
        log_source_identifier (str): Log Source Identifier.
        exclude_timestamp (bool): Leave out the timestamp.
        exclude_identifier (bool): Leave out the Log Source Identifier.

    Returns:
        str: Header, ending with a separator, or an empty string when
            both parts are excluded.
    """
    parts = []
    if not exclude_timestamp:
        parts.append(
            time.strftime(
                CONST.SYSLOG_TIMESTAMP_FORMAT, time.localtime(time.time())
            )
        )
    if not exclude_identifier:
        parts.append(log_source_identifier)
    if not parts:
        return ""
    return (
        CONST.SYSLOG_HEADER_SEPARATOR.join(parts)
        + CONST.SYSLOG_HEADER_SEPARATOR
    )


def transformation_compatibility_check(configuration):
    """Return True when the data must be sent in JSON format.

    Args:
        configuration (dict): Plugin configuration.

    Returns:
        bool: True for JSON, False for CEF.
    """
    transform_data = configuration.get(
        CONST.CONFIG_TRANSFORM_DATA, CONST.DEFAULT_FORMAT
    )
    if isinstance(transform_data, bool):
        # Boolean form, used by Cloud Exchange for plugins without
        # format options: True means CEF.
        return not transform_data
    return str(transform_data).strip().lower() == CONST.FORMAT_JSON


def get_exclude_flag_value(configuration, key):
    """Return the normalized value of an Exclude option.

    Args:
        configuration (dict): Plugin configuration.
        key (str): Configuration key.

    Returns:
        str: Lower case value, "no" when missing.
    """
    value = configuration.get(key, CONST.NO)
    if value is None:
        return CONST.NO
    return str(value).strip().lower()


def get_subtype_mapping(mappings, subtype):
    """Return the mapping of a subtype, ignoring the case.

    Args:
        mappings (dict): Mappings of a data type.
        subtype (str): Subtype.

    Returns:
        Mapping of the subtype.

    Raises:
        MappingValidationError: When the subtype has no mapping.
    """
    lowered = {key.lower(): value for key, value in mappings.items()}
    if subtype.lower() in lowered:
        return lowered[subtype.lower()]
    raise MappingValidationError(
        CONST.SUBTYPE_MAPPING_NOT_FOUND.format(subtype=subtype)
    )


def map_json_data(mappings, data):
    """Keep only the mapped fields of a record.

    Args:
        mappings (list): Field names, dot separated for nested fields.
            An empty list keeps the whole record.
        data (dict): Record.

    Returns:
        dict: Mapped record.
    """
    if mappings == [] or not data:
        return data
    mapped_dict = {}
    for key in mappings:
        if key in data:
            mapped_dict[key] = data[key]
            continue
        value, exists = get_nested_value(data, key)
        if exists:
            mapped_dict[key] = value
    return mapped_dict
