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

QRadar Plugin helper."""

import time

from jsonpath import jsonpath
from jsonschema.exceptions import ValidationError as JsonSchemaValidationError
from jsonschema.validators import validator_for

from netskope.integrations.cls.utils.converter import type_converter

from . import constants as CONST
from .exceptions import FieldNotFoundError, MappingValidationError


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


header_validator = compile_schema(CONST.HEADER_SCHEMA)
extension_validator = compile_schema(CONST.EXTENSION_SCHEMA)
extension_field_validator = compile_schema(CONST.EXTENSION_FIELD_SCHEMA)


def validate_header_extension_subdict(instance):
    """Validate the "mapping_field" and "default_value" of a field.

    Args:
        instance (dict): Header or extension field mapping.

    Raises:
        JsonSchemaValidationError: When the field is not an object, both
            values are empty, or the only value present is empty.
    """
    if not isinstance(instance, dict):
        raise JsonSchemaValidationError(CONST.MAPPING_FIELD_TYPE_ERROR)
    transformation = instance.get(CONST.MAPPING_TRANSFORMATION)
    if transformation is not None and transformation not in type_converter():
        raise JsonSchemaValidationError(
            CONST.MAPPING_TRANSFORMATION_ERROR.format(
                transformation=transformation
            )
        )
    has_mapping = CONST.MAPPING_FIELD in instance
    has_default = CONST.MAPPING_DEFAULT_VALUE in instance
    mapping = instance.get(CONST.MAPPING_FIELD)
    default = instance.get(CONST.MAPPING_DEFAULT_VALUE)
    if has_mapping and has_default and not mapping and not default:
        raise JsonSchemaValidationError(CONST.MAPPING_BOTH_EMPTY_ERROR)
    if has_mapping and not has_default and not mapping:
        raise JsonSchemaValidationError(CONST.MAPPING_FIELD_EMPTY_ERROR)
    if has_default and not has_mapping and not default:
        raise JsonSchemaValidationError(CONST.MAPPING_DEFAULT_EMPTY_ERROR)


def validate_header(instance):
    """Validate the CEF header mapping of a subtype.

    Args:
        instance (dict): Header mapping.
    """
    header_validator.validate(instance)
    for field in instance:
        validate_header_extension_subdict(instance[field])


def validate_extension_field(instance):
    """Validate one CEF extension field mapping.

    Args:
        instance (dict): Extension field mapping.
    """
    extension_field_validator.validate(instance)
    validate_header_extension_subdict(instance)


def validate_qradar_mappings(mappings, data_type):
    """Validate the CEF mapping of every subtype of a data type.

    Args:
        mappings (dict): Parsed mapping file.
        data_type (str): Data type to validate (alerts, events, ...).

    Raises:
        MappingValidationError: When a header or extension is not valid.
    """
    if data_type == CONST.MAPPING_JSON:
        return
    data_type_mapping = mappings[CONST.MAPPING_TAXONOMY][data_type]
    for subtype, subtype_mapping in data_type_mapping.items():
        try:
            validate_header(subtype_mapping[CONST.MAPPING_HEADER])
        except JsonSchemaValidationError as err:
            raise MappingValidationError(
                CONST.MAPPING_HEADER_ERROR.format(
                    subtype=subtype, error=err.message
                )
            ) from err
        extension = subtype_mapping[CONST.MAPPING_EXTENSION]
        try:
            extension_validator.validate(extension)
        except JsonSchemaValidationError as err:
            raise MappingValidationError(
                CONST.MAPPING_EXTENSION_ERROR.format(
                    subtype=subtype, error=err.message
                )
            ) from err
        for cef_field, field_mapping in extension.items():
            try:
                validate_extension_field(field_mapping)
            except JsonSchemaValidationError as err:
                raise MappingValidationError(
                    CONST.MAPPING_EXTENSION_FIELD_ERROR.format(
                        field=cef_field, subtype=subtype, error=err.message
                    )
                ) from err


def get_qradar_mappings(mappings):
    """Return the parts of the mapping file used by the transformation.

    Args:
        mappings (dict): Parsed mapping file.

    Returns:
        tuple: delimiter, CEF version and taxonomy.
    """
    return (
        mappings.get(CONST.MAPPING_DELIMITER, ""),
        mappings.get(CONST.MAPPING_CEF_VERSION, ""),
        mappings.get(CONST.MAPPING_TAXONOMY, {}),
    )


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


def get_timestamp_value(field_mapping, value):
    """Convert a "Time Stamp" value to an integer when possible.

    Args:
        field_mapping (dict): Field mapping.
        value: Value read from the record.

    Returns:
        int: Converted value, or None when it is not a timestamp.
    """
    if (
        field_mapping.get(CONST.MAPPING_TRANSFORMATION)
        != CONST.TRANSFORMATION_TIMESTAMP
        or not value
    ):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def get_mapping_value_from_field(data, field):
    """Return the value of a field and whether it has data.

    Args:
        data (dict): Record.
        field (str): Field name.

    Returns:
        tuple: (value, mapped). "null" and False for an empty value.
    """
    value = data[field]
    if value or isinstance(value, int):
        return value, True
    return CONST.NULL_VALUE, False


def get_field_value_from_data(field_mapping, data, is_json_path=False):
    """Return the value of a mapped CEF field.

    The value comes from "mapping_field" when it is in the record (JSON
    path, exact key, then dot separated path), otherwise from
    "default_value".

    Args:
        field_mapping (dict): Field mapping.
        data (dict): Record.
        is_json_path (bool): "mapping_field" is a JSON path.

    Returns:
        tuple: (value, mapped) where mapped is True when the value comes
            from the record.

    Raises:
        FieldNotFoundError: When the field is missing and there is no
            default value.
    """
    mapping_field = field_mapping.get(CONST.MAPPING_FIELD)
    if not mapping_field:
        return field_mapping[CONST.MAPPING_DEFAULT_VALUE], False
    if is_json_path:
        values = jsonpath(data, mapping_field)
        if values:
            return (
                CONST.JSON_PATH_VALUE_SEPARATOR.join(map(str, values)),
                True,
            )
        raise FieldNotFoundError(mapping_field)
    if mapping_field in data:
        timestamp = get_timestamp_value(field_mapping, data[mapping_field])
        if timestamp is not None:
            return timestamp, True
        return get_mapping_value_from_field(data, mapping_field)
    value, exists = get_nested_value(data, mapping_field)
    if exists:
        timestamp = get_timestamp_value(field_mapping, value)
        if timestamp is not None:
            return timestamp, True
        if value or isinstance(value, int):
            return value, True
        return CONST.NULL_VALUE, False
    if CONST.MAPPING_DEFAULT_VALUE in field_mapping:
        return field_mapping[CONST.MAPPING_DEFAULT_VALUE], False
    raise FieldNotFoundError(mapping_field)


def uses_tenant_name(header_mappings):
    """Return True when a header defaults to "$tenant_name".

    Args:
        header_mappings (dict): Header mapping of the subtype.

    Returns:
        bool: True when the tenant name is needed.
    """
    return any(
        str(mapping.get(CONST.MAPPING_DEFAULT_VALUE, "")).lower()
        == CONST.TENANT_NAME_VARIABLE
        for mapping in header_mappings.values()
        if isinstance(mapping, dict)
    )


def get_headers(header_mappings, data, data_type, tenant_name=None):
    """Build the CEF header values of a record.

    Args:
        header_mappings (dict): Header mapping of the subtype.
        data (dict): Record.
        data_type (str): Data type.
        tenant_name (str): Value of "$tenant_name"; not used for WebTx.

    Returns:
        tuple: (headers, mapped) where mapped is True when at least one
            value comes from the record.
    """
    headers = {}
    mapped_field_flag = False
    for cef_header, header_mapping in header_mappings.items():
        try:
            value, mapped_field = get_field_value_from_data(
                header_mapping, data
            )
        except FieldNotFoundError:
            continue
        mapped_field_flag = mapped_field_flag or mapped_field
        if (
            tenant_name is not None
            and data_type != CONST.WEBTX
            and isinstance(value, str)
            and value.lower() == CONST.TENANT_NAME_VARIABLE
        ):
            value = tenant_name
        headers[cef_header] = value
    return headers, mapped_field_flag


def get_extensions(extension_mappings, data):
    """Build the CEF extension values of a record.

    Args:
        extension_mappings (dict): Extension mapping of the subtype.
        data (dict): Record.

    Returns:
        tuple: (extensions, mapped) where mapped is True when at least
            one value comes from the record.
    """
    extension = {}
    mapped_field_flag = False
    for cef_extension, extension_mapping in extension_mappings.items():
        try:
            value, mapped_field = get_field_value_from_data(
                extension_mapping,
                data,
                is_json_path=CONST.MAPPING_IS_JSON_PATH in extension_mapping,
            )
        except FieldNotFoundError:
            continue
        extension[cef_extension] = value
        mapped_field_flag = mapped_field_flag or mapped_field
    return extension, mapped_field_flag
