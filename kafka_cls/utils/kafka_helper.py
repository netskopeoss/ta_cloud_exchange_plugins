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

Kafka Plugin Helper Module.
"""


from jsonschema import validate

from .kafka_exceptions import (
    MappingValidationError,
)
from jsonschema.exceptions import ValidationError as JsonSchemaValidationError


def validate_extension(instance):
    """Define JSON schema for validating mapped Kafka extension fields.

    Args:
        instance: JSON instance to be validated
    """
    schema = {"type": "object", "minProperties": 0}

    validate(instance=instance, schema=schema)


def validate_header_extension_subdict(instance, log_prefix):
    """Validate sub dict of header and extension having fields
    "mapping" and "default".

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
            '{}: Both "mapping" and "default" can not be empty'.format(
                log_prefix
            )
        )

    # If only one is there and it is empty, that's not valid
    if (
        "mapping_field" in instance
        and "default_value" not in instance
        and (not instance["mapping_field"])
    ):
        raise JsonSchemaValidationError(
            '{}: "mapping" field can not be empty as no "default"'
            " is provided".format(log_prefix)
        )

    # If only one is there and it is empty, that's not valid
    if (
        "default_value" in instance
        and "mapping_field" not in instance
        and (not instance["default_value"])
    ):
        raise JsonSchemaValidationError(
            '{}: "default" field can not be empty as no '
            '"mapping" is provided'.format(log_prefix)
        )


def validate_header(instance, log_prefix):
    """Define JSON schema for validating mapped Kafka header fields.

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
        validate_header_extension_subdict(instance[field], log_prefix)


def validate_extension_field(instance, log_prefix):
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
        "oneOf": [  # both empty are not allowed. So schema will be:
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
        ],
    }

    validate(instance=instance, schema=schema)
    validate_header_extension_subdict(instance, log_prefix)


def get_kafka_mappings(mappings, data_type, log_prefix):
    """Read mapping json and return the dict of mappings to be applied
    to raw_data.

    Args:
        data_type (str): Data type (alert/event) for which the mappings are t
        o be fetched
        mappings: Attribute mapping json string

    Returns:
        mapping delimiter, cef_version, kafka_mappings
    """
    data_type_specific_mapping = mappings["taxonomy"][data_type]

    if data_type == "json":
        return (
            mappings["delimiter"],
            mappings["cef_version"],
            mappings["taxonomy"],
        )

    # Validate the headers of each mapped subtype
    for subtype, subtype_map in data_type_specific_mapping.items():
        subtype_header = subtype_map["header"]
        try:
            validate_header(subtype_header, log_prefix)
        except JsonSchemaValidationError as err:
            raise MappingValidationError(
                "{}: Error occurred while validating"
                ' Kafka header for type "{}" Error: {}'.format(
                    log_prefix, subtype, err
                )
            )

    # Validate the extension for each mapped subtype
    for subtype, subtype_map in data_type_specific_mapping.items():
        subtype_extension = subtype_map["extension"]
        try:
            validate_extension(subtype_extension)
        except JsonSchemaValidationError as err:
            raise MappingValidationError(
                "{}: Error occurred while validating Kafka extension"
                ' for type "{}". Error: {}'.format(log_prefix, subtype, err)
            )

        # Validate each extension
        for cef_field, ext_dict in subtype_extension.items():
            try:
                validate_extension_field(ext_dict, log_prefix)
            except JsonSchemaValidationError as err:
                raise MappingValidationError(
                    "{}: Error occurred while validating Kafka extension field"
                    ' "{}" for type "{}". Error: {}'.format(
                        log_prefix, cef_field, subtype, err
                    )
                )

    return mappings["delimiter"], mappings["cef_version"], mappings["taxonomy"]


def extract_subtypes(mappings, data_type):
    """Extract subtypes of given data types. e.g: for data type "alert",
    possible subtypes are "dlp", "policy" etc.

    Args:
        data_type (str): Data type (alert/event) for which the mappings are
        to be fetched
        mappings: Attribute mapping json string

    Returns:
        extracted sub types
    """
    taxonomy = mappings["taxonomy"][data_type]
    return [subtype for subtype in taxonomy]


def get_subtype_mapping(mappings, subtype):
    """Retrieve subtype mappings (mappings for subtypes of alerts/events)
    case insensitively.

    Shared by both the CEF and JSON transform paths in main.py.

    Args:
        mappings: Mapping JSON from which subtypes are to be retrieved
        subtype: Subtype (e.g. DLP for alerts) for which the mapping is
            to be fetched

    Returns:
        Fetched mapping JSON object
    """
    mappings = {k.lower(): v for k, v in mappings.items()}
    if subtype.lower() in mappings:
        return mappings[subtype.lower()]
    else:
        return mappings[subtype.upper()]


def get_nested_field_value(data, field_path, logger=None, log_prefix=None):
    """Extract a value from a nested dict using dot notation.

    Used as the fallback lookup for JSON-mode selective field
    ingestion when a mapped field name (e.g. "host_info.device_make")
    is not a literal top-level key in the record.

    Args:
        data: The record dictionary to search.
        field_path: Dot-separated field path.
        logger: Optional plugin logger, used to report unexpected
            lookup errors (e.g. a non-string field_path).
        log_prefix: Optional plugin log prefix, used with ``logger``.

    Returns:
        tuple: (value, exists) where exists is True only if every
        segment of the path resolved.
    """
    try:
        current_data = data
        for part in field_path.split("."):
            if isinstance(current_data, dict) and part in current_data:
                current_data = current_data[part]
            else:
                return None, False
        return current_data, True
    except Exception as exp:
        if logger:
            logger.error(
                message=(
                    f"{log_prefix}: Error occurred while getting the "
                    f"nested field value for '{field_path}'. Error: {exp}"
                ),
                resolution=(
                    "Ensure that the JSON mapping field names use valid "
                    "dot-notation for nested Netskope fields."
                ),
            )
        return None, False


def map_json_data(mappings, data, logger=None, log_prefix=None):
    """Filter the raw data and returns the filtered data.

    Each listed field name is resolved as a literal top-level key
    first; if that fails, it falls back to a dot-notation nested
    lookup (e.g. "host_info.device_make") via
    :func:`get_nested_field_value`, so selective field ingestion also
    works for nested Netskope fields. A name that resolves neither way
    is simply omitted from the output.

    Args:
        mappings (list): List of fields to be pushed
        data (dict): Data to be mapped (retrieved from Netskope)
        logger: Optional plugin logger, forwarded to
            :func:`get_nested_field_value`.
        log_prefix: Optional plugin log prefix, forwarded to
            :func:`get_nested_field_value`.

    Returns:
        dict: Mapped data based on fields given in mapping file
    """
    if not (mappings and data):
        # If mapping is empty or data is empty return data.
        return data

    mapped_dict = {}
    data_keys = data.keys()
    for key in mappings:
        if key in data_keys:
            mapped_dict[key] = data[key]
        else:
            value, field_exists = get_nested_field_value(
                data, key, logger, log_prefix
            )
            if field_exists:
                mapped_dict[key] = value

    return mapped_dict
