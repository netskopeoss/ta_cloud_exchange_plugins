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

CrowdStrike Next-Gen SIEM Helper
"""

import json
import sys

from jsonschema import validate
from jsonschema.exceptions import ValidationError as JsonSchemaValidationError

from .constant import MAX_PAYLOAD_CHUNK_SIZE_IN_BYTES, PLATFORM_NAME
from .exception import MappingValidationError


def validate_subtype(instance):
    """Validate the subtype object mapped in mapping JSON files.

    Args:
      instance(List): The subtype object to be validated
    """
    schema = {
        "type": "array",
    }

    validate(instance=instance, schema=schema)


def validate_header_extension_subdict(instance):
    """Validate sub dict of header and extension having
    fields "mapping" and "default".

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
            'Both "mapping" and "default" can not be empty'
        )

    # If only one is there and it is empty, that's not valid
    if (
        "mapping_field" in instance
        and "default_value" not in instance
        and (not instance["mapping_field"])
    ):
        raise JsonSchemaValidationError(
            '"mapping" field can not be empty as no "default" is provided'
        )

    # If only one is there and it is empty, that's not valid
    if (
        "default_value" in instance
        and "mapping_field" not in instance
        and (not instance["default_value"])
    ):
        raise JsonSchemaValidationError(
            '"default" field can not be empty as no "mapping" is provided'
        )


def validate_header(instance):
    """Define JSON schema for validating mapped
    CrowdStrike Next-Gen SIEM header fields.

    Args:
        instance: JSON instance to be validated
    """
    properties_schema = {
        "default_value": {"type": "string"},
        "mapping_field": {"type": "string"},
        "transformation": {"type": "string"},
    }

    one_of_sub_schema = [
        # both empty are not allowed.
        # So schema will be: one of (one of (both), both)
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


def validate_extension(instance):
    """Define JSON schema for validating mapped
    CrowdStrike Next-Gen SIEM extension fields.

    Args:
        instance: JSON instance to be validated
    """
    schema = {"type": "object", "minProperties": 0}

    validate(instance=instance, schema=schema)


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
        "oneOf": [
            # both empty are not allowed.
            # So schema will be: one of (one of (both), both)
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


def get_crowdstrike_ngsiem_mappings(mappings, data_type):
    """Return the dict of mappings to be applied to raw data.

    Args:
        mappings: Mapping String
        data_type: Data type (alert/event) for which
        the mappings are to be fetched
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
            validate_header(subtype_header)
        except JsonSchemaValidationError as err:
            raise MappingValidationError(
                f"Error occurred while validating {PLATFORM_NAME} header for "
                f'type "{subtype}" Error: {err}'
            )

    # Validate the extension for each mapped subtype
    for subtype, subtype_map in data_type_specific_mapping.items():
        subtype_extension = subtype_map["extension"]
        try:
            validate_extension(subtype_extension)
        except JsonSchemaValidationError as err:
            raise MappingValidationError(
                f"Error occurred while validating {PLATFORM_NAME} extension "
                f'for type "{subtype}". Error: {err}'
            )

        # Validate each extension
        for cef_field, ext_dict in subtype_extension.items():
            try:
                validate_extension_field(ext_dict)
            except JsonSchemaValidationError as err:
                raise MappingValidationError(
                    f"Error occurred while validating {PLATFORM_NAME} "
                    f'extension field "{cef_field}" for type "{subtype}".'
                    f" Error: {err}"
                )
    return (
        mappings["delimiter"],
        mappings["cef_version"],
        mappings["taxonomy"],
    )


def split_into_size(total_payload, log_fields):
    """
    Split a list into parts, each approximately with a target
    size in 1024 bytes.

    Parameters:
    - total_payload: The list of data to be split.

    Returns:
    - A list of parts, each with a total size approximately equal
      to the target size.
    """
    result = []
    current_part = []
    current_size_bytes = 0

    for chunk in total_payload:
        updated_chunk = json.dumps(
            {
                "event": chunk,
                "timestamp": chunk.get("timestamp"),
                "fields": log_fields,
            }
        )
        item_size_bytes = sys.getsizeof(updated_chunk)
        if (
            current_size_bytes + item_size_bytes
            >= MAX_PAYLOAD_CHUNK_SIZE_IN_BYTES
        ):
            result.append(current_part)
            current_part = []
            current_size_bytes = 0

        current_part.append(updated_chunk)
        current_size_bytes += item_size_bytes

    if current_part:
        result.append(current_part)

    return result
