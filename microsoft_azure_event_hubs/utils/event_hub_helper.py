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

Microsoft Azure Event Hubs Plugin Helper Module.
"""

from jsonschema import validate

from .event_hub_exceptions import (
    MappingValidationError,
)
from .event_hub_constants import (
    LOG_SOURCE_IDENTIFIER,
    DEFAULT_BATCH_SIZE,
    DEFAULT_BUFFER_MEMORY,
    DEFAULT_MAX_BLOCK_TIME,
    DEFAULT_LINGER_TIME,
    DEFAULT_CHUNK_SIZE,
    DEFAULT_PORT,
    FLUSH_TIMEOUT
)
from jsonschema.exceptions import ValidationError as JsonSchemaValidationError
from typing import List


def validate_extension(instance):
    """Define JSON schema for validating mapped Microsoft\
        Azure Event Hubs extension fields.

    Args:
        instance: JSON instance to be validated
    """
    schema = {"type": "object", "minProperties": 0}

    validate(instance=instance, schema=schema)


def validate_header_extension_subdict(instance):
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
    """Define JSON schema for validating mapped Microsoft Azure Event Hubs\
          header fields.

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
    validate_header_extension_subdict(instance)


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


def validate_event_hubs_mappings(mappings, data_type):
    """Read mapping json and validate the dict of mappings.

    Args:
        data_type (str): Data type (alert/event) for which
        the mappings are to be fetched
        mappings: Attribute mapping json string

    Raises:
        MappingValidationError: For in-valid mapping \
            json for any of the data_type.
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
                'Error occurred while validating Microsoft Azure Event Hubs '
                'header for type "{}". '
                "Error: {}".format(subtype, err)
            )

    # Validate the extension for each mapped subtype
    for subtype, subtype_map in data_type_specific_mapping.items():
        subtype_extension = subtype_map["extension"]
        try:
            validate_extension(subtype_extension)
        except JsonSchemaValidationError as err:
            raise MappingValidationError(
                'Error occurred while validating Microsoft Azure Event Hubs '
                'extension for type "{}". '
                "Error: {}".format(subtype, err)
            )

        # Validate each extension
        for cef_field, ext_dict in subtype_extension.items():
            try:
                validate_extension_field(ext_dict)
            except JsonSchemaValidationError as err:
                raise MappingValidationError(
                    'Error occurred while validating Microsoft Azure Event'
                    ' Hubs extension field "{}" for '
                    'type "{}". Error: {}'.format(cef_field, subtype, err)
                )


def get_event_hubs_mappings(mappings):
    """Read mapping json and return the dict of mappings
    to be applied to raw_data.

    Args:
        mappings (dict): Attribute mapping json file.

    Returns:
        mapping delimiter, cef_version, syslog_mappings
    """
    return (
        mappings.get("delimiter", ""),
        mappings.get("cef_version", ""),
        mappings.get("taxonomy", {}),
    )


def get_config_params(configurations, params_to_get: List[str] = None):
    """get the reequired configuration parameters

    Args:
        configurations (dict): configuration parameters
        params_to_get (List[str]): list of parameters to get

    Returns:
        configuration parameters
    """
    all_params = {
        "namespace_name": configurations.get("namespace_name", "").strip(),
        "port": configurations.get("port", DEFAULT_PORT),
        "connection_string": (
            configurations.get("connection_string", "").strip()
        ),
        "event_hub_name": configurations.get("event_hub_name", "").strip(),
        "log_source_identifier": configurations.get(
            "log_source_identifier", LOG_SOURCE_IDENTIFIER
        ),
        "skip_timestamp_field": configurations.get(
            "skip_timestamp_field", "no"
        ),
        "skip_log_source_identifier_field": configurations.get(
            "skip_log_source_identifier_field", "no"
        ),
        "batch_size": configurations.get(
            "batch_size", DEFAULT_BATCH_SIZE
        ),
        "buffer_memory": configurations.get(
            "buffer_memory", DEFAULT_BUFFER_MEMORY
        ),
        "max_block_time": configurations.get(
            "max_block_time", DEFAULT_MAX_BLOCK_TIME
        ),
        "linger_time": configurations.get(
            "linger_time", DEFAULT_LINGER_TIME
        ),
        "chunk_size": configurations.get("chunk_size", DEFAULT_CHUNK_SIZE),
        "flush_timeout": configurations.get("flush_timeout", FLUSH_TIMEOUT),
        "bootstrap_server": "{}.servicebus.windows.net:{}".format(
            configurations.get("namespace_name", "").strip(),
            configurations.get("port", DEFAULT_PORT),
        ),
    }

    if not params_to_get:
        return tuple(all_params.values())
    result = [all_params.get(param) for param in params_to_get]

    return result[0] if len(result) == 1 else tuple(result)
