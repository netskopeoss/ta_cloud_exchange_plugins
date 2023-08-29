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
"""

"""CrowdStrike LogScale Helper."""


from typing import Dict
from jsonschema import validate
from netskope.common.utils import add_user_agent
from jsonschema.exceptions import ValidationError as JsonSchemaValidationError
from .crowdstrike_logscale_exception import (
    MappingValidationError,
)
from .crowdstrike_logscale_constant import (
    PLUGIN_VERSION,
    PLATFORM_NAME,
    MODULE_NAME,
)


def map_crowdstrike_logscale_data(mappings, data, logger, data_type, subtype):
    """Filter the raw data and returns the filtered data,
    which will be further pushed to CrowdStrike LogScale.

    :param mappings: List of fields to be pushed to CrowdStrike LogScale
    (read from mapping string)
    :param data: Data to be mapped (retrieved from Netskope)
    :param logger: Logger object for logging purpose
    :param data_type: The type of data being mapped (alerts/events)
    :param subtype: The subtype of data being mapped
    (for example DLP is a subtype of alerts data type)
    :return: Mapped data based on fields given in mapping file
    """
    mapped_dict = {}
    ignored_fields = []
    for key in mappings:
        if key in data:
            mapped_dict[key] = data[key]
        else:
            ignored_fields.append(key)

    return mapped_dict


def validate_subtype(instance):
    """Validate the subtype object mapped in mapping JSON files.

    :param instance: The subtype object to be validated
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
    CrowdStrike LogScale header fields.

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
    CrowdStrike LogScale extension fields.

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


def get_crowdstrike_logscale_mappings(mappings, data_type):
    """Return the dict of mappings to be applied to raw data.

    :param mappings: Mapping String
    :param data_type: Data type (alert/event) for which
    the mappings are to be fetched
    :return: Read mappings
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
                "Error occurred while validating {} header for "
                'type "{}" Error: {}'.format(PLATFORM_NAME, subtype, err)
            )

    # Validate the extension for each mapped subtype
    for subtype, subtype_map in data_type_specific_mapping.items():
        subtype_extension = subtype_map["extension"]
        try:
            validate_extension(subtype_extension)
        except JsonSchemaValidationError as err:
            raise MappingValidationError(
                "Error occurred while validating {} extension "
                'for type "{}". Error: {}'.format(PLATFORM_NAME, subtype, err)
            )

        # Validate each extension
        for cef_field, ext_dict in subtype_extension.items():
            try:
                validate_extension_field(ext_dict)
            except JsonSchemaValidationError as err:
                raise MappingValidationError(
                    "Error occurred while validating {} extension "
                    'field "{}" for type "{}". Error: {}'.format(
                        PLATFORM_NAME, cef_field, subtype, err
                    )
                )
    return mappings["delimiter"], mappings["cef_version"], mappings["taxonomy"]


def _add_user_agent(headers=None) -> str:
    """Add Client Name to request plugin make.

    Returns:
        str: String containing the Client Name.
    """
    headers = add_user_agent(headers)
    ce_added_agent = headers.get("User-Agent", "netskope-ce")
    user_agent = "{}-{}-{}/{}".format(
        ce_added_agent,
        MODULE_NAME.lower(),
        PLATFORM_NAME.replace(" ", "-").lower(),
        PLUGIN_VERSION,
    )
    headers.update({"User-Agent": user_agent})
    return headers
