"""
BSD 3-Clause License

Copyright (c) 2021, Netskope OSS
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice,
   this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its
   contributors may be used to endorse or promote products derived from
   this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
POSSIBILITY OF SUCH DAMAGE.

AWS CloudWatch CLS Plugin mapping helper.
"""

from typing import Tuple

from jsonschema import validate
from jsonschema.exceptions import ValidationError as JsonSchemaValidationError

from .constants import (
    CUSTOM_REGION_VALUE,
    PARTITION_AWS,
    PARTITION_AWS_CN,
    PARTITION_AWS_US_GOV,
    ROLES_ANYWHERE_DOMAIN,
    UNSUPPORTED_REGION_MARKERS,
    UNSUPPORTED_REGION_PREFIXES,
)
from .exceptions import MappingValidationError


def get_effective_region(configuration) -> str:
    """Get the region used everywhere, in one place.

    The CLS module supports a single dynamic configuration trigger and
    `authentication_method` already uses it, so the custom region field
    is always rendered and is only meaningful when the dropdown is set
    to 'Custom Region'.

    Args:
        configuration: Plugin configuration parameters.

    Returns:
        str: The trimmed custom region when the dropdown is set to
            custom, otherwise the trimmed dropdown value. Empty when
            neither is set.
    """
    selected = configuration.get("region_name")
    selected = selected.strip() if isinstance(selected, str) else ""
    if selected == CUSTOM_REGION_VALUE:
        custom = configuration.get("custom_region_name")
        return custom.strip() if isinstance(custom, str) else ""
    return selected


def get_region_partition(region: str):
    """Get the AWS partition of a region.

    Ported from aws_s3_edm.

    Args:
        region (str): Region code.

    Returns:
        str: ``aws``, ``aws-cn`` or ``aws-us-gov``; None for the ISO and
            AWS European Sovereign Cloud (``eusc-``) regions, which
            cannot be represented. Other unknown prefixes fall back to
            ``aws``.
    """
    if region.startswith("cn-"):
        return PARTITION_AWS_CN
    if region.startswith("us-gov-"):
        return PARTITION_AWS_US_GOV
    if region.startswith(UNSUPPORTED_REGION_PREFIXES) or any(
        marker in region for marker in UNSUPPORTED_REGION_MARKERS
    ):
        return None
    return PARTITION_AWS


def get_roles_anywhere_host(region: str) -> str:
    """Build the IAM Roles Anywhere endpoint host of a region.

    Ported from aws_s3_edm.

    Args:
        region (str): Region code of a supported partition.

    Returns:
        str: ``rolesanywhere.<region>.amazonaws.com`` (``.com.cn`` for
            China regions).
    """
    domain = ROLES_ANYWHERE_DOMAIN.get(
        get_region_partition(region) or PARTITION_AWS
    )
    return f"rolesanywhere.{region}.{domain}"


def validate_extension(instance) -> None:
    """Check that a CEF extension block is an object.

    Args:
        instance: Extension block read from the mapping file.
    """
    schema = {"type": "object", "minProperties": 0}
    validate(instance=instance, schema=schema)


def validate_header_extension_subdict(instance, name) -> None:
    """Check the mapping_field and default_value pair of one field.

    Args:
        instance: Mapping block of a single CEF header or extension field.
        name: Configuration name, kept for message context.

    Raises:
        JsonSchemaValidationError: When both values are empty, or when the
            only value present is empty.
    """
    # Both present but empty is not allowed.
    if (
        "mapping_field" in instance
        and "default_value" in instance
        and (not instance["mapping_field"] and not instance["default_value"])
    ):
        raise JsonSchemaValidationError(
            'Both "mapping" and "default" can not be empty'
        )

    # Only mapping_field present and it is empty.
    if (
        "mapping_field" in instance
        and "default_value" not in instance
        and (not instance["mapping_field"])
    ):
        raise JsonSchemaValidationError(
            '"mapping" field can not be empty as no "default" is provided'
        )

    # Only default_value present and it is empty.
    if (
        "default_value" in instance
        and "mapping_field" not in instance
        and (not instance["default_value"])
    ):
        raise JsonSchemaValidationError(
            '"default" field can not be empty as no "mapping" is provided'
        )


def validate_header(instance, name) -> None:
    """Check the CEF header block of one subtype.

    Args:
        instance: Header block read from the mapping file.
        name: Configuration name, kept for message context.
    """
    properties_schema = {
        "default_value": {"type": "string"},
        "mapping_field": {"type": "string"},
        "transformation": {"type": "string"},
    }

    one_of_sub_schema = [
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

    for field in instance:
        validate_header_extension_subdict(instance[field], name)


def validate_extension_field(instance, name) -> None:
    """Check one CEF extension field block.

    Args:
        instance: Mapping block of a single extension field.
        name: Configuration name, kept for message context.
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
    validate_header_extension_subdict(instance, name)


def validate_aws_cloudwatch_mappings(mappings, data_type, name) -> None:
    """Check the CEF mappings of one data type.

    Args:
        mappings: Parsed mapping file.
        data_type: Data type to check, for example alerts or events.
        name: Configuration name, kept for message context.

    Raises:
        MappingValidationError: When the mapping of any subtype is invalid.
    """
    data_type_specific_mapping = mappings["taxonomy"][data_type]
    if data_type == "json":
        return

    for subtype, subtype_map in data_type_specific_mapping.items():
        subtype_header = subtype_map["header"]
        try:
            validate_header(subtype_header, name)
        except JsonSchemaValidationError as err:
            raise MappingValidationError(
                "Error occurred while validating CEF header "
                'for type "{}". Error: {}'.format(subtype, err)
            )

    for subtype, subtype_map in data_type_specific_mapping.items():
        subtype_extension = subtype_map["extension"]
        try:
            validate_extension(subtype_extension)
        except JsonSchemaValidationError as err:
            raise MappingValidationError(
                "Error occurred while validating CEF extension "
                'for type "{}". Error: {}'.format(subtype, err)
            )

        for cef_field, ext_dict in subtype_extension.items():
            try:
                validate_extension_field(ext_dict, name)
            except JsonSchemaValidationError as err:
                raise MappingValidationError(
                    "Error occurred while validating CEF extension "
                    'field "{}" for type "{}". Error: {}'.format(
                        cef_field, subtype, err
                    )
                )


def get_aws_cloudwatch_mappings(mappings: dict) -> Tuple[str, str, dict]:
    """Read the mapping file and return the parts needed to transform data.

    Args:
        mappings (dict): Parsed mapping file.

    Returns:
        Tuple[str, str, dict]: delimiter, cef_version and taxonomy.
    """
    return (
        mappings.get("delimiter", ""),
        mappings.get("cef_version", ""),
        mappings.get("taxonomy", {}),
    )
