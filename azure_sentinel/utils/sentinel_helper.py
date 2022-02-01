"""Sentinel Helper."""
from datetime import datetime

from jsonschema import validate
from jsonschema.exceptions import ValidationError as JsonSchemaValidationError

from .sentinel_exception import (
    MappingValidationError,
)


def map_sentinel_data(mappings, data, logger, data_type, subtype):
    """Filter the raw data and returns the filtered data, which will be further pushed to Azure Sentinel.

    :param mappings: List of fields to be pushed to Azure Sentinel (read from mapping string)
    :param data: Data to be mapped (retrieved from Netskope)
    :param logger: Logger object for logging purpose
    :param data_type: The type of data being mapped (alerts/events)
    :param subtype: The subtype of data being mapped (for example DLP is a subtype of alerts data type)
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


def get_sentinel_mappings(mappings, data_type):
    """Return the dict of mappings to be applied to raw data.

    :param mappings: Mapping String
    :param data_type: Data type (alert/event) for which the mappings are to be fetched
    :return: Read mappings
    """
    mappings = mappings["taxonomy"][data_type]

    # Validate each subtype
    for subtype, subtype_map in mappings.items():
        try:
            validate_subtype(subtype_map)
        except JsonSchemaValidationError as err:
            raise MappingValidationError(
                'Error occurred while validating Azure Sentinel mappings for type "{}".\
                    Error: {}'.format(
                    subtype, err
                )
            )
    return mappings


conversion_map = {
    "datetime": lambda epoch: datetime.utcfromtimestamp(epoch).isoformat(
        sep="T", timespec="milliseconds"
    )
    + "Z",
    "string": lambda value: str(value),
}
