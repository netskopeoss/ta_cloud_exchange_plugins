"""Sentinel Validator."""
from jsonschema import validate
from jsonschema.exceptions import ValidationError as JsonSchemaValidationError


class AzureSentinelValidator(object):
    """AzureSentinelValidator class."""

    def __init__(self, logger):
        """Initialize."""
        super().__init__()
        self.logger = logger

    def validate_mappings(self, mappings):
        """Read the given mapping string and validates its schema.

        :param mappings: The mapping string for which the schema is to be validated
        :return: True in case of valid schema, False otherwise
        """
        # schema for mappings
        schema = {
            "type": "object",
            "properties": {
                "taxonomy": {
                    "type": "object",
                    "properties": {
                        "alerts": {"type": "object"},
                        "events": {"type": "object"},
                    },
                    "anyOf": [
                        {"required": ["alerts"]},
                        {"required": ["events"]},
                    ],
                }
            },
            "required": ["taxonomy"],
        }

        # If no exception is raised by validate(), the instance is valid.
        try:
            validate(instance=mappings, schema=schema)
            return True
        except JsonSchemaValidationError as err:
            self.logger.error(
                "Error occurred while validating Mapping String: {}".format(
                    err
                )
            )
        return False
