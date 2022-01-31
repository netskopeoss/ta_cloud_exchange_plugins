"""CSCC Validator class."""
from jsonschema import validate
from jsonschema.exceptions import ValidationError as JsonSchemaValidationError


class CSCCValidator(object):
    """CSCC Validator class."""

    def __init__(self, logger):
        """Init method."""
        super().__init__()
        self.logger = logger

    def validate_mapping_schema(self, mappings):
        """Read the given mapping file and validates its schema.

        :param mapping_file: The mapping file from which the schema is to be validated
        :return: True in case of valid schema, False otherwise
        """
        # schema for mapping file
        schema = {
            "type": "object",
            "properties": {
                "taxonomy": {
                    "type": "object",
                    "properties": {
                        "alerts": {"type": "object"},
                        "events": {"type": "object"},
                    },
                }
            },
        }

        # If no exception is raised by validate(), the instance is valid.
        try:
            validate(instance=mappings, schema=schema)
            return True
        except JsonSchemaValidationError as err:
            self.logger.error(
                "Error occurred while validating JSON schema: {}".format(err)
            )
        return False

    def validate_cscc_map(self, mappings):
        """Validate field mappings file. If not present, issues appropriate logs and exists docker.

        :param: mapping_file: the field mappings file to be validated
        :returns: Whether the provided value is valid or not. True in case of valid value, False otherwise
        """
        try:
            if self.validate_mapping_schema(mappings):
                return True
        except Exception as err:
            self.logger.error(
                "CSCC Plugin: Validation error occurred. Error: {}".format(
                    str(err)
                )
            )

        return False
