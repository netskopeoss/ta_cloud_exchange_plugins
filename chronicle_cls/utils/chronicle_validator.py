"""Chronicle Validator."""
import io
import csv
from jsonschema import validate
from jsonschema.exceptions import ValidationError as JsonSchemaValidationError


class ChronicleValidator(object):
    """Chronicle validator class."""

    def __init__(self, logger):
        """Initialize."""
        super().__init__()
        self.logger = logger

    def validate_taxonomy(self, instance):
        """Validate the schema of given taxonomy JSON.

        Args:
            instance: The JSON object to be validated

        Returns:
            True if the schema is valid, False otherwise
        """
        schema = {
            "type": "object",
            "properties": {
                "header": {"type": "object", "minProperties": 0},
                "extension": {"type": "object", "minProperties": 0},
            },
            "required": ["header", "extension"],
        }

        validate(instance=instance, schema=schema)

    def validate_mapping_schema(self, mappings):
        """Validate mapping schema.

        Args:
            mappings (dict): Mapping file.
        """
        schema = {
            "type": "object",
            "properties": {
                "udm_version": {"type": "string", "minLength": 1},
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
                },
            },
            "required": ["taxonomy", "udm_version"],
        }

        # If no exception is raised by validate(), the instance is valid.
        try:
            validate(instance=mappings, schema=schema)
        except JsonSchemaValidationError as err:
            self.logger.error(
                "Chronicle Plugin: Validation error occurred. Error: "
                "validating JSON schema: {}".format(err)
            )
            return False

        # Validate the schema of all taxonomy
        for data_type, dtype_taxonomy in mappings["taxonomy"].items():
            for subtype, subtype_taxonomy in dtype_taxonomy.items():
                try:
                    self.validate_taxonomy(subtype_taxonomy)
                except JsonSchemaValidationError as err:
                    self.logger.error(
                        "Chronicle Plugin: Validation error occurred. Error: "
                        'while validating JSON schema for type "{}" and subtype "{}": '
                        "{}".format(data_type, subtype, err)
                    )
                    return False
        return True

    def validate_chronicle_map(self, mappings):
        """Validate field JSON mappings.

        Args:
            mappings: the JSON string to be validated

        Returns:
            Whether the provided value is valid or not. True in case of valid value, False otherwise
        """
        if mappings is None:
            return False
        try:
            if self.validate_mapping_schema(mappings):
                return True
        except Exception as err:
            self.logger.error(
                "Chronicle Plugin: Validation error occurred. Error: {}".format(
                    str(err)
                )
            )

        return False

    def validate_valid_extensions(self, valid_extensions):
        """Validate CSV extensions.

        Args:
            valid_extensions: the CSV string to be validated

        Returns:
            Whether the provided value is valid or not. True in case of valid value, False otherwise
        """
        try:
            csviter = csv.DictReader(
                io.StringIO(valid_extensions), strict=True
            )
            headers = next(csviter)

            if all(
                header in headers
                for header in ["UDM Key Name", "Length", "Data Type"]
            ):
                return True
        except Exception:
            return False

        return False
