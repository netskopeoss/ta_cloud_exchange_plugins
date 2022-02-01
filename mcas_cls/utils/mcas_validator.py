"""MCAS Validator."""
import re
import csv
import io
from jsonschema import validate
from jsonschema.exceptions import ValidationError as JsonSchemaValidationError


class MCASValidator(object):
    """MCAS Validator."""

    def __init__(self, logger):
        """Init method."""
        super().__init__()
        self.logger = logger

    def validate_portal_url(self, portal_url):
        """Validate Portal url. If not present, issues appropriate logs and exists docker.

        :param: portal_url: the Portal url to be validated
        :returns: Whether the provided value is valid or not. True in case of valid value, False otherwise
        """
        if not portal_url:
            return False

        if portal_url.strip().startswith(
            "http://"
        ) or portal_url.strip().startswith("https://"):
            return False

        return True

    def validate_data_source(self, data_source):
        """Validate Data Source. If not present, issues appropriate logs and exists docker.

        :param: data_source: the Data Source to be validated
        :returns: Whether the provided value is valid or not. True in case of valid value, False otherwise
        """
        if not data_source:
            return False

        data_source_regex = re.compile(r"^[A-Za-z0-9_-]*$")
        return True if data_source_regex.match(data_source) else False

    def validate_taxonomy(self, instance):
        """Validate the schema of given taxonomy JSON.

        :param instance: The JSON object to be validated
        :return: True if the schema is valid, False otherwise
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
        """Read the given mapping file and validates its schema.

        :param mapping_file: The mapping file from which the schema is to be validated
        :return: True in case of valid schema, False otherwise
        """
        # Schema of mapping file
        schema = {
            "type": "object",
            "properties": {
                "delimiter": {"type": "string", "minLength": 1, "enum": ["|"]},
                "validator": {"type": "string", "minLength": 1},
                "cef_version": {"type": "string", "minLength": 1},
                "taxonomy": {
                    "type": "object",
                    "properties": {
                        "alerts": {"type": "object"},
                        "events": {"type": "object"},
                    },
                },
            },
            "required": ["delimiter", "taxonomy", "cef_version"],
        }

        # If no exception is raised by validate(), the instance is valid.
        try:
            validate(instance=mappings, schema=schema)
        except JsonSchemaValidationError as err:
            self.logger.error(
                "Error occurred while validating JSON schema: {}".format(err)
            )
            return False

        # Validate the schema of all taxonomy
        for data_type, dtype_taxonomy in mappings["taxonomy"].items():
            for subtype, subtype_taxonomy in dtype_taxonomy.items():
                try:
                    self.validate_taxonomy(subtype_taxonomy)
                except JsonSchemaValidationError as err:
                    self.logger.error(
                        'Error occurred while validating JSON schema for type "{}" and subtype "{}": '
                        "{}".format(data_type, subtype, err)
                    )
                    return False
        return True

    def validate_mcas_map(self, mappings):
        """Validate field mappings file. If not present, issues appropriate logs and exists docker.

        :param: mapping_file: the field mappings file to be validated
        :returns: Whether the provided value is valid or not. True in case of valid value, False otherwise
        """
        if not mappings:
            self.logger.error("Could not find mcas mappings.")
            return False
        try:
            if self.validate_mapping_schema(mappings):
                return True
        except Exception as err:
            self.logger.error(
                "An error occurred while validating the fields from the mapping file: {}".format(
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
                for header in ["CEF Key Name", "Length", "Data Type"]
            ):
                return True
        except Exception:
            return False

        return False
