""" File containing common validations for Configuration parameters."""
from urllib.parse import urlparse

from netskope.integrations.cte.plugin_base import ValidationResult


class PluginConfigValidators:
    """
    `PluginConfigValidators` is a generic class which contains methods for performing
    various checks on Plugin configuration parameters. This class currently supports
    below validation scenarios for the configuration parameters:
    1. `field_not_empty_check`  : Checks the presence of configuration parameter in the payload.
    2. `field_value_type_check` : Checks the data type of the configuration parameter.
    3. `validate_url_format`    : Checks if the configuration parameter obeys URL format standard.
    4. `validate_range`         : Checks if the configuration parameter value falls in the mentioned range.
    5. `validate_list_values`   : Checks if the value of configuration parameter is from the supported
                                  values list.
    6. `field_dependency_check` : Checks if the configuration payload satisfies parent-child field
                                  dependencies.
    """

    def __init__(self, config, logger, log_prefix):

        # Validation type to method mapping.
        self.validators = {
            "field_not_empty_check": self.field_not_empty_check,
            "field_value_type_check": self.field_value_type_check,
            "validate_url_format": self.validate_url_format,
            "validate_range": self.validate_range,
            "validate_list_values": self.validate_list_values,
            "field_dependency_check": self.field_dependency_check,
        }
        self.config = config
        self.log = logger
        self.log_prefix = log_prefix
        # Default validation message.
        self.validation_msg = "Validation error occurred."

    def execute_validations(self, parent_field, field_name, validation_checks={}):
        """
        Execute all validations for a configuration parameter. Validation execution stops
        if any validation fails.

        Args:
        parent_field (str)       : If field dependency needs to be verified, parent field name
                                  is required.
        field_name (str)         : Field for which validations should be executed.
        validation_checks (str)  : List of validations that needs to be executed for the field.

        Returns:
        validation status (bool) : Validation status for the field.
        validation result (`obj`) : Object of class `ValidationResult` with validation status and
                                    details of validation failure.
        """

        # Iterate over all the validation checks for the field.
        for validation_type, validation_params in validation_checks.items():
            validator_func = self.validators[validation_type]
            if parent_field:
                field_value = self.config.get(parent_field, {}).get(field_name)
            else:
                field_value = self.config.get(field_name)

            # Execute the validation check.
            check_status, validation_message = validator_func(
                field_name=field_name,
                field_value=field_value,
                validation_params=validation_params,
            )

            # Validation Failure. Stop executing further validations.
            if not check_status:
                return check_status, validation_message

        return True, ValidationResult(
            success=True,
            message="",
        )

    def field_not_empty_check(self, field_name, field_value, validation_params):
        """
        Validation: Checks the presence of configuration parameter in the payload.
        If field is "" or None, the validation fails.

        Args:
        field_name (str)         : Field for which validation needs to be performed.
        field_value (any)        : Value of field on which validation will be performed.
        validation_params (dict) : Helper object to contain fields used during validation.

        Returns:
        validation status (bool) : Validation status for the field.
        validation result (`obj`) : Object of class `ValidationResult` with validation status and
                                    details of validation failure.
        """
        error_msg = f"'{field_name}' is a required configuration parameter."
        if isinstance(field_value, str):
            field_value = field_value.strip()

        # Check if field is not empty in type of data.
        if field_value in [None, [], {}, ""]:
            error_msg = (
                (error_msg)
                if validation_params.get("error_message") in ["", None]
                else (validation_params["error_message"])
            )

            self.log.error(f"{self.log_prefix}: {self.validation_msg} {error_msg}")
            return False, ValidationResult(success=False, message=error_msg)

        return True, None

    def field_value_type_check(self, field_name, field_value, validation_params):
        """
        Validation: Checks the data type of the configuration parameter.

        Args:
        field_name (str)         : Field for which validation needs to be performed.
        field_value (any)        : Value of field on which validation will be performed.
        validation_params (dict) : Helper object to contain fields used during validation.

        Returns:
        validation status (bool) : Validation status for the field.
        validation result (`obj`) : Object of class `ValidationResult` with validation status and
                                    details of validation failure.
        """

        # Type mapping from Netskope data type to Python data type.
        type_mapping = {
            "text": (str),
            "number": (int, float),
            "multichoice": (list),
        }
        expected_value_type = validation_params["value_type"]
        error_msg = (
            f"Invalid value found for field: {field_name}. "
            f"Expected data type: {expected_value_type}"
        )

        # Execute validation.
        if field_value and not isinstance(
            field_value, type_mapping[expected_value_type]
        ):
            error_msg = (
                (error_msg)
                if validation_params.get("error_message") in ["", None]
                else (validation_params["error_message"])
            )

            self.log.error(f"{self.log_prefix}: {self.validation_msg} {error_msg}")
            return False, ValidationResult(success=False, message=error_msg)

        return True, None

    def _validate_url(self, url: str) -> bool:
        """
        Helper method to validate the URL format.
        Expected format: <scheme>://<URL>/

        Args:
        url (str) : URL string to validate.

        Returns:
        validation_status (bool): True is URL is in expected format, else False.
        """

        parsed = urlparse(url.strip())
        return (
            parsed.scheme.strip() != ""
            and parsed.netloc.strip() != ""
            and (parsed.path.strip() == "/" or parsed.path.strip() == "")
        )

    def validate_url_format(self, field_name, field_value, validation_params):
        """
        Validation: Checks if the configuration parameter obeys URL format standard.

        Args:
        field_name (str)         : Field for which validation needs to be performed.
        field_value (any)        : Value of field on which validation will be performed.
        validation_params (dict) : Helper object to contain fields used during validation.

        Returns:
        validation status (bool) : Validation status for the field.
        validation result (`obj`) : Object of class `ValidationResult` with validation status and
                                    details of validation failure.
        """

        # Parse the URL string.
        parsed_url = self._validate_url(field_value)
        error_msg = (
            f"Invalid Base URL found in the configuration parameter '{field_name}'. "
            "Expected format is: <http_scheme>://<url>/"
        )

        if not parsed_url:
            error_msg = (
                (error_msg)
                if validation_params.get("error_message") in ["", None]
                else (validation_params["error_message"])
            )

            self.log.error(f"{self.log_prefix}: {self.validation_msg} {error_msg}")
            return False, ValidationResult(success=False, message=error_msg)

        return True, None

    def validate_range(self, field_name, field_value, validation_params):
        """
        Validation: Checks if the configuration parameter value falls in the mentioned range.

        Args:
        field_name (str)         : Field for which validation needs to be performed.
        field_value (any)        : Value of field on which validation will be performed.
        validation_params (dict) : Helper object to contain fields used during validation.

        Returns:
        validation status (bool) : Validation status for the field.
        validation result (`obj`) : Object of class `ValidationResult` with validation status and
                                    details of validation failure.
        """
        # Fetch starting value and ending value of the range.
        lowest_value = float(validation_params["from"])
        highest_value = float(validation_params["to"])

        error_msg = (
            f"Invalid value provided for configuration parameter '{field_name}'. "
            "Expected value should be in the range "
            f"{validation_params['from'], validation_params['to']}."
        )

        # Execute validation.
        if int(field_value) < lowest_value or int(field_value) > highest_value:
            error_msg = (
                (error_msg)
                if validation_params.get("error_message") in ["", None]
                else (validation_params["error_message"])
            )

            self.log.error(f"{self.log_prefix}: {error_msg}")
            return False, ValidationResult(
                success=False,
                message=error_msg,
            )

        return True, None

    def validate_list_values(self, field_name, field_value, validation_params):
        """
        Validation: Checks if the value of configuration parameter is from the supported
                    values list.

        Args:
        field_name (str)         : Field for which validation needs to be performed.
        field_value (any)        : Value of field on which validation will be performed.
        validation_params (dict) : Helper object to contain fields used during validation.
            Expected keys:
            error_message (str)  : Error message if validation fails.
            supported_values (list) : List of valid values to check against field value.

        Returns:
        validation status (bool) : Validation status for the field.
        validation result (`obj`) : Object of class `ValidationResult` with validation status and
                                    details of validation failure.
        """

        # If Netskope configuration type = "Choice", the value received is not in list.
        # Hence, formatting the value in list data type for validation purpose.
        if not isinstance(field_value, list):
            field_value = [field_value]

        # List of unsupported values provided in the configuration parameter.
        unsupported_values = set(field_value) - set(
            validation_params["supported_values"]
        )

        if unsupported_values:
            error_msg = (
                f"Unsupported value(s) - {field_value} found in the field '{field_name}'. "
                f"Supported values are: {validation_params['supported_values']}"
            )

            error_msg = (
                (error_msg)
                if validation_params.get("error_message") in ["", None]
                else (validation_params["error_message"])
            )

            self.log.error(f"{self.log_prefix}: {self.validation_msg} {error_msg}")
            return False, ValidationResult(success=False, message=error_msg)

        return True, None

    def field_dependency_check(self, field_name, field_value, validation_params):
        """
        Validation: Checks if the configuration payload satisfies parent-child field
                    dependencies.

        Args:
        field_name (str)         : Field for which validation needs to be performed.
        field_value (any)        : Value of field on which validation will be performed.
        validation_params (list(dict)) : Helper list to contain entities used during validation.
            Expected keys in each object:
            condition (dict)     : Condition to check for verifying field dependency.
                                   If left blank, dependent fields are mandatory if parent field
                                   is present.
                Expected keys:
                value (any)      : If dependency needs to be checked based on parent field value,
                                   provide the parent field value in this field.
            fields_dependent (list) : List of dependent fields.
            error_message (str)  : Error message if validation fails.

        Returns:
        validation status (bool) : Validation status for the field.
        validation result (`obj`) : Object of class `ValidationResult` with validation status and
                                    details of validation failure.
        """

        # Check if parent field is value is present in configuration payload.
        if field_value:

            # Iterate over all dependencies of parent field.
            for dependency in validation_params:
                # Get parent field value if child fields are dependent on specific
                # parent field value.
                expected_parent_value = dependency.get("condition", {}).get("value")
                fields_dependent = dependency["fields_dependent"]

                error_msg = f"{fields_dependent} fields are required"
                # If parent field value is not expected value, validation will be skipped.
                if expected_parent_value:
                    if field_value != expected_parent_value:
                        continue
                    else:
                        error_msg = (
                            f"{error_msg} if {field_name} = {expected_parent_value}."
                        )
                else:
                    error_msg = (
                        f"{error_msg} if {field_name} is present in the configuration."
                    )

                error_msg = (
                    error_msg
                    if dependency.get("error_message") in ["", None]
                    else dependency["error_message"]
                )

                # Check child field dependencies.
                for dependent_field in fields_dependent:
                    dependent_field_value = self.config.get(dependent_field)
                    # Check the existence of child field in the configuration payload.
                    status, validation_message = self.field_not_empty_check(
                        field_name=dependent_field,
                        field_value=dependent_field_value,
                        validation_params={"error_message": error_msg},
                    )

                    if not status:
                        return status, validation_message

        return True, None
