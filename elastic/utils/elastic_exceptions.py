"""Exception class for elastic syslog plugin."""


class FormatECSError(Exception):
    """ECS Format Error class."""

    pass


class Error(Exception):
    """Base class for exceptions in this module."""

    pass


class ValidationError(Error):
    """Exception raised for validation failures for the parameters of docker-compose file.

    :attribute: expression -- input expression in which the error occurred
    :attribute: message -- explanation of the error
    """

    def __init__(self, parameter, message):
        """Initialize."""
        self.parameter = parameter
        self.message = message


class ECSValueError(FormatECSError, ValueError):
    """Exception raised for invalid value mappings.

    Attributes:
        message -- explanation of the error
    """

    def __init__(self, message):
        """Initialize."""
        self.message = message


class ECSTypeError(FormatECSError, TypeError):
    """Exception raised for data type mismatch between mapped value and ECS fields.

    Attributes:
        message -- explanation of the error
    """

    def __init__(self, message):
        """Initialize."""
        self.message = message


class MappingValidationError(Exception):
    """Exception raised when validation fails for syslog mappings file.

    Attributes:
        message -- explanation of the error
    """

    def __init__(self, message):
        """Initialize."""
        self.message = message


class EmptyExtensionError(Exception):
    """Exception raised when extension is empty for generated ECS event."""

    pass


class FieldNotFoundError(Exception):
    """Exception raised when mapped field is not found in Netskope response.

    Attributes:
        message -- explanation of the error
    """

    def __init__(self, message):
        """Initialize."""
        self.message = message
