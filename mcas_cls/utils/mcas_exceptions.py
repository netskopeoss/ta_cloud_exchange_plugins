"""MCAS Exceptions."""


class FormatCEFError(Exception):
    """CEF Format Error class."""

    pass


class Error(Exception):
    """Base class for exceptions in this module."""

    pass


class CEFValueError(FormatCEFError, ValueError):
    """Exception raised for invalid value mappings.

    :attribute: message -- explanation of the error
    """

    def __init__(self, message):
        """Initialize."""
        self.message = message


class CEFTypeError(FormatCEFError, TypeError):
    """Exception raised for data type mismatch between mapped value and CEF fields.

    :attribute: message -- explanation of the error
    """

    def __init__(self, message):
        """Initialize."""
        self.message = message


class MappingValidationError(Error):
    """Exception raised when validation fails for mcas mappings file.

    :attribute: message -- explanation of the error
    """

    def __init__(self, message):
        """Initialize."""
        self.message = message


class EmptyExtensionError(Error):
    """Exception raised when extension is empty for generated CEF event."""

    pass


class FieldNotFoundError(Error):
    """Exception raised when mapped field is not found in Netskope response.

    :attribute: message -- explanation of the error
    """

    def __init__(self, message):
        """Initialize."""
        self.message = message


class MaxRetriesExceededError(Error):
    """Exception raised when maximum number of retries exceeded while pulling data from Netskope."""

    def __init__(self, message):
        """Initialize."""
        self.message = message
