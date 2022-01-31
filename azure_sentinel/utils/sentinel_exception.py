"""Exception class for azure sentinel plugin."""


class Error(Exception):
    """Base class for exceptions in this module."""

    pass


class MappingValidationError(Error):
    """Exception raised when validation fails for Azure Sentinel mappings file.

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
