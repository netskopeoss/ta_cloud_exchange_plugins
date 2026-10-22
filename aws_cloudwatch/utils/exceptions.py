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

Exception classes for the AWS CloudWatch CLS plugin.
"""


class AWSCloudWatchPluginError(Exception):
    """Raised for any AWS CloudWatch plugin failure."""

    pass


class AWSCloudWatchResourceNotFoundError(AWSCloudWatchPluginError):
    """Raised when the target log group or log stream is missing."""

    pass


class FormatCEFError(Exception):
    """Base class for CEF formatting errors."""

    pass


class CEFValueError(FormatCEFError, ValueError):
    """Raised when a mapped value is not valid for a CEF field.

    Attributes:
        message: Explanation of the error.
    """

    def __init__(self, message):
        """Initialize CEFValueError."""
        self.message = message
        super().__init__(message)


class CEFTypeError(FormatCEFError, TypeError):
    """Raised when a mapped value type does not match the CEF field.

    Attributes:
        message: Explanation of the error.
    """

    def __init__(self, message):
        """Initialize CEFTypeError."""
        self.message = message
        super().__init__(message)


class MappingValidationError(Exception):
    """Raised when the mapping file fails validation.

    Attributes:
        message: Explanation of the error.
    """

    def __init__(self, message):
        """Initialize MappingValidationError."""
        self.message = message
        super().__init__(message)


class EmptyExtensionError(Exception):
    """Raised when a generated CEF event has an empty extension."""

    pass


class FieldNotFoundError(Exception):
    """Raised when a mapped field is missing from the Netskope record.

    Attributes:
        message: Explanation of the error.
    """

    def __init__(self, message):
        """Initialize FieldNotFoundError."""
        self.message = message
        super().__init__(message)
