"""
BSD 3-Clause License

Copyright (c) 2021, Netskope OSS
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its
   contributors may be used to endorse or promote products derived from
   this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

SentinelOne Singularity Data Lake CLS plugin exceptions.
"""

from typing import Optional


class SentinelOneSDLPluginException(Exception):
    """Base exception for the SentinelOne Singularity Data Lake plugin.

    Every other plugin exception inherits from this one, so a caller can
    catch this single type to catch all of them.

    Attributes:
        status_code (int): HTTP status that caused the error, when there
            was one.
    """

    def __init__(self, message: str, status_code: Optional[int] = None):
        """Store the message and the HTTP status.

        Args:
            message (str): What went wrong.
            status_code (int): HTTP status, if the error came from a
                response.
        """
        self.status_code = status_code
        super().__init__(message)


class SentinelOneSDLPayloadTooLargeError(SentinelOneSDLPluginException):
    """Raised when HEC answers 413 (request too large).

    push() catches this to split the batch and send the halves. The same
    body is never sent again as it is.
    """

    pass


class MappingValidationError(Exception):
    """Raised when the mapping is not usable or a record cannot be mapped.

    transform() catches it per record, so one bad record never stops the
    whole batch.

    Attributes:
        message (str): What went wrong.
    """

    def __init__(self, message: str):
        """Store the message.

        Args:
            message (str): What went wrong.
        """
        self.message = message
        super().__init__(message)


class FieldNotFoundError(Exception):
    """Raised when a mapped CEF field is not in the record and has no default.

    Attributes:
        message (str): Name of the missing field.
    """

    def __init__(self, message: str):
        """Store the message.

        Args:
            message (str): Name of the missing field.
        """
        self.message = message
        super().__init__(message)


class EmptyExtensionError(Exception):
    """Raised when a CEF record ends up with no extension values."""

    pass
