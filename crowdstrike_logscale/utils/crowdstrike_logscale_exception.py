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
"""

"""Exception class for CrowdStrike LogScale plugin."""


class CrowdStrikeLogScaleException(Exception):
    """CrowdStrikeLogScaleException exception class."""

    pass


class Error(Exception):
    """Base class for exceptions in this module."""

    pass


class MappingValidationError(Error):
    """Exception raised when validation fails for
    CrowdStrike LogScale mappings file.

    :attribute: message -- explanation of the error
    """

    def __init__(self, message):
        """Initialize."""
        self.message = message


class FieldNotFoundError(Exception):
    """Exception raised when mapped field is not found in Netskope response.

    Attributes:
        message -- explanation of the error
    """

    def __init__(self, message):
        """Initialize."""
        self.message = message


class MaxRetriesExceededError(Error):
    """Exception raised when maximum number of retries exceeded
    while pulling data from Netskope."""

    def __init__(self, message):
        """Initialize."""
        self.message = message
