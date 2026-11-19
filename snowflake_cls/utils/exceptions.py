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

Snowflake CLS Plugin exceptions.
"""


class SnowflakePluginException(Exception):
    """Base exception for the Snowflake CLS plugin.

    Every other exception in this plugin inherits from this one, so a
    caller can catch this single type to catch all of them.

    Attributes:
        status_code (int): The HTTP status that caused this, when there
            was one. Lets a caller treat a 404 differently from any
            other failure without reading the message.
    """

    def __init__(self, message, status_code=None):
        """Store the message and, when known, the HTTP status.

        Args:
            message (str): What went wrong.
            status_code (int): HTTP status, if this came from a response.
        """
        self.status_code = status_code
        super().__init__(message)


class SnowflakeAuthenticationError(SnowflakePluginException):
    """Raised when Snowflake rejects the credentials.

    Covers a 401 or 403 from either API, and a missing token.
    """

    pass


class SnowflakeConfigurationError(SnowflakePluginException):
    """Raised when a configuration value cannot be used at run time.

    Example: a table name that is not a valid Snowflake identifier.
    """

    pass


class MappingValidationError(Exception):
    """Raised when a record cannot be mapped.

    Caught per record in transform() so one bad record never stops the
    whole batch.

    Attributes:
        message (str): What went wrong.
    """

    def __init__(self, message):
        """Store the message and pass it to the base class.

        Args:
            message (str): What went wrong.
        """
        self.message = message
        super().__init__(message)
