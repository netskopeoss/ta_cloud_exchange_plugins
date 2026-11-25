"""CRE Armis Centrix plugin exceptions.

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

from typing import Optional


class ArmisPluginException(Exception):
    """Base exception of the Armis Centrix plugin."""

    def __init__(
        self,
        message: str = "",
        resolution: Optional[str] = None,
        status_code: Optional[int] = None,
    ):
        """Initialize the exception.

        Args:
            message (str): Error message, without the log prefix.
            resolution (Optional[str]): Resolution for the error.
            status_code (Optional[int]): HTTP status code of the failed
                Armis call, when there is one.
        """
        super().__init__(message)
        self.message = message
        self.resolution = resolution
        self.status_code = status_code


class ArmisAuthenticationException(ArmisPluginException):
    """Raised when an access token cannot be generated or is rejected."""


class ArmisAPIException(ArmisPluginException):
    """Raised when an Armis API call fails."""


class ArmisValidationException(ArmisPluginException):
    """Raised when a Device ID or a value of an action is invalid."""
