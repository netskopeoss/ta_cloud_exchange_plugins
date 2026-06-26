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

Azure Netskope LogStreaming Validator.
"""

from typing import Tuple
from ..utils.constants import CONNECTION_STRING_REQUIRED_COMPONENTS


def validate_connection_string_format(
    connection_string: str,
) -> Tuple[bool, str]:
    """Validate the structural format of an Azure Storage Account Connection String.

    This is a pre-flight format check run before attempting live auth,
    so users get a clear error for malformed strings rather than a cryptic
    SDK exception.

    Args:
        connection_string: Raw connection string value from configuration.

    Returns:
        Tuple of (is_valid, error_message). error_message is empty on success.
    """
    missing = [
        comp
        for comp in CONNECTION_STRING_REQUIRED_COMPONENTS
        if comp not in connection_string
    ]
    if missing:
        return False, (
            "Invalid Microsoft Azure Storage Account Connection String format. "
            f"Missing required components: {', '.join(missing)}. "
            "Expected format: DefaultEndpointsProtocol=https;"
            "AccountName=<storage_account_name>;"
            "AccountKey=<base64_encoded_key>;"
            "EndpointSuffix=core.windows.net"
        )
    return True, ""
