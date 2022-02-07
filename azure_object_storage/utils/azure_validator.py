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

"""azure validator."""


class AzureValidator(object):
    """Azure validator class."""

    def __init__(self, logger):
        """Initialize."""
        super().__init__()
        self.logger = logger

    def validate_max_file_size(self, max_file_size):
        """Validate max file size.

        Args:
            max_file_size: the max file size to be validated

        Returns:
            Whether the provided value is valid or not. True in case of valid value, False otherwise
        """
        if max_file_size:
            try:
                max_file_size = int(max_file_size)
                if 0 < max_file_size <= 100:
                    return True
                return False
            except ValueError:
                return False
        else:
            return False

    def validate_max_duration(self, max_duration):
        """Validate max duration.

        Args:
            max_duration: the max duration to be validated

        Returns:
            Whether the provided value is valid or not. True in case of valid value, False otherwise
        """
        if max_duration:
            try:
                max_duration = int(max_duration)
                if max_duration > 0:
                    return True
                return False
            except ValueError:
                return False
        else:
            return False
