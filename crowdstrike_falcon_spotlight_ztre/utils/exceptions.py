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

CRE CrowdStrike Falcon Spotlight plugin exception module.
"""

import traceback
from functools import wraps


class CrowdstrikeFalconSpotlightPluginException(Exception):
    """Crowdstrike Falcon Spotlight Plugin Exception class."""

    pass


def exception_handler(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        """
        Exception handler.

        Args:
            func (function): Function to wrap.

        Returns:
            function: Wrapped function.
        """
        self = args[0]
        try:
            return func(*args, **kwargs)
        except CrowdstrikeFalconSpotlightPluginException:
            raise
        except Exception as err:
            logger_msg = kwargs.get("context", {}).get("logger_msg")
            if not logger_msg:
                logger_msg = f"executing {func.__name__} method"
            err_msg = (
                f"{self.log_prefix}: Unexpected error occurred while"
                f" {logger_msg}. Error: {err}."
            )
            self.logger.error(
                message=err_msg,
                details=traceback.format_exc(),
            )
            raise CrowdstrikeFalconSpotlightPluginException(err_msg)

    return wrapper
