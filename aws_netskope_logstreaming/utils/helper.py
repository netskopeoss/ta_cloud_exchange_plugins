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

AWS Netskope LogStreaming helper module.
"""

from .exceptions import AWSD2CProviderException
from netskope.integrations.cls.plugin_base import ValidationResult
from typing import Dict, Any


def handle_and_raise(
    logger,
    log_prefix,
    err: str = "",
    err_msg: str = "",
    details_msg: str = "",
    exc_type: Exception = AWSD2CProviderException,
    if_raise: bool = True,
    return_validation_result: bool = False,
):
    """Handle and raise an exception.

    Args:
        logger (Logger): Logger object.
        log_prefix (str): Log prefix.
        err (Exception): Exception object.
        err_msg (str): Error message.
        details_msg (str): Details message.
        exc_type (Exception, optional): Exception type. Defaults to
            AWSD2CProviderException.
        if_raise (bool, optional): Whether to raise the exception.
            Defaults to True.
        return_validation_result (bool, optional): Whether to return
            validation result. Defaults to False.
    """
    if err:
        logger.error(
            message=f"{log_prefix}: {err_msg} Error: {err}",
            details=details_msg,
        )
    else:
        logger.error(
            message=f"{log_prefix}: {err_msg}",
            details=details_msg,
        )
    if if_raise:
        raise exc_type(err_msg)
    if return_validation_result:
        return ValidationResult(
            success=False,
            message=err_msg,
        )


def log_message(
    logger,
    log_prefix,
    plugin_name: str,
    data: Dict[str, Any],
    log_data_type: str,
    sub_type: str,
    pull_type: str,
) -> None:
    """Log the message for pulling data from Netskope log streaming.

    Args:
        logger (Logger): Logger object.
        log_prefix (str): Log prefix.
        plugin_name (str): Name of the plugin.
        data (Dict[str, Any]): Data pulled from Netskope log streaming.
        log_data_type (str): Type of log data.
        sub_type (str): Subtype of the data.
        pull_type (str): Type of pulling (maintenance, historical,
        real-time).
    """
    if log_data_type:
        log_data_type = log_data_type.rstrip('s')

    if sub_type == "v2":
        log_msg = (
            f"Pulled {len(data)} {log_data_type} log(s) "
            f"for plugin {plugin_name} from {pull_type}"
            f" in JSON format."
        )
    else:
        log_msg = (
            f"Pulled {len(data)} {sub_type} {log_data_type}(s) "
            f"for plugin {plugin_name} from {pull_type}"
            f" in JSON format."
        )

    logger.info(
        message=f"{log_prefix}: {log_msg}",
    )
