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

CLS Elastic plugin client module.
"""

import socket
import traceback
from .elastic_exceptions import ElasticPluginException


class ElasticClient:
    """Elastic plugin client class."""

    def __init__(self, configuration: dict, logger, log_prefix):
        """Initialize."""
        self.configuration = configuration
        self.logger = logger
        self.log_prefix = log_prefix

    def get_socket(self, is_validation=False):
        """To Get TCP socket.

        Args:
            is_validation (bool, optional): Is this request coming from
            validate method? Defaults to False.
        """
        try:
            validation_msg = "Validation error occurred,"
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.connect(
                (
                    self.configuration.get("server_address", "").strip(),
                    self.configuration.get("server_port"),
                )
            )
        except socket.gaierror as err:
            err_msg = (
                "Unable to establish connection with Elastic Server."
                " Verify the Server Address provided in "
                "configuration parameters."
            )
            if is_validation:
                err_msg = validation_msg + " " + err_msg
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {err}",
                details=str(traceback.format_exc()),
            )
            raise ElasticPluginException(err_msg)
        except socket.timeout as err:
            err_msg = (
                "Connection Timeout. Verify the Server Address, "
                "Server Port and proxy configuration provided."
            )
            if is_validation:
                err_msg = validation_msg + " " + err_msg
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {err}.",
                details=str(traceback.format_exc()),
            )
            raise ElasticPluginException(err_msg)

        except (Exception, socket.error) as err:
            err_msg = (
                "Unable to establish connection with Elastic Server. "
                "Verify the Server Address and Server Port provided in the "
                "configuration parameters."
            )
            if is_validation:
                err_msg = validation_msg + " " + err_msg
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {err}",
                details=str(traceback.format_exc()),
            )
            raise ElasticPluginException(err_msg)

    def push_data(self, data):
        """To Push the data to TCP server."""
        try:
            self.sock.sendall(bytes(data, encoding="utf-8"))
        except Exception as exp:
            raise ElasticPluginException(exp)

    def close(self):
        """To Close socket connection."""
        try:
            self.sock.close()
        except Exception as err:
            err_msg = "Error while closing socket connection."
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {err}",
                details=str(traceback.format_exc()),
            )
            raise ElasticPluginException(err)
