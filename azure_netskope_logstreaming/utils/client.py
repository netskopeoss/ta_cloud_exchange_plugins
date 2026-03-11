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

Azure Netskope LogStreaming Client Class.
"""

import traceback
from ..lib.azure.storage.queue import QueueClient, QueueServiceClient
from ..lib.azure.storage.blob import BlobServiceClient
from ..lib.azure.core.exceptions import (
    AzureError,
    ClientAuthenticationError,
    HttpResponseError,
    ServiceRequestError,
)
from netskope.common.utils import add_user_agent
from .exceptions import AzureNLSException
from .constants import (
    PLUGIN_NAME,
    PLATFORM_NAME,
    MODULE_NAME,
    PLUGIN_VERSION,
)


class AzureNLSClient:
    """Azure NLS client Class."""

    def __init__(self, configuration, logger, log_prefix):
        """Init method."""
        self.configuration = configuration
        self.logger = logger
        self.log_prefix = log_prefix

    def _get_user_agent(self) -> str:
        """Get User-Agent string.

        Args:
            None
        Returns:
            str: User-Agent string.
        """
        headers = add_user_agent()
        ce_added_agent = headers.get("User-Agent", "netskope-ce")
        user_agent = "{}-{}-{}-v{}".format(
            ce_added_agent,
            MODULE_NAME.lower(),
            PLUGIN_NAME.replace(" ", "-").lower(),
            PLUGIN_VERSION,
        )
        return user_agent

    def get_blob_service_client(self, is_validation=False):
        """To get blob service client client."""
        try:
            connection_string = self.configuration["connection_string"].strip()
            blob_service_client = BlobServiceClient.from_connection_string(
                conn_str=connection_string, user_agent=self._get_user_agent()
            )
            if is_validation:
                blob_service_client.get_service_properties()
            return blob_service_client
        except ClientAuthenticationError as exp:
            err_msg = (
                f"{PLATFORM_NAME} Blob Storage authentication failed. "
                f"Please check the {PLATFORM_NAME} Storage Account "
                "Connection String, Queue Name or permissions."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {exp}",
                details=str(traceback.format_exc()),
            )
            raise AzureNLSException(err_msg)
        except HttpResponseError as exp:
            err_msg = (
                f"{PLATFORM_NAME} Blob Storage HTTP error due to either "
                "missing blob, insufficient permissions, or invalid request."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {exp}",
                details=str(traceback.format_exc()),
            )
            raise AzureNLSException(err_msg)
        except ServiceRequestError as exp:
            err_msg = (
                "A network error occurred while communicating "
                f"with {PLATFORM_NAME} Blob Storage."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {exp}",
                details=str(traceback.format_exc()),
            )
            raise AzureNLSException(err_msg)
        except AzureError as exp:
            err_msg = (
                "An unexpected error occurred while "
                f"accessing {PLATFORM_NAME} Blob Storage."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {exp}",
                details=str(traceback.format_exc()),
            )
            raise AzureNLSException(err_msg)
        except Exception as exp:
            err_msg = (
                f"Error occurred while creating {PLATFORM_NAME} blob service "
                f"client object for {PLUGIN_NAME}. Verify the"
                f" {PLATFORM_NAME} Storage Account Connection String provided"
                " in the configuration parameters."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {exp}",
                details=str(traceback.format_exc()),
            )
            raise AzureNLSException(err_msg)

    def get_queue_client(self):
        """To get queue client client."""
        try:
            connection_string = self.configuration["connection_string"].strip()
            queue_name = self.configuration["queue_name"].strip()
            queue_client = QueueClient.from_connection_string(
                conn_str=connection_string,
                queue_name=queue_name,
                user_agent=self._get_user_agent(),
            )
            return queue_client
        except ClientAuthenticationError as exp:
            err_msg = (
                "Queue Storage authentication failed. "
                f"Please check the {PLATFORM_NAME} Storage Account,"
                " Connection String Queue Name or permissions."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {exp}",
                details=str(traceback.format_exc()),
            )
            raise AzureNLSException(err_msg)
        except HttpResponseError as exp:
            err_msg = (
                "Queue Storage HTTP error due to either "
                "missing blob, insufficient permissions, or invalid request."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {exp}",
                details=str(traceback.format_exc()),
            )
            raise AzureNLSException(err_msg)
        except ServiceRequestError as exp:
            err_msg = (
                "A network error occurred while communicating "
                f"with {PLATFORM_NAME} Queue Storage."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {exp}",
                details=str(traceback.format_exc()),
            )
            raise AzureNLSException(err_msg)
        except AzureError as exp:
            err_msg = (
                "An unexpected error occurred while "
                f"accessing {PLATFORM_NAME} Queue Storage."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {exp}",
                details=str(traceback.format_exc()),
            )
            raise AzureNLSException(err_msg)
        except Exception as exp:
            err_msg = (
                f"Error occurred while creating {PLATFORM_NAME} Storage queue "
                f"client object for {PLUGIN_NAME}. Verify the"
                " {PLATFORM_NAME} Storage Queue Name and connection "
                "string provided in the configuration parameters."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {exp}",
                details=str(traceback.format_exc()),
            )
            raise AzureNLSException(err_msg)

    def get_queue_service_client(self):
        """To get queue service client client."""
        try:
            connection_string = self.configuration["connection_string"].strip()
            queue_service = QueueServiceClient.from_connection_string(
                conn_str=connection_string, user_agent=self._get_user_agent()
            )
            return queue_service
        except ClientAuthenticationError as exp:
            err_msg = (
                f"Failed to authenticate {PLATFORM_NAME} Queue Service client."
                f" Please verify the {PLATFORM_NAME} Storage account "
                "connection string and account access."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {exp}",
                details=str(traceback.format_exc()),
            )
            raise AzureNLSException(err_msg)
        except HttpResponseError as exp:
            err_msg = (
                f"HTTP error while accessing {PLATFORM_NAME} Queue Service "
                "Check if the service is available and the resource exists."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {exp}",
                details=str(traceback.format_exc()),
            )
            raise AzureNLSException(err_msg)
        except ServiceRequestError as exp:
            err_msg = (
                "A network error occurred while "
                "initializing the Queue Service Client."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {exp}",
                details=str(traceback.format_exc()),
            )
            raise AzureNLSException(err_msg)
        except AzureError as exp:
            err_msg = (
                "An unexpected error occurred while "
                f"creating {PLATFORM_NAME} Queue Service client."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {exp}",
                details=str(traceback.format_exc()),
            )
            raise AzureNLSException(err_msg)
        except Exception as exp:
            err_msg = (
                f"Unexpected Error occurred while creating {PLATFORM_NAME}"
                f" queue service client object for {PLUGIN_NAME}. Verify the"
                " {PLATFORM_NAME} Storage Queue Name and connection string "
                "provided in the configuration parameters."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {exp}",
                details=str(traceback.format_exc()),
            )
            raise AzureNLSException(err_msg)
