"""Azure Netskope LogStreaming Client Class.

BSD 3-Clause License

Copyright (c) 2021, Netskope OSS
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

1. Redistributions of source code must retain the above copyright
   notice, this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright
   notice, this list of conditions and the following disclaimer in the
   documentation and/or other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its
   contributors may be used to endorse or promote products derived from
   this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
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
    """Azure NLS client class."""

    def __init__(self, configuration, logger, log_prefix):
        """Init method."""
        self.configuration = configuration
        self.logger = logger
        self.log_prefix = log_prefix

    def _get_user_agent(self) -> str:
        """Get User-Agent string."""
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
        """Create and return a BlobServiceClient.

        Args:
            is_validation: When True, performs a live
                get_service_properties() call to confirm connectivity
                and credentials during plugin validation.

        Returns:
            BlobServiceClient instance.

        Raises:
            AzureNLSException: On authentication, HTTP, network, or
                unexpected error.
        """
        try:
            connection_string = self.configuration.get(
                "connection_string"
            ).strip()
            blob_service_client = BlobServiceClient.from_connection_string(
                conn_str=connection_string,
                user_agent=self._get_user_agent(),
            )
            if is_validation:
                blob_service_client.get_service_properties()
            return blob_service_client
        except ClientAuthenticationError as exp:
            err_msg = (
                f"{PLATFORM_NAME} Blob Storage authentication "
                f"failed. Please check the {PLATFORM_NAME} Storage"
                " Account Connection String, Queue Name or "
                "permissions."
            )
            self.logger.error(
                message=(f"{self.log_prefix}: {err_msg} Error: {exp}"),
                details=str(traceback.format_exc()),
                resolution=(
                    "Ensure that the Microsoft Azure Storage Account"
                    " Connection String is correct."
                ),
            )
            raise AzureNLSException(err_msg)
        except HttpResponseError as exp:
            err_msg = (
                f"{PLATFORM_NAME} Blob Storage HTTP error. The "
                "storage account may be missing, have insufficient "
                "permissions, or the request is invalid."
            )
            self.logger.error(
                message=(f"{self.log_prefix}: {err_msg} Error: {exp}"),
                details=str(traceback.format_exc()),
                resolution=(
                    "Ensure that the Microsoft Azure Storage Account"
                    " exists and the account key in the "
                    "Connection String has not been rotated or "
                    "expired."
                ),
            )
            raise AzureNLSException(err_msg)
        except ServiceRequestError as exp:
            err_msg = (
                "A network error occurred while communicating "
                f"with {PLATFORM_NAME} Blob Storage."
            )
            self.logger.error(
                message=(f"{self.log_prefix}: {err_msg} Error: {exp}"),
                details=str(traceback.format_exc()),
                resolution=(
                    "Ensure that the CE host has network "
                    "connectivity and that firewall rules allow "
                    "outbound HTTPS traffic to "
                    "*.blob.core.windows.net."
                ),
            )
            raise AzureNLSException(err_msg)
        except AzureNLSException:
            raise
        except AzureError as exp:
            err_msg = (
                "An unexpected Azure error occurred while "
                f"accessing {PLATFORM_NAME} Blob Storage."
            )
            self.logger.error(
                message=(f"{self.log_prefix}: {err_msg} Error: {exp}"),
                details=str(traceback.format_exc()),
                resolution=(
                    "Ensure that the Microsoft Azure Storage Account"
                    " Connection String is correct and is accessible."
                ),
            )
            raise AzureNLSException(err_msg)
        except Exception as exp:
            err_msg = (
                f"Error occurred while creating {PLATFORM_NAME} "
                f"Blob Service Client for {PLUGIN_NAME}. Verify "
                f"the {PLATFORM_NAME} Storage Account Connection "
                "String provided in the configuration parameters."
            )
            self.logger.error(
                message=(f"{self.log_prefix}: {err_msg} Error: {exp}"),
                details=str(traceback.format_exc()),
                resolution=(
                    "Ensure that the Microsoft Azure Storage Account"
                    " Connection String follows the required format:"
                    " DefaultEndpointsProtocol=https;"
                    "AccountName=<name>;"
                    "AccountKey=<key>;"
                    "EndpointSuffix=core.windows.net"
                ),
            )
            raise AzureNLSException(err_msg)

    def get_queue_client(self):
        """Create and return a QueueClient from the connection string.

        Returns:
            QueueClient instance.

        Raises:
            AzureNLSException: On authentication, HTTP, network, or
                unexpected error.
        """
        try:
            connection_string = self.configuration.get(
                "connection_string"
            ).strip()
            queue_name = self.configuration.get("queue_name").strip()
            queue_client = QueueClient.from_connection_string(
                conn_str=connection_string,
                queue_name=queue_name,
                user_agent=self._get_user_agent(),
            )
            return queue_client
        except ClientAuthenticationError as exp:
            err_msg = (
                f"{PLATFORM_NAME} Queue Storage authentication "
                f"failed. Please check the {PLATFORM_NAME} Storage"
                " Account Connection String, Queue Name or "
                "permissions."
            )
            self.logger.error(
                message=(f"{self.log_prefix}: {err_msg} Error: {exp}"),
                details=str(traceback.format_exc()),
            )
            raise AzureNLSException(err_msg)
        except HttpResponseError as exp:
            err_msg = (
                f"{PLATFORM_NAME} Queue Storage HTTP error. The "
                "queue may be missing, permissions may be "
                "insufficient, or the request is invalid."
            )
            self.logger.error(
                message=(f"{self.log_prefix}: {err_msg} Error: {exp}"),
                details=str(traceback.format_exc()),
                resolution=(
                    "Ensure that the queue "
                    f"'{self.configuration.get('queue_name')}' "
                    f"exists in the {PLATFORM_NAME} Storage Account"
                    " and the Connection String has appropriate "
                    "queue permissions."
                ),
            )
            raise AzureNLSException(err_msg)
        except ServiceRequestError as exp:
            err_msg = (
                "A network error occurred while communicating "
                f"with {PLATFORM_NAME} Queue Storage."
            )
            self.logger.error(
                message=(f"{self.log_prefix}: {err_msg} Error: {exp}"),
                details=str(traceback.format_exc()),
                resolution=(
                    "Ensure that the CE host has network "
                    "connectivity and that firewall rules allow "
                    "outbound HTTPS traffic to "
                    "*.queue.core.windows.net."
                ),
            )
            raise AzureNLSException(err_msg)
        except AzureError as exp:
            err_msg = (
                "An unexpected Azure error occurred while "
                f"accessing {PLATFORM_NAME} Queue Storage."
            )
            self.logger.error(
                message=(f"{self.log_prefix}: {err_msg} Error: {exp}"),
                details=str(traceback.format_exc()),
                resolution=(
                    "Ensure that the Microsoft Azure Storage Account"
                    " is accessible and the Queue Name and "
                    "Connection String are valid."
                ),
            )
            raise AzureNLSException(err_msg)
        except Exception as exp:
            err_msg = (
                f"Error occurred while creating {PLATFORM_NAME} "
                f"Storage Queue Client for {PLUGIN_NAME}. Verify "
                f"the {PLATFORM_NAME} Storage Queue Name and "
                "Connection String provided in the configuration "
                "parameters."
            )
            self.logger.error(
                message=(f"{self.log_prefix}: {err_msg} Error: {exp}"),
                details=str(traceback.format_exc()),
                resolution=(
                    "Ensure that the Microsoft Azure Data Storage "
                    "Queue Name and Connection String are correctly "
                    "configured in the plugin configuration "
                    "parameters."
                ),
            )
            raise AzureNLSException(err_msg)

    def get_queue_service_client(self):
        """Create and return a QueueServiceClient.

        Returns:
            QueueServiceClient instance.

        Raises:
            AzureNLSException: On authentication, HTTP, network, or
                unexpected error.
        """
        try:
            connection_string = self.configuration.get(
                "connection_string"
            ).strip()
            queue_service = QueueServiceClient.from_connection_string(
                conn_str=connection_string,
                user_agent=self._get_user_agent(),
            )
            return queue_service
        except ClientAuthenticationError as exp:
            err_msg = (
                f"Failed to authenticate {PLATFORM_NAME} Queue "
                f"Service Client. Please verify the {PLATFORM_NAME}"
                " Storage Account Connection String and account "
                "access."
            )
            self.logger.error(
                message=(f"{self.log_prefix}: {err_msg} Error: {exp}"),
                details=str(traceback.format_exc()),
                resolution=(
                    "Ensure that the Microsoft Azure Storage Account"
                    " Connection String is correct."
                ),
            )
            raise AzureNLSException(err_msg)
        except HttpResponseError as exp:
            err_msg = (
                f"HTTP error while accessing {PLATFORM_NAME} Queue "
                "Service. Check if the service is available and the"
                " resource exists."
            )
            self.logger.error(
                message=(f"{self.log_prefix}: {err_msg} Error: {exp}"),
                details=str(traceback.format_exc()),
                resolution=(
                    "Ensure that the Microsoft Azure Storage Account"
                    " is active and the account key in the "
                    "Connection String has not been rotated or "
                    "expired."
                ),
            )
            raise AzureNLSException(err_msg)
        except ServiceRequestError as exp:
            err_msg = (
                "A network error occurred while initializing the "
                f"{PLATFORM_NAME} Queue Service Client."
            )
            self.logger.error(
                message=(f"{self.log_prefix}: {err_msg} Error: {exp}"),
                details=str(traceback.format_exc()),
                resolution=(
                    "Ensure that the CE host has network "
                    "connectivity and that firewall rules allow "
                    "outbound HTTPS traffic to "
                    "*.queue.core.windows.net."
                ),
            )
            raise AzureNLSException(err_msg)
        except AzureError as exp:
            err_msg = (
                "An unexpected Azure error occurred while creating "
                f"{PLATFORM_NAME} Queue Service Client."
            )
            self.logger.error(
                message=(f"{self.log_prefix}: {err_msg} Error: {exp}"),
                details=str(traceback.format_exc()),
                resolution=(
                    "Ensure that the Microsoft Azure Storage Account"
                    " is accessible and the Connection String is "
                    "valid."
                ),
            )
            raise AzureNLSException(err_msg)
        except Exception as exp:
            err_msg = (
                f"Unexpected error occurred while creating "
                f"{PLATFORM_NAME} Queue Service Client for "
                f"{PLUGIN_NAME}. Verify the {PLATFORM_NAME} "
                "Storage Queue Name and Connection String provided "
                "in the configuration parameters."
            )
            self.logger.error(
                message=(f"{self.log_prefix}: {err_msg} Error: {exp}"),
                details=str(traceback.format_exc()),
                resolution=(
                    "Ensure that the Microsoft Azure Storage Account"
                    " Connection String format and Queue Name are "
                    "correctly specified in the plugin configuration"
                    " parameters."
                ),
            )
            raise AzureNLSException(err_msg)

    def download_blob(self, container_name: str, blob_name: str) -> bytes:
        """Download blob content from Azure Blob Storage.

        Args:
            container_name: Azure Blob Storage container name.
            blob_name: Blob path/name within the container.

        Returns:
            Raw blob content as bytes.

        Raises:
            AzureNLSException: On authentication failure or unexpected
                error.
        """
        blob_service_client = self.get_blob_service_client()
        try:
            blob_client = blob_service_client.get_blob_client(
                container=container_name,
                blob=blob_name,
            )
            return blob_client.download_blob().readall()
        except ClientAuthenticationError as exp:
            err_msg = (
                "Authentication failed while downloading blob "
                f"'{blob_name}' from container '{container_name}'."
            )
            self.logger.error(
                message=(f"{self.log_prefix}: {err_msg} Error: {exp}"),
                details=str(traceback.format_exc()),
            )
            raise AzureNLSException(err_msg)
        except Exception as exp:
            err_msg = (
                f"Error occurred while downloading blob '{blob_name}"
                f"' from container '{container_name}'."
            )
            self.logger.error(
                message=(f"{self.log_prefix}: {err_msg} Error: {exp}"),
                details=str(traceback.format_exc()),
            )
            raise AzureNLSException(err_msg)

    def get_queue_messages(
        self,
        queue_client,
        messages_per_page: int,
        visibility_timeout: int,
    ):
        """Retrieve messages from the queue.

        Args:
            queue_client: QueueClient instance to receive from.
            messages_per_page: Messages to pull per page (max 32).
            visibility_timeout: Seconds messages stay invisible to
                other consumers after being received.

        Returns:
            QueueMessageIterator from the Azure SDK.

        Raises:
            AzureNLSException: On authentication failure or unexpected
                error.
        """
        try:
            return queue_client.receive_messages(
                messages_per_page=messages_per_page,
                visibility_timeout=visibility_timeout,
            )
        except ClientAuthenticationError as exp:
            err_msg = (
                "Authentication failed while receiving messages "
                f"from {PLATFORM_NAME} Storage Queue."
            )
            self.logger.error(
                message=(f"{self.log_prefix}: {err_msg} Error: {exp}"),
                details=str(traceback.format_exc()),
            )
            raise AzureNLSException(err_msg)
        except Exception as exp:
            err_msg = (
                "Error occurred while receiving messages from "
                f"{PLATFORM_NAME} Storage Queue."
            )
            self.logger.error(
                message=(f"{self.log_prefix}: {err_msg} Error: {exp}"),
                details=str(traceback.format_exc()),
                resolution=(
                    "Ensure that the queue exists and is accessible."
                    " Check that the CE host has network "
                    "connectivity to the Azure Storage endpoint."
                ),
            )
            raise AzureNLSException(err_msg)
