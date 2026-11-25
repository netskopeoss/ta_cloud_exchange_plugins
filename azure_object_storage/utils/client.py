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

Microsoft Azure Cloud Storage plugin client.
"""

import datetime
import re
import traceback
import uuid

from azure.core.exceptions import (
    AzureError,
    ClientAuthenticationError,
    HttpResponseError,
    ResourceExistsError,
    ServiceRequestError,
)
from azure.storage.blob import BlobServiceClient
from netskope.common.utils import add_user_agent

from .constants import (
    CONNECTION_TIMEOUT,
    MAX_RETRIES,
    MODULE_NAME,
    PLATFORM_NAME,
    PLUGIN_NAME,
    PLUGIN_VERSION,
    READ_TIMEOUT,
    TYPE_WEBTX,
)
from .exceptions import AzureCloudStorageException


class AzureCloudStorageClient:
    """Microsoft Azure Cloud Storage client class."""

    def __init__(
        self,
        configuration,
        logger,
        proxy,
        log_prefix,
        plugin_name=PLUGIN_NAME,
        plugin_version=PLUGIN_VERSION,
    ):
        """Initialize.

        Args:
            configuration (dict): Plugin configuration parameters.
            logger (logger): Logger object provided by CE Core.
            proxy (dict): Proxy configuration provided by CE Core.
            log_prefix (str): Log prefix for this plugin configuration.
            plugin_name (str): Plugin name read from the manifest.
            plugin_version (str): Plugin version read from the manifest.
        """
        self.configuration = configuration
        self.logger = logger
        self.proxy = proxy
        self.log_prefix = log_prefix
        self.plugin_name = plugin_name
        self.plugin_version = plugin_version
        self._blob_service_client = None
        self._prepared_container = None

    def _get_user_agent(self) -> str:
        """Build the User-Agent string sent with every Azure request.

        The name and version come from the manifest by way of the
        plugin, so the User-Agent cannot drift on a version bump.

        Returns:
            str: User-Agent string.
        """
        headers = add_user_agent()
        ce_added_agent = headers.get("User-Agent", "netskope-ce")
        return "{}-{}-{}-v{}".format(
            ce_added_agent,
            MODULE_NAME.lower(),
            self.plugin_name.lower().replace(" ", "-"),
            self.plugin_version,
        )

    def _handle_azure_error(self, exp, action_msg):
        """Log an Azure SDK error and raise the plugin exception.

        Args:
            exp (Exception): Exception raised by the Azure SDK.
            action_msg (str): What the plugin was doing, phrased so it
                reads as "... occurred while <action_msg>".

        Raises:
            AzureCloudStorageException: Always.
        """
        if isinstance(exp, ClientAuthenticationError):
            err_msg = (
                f"{PLATFORM_NAME} Blob Storage authentication failed "
                f"while {action_msg}."
            )
            resolution = (
                "Ensure that the Azure Connection String provided in "
                "the configuration parameters is correct and that the "
                "account key has not been rotated or expired."
            )
        elif isinstance(exp, ServiceRequestError):
            err_msg = f"A network error occurred while {action_msg}."
            resolution = (
                "Ensure that the CE host has network connectivity and "
                "that firewall rules allow outbound HTTPS traffic to "
                "*.blob.core.windows.net."
            )
        elif isinstance(exp, HttpResponseError):
            err_msg = (
                f"{PLATFORM_NAME} Blob Storage returned an HTTP error "
                f"while {action_msg}."
            )
            resolution = (
                "Ensure that the storage account and container exist "
                "and that the configured credentials are permitted to "
                "write blobs to the container."
            )
        elif isinstance(exp, AzureError):
            err_msg = (
                f"An unexpected Azure error occurred while {action_msg}."
            )
            resolution = (
                "Ensure that the Azure Connection String is correct "
                "and that the storage account is reachable from the "
                "CE host."
            )
        else:
            err_msg = f"Unexpected error occurred while {action_msg}."
            resolution = (
                "Ensure that the Azure Connection String follows the "
                "required format: DefaultEndpointsProtocol=https;"
                "AccountName=<name>;AccountKey=<key>;"
                "EndpointSuffix=core.windows.net"
            )
        self.logger.error(
            message=f"{self.log_prefix}: {err_msg} Error: {exp}",
            details=str(traceback.format_exc()),
            resolution=resolution,
        )
        raise AzureCloudStorageException(err_msg)

    def get_blob_service_client(self):
        """Return the BlobServiceClient, building it on first use.

        The client is cached so that a push cycle writing several
        blobs does not rebuild it for each one. The User-Agent, proxy
        configuration, retry count and socket timeouts are applied at
        construction so that every operation inherits them.

        Returns:
            BlobServiceClient: Configured blob service client.

        Raises:
            AzureCloudStorageException: If the client cannot be built.
        """
        if self._blob_service_client is not None:
            return self._blob_service_client
        connection_string = self.configuration.get(
            "azure_connection_string", ""
        ).strip()
        try:
            self._blob_service_client = (
                BlobServiceClient.from_connection_string(
                    conn_str=connection_string,
                    user_agent=self._get_user_agent(),
                    proxies=self.proxy,
                    retry_total=MAX_RETRIES,
                    connection_timeout=CONNECTION_TIMEOUT,
                    read_timeout=READ_TIMEOUT,
                )
            )
            return self._blob_service_client
        except Exception as exp:
            self._handle_azure_error(
                exp,
                f"creating the {PLATFORM_NAME} Blob Service Client",
            )

    def validate_connectivity(self, container_name):
        """Confirm the credentials can reach the configured container.

        The container is probed directly instead of listing every
        container on the account, so that credentials scoped to a
        single container validate successfully.

        Args:
            container_name (str): Container configured for this plugin.

        Raises:
            AzureCloudStorageException: If the container is unreachable.
        """
        action_msg = (
            f"validating access to the container '{container_name}'"
        )
        try:
            blob_service_client = self.get_blob_service_client()
            container_client = blob_service_client.get_container_client(
                container_name
            )
            container_client.exists()
        except AzureCloudStorageException:
            raise
        except Exception as exp:
            self._handle_azure_error(exp, action_msg)

    def _ensure_container(self, container_name):
        """Create the configured container when it does not exist.

        The check runs once per client, so a push cycle writing
        several blobs does not repeat the round trip.

        Args:
            container_name (str): Container to write to.
        """
        if self._prepared_container == container_name:
            return
        blob_service_client = self.get_blob_service_client()
        container_client = blob_service_client.get_container_client(
            container_name
        )
        try:
            if container_client.exists():
                self._prepared_container = container_name
                return
        except HttpResponseError:
            # A credential scoped to a single container may not be
            # permitted to check for existence. Fall through and let
            # the create attempt below decide.
            pass
        try:
            container_client.create_container()
            self.logger.info(
                f"{self.log_prefix}: Created a new container named "
                f"'{container_name}' in {PLATFORM_NAME} Blob Storage."
            )
        except ResourceExistsError:
            pass
        self._prepared_container = container_name

    def _get_object_name(self, data_type, subtype, extension) -> str:
        """Build the blob name, including its folders, for an upload.

        Blobs are grouped in folders by the Object Prefix, data type,
        subtype and the UTC hour of the upload, e.g.
        <prefix>/alerts/feedname=dlp/year=2026/month=11/day=24/hour=9/<name>.

        Args:
            data_type (str): Data type being pushed.
            subtype (str): Subtype being pushed.
            extension (str): Blob name suffix, including the leading dot.

        Returns:
            str: Blob name.
        """
        now = datetime.datetime.now(datetime.timezone.utc)
        feed = (
            re.sub(r"[^A-Za-z0-9_-]+", "_", str(subtype)).strip("_")
            if subtype
            else "none"
        )
        folder = (
            f"{data_type or TYPE_WEBTX}/feedname={feed}"
            f"/year={now.year}/month={now.month}/day={now.day}"
            f"/hour={now.hour}"
        )
        prefix = self.configuration.get("obj_prefix", "").strip().strip("/")
        if prefix:
            folder = f"{prefix}/{folder}"
        name = f"{int(now.timestamp())}_{uuid.uuid4()}"
        return f"{folder}/{name}{extension}"

    def push(self, file_name, data_type, subtype, extension) -> str:
        """Upload one prepared object file to the container.

        Args:
            file_name (str): Path of the local object file to upload.
            data_type (str): Data type being pushed.
            subtype (str): Subtype being pushed.
            extension (str): Blob name suffix, including the leading dot.

        Returns:
            str: Name of the blob that was created.

        Raises:
            AzureCloudStorageException: If the upload fails.
        """
        container_name = self.configuration.get("container_name", "").strip()
        object_name = self._get_object_name(data_type, subtype, extension)
        action_msg = (
            f"uploading the blob '{object_name}' to the container "
            f"'{container_name}'"
        )
        try:
            self._ensure_container(container_name)
            blob_service_client = self.get_blob_service_client()
            blob_client = blob_service_client.get_blob_client(
                container=container_name, blob=object_name
            )
            with open(file_name, "rb") as object_file:
                blob_client.upload_blob(object_file, overwrite=True)
            self.logger.debug(
                f"{self.log_prefix}: Successfully uploaded the blob "
                f"'{object_name}' to the container '{container_name}'."
            )
            return object_name
        except AzureCloudStorageException:
            raise
        except Exception as exp:
            self._handle_azure_error(exp, action_msg)
