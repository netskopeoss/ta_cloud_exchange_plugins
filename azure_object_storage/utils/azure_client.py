"""Azure Client."""
import time
import uuid
from azure.storage.blob import (
    BlobServiceClient,
)


class AzureClient:
    """Azure Sentinel Client Class."""

    def __init__(self, configuration, logger, proxy):
        """Initialize."""
        self.configuration = configuration
        self.logger = logger
        self.proxy = proxy

    def push(self, file_name, data_type, subtype):
        """Call method of post_data with appropriate parameters.

        :param data: The data to be ingested
        :param data_type: The type of the data being ingested (alerts/events)
        """
        # Setting a few properties of data being ingested
        cur_time = int(time.time())
        if data_type is None:
            object_name = (
                f'{self.configuration["obj_prefix"]}_webtx_{cur_time}'
            )
        else:
            object_name = f'{self.configuration["obj_prefix"]}_{data_type}_{subtype}_{cur_time}_{str(uuid.uuid1())}'

        try:
            connect_str = self.configuration.get("azure_connection_string")

            # Create the BlobServiceClient object which will be used to create a container client
            blob_service_client = BlobServiceClient.from_connection_string(
                connect_str,
            )
            container_name = self.configuration.get("container_name")
            name = []
            list_container = blob_service_client.list_containers(
                name_starts_with=None, proxies=self.proxy
            )
            for i in list_container:
                name.append(i["name"])

            if container_name not in name:
                # Create the container
                blob_service_client.create_container(container_name, proxies=self.proxy)
                self.logger.info(
                    "New container created named {} in Azure.".format(
                        container_name
                    )
                )

            # Create a blob client using the local file name as the name for the blob
            blob_client = blob_service_client.get_blob_client(
                container=container_name, blob=object_name
            )

            # Upload the created file
            with open(file_name, "rb") as data:
                blob_client.upload_blob(data, overwrite=True, proxies=self.proxy)

            self.logger.info(
                f"Successfully Uploaded to Azure Storage as blob file. {object_name}"
            )
        except Exception as ex:
            self.logger.error(
                f"Error occurred while Pushing data object: {ex}"
            )
            raise
