"""GCP validator."""

import json
from google.cloud import storage
from google.cloud import exceptions
from .gcp_constant import (
    locations_list,
    storage_classes_list,
)


class GCPValidator(object):
    """GCP validator class."""

    def __init__(self, logger):
        """Initialize."""
        super().__init__()
        self.logger = logger

    def validate_location_name(self, location):
        """Validate location.

        Args:
            location: region name.

        Returns:
            location will be supported in gcp storage. True if yes, False otherwise
        """
        if location in locations_list:
            return True
        else:
            return False

    def validate_storage_class(self, storage_class):
        """Validate storage class.

        Args:
            storage_class: storage class name.

        Returns:
            storage class will be supported in gcp storage. True if yes, False otherwise
        """
        if storage_class in storage_classes_list:
            return True
        else:
            return False

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

    def auth_key_file_and_create_bucket(
        self, json_key_file, bucket_name, location, storage_class_for_object
    ):
        """Validate key file for gcp service account."""
        try:
            key = json.loads(json_key_file)
        except json.decoder.JSONDecodeError as err:
            self.logger.error(
                f"GCP Storage Plugin: Error occurred while decoding JSON key: {err}"
            )
            raise
        except Exception as err:
            self.logger.error(f"Google Storage Plugin: {err}")
            raise

        try:
            client = storage.Client.from_service_account_info(key)
            buckets = list(client.list_buckets())  # Noqa
        except Exception as err:
            self.logger.error(
                "GCP Storage Plugin: Validation error occurred. Error: "
                "Invalid key file provided in configuration parameters."
            )
            self.logger.error(f"Google Storage Plugin: {err}")
            raise

        present = False
        for bucket in buckets:
            if bucket.name == bucket_name:
                present = True
                break

        if not present:
            try:
                bucket = client.bucket(bucket_name)
                bucket.storage_class = storage_class_for_object
                client.create_bucket(bucket, location=location)
            except exceptions.Conflict:
                self.logger.error(
                    f"Sorry, Bucket Name {bucket_name} is not available. Please try a different one."
                )
                raise
            except Exception as err:
                self.logger.error(
                    f"GCP Storage Plugin: Error occured while creating bucket: {err}"
                )
                raise
        return True
