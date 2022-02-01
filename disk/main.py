"""AWS S3 Plugin."""

import time
from typing import List
from os import path

from netskope.integrations.cls.plugin_base import (
    PluginBase,
    ValidationResult,
    PushResult,
)


class DiskPlugin(PluginBase):
    """The AWS S3 plugin implementation class."""

    def transform(self, raw_data, data_type, subtype) -> List:
        """Transform the raw netskope JSON data into target platform supported data formats.

        Args:
            raw_data (list): The raw data to be tranformed.
            data_type (str): The type of data to be ingested (alert/event)
            subtype (str): The subtype of data to be ingested (DLP, anomaly etc. in case of alerts)

        Raises:
            NotImplementedError: If the method is not implemented.

        Returns:
            List: list of transformed data.
        """
        return raw_data

    def push(self, transformed_data, data_type, subtype) -> PushResult:
        """Push the transformed_data to the 3rd party platform."""
        try:
            with open(
                path.join(
                    self.configuration.get("storage_path"),
                    f"{self.configuration.get('obj_prefix', 'default')}_webtx_{int(time.time())}.txt.gz",
                ),
                "wb",
            ) as out:
                for data in transformed_data:
                    out.write(data)
        except Exception as e:
            self.logger.error(f"Error while storing to disk: {e}")
            raise

    def validate(self, configuration: dict) -> ValidationResult:
        """Validate the configuration parameters dict."""
        return ValidationResult(success=True, message="Validation successful.")
