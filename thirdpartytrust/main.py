"""
TODO: Copyright (c) 2022 ThirdPartyTrust
"""

import json
from netskope.integrations.cls.plugin_base import (PluginBase, ValidationResult, PushResult)
from typing import List

from .utils.tpt_api import ThirdPartyTrustDataSender

from .utils.tpt_transformations import (ThirdPartyTrustDataTransformer, get_allowed_fields, get_fields_to_obfuscate,
                                        are_valid_type_subtype)


class ThirdPartyTrustPlugin(PluginBase):
    """The ThirdPartyTrustPlugin plugin implementation class."""

    def transform(self, raw_data, data_type, subtype) -> List:
        """Transform the raw netskope JSON data into target platform supported data formats.

        Args:
            raw_data (list): The raw data to be tranformed.
            data_type (str): The type of data to be ingested (alert/event)
            subtype (str): The subtype of data to be ingested (DLP, anomaly etc. in case of alerts)

        Returns:
            List: list of transformed data.
        """

        if not raw_data:
            return []

        if not are_valid_type_subtype(data_type, subtype):
            return []

        allowed_fields = get_allowed_fields()
        fields_to_obfuscate = get_fields_to_obfuscate()

        tpt_data_transformer = ThirdPartyTrustDataTransformer(allowed_fields=allowed_fields,
                                                              fields_to_obfuscate=fields_to_obfuscate)
        transformed_data = tpt_data_transformer(raw_data)

        return transformed_data

    def push(self, transformed_data, data_type, subtype) -> PushResult:
        """Push the transformed_data to ThirdPartyTrust.

        :param data_type: The type of data being pushed. Current possible values: alerts and events
        :param transformed_data: Transformed data to be ingested to ThirdPartyTrust
        :param subtype: The subtype of data being pushed. E.g. subtypes of alert is "dlp", "policy" etc.
        """

        data = []
        for json_data in transformed_data:
            data.append(json.dumps(json_data))
        final_data = "\n".join(data)

        tpt_token = self.configuration["tpt_integration_token"]
        tpt_data_sender = ThirdPartyTrustDataSender(tpt_token=tpt_token, proxy=self.proxy,
                                                    ssl_validation=self.ssl_validation)

        try:
            tpt_data_sender.send_data(data=final_data, data_type=data_type, data_subtype=subtype)
        except Exception as e:
            self.logger.error(f"Error while pushing data to ThirdPartyTrust: {e}")
            raise

    def validate(self, configuration: dict) -> ValidationResult:
        """Validate the configuration parameters dict."""

        if ("tpt_integration_token" not in configuration
                or type(configuration["tpt_integration_token"]) != str
                or not configuration["tpt_integration_token"].strip()
                or len(configuration["tpt_integration_token"].strip()) < 50):
            error_message = "Invalid ThirdPartyTrust API Key."
            self.logger.error(f"Third Party Trust Plugin: Validation error occurred. Error: {error_message}")
            return ValidationResult(success=False, message=error_message)

        tpt_token = configuration["tpt_integration_token"]
        tpt_data_sender = ThirdPartyTrustDataSender(tpt_token, self.proxy, self.ssl_validation)

        try:
            tpt_data_sender.send_data(data="validating plugin", data_type="validate")

        except Exception as error:
            error_message = "Error occurred while establishing connection with ThirdPartyTrust server. Make sure you " \
                            "have provided valid ThirdPartyTrust API Key."
            self.logger.error(f"Third Party Trust Plugin: Validation error occurred. Error: {error}")
            return ValidationResult(success=False, message=error_message)

        return ValidationResult(success=True, message="Validation successful.")
