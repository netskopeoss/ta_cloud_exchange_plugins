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
"""
"""BitSight CLS Plugin."""

import json
from typing import List

from netskope.integrations.cls.plugin_base import (
    PluginBase,
    PushResult,
    ValidationResult,
)

from .utils.tpt_api import BitSightDataSender
from .utils.tpt_transformations import (
    BitSightDataTransformer,
    are_valid_type_subtype,
    get_allowed_fields,
    get_fields_to_obfuscate,
)

PLUGIN_NAME = "BitSight CLS Plugin"


class BitSightPlugin(PluginBase):
    """The BitSight plugin implementation class."""

    def transform(self, raw_data: List, data_type: str, subtype: str) -> List:
        """Transform the raw netskope JSON data into target platform supported data formats.

        Args:
            raw_data (list): The raw data to be transformed.
            data_type (str): The type of data to be ingested (alert/event)
            subtype (str): The subtype of data to be ingested(DLP, anomaly etc. in case of alerts)

        Returns:
            List: list of transformed data.
        """

        if not raw_data:
            return []

        if not are_valid_type_subtype(data_type, subtype):
            return []

        allowed_fields = get_allowed_fields()
        fields_to_obfuscate = get_fields_to_obfuscate()

        bitsight_data_transformer = BitSightDataTransformer(
            allowed_fields=allowed_fields,
            fields_to_obfuscate=fields_to_obfuscate,
        )
        transformed_data = bitsight_data_transformer(raw_data)

        return transformed_data

    def push(
        self, transformed_data: List, data_type: str, subtype: str
    ) -> PushResult:
        """Push the transformed_data to BitSight.

        Args:
            transformed_data (List): Transformed data to be ingested to BitSight
            data_type (str): The type of data being pushed. Current possible values: alerts and events
            subtype (str): The subtype of data being pushed.E.g. subtypes of alert is "dlp", "policy" etc.

        Returns:
            PushResult: PushResult
        """
        data = []
        for json_data in transformed_data:
            data.append(json.dumps(json_data))
        final_data = "\n".join(data)

        bitsight_token = self.configuration[
            "bitsight_integration_token"
        ].strip()
        bitsight_data_sender = BitSightDataSender(
            bitsight_token=bitsight_token,
            proxy=self.proxy,
            ssl_validation=self.ssl_validation,
        )

        try:
            bitsight_data_sender.send_data(
                data=final_data, data_type=data_type, data_subtype=subtype
            )
        except Exception as e:
            self.logger.error(
                f"{PLUGIN_NAME}: Error occurred while pushing "
                f"data to BitSight.{e}"
            )
            raise

    def validate(self, configuration: dict) -> ValidationResult:
        """Validate the configuration parameters dict."""

        if (
            "bitsight_integration_token" not in configuration
            or not configuration["bitsight_integration_token"].strip()
        ):
            error_message = "API Key is a required field."
            self.logger.error(
                f"{PLUGIN_NAME}: Validation error occurred. "
                f"Error: {error_message}"
            )
            return ValidationResult(success=False, message=error_message)

        elif type(configuration["bitsight_integration_token"]) != str:
            error_message = "Invalid BitSight API Key."
            self.logger.error(
                f"{PLUGIN_NAME}: Validation error occurred. "
                f"Error: {error_message}"
            )
            return ValidationResult(success=False, message=error_message)

        if len(configuration["bitsight_integration_token"].strip()) < 50:
            error_message = "API Key should be greater than 50 characters."
            self.logger.error(
                f"{PLUGIN_NAME}: Validation Error occurred. "
                f"{error_message}"
            )
            return ValidationResult(success=False, message=error_message)

        bitsight_token = configuration["bitsight_integration_token"].strip()
        bitsight_data_sender = BitSightDataSender(
            bitsight_token, self.proxy, self.ssl_validation
        )

        try:
            bitsight_data_sender.send_data(
                data="validating plugin", data_type="validate"
            )

        except Exception as error:
            error_message = (
                "Error occurred while establishing connection with "
                "BitSight server. Make sure you "
                "have provided valid BitSight API Key."
            )
            self.logger.error(
                f"{PLUGIN_NAME}: Validation error occurred." f" Error: {error}"
            )
            return ValidationResult(success=False, message=error_message)

        return ValidationResult(success=True, message="Validation successful.")
