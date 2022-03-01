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

"""API Sources Plugin providing implementation for pull and validate methods from PluginBase."""


from typing import Dict
from netskope.integrations.cte.plugin_base import (
    PluginBase,
    ValidationResult,
    PushResult,
)
from netskope.integrations.cte.models.business_rule import Action, ActionWithoutParams


class APISourcesPlugin(PluginBase):
    """APISourcesPlugin class template implementation."""

    def pull(self):
        """Pull the Threat information from Netskope Tenant.

        Returns:
            List[cte.models.Indicators]: List of indicator objects received from the Netskope.
        """
        self.logger.info("Plugin: API Sources Pull successful")
        return []

    def push(self, indicators, action_dict: Dict):
        """Mark indicators as pushed."""
        return PushResult(success=True, message="Pushed successfully.")

    def validate(self, data):
        """Validate the Plugin configuration parameters.

        Args:
            data (dict): Dict object having all the Plugin configuration parameters.
        Returns:
            cte.plugin_base.ValidateResult: ValidateResult object with success flag and message.
        """
        self.logger.info("Plugin: API Sources Executing validate method")

        self.logger.info("Plugin: API Sources Validation Successfull")
        return ValidationResult(
            success=True,
            message="Validation Successfull for API sources plugin",
        )

    def get_actions(self):
        """Get available actions."""
        return [
            ActionWithoutParams(label="Share Indicators", value="share"),
        ]

    def validate_action(self, action: Action):
        """Validate APISource configuration."""
        if action.value not in ["share"]:
            return ValidationResult(
                success=False, message="Unsupported action provided."
            )

        return ValidationResult(success=True, message="Validation successful.")

    def get_action_fields(self, action: Action):
        """Get fields required for an action."""
        return []
