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
