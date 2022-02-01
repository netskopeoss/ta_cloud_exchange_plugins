"""MCASB implementation to push and pull the data."""
import requests
from netskope.integrations.cte.plugin_base import PluginBase, ValidationResult
from netskope.integrations.cte.models import Indicator, IndicatorType, TagIn
from netskope.integrations.cte.utils import TagUtils
from netskope.integrations.cte.models.business_rule import Action
from netskope.common.utils import add_user_agent


PAGE_SIZE = 50


class MicrosoftCASBPlugin(PluginBase):
    """The TAXIIPlugin implementation."""

    def _create_tags(self, utils):
        if not utils.exists(self.configuration["tag"].strip()):
            utils.create_tag(
                TagIn(name=self.configuration["tag"].strip(), color="#ED3347")
            )

    def pull(self):
        """Pull data from MCAS."""
        utils = TagUtils()
        if self.configuration["enable_tagging"] == "yes":
            self._create_tags(utils)
            tagging = True
        else:
            tagging = False
        domains = []
        skip = 0
        while True:
            response = requests.get(
                f"{self.configuration['url'].strip('/')}/api/discovery_block_scripts/",
                params={"type": "banned", "limit": PAGE_SIZE, "skip": skip},
                headers=add_user_agent({
                    "Authorization": f"Token {self.configuration['token']}"
                }),
            )
            response.raise_for_status()
            response_json = response.json()
            if response.status_code == 200:
                data = response_json.get("data", [])
                for item in data:
                    domains += item.get("domainList", [])
            skip = skip + PAGE_SIZE
            if not response_json.get("hasNext", False):
                break
        indicators = []
        for domain in domains:
            indicators.append(
                Indicator(
                    value=domain,
                    type=IndicatorType.URL,
                    tags=[self.configuration["tag"].strip()]
                    if tagging
                    else [],
                )
            )
        if tagging:
            utils.on_indicators(
                {"source": self.name, "value": {"$nin": domains}}
            ).remove(self.configuration["tag"].strip())
        return indicators

    def _validate_credentials(self, url: str, token: str):
        """Validate API credentials."""
        try:
            response = requests.get(
                f"{url.strip('/')}/api/discovery_block_scripts/",
                params={"type": "banned", "limit": 1},
                headers=add_user_agent({"Authorization": f"Token {token}"}),
            )
            if response.status_code == 200:
                return ValidationResult(
                    success=True, message="Validation successful."
                )
            elif response.status_code == 401:
                return ValidationResult(
                    success=False, message="Invalid API Token provided."
                )
            elif response.status_code == 404:
                return ValidationResult(
                    success=False, message="Invalid URL provided."
                )
            else:
                return ValidationResult(
                    success=False, message="Could not verify credentials."
                )
        except Exception as ex:
            self.logger.error(f"MCASB Plugin: {repr(ex)}")
            return ValidationResult(
                success=False, message="Could not verify credentials."
            )

    def validate(self, configuration):
        """Validate the configuration."""
        if "url" not in configuration or not configuration["url"].strip():
            self.logger.error(
                "MCASB Plugin: No url key found in the configuration parameters."
            )
            return ValidationResult(
                success=False, message="Invalid URL provided."
            )

        if "token" not in configuration or not configuration["token"].strip():
            self.logger.error(
                "MCASB Plugin: No token key found in the configuration parameters."
            )
            return ValidationResult(
                success=False, message="Invalid token provided."
            )

        if "tag" not in configuration or not configuration["tag"].strip():
            self.logger.error(
                "MCASB Plugin: No tag key found in the configuration parameters.."
            )
            return ValidationResult(
                success=False, message="Invalid tag name provided."
            )

        if len(configuration["tag"].strip()) > 50:
            return ValidationResult(
                success=False, message="Tag name can not exceed 50 characters."
            )

        return self._validate_credentials(
            configuration["url"], configuration["token"]
        )

    def get_actions(self):
        """Get available actions."""
        return []

    def validate_action(self, action: Action):
        """Validate mcas configuration."""
        return ValidationResult(success=True, message="Validation successful.")

    def get_action_fields(self, action: Action):
        """Get fields required for an action."""
        return []
