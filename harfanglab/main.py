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
HarfangLab Plugin providing implementation for pull and validate
methods from PluginBase."""

import json
import os
import requests
from typing import Dict, List, Tuple
import traceback
import urllib.parse

from netskope.integrations.cte.models import (
    Indicator,
)
from netskope.integrations.cte.models.business_rule import (
    Action,
    ActionWithoutParams,
)
from netskope.integrations.cte.plugin_base import (
    PluginBase,
    ValidationResult,
    PushResult,
)

from .utils.harfanglab_helper import (
    HarfangLabPluginException,
    HarfangLabPluginHelper,
)


from .utils.harfanglab_constants import (
    MODULE_NAME,
    PLUGIN_NAME,
    PLATFORM_NAME,
    PLUGIN_VERSION,
    INTERNAL_TYPES_TO_HARFANGLAB,
    PAGE_LIMIT,
)


class HarfangLabPlugin(PluginBase):
    """HarfangLab class template implementation."""

    def __init__(self, name, *args, **kwargs):
        """HarfangLab plugin initializer.

        Args:
            name (str): Plugin configuration name.
        """
        super().__init__(name, *args, **kwargs)
        self.plugin_name, self.plugin_version = self._get_plugin_info()
        self.log_prefix = f"{MODULE_NAME} {self.plugin_name}"
        if name:
            self.log_prefix = f"{self.log_prefix} [{name}]"

        self.harfanglab_helper = HarfangLabPluginHelper(
            logger=self.logger,
            log_prefix=self.log_prefix,
            plugin_name=self.plugin_name,
            plugin_version=self.plugin_version,
        )

    def _get_plugin_info(self) -> Tuple:
        """Get plugin name and version from manifest.

        Returns:
            tuple: Tuple of plugin's name and version fetched from manifest.
        """
        try:
            file_path = os.path.join(
                str(os.path.dirname(os.path.abspath(__file__))),
                "manifest.json",
            )
            with open(file_path, "r") as manifest:
                manifest_json = json.load(manifest)
                plugin_name = manifest_json.get("name", PLUGIN_NAME)
                plugin_version = manifest_json.get("version", PLUGIN_VERSION)
                return (plugin_name, plugin_version)
        except Exception as exp:
            self.logger.error(
                message=(
                    f"{MODULE_NAME} {PLUGIN_NAME}: Error occurred while"
                    f" getting plugin details. Error: {exp}"
                ),
                details=str(traceback.format_exc()),
            )
        return (PLUGIN_NAME, PLUGIN_VERSION)

    def push(self, indicators: List[Indicator], action_dict: Dict):
        """Push indicators to HarfangLab.

        Args:
            indicators (List[Indicator]): List of Indicators
            action_dict (dict): Action dictionary
        Returns:
            PushResult : return PushResult with success and message parameters.
        """
        try:
            action_parameters = action_dict.get("parameters", {})
            ioc_list_dict = json.loads(
                action_parameters.get("ioc_list_name", "")
            )
            ioc_list_name, ioc_list_id = (
                list(ioc_list_dict.keys())[0],
                list(ioc_list_dict.values())[0],
            )
            new_list_name = action_parameters.get("new_source", "")
            headers = {
                "accept": "application/json",
                "Authorization": self.configuration.get("apikey"),
                "Content-Type": "application/json",
            }
            list_name, list_id = self.validate_list(
                ioc_list_name, ioc_list_id, new_list_name
            )
            if not list_id:
                err_msg = (
                    f"The IOC List '{list_name}' "
                    f"does not exists on {PLATFORM_NAME}. "
                    "Verify the list name or select "
                    "Create New IOC List option."
                )
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg}",
                    details=(
                        f"IOC List selected '{list_name}' does not "
                        "exists on {PLATFORM_NAME}."
                    ),
                )
                raise HarfangLabPluginException(err_msg)

            ioc_url = (
                self.configuration.get("fqdn").strip().rstrip("/")
                + "/api/data/threat_intelligence/IOCRule/"
            )
            self.logger.debug(
                f"{self.log_prefix}: API Endpoint for pushing the indicators"
                f" - {ioc_url}."
            )
            if action_dict["value"] == "create_iocs":
                # Threat IoCs
                total_duplicated_ioc = 0
                total_skipped_ioc = 0
                total_pushed_ioc = 0
                for indicator in indicators:
                    indicator_value = indicator.value
                    log_msg = f"pushing indicator '{indicator_value}'"
                    payload = json.dumps(
                        {
                            "value": indicator.value,
                            "source_id": list_id,
                            "type": INTERNAL_TYPES_TO_HARFANGLAB[
                                indicator.type
                            ],
                        }
                    )
                    push_resp = self.harfanglab_helper.api_helper(
                        url=ioc_url,
                        method="POST",
                        proxies=self.proxy,
                        headers=headers,
                        payload=payload,
                        verify=self.ssl_validation,
                        is_handle_error_required=False,
                        logger_msg=log_msg,
                    )
                    if push_resp.status_code == 400 and push_resp.text.find(
                        "Ioc rule with this Type, Value and Source already exists."
                    ):
                        self.logger.info(
                            message=(
                                f"{self.log_prefix}: "
                                f"Indicator '{indicator_value}' will not "
                                "be shared as it already "
                                f"exists on {PLATFORM_NAME}."
                            )
                        )
                        total_duplicated_ioc += 1
                        continue
                    elif push_resp.status_code == 400:
                        self.logger.error(
                            f"{self.log_prefix}: Error occurred while "
                            f"sharing indicator '{indicator_value}'.",
                            details=f"Error: {push_resp.text}",
                        )
                        total_skipped_ioc += 1
                        continue
                    self.harfanglab_helper.handle_error(push_resp, log_msg)
                    total_pushed_ioc += 1
                self.logger.info(
                    f"{self.log_prefix}: Successfully shared "
                    f"{total_pushed_ioc} indicator(s), "
                    f"{total_duplicated_ioc} indicator(s) were not "
                    f"shared as they were already present on {PLATFORM_NAME}, "
                    f"failed to share {total_skipped_ioc} indicator(s) as "
                    "some error occurred while sharing."
                )
                return PushResult(
                    success=True,
                    message=f"Successfully executed push method for "
                    f"action '{action_dict.get('label')}'.",
                )
        except HarfangLabPluginException as err:
            error_msg = (
                "Error occurred while sharing "
                f"indicators with {PLATFORM_NAME}."
            )
            authorization = headers.get(
                "Authorization", "No value in Authorization"
            )
            redacted_msg = str(err).replace(authorization, "<API Token>")
            self.logger.error(
                f"{self.log_prefix}: {error_msg}",
                details=str(traceback.format_exc()).replace(
                    authorization, "<API Token>"
                ),
            )
            raise HarfangLabPluginException(redacted_msg)
        except Exception as err:
            error_msg = (
                f"Error occurred while sharing "
                f"indicators with {PLATFORM_NAME}."
            )
            authorization = headers.get(
                "Authorization", "No value in Authorization"
            )
            redacted_msg = str(err).replace(authorization, "<API Token>")
            self.logger.error(
                f"{self.log_prefix}: {error_msg} Error: {redacted_msg}",
                details=str(traceback.format_exc()).replace(
                    authorization, "<API Token>"
                ),
            )
            raise HarfangLabPluginException(redacted_msg)

    def pull(self):
        """Pull indicators from HarfangLab."""
        self.logger.info(
            f"{self.log_prefix}: Pulling of indicators is not "
            f"supported by {PLATFORM_NAME}, "
            "hence no indicators will be pulled."
        )
        return []

    def _validate_url(self, url: str) -> bool:
        """Validate the URL using parsing.

        Args:
            url (str): Given URL.

        Returns:
            bool: True or False { Valid or not Valid URL }.
        """
        parsed = urllib.parse.urlparse(url.strip())
        return (
            parsed.scheme.strip() != ""
            and parsed.netloc.strip() != ""
            and (parsed.path.strip() == "/" or parsed.path.strip() == "")
        )

    def validate(self, configuration) -> ValidationResult:
        """Validate the Plugin configuration parameters.

        Args:
            configuration (dict): Dict object having all the Plugin
            configuration parameters.
        Returns:
            cte.plugin_base.ValidateResult: ValidateResult object with
            success flag and message.
        """

        # Base URL
        fqdn = configuration.get("fqdn", "").strip().rstrip("/")
        if "fqdn" not in configuration or not fqdn:
            err_msg = "Tenant URL is a required field."
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            return ValidationResult(success=False, message=err_msg)
        elif not isinstance(fqdn, str) or not self._validate_url(fqdn):
            err_msg = "Invalid Tenant URL provided."
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            return ValidationResult(success=False, message=err_msg)

        # API Token
        api_secret = configuration.get("apikey")
        if "apikey" not in configuration or not api_secret:
            err_msg = "API Token is a required field."
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            return ValidationResult(success=False, message=err_msg)
        elif not isinstance(api_secret, str):
            err_msg = "Invalid API Token provided."
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            return ValidationResult(success=False, message=err_msg)

        return self.validate_params(configuration)

    def validate_params(self, configuration) -> ValidationResult:
        """Validate the authentication params with HarfangLab platform.

        Args: configuration (dict): Configuration parameters dictionary.
        Returns:
            ValidationResult: ValidationResult object having validation
            results after making an API call.
        """

        try:
            url_endpoint = (
                f"{configuration.get('fqdn', '').strip().rstrip('/')}"
                "/api/data/threat_intelligence/IOCSource"
            )
            headers = {"Authorization": configuration.get("apikey")}
            payload = {"limit": 1}
            self.harfanglab_helper.api_helper(
                url=url_endpoint,
                method="GET",
                headers=headers,
                payload=payload,
                proxies=self.proxy,
                verify=self.ssl_validation,
                is_handle_error_required=True,
                logger_msg="authenticating",
            )
            return ValidationResult(
                success=True,
                message="Validation successful.",
            )
        except requests.exceptions.ProxyError as err:
            return ValidationResult(
                success=False,
                message=str(err),
            )
        except requests.exceptions.ConnectionError as err:
            return ValidationResult(success=False, message=str(err))
        except requests.HTTPError as err:
            return ValidationResult(
                success=False,
                message=str(err),
            )
        except HarfangLabPluginException as err:
            return ValidationResult(
                success=False,
                message=str(err),
            )
        except Exception as exp:
            err_msg = (
                "Error occurred while validating credentials, "
                "check the credentials provided."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}. Error: {exp}",
                details=str(traceback.format_exc()),
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )

    def get_actions(self):
        """Get available actions."""
        return [
            ActionWithoutParams(
                label="Create IOCs",
                value="create_iocs",
            ),
        ]

    def validate_list(self, ioc_list_name, ioc_list_id, new_source_name):
        """Validate List validates whether the list provided
        still exists on the HarfangLab platform. Also tries to create list
        in case new list name is provided.

        Args:
            request (request): Requests object.
            ioc_list_name (str): Selected IOC List Name by the user.
            ioc_list_id (str): ID of the selected IOC List Name.
            newsource_name (str): New Source Name to create new list.

        Returns:
            tuple: IOC List Name and IOC List ID.
        """
        try:
            all_list_names = self.get_ioc_sources()
            if ioc_list_name != "create_new_list":
                if ioc_list_name not in all_list_names.keys():
                    err_msg = (
                        f"The selected IOC List Name '{ioc_list_name}' "
                        f"does not exists on the {PLATFORM_NAME}."
                        "Check the IOC List Name provided or select "
                        "'Create New IOC List' option."
                    )
                    self.logger.error(
                        f"{self.log_prefix}: {err_msg}",
                        details=f"'{ioc_list_name}' does not exists on "
                        f"the {PLATFORM_NAME}.",
                    )
                    raise HarfangLabPluginException(err_msg)
                self.logger.info(
                    f"{self.log_prefix}: Successfully verified IOC List "
                    f"'{ioc_list_name}' with ID: {ioc_list_id} "
                    f"on {PLATFORM_NAME}."
                )
                return ioc_list_name, ioc_list_id

            # Check if the new list name provided already exists
            if new_source_name in all_list_names:
                msg = (
                    f"The new list name '{new_source_name}' "
                    f"already exists on {PLATFORM_NAME}. "
                    "Indicators will be shared to the same list."
                )
                self.logger.info(f"{self.log_prefix}: {msg}")
                ioc_list_id = all_list_names.get(new_source_name)
                self.logger.info(
                    f"{self.log_prefix}: Successfully fetched IOC List ID "
                    f"for IOC List '{new_source_name}' - {ioc_list_id}."
                )
                return new_source_name, ioc_list_id
            # create list
            headers = {"Authorization": self.configuration.get("apikey")}
            payload = {
                "description": "IOC List created from Netskope CE",
                "name": new_source_name,
            }
            url_endpoint = (
                f"{self.configuration.get('fqdn', '').strip().rstrip('/')}"
                "/api/data/threat_intelligence/IOCSource/"
            )
            create_list_resp = self.harfanglab_helper.api_helper(
                url=url_endpoint,
                method="POST",
                headers=headers,
                payload=payload,
                verify=self.ssl_validation,
                proxies=self.proxy,
                is_handle_error_required=True,
                logger_msg="creating IOC List",
            )
            ioc_list_id = create_list_resp.get("id", "")
            self.logger.info(
                f"{self.log_prefix}: Successfully created IOC List with "
                f"name '{new_source_name}' and ID '{ioc_list_id}'."
            )
            return new_source_name, ioc_list_id
        except HarfangLabPluginException as err:
            raise HarfangLabPluginException(err)
        except Exception as err:
            err_msg = "Error occurred while fetching IOC List ID."
            self.logger.error(
                f"{self.log_prefix}: {err_msg} Error: {err}",
                details=str(traceback.format_exc()),
            )
            raise HarfangLabPluginException(err_msg)

    def validate_action(self, action: Action):
        """Validate HarfangLab Action Configuration."""
        try:
            if action.value not in ["create_iocs"]:
                return ValidationResult(
                    success=False, message="Invalid action."
                )
            action_parameters = action.parameters
            if (
                "ioc_list_name" not in action_parameters
                or not action_parameters.get("ioc_list_name", "")
            ):
                error_msg = "IOC List Name is a required field."
                self.logger.error(f"{self.log_prefix}: {error_msg}")
                return ValidationResult(success=False, message=f"{error_msg}")
            elif not isinstance(
                action_parameters.get("ioc_list_name", ""), str
            ):
                error_msg = "Invalid IOC List Name provided."
                self.logger.error(f"{self.log_prefix}: {error_msg}")
                return ValidationResult(success=False, message=f"{error_msg}")
            ioc_source_value = json.loads(
                action_parameters.get("ioc_list_name", "")
            )
            ioc_source_name = list(ioc_source_value.keys())[0]
            ioc_source_id = ioc_source_value.get(ioc_source_name)
            new_source_name = action_parameters.get("new_source", "").strip()
            if ioc_source_name == "create_new_list" and not new_source_name:
                error_msg = (
                    "New IOC List Name is a required field when "
                    "'Create New IOC List' is selected in the "
                    "'IOC List Name' field."
                )
                self.logger.error(f"{self.log_prefix}: {error_msg}")
                return ValidationResult(success=False, message=error_msg)
            _, ioc_list_id = self.validate_list(
                ioc_source_name, ioc_source_id, new_source_name
            )
            if ioc_list_id:
                return ValidationResult(
                    success=True, message="Validation successful."
                )
            else:
                error_msg = (
                    f"Unable to find the List Name provided on "
                    f"{PLATFORM_NAME}. "
                    "Verify the selected IOC List Name."
                )
                self.logger.error(f"{self.log_prefix}: {error_msg}")
                return ValidationResult(success=False, message=f"{error_msg}")
        except HarfangLabPluginException as err:
            raise HarfangLabPluginException(err)
        except Exception as err:
            error_msg = "Error occurred while validating actions."
            self.logger.error(
                f"{self.log_prefix}: {error_msg}" f"Error: {err}",
                details=str(traceback.format_exc()),
            )
            raise HarfangLabPluginException(error_msg)

    def get_ioc_sources(self):
        """Fetch all available IOC lists from HarfangLab.

        Returns:
            dict: dictionary containing name and id of all IOC lists.
        """
        headers = {"Authorization": self.configuration.get("apikey")}
        params = {"limit": PAGE_LIMIT}
        url_endpoint = (
            f"{self.configuration.get('fqdn', '').strip().rstrip('/')}"
            "/api/data/threat_intelligence/IOCSource"
        )
        sources_list = {}
        while True:
            ioc_sources = self.harfanglab_helper.api_helper(
                url=url_endpoint,
                method="GET",
                headers=headers,
                params=params,
                payload={},
                verify=self.ssl_validation,
                proxies=self.proxy,
                logger_msg=("fetching existing IOC lists"),
                is_handle_error_required=True,
            )
            for source in ioc_sources.get("results", []):
                sources_list[source.get("name", "")] = source.get("id", "")
            if not ioc_sources.get("next"):
                break
            url_endpoint = (
                f"{self.configuration.get('fqdn', '').strip().rstrip('/')}"
                f"{ioc_sources.get('next', '')}"
            )
        return sources_list

    def get_action_fields(self, action: Action):
        """Get fields required for an action."""
        if action.value == "create_iocs":
            create_new_list_dict = {"create_new_list": "id"}
            ioc_source_list = self.get_ioc_sources()
            choice_list = [
                {
                    "key": source_name,
                    "value": json.dumps({source_name: source_id}),
                }
                for source_name, source_id in ioc_source_list.items()
            ] + [
                {
                    "key": "Create New IOC List",
                    "value": json.dumps(create_new_list_dict),
                }
            ]
            return [
                {
                    "label": "IOC List Name",
                    "key": "ioc_list_name",
                    "type": "choice",
                    "choices": choice_list,
                    "default": choice_list[0]["value"],
                    "mandatory": True,
                    "description": "Select IOC List Name available from "
                    "Threat Intelligence > IOC. Indicators will be shared "
                    "to the selected IOC List.",
                },
                {
                    "label": "New IOC List Name (only applicable when "
                    "Create New IOC List is selected)",
                    "key": "new_source",
                    "type": "text",
                    "mandatory": False,
                    "description": "New IOC List Name where the "
                    "indicators will be shared.",
                },
            ]
        else:
            return []
