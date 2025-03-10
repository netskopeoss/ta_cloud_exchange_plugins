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

CRE Bitsight Plugin.
"""

import json
import traceback
from typing import List, Union

from netskope.integrations.crev2.models import Action, ActionWithoutParams
from netskope.integrations.crev2.plugin_base import (
    Entity,
    EntityField,
    EntityFieldType,
    PluginBase,
    ValidationResult,
)

from .utils.constants import (
    API_ENDPOINTS,
    COMPANIES_LIMIT,
    COMPANY_FIELD_MAPPING,
    ENTITY_NAME,
    MAX_TIERS,
    MODULE_NAME,
    NETSKOPE_NORMALIZED_SCORE,
    PAGE_LIMIT,
    PLATFORM_NAME,
    PLUGIN_VERSION,
)
from .utils.helper import BitsightPluginException, BitsightPluginHelper


class BitsightPlugin(PluginBase):
    """Bitsight plugin implementation."""

    def __init__(
        self,
        name,
        *args,
        **kwargs,
    ):
        """Init method.

        Args:
            name (str): Configuration name.
        """
        super().__init__(
            name,
            *args,
            **kwargs,
        )
        self.plugin_name, self.plugin_version = self._get_plugin_info()
        self.log_prefix = f"{MODULE_NAME} {self.plugin_name}"
        if name:
            self.log_prefix = f"{self.log_prefix} [{name}]"
        self.bitsight_helper = BitsightPluginHelper(
            logger=self.logger,
            log_prefix=self.log_prefix,
            plugin_name=self.plugin_name,
            plugin_version=self.plugin_version,
        )

    def _get_plugin_info(self) -> tuple:
        """Get plugin name and version from metadata.

        Returns:
            tuple: Tuple of plugin's name and version fetched from metadata.
        """
        try:
            metadata_json = BitsightPlugin.metadata
            plugin_name = metadata_json.get("name", PLATFORM_NAME)
            plugin_version = metadata_json.get("version", PLUGIN_VERSION)
            return (plugin_name, plugin_version)
        except Exception as exp:
            self.logger.error(
                message=(
                    "{} {}: Error occurred while"
                    " getting plugin details. Error: {}".format(
                        MODULE_NAME, PLATFORM_NAME, exp
                    )
                ),
                details=traceback.format_exc(),
            )
        return (PLATFORM_NAME, PLUGIN_VERSION)

    def get_actions(self) -> List[ActionWithoutParams]:
        """Get available actions.

        Args:
            None

        Returns:
            list of ActionWithoutParams: List of ActionWithoutParams
                which has label and value defined

        """
        return [
            ActionWithoutParams(label="No action", value="generate"),
            ActionWithoutParams(label="Add company to tier", value="add"),
            ActionWithoutParams(
                label="Remove company from tier", value="remove"
            ),
        ]

    def get_action_params(self, action: Action) -> List:
        """Get fields required for an action.

        Args:
            action (Action): The type of action

        Returns:
            (list): Returns a list of details for UI to display Tiers.

        """
        if action.value == "generate":
            return []

        tiers = self._get_all_tiers()
        tiers = sorted(tiers, key=lambda tier: tier.get("name", "").lower())

        new_tier_dict = json.dumps({"name": "create"})
        if action.value == "add":
            return [
                {
                    "label": "Company GUID",
                    "key": "company_guid",
                    "type": "text",
                    "default": "",
                    "mandatory": True,
                    "description": (
                        "GUID of the company you want to add to a tier."
                        " Multiple comma separated values are accepted."
                    ),
                },
                {
                    "label": "Tiers",
                    "key": "tier",
                    "type": "choice",
                    "choices": [
                        {"key": tier.get("name"), "value": json.dumps(tier)}
                        for tier in tiers
                    ]
                    + [
                        {
                            "key": "Create new tier",
                            "value": new_tier_dict,
                        }
                    ],
                    "default": (
                        json.dumps(tiers[0]) if tiers else new_tier_dict
                    ),
                    "mandatory": True,
                    "description": (
                        "Select tier to which you want to add the company."
                    ),
                },
                {
                    "label": "New Tier Name",
                    "key": "new_tier_name",
                    "type": "text",
                    "default": "",
                    "mandatory": False,
                    "description": (
                        f"Create new teir on {PLATFORM_NAME}. This will be "
                        "only applied when Create new tier is selected in"
                        " Tiers parameter."
                    ),
                },
            ]

        elif action.value == "remove":
            return [
                {
                    "label": "Company GUID",
                    "key": "company_guid",
                    "type": "text",
                    "default": "",
                    "mandatory": True,
                    "description": (
                        "GUID of the company you want to remove from "
                        "the tier. Multiple comma separated values "
                        "are accepted."
                    ),
                },
                {
                    "label": "Tiers",
                    "key": "tier",
                    "type": "choice",
                    "choices": [
                        {"key": tier.get("name"), "value": json.dumps(tier)}
                        for tier in tiers
                    ],
                    "default": (
                        json.dumps(tiers[0])
                        if tiers
                        else f"No tiers found on {PLATFORM_NAME} server"
                    ),
                    "mandatory": True,
                    "description": (
                        "Select tier from which the company should"
                        " be removed."
                    ),
                },
            ]

    def _get_all_tiers(self):
        """Get all tiers.

        Returns:
            dict: Dictionary containing tiers GUID and name.
        """
        config_params = self.bitsight_helper.get_credentials(
            configuration=self.configuration
        )
        endpoint = API_ENDPOINTS["get_teirs"]
        user_api_token = config_params.get("user_api_token")
        teirs = []
        try:
            resp_json = self.bitsight_helper.api_helper(
                url=endpoint,
                method="GET",
                auth=(user_api_token, ""),
                logger_msg=f"pulling tiers from {PLATFORM_NAME}",
                proxies=self.proxy,
                verify=self.ssl_validation,
            )
            for tier in resp_json:
                if tier.get("guid") and tier.get("name"):
                    teirs.append(
                        {
                            "guid": tier.get("guid"),
                            "name": tier.get("name"),
                        }
                    )

            self.logger.info(
                f"{self.log_prefix}: Successfully fetched "
                f"{len(teirs)} teir(s) from {PLATFORM_NAME}."
            )
            return teirs
        except BitsightPluginException:
            raise
        except Exception as exp:
            err_msg = (
                "Unexpected error occurred while pulling"
                f" tiers from {PLATFORM_NAME}."
            )
            self.logger.error(
                message=(f"{self.log_prefix}: {err_msg} Error: {exp}"),
                details=traceback.format_exc(),
            )
            raise BitsightPluginException(err_msg)

    def _get_company_guids(
        self, company_guid: Union[str, list[str]]
    ) -> list[str]:
        """Convert to List.

        Args:
            value (Union[str, list[str]]): Value for the company

        Returns:
            list[str]: List of Company GUIDs.
        """
        if isinstance(company_guid, list):
            return company_guid
        elif isinstance(company_guid, str):
            return list(
                filter(
                    lambda x: len(x) != 0,
                    map(lambda x: x.strip(), company_guid.split(",")),
                )
            )
        return []

    def _create_tier(self, user_api_token: str, tier_name: str) -> dict:
        """Create tier.

        Args:
            tier_name (str): Tier Name.

        Returns:
            dict: Created Tier Details.
        """
        self.logger.info(
            f"{self.log_prefix}: Creating {tier_name} tier on {PLATFORM_NAME}."
        )
        payload = {
            "name": tier_name,
            "description": "This tier is created by Netskope.",
            "companies": [],
        }
        try:
            logger_msg = f"creating tier {tier_name} on {PLATFORM_NAME}"
            response = self.bitsight_helper.api_helper(
                url=API_ENDPOINTS["create_tier"],
                method="POST",
                auth=(user_api_token, ""),
                verify=self.ssl_validation,
                proxies=self.proxy,
                json=payload,
                logger_msg=logger_msg,
                is_handle_error_required=False,
            )
            if response.status_code == 201:
                resp_json = self.bitsight_helper.parse_response(
                    response=response, logger_msg=logger_msg
                )
                self.logger.info(
                    f"{self.log_prefix}: Successfully created {tier_name} tier"
                    f" on {PLATFORM_NAME}."
                )
                return {
                    "guid": resp_json.get("guid"),
                    "name": resp_json.get("name"),
                }
            elif response.status_code == 400:
                resp_json = self.bitsight_helper.parse_response(
                    response=response, logger_msg=logger_msg
                )
                if (
                    resp_json.get("error_code")
                    == "TIERS-MAXIMUM_TIER_SET_SIZE"
                ):
                    err_msg = (
                        "Maximum limit for tier is "
                        "reached, hence can't create more tier on "
                        f"{PLATFORM_NAME}. Choose available tier "
                        "from the Tiers field to perform the action."
                    )
                    self.logger.error(
                        message=(f"{self.log_prefix}: {err_msg}"),
                        details=str(resp_json),
                    )
                    raise BitsightPluginException(err_msg)
                else:
                    err_msg = (
                        f"Unable to create tier {tier_name} on"
                        f" {PLATFORM_NAME}"
                    )
                    self.logger.error(
                        message=(f"{self.log_prefix}: {err_msg}"),
                        details=str(resp_json),
                    )
                    raise BitsightPluginException(err_msg)
            self.bitsight_helper.handle_error(
                response=response, logger_msg=logger_msg
            )
        except BitsightPluginException:
            raise
        except Exception as exp:
            err_msg = (
                "Unexpected error occurred while creating tier on"
                f" {PLATFORM_NAME}."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {exp}",
                details=traceback.format_exc(),
            )
            raise BitsightPluginException(err_msg)

    def _execute_action(
        self,
        action_label: str,
        action,
        user_api_token: str,
        tier_info: dict,
        is_add_action=False,
        is_bulk_action=False,
    ):
        """Execute action on the users.

        Args:
            action_label (str): Action label.
            action_params (dict): Action parameters.
            user_api_token (str): User API token.
            tier_info (dict): Tier details.

        Returns:
            None
        """
        company_guids = set()
        if is_bulk_action:
            for a in action:
                company_guids.update(
                    set(
                        self._get_company_guids(
                            a.parameters.get("company_guid")
                        )
                    )
                )
        else:
            company_guids = self._get_company_guids(
                action.get("company_guid")
            )
        company_guids = list(company_guids)
        self.logger.info(
            "{}: {} action will be executed "
            "for {} {}.".format(
                self.log_prefix,
                action_label,
                len(company_guids),
                "company" if len(company_guids) <= 1 else "companies",
            )
        )
        for i in range(0, len(company_guids), COMPANIES_LIMIT):
            self._perform_action_on_companies(
                user_api_token=user_api_token,
                data=company_guids[i : i + COMPANIES_LIMIT],  # noqa
                tier_details=tier_info,
                is_add_action=is_add_action,
            )

    def execute_action(self, action: Action):
        """Execute action on the users.

        Args:
            action (Action): Action that needs to be perform on users.

        Returns:
            None
        """
        action_label = action.label
        action_params = action.parameters

        if action.value == "generate":
            self.logger.info(
                f"{self.log_prefix}: Successfully executed '{action_label}' "
                "action. Note: No processing will be done from plugin for "
                f"the '{action_label}' action."
            )
            return
        self.logger.info(
            f"{self.log_prefix}: Executing action {action_label} on"
            f" {ENTITY_NAME}."
        )
        user_api_token = self.configuration.get("user_api_token")
        tier_info = json.loads(action_params.get("tier"))
        if action.value == "add":
            if tier_info.get("name", "") == "create":
                try:
                    new_tier_name = action_params.get(
                        "new_tier_name", ""
                    ).strip()

                    tiers = self._get_all_tiers()

                    match_tier = None
                    for tier in tiers:
                        if tier.get("name") == new_tier_name:
                            match_tier = {
                                "name": new_tier_name,
                                "guid": tier.get("guid"),
                            }
                            break

                    if match_tier is None:
                        match_tier = self._create_tier(
                            user_api_token, new_tier_name
                        )
                    tier_info = match_tier
                except Exception as exp:
                    err_msg = (
                        "Error occurred while creating "
                        f"new tier named {new_tier_name}. Error: {exp}"
                    )
                    self.logger.error(
                        message=f"{self.log_prefix}: {err_msg}",
                        details=traceback.format_exc(),
                    )
                    raise BitsightPluginException(err_msg)

            self._execute_action(
                action_label=action_label,
                action=action_params,
                user_api_token=user_api_token,
                tier_info=tier_info,
                is_add_action=True,
                is_bulk_action=False,
            )
        elif action.value == "remove":
            self._execute_action(
                action_label=action_label,
                action=action_params,
                user_api_token=user_api_token,
                tier_info=tier_info,
                is_add_action=False,
                is_bulk_action=False,
            )

    def execute_actions(self, action: Action):
        """Execute action on the users.

        Args:
            action (Action): Action that needs to be perform on users.

        Returns:
            None
        """
        first_action = action[0]
        action_label = first_action.label
        action_value = first_action.value

        if first_action.value == "generate":
            self.logger.info(
                f"{self.log_prefix}: Successfully executed '{action_label}' "
                "action. Note: No processing will be done from plugin for "
                f"the '{action_label}' action."
            )
            return
        self.logger.info(
            f"{self.log_prefix}: Executing action {action_label} on"
            f" {ENTITY_NAME}."
        )

        user_api_token = self.configuration.get("user_api_token")
        first_action_params = first_action.parameters
        tier_info = json.loads(first_action_params.get("tier"))
        if action_value == "add":

            if tier_info.get("name", "") == "create":
                try:
                    new_tier_name = first_action_params.get(
                        "new_tier_name", ""
                    ).strip()

                    tiers = self._get_all_tiers()

                    match_tier = None
                    for tier in tiers:
                        if tier.get("name") == new_tier_name:
                            match_tier = {
                                "name": new_tier_name,
                                "guid": tier.get("guid"),
                            }
                            break
                    # If no match found create a new tier.
                    if match_tier is None:
                        match_tier = self._create_tier(
                            user_api_token,
                            new_tier_name,
                        )
                    tier_info = match_tier
                except Exception as exp:
                    err_msg = (
                        "Error occurred while creating "
                        f"new tier named {new_tier_name}. Error: {exp}"
                    )
                    self.logger.error(
                        message=f"{self.log_prefix}: {err_msg}",
                        details=traceback.format_exc(),
                    )
                    raise BitsightPluginException(err_msg)

            self._execute_action(
                action_label=action_label,
                action=action,
                user_api_token=user_api_token,
                tier_info=tier_info,
                is_add_action=True,
                is_bulk_action=True,
            )
        elif action_value == "remove":
            self._execute_action(
                action_label=action_label,
                action=action,
                user_api_token=user_api_token,
                tier_info=tier_info,
                is_add_action=False,
                is_bulk_action=True,
            )

    def _perform_action_on_companies(
        self,
        user_api_token: str,
        tier_details: str,
        data: List,
        is_add_action: bool = True,
    ):
        """Perform action on companies.

        Args:
            user_api_token (str): User API token.
            tier_details (str): Tier details.
            data (List): List of companies.
            is_add_action (bool, optional): Whether
              to add or remove companies. Defaults to True.
        """
        try:
            if is_add_action:
                payload = {"add_companies": data}
            else:
                payload = {"remove_companies": data}

            if is_add_action:
                add_companies_size = len(data)
                logger_msg = (
                    "adding {companies} {suffix} to tier {tier_name}".format(
                        companies=add_companies_size,
                        suffix=(
                            "companies"
                            if add_companies_size > 1
                            else "company"
                        ),
                        tier_name=tier_details["name"],
                    )
                )
            else:
                remove_companies_size = len(payload["remove_companies"])
                logger_msg = (
                    "removing {companies} {suffix} from tier {tier_name}"
                ).format(
                    companies=remove_companies_size,
                    suffix=(
                        "companies"
                        if remove_companies_size > 1
                        else "company"
                    ),
                    tier_name=tier_details["name"],
                )

            resp_json = self.bitsight_helper.api_helper(
                url=API_ENDPOINTS["companies"].format(
                    tier_guid=tier_details["guid"]
                ),
                method="PATCH",
                auth=(user_api_token, ""),
                verify=self.ssl_validation,
                proxies=self.proxy,
                json=payload,
                logger_msg=logger_msg,
            )
            log_msg = ""
            if is_add_action:
                is_success = len(resp_json.get("added", []))
                is_fail = len(resp_json.get("not_added", []))
                log_msg = ""
                if is_success:
                    log_msg += "Successfully added {} {} to tier {}".format(
                        is_success,
                        "companies" if is_success > 1 else "company",
                        tier_details["name"],
                    )
                if is_fail:
                    log_msg += (
                        " {} to add {} {} as"
                        " they might already exist in the tier or are"
                        " invalid company guid(s)".format(
                            "and unable" if is_success else "Unable",
                            is_fail,
                            "companies" if is_fail > 1 else "company",
                        )
                    )
                self.logger.info(
                    message=f"{self.log_prefix}: {log_msg}.",
                    details="{}".format(
                        f"Failed to add companies: {resp_json.get('not_added', [])}"  # noqa
                        if is_fail
                        else ""
                    ),
                )
            else:
                is_success = len(resp_json.get("removed", []))
                is_fail = len(resp_json.get("not_removed", []))
                log_msg = ""
                if is_success:
                    log_msg += (
                        "Successfully removed {} {} from tier {}".format(
                            is_success,
                            "companies" if is_success else "company",
                            tier_details["name"],
                        )
                    )
                if is_fail:
                    log_msg += (
                        " {} to remove {} {} as"
                        " they might not exist in the tier or are invalid"
                        " Company GUID(s)".format(
                            "and unable" if is_success else "Unable",
                            is_fail,
                            "companies" if is_fail > 1 else "company",
                        )
                    )
                self.logger.info(
                    message=f"{self.log_prefix}: {log_msg}.",
                    details="{}".format(
                        f"Failed to remove companies: {is_fail}"
                        if resp_json.get("not_removed", [])
                        else ""
                    ),
                )

        except BitsightPluginException:
            raise
        except Exception as exp:
            err_msg = (
                "Unexpected error occurred while performing action"
                " on companies."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {exp}",
                details=traceback.format_exc(),
            )
            raise BitsightPluginException(err_msg)

    def validate_action(self, action: Action) -> ValidationResult:
        """Validate Bitsight action configuration.

        Args:
            action (Action): The type of action

        Returns:
            ValidationResult: validation result true or false with message
        """
        action_value = action.value
        action_params = action.parameters
        if action_value not in ["add", "remove", "generate"]:
            self.logger.error(
                f'{self.log_prefix}: Unsupported action "{action_value}" '
                "provided in the action configuration."
            )
            return ValidationResult(
                success=False, message="Unsupported action provided."
            )

        if action_value == "generate":
            log_msg = (
                "Successfully validated "
                f"action configuration for '{action.label}'."
            )
            self.logger.debug(f"{self.log_prefix}: {log_msg}")
            return ValidationResult(success=True, message=log_msg)
        create_dict = json.dumps({"name": "create"})
        tiers = self._get_all_tiers()
        tiers = [tier.get("guid", "") for tier in tiers]
        company_guid = action_params.get("company_guid")

        if not company_guid:
            err_msg = "Company GUID is a required action parameter."
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            return ValidationResult(success=False, message=err_msg)
        elif not isinstance(company_guid, str):
            err_msg = (
                "Invalid Company GUID provided in action "
                "parameters. Company GUID should be valid comma"
                " separated string."
            )
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            return ValidationResult(success=False, message=err_msg)

        tier = action_params.get("tier")
        if action_value == "add":
            if not tier:
                err_msg = "Select a Tier to perform action on."
                self.logger.error(f"{self.log_prefix}: {err_msg}")
                return ValidationResult(success=False, message=err_msg)
            elif create_dict not in tier and ("$" in tier):
                err_msg = (
                    "Tier contains the Business Rule Record Field."
                    " Please select tier from Static Field dropdown only."
                )
                self.logger.error(f"{self.log_prefix}: {err_msg}")
                return ValidationResult(success=False, message=err_msg)
            elif (
                create_dict in tier
                and len(action_params.get("new_tier_name", "").strip()) == 0
            ):
                err_msg = (
                    "New Tier Name is a required action parameter to "
                    f"Create New Tier on {PLATFORM_NAME}."
                )
                self.logger.error(f"{self.log_prefix}: {err_msg}")
                return ValidationResult(success=False, message=err_msg)
            elif create_dict in tier and len(tiers) >= MAX_TIERS:
                err_msg = (
                    f"Maximum {MAX_TIERS} Tiers can be created on "
                    f"{PLATFORM_NAME}. Please delete Tier to add new Tier"
                    " or select existing Tier."
                )
                self.logger.error(f"{self.log_prefix}: {err_msg}")
                return ValidationResult(success=False, message=err_msg)

            elif create_dict not in tier and (
                not any(
                    map(
                        lambda guid: guid == json.loads(tier).get("guid"),
                        tiers,
                    )
                )
            ):
                err_msg = (
                    "Invalid Tier Name Provided. "
                    "Select tier names from drop down list."
                )
                self.logger.error(f"{self.log_prefix}: {err_msg}")
                return ValidationResult(success=False, message=err_msg)
        else:
            if (
                f"No groups found on {PLATFORM_NAME} platform."
                in action_params.get("tier", "")
            ):
                err_msg = (
                    "Action will not be saved as no Tier"
                    f" found on {PLATFORM_NAME} server."
                )
                self.logger.error(f"{self.log_prefix}: {err_msg}")
                return ValidationResult(success=False, message=err_msg)
            elif not any(
                map(
                    lambda id: id == json.loads(tier).get("guid", ""),
                    tiers,
                )
            ):
                err_msg = "Invalid Tier Name provided in action parameters."
                self.logger.error(f"{self.log_prefix}: {err_msg}")
                return ValidationResult(success=False, message=err_msg)

        log_msg = (
            "Successfully validated "
            f"action configuration for '{action.label}'."
        )
        self.logger.debug(f"{self.log_prefix}: {log_msg}")
        return ValidationResult(success=True, message=log_msg)

    def validate(self, configuration):
        """Validate the Plugin configuration parameters.

        Args:
            configuration (dict): Contains the below keys:

        Returns:
            ValidateResult: ValidateResult object with success flag and
                            message.
        """
        validation_err_msg = "Validation error occurred."
        # Validate User API Token
        user_api_token = configuration.get("user_api_token", "")
        if not user_api_token:
            err_msg = "User API Token is a required configuration parameter."
            self.logger.error(
                f"{self.log_prefix}: {validation_err_msg} {err_msg}"
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        elif not isinstance(user_api_token, str):
            err_msg = (
                "Invalid User API Token provided in configuration parameters."
            )
            self.logger.error(
                f"{self.log_prefix}: {validation_err_msg} {err_msg}"
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )

        # Validate Security Rating
        rating = configuration.get("rating", 900)
        if rating is None:
            err_msg = (
                "Security Rating is a required configuration" " parameter."
            )
            self.logger.error(f"{validation_err_msg} {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        elif not isinstance(rating, int) or rating < 250 or rating > 900:
            err_msg = (
                "Invalid value provided in Security Rating. "
                "Valid value should be an integer in range 250 to 900."
            )
            self.logger.error(f"{validation_err_msg} {err_msg}")
            return ValidationResult(success=False, message=err_msg)

        # Validate Rating Type
        rating_type = configuration.get("rating_type", "").strip()
        if not rating_type:
            err_msg = "Rating Type is a required configuration parameter."
            self.logger.error(f"{validation_err_msg} {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        elif not isinstance(rating_type, str) or rating_type not in [
            "CURATED",
            "PRIVATE",
            "SELF-PUBLISHED",
            "All",
        ]:
            err_msg = (
                "Invalid value provided in Rating Type. Valid values are"
                " Bitsight Curated, Self-Published, Privately Published, "
                "and All Rating Types."
            )
            self.logger.error(f"{validation_err_msg} {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )

        # Validate auth credentials.
        return self.validate_auth_params(user_api_token, rating, rating_type)

    def validate_auth_params(self, user_api_token, rating, rating_type):
        """Validate the authentication params with Bitsight platform.

        Args: configuration (dict).

        Returns:
            ValidationResult: ValidationResult object having validation
            results after making an API call.
        """
        try:
            params = {
                "limit": 1,
                "rating_lte": int(rating),
                "type": rating_type,
            }
            if rating_type != "All":
                params["type"] = rating_type
            self.bitsight_helper.api_helper(
                url=API_ENDPOINTS["portfolio"],
                method="GET",
                auth=(user_api_token, ""),
                params=params,
                logger_msg="pulling companies for authenticating credentials",
                is_validation=True,
            )
            log_msg = (
                f"Validation successful for {MODULE_NAME} "
                f"{PLATFORM_NAME} plugin."
            )
            self.logger.debug(f"{self.log_prefix}: {log_msg}")
            return ValidationResult(
                success=True,
                message=log_msg,
            )
        except BitsightPluginException as exp:
            return ValidationResult(success=False, message=str(exp))
        except Exception as exp:
            err_msg = "Unexpected validation error occurred."
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {exp}",
                details=traceback.format_exc(),
            )
            return ValidationResult(
                success=False,
                message=f"{err_msg} Check logs for more details.",
            )

    def add_field(
        self,
        fields_dict: dict,
        field_name: str,
        value,
        transformation: str = None,
    ):
        """Function to add field to the extracted_fields dictionary.

        Args:
            fields_dict (dict): Field dictionary to update.
            field_name (str): Field name to add.
            value: Field to add.
        """
        if transformation and transformation == "string":
            value = str(value)
        elif isinstance(value, int):
            value = value
        elif isinstance(value, str) and value:
            value = value
        fields_dict[field_name] = value

    def _extract_field_from_event(
        self, key: str, event: dict, default, transformation=None
    ):
        """Extract field from event.

        Args:
            key (str): Key to fetch.
            event (dict): Event dictionary.
            default (str,None): Default value to set.
            transformation (str, None, optional): Transformation
                to perform on key. Defaults to None.

        Returns:
            Any: Value of the key from event.
        """
        keys = key.split(".")
        while keys:
            k = keys.pop(0)
            if k not in event and default is not None:
                return default
            event = event.get(k, {})
        if transformation and transformation == "string":
            return str(event)
        elif transformation and transformation == "integer":
            return int(event)
        elif transformation and transformation == "float":
            return float(event)
        return event

    def _extract_company_fields(
        self,
        company: dict,
        is_normalized: bool = False,
    ) -> dict:
        """Extract user fields.

        Args:
            event (dict): Event payload.
            participant (dict): Participant dictionary.

        Returns:
            dict: Extracted fields dictionary.
        """
        extracted_fields = {}
        for field_name, field_value in COMPANY_FIELD_MAPPING.items():
            key, default, transformation = (
                field_value.get("key"),
                field_value.get("default"),
                field_value.get("transformation"),
            )
            self.add_field(
                extracted_fields,
                field_name,
                self._extract_field_from_event(
                    key, company, default, transformation
                ),
            )
        if is_normalized and company.get("rating"):
            extracted_fields[NETSKOPE_NORMALIZED_SCORE] = (
                self._normalize_risk_score(company.get("rating"))
            )

        return extracted_fields

    def _normalize_risk_score(self, bitsight_rating):
        return int((((bitsight_rating) - 250) / (650)) * 1000)

    def fetch_records(self, entity: str) -> List:
        """Pull Records from Bitsight.

        Returns:
            List: List of records to be stored on the platform.
        """
        entity_name = entity.lower()
        if entity != ENTITY_NAME:
            err_msg = (
                f"Invalid entity found. {PLATFORM_NAME} only supports "
                f"{ENTITY_NAME} entity."
            )
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            raise BitsightPluginException(err_msg)

        self.logger.info(
            f"{self.log_prefix}: Fetching {entity_name} from "
            f"{PLATFORM_NAME} platform."
        )

        config_params = self.bitsight_helper.get_credentials(
            configuration=self.configuration
        )
        params = {
            "limit": PAGE_LIMIT,
            "rating_lte": int(config_params.get("rating")),
            "offset": 0,
        }
        if config_params.get("rating_type") != "All":
            params["type"] = config_params.get("rating_type")
        user_api_token = config_params.get("user_api_token")
        page_count = 1
        skip_count = 0
        total_companies = []
        while True:
            try:
                page_companies = 0
                resp_json = self.bitsight_helper.api_helper(
                    url=API_ENDPOINTS["portfolio"],
                    method="GET",
                    auth=(user_api_token, ""),
                    params=params,
                    logger_msg=f"pulling companies for page {page_count}",
                )
                if not resp_json.get("results"):
                    break
                for company in resp_json.get("results"):
                    try:
                        if company.get("guid"):
                            company_fields = self._extract_company_fields(
                                company
                            )
                            if company_fields:
                                total_companies.append(company_fields)
                                page_companies += 1
                            else:
                                skip_count += 1
                        else:
                            skip_count += 1
                            continue
                    except BitsightPluginException:
                        skip_count += 1
                    except Exception as err:
                        id = company.get("guid")
                        err_msg = (
                            "Unable to extract fields from company"
                            f' having id "{id}".'
                        )
                        self.logger.error(
                            message=(
                                f"{self.log_prefix}: {err_msg}"
                                f" Error: {err}"
                            ),
                            details=f"Company Record: {company}",
                        )
                        skip_count += 1
                self.logger.info(
                    f"{self.log_prefix}: Successfully fetched "
                    f"{page_companies} companies for page {page_count}."
                    f" Total companies fetched: {len(total_companies)}"
                )
                if len(resp_json.get("results", [])) < PAGE_LIMIT:
                    break

                params["offset"] += PAGE_LIMIT
                page_count += 1

            except BitsightPluginException:
                raise
            except Exception as exp:
                err_msg = (
                    f"Unexpected error occurred while fetching "
                    f"{entity_name} from {PLATFORM_NAME} platform."
                    f" Error: {exp}"
                )
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg}",
                    details=str(traceback.format_exc()),
                )
                raise BitsightPluginException(err_msg)
        if skip_count > 0:
            self.logger.info(
                f"{self.log_prefix}: Skipped {skip_count}"
                f" {entity_name} because they might not contain Company GUID"
                " (guid) in their API response or fields could not be"
                " extracted from them."
            )

        self.logger.info(
            f"{self.log_prefix}: Successfully fetched "
            f"{len(total_companies)} companies for {entity_name} "
            f"from {PLATFORM_NAME} platform."
        )

        return total_companies

    def update_records(self, entity: str, records: list[dict]) -> list[dict]:
        """Update user scores.

        Args:
            users (List): List of users.

        Returns:
            List: List of users with scores assigned.
        """
        entity_name = entity.lower()

        if entity != ENTITY_NAME:
            err_msg = (
                f"Invalid entity found. {PLATFORM_NAME} only supports "
                f"{entity_name} entity."
            )
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            raise BitsightPluginException(err_msg)

        self.logger.info(
            f"{self.log_prefix}: Updating {len(records)} {entity_name}"
            f" record(s) from {PLATFORM_NAME}."
        )
        company_guid = {}
        counter = 0
        for record in records:
            if record.get("Company GUID"):
                company_guid[record.get("Company GUID")] = {
                    "Company GUID": record.get("Company GUID"),
                    "Security Rating": record.get("Security Rating"),
                }
                counter += 1

        log_msg = (
            f"{counter} {entity_name} record(s) will be updated out"
            f" of {len(records)} record(s) from {PLATFORM_NAME}."
        )

        if counter > 0:
            log_msg += (
                f" Skipped {len(records) - counter} companies as they"
                " do not have Company GUID field in them."
            )

        self.logger.info(f"{self.log_prefix}: {log_msg}")

        skip_count = 0
        for guid, record in company_guid.items():
            risk_score = record.get("Security Rating")
            if isinstance(risk_score, int) and 250 <= risk_score <= 900:
                normalized_score = self._normalize_risk_score(risk_score)
                self.add_field(
                    record,
                    "Netskope Normalized Score",
                    normalized_score,
                )
            else:
                err_msg = (
                    f"{self.log_prefix}: Invalid "
                    f"{PLATFORM_NAME} Security Rating received "
                    f"for Company GUID: {record.get('Company GUID')}."
                    "Netskope Normalized Score will not be "
                    "calculated for this Detection. "
                    "Valid Risk Score range is 250 to 900."
                )
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg}",
                    details=f"Security Rating: '{risk_score}'",
                )
                skip_count += 1
        if skip_count > 0:
            self.logger.info(
                f"{self.log_prefix}: Skipped {skip_count}"
                f" {entity_name} record(s) for Normalization as they might"
                " have invalid Security Rating or there might be some"
                " issue calculating the Netskope Normalized Score."
            )
        records = list(company_guid.values())
        self.logger.info(
            f"{self.log_prefix}: Successfully Normalized Risk Score for "
            f"{len(records)} detection(s) for {entity_name}."
        )
        return records

    def get_entities(self) -> list[Entity]:
        """Get available entities."""
        return [
            Entity(
                name=ENTITY_NAME,
                fields=[
                    EntityField(
                        name="Company GUID",
                        type=EntityFieldType.STRING,
                        required=True,
                    ),
                    EntityField(
                        name="Security Rating",
                        type=EntityFieldType.NUMBER,
                        required=True,
                    ),
                    EntityField(
                        name="Company Name", type=EntityFieldType.STRING
                    ),
                    EntityField(
                        name="Rating Type",
                        type=EntityFieldType.LIST,
                    ),
                    EntityField(
                        name="Primary Domain",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="Tier GUID",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="Tier Name",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="Confidence",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="Netskope Normalized Score",
                        type=EntityFieldType.NUMBER,
                    ),
                ],
            )
        ]
