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

CRE Tenable Plugin.
"""

import traceback
from typing import Dict, List, Union
from datetime import datetime, timedelta, timezone

from netskope.common.api import __version__ as CE_VERSION
from netskope.integrations.crev2.models import Action, ActionWithoutParams
from netskope.integrations.crev2.plugin_base import (
    Entity,
    EntityField,
    EntityFieldType,
    PluginBase,
    ValidationResult,
)
from packaging import version

from .utils.constants import (
    ASSETS_CHUNK_DOWNLOAD_ENDPOINT,
    ASSETS_EXPORT_ENDPOINT,
    ASSETS_STATUS_ENDPOINT,
    BASE_URL,
    INTEGER_THRESHOLD,
    MAXIMUM_CE_VERSION,
    MODULE_NAME,
    PLATFORM_NAME,
    PLUGIN_VERSION,
    VALIDATION_ERROR_MSG,
    FINDINGS_CHUNK_DOWNLOAD_ENDPOINT,
    FINDINGS_EXPORT_ENDPOINT,
    FINDINGS_STATUS_ENDPOINT,
    ASSET_PAGE_SIZE,
    VULN_PAGE_SIZE,
    TAG_VALUE_MAX_LENGTH,
    CONFIGURATION,
    ACTION,
    TAG_ASSIGNMENT_BATCH_SIZE,
)
from .utils.exceptions import (
    TenablePluginException,
    exception_handler,
)
from .utils.helper import TenableHelper
from .utils.parser import TenableParser


class TenablePlugin(PluginBase):
    """Tenable plugin Class."""

    def __init__(
        self,
        name,
        *args,
        **kwargs,
    ):
        """Tenable plugin initializer.

        Args:
            name (str): Plugin configuration name.
        """
        super().__init__(
            name,
            *args,
            **kwargs,
        )
        # Flag to check if CE version is more than v5.1.2
        self._is_ce_post_v512 = self._check_ce_version()
        # Method to decide which logger to use with or without
        # resolutions based on the CE version
        self._patch_error_logger()
        self.plugin_name, self.plugin_version = self._get_plugin_info()
        self.log_prefix = f"{MODULE_NAME} {self.plugin_name}"
        if name:
            self.log_prefix = f"{self.log_prefix} [{name}]"
        self.parser = TenableParser(
            logger=self.logger,
            log_prefix=self.log_prefix,
        )
        self.tenable_helper = TenableHelper(
            logger=self.logger,
            plugin_name=self.plugin_name,
            plugin_version=self.plugin_version,
            log_prefix=self.log_prefix,
            parser=self.parser,
        )
        if self._is_ce_post_v512:
            self.provide_action_id = True

    def _get_plugin_info(self) -> tuple:
        """Get plugin name and version from manifest.

        Returns:
            tuple: tuple of plugin's name and version fetched from manifest.
        """
        try:
            manifest_json = TenablePlugin.metadata
            plugin_name = manifest_json.get("name", PLATFORM_NAME)
            plugin_version = manifest_json.get("version", PLUGIN_VERSION)
            return plugin_name, plugin_version
        except Exception as exp:
            self.logger.error(
                message=(
                    f"{MODULE_NAME} {PLATFORM_NAME}: Error occurred while "
                    f"getting plugin details. Error: {exp}"
                ),
                details=traceback.format_exc(),
            )
        return (PLATFORM_NAME, PLUGIN_VERSION)

    def _check_ce_version(self) -> bool:
        """Check if CE version is greater than v5.1.2.

        Returns:
            bool: True if CE version is greater than v5.1.2, False otherwise.
        """
        return version.parse(CE_VERSION) > version.parse(MAXIMUM_CE_VERSION)

    def _patch_error_logger(self):
        """Monkey patch logger methods to handle resolution parameter
        compatibility.
        """
        # Store original methods
        original_error = self.logger.error

        def patched_error(
            message=None,
            details=None,
            resolution=None,
            **kwargs,
        ):
            """Patched error method that handles resolution compatibility."""
            log_kwargs = {"message": message}
            if details:
                log_kwargs["details"] = details
            if resolution and self._is_ce_post_v512:
                log_kwargs["resolution"] = resolution
            log_kwargs.update(kwargs)
            return original_error(**log_kwargs)

        # Replace logger methods with patched versions
        self.logger.error = patched_error

    def _get_storage(self) -> Dict:
        """Get storage object.

        Returns:
            Dict: Storage object.
        """
        storage = self.storage if self.storage is not None else {}
        return storage

    def _get_since_time(
        self,
        initial_range: int,
        storage: dict,
    ) -> int:
        """Calculate since time for filtering records.

        Args:
            initial_range (int): Initial range in days.
            storage (dict): Storage dictionary containing checkpoint.

        Returns:
            int: Unix timestamp for since filter.
        """
        last_run_at = self.last_run_at
        if storage and storage.get("vulnerability_checkpoint"):
            since_time = int(
                storage.get("vulnerability_checkpoint").timestamp()
            )
        elif storage and storage.get("last_run_at"):
            since_time = int(storage.get("last_run_at").timestamp())
        elif last_run_at:
            since_time = int(last_run_at.timestamp())
        else:
            since_datetime = (
                datetime.now(timezone.utc) - timedelta(days=initial_range)
            )
            since_time = int(since_datetime.timestamp())
            self.logger.info(
                f"{self.log_prefix}: This is initial data fetch since "
                "checkpoint is empty. Querying vulnerability finding(s) for "
                f"last {initial_range} days."
            )
        return since_time

    @exception_handler
    def _fetch_vulnerability_findings(
        self,
        headers: dict,
        initial_range: int,
        no_of_retries: int = 3,
        context: dict = {},
        is_validation: bool = False,
    ):
        """Fetch vulnerability findings from Tenable using export API.

        Args:
            headers (dict): Headers dictionary.
            initial_range (int): Initial range in days.
            no_of_retries (int): Number of retries.
            context (dict): Context dictionary.
            is_validation (bool): Whether this is for validation.

        Returns:
            list: List of vulnerability findings records.
        """
        self.logger.info(
            f"{self.log_prefix}: Fetching vulnerability findings "
            f"for assets from {PLATFORM_NAME} platform."
        )
        context["logger_msg"] = "fetching vulnerability findings"

        if is_validation:
            body = {"num_assets": 1}
        else:
            storage = self._get_storage()
            since_time = self._get_since_time(
                initial_range=initial_range,
                storage=storage,
            )
            body = {
                "num_assets": VULN_PAGE_SIZE,
                "filters": {
                    "since": since_time
                }
            }
            self.logger.info(
                f"{self.log_prefix}: Querying vulnerability finding(s) "
                f"since {datetime.fromtimestamp(since_time)}."
            )

        export_endpoint = FINDINGS_EXPORT_ENDPOINT.format(base_url=BASE_URL)
        export_uuid = self.tenable_helper.initiate_export(
            endpoint=export_endpoint,
            headers=headers,
            body=body,
            entity_type="vulnerability findings",
            verify=self.ssl_validation,
            proxies=self.proxy,
            is_validation=is_validation,
        )
        vulnerability_checkpoint = datetime.now(timezone.utc)

        status_endpoint = FINDINGS_STATUS_ENDPOINT.format(
            base_url=BASE_URL,
            export_uuid=export_uuid
        )

        status_response = self.tenable_helper.check_export_status(
            status_endpoint=status_endpoint,
            headers=headers,
            export_uuid=export_uuid,
            entity_type="vulnerability findings",
            no_of_retries=no_of_retries,
            verify=self.ssl_validation,
            proxies=self.proxy,
            is_validation=is_validation,
        )

        chunk_ids = status_response.get("chunks_available", [])
        if not chunk_ids:
            self.logger.info(
                f"{self.log_prefix}: No vulnerability findings "
                "available to fetch."
            )
            if not is_validation:
                storage.update(
                    {
                        "vulnerability_checkpoint": vulnerability_checkpoint
                    }
                )
            return []

        if is_validation:
            chunk_ids = chunk_ids[:1]

        all_records = self.tenable_helper.fetch_chunks(
            chunk_endpoint_template=FINDINGS_CHUNK_DOWNLOAD_ENDPOINT,
            headers=headers,
            export_uuid=export_uuid,
            chunk_ids=chunk_ids,
            entity_type="vulnerability findings",
            verify=self.ssl_validation,
            proxies=self.proxy,
            is_validation=is_validation,
        )

        if is_validation:
            self.logger.debug(
                f"{self.log_prefix}: Successfully validated findings."
            )
            return []

        storage.update(
            {
                "vulnerability_checkpoint": vulnerability_checkpoint
            }
        )

        return all_records

    @exception_handler
    def _fetch_assets(
        self,
        headers: dict,
        no_of_retries: int = 3,
        context: dict = {},
        is_validation: bool = False,
    ):
        """Fetch assets from Tenable using export API.

        Args:
            headers (dict): Headers dictionary.
            no_of_retries (int): Number of retries.
            context (dict): Context dictionary.
            is_validation (bool): Whether this is for validation.

        Returns:
            list: List of asset records.
        """
        self.logger.info(
            f"{self.log_prefix}: Fetching assets from "
            f"{PLATFORM_NAME} platform."
        )
        context["logger_msg"] = "fetching assets"

        if is_validation:
            body = {
                "chunk_size": 100,
                "include_resource_tags": True,
            }
        else:
            storage = self._get_storage()
            last_run_at = self.last_run_at
            body = {
                "chunk_size": ASSET_PAGE_SIZE,
                "include_resource_tags": True,
            }

        export_endpoint = ASSETS_EXPORT_ENDPOINT.format(base_url=BASE_URL)
        export_uuid = self.tenable_helper.initiate_export(
            endpoint=export_endpoint,
            body=body,
            headers=headers,
            entity_type="assets",
            verify=self.ssl_validation,
            proxies=self.proxy,
            is_validation=is_validation,
        )

        status_endpoint = ASSETS_STATUS_ENDPOINT.format(
            base_url=BASE_URL,
            export_uuid=export_uuid
        )

        status_response = self.tenable_helper.check_export_status(
            status_endpoint=status_endpoint,
            headers=headers,
            export_uuid=export_uuid,
            entity_type="assets",
            no_of_retries=no_of_retries,
            verify=self.ssl_validation,
            proxies=self.proxy,
            is_validation=is_validation,
        )

        chunk_ids = status_response.get("chunks_available", [])
        if not chunk_ids:
            self.logger.info(
                f"{self.log_prefix}: No assets available to fetch."
            )
            if not is_validation:
                storage.update(
                    {
                        "last_run_at": last_run_at
                    }
                )
            return []

        if is_validation:
            chunk_ids = chunk_ids[:1]

        all_records = self.tenable_helper.fetch_chunks(
            chunk_endpoint_template=ASSETS_CHUNK_DOWNLOAD_ENDPOINT,
            headers=headers,
            export_uuid=export_uuid,
            chunk_ids=chunk_ids,
            entity_type="assets",
            verify=self.ssl_validation,
            proxies=self.proxy,
            is_validation=is_validation,
        )

        if is_validation:
            self.logger.debug(
                f"{self.log_prefix}: Successfully validated assets."
            )
            return []

        storage.update(
            {
                "last_run_at": last_run_at
            }
        )

        return all_records

    def _combine_asset_vulnerability_findings(
        self,
        asset_records: list,
        finding_records: list,
    ) -> list:
        """Combine asset and vulnerability finding records.

        Args:
            asset_records (list): List of asset records.
            finding_records (list): List of vulnerability finding records.

        Returns:
            list: List of combined asset and vulnerability finding records.
        """
        if not asset_records or not finding_records:
            return []

        # Create asset lookup map
        asset_map = {
            asset.get("Asset ID"): asset
            for asset in asset_records
            if asset.get("Asset ID")
        }

        # Merge findings into assets
        combined_count = 0
        updated_assets = []
        processed_assets = set()
        for finding in finding_records:
            asset_id = finding.get("Asset ID")
            if not asset_id or asset_id not in asset_map:
                continue

            updated_assets.append(finding)
            processed_assets.add(asset_id)
            combined_count += 1

        self.logger.info(
            f"{self.log_prefix}: Successfully updated {len(processed_assets)} "
            f"asset(s) with {combined_count} vulnerability findings."
        )
        return updated_assets

    def fetch_records(self, entity: str) -> list:
        """Fetch vulnerability records from Tenable.

        Args:
            entity (str): Entity name to fetch records for.

        Returns:
            list: List of vulnerability records fetched from Tenable.
        """
        entity_name = entity.lower()
        fetched_records = []
        if entity_name == "assets":
            access_key, secret_key, _, no_of_retries = (
                self.tenable_helper.get_configuration_parameters(
                    configuration=self.configuration,
                )
            )
            headers = self.tenable_helper.get_auth_headers(
                access_key, secret_key
            )
            fetched_records = self._fetch_assets(
                headers=headers,
                no_of_retries=no_of_retries,
                context={}
            )

            return fetched_records
        else:
            err_msg = (
                f"Invalid entity found. {PLATFORM_NAME} plugin "
                "only supports 'Assets' Entity."
            )
            resolution = "Ensure that the entity is 'Assets'."
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                resolution=resolution,
            )
            raise TenablePluginException(err_msg)

    def update_records(self, entity: str, records: list[dict]) -> list[dict]:
        """Fetch asset's vulnerability findings from Tenable platform.

        Args:
            entity (str): Entity name.
            records (list[Record]): list of records

        Returns:
            list[Record]: list of records with vulnerability findings.
        """
        entity_name = entity.lower()

        if not records:
            self.logger.info(
                f"{self.log_prefix}: Skipping update records "
                "as no records to update."
            )
            return []

        if entity_name == "assets":
            self.logger.info(
                f"{self.log_prefix}: Updating {len(records)} "
                f"Asset(s) records from {PLATFORM_NAME} platform."
            )
            access_key, secret_key, initial_range, no_of_retries = (
                self.tenable_helper.get_configuration_parameters(
                    configuration=self.configuration,
                )
            )
            headers = self.tenable_helper.get_auth_headers(
                access_key, secret_key
            )

            finding_records = self._fetch_vulnerability_findings(
                headers=headers,
                initial_range=initial_range,
                no_of_retries=no_of_retries,
                context={}
            )

            merge_records = self._combine_asset_vulnerability_findings(
                asset_records=records,
                finding_records=finding_records,
            )
            return merge_records
        else:
            err_msg = (
                f"Invalid entity found. {PLATFORM_NAME} plugin "
                "only supports 'Assets' Entity."
            )
            resolution = "Ensure that the entity is 'Assets'."
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                resolution=resolution,
            )
            raise TenablePluginException(err_msg)

    def get_actions(self):
        """Get available actions."""
        return [
            ActionWithoutParams(
                label="Tag/Untag Asset", value="tag_untag_asset"
            ),
            ActionWithoutParams(label="No action", value="generate"),
        ]

    def get_action_params(self, action: Action):
        """Get action params.

        Args:
            action (Action): Action object.

        Returns:
            list: List of action parameters.
        """
        if action.value == "generate":
            return []

        if action.value == "tag_untag_asset":
            access_key, secret_key, *_ = (
                self.tenable_helper.get_configuration_parameters(
                    configuration=self.configuration,
                )
            )
            headers = self.tenable_helper.get_auth_headers(
                access_key, secret_key
            )
            categories = self.tenable_helper.get_all_categories(
                verify=self.ssl_validation,
                proxies=self.proxy,
                headers=headers
            )
            return [
                {
                    "label": "Tag Action",
                    "key": "tag_action",
                    "type": "choice",
                    "choices": [
                        {
                            "key": "Add",
                            "value": "tag_assets",
                        },
                        {
                            "key": "Remove",
                            "value": "untag_assets",
                        }
                    ],
                    "mandatory": True,
                    "default": "tag_assets",
                    "description": (
                        "Select 'Add' to tag the asset or "
                        "'Remove' to untag the asset from "
                        "Static field dropdown only."
                    )
                },
                {
                    "label": "Asset ID",
                    "key": "asset_id",
                    "type": "text",
                    "default": "",
                    "mandatory": True,
                    "description": (
                        "Select Asset ID field from source "
                        "or provide static multiple comma separated Asset IDs."
                    )
                },
                {
                    "label": "Category",
                    "key": "tags_category",
                    "type": "choice",
                    "choices": [
                        {
                            "key": cat.get("name", ""),
                            "value": cat.get("name", ""),
                        }
                        for cat in categories
                    ]
                    + [{"key": "Create new category", "value": "create"}],
                    "default": (
                        categories[0]["name"] if len(categories) > 0
                        else "create"
                    ),
                    "mandatory": False,
                    "description": (
                        "Select an existing category or "
                        "'Create new category' from Static field "
                        "dropdown only."
                    )
                },
                {
                    "label": "Create New Category",
                    "key": "create_new_category",
                    "type": "text",
                    "default": "",
                    "mandatory": False,
                    "description": (
                        "Provide a tag category name if 'Create new category' "
                        "is selected in 'Category' field."
                    )
                },
                {
                    "label": "Tag(s)",
                    "key": "tags",
                    "type": "text",
                    "default": "",
                    "mandatory": True,
                    "description": (
                        "Select source field for the tags or provide "
                        "static multiple comma separated tags. Tag value(s) "
                        "should be less than or equal to "
                        f"{TAG_VALUE_MAX_LENGTH} characters."
                    )
                },
            ]

        return []

    def validate_action(self, action: Action):
        """Validate Netskope configuration.

        Args:
            action (Action): Action to perform on assets.

        Returns:
            ValidationResult: Validation result.
        """
        action_value = action.value
        if action_value not in ["generate", "tag_untag_asset"]:
            err_msg = (
                f"Unsupported action '{action_value}' "
                "provided in the action configuration. "
                "Supported Actions are - 'Tag/Untag Asset' "
                "and 'No Action'."
            )
            resolution = (
                "Ensure that the action is selected from the "
                "supported actions 'Tag/Untag Asset' and "
                "'No Action' in the action configuration."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                resolution=resolution,
            )
            return ValidationResult(
                success=False, message="Unsupported action provided."
            )

        if action_value == "tag_untag_asset":
            # Validate tag action parameters
            params = action.parameters

            tag_action = params.get("tag_action", "tag_assets")
            if validation_result := self._validate_parameters(
                parameter_type=ACTION,
                field_name="Tag Action",
                field_value=tag_action,
                field_type=str,
                is_source_field_allowed=False,
            ):
                return validation_result

            # Validate Asset ID field
            asset_id = params.get("asset_id", "")
            if validation_result := self._validate_parameters(
                parameter_type=ACTION,
                field_name="Asset ID",
                field_value=asset_id,
                field_type=str,
                check_dollar=True,
            ):
                return validation_result

            # Validate tags category
            tags_category = params.get("tags_category", "")
            if validation_result := self._validate_parameters(
                parameter_type=ACTION,
                field_name="Category",
                field_value=tags_category,
                field_type=str,
                is_required=False,
                is_source_field_allowed=False,
            ):
                return validation_result

            if tag_action == "tag_assets" and not tags_category.strip():
                err_msg = (
                    "Category is required action parameters when "
                    "Tag Action is 'Add'."
                )
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg}",
                    resolution=(
                        "Ensure that the 'Category' field is provided "
                        "in the action parameters when Tag Action is "
                        "'Add'."
                    ),
                )
                return ValidationResult(
                    success=False,
                    message=err_msg,
                )

            if tag_action == "untag_assets" and tags_category == "create":
                err_msg = (
                    "'Create new category' is not allowed "
                    "when Tag Action is 'Remove'."
                )
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg}",
                    resolution=(
                        "Ensure that the existing 'Category' is "
                        "selected in the action parameters when Tag Action is "
                        "'Remove'."
                    ),
                )
                return ValidationResult(
                    success=False,
                    message=err_msg,
                )

            # Validate create new category
            if tags_category == "create":
                create_new_category = params.get("create_new_category", "")
                if validation_result := self._validate_parameters(
                    parameter_type=ACTION,
                    field_name="Create New Category",
                    field_value=create_new_category,
                    field_type=str,
                    is_required=False,
                    is_source_field_allowed=False,
                ):
                    return validation_result

                if not create_new_category.strip():
                    err_msg = (
                        "Create New Category is required when "
                        "'Create New Category' is selected in the "
                        "'Category' field."
                    )
                    self.logger.error(
                        message=f"{self.log_prefix}: {err_msg}",
                        resolution=(
                            "Ensure that the 'Create New Category' field is "
                            "provided in the action parameters when "
                            "'Create New Category' is selected in the "
                            "'Category' field."
                        ),
                    )
                    return ValidationResult(
                        success=False,
                        message=err_msg,
                    )

            # Validate Tag(s)
            tags = params.get("tags", "")
            if validation_result := self._validate_parameters(
                parameter_type=ACTION,
                field_name="Tag(s)",
                field_value=tags,
                field_type=str,
                check_dollar=True,
            ):
                return validation_result

            # Validate tag values
            tag_list = [tag.strip() for tag in tags.split(",")]
            for tag in tag_list:
                if not tag:
                    err_msg = (
                        "Invalid tag value(s) provided."
                    )
                    self.logger.error(
                        message=f"{self.log_prefix}: {err_msg}",
                        resolution=(
                            "Ensure that the tag value(s) "
                            "provided in the action parameters "
                            "are valid."
                        ),
                    )
                    return ValidationResult(
                        success=False,
                        message=err_msg,
                    )
                if len(tag) > TAG_VALUE_MAX_LENGTH:
                    err_msg = (
                        f"Tag '{tag}' exceeds maximum length of "
                        f"{TAG_VALUE_MAX_LENGTH} characters."
                    )
                    self.logger.error(
                        message=f"{self.log_prefix}: {err_msg}",
                        resolution=(
                            f"Ensure that the tag '{tag}' is less than "
                            f"{TAG_VALUE_MAX_LENGTH} characters."
                        ),
                    )
                    return ValidationResult(
                        success=False,
                        message=err_msg,
                    )

        return ValidationResult(success=True, message="Validation successful.")

    @exception_handler
    def execute_actions(self, actions: List[Action]):
        """Execute actions on records.

        Args:
            actions (List[Action]): List of actions to execute.
        """
        first_action = (
            actions[0].get("params", {})
            if self._is_ce_post_v512
            else actions[0]
        )
        action_label = first_action.label
        action_value = first_action.value
        self.logger.info(
            f"{self.log_prefix}: Executing '{action_label}' action "
            f"for {len(actions)} records."
        )

        if action_value == "generate":
            self.logger.info(
                f"{self.log_prefix}: Successfully executed 'No Action'. "
                "Note: No processing will be done from plugin for this action."
            )
            return

        if action_value == "tag_untag_asset":
            failed_action_ids = self._execute_tag_untag_actions(actions)

            # If CE supports partial action failure return ActionResult model
            if self._is_ce_post_v512:
                from netskope.integrations.crev2.plugin_base import (
                    ActionResult,
                )
                return ActionResult(
                    success=True,
                    message=f"Successfully executed {action_label} action.",
                    failed_action_ids=list(set(failed_action_ids)),
                )
            return
        else:
            err_msg = (
                f"Unsupported action '{action_value}' "
                "provided in the action configuration. Supported Actions "
                "are - 'Tag/Untag Asset' and 'No Action'."
            )
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            raise TenablePluginException(err_msg)

    def _execute_tag_untag_actions(self, actions: List[Action]) -> List[str]:
        """Execute tag/untag actions on assets with bulk processing.

        Args:
            actions (List[Action]): List of actions with records.

        Returns:
            List[str]: List of failed action IDs.
        """
        failed_action_ids = []
        tag_groups = {}

        access_key, secret_key, *_ = (
            self.tenable_helper.get_configuration_parameters(
                configuration=self.configuration,
            )
        )
        headers = self.tenable_helper.get_auth_headers(
            access_key, secret_key
        )

        try:
            # Get all existing tags once for efficiency
            existing_tags = self.tenable_helper.get_all_tags(
                verify=self.ssl_validation,
                proxies=self.proxy,
                headers=headers
            )
        except Exception as exp:
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Failed to fetch tags. "
                    f"Error: {exp}"
                ),
                details=traceback.format_exc(),
            )
            # Return all action IDs as failed or handle gracefully
            return [
                action_dict.get("id", "") for action_dict in actions
                if self._is_ce_post_v512
            ]

        tag_groups, failed_actions = self._process_actions_and_group_by(
            actions=actions,
        )
        failed_action_ids.extend(failed_actions)

        # Execute bulk operations for each tag group
        for (
            (tag_value, api_action, category_name),
            group_data
        ) in tag_groups.items():
            asset_ids = group_data.get("asset_ids", [])
            action_id_to_assets = group_data.get("action_id_to_assets", {})

            # Remove duplicates while preserving order
            unique_asset_ids = list(dict.fromkeys(asset_ids))

            try:
                group_failed_action_ids = (
                    self._bulk_execute_tag_action_with_batching(
                        action_type=api_action,
                        tag_value=tag_value,
                        existing_tags=existing_tags,
                        category_name=category_name,
                        asset_ids=unique_asset_ids,
                        action_id_to_assets=action_id_to_assets,
                        headers=headers,
                    )
                )
                failed_action_ids.extend(group_failed_action_ids)
            except Exception as exp:
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: Error executing bulk tag action "
                        f"for tag '{tag_value}'. Error: {exp}"
                    ),
                    details=traceback.format_exc(),
                )
                # Mark all actions in this group as failed
                failed_action_ids.extend(list(action_id_to_assets.keys()))

        return failed_action_ids

    def _process_actions_and_group_by(
        self,
        actions: List[Action],
    ):
        """Process actions and group by tag, action type, and category name.

        Args:
            actions (List[Action]): List of actions to process

        Returns:
            Dict: Dictionary of tag, action type, and category name to \
                asset IDs
        """
        tag_groups = {}
        failed_action_ids = []
        # Process each action and group by tag/action type
        for action_dict in actions:
            try:
                if self._is_ce_post_v512:
                    action_params = action_dict.get("params", {}).parameters
                    action_id = action_dict.get("id", "")
                else:
                    action_params = action_dict.parameters
                    action_id = ""

                asset_id_str = action_params.get("asset_id", "")
                tags_category = action_params.get("tags_category", "")
                create_new_category = (
                    action_params.get("create_new_category", "")
                )

                if not asset_id_str:
                    self.logger.debug(
                        f"{self.log_prefix}: Skipping action {action_id} - "
                        "no asset ID provided."
                    )
                    if action_id:
                        failed_action_ids.append(action_id)
                    continue

                asset_ids = []
                if isinstance(asset_id_str, list):
                    asset_ids = [
                        str(id).strip() for id in asset_id_str
                        if str(id).strip()
                    ]
                elif isinstance(asset_id_str, str):
                    if not asset_id_str.strip():
                        self.logger.debug(
                            f"{self.log_prefix}: Skipping action {action_id}"
                            " - empty asset ID provided."
                        )
                        failed_action_ids.append(action_id)
                        continue
                    asset_ids = (
                        [
                            id.strip() for id in asset_id_str.split(",")
                            if id.strip()
                        ]
                        if "," in asset_id_str
                        else [str(asset_id_str).strip()]
                    )
                else:
                    asset_ids = (
                        [str(asset_id_str).strip()]
                        if asset_id_str
                        else []
                    )

                # Determine category name
                category_name = None
                if tags_category == "create":
                    category_name = create_new_category.strip()
                elif tags_category:
                    category_name = tags_category

                if not category_name:
                    self.logger.debug(
                        f"{self.log_prefix}: Skipping action {action_id} - "
                        "could not determine category name."
                    )
                    if action_id:
                        failed_action_ids.append(action_id)
                    continue

                tag_value = action_params.get("tags", "")
                if not tag_value:
                    self.logger.debug(
                        f"{self.log_prefix}: Skipping action {action_id} - "
                        "no tags provided."
                    )
                    if action_id:
                        failed_action_ids.append(action_id)
                    continue

                tag_list = []
                # Source field - extract from record
                if tag_value and isinstance(tag_value, list):
                    tag_list = [
                        str(t).strip()
                        for t in tag_value
                        if str(t).strip()
                    ]
                elif tag_value and isinstance(tag_value, str):
                    # Static field - parse comma-separated values
                    if not tag_value.strip():
                        self.logger.debug(
                            f"{self.log_prefix}: Skipping action {action_id} "
                            "- empty tag value provided."
                        )
                        if action_id:
                            failed_action_ids.append(action_id)
                        continue
                    tag_list = (
                        [
                            tag.strip() for tag in tag_value.split(",")
                            if tag.strip()
                        ]
                        if "," in tag_value
                        else [str(tag_value).strip()]
                    )
                else:
                    tag_list = [str(tag_value).strip()] if tag_value else []

                # Group by (tag, action_type, category_name) for bulk
                tag_action = action_params.get("tag_action", "tag_assets")
                api_action = "add" if tag_action == "tag_assets" else "remove"
                for tag_value in tag_list:
                    tag_key = (tag_value, api_action, category_name)

                    if tag_key not in tag_groups:
                        tag_groups[tag_key] = {
                            "asset_ids": [],
                            "action_id_to_assets": {},
                        }

                    tag_groups[tag_key]["asset_ids"].extend(asset_ids)
                    if action_id:
                        action_assets = (
                            tag_groups[tag_key]["action_id_to_assets"]
                        )
                        if action_id not in action_assets:
                            action_assets[action_id] = []
                        action_assets[action_id].extend(asset_ids)

            except Exception as exp:
                err_msg = (
                    f"Error occurred while processing action "
                    f"with ID '{action_id if action_id else 'unknown'}'. "
                    f"Error: {exp}."
                )
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg}",
                    details=traceback.format_exc(),
                )
                if action_id:
                    failed_action_ids.append(action_id)
                continue

        return tag_groups, failed_action_ids

    def _bulk_execute_tag_action_with_batching(
        self,
        action_type: str,
        tag_value: str,
        existing_tags: list[dict],
        category_name: str,
        asset_ids: List[str],
        action_id_to_assets: Dict[str, List[str]],
        headers: dict,
    ) -> List[str]:
        """Execute bulk tag action with batching and failure tracking.

        Args:
            action_label (str): Action label for logging
            action_type (str): Action type ('add' or 'remove')
            tag_value (str): Tag value to apply/remove
            category_name (str): Category name
            asset_ids (List[str]): List of unique asset IDs
            action_id_to_assets (Dict[str, List[str]]): Mapping of action_id
                to asset_ids
            headers (dict): API Headers

        Returns:
            List[str]: List of failed action IDs
        """
        failed_action_ids = []

        log_prefix = "Adding" if action_type == "add" else "Removing"
        self.logger.info(
            f"{self.log_prefix}: {log_prefix} tag '{tag_value}' of category "
            f"'{category_name}' on {len(asset_ids)} asset(s) in batches of "
            f"{TAG_ASSIGNMENT_BATCH_SIZE}."
        )

        # Get or create tag UUID
        tag_uuid = self._get_or_create_tag(
            category_name=category_name,
            existing_tags=existing_tags,
            tag_value=tag_value,
            action_type=action_type,
            headers=headers
        )

        if not tag_uuid:
            err_msg = (
                f"Unable to get '{tag_value}' in category "
                f"'{category_name}' hence skipping "
                f"this action."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
            )
            # Mark all actions as failed
            return list(action_id_to_assets.keys())

        # Process in batches
        total_batches = (
            (len(asset_ids) + TAG_ASSIGNMENT_BATCH_SIZE - 1) //
            TAG_ASSIGNMENT_BATCH_SIZE
        )
        failed_asset_ids = set()
        successful_batches = 0

        for batch_num in range(total_batches):
            start_idx = batch_num * TAG_ASSIGNMENT_BATCH_SIZE
            end_idx = min(
                start_idx + TAG_ASSIGNMENT_BATCH_SIZE, len(asset_ids)
            )
            batch_asset_ids = asset_ids[start_idx:end_idx]

            batch_action_ids = []
            for action_id, action_asset_ids in action_id_to_assets.items():
                if any(
                    asset_id in batch_asset_ids
                    for asset_id in action_asset_ids
                ):
                    batch_action_ids.append(action_id)

            try:
                logger_msg = (
                    f"{log_prefix} tag '{tag_value}' of category "
                    f"{category_name} on batch "
                    f"{batch_num + 1}/{total_batches} ({len(batch_asset_ids)} "
                    "asset(s))"
                )
                _ = self.tenable_helper.assign_remove_tags(
                    action=action_type,
                    asset_uuids=batch_asset_ids,
                    tag_uuids=[tag_uuid],
                    headers=headers,
                    verify=self.ssl_validation,
                    proxies=self.proxy,
                    logger_msg=logger_msg
                )

                successful_batches += 1
                self.logger.info(
                    f"{self.log_prefix}: Successfully "
                    f"{'added' if action_type == 'add' else 'removed'} tag "
                    f"'{tag_value}' on {len(batch_asset_ids)} asset(s) in "
                    f"batch {batch_num + 1}/{total_batches}."
                )

            except Exception as e:
                # Track failed asset IDs and action IDs
                failed_asset_ids.update(batch_asset_ids)
                failed_action_ids.extend(batch_action_ids)

                action_verb = 'add' if action_type == 'add' else 'remove'
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: Failed to {action_verb} tag "
                        f"'{tag_value}' in batch {batch_num + 1}/"
                        f"{total_batches} ({len(batch_asset_ids)} asset(s)). "
                        f"Error: {str(e)}"
                    ),
                    details=traceback.format_exc(),
                )

        successful_assets = len(asset_ids) - len(failed_asset_ids)
        action_verb = 'added' if action_type == 'add' else 'removed'
        self.logger.info(
            f"{self.log_prefix}: Successfully {action_verb} tag '{tag_value}' "
            f"on {successful_assets} asset(s) and failed on "
            f"{len(failed_asset_ids)} asset(s)."
        )

        return failed_action_ids

    def _get_or_create_tag(
        self,
        category_name: str,
        existing_tags: list[dict],
        tag_value: str,
        action_type: str,
        headers: dict
    ) -> str:
        """Get existing tag UUID or create new tag.

        Args:
            category_name (str): Category name.
            existing_tags (list[dict]): List of existing tags.
            action_type (str): Action type ('add' or 'remove').
            tag_value (str): Tag value.
            headers (dict): API Headers.

        Returns:
            str: Tag UUID or None if failed.
        """
        try:
            for tag in existing_tags:
                if (tag.get("category_name") == category_name and
                        tag.get("value").lower() == tag_value.lower()):
                    tag_uuid = tag.get("uuid")
                    if tag_uuid:
                        self.logger.debug(
                            f"{self.log_prefix}: Found existing tag "
                            f"'{tag_value}' in category '{category_name}' "
                            f"with UUID: {tag_uuid}."
                        )
                        return tag_uuid

            if action_type == 'remove':
                return None

            if len(tag_value) > TAG_VALUE_MAX_LENGTH:
                err_msg = (
                    f"Tag value '{tag_value}' exceeds maximum length of "
                    f"{TAG_VALUE_MAX_LENGTH} characters."
                )
                resolution = (
                    f"Ensure that tag value '{tag_value}' does not exceed maximum "
                    f"length of {TAG_VALUE_MAX_LENGTH} characters."
                )
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg}",
                    resolution=resolution,
                )
                return None

            # Tag doesn't exist, create it
            self.logger.debug(
                f"{self.log_prefix}: Creating new tag '{tag_value}' "
                f"in category '{category_name}'."
            )
            response = self.tenable_helper.create_tag_value(
                category_name=category_name,
                tag_value=tag_value,
                verify=self.ssl_validation,
                proxies=self.proxy,
                headers=headers
            )
            if response and isinstance(response, dict):
                tag_uuid = response.get("uuid")
                if tag_uuid:
                    self.logger.info(
                        f"{self.log_prefix}: Successfully created tag "
                        f"'{tag_value}' in category '{category_name}' "
                        f"with UUID: {tag_uuid}."
                    )
                    existing_tags.append(response)
                    return tag_uuid

            err_msg = (
                f"Unable to get or create tag '{tag_value}' "
                f"in category '{category_name}'."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=f"API response: {response}",
            )
            return None
        except Exception as exp:
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Failed to get or create tag. "
                    f"Error: {exp}"
                ),
                details=traceback.format_exc(),
            )
            return None

    def _validate_parameters(
        self,
        parameter_type: str,
        field_name: str,
        field_value: Union[str, List, bool, int],
        field_type: type,
        max_value: int = None,
        min_value: int = None,
        is_required: bool = True,
        check_dollar: bool = False,
        is_source_field_allowed: bool = True,
    ) -> Union[ValidationResult, None]:
        """
        Validate the given configuration field value.

        Args:
            parameter_type (str): Type of the configuration parameter.
            field_name (str): Name of the configuration field.
            field_value (str, List, bool, int): Value of the configuration
                field.
            field_type (type): Expected type of the configuration field.
            max_value (int, optional): Maximum value for the configuration
                field. Defaults to None.
            min_value (int, optional): Minimum value for the configuration
                field. Defaults to None.
            is_required (bool, optional): Whether the field is required.
                Defaults to True.
            check_dollar (bool, optional): Whether to check for the dollar
                sign in the field value. Defaults to False.
            is_source_field_allowed (bool, optional): Whether the source field
                is allowed. Defaults to True.

        Returns:
            ValidationResult: ValidationResult object indicating whether the
                validation was successful or not.
        """
        if (
            parameter_type == "action" and
            not is_source_field_allowed and
            isinstance(field_value, str) and
            "$" in field_value
        ):
            err_msg = (
                f"'{field_name}' contains the Source Field. "
                f"Provide '{field_name}' in Static field."
            )
            resolution = (
                "Ensure that Static is selected for the field "
                f"'{field_name}' in the action configuration."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                resolution=resolution,
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )

        if (
            check_dollar and
            isinstance(field_value, str) and
            "$" in field_value
        ):
            info_msg = (
                f"'{field_name}' contains the Source Field "
                "hence validation for this field will be performed "
                "while executing the action."
            )
            self.logger.info(
                message=f"{self.log_prefix}: {info_msg}",
            )
            return

        if field_type is str and isinstance(field_value, str):
            field_value = field_value.strip()
        if (
            is_required and
            not isinstance(field_value, int) and
            not field_value
        ):
            err_msg = (
                f"'{field_name}' is a required {parameter_type} parameter."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {VALIDATION_ERROR_MSG}{err_msg}",
                resolution=(
                    f"Ensure that {field_name} field value is provided."
                ),
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        if not isinstance(field_value, field_type):
            err_msg = (
                f"Invalid value provided for the {parameter_type} "
                f"parameter '{field_name}'."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {VALIDATION_ERROR_MSG}{err_msg}",
                resolution=(
                    f"Ensure that {field_name} field value is valid."
                ),
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )

        if max_value is not None and min_value is not None:
            if min_value > field_value or max_value < field_value:
                if max_value == INTEGER_THRESHOLD:
                    max_value = "2^62"
                err_msg = (
                    f"Invalid value provided for the {parameter_type} "
                    f"parameter '{field_name}'. Valid value should be "
                    f"an integer greater than {min_value} and "
                    f"less than {max_value}."
                )
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: {VALIDATION_ERROR_MSG}{err_msg}"
                    ),
                    resolution=(
                        f"Ensure that a valid value greater than "
                        f" {min_value} and less than {max_value} "
                        f"is provided for the {parameter_type} "
                        f"parameter '{field_name}'."
                    )
                )
                return ValidationResult(
                    success=False,
                    message=err_msg,
                )

    def validate(self, configuration: dict) -> ValidationResult:
        """Validate the Plugin configuration parameters.

        Args:
            configuration (dict): dict object having all the Plugin
            configuration parameters.
        Returns:
            cte.plugin_base.ValidateResult: ValidateResult object with success
            flag and message.
        """
        access_key, secret_key, initial_range, no_of_retries = (
            self.tenable_helper.get_configuration_parameters(
                configuration=configuration,
            )
        )

        # Validate Access Key
        if validation_result := self._validate_parameters(
            parameter_type=CONFIGURATION,
            field_name="Access Key",
            field_value=access_key,
            field_type=str,
        ):
            return validation_result

        # Validate Secret Key
        if validation_result := self._validate_parameters(
            parameter_type=CONFIGURATION,
            field_name="Secret Key",
            field_value=secret_key,
            field_type=str,
        ):
            return validation_result

        # Validate Initial range
        if validation_result := self._validate_parameters(
            parameter_type=CONFIGURATION,
            field_name="Initial Range (in days)",
            field_value=initial_range,
            field_type=int,
            min_value=0,
            max_value=INTEGER_THRESHOLD,
        ):
            return validation_result

        # Validate Number of Retries
        if validation_result := self._validate_parameters(
            parameter_type=CONFIGURATION,
            field_name="Number of Retries",
            field_value=no_of_retries,
            field_type=int,
            min_value=0,
            max_value=INTEGER_THRESHOLD,
        ):
            return validation_result

        # Validate Auth Credentials
        return self._validate_connectivity(
            configuration=configuration,
        )

    def _validate_connectivity(
        self,
        configuration: dict,
    ) -> ValidationResult:
        """Validate the authentication params with Tenable platform.

        Args:
            configuration (dict): Configuration dictionary.

        Returns:
            ValidationResult: ValidationResult object having validation
                results after making an API call.
        """
        try:
            self.logger.info(
                f"{self.log_prefix}: Validating connectivity with "
                f"{PLATFORM_NAME} platform."
            )

            access_key, secret_key, initial_range, *_ = (
                self.tenable_helper.get_configuration_parameters(
                    configuration=configuration,
                )
            )
            headers = self.tenable_helper.get_auth_headers(
                access_key, secret_key
            )

            self._fetch_assets(
                headers=headers,
                context={},
                is_validation=True
            )

            self._fetch_vulnerability_findings(
                headers=headers,
                initial_range=initial_range,
                context={},
                is_validation=True
            )

            success_msg = (
                f"Successfully validated connectivity with "
                f"{PLATFORM_NAME} platform."
            )
            self.logger.debug(
                f"{self.log_prefix}: {success_msg}"
            )

            return ValidationResult(
                success=True,
                message=success_msg,
            )

        except TenablePluginException as exp:
            err_msg = f"Validation failed. Error: {exp}"
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=traceback.format_exc(),
            )
            return ValidationResult(
                success=False,
                message=str(exp)
            )
        except Exception as exp:
            err_msg = f"Unexpected validation error occurred. Error: {exp}"
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=traceback.format_exc(),
            )
            return ValidationResult(
                success=False,
                message="Unexpected validation error occurred. Check logs."
            )

    def get_entities(self) -> list[Entity]:
        """Get available entities."""
        return [
            Entity(
                name="Assets",
                fields=[
                    EntityField(
                        name="Asset ID",
                        label="Asset ID",
                        type=EntityFieldType.STRING,
                        required=True,
                    ),
                    EntityField(
                        name="Agent UUID",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="Asset Types",
                        type=EntityFieldType.LIST,
                    ),
                    EntityField(
                        name="Agent Names",
                        type=EntityFieldType.LIST,
                    ),
                    EntityField(
                        name="Operating Systems",
                        type=EntityFieldType.LIST,
                    ),
                    EntityField(
                        name="System Types",
                        type=EntityFieldType.LIST,
                    ),
                    EntityField(
                        name="Installed Software",
                        type=EntityFieldType.LIST,
                    ),
                    EntityField(
                        name="Serial Number",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="Sources Name",
                        type=EntityFieldType.LIST,
                    ),
                    EntityField(
                        name="Tags",
                        type=EntityFieldType.LIST,
                    ),
                    EntityField(
                        name="IPv4 Addresses",
                        type=EntityFieldType.LIST,
                    ),
                    EntityField(
                        name="IPv6 Addresses",
                        type=EntityFieldType.LIST,
                    ),
                    EntityField(
                        name="FQDNs",
                        type=EntityFieldType.LIST,
                    ),
                    EntityField(
                        name="MAC Addresses",
                        type=EntityFieldType.LIST,
                    ),
                    EntityField(
                        name="Hostname",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="Hostnames",
                        type=EntityFieldType.LIST,
                    ),
                    EntityField(
                        name="First Seen",
                        type=EntityFieldType.DATETIME,
                    ),
                    EntityField(
                        name="Last Seen",
                        type=EntityFieldType.DATETIME,
                    ),
                    EntityField(
                        name="Asset Criticality Rating",
                        type=EntityFieldType.NUMBER,
                    ),
                    EntityField(
                        name="Asset Exposure Score",
                        type=EntityFieldType.NUMBER,
                    ),
                    EntityField(
                        name="Cloud Resource Tags",
                        type=EntityFieldType.LIST,
                    ),
                    EntityField(
                        name="CVSSv3 Base Score",
                        type=EntityFieldType.NUMBER,
                    ),
                    EntityField(
                        name="CVSSv3 Temporal Score",
                        type=EntityFieldType.NUMBER,
                    ),
                    EntityField(
                        name="VPR Score",
                        type=EntityFieldType.NUMBER,
                    ),
                    EntityField(
                        name="EPSS Score",
                        type=EntityFieldType.NUMBER,
                    ),
                    EntityField(
                        name="Risk Factor",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="Severity",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="State",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="CVEs",
                        type=EntityFieldType.LIST,
                    ),
                ],
            )
        ]
