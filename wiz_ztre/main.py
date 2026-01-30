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

CRE Wiz Plugin.
"""

import traceback
from copy import deepcopy
from datetime import datetime, timedelta
from dateutil import parser
from typing import Callable, Dict, List, Tuple, Type, Union
from urllib.parse import urlparse

from netskope.common.api import __version__ as CE_VERSION
from netskope.integrations.crev2.models import (
    Action,
    ActionWithoutParams
)
from netskope.integrations.crev2.plugin_base import (
    PluginBase,
    ValidationResult,
    Entity,
    EntityField,
    EntityFieldType
)
from packaging import version

from .utils.wiz_constants import (
    MODULE_NAME,
    PAGE_SIZE,
    PLATFORM_NAME,
    PLUGIN_VERSION,
    GRAPHQL_QUERY,
    WORKLOADS_QUERY,
    WORKLOADS_FIELDS,
    MAXIMUM_CE_VERSION,
    WORKLOADS_ENTITY_NAME,
    GRAPHQL_ENDPOINT,
    APPLICATION_FIELDS,
    APPLICATION_ENTITY_NAME,
    DATE_TIME_FORMAT,
    INTEGER_THRESHOLD
)
from .utils.wiz_helper import WizPluginException, WizPluginHelper


class WizPlugin(PluginBase):
    """Wiz plugin implementation."""

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
        # Flag to check if CE version is more than v5.1.2
        self._is_ce_post_v512 = self._check_ce_version()
        # Method to decide which logger to use with or without
        # resolutions based on the CE version
        self._patch_error_logger()
        self.plugin_name, self.plugin_version = self._get_plugin_info()
        self.log_prefix = f"{MODULE_NAME} {self.plugin_name} [{name}]"
        self.wiz_helper = WizPluginHelper(
            logger=self.logger,
            log_prefix=self.log_prefix,
            plugin_name=self.plugin_name,
            plugin_version=self.plugin_version,
        )

    def _check_ce_version(self):
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

    def _create_entity(
        self, name: str, label: str = None, fields: list = None
    ) -> Entity:
        """Create Entity with backward compatible label parameter.

        Args:
            name (str): Entity name.
            label (str, optional): Entity label (only for CE > 5.1.2).
            fields (list, optional): List of EntityField objects.

        Returns:
            Entity: Entity object with conditional label parameter.
        """
        entity_kwargs = {"name": name}
        if fields:
            entity_kwargs["fields"] = fields
        if label and self._is_ce_post_v512:
            entity_kwargs["label"] = label
        return Entity(**entity_kwargs)

    def _create_entity_field(
        self,
        name: str,
        type: EntityFieldType,
        label: str = None,
        required: bool = False,
        **kwargs
    ) -> EntityField:
        """Create EntityField with backward compatible label parameter.

        Args:
            name (str): Field name.
            type (EntityFieldType): Field type.
            label (str, optional): Field label (only for CE > 5.1.2).
            required (bool, optional): Whether field is required.
                Defaults to False.
            **kwargs: Additional parameters to pass to EntityField.

        Returns:
            EntityField: EntityField object with conditional label
                parameter.
        """
        field_kwargs = {"name": name, "type": type}
        if required:
            field_kwargs["required"] = required
        if label and self._is_ce_post_v512:
            field_kwargs["label"] = label
        field_kwargs.update(kwargs)
        return EntityField(**field_kwargs)

    def _get_plugin_info(self) -> tuple:
        """Get plugin name and version from metadata.

        Returns:
            tuple: Tuple of plugin's name and version fetched from metadata.
        """
        try:
            metadata_json = WizPlugin.metadata
            plugin_name = metadata_json.get("name", PLATFORM_NAME)
            plugin_version = metadata_json.get("version", PLUGIN_VERSION)
            return (plugin_name, plugin_version)
        except Exception as exp:
            self.logger.error(
                message=(
                    f"{MODULE_NAME} {PLATFORM_NAME}: Error occurred while"
                    f" getting plugin details. Error: {exp}"
                ),
                details=traceback.format_exc(),
            )
        return (PLATFORM_NAME, PLUGIN_VERSION)

    def get_actions(self) -> List[ActionWithoutParams]:
        """Get available actions.

        Args:
            None

        Returns:
            [...] list of ActionWithoutParams: List of ActionWithoutParams
                which has label and value defined

        """
        return [
            ActionWithoutParams(label="No action", value="generate"),
        ]

    def execute_action(self, action: Action):
        """Execute action on the application.

        Args:
            record: Record of a application on which action will be
            performed.
            action (Action): Action that needs to be perform on application.

        Returns:
            None
        """
        if action.value == "generate":
            return

    def execute_actions(self, actions: List[Action]):
        """Execute actions in bulk.

        Args:
            actions (List[Action]): List of Action objects.
        """
        first_action = actions[0]
        action_label = first_action.label
        if first_action.value == "generate":
            self.logger.info(
                f"{self.log_prefix}: Successfully performed action "
                f"'{action_label}' on {len(actions)} records."
                "Note: No processing will be done from plugin for "
                f"the '{action_label}' action."
            )
            return

    def get_action_params(self, action: Action) -> List:
        """Get fields required for an action.

        Args:
            action (Action): The type of action

        Returns:
            [...] (list): Returns a list of details for UI to display group

        """
        if action.value in ["generate"]:
            return []

    def validate_action(self, action: Action) -> ValidationResult:
        """Validate Wiz action configuration.

        Args:
            action (Action): The type of action

        Returns:
            ValidationResult: validation result true or false with message
        """
        action_value = action.value
        if action_value not in [
            "generate"
        ]:
            return ValidationResult(
                success=False, message="Unsupported action provided."
            )

        return ValidationResult(
            success=True, message="Validation successful."
        )

    def _extract_field_from_event(
        self, key: str, event: dict, default, transformation=None
    ):
        """
        Extract field from event.

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
            if k not in event:
                return default
            if not isinstance(event, dict):
                return default
            event = event.get(k)
        if transformation and transformation == "string":
            return str(event)
        return event

    def _add_field(self, fields_dict: dict, field_name: str, value):
        """
        Add field to the extracted_fields dictionary.

        Args:
            fields_dict (dict): Field dictionary to update.
            field_name (str): Field name to add.
            value: Field to add.
        """
        # Skip empty dicts to prevent MongoDB errors
        if (isinstance(value, dict) or isinstance(value, list)) and not value:
            fields_dict[field_name] = None
            return

        if isinstance(value, int) or isinstance(value, float):
            fields_dict[field_name] = value
            return

        fields_dict[field_name] = value

    def _extract_entity_fields(self, event: dict, entity_fields: dict) -> dict:
        """Extract entity fields from event payload.

        Args:
            event (dict): Event Payload.
            entity_fields (dict): Entity fields.

        Returns:
            dict: Dictionary containing required fields.
        """
        extracted_fields = {}
        for field_name, field_value in entity_fields.items():
            key, default, transformation = (
                field_value.get("key"),
                field_value.get("default"),
                field_value.get("transformation"),
            )
            self._add_field(
                extracted_fields,
                field_name,
                self._extract_field_from_event(
                    key, event, default, transformation
                ),
            )

        if entity_fields == WORKLOADS_FIELDS:
            tags = extracted_fields.get("Tags", {})
            tags_list = []
            if tags:
                if isinstance(tags, dict):
                    tags_list = [f"{k}: {v}" for k, v in tags.items()]
                elif isinstance(tags, str):
                    tags_list = [tags.strip()]
                elif isinstance(tags, list):
                    tags_list = [str(tag) for tag in tags if tag]
                else:
                    tags_list = [str(tags)] if tags else []
            else:
                tags_list = []

            extracted_fields["Tags"] = tags_list

        if entity_fields == APPLICATION_FIELDS:
            creation_date = extracted_fields.get("Creation Date", "")
            if creation_date := self._parse_datetime(
                datetime_str=creation_date
            ):
                extracted_fields["Creation Date"] = creation_date

            first_seen = extracted_fields.get("First Seen", "")
            if first_seen := self._parse_datetime(
                datetime_str=first_seen
            ):
                extracted_fields["First Seen"] = first_seen

            last_seen = extracted_fields.get("Last Seen", "")
            if last_seen := self._parse_datetime(
                datetime_str=last_seen
            ):
                extracted_fields["Last Seen"] = last_seen

        return extracted_fields

    def _parse_datetime(
        self,
        datetime_str: str,
    ):
        """Parse datetime string into datetime object.

        Args:
            datetime_str (str): Datetime string to parse.

        Returns:
            datetime: Parsed datetime object.
        """
        try:
            return parser.parse(datetime_str)
        except Exception:
            return None

    def _get_storage(self) -> Dict:
        """Get storage object.

        Returns:
            Dict: Storage object.
        """
        storage = self.storage if self.storage is not None else {}
        return storage

    def get_access_token_and_storage(
        self, configuration: Dict, is_validation: bool = False
    ) -> Tuple[str, Dict]:
        """
        Get access token and storage.

        Args:
            configuration (Dict): Configuration.
            is_validation (bool, optional): Is validation. Defaults to False.

        Returns:
            Tuple[str, Dict]: Access token and storage.
        """
        storage = self._get_storage()
        auth_header = storage.get("auth_header")
        stored_config_hash = storage.get("config_hash")
        base_url, token_url, client_id, client_secret, *_ = (
            self.wiz_helper.get_config_params(
                configuration=configuration
            )
        )
        current_config_hash = self.wiz_helper.hash_string(
            string=f"{base_url}{token_url}{client_id}{client_secret}"
        )
        if auth_header and stored_config_hash == current_config_hash:
            return auth_header, storage
        else:
            auth_header = self.wiz_helper.get_auth_header(
                client_id=client_id,
                client_secret=client_secret,
                token_url=token_url,
                verify=self.ssl_validation,
                proxies=self.proxy,
                is_validation=is_validation,
            )
            storage.update(
                {
                    "auth_header": auth_header,
                    "config_hash": current_config_hash,
                }
            )
            return auth_header, storage

    def _fetch_workloads(
        self,
        api_endpoint_url: str,
        headers: dict,
        storage: dict,
        initial_range: int
    ) -> List:
        """Fetch workloads from Wiz.

        Args:
            api_endpoint_url (str): API Endpoint URL of Wiz.
            headers (dict): Headers for the API call.
            storage (dict): Storage object.
            initial_range (int): Initial range for data fetch.

        Returns:
            List: List of workloads.
        """
        if storage and storage.get("workloads_checkpoint"):
            start_time = storage.get("workloads_checkpoint")
            self.logger.info(
                f"{self.log_prefix}: Fetching {WORKLOADS_ENTITY_NAME} "
                f"from {start_time}."
            )
        else:
            start_time = datetime.now() - timedelta(days=initial_range)
            start_time = start_time.strftime(DATE_TIME_FORMAT)
            self.logger.info(
                f"{self.log_prefix}: This is initial data fetch since "
                f"checkpoint is empty. Fetching {WORKLOADS_ENTITY_NAME} "
                f"for last {initial_range} days."
            )

        total_workloads = []
        total_unique_workloads = set()
        skipped_vulnerability_ids = []
        page_count = 1
        total_skip_count = 0
        graphql_url = GRAPHQL_ENDPOINT.format(
            api_endpoint_url=api_endpoint_url
        )
        graphql_query = deepcopy(WORKLOADS_QUERY)
        graphql_query.update(
            {
                "variables": {
                    "first": PAGE_SIZE,
                    "filterBy": {
                        "updatedAt": {
                            "after": start_time
                        }
                    }
                }
            }
        )

        while True:
            try:
                logger_msg = (
                    f"{WORKLOADS_ENTITY_NAME} for page {page_count} "
                    f"from {PLATFORM_NAME} platform"
                )
                self.logger.debug(
                    f"{self.log_prefix}: Fetching {logger_msg}."
                )
                resp_json = self.wiz_helper.api_helper(
                    url=graphql_url,
                    method="POST",
                    json=graphql_query,
                    headers=headers,
                    storage=storage,
                    configuration=self.configuration,
                    proxies=self.proxy,
                    verify=self.ssl_validation,
                    logger_msg=f"fetching {logger_msg}"
                )

                if not (
                    isinstance(resp_json, dict)
                    and isinstance(data := resp_json.get("data"), dict)
                    and isinstance(findings := data.get("vulnerabilityFindings"), dict)
                    and isinstance(nodes := findings.get("nodes"), list)
                    and nodes
                ):
                    break

                curr_workloads_count = len(nodes)
                page_workloads_count = 0
                page_unique_workloads = set()
                page_skip_count = 0

                for workload in nodes:
                    try:
                        extracted_fields = self._extract_entity_fields(
                            event=workload, entity_fields=WORKLOADS_FIELDS
                        )
                        if extracted_fields:
                            page_unique_workloads.add(
                                extracted_fields.get("Workload ID")
                            )
                            total_workloads.append(extracted_fields)
                            page_workloads_count += 1
                        else:
                            page_skip_count += 1
                    except Exception:
                        vulnerability_id = workload.get(
                            "id", None
                        )
                        if vulnerability_id:
                            skipped_vulnerability_ids.append(vulnerability_id)
                        page_skip_count += 1

                total_unique_workloads.update(page_unique_workloads)
                if page_skip_count > 0:
                    self.logger.debug(
                        f"{self.log_prefix}: Skipped {page_skip_count} "
                        f"vulnerability record(s) in page {page_count}."
                    )

                self.logger.info(
                    f"{self.log_prefix}: Successfully fetched "
                    f"{len(page_unique_workloads)} unique "
                    f"{WORKLOADS_ENTITY_NAME} from "
                    f"{page_workloads_count} vulnerabilities "
                    f"in page {page_count}. "
                    f"Total unique {WORKLOADS_ENTITY_NAME} "
                    f"fetched: {len(total_unique_workloads)}."
                )

                page_count += 1
                total_skip_count += page_skip_count

                # Check for next page
                page_info = findings.get("pageInfo", {})
                if not page_info or not isinstance(page_info, dict):
                    break

                has_next_page = page_info.get("hasNextPage", False)
                if (
                    not has_next_page
                    or (curr_workloads_count < PAGE_SIZE)
                ):
                    break

                after_cursor = page_info.get("endCursor", "")
                graphql_query["variables"]["after"] = after_cursor

            except WizPluginException:
                raise
            except Exception as exp:
                err_msg = (
                    f"Unexpected error occurred while fetching "
                    f"{WORKLOADS_ENTITY_NAME} for page {page_count} from "
                    f"{PLATFORM_NAME} platform. Error: {exp}"
                )
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg}",
                    details=str(traceback.format_exc()),
                )
                raise WizPluginException(err_msg)

        if skipped_vulnerability_ids:
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Unable to extract fields "
                    f"from {len(skipped_vulnerability_ids)} vulnerability "
                    "record(s) as some error occurred while processing."
                ),
                details=str(skipped_vulnerability_ids),
            )

        logger_msg = (
            f"Successfully fetched "
            f"{len(total_unique_workloads)} unique "
            f"{WORKLOADS_ENTITY_NAME} from {len(total_workloads)} "
            f"vulnerabilities from {PLATFORM_NAME} platform"
        )

        if total_skip_count > 0:
            logger_msg += (
                f" and skipped {total_skip_count} "
                f"vulnerability record(s) because fields "
                "could not be extracted from the vulnerability record"
            )

        self.logger.info(
            f"{self.log_prefix}: {logger_msg}."
        )
        storage.update(
            {"workloads_checkpoint": datetime.now().strftime(DATE_TIME_FORMAT)}
        )
        return total_workloads

    def _fetch_applications(
        self,
        api_endpoint_url: str,
        headers: dict,
        storage: dict,
    ) -> List:
        """Fetch Applications from Wiz."""
        total_records = []
        skipped_application_ids = []
        skipped_records = 0
        page_count = 1

        graphql_url = GRAPHQL_ENDPOINT.format(
            api_endpoint_url=api_endpoint_url
        )
        graphql_query = deepcopy(GRAPHQL_QUERY)
        graphql_query.update(
            {
                "variables": {
                    "filterBy": {
                        "type": {
                            "equals": ["BUCKET"]
                        }
                    },
                    "first": PAGE_SIZE
                }
            }
        )
        while True:
            try:
                logger_msg = (
                    f"{APPLICATION_ENTITY_NAME} for page {page_count} "
                    f"from {PLATFORM_NAME} platform"
                )
                self.logger.debug(
                    f"{self.log_prefix}: Fetching {logger_msg}."
                )
                resp_json = self.wiz_helper.api_helper(
                    url=graphql_url,
                    method="POST",
                    json=graphql_query,
                    headers=headers,
                    storage=storage,
                    configuration=self.configuration,
                    proxies=self.proxy,
                    verify=self.ssl_validation,
                    logger_msg=f"fetching {logger_msg}"
                )

                if not (
                    isinstance(resp_json, dict)
                    and isinstance(data := resp_json.get("data"), dict)
                    and isinstance(cloudResourcesV2 := data.get("cloudResourcesV2"), dict)
                    and isinstance(nodes := cloudResourcesV2.get("nodes"), list)
                    and nodes
                ):
                    break

                current_app_count = len(nodes)
                page_app_count = 0
                page_app_skip_count = 0

                # We get all the app id and
                # store it in total app id list
                for each_app in nodes:
                    try:
                        extracted_fields = self._extract_entity_fields(
                            event=each_app,
                            entity_fields=APPLICATION_FIELDS
                        )
                        if extracted_fields:
                            total_records.append(extracted_fields)
                            page_app_count += 1
                        else:
                            page_app_skip_count += 1
                    except Exception:
                        application_id = each_app.get(
                            "id",
                            None
                        )
                        if application_id:
                            skipped_application_ids.append(application_id)
                        page_app_skip_count += 1

                if page_app_skip_count > 0:
                    self.logger.debug(
                        f"{self.log_prefix}: Skipped "
                        f"{page_app_skip_count} {APPLICATION_ENTITY_NAME} "
                        f"in page {page_count}."
                    )
                self.logger.info(
                    f"{self.log_prefix}: Successfully fetched "
                    f"{page_app_count} {APPLICATION_ENTITY_NAME} "
                    f"in page {page_count}. "
                    f"Total {APPLICATION_ENTITY_NAME} fetched: "
                    f"{len(total_records)}."
                )
                page_count += 1
                skipped_records += page_app_skip_count

                # if hasNextPage value in pageInfo is False then break
                page_info = cloudResourcesV2.get("pageInfo", {})
                if not page_info or not isinstance(page_info, dict):
                    break

                has_next_page = page_info.get("hasNextPage", False)
                if (
                    not has_next_page or
                    (current_app_count < PAGE_SIZE)
                ):
                    break

                after_cursor = page_info.get("endCursor", "")
                graphql_query["variables"]["after"] = after_cursor
            except WizPluginException:
                raise
            except Exception as exp:
                err_msg = (
                    "Unexpected error occurred "
                    f"while fetching {APPLICATION_ENTITY_NAME} for page "
                    f"{page_count} from {PLATFORM_NAME} platform. "
                    f"Error: {exp}"
                )
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg}",
                    details=str(traceback.format_exc()),
                )
                raise WizPluginException(err_msg)

        if skipped_application_ids:
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Unable to extract fields "
                    f"from {len(skipped_application_ids)} application "
                    "record(s) as some error occurred while processing."
                ),
                details=str(skipped_application_ids),
            )

        logger_msg = (
            f"Successfully fetched "
            f"{len(total_records)} {APPLICATION_ENTITY_NAME} record(s) "
            f"from {PLATFORM_NAME} platform"
        )
        if skipped_records > 0:
            logger_msg += (
                f" and skipped {skipped_records} "
                f"{APPLICATION_ENTITY_NAME} record(s) because fields "
                "could not be extracted from the application record"
            )
        self.logger.info(
            f"{self.log_prefix}: {logger_msg}."
        )
        return total_records

    def fetch_records(self, entity: str) -> List:
        """Pull Records from Wiz.

        Args:
            entity (str): Entity to be fetched.

        Returns:
            List: List of records to be stored on the platform.
        """
        entity_name = entity.lower()
        self.logger.debug(
            f"{self.log_prefix}: Fetching {entity_name} records from "
            f"{PLATFORM_NAME} platform."
        )

        (api_endpoint_url, *_, initial_range) = (
            self.wiz_helper.get_config_params(self.configuration)
        )

        headers, storage = self.get_access_token_and_storage(
            configuration=self.configuration,
            is_validation=False,
        )
        try:
            if entity == APPLICATION_ENTITY_NAME:
                applications_data = self._fetch_applications(
                    api_endpoint_url=api_endpoint_url,
                    headers=headers,
                    storage=storage
                )
                return applications_data
            elif entity == WORKLOADS_ENTITY_NAME:
                workloads_data = self._fetch_workloads(
                    api_endpoint_url=api_endpoint_url,
                    headers=headers,
                    storage=storage,
                    initial_range=initial_range
                )
                return workloads_data
            else:
                err_msg = (
                    f"Invalid entity found. {PLATFORM_NAME} plugin "
                    f"only supports '{APPLICATION_ENTITY_NAME}' and "
                    f"'{WORKLOADS_ENTITY_NAME}' Entities."
                )
                resolution = (
                    f"Ensure that the entity should be of "
                    f"'{APPLICATION_ENTITY_NAME}' and "
                    f"'{WORKLOADS_ENTITY_NAME}'."
                )
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg}",
                    resolution=resolution,
                )
                raise WizPluginException(err_msg)
        except WizPluginException:
            raise
        except Exception as exp:
            err_msg = (
                f"Unexpected error occurred while fetching {entity_name} "
                f"records from {PLATFORM_NAME}."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {exp}",
                details=str(traceback.format_exc()),
            )
            raise WizPluginException(err_msg)

    def update_records(self, entity: str, records: list[dict]) -> list[dict]:
        """Update records.

        Args:
            entity (str): Entity to be updated.
            records (list): Records to be updated.

        Returns:
            List: List of updated records.
        """
        return []

    def _validate_url(self, url: str) -> bool:
        """Validate the URL using parsing.

        Args:
            url (str): Given URL.

        Returns:
            bool: True or False { Valid or not Valid URL }.
        """
        parsed = urlparse(url)
        return parsed.scheme.strip() != "" and parsed.netloc.strip() != ""

    def _validate_parameters(
        self,
        field_name: str,
        field_value: Union[str, int, List, bool],
        field_type: Type,
        is_required: bool = True,
        max_value: int = None,
        min_value: int = None,
        allowed_values: List = None,
        custom_validation_func: Callable = None,
    ):
        """Validate the plugin configuration parameters.

        Args:
            field_name (str): Name of the field.
            field_value (Union[str, int, List]): Value of the field.
            field_type (Type): Type of the field.
            is_required (bool, optional): Whether the field is required.
                Defaults to True.
            max_value (int, optional): Maximum value for the configuration
                field. Defaults to None.
            min_value (int, optional): Minimum value for the configuration
                field. Defaults to None.
            allowed_values (List, optional): List of allowed values.
                Defaults to None.

        Returns:
            ValidationResult: ValidationResult object if validation fails,
                None otherwise.
        """
        validation_err_msg = "Validation error occurred."

        if field_type is str and isinstance(field_value, str):
            field_value = field_value.strip()

        if (
            is_required and
            not isinstance(field_value, int) and
            not field_value
        ):
            err_msg = f"'{field_name}' is a required configuration parameter."
            self.logger.error(
                message=f"{self.log_prefix}: {validation_err_msg} {err_msg}",
                resolution=(
                    f"Ensure that {field_name} value is provided in the "
                    "configuration parameters."
                ),
            )
            return ValidationResult(success=False, message=err_msg)

        if is_required and not isinstance(field_value, field_type):
            err_msg = (
                f"Invalid {field_name} value provided in the "
                "configuration parameters."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {validation_err_msg} {err_msg}",
                resolution=(
                    f"Ensure that valid value for {field_name} is "
                    "provided in the configuration parameters."
                ),
            )
            return ValidationResult(success=False, message=err_msg)

        if custom_validation_func and not custom_validation_func(field_value):
            err_msg = (
                f"Invalid {field_name} value provided in the "
                "configuration parameters."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {validation_err_msg} {err_msg}",
                resolution=(
                    f"Ensure that valid value for {field_name} is "
                    "provided in the configuration parameters."
                ),
            )
            return ValidationResult(success=False, message=err_msg)

        if allowed_values:
            allowed_values_str = ", ".join(allowed_values)
            # For list type, check if all values are in allowed_values
            if field_type is list:
                invalid_values = [
                    v for v in field_value if v not in allowed_values
                ]
                if invalid_values:
                    err_msg = (
                        f"Invalid {field_name} value(s) provided. "
                        f"Allowed values are: {allowed_values_str}."
                    )
                    self.logger.error(
                        message=(
                            f"{self.log_prefix}: "
                            f"{validation_err_msg} {err_msg}"
                        ),
                        resolution=(
                            f"Ensure that valid value for {field_name} is "
                            "provided in the configuration parameters "
                            f"and it should be one of {allowed_values_str}."
                        ),
                    )
                    return ValidationResult(success=False, message=err_msg)
            elif field_value not in allowed_values:
                err_msg = (
                    f"Invalid {field_name} value provided. "
                    f"Allowed values are: {allowed_values_str}."
                )
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: "
                        f"{validation_err_msg} {err_msg}"
                    ),
                    resolution=(
                        f"Ensure that valid value for {field_name} is "
                        "provided in the configuration parameters "
                        f"and it should be one of {allowed_values_str}."
                    ),
                )
                return ValidationResult(success=False, message=err_msg)

        if max_value is not None and min_value is not None and field_value:
            if min_value > field_value or max_value < field_value:
                if max_value == INTEGER_THRESHOLD:
                    max_value = "2^62"
                err_msg = (
                    f"Invalid value provided for the configuration "
                    f"parameter '{field_name}'. Valid value should be "
                    f"an integer greater than {min_value} and "
                    f"less than {max_value}."
                )
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: {validation_err_msg}{err_msg}"
                    ),
                    resolution=(
                        f"Ensure that a valid value greater than "
                        f" {min_value} and less than {max_value} "
                        f"is provided for the configuration "
                        f"parameter '{field_name}'."
                    )
                )
                return ValidationResult(
                    success=False,
                    message=err_msg,
                )

    def validate(self, configuration):
        """Validate the Plugin configuration parameters.

        Args:
            configuration (dict): Contains the below keys:
            client_id (str): Client ID required to generate OAUTH2 token.
            client_secret (str): Client Secret required to generate OAUTH2
                                token.
            api_endpoint_url (str): API Endpoint URLof Wiz.
            token_url (str): Token URL of Wiz.
            wiz_tables (list): List of Wiz tables to fetch data from.

        Returns:
            ValidateResult: ValidateResult object with success flag and
                            message.
        """
        # Validate API Endpoint URL
        api_endpoint_url = configuration.get("base_url", "").strip().strip("/")
        if validation_failure := self._validate_parameters(
            field_name="API Endpoint URL",
            field_value=api_endpoint_url,
            field_type=str,
            custom_validation_func=self._validate_url,
        ):
            return validation_failure

        # Validate Token URL
        token_url = configuration.get("token_url", "").strip().strip("/")
        if validation_failure := self._validate_parameters(
            field_name="Token URL",
            field_value=token_url,
            field_type=str,
            custom_validation_func=self._validate_url,
        ):
            return validation_failure

        # Validate Client ID
        client_id = configuration.get("client_id", "").strip()
        if validation_failure := self._validate_parameters(
            field_name="Client ID",
            field_value=client_id,
            field_type=str,
        ):
            return validation_failure

        # Validate Client Secret
        client_secret = configuration.get("client_secret", "")
        if validation_failure := self._validate_parameters(
            field_name="Client Secret",
            field_value=client_secret,
            field_type=str,
        ):
            return validation_failure

        # Validate Wiz Tables
        wiz_tables = configuration.get("wiz_tables", [])
        allowed_wiz_tables = [
            "applications",
            "workloads",
        ]
        if validation_failure := self._validate_parameters(
            field_name="Wiz Tables",
            field_value=wiz_tables,
            field_type=list,
            allowed_values=allowed_wiz_tables,
        ):
            return validation_failure

        # Validate Initial range
        initial_range = configuration.get("initial_range")
        if validation_result := self._validate_parameters(
            field_name="Initial Range (in days)",
            field_value=initial_range,
            field_type=int,
            is_required=False,
            min_value=0,
            max_value=INTEGER_THRESHOLD,
        ):
            return validation_result

        if "workloads" in wiz_tables and initial_range is None:
            err_msg = (
                "Initial Range is required when 'Workloads' is selected "
                "in the 'Wiz Tables' field."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                resolution=(
                    "Ensure that the 'Initial Range (in days)' value is "
                    "provided in the configuration parameters when "
                    "'Workloads' is selected in the "
                    "'Wiz Tables' field."
                ),
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )

        return self._validate_auth_params(configuration)

    def _validate_auth_params(self, configuration: dict) -> ValidationResult:
        """Validate the authentication params with Wiz platform.

        Args:
            configuration (dict): Configuration parameters dictionary.

        Returns:
            ValidationResult: ValidationResult object having validation
            results after making an API call.
        """
        try:
            self.logger.debug(
                f"{self.log_prefix}: Validating authentication credentials."
            )
            (api_endpoint_url, *_) = (
                self.wiz_helper.get_config_params(configuration)
            )

            wiz_tables = configuration.get("wiz_tables", [])
            validation_logger = (
                "checking connectivity for {wiz_tables} table "
                f"on {PLATFORM_NAME} platform"
            )

            headers, storage = self.get_access_token_and_storage(
                configuration=configuration,
                is_validation=True,
            )

            graphql_url = GRAPHQL_ENDPOINT.format(
                api_endpoint_url=api_endpoint_url
            )

            if "applications" in wiz_tables:
                graphql_query = deepcopy(GRAPHQL_QUERY)
                graphql_query.update(
                    {
                        "variables": {
                            "filterBy": {
                                "type": {
                                    "equals": ["BUCKET"]
                                }
                            },
                            "first": 1
                        }
                    }
                )

                self.wiz_helper.api_helper(
                    url=graphql_url,
                    method="POST",
                    headers=headers,
                    json=graphql_query,
                    proxies=self.proxy,
                    verify=self.ssl_validation,
                    configuration=configuration,
                    storage=storage,
                    logger_msg=validation_logger.format(
                        wiz_tables=APPLICATION_ENTITY_NAME,
                    ),
                    is_validation=True,
                )

            if "workloads" in wiz_tables:
                graphql_query = deepcopy(WORKLOADS_QUERY)
                graphql_query.update({"variables": {"first": 1}})

                self.wiz_helper.api_helper(
                    url=graphql_url,
                    method="POST",
                    headers=headers,
                    json=graphql_query,
                    proxies=self.proxy,
                    verify=self.ssl_validation,
                    configuration=configuration,
                    storage=storage,
                    logger_msg=validation_logger.format(
                        wiz_tables=WORKLOADS_ENTITY_NAME,
                    ),
                    is_validation=True,
                )

            logger_msg = (
                "Successfully validated "
                f"connectivity with {PLATFORM_NAME} server "
                "and plugin configuration parameters."
            )
            self.logger.debug(
                f"{self.log_prefix}: {logger_msg}"
            )
            return ValidationResult(
                success=True,
                message=logger_msg,
            )

        except WizPluginException as exp:
            err_msg = f"Validation error occurred. Error: {exp}"
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=str(traceback.format_exc()),
            )
            return ValidationResult(
                success=False,
                message=f"{str(exp)} Check logs for more details."
            )
        except Exception as exp:
            err_msg = "Unexpected validation error occurred."
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {exp}",
                details=str(traceback.format_exc()),
            )
            return ValidationResult(
                success=False,
                message=f"{err_msg} Check logs for more details.",
            )

    def get_entities(self) -> list[Entity]:
        """Get available entities."""
        wiz_entities = []
        wiz_tables = self.configuration.get("wiz_tables", [])
        if "applications" in wiz_tables:
            wiz_entities.append(
                self._create_entity(
                    name=APPLICATION_ENTITY_NAME,
                    label=APPLICATION_ENTITY_NAME,
                    fields=[
                        self._create_entity_field(
                            name="Application ID",
                            label="Application ID",
                            type=EntityFieldType.STRING,
                            required=True
                        ),
                        self._create_entity_field(
                            name="Subscription External ID",
                            label="Subscription External ID",
                            type=EntityFieldType.STRING
                        ),
                        self._create_entity_field(
                            name="Subscription ID",
                            label="Subscription ID",
                            type=EntityFieldType.STRING
                        ),
                        self._create_entity_field(
                            name="Application Name",
                            label="Application Name",
                            type=EntityFieldType.STRING
                        ),
                        self._create_entity_field(
                            name="Cloud Platform",
                            label="Cloud Platform",
                            type=EntityFieldType.STRING
                        ),
                        self._create_entity_field(
                            name="Cloud Provider URL",
                            label="Cloud Provider URL",
                            type=EntityFieldType.STRING
                        ),
                        self._create_entity_field(
                            name="Creation Date",
                            label="Creation Date",
                            type=EntityFieldType.DATETIME
                        ),
                        self._create_entity_field(
                            name="First Seen",
                            label="First Seen",
                            type=EntityFieldType.DATETIME
                        ),
                        self._create_entity_field(
                            name="Last Seen",
                            label="Last Seen",
                            type=EntityFieldType.DATETIME
                        ),
                    ],
                )
            )

        if "workloads" in wiz_tables:
            wiz_entities.append(
                self._create_entity(
                    name=WORKLOADS_ENTITY_NAME,
                    label=WORKLOADS_ENTITY_NAME,
                    fields=[
                        self._create_entity_field(
                            name="Workload ID",
                            label="Workload ID",
                            type=EntityFieldType.STRING,
                            required=True
                        ),
                        self._create_entity_field(
                            name="IP Addresses",
                            label="IP Addresses",
                            type=EntityFieldType.LIST,
                        ),
                        self._create_entity_field(
                            name="Type",
                            label="Type",
                            type=EntityFieldType.STRING,
                        ),
                        self._create_entity_field(
                            name="Name",
                            label="Name",
                            type=EntityFieldType.STRING,
                        ),
                        self._create_entity_field(
                            name="Region",
                            label="Region",
                            type=EntityFieldType.STRING,
                        ),
                        self._create_entity_field(
                            name="Cloud Platform",
                            label="Cloud Platform",
                            type=EntityFieldType.STRING,
                        ),
                        self._create_entity_field(
                            name="Cloud Provider URL",
                            label="Cloud Provider URL",
                            type=EntityFieldType.STRING,
                        ),
                        self._create_entity_field(
                            name="Status",
                            label="Status",
                            type=EntityFieldType.STRING,
                        ),
                        self._create_entity_field(
                            name="Subscription Name",
                            label="Subscription Name",
                            type=EntityFieldType.STRING,
                        ),
                        self._create_entity_field(
                            name="Subscription External ID",
                            label="Subscription External ID",
                            type=EntityFieldType.STRING,
                        ),
                        self._create_entity_field(
                            name="Subscription ID",
                            label="Subscription ID",
                            type=EntityFieldType.STRING,
                        ),
                        self._create_entity_field(
                            name="OS",
                            label="OS",
                            type=EntityFieldType.STRING,
                        ),
                        self._create_entity_field(
                            name="Tags",
                            label="Tags",
                            type=EntityFieldType.LIST,
                        ),
                        self._create_entity_field(
                            name="Vulnerability Name",
                            label="Vulnerability Name",
                            type=EntityFieldType.STRING,
                        ),
                        self._create_entity_field(
                            name="CVSS Severity",
                            label="CVSS Severity",
                            type=EntityFieldType.STRING,
                        ),
                        self._create_entity_field(
                            name="Vulnerability Score",
                            label="Vulnerability Score",
                            type=EntityFieldType.NUMBER,
                        ),
                        self._create_entity_field(
                            name="Exploitability Score",
                            label="Exploitability Score",
                            type=EntityFieldType.NUMBER,
                        ),
                        self._create_entity_field(
                            name="Severity",
                            label="Severity",
                            type=EntityFieldType.STRING,
                        ),
                        self._create_entity_field(
                            name="Impact Score",
                            label="Impact Score",
                            type=EntityFieldType.NUMBER,
                        ),
                        self._create_entity_field(
                            name="Vulnerability Status",
                            label="Vulnerability Status",
                            type=EntityFieldType.STRING,
                        ),
                        self._create_entity_field(
                            name="EPSS Severity",
                            label="EPSS Severity",
                            type=EntityFieldType.STRING,
                        ),
                        self._create_entity_field(
                            name="EPSS Percentile",
                            label="EPSS Percentile",
                            type=EntityFieldType.NUMBER,
                        ),
                        self._create_entity_field(
                            name="EPSS Probability",
                            label="EPSS Probability",
                            type=EntityFieldType.NUMBER,
                        ),
                        self._create_entity_field(
                            name="CNA Score",
                            label="CNA Score",
                            type=EntityFieldType.NUMBER,
                        )
                    ],
                )
            )

        return wiz_entities
