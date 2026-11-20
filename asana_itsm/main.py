"""
BSD 3-Clause License

Copyright (c) 2021, Netskope OSS
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice,
   this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its contributors
   may be used to endorse or promote products derived from this software
   without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
POSSIBILITY OF SUCH DAMAGE.

Asana CTO plugin for Netskope Cloud Exchange.
"""

import traceback
from typing import Dict, List, Optional, Tuple, Union

from netskope.integrations.itsm.models import (
    Alert,
    CustomFieldMapping,
    CustomFieldsSectionWithMappings,
    Event,
    FieldMapping,
    Queue,
    Severity,
    Task,
    TaskStatus,
    UpdatedTaskValues,
)
from netskope.integrations.itsm.plugin_base import (
    MappingField,
    PluginBase,
    ValidationResult,
)

from .utils import constants as CONST
from .utils.custom_fields import (
    build_mapping_field_labels,
    build_project_field_index,
    convert_value,
    describe_field,
    find_named_fields,
    truncate_comment,
)
from .utils.exceptions import (
    AsanaMappingException,
    AsanaPluginException,
)
from .utils.helper import AsanaPluginHelper


class AsanaPlugin(PluginBase):
    """Asana CTO plugin.

    Creates Asana tasks from Netskope alerts and events in the project
    selected as the queue, updates them, adds deduplication comments and
    syncs their status, severity and assignee back to Cloud Exchange.
    """

    def __init__(self, name: str, *args, **kwargs) -> None:
        """Initialize the plugin.

        Args:
            name (str): Configuration name.
        """
        super().__init__(name, *args, **kwargs)
        self.plugin_name, self.plugin_version = self._get_plugin_info()
        self.log_prefix = f"{CONST.MODULE_NAME} {self.plugin_name}"
        if name:
            self.log_prefix = f"{self.log_prefix} [{name}]"
        self.asana_helper = AsanaPluginHelper(
            logger=self.logger,
            log_prefix=self.log_prefix,
            plugin_name=self.plugin_name,
            plugin_version=self.plugin_version,
            ssl_validation=self.ssl_validation,
            proxy=self.proxy,
        )
        # Custom field dictionaries of the queue projects, keyed by project
        # gid. Kept in memory only, so a field changed in Asana is read
        # again by the next plugin instance.
        self._project_fields: Dict[str, Tuple[Dict, Dict]] = {}
        # Names of the workspace custom fields, read once for error messages.
        self._field_names: Optional[Dict[str, str]] = None

    def _get_plugin_info(self) -> Tuple[str, str]:
        """Return the plugin name and version from the manifest.

        Returns:
            Tuple[str, str]: (plugin name, plugin version).
        """
        try:
            manifest_json = AsanaPlugin.metadata
            plugin_name = manifest_json.get("name", CONST.PLATFORM_NAME)
            plugin_version = manifest_json.get("version", CONST.PLUGIN_VERSION)
            return plugin_name, plugin_version
        except Exception as exp:
            self.logger.error(
                message=(
                    f"{CONST.MODULE_NAME} {CONST.PLATFORM_NAME}: Error"
                    f" occurred while getting plugin details. Error: {exp}"
                ),
                details=traceback.format_exc(),
            )
        return CONST.PLATFORM_NAME, CONST.PLUGIN_VERSION

    # ------------------------------------------------------------------
    # Common helpers
    # ------------------------------------------------------------------

    def _get_connection(
        self, configuration: Optional[Dict] = None
    ) -> Tuple[str, Dict]:
        """Return the API Base URL and the request headers.

        Args:
            configuration (Optional[Dict]): Plugin configuration; the saved
                configuration is used when omitted.

        Returns:
            Tuple[str, Dict]: (base_url, headers).
        """
        base_url, token = self.asana_helper.get_auth_params(
            {"auth": self._get_config_params(configuration, "auth")}
        )
        return base_url, self.asana_helper.get_headers(token)

    def _get_config_params(
        self, configuration: Optional[Dict] = None, step: str = "auth"
    ) -> Dict:
        """Return the parameters of a configuration step.

        Args:
            configuration (Optional[Dict]): Plugin configuration; the saved
                configuration is used when omitted.
            step (str): "auth", "params" or another top-level key of the
                configuration, for example "mapping_config".

        Returns:
            Dict: Parameters of the step; empty when it is missing.
        """
        return self.asana_helper.get_config_params(
            self.configuration if configuration is None else configuration,
            step,
        )

    def _get_workspace_gid(self, configuration: Optional[Dict] = None) -> str:
        """Return the workspace gid saved in the Configuration Parameters.

        Args:
            configuration (Optional[Dict]): Plugin configuration; the saved
                configuration is used when omitted.

        Returns:
            str: Workspace gid, or an empty string.
        """
        params = self._get_config_params(configuration, "params")
        return str(params.get("workspace") or "").strip()

    # ------------------------------------------------------------------
    # Validation
    # ------------------------------------------------------------------

    def validate_step(
        self, name: str, configuration: Dict
    ) -> ValidationResult:
        """Validate one configuration step.

        Args:
            name (str): Step name ("auth" or "params").
            configuration (Dict): Plugin configuration.

        Returns:
            ValidationResult: Validation result.
        """
        if name == "auth":
            return self._validate_auth(configuration)
        if name == "params":
            return self._validate_params(configuration)
        return ValidationResult(success=True, message="Validation successful.")

    def _validation_error(self, message: str) -> ValidationResult:
        """Log a validation error and return the failed result.

        Args:
            message (str): Message shown in the configuration screen.

        Returns:
            ValidationResult: Failed validation result.
        """
        self.logger.error(
            message=(
                f"{self.log_prefix}: Error occurred while validating the"
                f" configuration parameters. {message}"
            ),
            resolution=(
                "Ensure that the configuration parameters are provided"
                " and valid."
            ),
        )
        return ValidationResult(success=False, message=message)

    def _validate_auth(self, configuration: Dict) -> ValidationResult:
        """Validate the Authentication step.

        Args:
            configuration (Dict): Plugin configuration.

        Returns:
            ValidationResult: Validation result.
        """
        auth = self._get_config_params(configuration, "auth")
        base_url = auth.get("base_url")
        if base_url is None or (
            isinstance(base_url, str) and not base_url.strip()
        ):
            return self._validation_error(
                "API Base URL is a required configuration parameter."
            )
        if not isinstance(base_url, str) or not self.asana_helper.validate_url(
            base_url.strip()
        ):
            return self._validation_error(
                "Invalid API Base URL provided in the configuration"
                " parameters."
            )
        token = auth.get("token")
        if not token:
            return self._validation_error(
                "Token is a required configuration parameter."
            )
        if not isinstance(token, str):
            return self._validation_error(
                "Invalid Token provided in the configuration parameters."
            )
        return self._validate_connectivity(configuration)

    def _validate_connectivity(self, configuration: Dict) -> ValidationResult:
        """Validate the credentials with GET /users/me.

        Args:
            configuration (Dict): Plugin configuration.

        Returns:
            ValidationResult: Validation result.
        """
        base_url, headers = self._get_connection(configuration)
        logger_msg = "validating the authentication parameters with Asana"
        try:
            response = self.asana_helper.api_helper(
                logger_msg=logger_msg,
                url=f"{base_url}{CONST.USERS_ME_ENDPOINT}",
                method="GET",
                headers=headers,
                params={"opt_fields": CONST.USERS_ME_OPT_FIELDS, "limit": 1},
                is_validation=True,
            )
        except AsanaPluginException as exp:
            return ValidationResult(success=False, message=str(exp))
        except Exception as exp:
            self.asana_helper.log_unexpected_error(logger_msg, exp)
            return ValidationResult(
                success=False,
                message=(
                    f"Error occurred while {logger_msg}. Check"
                    " logs for more details."
                ),
            )
        user = response.get("data") if isinstance(response, dict) else None
        if not isinstance(user, dict) or not user.get("gid"):
            return self._validation_error(
                CONST.VALIDATION_INVALID_RESPONSE_MESSAGE
            )
        self.logger.debug(
            f"{self.log_prefix}: Validation completed successfully."
        )
        return ValidationResult(
            success=True, message=CONST.VALIDATION_SUCCESS_MESSAGE
        )

    def _validate_params(self, configuration: Dict) -> ValidationResult:
        """Validate the Configuration Parameters step.

        Args:
            configuration (Dict): Plugin configuration.

        Returns:
            ValidationResult: Validation result.
        """
        workspace = self._get_config_params(configuration, "params").get(
            "workspace"
        )
        if workspace is None or (
            isinstance(workspace, str) and not workspace.strip()
        ):
            return self._validation_error(
                "Workspace is a required configuration parameter."
            )
        if not isinstance(workspace, str):
            return self._validation_error(
                "Invalid Workspace provided in the configuration"
                " parameters. Select a Workspace from the list."
            )
        workspace_gid = workspace.strip()
        try:
            base_url, headers = self._get_connection(configuration)
            workspaces = self.asana_helper.fetch_workspaces(
                base_url, headers, is_validation=True
            )
        except AsanaPluginException as exp:
            return ValidationResult(success=False, message=str(exp))
        except Exception as exp:
            logger_msg = f"fetching workspaces from {CONST.PLATFORM_NAME}"
            self.asana_helper.log_unexpected_error(logger_msg, exp)
            return ValidationResult(
                success=False,
                message=(
                    f"Error occurred while {logger_msg}. Check"
                    " logs for more details."
                ),
            )
        if workspace_gid not in {ws.get("gid") for ws in workspaces}:
            return self._validation_error(
                "Invalid Workspace provided in the configuration"
                " parameters. Select a Workspace from the list."
            )
        field_result = self._validate_field_names(
            configuration, workspace_gid
        )
        if field_result:
            return field_result
        self.logger.debug(
            f"{self.log_prefix}: Validation completed successfully."
        )
        return ValidationResult(
            success=True,
            message="Successfully validated the configuration parameters.",
        )

    def _validate_field_names(
        self, configuration: Dict, workspace_gid: str
    ) -> Optional[ValidationResult]:
        """Validate the Status Field Name and Severity Field Name.

        Every custom field of the workspace is read (all pages) and each
        provided name must match the name of one of them exactly.

        Args:
            configuration (Dict): Plugin configuration.
            workspace_gid (str): Selected workspace gid.

        Returns:
            Optional[ValidationResult]: Failed result, or None when the
                names are valid.
        """
        params = self._get_config_params(configuration, "params")
        names = {}
        for key, label in (
            (CONST.STATUS_FIELD_KEY, "Status Field Name"),
            (CONST.SEVERITY_FIELD_KEY, "Severity Field Name"),
        ):
            value = params.get(key)
            if value is None:
                continue
            if not isinstance(value, str):
                return self._validation_error(
                    f"Invalid {label} provided in the configuration"
                    " parameters. Provide the name of an Asana custom field."
                )
            if value.strip():
                names[label] = value.strip()
        if not names:
            return None
        logger_msg = f"fetching custom fields from {CONST.PLATFORM_NAME}"
        try:
            base_url, headers = self._get_connection(configuration)
            custom_fields = self.asana_helper.fetch_workspace_custom_fields(
                base_url, headers, workspace_gid, is_validation=True
            )
        except AsanaPluginException as exp:
            return ValidationResult(success=False, message=str(exp))
        except Exception as exp:
            self.asana_helper.log_unexpected_error(logger_msg, exp)
            return ValidationResult(
                success=False,
                message=(
                    f"Error occurred while {logger_msg}. Check"
                    " logs for more details."
                ),
            )
        for label, name in names.items():
            if not find_named_fields(custom_fields, name):
                return self._validation_error(
                    f"Invalid {label} provided in the configuration"
                    f" parameters. Custom field '{name}' was not found in"
                    " the selected Asana workspace. Provide the exact name"
                    " of the field, including its case."
                )
        return None

    def _get_named_field(self, key: str) -> str:
        """Return the name of the Status or Severity field.

        Args:
            key (str): Configuration Parameter of the field name.

        Returns:
            str: Trimmed field name; empty when it is not provided.
        """
        value = self._get_config_params(step="params").get(key)
        return value.strip() if isinstance(value, str) else ""

    # ------------------------------------------------------------------
    # Dynamic configuration
    # ------------------------------------------------------------------

    def get_fields(self, name: str, configuration: Dict) -> List[Dict]:
        """Return the fields of a dynamic configuration step.

        For "params" the Workspace dropdown is fetched live from Asana
        with the credentials of the Authentication step.

        Args:
            name (str): Step name.
            configuration (Dict): Plugin configuration.

        Returns:
            List[Dict]: Field definitions; empty when the user has no
                workspace.

        Raises:
            AsanaPluginException: When the workspaces cannot be fetched, so
                that Cloud Exchange shows an error instead of an empty step.
        """
        if name != "params":
            return []
        try:
            base_url, headers = self._get_connection(configuration)
            workspaces = self.asana_helper.fetch_workspaces(
                base_url, headers
            )
        except AsanaPluginException:
            raise
        except Exception as exp:
            raise self.asana_helper.log_unexpected_error(
                f"fetching workspaces from {CONST.PLATFORM_NAME}", exp
            )
        if not workspaces:
            self.logger.info(
                f"{self.log_prefix}: No workspaces found on"
                f" {CONST.PLATFORM_NAME} for the user of the Token."
            )
            return []
        choices = [
            {"key": str(ws.get("name")), "value": str(ws.get("gid"))}
            for ws in workspaces
        ]
        self.logger.info(
            f"{self.log_prefix}: Successfully fetched {len(choices)}"
            f" workspace(s) from {CONST.PLATFORM_NAME}."
        )
        saved_gid = self._get_workspace_gid(configuration)
        valid_gids = {choice["value"] for choice in choices}
        default = saved_gid if saved_gid in valid_gids else choices[0]["value"]
        params = self._get_config_params(configuration, "params")
        status_field = params.get(CONST.STATUS_FIELD_KEY)
        severity_field = params.get(CONST.SEVERITY_FIELD_KEY)
        return [
            {
                "label": "Workspace",
                "key": "workspace",
                "type": "choice",
                "choices": choices,
                "default": default,
                "mandatory": True,
                "description": (
                    "Select the Asana workspace that contains the projects."
                    " The list is fetched live from Asana instance."
                    " You can see your workspaces from the profile photo"
                    " menu at the bottom left of Asana."
                ),
            },
            {
                "label": "Status Field Name",
                "key": CONST.STATUS_FIELD_KEY,
                "type": "text",
                "default": (
                    status_field if isinstance(status_field, str) else ""
                ),
                "mandatory": False,
                "placeholder": "e.g. Status",
                "description": (
                    "Exact name of the Asana custom field that holds the"
                    " task status. Used to sync the status to Cloud"
                    " Exchange. If empty, the status will not be synced."
                ),
            },
            {
                "label": "Severity Field Name",
                "key": CONST.SEVERITY_FIELD_KEY,
                "type": "text",
                "default": (
                    severity_field if isinstance(severity_field, str) else ""
                ),
                "mandatory": False,
                "placeholder": "e.g. Severity",
                "description": (
                    "Exact name of the Asana custom field that holds the"
                    " task severity. Used to sync the severity to Cloud"
                    " Exchange. If empty, the severity will not be synced."
                ),
            },
        ]

    # ------------------------------------------------------------------
    # Mapping configuration
    # ------------------------------------------------------------------

    @staticmethod
    def _get_static_fields() -> List[MappingField]:
        """Return the mapping fields that exist for every project.

        Returns:
            List[MappingField]: Name, Notes, Assignee and Text. The project
                is not a mapping field: it is the project selected as the
                queue.
        """
        return [
            MappingField(
                label="Name", value=CONST.NAME_FIELD, updateAble=False
            ),
            MappingField(
                label="Notes", value=CONST.NOTES_FIELD, updateAble=False
            ),
            MappingField(
                label="Assignee", value=CONST.ASSIGNEE_FIELD, updateAble=False
            ),
            # Only the comment is written when a duplicate is found (the
            # dedup mapping), so only Text can be mapped there.
            MappingField(
                label="Text", value=CONST.COMMENT_FIELD, updateAble=True
            ),
        ]

    def get_available_fields(self, configuration: Dict) -> List[MappingField]:
        """Return the fields available in the queue mapping.

        The static fields are always returned. The writable custom fields
        of the configured workspace are added; when the selected queue
        project does not contain a mapped field, create_task and
        update_task raise an error before any write.

        Args:
            configuration (Dict): Plugin configuration.

        Returns:
            List[MappingField]: Mapping fields.
        """
        fields = self._get_static_fields()
        workspace_gid = self._get_workspace_gid(configuration)
        if not workspace_gid:
            return fields
        logger_msg = f"fetching custom fields from {CONST.PLATFORM_NAME}"
        try:
            base_url, headers = self._get_connection(configuration)
            custom_fields = self.asana_helper.fetch_workspace_custom_fields(
                base_url, headers, workspace_gid
            )
        except AsanaPluginException:
            return fields
        except Exception as exp:
            self.asana_helper.log_unexpected_error(logger_msg, exp)
            return fields
        labels = build_mapping_field_labels(custom_fields)
        fields.extend(
            MappingField(label=label, value=key, updateAble=False)
            for label, key in labels
        )
        self.logger.info(
            f"{self.log_prefix}: Successfully fetched {len(labels)} custom"
            f" field(s) from {CONST.PLATFORM_NAME} for the queue mapping."
        )
        return fields

    def get_default_mappings(
        self, configuration: Dict
    ) -> Dict[str, List[FieldMapping]]:
        """Return the default mappings of a new queue.

        Args:
            configuration (Dict): Plugin configuration.

        Returns:
            Dict[str, List[FieldMapping]]: "mappings" used by create_task and
                "dedup" used by update_task.
        """
        return {
            "mappings": [
                FieldMapping(
                    extracted_field="custom_message",
                    destination_field=CONST.NAME_FIELD,
                    custom_message=(
                        "Netskope $appCategory alert name: $alertName,"
                        " Event Name: $alert_name"
                    ),
                ),
                FieldMapping(
                    extracted_field="custom_message",
                    destination_field=CONST.NOTES_FIELD,
                    custom_message=(
                        "Alert/Event ID: $id\nAlert/Event App: $app\n"
                        "Alert/Event User: $user\n\n"
                        "Alert Name: $alertName\nAlert Type: $alertType\n"
                        "Alert App Category: $appCategory\n\n"
                        "Event Name: $alert_name\nEvent Type: $eventType"
                    ),
                ),
            ],
            "dedup": [
                FieldMapping(
                    extracted_field="custom_message",
                    destination_field=CONST.COMMENT_FIELD,
                    custom_message=(
                        "Received new alert/event with Alert/Event ID: $id"
                        " and Alert Name: $alertName, Event Name:"
                        " $alert_name in Cloud Exchange."
                    ),
                ),
            ],
        }

    def get_default_custom_mappings(
        self,
    ) -> List[CustomFieldsSectionWithMappings]:
        """Return the default Status and Severity mappings.

        The Asana values are option names of the Status and Severity custom
        fields. Users can change them in the CE Mapping Configuration.

        Returns:
            List[CustomFieldsSectionWithMappings]: Status and Severity
                sections.
        """
        status_values = [
            ("New", "New"),
            ("In Progress", "In Progress"),
            ("On Hold", "On Hold"),
            ("Closed", "Closed"),
            ("Deleted", ""),
            ("Other", "other"),
        ]
        severity_values = [
            ("Critical", "Critical"),
            ("High", "High"),
            ("Medium", "Medium"),
            ("Low", "Low"),
            ("Informational", ""),
            ("Other", "other"),
        ]
        return [
            CustomFieldsSectionWithMappings(
                section=section,
                event_field=section,
                destination_label=CONST.PLATFORM_NAME,
                field_mappings=[
                    CustomFieldMapping(
                        name=name, mapped_value=value, is_default=True
                    )
                    for name, value in values
                ],
            )
            for section, values in (
                ("status", status_values),
                ("severity", severity_values),
            )
        ]

    # ------------------------------------------------------------------
    # Queues
    # ------------------------------------------------------------------

    def get_queues(self) -> List[Queue]:
        """Return the projects of the configured workspace as queues.

        Returns:
            List[Queue]: Queues sorted by project name, then gid; empty when
                the projects cannot be fetched.
        """
        workspace_gid = self._get_workspace_gid()
        logger_msg = f"fetching projects as queues from {CONST.PLATFORM_NAME}"
        if not workspace_gid:
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Error occurred while {logger_msg}."
                    " No Workspace is configured."
                ),
                resolution=(
                    "Ensure that a Workspace is selected in the"
                    " Configuration Parameters of the plugin."
                ),
            )
            return []
        base_url, headers = self._get_connection()
        endpoint = CONST.WORKSPACE_PROJECTS_ENDPOINT.format(
            workspace_gid=workspace_gid
        )
        try:
            projects = self.asana_helper.paginate(
                logger_msg=logger_msg,
                url=f"{base_url}{endpoint}",
                headers=headers,
                params={
                    "archived": "false",
                    "opt_fields": CONST.PROJECTS_OPT_FIELDS,
                },
            )
        except AsanaPluginException:
            return []
        except Exception as exp:
            self.asana_helper.log_unexpected_error(logger_msg, exp)
            return []
        queues = [
            Queue(
                label=str(project.get("name")),
                value=str(project.get("gid")),
            )
            for project in projects
            if isinstance(project, dict)
            and project.get("gid")
            and project.get("name")
        ]
        queues.sort(key=lambda queue: (queue.label.lower(), queue.value))
        self.logger.info(
            f"{self.log_prefix}: Successfully fetched {len(queues)}"
            f" project(s) as queues from {CONST.PLATFORM_NAME}."
        )
        return queues

    # ------------------------------------------------------------------
    # Custom field values
    # ------------------------------------------------------------------

    def _get_project_fields(self, project_gid: str) -> Tuple[Dict, Dict]:
        """Return the custom field dictionaries of a project.

        Args:
            project_gid (str): Project gid of the queue.

        Returns:
            Tuple[Dict, Dict]: Fields keyed by gid, and the lower-case name
                mapped to the gids with that name.
        """
        if project_gid not in self._project_fields:
            base_url, headers = self._get_connection()
            endpoint = CONST.PROJECT_CUSTOM_FIELD_SETTINGS_ENDPOINT.format(
                project_gid=project_gid
            )
            settings = self.asana_helper.paginate(
                logger_msg=(
                    f"fetching custom fields of project '{project_gid}'"
                    f" from {CONST.PLATFORM_NAME}"
                ),
                url=f"{base_url}{endpoint}",
                headers=headers,
                params={
                    "opt_fields": (
                        CONST.PROJECT_CUSTOM_FIELD_SETTINGS_OPT_FIELDS
                    )
                },
            )
            self._project_fields[project_gid] = build_project_field_index(
                settings
            )
        return self._project_fields[project_gid]

    def _get_custom_field_name(self, field_gid: str) -> str:
        """Return the name of a workspace custom field for error messages.

        Args:
            field_gid (str): Custom field gid.

        Returns:
            str: Field name, or the gid when the name cannot be read.
        """
        if self._field_names is None:
            # Read the workspace custom fields once per plugin instance, so
            # a burst of failing alerts does not repeat the paginated call.
            self._field_names = {}
            workspace_gid = self._get_workspace_gid()
            if workspace_gid:
                try:
                    base_url, headers = self._get_connection()
                    custom_fields = (
                        self.asana_helper.fetch_workspace_custom_fields(
                            base_url, headers, workspace_gid
                        )
                    )
                except Exception:
                    custom_fields = []
                self._field_names = {
                    str(custom_field.get("gid")): str(custom_field.get("name"))
                    for custom_field in custom_fields
                    if isinstance(custom_field, dict)
                    and custom_field.get("gid")
                    and custom_field.get("name")
                }
        return self._field_names.get(field_gid, field_gid)

    def _get_cached_fields(self, project_gid: str) -> Dict:
        """Return the cached custom field entries of a project.

        Args:
            project_gid (str): Project gid of the queue.

        Returns:
            Dict: Field entries keyed by field gid; empty when the project
                fields were not read.
        """
        fields, _ = self._project_fields.get(project_gid, ({}, {}))
        return fields

    def _build_custom_fields(
        self, mappings: Dict, project_gid: str, project_label: str = ""
    ) -> Dict:
        """Convert the mapped custom field values for a project.

        Args:
            mappings (Dict): Queue mapping values.
            project_gid (str): Project gid of the queue.
            project_label (str): Quoted project label of the queue (see
                AsanaPluginHelper.get_project_label), for the errors.

        Returns:
            Dict: custom_fields object keyed by custom field gid.

        Raises:
            AsanaMappingException: When a field is not part of the project
                or a value is not valid.
        """
        mapped = {
            key[len(CONST.CUSTOM_FIELD_PREFIX):]: value
            for key, value in mappings.items()
            if key.startswith(CONST.CUSTOM_FIELD_PREFIX)
            and value is not None
            and str(value).strip()
        }
        if not mapped:
            return {}
        project_label = project_label or f"'{project_gid}'"
        fields, _ = self._get_project_fields(project_gid)
        custom_fields = {}
        for field_gid, value in mapped.items():
            entry = fields.get(field_gid)
            if not entry:
                field_name = self._get_custom_field_name(field_gid)
                raise AsanaMappingException(
                    f"Custom field '{field_name}' is not a field of the"
                    f" project {project_label} selected as the queue, so"
                    f" the value '{value}' cannot be written. Select a"
                    " project that contains the field or remove the"
                    " mapping.",
                    resolution=(
                        f"Ensure that the custom field '{field_name}' is"
                        " added to the Asana project selected as the queue,"
                        " or remove it from the queue mapping."
                    ),
                )
            if not entry.get("writable"):
                field_text = describe_field(entry, project_label)
                raise AsanaMappingException(
                    f"{field_text[0].upper()}{field_text[1:]} cannot be"
                    " written by Cloud Exchange.",
                    resolution=(
                        "Ensure that only text, number, enum, multi_enum and"
                        " date custom fields are mapped."
                    ),
                )
            converted = convert_value(entry, value, project_label)
            if converted is not None:
                custom_fields[field_gid] = converted
        return custom_fields

    # ------------------------------------------------------------------
    # Task values
    # ------------------------------------------------------------------

    def _to_asana_value(
        self, value: Union[str, TaskStatus, None], event_field: str
    ) -> Union[str, TaskStatus, None]:
        """Convert a stored CE status or severity to the Asana value.

        Args:
            value (Union[str, TaskStatus, None]): Stored CE value of the
                task.
            event_field (str): "status" or "severity".

        Returns:
            Union[str, TaskStatus, None]: The Asana value from the Mapping
                Configuration, or the value unchanged when it is not mapped.
        """
        key = getattr(value, "value", value)
        if isinstance(key, str):
            value_map = self.asana_helper.get_value_mapping(
                self._get_config_params(step="mapping_config"), event_field
            )
            return value_map.get(key, value)
        return value

    def _read_asana_value(
        self,
        custom_fields: List[Dict],
        task: Task,
        field_key: str,
        event_field: str,
        fallback: Union[str, TaskStatus, Severity, None],
        other: Union[TaskStatus, Severity],
    ) -> Union[str, TaskStatus, Severity, None]:
        """Read the Status or Severity value of a task from Asana.

        Without a field name the fallback is used. An empty value, or a
        value that is not an Asana value of the Mapping Configuration, is
        returned as "other", because CE would show a value it cannot map as
        New or Low.

        Args:
            custom_fields (List[Dict]): custom_fields array of the task.
            task (Task): CE task.
            field_key (str): Key of the Status or Severity Field Name.
            event_field (str): "status" or "severity".
            fallback: Value used when the field is not provided.
            other: TaskStatus.OTHER or Severity.OTHER.

        Returns:
            The Asana value, the fallback or the "other" value.
        """
        field_name = self._get_named_field(field_key)
        if not field_name:
            return fallback
        value = self.asana_helper.read_named_value(
            custom_fields, field_name, None, task_id=task.id
        )
        if not value:
            self.logger.debug(
                f"{self.log_prefix}: The {event_field} of task '{task.id}'"
                f" is empty on {CONST.PLATFORM_NAME}. Setting it to Other."
            )
            return other
        value_map = self.asana_helper.get_value_mapping(
            self._get_config_params(step="mapping_config"), event_field
        )
        # Without a saved mapping CE maps the value by its own names, so
        # there is nothing to compare the value with.
        if value_map and value not in value_map.values():
            self.logger.debug(
                f"{self.log_prefix}: The {event_field} '{value}' of task"
                f" '{task.id}' is not in the {event_field.capitalize()}"
                " Mapping. Setting it to Other."
            )
            return other
        return value

    def _update_task_values(
        self,
        task: Task,
        task_data: Dict,
        fallback_status: Optional[str] = None,
        event: Union[Alert, Event, None] = None,
    ) -> Task:
        """Copy the Asana status, severity and assignee into the CE task.

        Status and severity come from the custom fields named exactly as in
        the Status Field Name and Severity Field Name parameters. When a
        parameter is empty, the status is the fallback (the alert or event
        value on create and update, the stored value on sync) and the
        severity is None, because it is not synced. When the parameter is
        set and the field has no value or a value that is not in the
        Mapping Configuration, the value is Other. CE converts the returned
        values to CE values with the Status and Severity mapping.

        The old assignee is the assignee of the alert or event, as in the
        reference plugins, so that CE sends the Asana assignee back to the
        Netskope incident when they differ.

        Args:
            task (Task): CE task.
            task_data (Dict): Task object returned by Asana.
            fallback_status: Status when the task has no Status field;
                the stored status when None.
            event (Union[Alert, Event, None]): Alert or event of the call;
                task.dataItem when None.

        Returns:
            Task: Updated task.
        """
        custom_fields = task_data.get("custom_fields") or []
        if fallback_status is None:
            fallback_status = self._to_asana_value(task.status, "status")
        status = self._read_asana_value(
            custom_fields,
            task,
            CONST.STATUS_FIELD_KEY,
            "status",
            fallback_status,
            TaskStatus.OTHER,
        )
        severity = (
            self._read_asana_value(
                custom_fields,
                task,
                CONST.SEVERITY_FIELD_KEY,
                "severity",
                None,
                Severity.OTHER,
            )
            if self._get_named_field(CONST.SEVERITY_FIELD_KEY)
            else None
        )
        assignee = (task_data.get("assignee") or {}).get("email") or None
        old_assignee = self.asana_helper.get_event_value(
            event if event is not None else task.dataItem, "assignee"
        )
        if task.updatedValues:
            task.updatedValues.status = status
            task.updatedValues.severity = severity
            task.updatedValues.assignee = assignee
            task.updatedValues.oldAssignee = old_assignee
        else:
            task.updatedValues = UpdatedTaskValues(
                status=status,
                severity=severity,
                assignee=assignee,
                oldAssignee=old_assignee,
            )
        task.status = status
        task.severity = severity
        if task_data.get("permalink_url"):
            task.link = task_data.get("permalink_url")
        return task

    def _mark_task_deleted(self, task: Task) -> Task:
        """Mark a task as deleted on Asana.

        The task was not read from Asana, so its stored CE severity is
        converted back to the Asana value before CE maps it again.

        Args:
            task (Task): CE task.

        Returns:
            Task: Task with status TaskStatus.DELETED.
        """
        self._restore_asana_values(task, ("severity",))
        if task.updatedValues:
            if task.updatedValues.status != TaskStatus.DELETED:
                task.updatedValues.oldStatus = task.updatedValues.status
            task.updatedValues.status = TaskStatus.DELETED
        else:
            task.updatedValues = UpdatedTaskValues(
                status=TaskStatus.DELETED, oldStatus=task.status
            )
        task.status = TaskStatus.DELETED
        return task

    # ------------------------------------------------------------------
    # Create task
    # ------------------------------------------------------------------

    def _build_create_payload(
        self, mappings: Dict, project_gid: str, project_label: str
    ) -> Dict:
        """Build the body of POST /tasks.

        Args:
            mappings (Dict): Queue mapping values.
            project_gid (str): Project gid of the queue.
            project_label (str): Quoted project label, for the errors.

        Returns:
            Dict: Request body.

        Raises:
            AsanaMappingException: When the mapping is not valid.
        """
        name = str(mappings.get(CONST.NAME_FIELD) or "").strip()
        if not name:
            raise AsanaMappingException(
                "Name is required to create a task on Asana.",
                resolution=(
                    "Ensure that a value is mapped to the Name field in the"
                    " queue mapping."
                ),
            )
        data = {
            "name": name,
            # The task is always created in the project selected as the
            # queue; the project is not a mapping field.
            "projects": [project_gid],
        }
        notes = str(mappings.get(CONST.NOTES_FIELD) or "").strip()
        if notes:
            data["notes"] = notes
        assignee = str(mappings.get(CONST.ASSIGNEE_FIELD) or "").strip()
        if assignee:
            data["assignee"] = assignee
        custom_fields = self._build_custom_fields(
            mappings, project_gid, project_label
        )
        if custom_fields:
            data["custom_fields"] = custom_fields
        return {"data": data}

    def create_task(
        self,
        alert: Union[Alert, Event],
        mappings: Dict,
        queue: Queue,
    ) -> Task:
        """Create an Asana task in the project selected as the queue.

        Args:
            alert (Union[Alert, Event]): Alert or event.
            mappings (Dict): Queue mapping values.
            queue (Queue): Queue; its value is the project gid.

        Returns:
            Task: Created task.

        Raises:
            AsanaPluginException: When the task cannot be created.
        """
        event_label = self.asana_helper.get_event_label(alert)
        logger_msg = (
            f"creating a task for {event_label} ID '{alert.id}'"
            f" on {CONST.PLATFORM_NAME}"
        )
        if not mappings:
            raise self.asana_helper.log_mapping_error(
                logger_msg,
                AsanaMappingException(
                    "No mappings found in the queue configuration.",
                    resolution=(
                        "Ensure that the queue mapping contains at least the"
                        " Name field."
                    ),
                ),
            )
        project_gid = str(getattr(queue, "value", "") or "").strip()
        if not project_gid:
            raise self.asana_helper.log_mapping_error(
                logger_msg,
                AsanaMappingException(
                    "No Asana project is selected as the queue.",
                    resolution=(
                        "Ensure that an Asana project is selected as the"
                        " queue."
                    ),
                ),
            )
        self.logger.info(
            f"{self.log_prefix}: Creating a task for {event_label} ID"
            f" '{alert.id}' in project '{project_gid}' on"
            f" {CONST.PLATFORM_NAME}."
        )
        try:
            project_label = self.asana_helper.get_project_label(
                queue, project_gid
            )
            payload = self._build_create_payload(
                mappings, project_gid, project_label
            )
            base_url, headers = self._get_connection()
            response = self.asana_helper.api_helper(
                logger_msg=logger_msg,
                url=f"{base_url}{CONST.TASKS_ENDPOINT}",
                method="POST",
                headers=headers,
                params={"opt_fields": ",".join(CONST.TASK_WRITE_OPT_FIELDS)},
                json_data=payload,
                error_context=self.asana_helper.describe_sent_values(
                    payload.get("data", {}),
                    mappings,
                    project_gid,
                    self._get_cached_fields(project_gid),
                ),
            )
            task_data = (
                response.get("data") if isinstance(response, dict) else {}
            )
            task_gid = str((task_data or {}).get("gid") or "")
            if not task_gid:
                err_msg = (
                    f"Error occurred while {logger_msg}. The response of"
                    " Asana contains no task ID."
                )
                self.logger.error(message=f"{self.log_prefix}: {err_msg}")
                raise AsanaPluginException(err_msg)
        except AsanaMappingException as exp:
            raise self.asana_helper.log_mapping_error(logger_msg, exp)
        except AsanaPluginException:
            raise
        except Exception as exp:
            raise self.asana_helper.log_unexpected_error(logger_msg, exp)

        task = Task(
            id=task_gid,
            status=TaskStatus.NEW,
            link=str(task_data.get("permalink_url") or ""),
            dataItem=alert,
        )
        self._update_task_values(
            task,
            task_data,
            fallback_status=(
                self.asana_helper.get_event_value(alert, "status")
                or TaskStatus.NEW
            ),
            event=alert,
        )
        self.logger.info(
            f"{self.log_prefix}: Successfully created task with ID"
            f" '{task_gid}' on {CONST.PLATFORM_NAME} for {event_label} ID"
            f" '{alert.id}'."
        )
        return task

    # ------------------------------------------------------------------
    # Update task
    # ------------------------------------------------------------------

    def _get_comment_text(
        self, mappings: Dict, alert: Union[Alert, Event]
    ) -> str:
        """Return the comment added to a task.

        Args:
            mappings (Dict): Queue mapping values.
            alert (Union[Alert, Event]): Alert or event.

        Returns:
            str: Mapped Text value, or the default comment, truncated to the
                Asana limit.
        """
        text = str(mappings.get(CONST.COMMENT_FIELD) or "").strip()
        if not text:
            event_label = self.asana_helper.get_event_label(alert).lower()
            text = (
                f"Received new {event_label} with"
                f" Alert/Event ID: {alert.id} in Cloud Exchange."
            )
        return truncate_comment(text)

    def _source_text(self, alert: Union[Alert, Event]) -> str:
        """Return the alert or event that caused an update, for the logs.

        Args:
            alert (Union[Alert, Event]): Alert or event.

        Returns:
            str: For example " for Alert ID 'abc'".
        """
        event_label = self.asana_helper.get_event_label(alert)
        return f" for {event_label} ID '{alert.id}'"

    def _add_comment(self, task: Task, text: str, source: str = "") -> Task:
        """Add a comment to a task with POST /tasks/{gid}/stories.

        Args:
            task (Task): CE task.
            text (str): Comment text.
            source (str): Alert or event of the comment, for the log (see
                _source_text).

        Returns:
            Task: Task, marked deleted when Asana returns HTTP 404.

        Raises:
            AsanaPluginException: When the comment cannot be added.
        """
        logger_msg = (
            f"adding a comment to task '{task.id}' on {CONST.PLATFORM_NAME}"
        )
        base_url, headers = self._get_connection()
        endpoint = CONST.TASK_STORIES_ENDPOINT.format(task_gid=task.id)
        response = self.asana_helper.api_helper(
            logger_msg=logger_msg,
            url=f"{base_url}{endpoint}",
            method="POST",
            headers=headers,
            params={"opt_fields": ",".join(CONST.STORY_OPT_FIELDS)},
            json_data={"data": {"text": text}},
            is_handle_error_required=False,
        )
        if response.status_code == 404:
            self.logger.info(
                f"{self.log_prefix}: Task '{task.id}' no longer exists on"
                f" {CONST.PLATFORM_NAME}. Marking the task as deleted."
            )
            return self._mark_task_deleted(task)
        self.asana_helper.handle_error(response, logger_msg)
        self.logger.info(
            f"{self.log_prefix}: Successfully added a comment to task"
            f" '{task.id}' on {CONST.PLATFORM_NAME}{source}."
        )
        return task

    def _build_update_data(
        self, mappings: Dict, project_gid: str, project_label: str
    ) -> Dict:
        """Build the body of PUT /tasks/{gid}.

        Only the assignee and the custom fields are updated. Empty values
        are not sent, so Asana never clears a value.

        Args:
            mappings (Dict): Queue mapping values.
            project_gid (str): Project gid of the queue.
            project_label (str): Quoted project label, for the errors.

        Returns:
            Dict: Update data; empty when nothing is mapped.

        Raises:
            AsanaMappingException: When a mapped value is not valid.
        """
        data = {}
        assignee = str(mappings.get(CONST.ASSIGNEE_FIELD) or "").strip()
        if assignee:
            data["assignee"] = assignee
        if project_gid:
            custom_fields = self._build_custom_fields(
                mappings, project_gid, project_label
            )
            if custom_fields:
                data["custom_fields"] = custom_fields
        return data

    def _update_with_batch(
        self,
        task: Task,
        update_data: Dict,
        comment: str,
        project_gid: str,
        alert: Union[Alert, Event],
        mappings: Dict,
    ) -> Task:
        """Update a task and add a comment in one batch request.

        Args:
            task (Task): CE task.
            update_data (Dict): Body data of PUT /tasks/{gid}.
            comment (str): Comment text.
            project_gid (str): Project gid of the queue.
            alert (Union[Alert, Event]): Alert or event of the update.
            mappings (Dict): Queue mapping values, for the errors.

        Returns:
            Task: Updated task.

        Raises:
            AsanaPluginException: When the update fails.
        """
        update_msg = f"updating task '{task.id}' on {CONST.PLATFORM_NAME}"
        base_url, headers = self._get_connection()
        actions = [
            {
                "relative_path": CONST.TASK_ENDPOINT.format(task_gid=task.id),
                "method": "put",
                "data": update_data,
                "options": {"fields": CONST.TASK_WRITE_OPT_FIELDS},
            },
            {
                "relative_path": CONST.TASK_STORIES_ENDPOINT.format(
                    task_gid=task.id
                ),
                "method": "post",
                "data": {"text": comment},
                "options": {"fields": CONST.STORY_OPT_FIELDS},
            },
        ]
        update_result, comment_result = self.asana_helper.execute_batch(
            logger_msg=update_msg,
            base_url=base_url,
            headers=headers,
            actions=actions,
        )
        if 404 in (
            update_result.get("status_code"),
            comment_result.get("status_code"),
        ):
            self.logger.info(
                f"{self.log_prefix}: Task '{task.id}' no longer exists on"
                f" {CONST.PLATFORM_NAME}. Marking the task as deleted."
            )
            return self._mark_task_deleted(task)

        source = self._source_text(alert)
        if comment_result.get("status_code") in (200, 201):
            self.logger.info(
                f"{self.log_prefix}: Successfully added a comment to task"
                f" '{task.id}' on {CONST.PLATFORM_NAME}{source}."
            )
        else:
            self.asana_helper.log_action_error(
                f"adding a comment to task '{task.id}' on"
                f" {CONST.PLATFORM_NAME}",
                comment_result,
            )

        if update_result.get("status_code") not in (200, 201):
            context = self.asana_helper.describe_sent_values(
                update_data,
                mappings,
                project_gid,
                self._get_cached_fields(project_gid),
            )
            err_msg = self.asana_helper.log_action_error(
                update_msg, update_result, f" {context}" if context else ""
            )
            raise AsanaPluginException(
                err_msg, status_code=update_result.get("status_code")
            )

        task_data = (update_result.get("body") or {}).get("data") or {}
        self._update_task_values(
            task,
            task_data,
            fallback_status=self.asana_helper.get_event_value(
                alert, "status"
            ),
            event=alert,
        )
        updated = self.asana_helper.describe_update(
            update_data, self._get_cached_fields(project_gid)
        )
        self.logger.info(
            f"{self.log_prefix}: Successfully updated {updated} of task"
            f" '{task.id}' on {CONST.PLATFORM_NAME}{source}."
        )
        return task

    def update_task(
        self,
        task: Task,
        alert: Union[Alert, Event],
        mappings: Dict,
        queue: Queue,
        upsert_task: bool = False,
    ) -> Task:
        """Update an Asana task for a deduplicated alert or event.

        upsert_task=False adds one comment. upsert_task=True also updates
        the assignee and the mapped custom fields; both writes are sent in
        one batch request.

        Args:
            task (Task): CE task.
            alert (Union[Alert, Event]): Alert or event.
            mappings (Dict): Queue mapping values (dedup mappings when
                upsert_task is False, create mappings otherwise).
            queue (Queue): Queue; its value is the project gid.
            upsert_task (bool): True to update the task fields.

        Returns:
            Task: Updated task.

        Raises:
            AsanaPluginException: When the task cannot be updated.
        """
        mappings = mappings or {}
        logger_msg = f"updating task '{task.id}' on {CONST.PLATFORM_NAME}"
        comment = self._get_comment_text(mappings, alert)
        try:
            update_data = {}
            project_gid = str(getattr(queue, "value", "") or "").strip()
            if upsert_task:
                update_data = self._build_update_data(
                    mappings,
                    project_gid,
                    self.asana_helper.get_project_label(queue, project_gid),
                )
            if update_data:
                return self._update_with_batch(
                    task, update_data, comment, project_gid, alert, mappings
                )
            task = self._add_comment(
                task, comment, self._source_text(alert)
            )
            # Only a comment was added, so the task values were not read
            # from Asana; restore the Asana values before CE maps them
            # again. A deleted task was already restored when marked.
            if not self.asana_helper.is_deleted(task):
                self._restore_asana_values(task)
            return task
        except AsanaMappingException as exp:
            raise self.asana_helper.log_mapping_error(logger_msg, exp)
        except AsanaPluginException:
            raise
        except Exception as exp:
            raise self.asana_helper.log_unexpected_error(logger_msg, exp)

    # ------------------------------------------------------------------
    # Sync states
    # ------------------------------------------------------------------

    def _restore_asana_values(
        self, task: Task, fields: Tuple[str, ...] = ("status", "severity")
    ) -> Task:
        """Convert the stored CE values of a task back to Asana values.

        CE maps the status and severity of every returned task from Asana
        values to CE values. A task returned without reading Asana still
        holds CE values, which CE would map again (to the defaults "New"
        and "Low" when the user changed the mapping). Converting them back
        keeps the stored values unchanged.

        Args:
            task (Task): CE task.
            fields (Tuple[str, ...]): Task attributes to convert.

        Returns:
            Task: The task with Asana values.
        """
        for field in fields:
            setattr(
                task,
                field,
                self._to_asana_value(getattr(task, field, None), field),
            )
        return task

    def _keep_deleted(self, task: Task) -> Task:
        """Return a deleted task with the TaskStatus.DELETED status.

        CE maps the returned status again. The stored label "Deleted" is
        not a mapped Asana value and would become "New", while the enum
        value maps back to "Deleted". The severity is converted back to
        the Asana value for the same reason.

        Args:
            task (Task): Task already marked deleted.

        Returns:
            Task: The task with the enum status.
        """
        self._restore_asana_values(task, ("severity",))
        task.status = TaskStatus.DELETED
        if task.updatedValues:
            task.updatedValues.status = TaskStatus.DELETED
        return task

    def _sync_batch(
        self, batch: List[Task], batch_number: int
    ) -> List[Task]:
        """Read one group of up to 10 tasks with the Batch API.

        Args:
            batch (List[Task]): Tasks of the group.
            batch_number (int): Index of the group, starting at 1.

        Returns:
            List[Task]: Tasks read from Asana or marked deleted. Tasks whose
                action failed are not returned.
        """
        base_url, headers = self._get_connection()
        actions = [
            {
                "relative_path": CONST.TASK_ENDPOINT.format(task_gid=task.id),
                "method": "get",
                "options": {"fields": CONST.TASK_READ_OPT_FIELDS},
            }
            for task in batch
        ]
        results = self.asana_helper.execute_batch(
            logger_msg=(
                f"syncing batch {batch_number} ({len(batch)} task(s))"
                f" with {CONST.PLATFORM_NAME}"
            ),
            base_url=base_url,
            headers=headers,
            actions=actions,
        )
        synced = []
        for task, result in zip(batch, results):
            status_code = result.get("status_code")
            if status_code == 200:
                body = result.get("body") or {}
                self._update_task_values(task, body.get("data") or {})
                synced.append(task)
            elif status_code == 404:
                self.logger.info(
                    f"{self.log_prefix}: Task '{task.id}' no longer exists"
                    f" on {CONST.PLATFORM_NAME}. Marking the task as deleted."
                )
                self._mark_task_deleted(task)
                synced.append(task)
            else:
                self.asana_helper.log_action_error(
                    f"syncing task '{task.id}' with {CONST.PLATFORM_NAME}",
                    result,
                    " The task will be read again in the next sync cycle.",
                )
        return synced

    def _log_unsynced_fields(self) -> None:
        """Log the Status and Severity fields that are not synced.

        A field is synced only when its name is provided in the
        Configuration Parameters.
        """
        missing = [
            (label, value)
            for key, label, value in (
                (CONST.STATUS_FIELD_KEY, "Status Field Name", "status"),
                (CONST.SEVERITY_FIELD_KEY, "Severity Field Name", "severity"),
            )
            if not self._get_named_field(key)
        ]
        if not missing:
            return
        labels = " and ".join(label for label, _ in missing)
        values = " and ".join(value for _, value in missing)
        verb = "are" if len(missing) > 1 else "is"
        self.logger.info(
            f"{self.log_prefix}: {labels} {verb} not provided in the"
            f" configuration parameters, so the {values} of the task(s)"
            f" will not be synced from {CONST.PLATFORM_NAME}. Provide the"
            " exact name of the Asana custom field to sync it."
        )

    def sync_states(self, tasks: List[Task]) -> List[Task]:
        """Sync the status, severity and assignee of tasks from Asana.

        Tasks are read 10 at a time with the Batch API. A task is marked
        deleted only for an HTTP 404 of its own action. Tasks that could not
        be read (failed action or failed group) are left out of the result,
        so CE keeps their stored values and they are read again in the next
        cycle; returning them unchanged would make CE map their stored CE
        labels again.

        Args:
            tasks (List[Task]): Tasks of the configuration.

        Returns:
            List[Task]: Tasks that were read from Asana or are deleted.
        """
        result = []
        to_sync = []
        for task in tasks:
            if self.asana_helper.is_deleted(task):
                result.append(self._keep_deleted(task))
            elif task.id:
                to_sync.append(task)
        if not to_sync:
            self.logger.info(
                f"{self.log_prefix}: No task(s) to sync with"
                f" {CONST.PLATFORM_NAME}."
            )
            return result
        self.logger.info(
            f"{self.log_prefix}: Syncing status for {len(to_sync)} task(s)"
            f" with {CONST.PLATFORM_NAME}."
        )
        self._log_unsynced_fields()
        total_synced = 0
        for index in range(0, len(to_sync), CONST.BATCH_SIZE):
            batch = to_sync[index:index + CONST.BATCH_SIZE]
            batch_number = index // CONST.BATCH_SIZE + 1
            try:
                synced = self._sync_batch(batch, batch_number)
            except AsanaPluginException as exp:
                if self.asana_helper.stops_sync(exp):
                    self.logger.info(
                        f"{self.log_prefix}: Skipping the remaining"
                        f" task(s) of this sync cycle because of the error"
                        " above. They will be read again in the next sync"
                        " cycle."
                    )
                    break
                continue
            except Exception as exp:
                self.asana_helper.log_unexpected_error(
                    f"syncing batch {batch_number} with"
                    f" {CONST.PLATFORM_NAME}",
                    exp,
                )
                continue
            result.extend(synced)
            total_synced += len(synced)
            self.logger.info(
                f"{self.log_prefix}: Successfully synced {len(synced)}"
                f" task(s) from {CONST.PLATFORM_NAME} in batch {batch_number}."
                f" Total task(s) synced: {total_synced}."
            )
        skip_count = len(to_sync) - total_synced
        if skip_count:
            self.logger.info(
                f"{self.log_prefix}: Failed to sync {skip_count} task(s)"
                f" with {CONST.PLATFORM_NAME}. They will be read again in the"
                " next sync cycle."
            )
        if total_synced:
            self.logger.info(
                f"{self.log_prefix}: Successfully synced {total_synced}"
                f" task(s) with {CONST.PLATFORM_NAME}."
            )
        return result
