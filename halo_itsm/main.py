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

HaloITSM CTO Plugin for Netskope Cloud Exchange.
"""

import re
import traceback
from typing import Dict, List, Optional, Tuple, Union
from urllib.parse import urlparse

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

from .utils.halo_api_helper import HaloPluginHelper
from .utils.halo_constants import (
    ACTIONS_ENDPOINT,
    AGENT_CACHE_KEY,
    BASE_URL,
    CREATE_NOTE_OUTCOME,
    DICT_FIELD_WRAPPERS,
    FIELD_NAME_MAP,
    STANDARD_POST_FIELDS,
    IMPACT_FIELD_NAMES,
    IMPACT_LABEL_TO_ID,
    MODULE_NAME,
    PAGE_SIZE,
    PLATFORM_NAME,
    PLUGIN_VERSION,
    SEVERITY_MAPPINGS,
    STATUS_ENDPOINT,
    TEAM_ENDPOINT,
    TICKET_TYPE_ENDPOINT,
    TICKETS_ENDPOINT,
    URGENCY_FIELD_NAMES,
    URGENCY_LABEL_TO_ID,
    USERS_ENDPOINT,
)
from .utils.halo_exceptions import HaloITSMPluginException


class HaloITSMPlugin(PluginBase):
    """HaloITSM CTO Plugin implementation."""

    def __init__(
        self,
        name: str,
        *args,
        **kwargs,
    ) -> None:
        """HaloITSM plugin initializer.

        Args:
            name (str): Plugin configuration name.
        """
        super().__init__(name, *args, **kwargs)
        self.plugin_name, self.plugin_version = self._get_plugin_info()
        self.log_prefix = f"{MODULE_NAME} {self.plugin_name} [{name}]"
        self.halo_helper = HaloPluginHelper(
            logger=self.logger,
            log_prefix=self.log_prefix,
            plugin_name=self.plugin_name,
            plugin_version=self.plugin_version,
            ssl_validation=self.ssl_validation,
            proxy=self.proxy,
        )

    def _get_plugin_info(self) -> Tuple[str, str]:
        """Get plugin name and version from manifest.

        Returns:
            Tuple[str, str]: Tuple of plugin's name and version fetched
                from manifest.
        """
        try:
            manifest_json = HaloITSMPlugin.metadata
            plugin_name = manifest_json.get("name", PLATFORM_NAME)
            plugin_version = manifest_json.get("version", PLUGIN_VERSION)
            return plugin_name, plugin_version
        except Exception as exp:
            self.logger.error(
                message=(
                    f"{MODULE_NAME} {PLATFORM_NAME}: Error occurred while"
                    f" getting plugin details. Error: {exp}"
                ),
                details=traceback.format_exc(),
            )
        return (PLATFORM_NAME, PLUGIN_VERSION)

    # ------------------------------------------------------------------
    # Storage helpers
    # ------------------------------------------------------------------

    def _get_storage(self) -> Dict:
        """Return the persistent storage dictionary.

        Returns:
            Dict: Storage dict; empty dict when storage is unavailable.
        """
        return self.storage if self.storage is not None else {}

    # ------------------------------------------------------------------
    # Auth helpers
    # ------------------------------------------------------------------

    def _get_base_url(self, configuration: Dict) -> str:
        """Build and return the base URL for the configured tenant.

        Args:
            configuration (Dict): Full plugin configuration dictionary.

        Returns:
            str: Base URL in the form https://<tenant>.haloitsm.com.
        """
        tenant = (
            self.halo_helper.get_config_params(configuration, "auth")
            .get("tenantname", "")
            .strip()
        )
        return BASE_URL.format(tenant)

    def generate_token(
        self,
        configuration: Dict,
        is_from_validation: bool = False,
    ) -> str:
        """Generate and return an OAuth2 access token from HaloITSM.

        Delegates to HaloPluginHelper._generate_token so that token
        caching and regeneration live in one place and api_helper can
        call them directly on 401 without an external callable.

        Args:
            configuration (Dict): Full plugin configuration dictionary.
            is_from_validation (bool): When True always requests a fresh
                token and skips cache read/write.

        Returns:
            str: Valid OAuth2 access token.

        Raises:
            HaloITSMPluginException: When token generation fails.
        """
        return self.halo_helper._generate_token(
            configuration=configuration,
            storage=self._get_storage(),
            is_from_validation=is_from_validation,
        )

    def get_headers(
        self,
        configuration: Dict,
        force_refresh: bool = False,
    ) -> Dict:
        """Build and return authenticated request headers.

        Delegates to HaloPluginHelper._get_auth_headers so that the
        same headers are used by direct callers and by api_helper's
        internal 401 refresh.

        Args:
            configuration (Dict): Full plugin configuration dictionary.
            force_refresh (bool): When True clears the cached token
                before generating a new one.

        Returns:
            Dict: Headers dict with Bearer token and Content-Type.
        """
        return self.halo_helper._get_auth_headers(
            configuration=configuration,
            storage=self._get_storage(),
            force_refresh=force_refresh,
        )

    # ------------------------------------------------------------------
    # Validation
    # ------------------------------------------------------------------

    def _validate_configuration_parameters(
        self,
        field_name: str,
        field_value: Union[str, int],
        field_type: type,
        is_required: bool = True,
        allowed_values: Optional[List] = None,
        validation_err_msg: str = "Validation error occurred.",
        required_field_message: Optional[str] = None,
    ) -> Optional[ValidationResult]:
        """Validate a single configuration field.

        Returns ValidationResult on failure, None on success so callers
        can use the walrus operator: ``if result := _validate_...:
        return result``

        Args:
            field_name: Human-readable name used in error messages.
            field_value: Value to validate.
            field_type: Expected Python type (str, int, …).
            is_required: When True an empty/None value is an error.
            allowed_values: When provided the value must be one of these.
            validation_err_msg: Prefix logged before the field-level error.
            required_field_message: Custom message when required field is
                empty. Defaults to a generic "<field_name> is a required
                configuration parameter." message.

        Returns:
            ValidationResult with success=False on failure, None on success.
        """
        if field_type is str and isinstance(field_value, str):
            field_value = field_value.strip()

        if (
            is_required
            and not isinstance(field_value, int)
            and not field_value
        ):
            err_msg = (
                required_field_message
                if required_field_message
                else f"{field_name} is a required configuration parameter."
            )
            self.logger.error(
                f"{self.log_prefix}: {validation_err_msg} {err_msg}"
            )
            return ValidationResult(success=False, message=err_msg)

        if field_value and not isinstance(field_value, field_type):
            err_msg = (
                f"Invalid value provided for the configuration"
                f" parameter '{field_name}'."
            )
            self.logger.error(
                f"{self.log_prefix}: {validation_err_msg} {err_msg}"
            )
            return ValidationResult(success=False, message=err_msg)

        if (
            allowed_values
            and field_type is str
            and field_value not in allowed_values
        ):
            err_msg = (
                f"Invalid value provided for '{field_name}'."
                f" Allowed values are:"
                f" {', '.join(str(v) for v in allowed_values)}."
            )
            self.logger.error(
                f"{self.log_prefix}: {validation_err_msg} {err_msg}"
            )
            return ValidationResult(success=False, message=err_msg)

        return None

    def validate_step(
        self, name: str, configuration: Dict
    ) -> ValidationResult:
        """Dispatch validation to the correct step handler.

        Args:
            name (str): Step name ('auth' or 'params').
            configuration (Dict): Full plugin configuration dictionary.

        Returns:
            ValidationResult: Result with success flag and message.
        """
        if name == "auth":
            return self._validate_auth(configuration)
        elif name == "params":
            return self._validate_params(configuration)
        else:
            return ValidationResult(
                success=True, message="Validation successful."
            )

    def _validate_auth(self, configuration: Dict) -> ValidationResult:
        """Validate Authentication step fields and connectivity.

        Checks Tenant Name, Authentication Method, Client ID, and the
        credential fields required for the selected auth method
        (Client Secret for client_credentials; Username and Password
        for password). Runs a live connectivity check at the end.

        Args:
            configuration (Dict): Full plugin configuration dictionary.

        Returns:
            ValidationResult: Result with success flag and message.
        """
        auth_params = self.halo_helper.get_config_params(configuration, "auth")
        validation_error = "Validation error occurred."

        # Validate Tenant Name
        tenant = auth_params.get("tenantname", "").strip()
        if result := self._validate_configuration_parameters(
            field_name="Tenant Name",
            field_value=tenant,
            field_type=str,
            is_required=True,
            validation_err_msg=validation_error,
            required_field_message=(
                "Tenant Name is a required Authentication parameter."
            ),
        ):
            return result

        base_url = self._get_base_url(configuration)
        parsed = urlparse(base_url)
        if not (parsed.scheme and parsed.netloc):
            err_msg = (
                f"Tenant Name '{tenant}' produces an invalid URL."
                " Ensure it contains only alphanumeric characters"
                " and hyphens (e.g. 'mycompany')."
            )
            self.logger.error(
                f"{self.log_prefix}: {validation_error} {err_msg}"
            )
            return ValidationResult(success=False, message=err_msg)

        # Validate Authentication Method
        auth_method = auth_params.get("auth_method", "").strip()
        if result := self._validate_configuration_parameters(
            field_name="Authentication Method",
            field_value=auth_method,
            field_type=str,
            is_required=True,
            allowed_values=["password", "client_credentials"],
            validation_err_msg=validation_error,
            required_field_message=(
                "Authentication Method is a required Authentication parameter."
            ),
        ):
            return result

        # Validate Client ID
        client_id = auth_params.get("client_id", "").strip()
        if result := self._validate_configuration_parameters(
            field_name="Client ID",
            field_value=client_id,
            field_type=str,
            is_required=True,
            validation_err_msg=validation_error,
            required_field_message=(
                "Client ID is a required Authentication parameter."
            ),
        ):
            return result

        # Validate credential fields for the selected auth method
        if auth_method == "client_credentials":
            client_secret = auth_params.get("client_secret", "")
            if result := self._validate_configuration_parameters(
                field_name="Client Secret",
                field_value=client_secret,
                field_type=str,
                is_required=True,
                validation_err_msg=validation_error,
                required_field_message=(
                    "Client Secret is a required Authentication parameter."
                ),
            ):
                return result

        elif auth_method == "password":
            username = auth_params.get("username", "").strip()
            if result := self._validate_configuration_parameters(
                field_name="Username",
                field_value=username,
                field_type=str,
                is_required=True,
                validation_err_msg=validation_error,
                required_field_message=(
                    "Username is a required Authentication parameter."
                ),
            ):
                return result

            password = auth_params.get("password", "")
            if result := self._validate_configuration_parameters(
                field_name="Password",
                field_value=password,
                field_type=str,
                is_required=True,
                validation_err_msg=validation_error,
                required_field_message=(
                    "Password is a required Authentication parameter."
                ),
            ):
                return result

        return self._validate_connectivity(configuration)

    def _validate_params(self, configuration: Dict) -> ValidationResult:
        """Validate Configuration Parameters step fields.

        Connectivity was already confirmed in _validate_auth. This step
        checks that a Ticket Type has been selected.

        Args:
            configuration (Dict): Full plugin configuration dictionary.

        Returns:
            ValidationResult: Result with success flag and message.
        """
        params = self.halo_helper.get_config_params(configuration, "params")
        validation_error = "Validation error occurred."

        # Validate Ticket Type
        tickettype_id = str(params.get("tickettype_id") or "").strip()
        if result := self._validate_configuration_parameters(
            field_name="Ticket Type",
            field_value=tickettype_id,
            field_type=str,
            is_required=True,
            validation_err_msg=validation_error,
            required_field_message=(
                "Ticket Type is a required Configuration parameter."
            ),
        ):
            return result

        validation_msg = "Successfully validated Configuration Parameters."
        self.logger.debug(f"{self.log_prefix}: {validation_msg}")
        return ValidationResult(success=True, message=validation_msg)

    def _validate_connectivity(self, configuration: Dict) -> ValidationResult:
        """Test connectivity by generating a live access token.

        Args:
            configuration (Dict): Full plugin configuration dictionary.

        Returns:
            ValidationResult: Result with success flag and message.
        """
        logger_msg = f"connectivity with {PLATFORM_NAME} server"
        try:
            self.logger.debug(f"{self.log_prefix}: Validating {logger_msg}.")
            self.generate_token(configuration, is_from_validation=True)
            validation_msg = f"Successfully validated {logger_msg}."
            self.logger.debug(f"{self.log_prefix}: {validation_msg}")
            return ValidationResult(success=True, message=validation_msg)
        except HaloITSMPluginException as exp:
            return ValidationResult(success=False, message=str(exp))
        except Exception as exp:
            err_msg = "Error occurred while validating" f" {logger_msg}."
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {exp}",
                details=traceback.format_exc(),
                resolution=(
                    "Ensure that the Authentication parameters provided"
                    " in the configuration are correct."
                ),
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )

    # ------------------------------------------------------------------
    # Enum field resolution
    # ------------------------------------------------------------------

    def _resolve_enum_value(
        self, field_name: str, field_value: object
    ) -> object:
        """Resolve an impact or urgency label to its HaloITSM integer ID.

        HaloITSM expects integer IDs for impact and urgency fields.
        Accepts the human-readable label (case-insensitive) or a raw
        integer / numeric string and returns the correct integer.

        Valid impact values:
            1 — Company Wide
            2 — Multiple Users Affected
            3 — Single User Affected

        Valid urgency values:
            1 — High
            2 — Medium
            3 — Low

        For all other field names the original value is returned unchanged.

        Args:
            field_name (str): Ticket field name from the queue mapping.
            field_value (object): Value provided by the user.

        Returns:
            object: Integer ID for known impact/urgency labels or numeric
                strings; the original value for unrecognised inputs and
                all other field names.
        """
        if field_name in IMPACT_FIELD_NAMES:
            label_to_id = IMPACT_LABEL_TO_ID
        elif field_name in URGENCY_FIELD_NAMES:
            label_to_id = URGENCY_LABEL_TO_ID
        else:
            return field_value

        # Label match (case-insensitive)
        resolved = label_to_id.get(str(field_value).strip().lower())
        if resolved is not None:
            return resolved

        # Numeric string fallback (e.g. user typed "1", "2", "3")
        try:
            return int(field_value)
        except (ValueError, TypeError):
            self.logger.error(
                f"{self.log_prefix}: Unrecognised value '{field_value}'"
                f" for field '{field_name}'."
                f" Valid labels: {list(label_to_id.keys())}."
                " Passing the value as-is."
            )
            return field_value

    def _fetch_all_agent_users(self, storage: Dict) -> Dict:
        """Fetch all HaloITSM users with pagination and populate agent cache.

        Calls GET /api/Users with paginate=true, iterating pages until
        exhausted. Stores email → linked_agent_id for every user that has
        both fields. Returns the updated cache dict (same reference as
        storage[AGENT_CACHE_KEY]).

        Args:
            storage (Dict): CE persistent storage dict (same reference
                used by the caller so updates persist without re-fetching).

        Returns:
            Dict: Agent email cache {email: linked_agent_id}.
        """
        cache = storage.setdefault(AGENT_CACHE_KEY, {})
        base_url = self._get_base_url(self.configuration)
        url = f"{base_url}{USERS_ENDPOINT}"
        page_no = 1
        total_fetched = 0
        while True:
            logger_msg = f"fetching agents page {page_no} from {PLATFORM_NAME}"
            try:
                response = self.halo_helper.api_helper(
                    logger_msg=logger_msg,
                    url=url,
                    method="GET",
                    params={
                        "paginate": True,
                        "page_size": PAGE_SIZE,
                        "page_no": page_no,
                    },
                    headers=self.get_headers(self.configuration),
                    verify=self.ssl_validation,
                    proxies=self.proxy,
                    configuration=self.configuration,
                    storage=storage,
                )
            except HaloITSMPluginException:
                break
            except Exception:
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: Error occurred while fetching"
                        f" agents page {page_no} from {PLATFORM_NAME}."
                    ),
                    details=traceback.format_exc(),
                )
                break

            users = (
                response
                if isinstance(response, list)
                else response.get("users", [])
            )
            if not users:
                break

            for user in users:
                email = (
                    user.get("emailaddress") or user.get("email", "")
                ).strip()
                linked_agent_id = user.get("linked_agent_id")
                if email and linked_agent_id is not None:
                    try:
                        cache[email] = int(linked_agent_id)
                    except (ValueError, TypeError):
                        pass
            total_fetched += len(users)

            if len(users) < PAGE_SIZE:
                break
            page_no += 1

        self.logger.debug(
            f"{self.log_prefix}: Successfully fetched {total_fetched}"
            f" agent(s) from {PLATFORM_NAME}."
        )
        return cache

    def _resolve_agent_id(self, value: str) -> Optional[int]:
        """Resolve an Assigned Agent mapping value to a HaloITSM agent_id.

        Accepts either a raw integer string (returned as-is, no cache
        update) or a valid email address. For email inputs the agent cache
        in CE persistent storage is checked first; on a cache miss all
        users are fetched via _fetch_all_agent_users (paginated) and the
        full cache is populated before retrying. Returns None when the
        email is invalid or not found — callers should skip agent assignment.

        Args:
            value (str): Raw mapping value — email address or integer ID.

        Returns:
            Optional[int]: Resolved integer agent_id, or None on failure.
        """
        value = value.strip()
        if not value:
            return None

        # Raw integer ID — pass through directly without touching the cache.
        try:
            return int(value)
        except ValueError:
            pass

        # Validate email format before making any API call.
        email_pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
        if not re.match(email_pattern, value):
            self.logger.info(
                f"{self.log_prefix}: '{value}' provided for Assigned Agent"
                " is not a valid email address or numeric agent ID."
                " Skipping agent assignment."
            )
            return None

        # Check the persistent cache before hitting the API.
        storage = self._get_storage()
        cache = storage.setdefault(AGENT_CACHE_KEY, {})
        if value in cache:
            return cache[value]

        # Cache miss — fetch all users and populate the full cache, then retry.
        cache = self._fetch_all_agent_users(storage)
        if value in cache:
            return cache[value]

        self.logger.info(
            f"{self.log_prefix}: Agent with email '{value}' not found"
            f" in {PLATFORM_NAME}. Skipping agent assignment."
        )
        return None

    # ------------------------------------------------------------------
    # Ticket type helpers
    # ------------------------------------------------------------------

    def _fetch_ticket_type_fields(
        self, configuration: Dict, tickettype_id: str
    ) -> List[MappingField]:
        """Fetch field definitions for a specific ticket type.

        Calls GET /api/TicketType/{id} and walks the nested structure:
          response["fields"]
            └── row["group"]["fields"]
                  └── field["fieldinfo"]["name"] / ["label"]

        Always appends a 'Note' field (updateAble=True) for dedup
        support whether or not it appears in the API response.

        Args:
            configuration (Dict): Full plugin configuration dictionary.
            tickettype_id (str): ID of the ticket type to inspect.

        Returns:
            List[MappingField]: Field definitions ready for CE mapping.

        Raises:
            HaloITSMPluginException: When the API call fails.
        """
        base_url = self._get_base_url(configuration)
        url = f"{base_url}{TICKET_TYPE_ENDPOINT}/{tickettype_id}"
        log_msg = (
            f"fetching available fields for ticket type"
            f" '{tickettype_id}' from {PLATFORM_NAME}"
        )
        response = self.halo_helper.api_helper(
            logger_msg=log_msg,
            url=url,
            method="GET",
            headers=self.get_headers(configuration),
            verify=self.ssl_validation,
            proxies=self.proxy,
            configuration=configuration,
            storage=self._get_storage(),
        )

        fields: List[MappingField] = []
        seen: set = set()

        def _add_fieldinfo(fieldinfo: Dict) -> None:
            if not isinstance(fieldinfo, dict):
                return
            name = fieldinfo.get("name", "")
            label = fieldinfo.get("label", "")
            if not name or name == "N/A" or not label or name in seen:
                return
            if re.search(r"\bAI\b", label):
                return
            seen.add(name)
            is_custom = fieldinfo.get("custom", 0) == 1
            if is_custom:
                value = name
            else:
                value = FIELD_NAME_MAP.get(name, name)
            seen.add(value)
            if value == "agent_id":
                label = "Assigned Agent"
            fields.append(
                MappingField(
                    label=label,
                    value=value,
                    updateAble=(value in ("note_html", "agent_id")),
                )
            )

        top_fields = (
            response.get("fields", []) if isinstance(response, dict) else []
        )
        for top_field in top_fields:
            if not isinstance(top_field, dict):
                continue

            # Case 1: fieldinfo directly on the top-level field entry.
            _add_fieldinfo(top_field.get("fieldinfo", {}))

            # Case 2: fieldinfo nested inside group.fields[].
            group = top_field.get("group", {})
            if isinstance(group, dict):
                for group_field in group.get("fields", []):
                    if isinstance(group_field, dict):
                        _add_fieldinfo(group_field.get("fieldinfo", {}))

        if "note_html" not in seen:
            fields.append(
                MappingField(
                    label="Note",
                    value="note_html",
                    updateAble=True,
                )
            )

        # status_id is never returned by the TicketType API but is always
        # offered as a mappable field so users can set a non-default status
        # on ticket creation via a post-create status update call.
        if "status_id" not in seen:
            fields.append(
                MappingField(
                    label="Status",
                    value="status_id",
                    updateAble=False,
                )
            )

        # agent_id is always offered for all ticket types. If the ticket type
        # API already returned it (via assignedtoint), the label is overridden
        # to "Assigned Agent" inside _add_fieldinfo and seen contains
        # "agent_id" so this block is skipped. Otherwise it is appended here.
        if "agent_id" not in seen:
            fields.append(
                MappingField(
                    label="Assigned Agent",
                    value="agent_id",
                    updateAble=True,
                )
            )

        return fields

    def _fetch_ticket_types(self, configuration: Dict) -> List[Dict]:
        """Fetch all ticket types from HaloITSM.

        Calls GET /api/TicketType and returns a list of dicts, each
        containing 'id' (int) and 'name' (str).

        Args:
            configuration (Dict): Full plugin configuration dictionary.

        Returns:
            List[Dict]: Ticket type records from the API.

        Raises:
            HaloITSMPluginException: When the API call fails.
        """
        base_url = self._get_base_url(configuration)
        url = f"{base_url}{TICKET_TYPE_ENDPOINT}"
        response = self.halo_helper.api_helper(
            logger_msg="fetching ticket types",
            url=url,
            method="GET",
            headers=self.get_headers(configuration),
            verify=self.ssl_validation,
            proxies=self.proxy,
            configuration=configuration,
            storage=self._get_storage(),
        )
        if isinstance(response, list):
            return response
        return response.get("tickettypes", response.get("result", []))

    # ------------------------------------------------------------------
    # Dynamic configuration fields
    # ------------------------------------------------------------------

    def get_fields(self, name: str, configuration: Dict) -> List[Dict]:
        """Return dynamic field definitions for a given step.

        For 'params': authenticates using the credentials saved in the
        static Authentication step and returns a live Ticket Type
        dropdown fetched from HaloITSM.

        Args:
            name (str): Step name ('params').
            configuration (Dict): Full plugin configuration dictionary.

        Returns:
            List[Dict]: Field definition dicts for the CE config UI.
        """
        fields: List[Dict] = []

        if name == "params":
            try:
                ticket_types = self._fetch_ticket_types(configuration)
                tt_choices = [
                    {
                        "key": t.get("name", f"Type {t.get('id', '')}"),
                        "value": str(t.get("id", "")),
                    }
                    for t in ticket_types
                    if t.get("id") and t.get("name")
                ]
                if tt_choices:
                    saved_id = str(
                        self.halo_helper.get_config_params(
                            configuration, "params"
                        ).get("tickettype_id", "")
                    ).strip()
                    valid_ids = {c["value"] for c in tt_choices}
                    if saved_id and saved_id in valid_ids:
                        default_id = saved_id
                    else:
                        incident_choice = next(
                            (
                                c for c in tt_choices
                                if c["key"].lower() == "incident"
                            ),
                            None,
                        )
                        default_id = (
                            incident_choice["value"]
                            if incident_choice
                            else tt_choices[0]["value"]
                        )
                    fields.append(
                        {
                            "label": "Ticket Type",
                            "key": "tickettype_id",
                            "type": "choice",
                            "choices": tt_choices,
                            "default": default_id,
                            "mandatory": True,
                            "description": (
                                "Select the ticket type to use when creating"
                                " tickets. The list is fetched live from"
                                " HaloITSM. Navigate to Configuration > "
                                " Ticket Types to manage available types."
                            ),
                        }
                    )
            except Exception as exp:
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: Error occurred while fetching"
                        f" ticket types from {PLATFORM_NAME}."
                        f" Error: {exp}"
                    ),
                    details=traceback.format_exc(),
                    resolution=(
                        "Ensure that the configured credentials have"
                        " sufficient permissions to access ticket types"
                        f" on {PLATFORM_NAME}."
                    ),
                )

        return fields

    # ------------------------------------------------------------------
    # Field mapping
    # ------------------------------------------------------------------

    def get_available_fields(self, configuration: Dict) -> List[MappingField]:
        """Return available fields for ticket mapping.

        Fetches field definitions from GET /api/TicketType/{id} based on
        the Ticket Type saved in Configuration Parameters. Falls back to
        a static list when no ticket type is configured or the API call
        fails.

        Args:
            configuration (Dict): Full plugin configuration dictionary.

        Returns:
            List[MappingField]: Field definitions for CE mapping UI.
                The 'Note' field always has updateAble=True for dedup.
        """
        tickettype_id = str(
            self.halo_helper.get_config_params(configuration, "params").get(
                "tickettype_id", ""
            )
        ).strip()

        if tickettype_id:
            try:
                return self._fetch_ticket_type_fields(
                    configuration, tickettype_id
                )
            except Exception as exp:
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: Error occurred while fetching"
                        f" available fields for ticket type '{tickettype_id}'"
                        f" from {PLATFORM_NAME}. Error: {exp}"
                    ),
                    details=traceback.format_exc(),
                    resolution=(
                        "Ensure that the Ticket Type ID is valid and"
                        " the configured credentials have sufficient"
                        " permissions to access ticket type fields"
                        f" on {PLATFORM_NAME}."
                    ),
                )

        return [
            MappingField(
                label="Note",
                value="note_html",
                updateAble=True,
            ),
        ]

    def get_default_mappings(
        self, configuration: Dict
    ) -> Dict[str, List[FieldMapping]]:
        """Return the default field mappings applied to new queues.

        Args:
            configuration (Dict): Full plugin configuration dictionary.

        Returns:
            Dict[str, List[FieldMapping]]: Dict with 'mappings' (used
                on create_task) and 'dedup' (used on update_task) lists.
        """
        return {
            "mappings": [],
            "dedup": [
                FieldMapping(
                    extracted_field="custom_message",
                    destination_field="note_html",
                    custom_message=(
                        "Received new alert/event with Alert/Event ID:"
                        " $id and Alert Name: $alertName in"
                        " Netskope Cloud Exchange."
                    ),
                ),
            ],
        }

    # ------------------------------------------------------------------
    # Ticket operations
    # ------------------------------------------------------------------

    def create_task(
        self,
        alert: Union[Alert, Event],
        mappings: Dict,
        queue: Queue,
    ) -> Task:
        """Create a new ticket on the HaloITSM platform.

        Args:
            alert (Union[Alert, Event]): The triggering alert or event.
            mappings (Dict): Resolved destination field to value mapping.
            queue (Queue): Selected CE queue; queue.value holds the
                HaloITSM team name.

        Returns:
            Task: Created task with ticket ID, status, and deep link.

        Raises:
            HaloITSMPluginException: When the API call fails.
        """
        if not mappings:
            err_msg = "No mappings found in Queue Configuration."
            self.logger.error(
                f"{self.log_prefix}: {err_msg} Queue mapping "
                f"is required to create a ticket on {PLATFORM_NAME}."
            )
            raise HaloITSMPluginException(err_msg)

        base_url = self._get_base_url(self.configuration)
        url = f"{base_url}{TICKETS_ENDPOINT}"
        event_type = "Event" if hasattr(alert, "eventType") else "Alert"
        try:
            tickettype_id = int(
                self.halo_helper.get_config_params(
                    self.configuration, "params"
                ).get("tickettype_id", 1)
            )
        except (ValueError, TypeError):
            tickettype_id = 1

        self.logger.info(
            f"{self.log_prefix}: Creating a ticket for {event_type}"
            f" ID '{alert.id}' on {PLATFORM_NAME}"
        )

        # Resolve Assigned Agent email to integer linked_agent_id before
        # building the payload. Raw integer IDs are passed through directly.
        agent_value = str(mappings.get("agent_id", "")).strip()
        resolved_agent = None
        if agent_value:
            resolved_agent = self._resolve_agent_id(agent_value)
            if resolved_agent is not None:
                mappings["agent_id"] = resolved_agent
            else:
                mappings.pop("agent_id", None)

        # Extract status_name before building the payload.
        # status_id is not sent during creation (HaloITSM ignores it);
        # instead it is applied via a follow-up POST after the ticket exists.
        status_name = str(mappings.get("status_id", "")).strip()

        payload: Dict = {"tickettype_id": tickettype_id}
        custom_fields: List[Dict] = []
        for field_name, field_value in mappings.items():
            if field_name in ("note_html", "status_id"):
                continue
            if field_value is None or field_value == "":
                continue
            if field_name in DICT_FIELD_WRAPPERS:
                if isinstance(field_value, dict):
                    payload[field_name] = field_value
                else:
                    payload[field_name] = {
                        DICT_FIELD_WRAPPERS[field_name]: str(field_value)
                    }
            elif field_name not in STANDARD_POST_FIELDS:
                custom_fields.append(
                    {"name": field_name, "value": str(field_value)}
                )
            else:
                resolved = self._resolve_enum_value(field_name, field_value)
                payload[field_name] = (
                    resolved
                    if isinstance(resolved, (int, str))
                    else str(resolved)
                )
        if custom_fields:
            payload["customfields"] = custom_fields
        if queue and queue.value not in ("default", ""):
            payload["team"] = queue.value

        try:
            response = self.halo_helper.api_helper(
                logger_msg=(
                    f"creating a ticket for {event_type}"
                    f" ID '{alert.id}' on {PLATFORM_NAME}"
                ),
                url=url,
                method="POST",
                headers=self.get_headers(self.configuration),
                verify=self.ssl_validation,
                proxies=self.proxy,
                configuration=self.configuration,
                storage=self._get_storage(),
                json=[payload],
                resolution_override={
                    400: (
                        "Ensure that the queue mapping is correct and"
                        " valid values are passed. For integer fields"
                        " provide the numeric ID from HaloITSM, not the"
                        " display name (except Impact and Urgency)."
                        " Check the HaloITSM platform for the correct IDs"
                        " and update the queue mapping."
                    ),
                },
            )
            # POST /api/tickets returns either a list [{...}] or a dict
            if isinstance(response, list):
                response = response[0] if response else {}
            ticket_id = str(response.get("id", ""))
            ticket_link = f"{base_url}/tickets?id={ticket_id}&showmenu=true"
            task = Task(
                id=ticket_id,
                status=TaskStatus.NEW,
                link=ticket_link,
            )

            # Apply the requested status via a follow-up update call.
            # HaloITSM always creates tickets with the default status and
            # ignores status_id in the creation payload, so we POST a
            # status-only update immediately after creation.
            if status_name and ticket_id:
                try:
                    self._update_ticket_status(
                        task=task,
                        ticket_id=ticket_id,
                        status_name=status_name,
                        event_type=event_type,
                        alert_id=alert.id,
                    )
                except HaloITSMPluginException as exp:
                    self.logger.error(
                        f"{self.log_prefix}: Failed to set status"
                        f" '{status_name}' on ticket '{ticket_id}'."
                        f" Error: {exp}"
                    )

            note_html = str(mappings.get("note_html", "")).strip()
            if note_html and ticket_id:
                try:
                    self._add_note(
                        task=task,
                        ticket_id=ticket_id,
                        note_html=note_html,
                        outcome=CREATE_NOTE_OUTCOME,
                        event_type=event_type,
                        alert_id=alert.id,
                    )
                except HaloITSMPluginException as exp:
                    self.logger.error(
                        f"{self.log_prefix}: Failed to add note to"
                        f" ticket '{ticket_id}'. Error: {exp}"
                    )
            if (
                resolved_agent is not None
                and ticket_id
                and task.status != TaskStatus.DELETED
            ):
                self._set_task_assignee(
                    task,
                    self._agent_id_to_email(agent_value, resolved_agent),
                )

            self.logger.info(
                f"{self.log_prefix}: Successfully created ticket"
                f" with ID '{ticket_id}' on {PLATFORM_NAME} for"
                f" {event_type} ID '{alert.id}'."
            )
            return task
        except HaloITSMPluginException:
            raise
        except Exception as exp:
            err_msg = (
                f"Error occurred while creating a ticket"
                f" for {event_type} ID '{alert.id}'"
                f" on {PLATFORM_NAME}."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {exp}",
                details=traceback.format_exc(),
                resolution=(
                    "Ensure that the ticket payload is valid and the"
                    " configured credentials have sufficient permissions"
                    f" to create tickets on {PLATFORM_NAME}."
                ),
            )
            raise HaloITSMPluginException(err_msg)

    def _add_note(
        self,
        task: Task,
        ticket_id: str,
        note_html: str,
        outcome: str,
        event_type: str,
        alert_id: str,
    ) -> None:
        """Add a note to a HaloITSM ticket via POST /api/Actions.

        HaloITSM does not support adding notes through the tickets API.
        Notes must be posted to the Actions endpoint with ticket_id,
        note_html and a mandatory outcome label.

        On 200/201: logs success.
        On 404: marks task as DELETED via _mark_task_deleted.
        On other errors: raises HaloITSMPluginException.

        Args:
            task: CE task (used to mark DELETED on 404).
            ticket_id: HaloITSM ticket ID to add the note to.
            note_html: HTML-formatted note content.
            outcome: Action outcome label (mandatory in HaloITSM).
            event_type: "Alert" or "Event" (for log messages).
            alert_id: CE alert/event ID (for log messages).

        Raises:
            HaloITSMPluginException: On non-2xx, non-404 API errors.
        """
        base_url = self._get_base_url(self.configuration)
        url = f"{base_url}{ACTIONS_ENDPOINT}"
        logger_msg = (
            f"adding note to ticket '{ticket_id}' for"
            f" {event_type} ID '{alert_id}' on {PLATFORM_NAME}"
        )
        response = self.halo_helper.api_helper(
            logger_msg=logger_msg,
            url=url,
            method="POST",
            headers=self.get_headers(self.configuration),
            verify=self.ssl_validation,
            proxies=self.proxy,
            configuration=self.configuration,
            storage=self._get_storage(),
            is_handle_error_required=False,
            json=[
                {
                    "ticket_id": int(ticket_id),
                    "note_html": note_html,
                    "outcome": outcome,
                }
            ],
        )
        if response.status_code in [200, 201]:
            self.logger.info(
                f"{self.log_prefix}: Successfully updated"
                f" ticket '{ticket_id}' on {PLATFORM_NAME}."
            )
        elif response.status_code == 404:
            self.logger.info(
                f"{self.log_prefix}: Ticket '{ticket_id}' no longer"
                f" exists on {PLATFORM_NAME}."
            )
            self._mark_task_deleted(task)
        else:
            self.halo_helper.handle_error(response, logger_msg)

    def _mark_task_deleted(self, task: Task) -> Task:
        """Mark a CE task as DELETED and update its updatedValues.

        Called whenever HaloITSM returns 404 for a ticket, indicating it
        no longer exists on the platform.

        Args:
            task (Task): CE task to mark as deleted.

        Returns:
            Task: Task with status set to TaskStatus.DELETED.
        """
        if (
            task.updatedValues
            and task.updatedValues.status
            and task.updatedValues.status != TaskStatus.DELETED
        ):
            task.updatedValues.oldStatus = task.updatedValues.status
            task.updatedValues.status = TaskStatus.DELETED
        else:
            old = (
                task.updatedValues.status
                if task.updatedValues
                else task.status
            )
            task.updatedValues = UpdatedTaskValues(
                status=TaskStatus.DELETED, oldStatus=old
            )
        task.status = TaskStatus.DELETED
        return task

    def _update_ticket_status(
        self,
        task: Task,
        ticket_id: str,
        status_name: str,
        event_type: str,
        alert_id: str,
        team_name: str = "",
    ) -> Task:
        """POST a combined status and/or team update for a ticket.

        Builds a single POST /api/tickets payload that may contain
        status_id (when status_name resolves) and team (when team_name is
        provided). If neither resolves the task is returned unchanged.

        On 200/201: updates task.status when status was included.
        On 404: marks the task as DELETED via _mark_task_deleted.
        On other errors: raises HaloITSMPluginException.

        Args:
            task (Task): CE task to update.
            ticket_id (str): HaloITSM ticket ID.
            status_name (str): Human-readable status name (e.g. "Closed").
                Pass empty string to skip status update.
            event_type (str): "Alert" or "Event" for log messages.
            alert_id (str): CE alert/event ID for log messages.
            team_name (str): Team name to assign; empty string to skip.

        Returns:
            Task: Task with updated status when applicable.

        Raises:
            HaloITSMPluginException: On non-2xx, non-404 API errors.
        """
        ticket_payload: Dict = {"id": int(ticket_id)}

        if status_name:
            status_map = self._fetch_status_map(search=status_name)
            resolved_status_id = next(
                (
                    sid
                    for sid, sname in status_map.items()
                    if sname.strip().lower() == status_name.strip().lower()
                ),
                None,
            )
            if resolved_status_id is None:
                self.logger.info(
                    f"{self.log_prefix}: Status '{status_name}' not found"
                    f" for ticket '{ticket_id}'. Skipping status update."
                )
            else:
                ticket_payload["status_id"] = resolved_status_id

        if team_name:
            ticket_payload["team"] = team_name

        if len(ticket_payload) == 1:
            return task

        parts = []
        if "status_id" in ticket_payload:
            parts.append(f"status to '{status_name}'")
        if "team" in ticket_payload:
            parts.append(f"team to '{team_name}'")
        logger_msg = (
            f"updating {' and '.join(parts)} on ticket '{ticket_id}'"
            f" for {event_type} ID '{alert_id}' on {PLATFORM_NAME}"
        )
        base_url = self._get_base_url(self.configuration)
        url = f"{base_url}{TICKETS_ENDPOINT}"
        try:
            response = self.halo_helper.api_helper(
                logger_msg=logger_msg,
                url=url,
                method="POST",
                headers=self.get_headers(self.configuration),
                verify=self.ssl_validation,
                proxies=self.proxy,
                configuration=self.configuration,
                storage=self._get_storage(),
                is_handle_error_required=False,
                json=[ticket_payload],
            )
            if response.status_code in [200, 201]:
                if "status_id" in ticket_payload:
                    task.status = status_name
            elif response.status_code == 404:
                self._mark_task_deleted(task)
                self.logger.info(
                    f"{self.log_prefix}: Ticket with ID '{ticket_id}' no "
                    f"longer exists on {PLATFORM_NAME}."
                )
            else:
                self.halo_helper.handle_error(response, logger_msg)
        except HaloITSMPluginException:
            raise
        except Exception as exp:
            self.logger.error(
                f"{self.log_prefix}: Error while updating"
                f" ticket '{ticket_id}'. Error: {exp}",
                details=traceback.format_exc(),
            )
        return task

    def _update_ticket_agent(
        self,
        task: Task,
        ticket_id: str,
        agent_id: int,
        event_type: str,
        alert_id: str,
    ) -> Task:
        """Update the assigned agent on an existing HaloITSM ticket.

        Posts POST /api/tickets [{id, agent_id}] to reassign the ticket.
        On 404 marks the task as DELETED. On other errors raises
        HaloITSMPluginException.

        Args:
            task (Task): CE task to update.
            ticket_id (str): HaloITSM ticket ID.
            agent_id (int): Resolved integer agent ID.
            event_type (str): "Alert" or "Event" for log messages.
            alert_id (str): CE alert/event ID for log messages.

        Returns:
            Task: Task unchanged (agent update does not affect CE status).

        Raises:
            HaloITSMPluginException: On non-2xx, non-404 API errors.
        """
        base_url = self._get_base_url(self.configuration)
        url = f"{base_url}{TICKETS_ENDPOINT}"
        logger_msg = (
            f"updating assigned agent on ticket '{ticket_id}'"
            f" for {event_type} ID '{alert_id}' on {PLATFORM_NAME}"
        )
        try:
            response = self.halo_helper.api_helper(
                logger_msg=logger_msg,
                url=url,
                method="POST",
                headers=self.get_headers(self.configuration),
                verify=self.ssl_validation,
                proxies=self.proxy,
                configuration=self.configuration,
                storage=self._get_storage(),
                is_handle_error_required=False,
                json=[{"id": int(ticket_id), "agent_id": agent_id}],
            )
            if response.status_code in [200, 201]:
                self.logger.info(
                    f"{self.log_prefix}: Successfully updated assigned"
                    f" agent on ticket '{ticket_id}' on {PLATFORM_NAME}."
                )
            elif response.status_code == 404:
                self._mark_task_deleted(task)
                self.logger.info(
                    f"{self.log_prefix}: Ticket with ID '{ticket_id}'"
                    f" no longer exists on {PLATFORM_NAME}."
                )
            else:
                self.halo_helper.handle_error(response, logger_msg)
        except HaloITSMPluginException:
            raise
        except Exception as exp:
            self.logger.error(
                f"{self.log_prefix}: Error while updating assigned"
                f" agent on ticket '{ticket_id}'. Error: {exp}",
                details=traceback.format_exc(),
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
        """Update an existing ticket on the HaloITSM platform.

        upsert_task=True  → posts the mapped status_id to HaloITSM via
                            POST /api/tickets and reads back the new status,
                            then adds a work note.
        upsert_task=False → posts a note to HaloITSM via POST /api/Actions.
                            Falls back to a default message when note_html
                            is not mapped.

        Args:
            task (Task): Existing CE task containing the ticket ID.
            alert (Union[Alert, Event]): The new triggering alert/event.
            mappings (Dict): Resolved field to value mapping.
            queue (Queue): Selected CE queue; queue.value is sent as team
            on upsert.
            upsert_task (bool): When True posts the mapped status rather
                than a dedup note.

        Returns:
            Task: Task with status, severity and updatedValues reflected
                from the HaloITSM response.

        Raises:
            HaloITSMPluginException: When the API call fails.
        """
        event_type = "Event" if hasattr(alert, "eventType") else "Alert"

        if upsert_task:
            if task.status != TaskStatus.DELETED:
                status_name = str(mappings.get("status_id", "")).strip()
                team_name = (
                    queue.value
                    if queue and queue.value not in ("default", "")
                    else ""
                )
                if status_name or team_name:
                    try:
                        self._update_ticket_status(
                            task=task,
                            ticket_id=task.id,
                            status_name=status_name,
                            event_type=event_type,
                            alert_id=alert.id,
                            team_name=team_name,
                        )
                    except HaloITSMPluginException as exp:
                        self.logger.error(
                            f"{self.log_prefix}: Failed to update ticket"
                            f" '{task.id}'. Error: {exp}"
                        )

                agent_value = str(mappings.get("agent_id", "")).strip()
                if agent_value:
                    resolved_agent = self._resolve_agent_id(agent_value)
                    if resolved_agent is not None:
                        try:
                            self._update_ticket_agent(
                                task=task,
                                ticket_id=task.id,
                                agent_id=resolved_agent,
                                event_type=event_type,
                                alert_id=alert.id,
                            )
                            if task.status != TaskStatus.DELETED:
                                self._set_task_assignee(
                                    task,
                                    self._agent_id_to_email(
                                        agent_value, resolved_agent
                                    ),
                                )
                        except HaloITSMPluginException as exp:
                            self.logger.error(
                                f"{self.log_prefix}: Failed to update"
                                f" assigned agent on ticket '{task.id}'."
                                f" Error: {exp}"
                            )

                note_html = str(mappings.get("note_html", "")).strip()
                if not note_html:
                    note_html = (
                        f"Received new {event_type.lower()} with"
                        f" Alert/Event ID: {alert.id} in"
                        " Netskope Cloud Exchange."
                    )
                try:
                    self._add_note(
                        task=task,
                        ticket_id=task.id,
                        note_html=note_html,
                        outcome=CREATE_NOTE_OUTCOME,
                        event_type=event_type,
                        alert_id=alert.id,
                    )
                except Exception as exp:
                    self.logger.error(
                        f"{self.log_prefix}: Failed to add note"
                        f" to ticket '{task.id}' after status"
                        f" update. Error: {exp}"
                    )
        else:
            note_html = str(mappings.get("note_html", "")).strip()
            if not note_html:
                note_html = (
                    f"Received new {event_type.lower()} with"
                    f" Alert/Event ID: {alert.id} in"
                    " Netskope Cloud Exchange."
                )
            self._add_note(
                task=task,
                ticket_id=task.id,
                note_html=note_html,
                outcome=CREATE_NOTE_OUTCOME,
                event_type=event_type,
                alert_id=alert.id,
            )
        return task

    # ------------------------------------------------------------------
    # State synchronisation
    # ------------------------------------------------------------------

    def _fetch_status_map(
        self, search: Optional[str] = None
    ) -> Dict[int, str]:
        """Fetch HaloITSM statuses and return an id-to-name mapping.

        When *search* is provided the request includes ``?search=<name>`` so
        only matching statuses are returned — avoids loading the full list
        when resolving a single status name.  Called without *search* from
        sync_states to get the complete map for the whole batch.

        Returns an empty dict on failure so callers can fall back gracefully.

        Args:
            search (Optional[str]): Status name to filter by. When None the
                full status list is fetched.

        Returns:
            Dict[int, str]: Mapping of HaloITSM status_id to status name.
        """
        base_url = self._get_base_url(self.configuration)
        url = f"{base_url}{STATUS_ENDPOINT}"
        logger_msg = (
            f"fetching status '{search}' from {PLATFORM_NAME}"
            if search
            else f"fetching status list from {PLATFORM_NAME}"
        )
        params = {"search": search} if search else {}
        try:
            response = self.halo_helper.api_helper(
                logger_msg=logger_msg,
                url=url,
                method="GET",
                params=params,
                headers=self.get_headers(self.configuration),
                verify=self.ssl_validation,
                proxies=self.proxy,
                configuration=self.configuration,
                storage=self._get_storage(),
            )
            statuses = (
                response
                if isinstance(response, list)
                else response.get("statuses", response.get("result", []))
            )
            return {
                int(s["id"]): s.get("name", "")
                for s in statuses
                if isinstance(s, dict) and s.get("id") and s.get("name")
            }
        except Exception as exp:
            self.logger.error(
                f"{self.log_prefix}: Unable to fetch status"
                f"{f' {repr(search)}' if search else ' list'} from"
                f" {PLATFORM_NAME}. Error: {exp}"
            )
            return {}

    def _agent_id_to_email(
        self, agent_value: str, resolved_agent: int
    ) -> Optional[str]:
        """Return the email for a resolved agent_id, or None if not found.

        When agent_value is an email it is returned as-is. When it is a raw
        integer string the cache is checked for a reverse mapping; on a miss
        _fetch_all_agent_users is called to populate the cache and the lookup
        is retried. Returns None when no email is found so that CE stores null
        instead of a bare integer ID.

        Args:
            agent_value (str): Original mapping value
            (email or integer string).
            resolved_agent (int): The integer agent_id already resolved by
                _resolve_agent_id.

        Returns:
            Optional[str]: Email address, or None when not resolvable.
        """
        try:
            int(agent_value)
        except ValueError:
            return agent_value

        storage = self._get_storage()
        cache = storage.get(AGENT_CACHE_KEY, {})
        email = next(
            (e for e, aid in cache.items() if aid == resolved_agent), None
        )
        if email is None:
            cache = self._fetch_all_agent_users(storage)
            email = next(
                (e for e, aid in cache.items() if aid == resolved_agent), None
            )
        return email

    def _set_task_assignee(self, task: Task, assignee: Optional[str]) -> None:
        """Set assignee and oldAssignee on task.updatedValues.

        Reads the previous assignee from task.dataItem.rawData and writes
        both oldAssignee and assignee into the existing updatedValues object,
        or creates a new one when none exists yet.

        Args:
            task (Task): CE task to mutate.
            assignee (Optional[str]): New assignee value (email or ID string).
                Pass None to leave assignee unchanged while still recording
                oldAssignee.
        """
        old_assignee = (
            task.dataItem.rawData.get("assignee", None)
            if task.dataItem and task.dataItem.rawData
            else None
        )
        if task.updatedValues:
            task.updatedValues.oldAssignee = old_assignee
        else:
            task.updatedValues = UpdatedTaskValues(
                assignee=None,
                oldAssignee=old_assignee,
            )

        if assignee:
            task.updatedValues.assignee = assignee

    def _update_task_values(
        self,
        task: Task,
        status_name: Optional[str],
        priority_id: Optional[int],
        agent_id: Optional[int] = None,
    ) -> Task:
        """Apply synced HaloITSM values to a CE Task object.

        Populates task.updatedValues with old and new status, severity,
        and assignee. Assignee is resolved from the agent_id via a reverse
        lookup in the agent email cache — only emails previously looked up
        during create/update are available for reverse resolution.

        status_name is the raw HaloITSM status name string (e.g. "New",
        "Closed"). CE core translates it to a TaskStatus enum value using
        the mappings defined in get_default_custom_mappings(). When the
        name is absent or unrecognised CE falls back to TaskStatus.OTHER.

        Args:
            task (Task): CE task to update.
            status_name (Optional[str]): HaloITSM status name resolved
                from the status_id returned by the ticket API.
            priority_id (Optional[int]): HaloITSM priority_id from API
                mapped to CE Severity.
            agent_id (Optional[int]): HaloITSM agent_id from the ticket
                response used to resolve the assignee email.

        Returns:
            Task: Task with status, severity, and updatedValues set.
        """
        new_status = status_name or TaskStatus.OTHER
        new_severity = SEVERITY_MAPPINGS.get(priority_id, Severity.OTHER)
        task.status = new_status
        task.severity = new_severity

        assignee_email = None
        if agent_id is not None:
            storage = self._get_storage()
            cache = storage.get(AGENT_CACHE_KEY, {})
            assignee_email = next(
                (email for email, aid in cache.items() if aid == agent_id),
                None,
            )
            if assignee_email is None:
                cache = self._fetch_all_agent_users(storage)
                assignee_email = next(
                    (email for email, aid in cache.items() if aid == agent_id),
                    None,
                )
        self._set_task_assignee(task, assignee_email)

        return task

    def sync_states(self, tasks: List[Task]) -> List[Task]:
        """Sync ticket status, severity and assignee from HaloITSM.

        Fetches each tracked ticket individually via GET /api/tickets/{id}.
        This avoids the issue where HaloITSM ignores comma-separated id
        filters and returns all platform tickets, causing massive responses
        that fail JSON parsing. The api_helper handles 429 rate-limit
        responses automatically (Retry-After header, up to MAX_RETRIES).
        Individual fetch failures are logged and skipped so one bad ticket
        does not abort the entire sync cycle.

        Args:
            tasks (List[Task]): List of CE tasks to sync.

        Returns:
            List[Task]: Tasks with updated state fields.
        """
        total = len(tasks)
        base_url = self._get_base_url(self.configuration)
        url = f"{base_url}{TICKETS_ENDPOINT}"
        headers = self.get_headers(self.configuration)

        self.logger.info(
            f"{self.log_prefix}: Syncing status for {total}"
            f" ticket(s) with {PLATFORM_NAME}."
        )

        # Fetch the full status list once so all tickets in this sync
        # share the same id->name lookup without repeated API calls.
        status_map = self._fetch_status_map()

        for task in tasks:
            task_id = task.id
            logger_msg = f"getting ticket '{task_id}' from {PLATFORM_NAME}"
            try:
                response = self.halo_helper.api_helper(
                    logger_msg=logger_msg,
                    url=f"{url}/{task_id}",
                    method="GET",
                    headers=headers,
                    verify=self.ssl_validation,
                    proxies=self.proxy,
                    configuration=self.configuration,
                    storage=self._get_storage(),
                    is_handle_error_required=False,
                )
                if response.status_code in [200, 201]:
                    parsed = self.halo_helper.parse_response(
                        response, logger_msg
                    )
                    ticket = None
                    if isinstance(parsed, dict) and parsed.get("id"):
                        ticket = parsed
                    elif isinstance(parsed, list) and parsed:
                        ticket = parsed[0]

                    if ticket:
                        raw_status_id = ticket.get("status_id")
                        raw_priority_id = ticket.get("priority_id")
                        raw_agent_id = ticket.get("agent_id")
                        try:
                            status_id = (
                                int(raw_status_id)
                                if raw_status_id is not None
                                else None
                            )
                        except (ValueError, TypeError):
                            status_id = None
                        try:
                            priority_id = (
                                int(raw_priority_id)
                                if raw_priority_id is not None
                                else None
                            )
                        except (ValueError, TypeError):
                            priority_id = None
                        try:
                            agent_id = (
                                int(raw_agent_id)
                                if raw_agent_id is not None
                                else None
                            )
                        except (ValueError, TypeError):
                            agent_id = None
                        status_name = (
                            status_map.get(status_id)
                            if status_id is not None
                            else None
                        )
                        self._update_task_values(
                            task, status_name, priority_id, agent_id
                        )
                elif response.status_code == 404:
                    self._mark_task_deleted(task)
            except HaloITSMPluginException:
                self.logger.error(
                    f"{self.log_prefix}: Failed to fetch ticket"
                    f" '{task_id}' from {PLATFORM_NAME}. Skipping"
                    " status update for this cycle."
                )
            except Exception as exp:
                err_msg = (
                    f"Error occurred while getting ticket '{task_id}'"
                    f" from {PLATFORM_NAME}."
                )
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg} Error: {exp}",
                    details=traceback.format_exc(),
                )

        self.logger.info(
            f"{self.log_prefix}: Successfully synced"
            f" {total} ticket(s) with {PLATFORM_NAME}."
        )
        return tasks

    # ------------------------------------------------------------------
    # Queues
    # ------------------------------------------------------------------

    def get_queues(self) -> List[Queue]:
        """Fetch HaloITSM teams and return them as CE Queue objects.

        Queries GET /api/Team with pagination. A 'Default Team' sentinel
        queue is always prepended so business rules can opt out of
        team-based routing. Returns the sentinel-only list on errors.

        Returns:
            List[Queue]: Queues starting with 'Default Team' followed by
                all teams returned by HaloITSM.
        """
        default_queue = [Queue(label="Default Team", value="default")]
        base_url = self._get_base_url(self.configuration)
        url = f"{base_url}{TEAM_ENDPOINT}"
        log_msg = f"fetching list of {PLATFORM_NAME} teams as queues"
        try:
            params = {
                "pageinate": "true",
                "page_size": PAGE_SIZE,
                "page_no": 1,
            }
            all_teams: List[Dict] = []
            page = 1

            while True:
                params["page_no"] = page
                response = self.halo_helper.api_helper(
                    logger_msg=log_msg,
                    url=url,
                    method="GET",
                    params=params,
                    headers=self.get_headers(self.configuration),
                    verify=self.ssl_validation,
                    proxies=self.proxy,
                    configuration=self.configuration,
                    storage=self._get_storage(),
                )

                batch: List[Dict] = (
                    response
                    if isinstance(response, list)
                    else response.get("teams", response.get("result", []))
                )
                all_teams.extend(batch)
                if len(batch) < PAGE_SIZE:
                    break
                page += 1

            if not all_teams:
                self.logger.debug(
                    f"{self.log_prefix}: No teams returned from"
                    f" {PLATFORM_NAME}. Returning default queue only."
                )
                return default_queue

            queue_list = [
                Queue(
                    label=team.get("name", ""),
                    value=team.get("name", ""),
                )
                for team in all_teams
                if team.get("name")
            ]
            return default_queue + queue_list

        except (HaloITSMPluginException, Exception) as exp:
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Error occurred while fetching"
                    f" teams as queues from {PLATFORM_NAME}. Error: {exp}"
                ),
                details=traceback.format_exc(),
                resolution=(
                    "Ensure that the configured credentials have sufficient"
                    " permissions to access the Teams API on"
                    f" {PLATFORM_NAME}. Note: agent login is required for"
                    " the Teams API when using Client Credentials"
                    " authentication."
                ),
            )
            return default_queue

    # ------------------------------------------------------------------
    # Custom field mappings (status / severity tabs in CE UI)
    # ------------------------------------------------------------------

    def get_default_custom_mappings(
        self,
    ) -> List[CustomFieldsSectionWithMappings]:
        """Return default custom field mappings for status synchronisation.

        Defines how CE TaskStatus values map to HaloITSM status names.
        The mapped_value for each entry is the exact status name as it
        appears in HaloITSM (case-insensitive match used during sync).
        Users can adjust these values to match their tenant's status names
        via the CE UI mapping configuration.

        Returns:
            List[CustomFieldsSectionWithMappings]: Status section with
                pre-populated HaloITSM status name mappings.
        """
        return [
            CustomFieldsSectionWithMappings(
                section="status",
                event_field="status",
                destination_label=PLATFORM_NAME,
                field_mappings=[
                    CustomFieldMapping(
                        name="New",
                        mapped_value="New",
                        is_default=True,
                    ),
                    CustomFieldMapping(
                        name="In Progress",
                        mapped_value="In Progress",
                        is_default=True,
                    ),
                    CustomFieldMapping(
                        name="On Hold",
                        mapped_value="On Hold",
                        is_default=True,
                    ),
                    CustomFieldMapping(
                        name="Closed",
                        mapped_value="Closed",
                        is_default=True,
                    ),
                    CustomFieldMapping(
                        name="Deleted",
                        mapped_value="",
                        is_default=True,
                    ),
                    CustomFieldMapping(
                        name="Other",
                        mapped_value="",
                        is_default=True,
                    ),
                ],
            ),
        ]
