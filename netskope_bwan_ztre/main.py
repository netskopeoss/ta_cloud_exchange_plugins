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

CRE Netskope Borderless WAN Plugin.
"""

import ipaddress
import traceback
from typing import Any, Callable, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

from netskope.common.utils import AlertsHelper, resolve_secret
from netskope.integrations.crev2.models import Action, ActionWithoutParams
from netskope.integrations.crev2.plugin_base import (
    ActionResult,
    Entity,
    PluginBase,
    ValidationResult,
)

from .utils.constants import (
    ACTION_CONTEXT,
    ADDRESS_GROUPS_ENDPOINT,
    ADDRESS_GROUP_PARAM,
    ADDRESS_OBJECTS_ENDPOINT,
    ADDRESS_OBJECT_ENDPOINT,
    ADDRESS_OBJECT_TYPE,
    ADD_TO_ADDRESS_GROUP,
    ADD_TO_ADDRESS_GROUP_LABEL,
    API_TOKEN_PARAM,
    BUCKET_CREATE,
    BUCKET_EXISTING,
    CONFIG_CONTEXT,
    CREATE_NEW_ADDRESS_GROUP_LABEL,
    CREATE_NEW_ADDRESS_GROUP_VALUE,
    DESCRIPTION_PARAM,
    IP_ADDRESS_PARAM,
    IP_PARAM_LABEL,
    MAX_ADDRESS_OBJECTS_PER_GROUP,
    MODULE_NAME,
    NEW_ADDRESS_GROUP_NAME_LABEL,
    NEW_ADDRESS_GROUP_NAME_PARAM,
    NO_ACTION,
    NO_ACTION_LABEL,
    OUTCOME_ADDED,
    OUTCOME_ALREADY_EXISTS,
    OUTCOME_EXISTS_ON_TENANT,
    OUTCOME_FAILED,
    OUTCOME_LIMIT_EXCEEDED,
    OUTCOME_NOT_FOUND,
    OUTCOME_REMOVED,
    PLATFORM_NAME,
    PLUGIN_VERSION,
    RECOVERY_ALREADY_EXISTS,
    RECOVERY_CREATED,
    RECOVERY_CREATED_AFTER_RETRY,
    REMOVE_FROM_ADDRESS_GROUP,
    REMOVE_FROM_ADDRESS_GROUP_LABEL,
    RESOLUTION_ADDRESS_GROUP_LIMIT,
    RESOLUTION_ADDRESS_GROUP_NOT_FOUND,
    RESOLUTION_ADD_IP,
    RESOLUTION_BASE_URL,
    RESOLUTION_CREATE_ADDRESS_GROUP,
    RESOLUTION_EXISTS_ON_TENANT,
    RESOLUTION_FETCH_ADDRESS_GROUPS,
    RESOLUTION_FETCH_ADDRESS_OBJECTS,
    RESOLUTION_INVALID_IP,
    RESOLUTION_NEW_ADDRESS_GROUP,
    RESOLUTION_NO_ADDRESS_GROUPS,
    RESOLUTION_NO_IP,
    RESOLUTION_REMOVE_IP,
    RESOLUTION_REVERT_ADDRESS_GROUP_NOT_FOUND,
    RESOLUTION_TENANT,
    RESOLUTION_UNSUPPORTED_ACTION,
    REVERTIBLE_ACTIONS,
    SUPPORTED_ACTIONS,
    TENANT_CONTEXT,
    VALIDATION_PAGE_SIZE,
    VALIDATION_SUCCESS_MSG,
)
from .utils.helper import (
    NetskopeBwanFatalAPIException,
    NetskopeBwanPluginException,
    NetskopeBwanPluginHelper,
)


class NetskopeBwanPlugin(PluginBase):
    """Netskope Borderless WAN CRE plugin implementation.

    The plugin is action-only. It adds IPv4 addresses and IPv4 CIDR
    ranges to Address Groups and removes them from Address Groups on
    the Netskope Borderless WAN platform.
    """

    def __init__(self, name, *args, **kwargs):
        """Initialize the plugin.

        Args:
            name (str): Configuration name.
        """
        super().__init__(name, *args, **kwargs)
        self.plugin_name, self.plugin_version = self._get_plugin_info()
        self.log_prefix = f"{MODULE_NAME} {self.plugin_name}"
        if name:
            self.log_prefix = f"{self.log_prefix} [{name}]"
        # Base URL and Auth Token resolved from the tenant, per tenant.
        self._tenant_credentials: Dict[str, Tuple[str, str]] = {}
        self.bwan_helper = NetskopeBwanPluginHelper(
            logger=self.logger,
            log_prefix=self.log_prefix,
            plugin_name=self.plugin_name,
            plugin_version=self.plugin_version,
        )
        # CE passes {"id": ..., "params": Action} dicts to
        # execute_actions so per-record failures can be reported
        # through ActionResult.failed_action_ids.
        self.provide_action_id = True

    def _get_plugin_info(self) -> tuple:
        """Get plugin name and version from metadata.

        Returns:
            tuple: Tuple of plugin's name and version fetched from
                metadata.
        """
        try:
            metadata_json = NetskopeBwanPlugin.metadata
            plugin_name = metadata_json.get("name", PLATFORM_NAME)
            plugin_version = metadata_json.get("version", PLUGIN_VERSION)
            return (plugin_name, plugin_version)
        except Exception as exp:
            self.logger.error(
                message=(
                    f"{MODULE_NAME} {PLATFORM_NAME}: Error occurred while "
                    f"getting plugin details. Error: {exp}"
                ),
                details=traceback.format_exc(),
            )
        return (PLATFORM_NAME, PLUGIN_VERSION)

    def get_entities(self) -> list[Entity]:
        """Get available entities.

        The plugin is action-only and does not define any entity. A
        single empty placeholder entity is returned, following the
        action-only Silverfort CRE plugin.

        Returns:
            list[Entity]: Placeholder entity list.
        """
        return [Entity(name="", fields=[])]

    def fetch_records(self, entity: str) -> list:
        """Fetch records from Netskope Borderless WAN.

        The plugin is action-only and does not fetch any records.

        Args:
            entity (str): Entity name.

        Returns:
            list: Empty list.
        """
        return []

    def update_records(self, entity: str, records: list[dict]) -> list[dict]:
        """Update records from Netskope Borderless WAN.

        The plugin is action-only and does not update any records.

        Args:
            entity (str): Entity name.
            records (list[dict]): Records to update.

        Returns:
            list[dict]: Empty list.
        """
        return []

    # ------------------------------------------------------------------ #
    # Configuration helpers
    # ------------------------------------------------------------------ #
    def get_types_to_pull(self, data_type: str) -> List[str]:
        """Get the Netskope Borderless WAN Tenant data types to pull.

        CE calls this for every active CRE configuration of a Netskope
        tenant to schedule the tenant's common pull tasks. The plugin is
        action-only and does not need any tenant data, hence nothing is
        pulled for it.

        Args:
            data_type (str): Type of data ('alerts' or 'events').

        Returns:
            List[str]: Empty list.
        """
        return []

    def _get_tenant(self, configuration: Dict):
        """Get the Netskope Borderless WAN Tenant of the plugin.

        During validation, CE passes the tenant selected in Basic
        Information as configuration['tenant']. Otherwise, the tenant
        linked to this plugin configuration is used.

        Args:
            configuration (Dict): Configuration parameters.

        Returns:
            Tenant: Netskope Borderless WAN Tenant.

        Raises:
            NetskopeBwanPluginException: When the tenant could not be
                found.
        """
        tenant_name = None
        if isinstance(configuration, dict):
            tenant_name = configuration.get("tenant")
        err_msg = (
            f"Error occurred while getting the {PLATFORM_NAME} Tenant "
            "configuration."
        )
        try:
            helper = AlertsHelper()
            if tenant_name:
                tenant = helper.get_tenant(tenant_name)
            else:
                tenant = helper.get_tenant_crev2(self.name)
        except Exception as exp:
            err_msg = f"{err_msg} Error: {exp}"
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=traceback.format_exc(),
                resolution=RESOLUTION_TENANT,
            )
            raise NetskopeBwanPluginException(err_msg)
        if not isinstance(getattr(tenant, "parameters", None), dict):
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                resolution=RESOLUTION_TENANT,
            )
            raise NetskopeBwanPluginException(err_msg)
        return tenant

    def _get_config_params(self, configuration: Dict) -> Tuple[str, str]:
        """Get the Base URL and Auth Token from the tenant.

        The plugin has no configuration parameters of its own. Both
        values are read from the Netskope Borderless WAN Tenant, whose
        manifest stores them under these keys:

        - 'tenantName': the tenant's 'Base URL' field (the Netskope
          Borderless WAN API URL, e.g.
          https://<tenant-name>.api.infiot.net), not a name.
        - 'v2token': the tenant's 'Auth Token' field (the Netskope
          Borderless WAN API token).

        The resolved values are cached per tenant for the lifetime of
        the plugin instance. The Auth Token is a password field, hence
        it is not stripped.

        Args:
            configuration (Dict): Configuration parameters.

        Returns:
            Tuple[str, str]: Base URL and Auth Token.

        Raises:
            NetskopeBwanPluginException: When the tenant could not be
                found.
        """
        cache_key = self.name
        if isinstance(configuration, dict) and configuration.get("tenant"):
            cache_key = f"tenant:{configuration.get('tenant')}"
        if cache_key not in self._tenant_credentials:
            parameters = self._get_tenant(configuration).parameters
            base_url = parameters.get("tenantName", "")
            if isinstance(base_url, str):
                base_url = base_url.strip().rstrip("/")
            api_token = resolve_secret(parameters.get("v2token", ""))
            self._tenant_credentials[cache_key] = (base_url, api_token)
        return self._tenant_credentials[cache_key]

    def _get_config_api_token(self, configuration: Dict) -> Optional[str]:
        """Get the optional 'API Token' configuration parameter.

        The API Token is a password field, hence it is not stripped.

        Args:
            configuration (Dict): Configuration parameters.

        Returns:
            Optional[str]: API Token, or None when it is not provided.
        """
        if not isinstance(configuration, dict):
            return None
        api_token = configuration.get(API_TOKEN_PARAM)
        return api_token if isinstance(api_token, str) and api_token else None

    def _get_headers(self, configuration: Dict) -> Dict:
        """Get the request headers for the configuration.

        The optional 'API Token' configuration parameter is used when
        provided (the Tenant Auth Token is then not used), else the Auth
        Token of the Netskope Borderless WAN Tenant.

        Args:
            configuration (Dict): Configuration parameters.

        Returns:
            Dict: Request headers.
        """
        api_token = self._get_config_api_token(configuration)
        if not api_token:
            _, api_token = self._get_config_params(configuration)
        return self.bwan_helper.get_headers(api_token)

    def _is_config_token(self, configuration: Dict) -> bool:
        """Get whether the optional 'API Token' is used for the requests.

        When it is provided, it is the only token used; the Auth Token
        of the Netskope Borderless WAN Tenant is not used.

        Args:
            configuration (Dict): Configuration parameters.

        Returns:
            bool: True when the 'API Token' is provided.
        """
        return self._get_config_api_token(configuration) is not None

    def _validate_url(self, url: str) -> bool:
        """Validate the URL using parsing.

        Args:
            url (str): Given URL.

        Returns:
            bool: True if the URL has an http(s) scheme and a network
                location, False otherwise (including unparsable URLs).
        """
        try:
            parsed = urlparse(url)
        except ValueError:
            return False
        return (
            parsed.scheme.strip().lower() in ("http", "https")
            and parsed.netloc.strip() != ""
        )

    def _validation_error(
        self,
        err_msg: str,
        resolution: Optional[str],
        details: Optional[str] = None,
    ) -> ValidationResult:
        """Log a validation error and build a failed ValidationResult.

        Args:
            err_msg (str): Error message (without log prefix).
            resolution (str, optional): Resolution for the error. None
                when the user cannot fix the error.
            details (str, optional): Details for the error log.

        Returns:
            ValidationResult: Failed validation result.
        """
        log_kwargs = {"message": f"{self.log_prefix}: {err_msg}"}
        if details:
            log_kwargs["details"] = details
        if resolution:
            log_kwargs["resolution"] = resolution
        self.logger.error(**log_kwargs)
        return ValidationResult(success=False, message=err_msg)

    def _validate_parameters(
        self,
        value: Any,
        field_label: str,
        field_type: Optional[type] = str,
        required: bool = True,
        extra_check: Optional[Callable[[Any], bool]] = None,
        extra_check_err: Optional[str] = None,
        context: str = TENANT_CONTEXT,
        resolution: Optional[str] = None,
    ) -> Optional[ValidationResult]:
        """Validate a configuration or action parameter.

        Runs the "required -> type check -> extra check" sequence.

        Args:
            value (Any): Value to validate.
            field_label (str): Label of the field used in messages.
            field_type (type, optional): Expected type of the value.
                None skips the type check. Defaults to str.
            required (bool, optional): Whether the field is mandatory.
            extra_check (Callable, optional): Additional predicate the
                value must satisfy.
            extra_check_err (str, optional): Resolution used when the
                extra check fails.
            context (str, optional): "configuration parameters" or
                "action parameters".
            resolution (str, optional): Single resolution used for every
                failure of this field. Overrides the default resolutions.

        Returns:
            Optional[ValidationResult]: None when the value is valid,
                else a failed ValidationResult.
        """
        is_tenant = context == TENANT_CONTEXT
        if required and not value:
            if is_tenant:
                err_msg = (
                    f"Error occurred while validating {context}. "
                    f"'{field_label}' is not configured in the "
                    f"{PLATFORM_NAME} Tenant."
                )
                resolution_msg = (
                    f"Ensure that the '{field_label}' is configured in the "
                    f"{PLATFORM_NAME} Tenant."
                )
            else:
                err_msg = (
                    f"Error occurred while validating {context}. "
                    f"'{field_label}' is a required action parameter."
                )
                resolution_msg = (
                    f"Ensure that a value is provided for '{field_label}'."
                )
            return self._validation_error(
                err_msg, resolution or resolution_msg
            )

        if value and field_type and not isinstance(value, field_type):
            err_msg = (
                f"Error occurred while validating {context}. "
                f"'{field_label}' must be of type string."
            )
            resolution_msg = (
                f"Ensure that '{field_label}' is provided as a valid string."
            )
            return self._validation_error(
                err_msg, resolution or resolution_msg
            )

        if value and extra_check is not None and not extra_check(value):
            err_msg = (
                f"Error occurred while validating {context}. "
                f"Invalid '{field_label}' provided."
            )
            resolution_msg = extra_check_err or (
                f"Ensure that a valid value is provided for '{field_label}'."
            )
            return self._validation_error(
                err_msg, resolution or resolution_msg
            )
        return None

    # ------------------------------------------------------------------ #
    # Netskope Borderless WAN API wrappers
    # ------------------------------------------------------------------ #
    def _get_all_address_groups(
        self, configuration: Dict, is_validation: bool = False
    ) -> List[Dict]:
        """Fetch all the Address Groups from Netskope Borderless WAN.

        Args:
            configuration (Dict): Configuration parameters.
            is_validation (bool, optional): Whether called from
                validation. Validation calls are not retried.

        Returns:
            List[Dict]: Address Groups having both 'id' and 'name'.

        Raises:
            NetskopeBwanPluginException: When the fetch fails.
        """
        logger_msg = f"fetching Address Groups from {PLATFORM_NAME}"
        try:
            base_url, _ = self._get_config_params(configuration)
            groups = self.bwan_helper.fetch_paginated_data(
                logger_msg=logger_msg,
                url=ADDRESS_GROUPS_ENDPOINT.format(base_url=base_url),
                headers=self._get_headers(configuration),
                is_config_token=self._is_config_token(configuration),
                verify=self.ssl_validation,
                proxies=self.proxy,
                required_keys=("id", "name"),
                is_validation=is_validation,
                resolution=RESOLUTION_FETCH_ADDRESS_GROUPS,
                entity_label="Address Group",
            )
            self.logger.debug(
                f"{self.log_prefix}: Successfully fetched {len(groups)} "
                f"Address Group(s) from {PLATFORM_NAME}."
            )
            return groups
        except NetskopeBwanPluginException:
            raise
        except Exception as exp:
            raise self.bwan_helper.handle_unexpected_error(
                logger_msg, exp
            )

    def _get_all_address_objects(
        self, configuration: Dict, group_id: str, group_name: str
    ) -> List[Dict]:
        """Fetch all the Address Objects of an Address Group.

        Args:
            configuration (Dict): Configuration parameters.
            group_id (str): Address Group ID.
            group_name (str): Address Group name.

        Every Address Object returned by the listing is kept, so that
        the Address Group limit counts all of them. Only the objects
        having both 'id' and 'address' are matched against IPs (see
        _build_address_map).

        Returns:
            List[Dict]: Address Objects of the Address Group.

        Raises:
            NetskopeBwanPluginException: When the fetch fails.
        """
        logger_msg = (
            f"fetching Address Objects from Address Group '{group_name}'"
        )
        try:
            base_url, _ = self._get_config_params(configuration)
            objects = self.bwan_helper.fetch_paginated_data(
                logger_msg=logger_msg,
                url=ADDRESS_OBJECTS_ENDPOINT.format(
                    base_url=base_url, address_group_id=group_id
                ),
                headers=self._get_headers(configuration),
                is_config_token=self._is_config_token(configuration),
                verify=self.ssl_validation,
                proxies=self.proxy,
                required_keys=(),
                resolution=RESOLUTION_FETCH_ADDRESS_OBJECTS,
                entity_label="Address Object",
            )
            self.logger.debug(
                f"{self.log_prefix}: Successfully fetched {len(objects)} "
                f"Address Object(s) from Address Group '{group_name}'."
            )
            return objects
        except NetskopeBwanPluginException:
            raise
        except Exception as exp:
            raise self.bwan_helper.handle_unexpected_error(
                logger_msg, exp
            )

    def _normalize_group_name(self, name: Any) -> str:
        """Normalize an Address Group name for matching.

        The same rule is used everywhere an Address Group is matched by
        name: the name is converted to a string and stripped. Matching
        stays case-sensitive.

        Args:
            name (Any): Address Group name.

        Returns:
            str: Normalized name.
        """
        return str(name if name is not None else "").strip()

    def _find_address_group_by_name(
        self, configuration: Dict, name: str, reason: str
    ) -> Dict:
        """Re-fetch the Address Groups and find one by exact name.

        Used to recover the target Address Group when the create request
        returned 409 or a 2xx without an ID, or failed after retries or
        with a transport error (an earlier attempt may have created it).

        Args:
            configuration (Dict): Configuration parameters.
            name (str): Case-sensitive Address Group name. Leading and
                trailing whitespace is ignored on both sides.
            reason (str): Why the lookup is needed. One of
                RECOVERY_CREATED, RECOVERY_CREATED_AFTER_RETRY or
                RECOVERY_ALREADY_EXISTS.

        Returns:
            Dict: Address Group with 'id' and 'name'.

        Raises:
            NetskopeBwanPluginException: When the Address Groups could
                not be fetched (already logged) or no Address Group with
                the name exists.
        """
        groups = self._get_all_address_groups(configuration)
        name = self._normalize_group_name(name)
        for group in groups:
            if self._normalize_group_name(group.get("name")) != name:
                continue
            if reason == RECOVERY_CREATED:
                log_msg = (
                    f"Successfully created Address Group '{name}' on "
                    f"{PLATFORM_NAME}."
                )
            elif reason == RECOVERY_CREATED_AFTER_RETRY:
                log_msg = (
                    f"Address Group '{name}' was created on "
                    f"{PLATFORM_NAME} after retry."
                )
            else:
                log_msg = (
                    f"Address Group '{name}' already exists on "
                    f"{PLATFORM_NAME}. Hence using the existing Address "
                    "Group."
                )
            self.logger.info(f"{self.log_prefix}: {log_msg}")
            return {"id": group["id"], "name": name}

        err_msg = (
            f"Error occurred while creating Address Group '{name}'. "
            f"Address Group was not found on {PLATFORM_NAME} after the "
            "create request."
        )
        self.logger.error(
            message=f"{self.log_prefix}: {err_msg}",
            resolution=RESOLUTION_CREATE_ADDRESS_GROUP,
        )
        raise NetskopeBwanPluginException(err_msg)

    def _create_address_group(
        self, configuration: Dict, name: str, description: str
    ) -> Dict:
        """Create a new Address Group on Netskope Borderless WAN.

        Any 2xx response is a success; its body is not required to be a
        JSON. The Address Groups are re-fetched and the group with the
        exact name is used when the response is a 2xx without an ID, a
        409, or when the request failed after retries or with a
        transport error. Any other 4xx fails immediately.

        Args:
            configuration (Dict): Configuration parameters.
            name (str): Name of the Address Group.
            description (str): Description of the Address Group.

        Returns:
            Dict: Address Group with 'id' and 'name'.

        Raises:
            NetskopeBwanPluginException: When the Address Group could
                not be created or found.
        """
        logger_msg = f"creating Address Group '{name}'"
        try:
            base_url, _ = self._get_config_params(configuration)
            try:
                response = self.bwan_helper.api_helper(
                    logger_msg=logger_msg,
                    url=ADDRESS_GROUPS_ENDPOINT.format(base_url=base_url),
                    method="POST",
                    json_data={
                        "name": name,
                        "description": description or "",
                    },
                    headers=self._get_headers(configuration),
                    is_config_token=self._is_config_token(configuration),
                    verify=self.ssl_validation,
                    proxies=self.proxy,
                    is_handle_error_required=False,
                    resolution=RESOLUTION_CREATE_ADDRESS_GROUP,
                )
            except NetskopeBwanPluginException:
                # Retries exhausted (429/5xx) or transport error, already
                # logged. An earlier attempt may have created the group.
                return self._find_address_group_by_name(
                    configuration, name, RECOVERY_CREATED_AFTER_RETRY
                )

            status_code = response.status_code
            if 200 <= status_code < 300:
                group_id = self.bwan_helper.get_json_body(response).get("id")
                if not group_id:
                    return self._find_address_group_by_name(
                        configuration, name, RECOVERY_CREATED
                    )
                self.logger.info(
                    f"{self.log_prefix}: Successfully created Address "
                    f"Group '{name}' on {PLATFORM_NAME}."
                )
                return {"id": group_id, "name": name}
            if status_code == 409:
                reason = (
                    RECOVERY_CREATED_AFTER_RETRY
                    if response.bwan_had_server_error is True
                    else RECOVERY_ALREADY_EXISTS
                )
                return self._find_address_group_by_name(
                    configuration, name, reason
                )
            # handle_error always raises for a non-2xx status code.
            self.bwan_helper.handle_error(
                response,
                logger_msg,
                resolution=RESOLUTION_CREATE_ADDRESS_GROUP,
            )
        except NetskopeBwanPluginException:
            raise
        except Exception as exp:
            raise self.bwan_helper.handle_unexpected_error(
                logger_msg, exp
            )

    def _build_address_object_payload(self, ip: str) -> Dict:
        """Build the payload to create an Address Object.

        'name' is the display name of the Address Object, hence the IP
        value itself is used, so each object is identifiable in the
        Netskope Borderless WAN console.

        Args:
            ip (str): Canonical IPv4 address or IPv4 CIDR range.

        Returns:
            Dict: Address Object payload.
        """
        return {"name": ip, "address": ip, "type": ADDRESS_OBJECT_TYPE}

    def _add_address_object(
        self,
        configuration: Dict,
        group_id: str,
        group_name: str,
        ip: str,
    ) -> str:
        """Add an IP as an Address Object to an Address Group.

        Any 2xx response is a success (the body is not parsed).
        Netskope Borderless WAN rejects an address that already exists
        anywhere on the tenant with HTTP 409 ('already_exists'), even
        when it is not in this Address Group. IPs already in the group
        are filtered out before this call, so a 409 means
        'exists_on_tenant' (not added).
        After a retried 5xx, an earlier attempt of this call may have
        created it, hence the Address Objects of the group are fetched
        once and the IP counts as 'added' only if it is in the group.

        Args:
            configuration (Dict): Configuration parameters.
            group_id (str): Address Group ID.
            group_name (str): Address Group name.
            ip (str): Canonical IPv4 address or IPv4 CIDR range.

        Returns:
            str: 'added' or 'exists_on_tenant'.

        Raises:
            NetskopeBwanFatalAPIException: When retries are exhausted on
                HTTP 429/5xx or on HTTP 401/403, so the remaining IPs
                should not be sent.
            NetskopeBwanPluginException: When the add call fails.
        """
        logger_msg = f"adding IP '{ip}' to Address Group '{group_name}'"
        try:
            base_url, _ = self._get_config_params(configuration)
            response = self.bwan_helper.api_helper(
                logger_msg=logger_msg,
                url=ADDRESS_OBJECTS_ENDPOINT.format(
                    base_url=base_url, address_group_id=group_id
                ),
                method="POST",
                json_data=self._build_address_object_payload(ip),
                headers=self._get_headers(configuration),
                is_config_token=self._is_config_token(configuration),
                verify=self.ssl_validation,
                proxies=self.proxy,
                is_handle_error_required=False,
                resolution=RESOLUTION_ADD_IP,
            )
            if 200 <= response.status_code < 300:
                return OUTCOME_ADDED
            if response.status_code == 409:
                if response.bwan_had_server_error is True:
                    return self._confirm_added_after_retry(
                        configuration, group_id, group_name, ip
                    )
                return OUTCOME_EXISTS_ON_TENANT
            # handle_error always raises for a non-2xx status code.
            self.bwan_helper.handle_error(
                response, logger_msg, resolution=RESOLUTION_ADD_IP
            )
        except NetskopeBwanPluginException:
            raise
        except Exception as exp:
            raise self.bwan_helper.handle_unexpected_error(
                logger_msg, exp
            )

    def _confirm_added_after_retry(
        self,
        configuration: Dict,
        group_id: str,
        group_name: str,
        ip: str,
    ) -> str:
        """Check whether a 409 after a retried 5xx means the IP was added.

        The 5xx may have been returned after the server created the
        Address Object, or the IP may exist elsewhere on the tenant. The
        Address Objects of the group are fetched once to tell these
        cases apart.

        Args:
            configuration (Dict): Configuration parameters.
            group_id (str): Address Group ID.
            group_name (str): Address Group name.
            ip (str): Canonical IPv4 address or IPv4 CIDR range.

        Returns:
            str: 'added' when the IP is in the Address Group, else
                'exists_on_tenant'.

        Raises:
            NetskopeBwanPluginException: When the Address Objects could
                not be fetched (already logged).
        """
        objects = self._get_all_address_objects(
            configuration, group_id, group_name
        )
        if ip in self._build_address_map(objects):
            self.logger.debug(
                f"{self.log_prefix}: Confirmed that IP '{ip}' exists in "
                f"Address Group '{group_name}' after a retried request."
            )
            return OUTCOME_ADDED
        return OUTCOME_EXISTS_ON_TENANT

    def _delete_address_object(
        self,
        configuration: Dict,
        group_id: str,
        group_name: str,
        object_id: str,
        ip: str,
    ) -> str:
        """Remove an Address Object from an Address Group.

        Any 2xx response is a success (the body is not parsed). HTTP 404
        is also a success: 'removed' when an earlier attempt of this
        call received a 5xx (the server may already have deleted the
        object), else 'not_found'.

        Args:
            configuration (Dict): Configuration parameters.
            group_id (str): Address Group ID.
            group_name (str): Address Group name.
            object_id (str): Address Object ID.
            ip (str): Canonical IPv4 address or IPv4 CIDR range.

        Returns:
            str: 'removed' or 'not_found'.

        Raises:
            NetskopeBwanFatalAPIException: When retries are exhausted on
                HTTP 429/5xx or on HTTP 401/403, so the remaining IPs
                should not be removed.
            NetskopeBwanPluginException: When the delete call fails.
        """
        logger_msg = f"removing IP '{ip}' from Address Group '{group_name}'"
        try:
            base_url, _ = self._get_config_params(configuration)
            response = self.bwan_helper.api_helper(
                logger_msg=logger_msg,
                url=ADDRESS_OBJECT_ENDPOINT.format(
                    base_url=base_url,
                    address_group_id=group_id,
                    address_object_id=object_id,
                ),
                method="DELETE",
                headers=self._get_headers(configuration),
                is_config_token=self._is_config_token(configuration),
                verify=self.ssl_validation,
                proxies=self.proxy,
                is_handle_error_required=False,
                resolution=RESOLUTION_REMOVE_IP,
            )
            if 200 <= response.status_code < 300:
                return OUTCOME_REMOVED
            if response.status_code == 404:
                if response.bwan_had_server_error is True:
                    return OUTCOME_REMOVED
                return OUTCOME_NOT_FOUND
            # handle_error always raises for a non-2xx status code.
            self.bwan_helper.handle_error(
                response, logger_msg, resolution=RESOLUTION_REMOVE_IP
            )
        except NetskopeBwanPluginException:
            raise
        except Exception as exp:
            raise self.bwan_helper.handle_unexpected_error(
                logger_msg, exp
            )

    # ------------------------------------------------------------------ #
    # IP parsing
    # ------------------------------------------------------------------ #
    def _get_canonical_ip(self, value: Any) -> Optional[str]:
        """Get the canonical form of an IPv4 address or IPv4 CIDR range.

        CIDR ranges are kept exactly as provided, including host bits,
        since Netskope Borderless WAN accepts them as they are. Only a
        '/32' prefix is dropped and a netmask is converted to a prefix
        length.

        Args:
            value (Any): Value to parse.

        Returns:
            Optional[str]: '10.1.1.1' for a host (or /32), else the
                address with its prefix length, e.g. '10.1.1.5/24' or
                '10.1.1.0/24'. None when the value is empty, invalid or
                not IPv4.
        """
        if value is None:
            return None
        value = str(value).strip()
        if not value:
            return None
        try:
            interface = ipaddress.ip_interface(value)
        except ValueError:
            return None
        if interface.version != 4:
            return None
        if interface.network.prefixlen == 32:
            return str(interface.ip)
        return str(interface)

    def _flatten_ip_values(self, value: Any) -> List[Any]:
        """Flatten the IP action parameter into single values.

        Lists (including nested lists) are flattened, and every string,
        including list elements, is split on ','. Any other type is
        kept as a single value.

        Args:
            value (Any): IP action parameter value.

        Returns:
            List[Any]: Flattened values.
        """
        if value is None:
            return []
        if isinstance(value, (list, tuple, set)):
            flattened = []
            for element in value:
                flattened.extend(self._flatten_ip_values(element))
            return flattened
        if isinstance(value, str):
            return value.split(",")
        return [value]

    def _parse_ip_values(self, value: Any) -> Tuple[List[str], List[str]]:
        """Parse the IP action parameter into valid and invalid values.

        Lists are flattened and comma-separated strings (also inside
        list elements) are split.

        Args:
            value (Any): IP action parameter value.

        Returns:
            Tuple[List[str], List[str]]: De-duplicated canonical IPs (in
                order) and the invalid values.
        """
        valid_ips, invalid_values = [], []
        for raw_value in self._flatten_ip_values(value):
            if raw_value is None or not str(raw_value).strip():
                continue
            canonical_ip = self._get_canonical_ip(raw_value)
            if canonical_ip:
                valid_ips.append(canonical_ip)
            else:
                invalid_values.append(str(raw_value).strip())
        return list(dict.fromkeys(valid_ips)), invalid_values

    # ------------------------------------------------------------------ #
    # Actions
    # ------------------------------------------------------------------ #
    def get_actions(self) -> List[ActionWithoutParams]:
        """Get available actions.

        Returns:
            List[ActionWithoutParams]: Supported actions.
        """
        return [
            ActionWithoutParams(
                label=ADD_TO_ADDRESS_GROUP_LABEL, value=ADD_TO_ADDRESS_GROUP
            ),
            ActionWithoutParams(
                label=REMOVE_FROM_ADDRESS_GROUP_LABEL,
                value=REMOVE_FROM_ADDRESS_GROUP,
            ),
            ActionWithoutParams(label=NO_ACTION_LABEL, value=NO_ACTION),
        ]

    def _get_address_group_choices(self) -> List[Dict]:
        """Get the Address Group dropdown choices sorted by name.

        The Address Groups are fetched without retries, since this runs
        while the user is configuring the action.

        Returns:
            List[Dict]: Choices as {"key": name, "value": id}.

        Raises:
            NetskopeBwanPluginException: When the Address Groups could
                not be fetched (already logged). CE then shows that the
                action parameters could not be loaded.
        """
        groups = self._get_all_address_groups(
            self.configuration, is_validation=True
        )
        groups = sorted(
            groups, key=lambda group: str(group.get("name")).lower()
        )
        return [
            {"key": group.get("name"), "value": group.get("id")}
            for group in groups
        ]

    def _get_ip_param(self, operation: str) -> Dict:
        """Get the IP action parameter definition.

        Args:
            operation (str): 'add to' or 'remove from'.

        Returns:
            Dict: IP action parameter.
        """
        description = (
            "Select the Source field containing IPv4 addresses or IPv4 "
            "CIDR ranges, or provide Static comma-separated values to "
            f"{operation} the Address Group. IPv6 values are skipped. CIDR "
            "ranges are used exactly as provided."
        )
        if operation == "remove from":
            description += (
                " Values are matched exactly, e.g. removing 10.0.0.7 does "
                "not remove 10.0.0.0/24."
            )
        return {
            "label": IP_PARAM_LABEL,
            "key": IP_ADDRESS_PARAM,
            "type": "text",
            "default": "",
            "placeholder": "e.g. 10.0.0.1, 192.168.1.0/24",
            "mandatory": True,
            "description": description,
        }

    def get_action_params(self, action: Action) -> List:
        """Get fields required for an action.

        Args:
            action (Action): Action object.

        Returns:
            List: Action parameters.

        Raises:
            NetskopeBwanPluginException: When the Address Groups could
                not be fetched.
        """
        if action.value not in REVERTIBLE_ACTIONS:
            # No Action (and any unsupported action) has no parameters.
            return []

        choices = self._get_address_group_choices()
        if action.value == ADD_TO_ADDRESS_GROUP:
            choices.append(
                {
                    "key": CREATE_NEW_ADDRESS_GROUP_LABEL,
                    "value": CREATE_NEW_ADDRESS_GROUP_VALUE,
                }
            )
            return [
                self._get_ip_param("add to"),
                {
                    "label": "Address Group",
                    "key": ADDRESS_GROUP_PARAM,
                    "type": "choice",
                    "choices": choices,
                    "default": choices[0]["value"],
                    "mandatory": True,
                    "description": (
                        "Select an Address Group from the available "
                        "options, or select 'Create New Address Group' to "
                        "create a new Address Group and add the IPs to it."
                        " Select the Address Group from the Static Field "
                        "dropdown only."
                    ),
                },
                {
                    "label": NEW_ADDRESS_GROUP_NAME_LABEL,
                    "key": NEW_ADDRESS_GROUP_NAME_PARAM,
                    "type": "text",
                    "default": "",
                    "mandatory": False,
                    "description": (
                        "Name of the Address Group to create. Required "
                        "only when 'Create New Address Group' is selected "
                        "in Address Group. If an Address Group with this "
                        "name already exists, it is used instead. Provide "
                        "it in the Static Field."
                    ),
                },
                {
                    "label": "Description",
                    "key": DESCRIPTION_PARAM,
                    "type": "text",
                    "default": "",
                    "mandatory": False,
                    "description": (
                        "Description of the new Address Group. Used only "
                        "when 'Create New Address Group' is selected in "
                        "Address Group. Ignored if the Address Group "
                        "already exists. Provide it in the Static Field."
                    ),
                },
            ]

        return [
            self._get_ip_param("remove from"),
            {
                "label": "Address Group",
                "key": ADDRESS_GROUP_PARAM,
                "type": "choice",
                "choices": choices,
                "default": choices[0]["value"] if choices else "",
                "mandatory": True,
                "description": (
                    "Select the Address Group to remove the IPs from. "
                    "Select the Address Group from the Static Field "
                    "dropdown only."
                ),
            },
        ]

    def _source_field_error(
        self, field_label: str, is_choice: bool = False
    ) -> ValidationResult:
        """Build the validation error for a Source Field value.

        Uses the wording mandated by the CE best practices.

        Args:
            field_label (str): Label of the field.
            is_choice (bool, optional): Whether the field is a dropdown.

        Returns:
            ValidationResult: Failed validation result.
        """
        if is_choice:
            detail = (
                f"{field_label} contains the Source Field. Please select "
                f"{field_label} from the Static Field dropdown only."
            )
            resolution = (
                f"Ensure that {field_label} is selected from the Static "
                "Field dropdown only."
            )
        else:
            detail = (
                f"{field_label} contains the Source Field. Please provide "
                f"{field_label} in the Static Field only."
            )
            resolution = (
                f"Ensure that {field_label} is provided in the Static "
                "Field only."
            )
        return self._validation_error(
            f"Error occurred while validating action parameters. {detail}",
            resolution,
        )

    def _validate_address_group_param(
        self, action_value: str, address_group: Any
    ) -> Optional[ValidationResult]:
        """Validate the Address Group action parameter.

        Args:
            action_value (str): Action value.
            address_group (Any): Address Group action parameter value.

        Returns:
            Optional[ValidationResult]: None when valid, else a failed
                ValidationResult.
        """
        is_remove = action_value == REMOVE_FROM_ADDRESS_GROUP
        if is_remove and address_group == "":
            if result := self._validate_empty_remove_address_group():
                return result
        if result := self._validate_parameters(
            address_group, "Address Group", context=ACTION_CONTEXT
        ):
            return result
        if "$" in address_group:
            return self._source_field_error("Address Group", is_choice=True)
        if address_group == CREATE_NEW_ADDRESS_GROUP_VALUE:
            if is_remove:
                return self._validation_error(
                    (
                        "Error occurred while validating action "
                        f"parameters. '{CREATE_NEW_ADDRESS_GROUP_LABEL}' "
                        "is not supported for the "
                        f"'{REMOVE_FROM_ADDRESS_GROUP_LABEL}' action."
                    ),
                    "Ensure that an existing Address Group is selected "
                    f"for the '{REMOVE_FROM_ADDRESS_GROUP_LABEL}' action.",
                )
            return None

        try:
            groups = self._get_all_address_groups(
                self.configuration, is_validation=True
            )
        except NetskopeBwanPluginException as exp:
            return ValidationResult(success=False, message=str(exp))
        if address_group not in {group.get("id") for group in groups}:
            return self._validation_error(
                (
                    "Error occurred while validating action parameters. "
                    f"The selected Address Group (ID '{address_group}') "
                    f"does not exist on {PLATFORM_NAME}. It may have been "
                    "deleted."
                ),
                f"Ensure that the Address Group exists on {PLATFORM_NAME}, "
                "or select another Address Group or "
                f"'{CREATE_NEW_ADDRESS_GROUP_LABEL}' in the action.",
                details=f"Selected Address Group value: '{address_group}'",
            )
        return None

    def _validate_empty_remove_address_group(
        self,
    ) -> Optional[ValidationResult]:
        """Explain an empty Address Group for the Remove action.

        The Address Group dropdown of the Remove action is empty when no
        Address Group exists. The Address Groups are re-fetched to tell
        this apart from a fetch failure at validation time.

        Returns:
            Optional[ValidationResult]: Failed ValidationResult for a
                fetch failure or when no Address Group exists, else None
                (the generic required-parameter check then applies).
        """
        try:
            groups = self._get_all_address_groups(
                self.configuration, is_validation=True
            )
        except NetskopeBwanPluginException as exp:
            return ValidationResult(success=False, message=str(exp))
        if not groups:
            return self._validation_error(
                (
                    "Error occurred while validating action parameters. "
                    f"No Address Groups found on {PLATFORM_NAME}."
                ),
                RESOLUTION_NO_ADDRESS_GROUPS,
            )
        return None

    def _validate_new_address_group_params(
        self, parameters: Dict
    ) -> Optional[ValidationResult]:
        """Validate the New Address Group Name and Description.

        Args:
            parameters (Dict): Action parameters.

        Returns:
            Optional[ValidationResult]: None when valid, else a failed
                ValidationResult.
        """
        new_group_name = parameters.get(NEW_ADDRESS_GROUP_NAME_PARAM, "")
        if result := self._validate_parameters(
            new_group_name,
            NEW_ADDRESS_GROUP_NAME_LABEL,
            required=False,
            context=ACTION_CONTEXT,
        ):
            return result
        if not (new_group_name or "").strip():
            return self._validation_error(
                (
                    "Error occurred while validating action parameters. "
                    f"'{NEW_ADDRESS_GROUP_NAME_LABEL}' is required when "
                    f"'{CREATE_NEW_ADDRESS_GROUP_LABEL}' is selected in "
                    "'Address Group'."
                ),
                RESOLUTION_NEW_ADDRESS_GROUP,
            )
        if "$" in new_group_name:
            return self._source_field_error(NEW_ADDRESS_GROUP_NAME_LABEL)

        description = parameters.get(DESCRIPTION_PARAM, "")
        if result := self._validate_parameters(
            description,
            "Description",
            required=False,
            context=ACTION_CONTEXT,
        ):
            return result
        if description and "$" in description:
            return self._source_field_error("Description")
        return None

    def _validate_ip_param(
        self, action_label: str, ip_address: Any
    ) -> Optional[ValidationResult]:
        """Validate the IP action parameter.

        Args:
            action_label (str): Action label.
            ip_address (Any): IP action parameter value.

        Returns:
            Optional[ValidationResult]: None when valid, else a failed
                ValidationResult.
        """
        if result := self._validate_parameters(
            ip_address,
            IP_PARAM_LABEL,
            field_type=None,
            context=ACTION_CONTEXT,
        ):
            return result
        # A Source Field can be a string or, from CE 7.0.0, a list of
        # Source Fields; both are resolved only at execution time.
        if any(
            isinstance(value, str) and "$" in value
            for value in self._flatten_ip_values(ip_address)
        ):
            self.logger.debug(
                f"{self.log_prefix}: '{IP_PARAM_LABEL}' contains the Source "
                "Field, hence validation for this field will be performed "
                f"while executing the '{action_label}' action."
            )
            return None
        valid_ips, invalid_values = self._parse_ip_values(ip_address)
        if not valid_ips and not invalid_values:
            return self._validation_error(
                (
                    "Error occurred while validating action parameters. "
                    f"No IP value provided in '{IP_PARAM_LABEL}'."
                ),
                RESOLUTION_NO_IP,
                details="No IP value was provided.",
            )
        if invalid_values:
            return self._validation_error(
                (
                    "Error occurred while validating action parameters. "
                    f"'{IP_PARAM_LABEL}' contains invalid value(s). Only "
                    "IPv4 addresses and IPv4 CIDR ranges are supported."
                ),
                RESOLUTION_INVALID_IP,
                details=f"Invalid value(s): {', '.join(invalid_values)}",
            )
        return None

    def validate_action(self, action: Action) -> ValidationResult:
        """Validate the Netskope Borderless WAN action configuration.

        Args:
            action (Action): Action to validate.

        Returns:
            ValidationResult: Validation result.
        """
        try:
            action_value = action.value
            if action_value not in SUPPORTED_ACTIONS:
                return self._validation_error(
                    (
                        "Error occurred while validating action "
                        f"parameters. Unsupported action '{action_value}' "
                        "provided."
                    ),
                    RESOLUTION_UNSUPPORTED_ACTION,
                )
            if action_value == NO_ACTION:
                self.logger.debug(
                    f"{self.log_prefix}: Successfully validated action "
                    f"configuration for '{NO_ACTION_LABEL}'."
                )
                return ValidationResult(
                    success=True, message=VALIDATION_SUCCESS_MSG
                )
            action_label = (
                ADD_TO_ADDRESS_GROUP_LABEL
                if action_value == ADD_TO_ADDRESS_GROUP
                else REMOVE_FROM_ADDRESS_GROUP_LABEL
            )
            parameters = action.parameters or {}
            address_group = parameters.get(ADDRESS_GROUP_PARAM, "")
            if isinstance(address_group, str):
                address_group = address_group.strip()
            if result := self._validate_address_group_param(
                action_value, address_group
            ):
                return result
            if (
                action_value == ADD_TO_ADDRESS_GROUP
                and address_group == CREATE_NEW_ADDRESS_GROUP_VALUE
            ):
                if result := self._validate_new_address_group_params(
                    parameters
                ):
                    return result
            if result := self._validate_ip_param(
                action_label, parameters.get(IP_ADDRESS_PARAM, "")
            ):
                return result

            self.logger.debug(
                f"{self.log_prefix}: Successfully validated action "
                f"configuration for '{action_label}'."
            )
            return ValidationResult(
                success=True, message=VALIDATION_SUCCESS_MSG
            )
        except Exception as exp:
            return self._validation_error(
                (
                    "Error occurred while validating action parameters. "
                    f"Error: {exp}"
                ),
                None,
                details=traceback.format_exc(),
            )

    # ------------------------------------------------------------------ #
    # Configuration validation
    # ------------------------------------------------------------------ #
    def _validate_auth_params(self, configuration: Dict) -> ValidationResult:
        """Validate the credentials with the Netskope Borderless WAN platform.

        Args:
            configuration (Dict): Configuration parameters.

        Returns:
            ValidationResult: Validation result.
        """
        logger_msg = "validating the credentials"
        try:
            base_url, _ = self._get_config_params(configuration)
            response = self.bwan_helper.api_helper(
                logger_msg=logger_msg,
                url=ADDRESS_GROUPS_ENDPOINT.format(base_url=base_url),
                method="GET",
                params={"first": VALIDATION_PAGE_SIZE},
                headers=self._get_headers(configuration),
                is_config_token=self._is_config_token(configuration),
                verify=self.ssl_validation,
                proxies=self.proxy,
                is_validation=True,
            )
            if not isinstance(response, dict) or not isinstance(
                response.get("data"), list
            ):
                return self._validation_error(
                    (
                        f"Error occurred while {logger_msg}. Invalid "
                        f"response received from {PLATFORM_NAME}."
                    ),
                    RESOLUTION_BASE_URL,
                    details=f"API response: {response}",
                )
            self.logger.debug(
                f"{self.log_prefix}: Successfully validated configuration "
                "parameters."
            )
            return ValidationResult(
                success=True, message=VALIDATION_SUCCESS_MSG
            )
        except NetskopeBwanPluginException as exp:
            return ValidationResult(success=False, message=str(exp))
        except Exception as exp:
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Error occurred while {logger_msg}. "
                    f"Error: {exp}"
                ),
                details=traceback.format_exc(),
            )
            return ValidationResult(
                success=False,
                message=(
                    f"Error occurred while {logger_msg}. Check logs for "
                    "more details."
                ),
            )

    def validate(self, configuration: Dict) -> ValidationResult:
        """Validate the plugin configuration.

        The plugin has no configuration parameters. The Base URL and
        Auth Token of the selected Netskope Borderless WAN Tenant are
        validated, followed by a connectivity check.

        Args:
            configuration (Dict): Configuration parameters.

        Returns:
            ValidationResult: Validation result.
        """
        try:
            base_url, api_token = self._get_config_params(configuration)
        except NetskopeBwanPluginException as exp:
            return ValidationResult(success=False, message=str(exp))
        if result := self._validate_parameters(
            base_url,
            "Base URL",
            extra_check=self._validate_url,
            resolution=RESOLUTION_BASE_URL,
        ):
            return result

        # Auth Token is a password field, hence it is not stripped.
        if result := self._validate_parameters(api_token, "Auth Token"):
            return result

        # Optional 'API Token' (password field, hence not stripped). When
        # provided, the connectivity check below is made with it.
        if result := self._validate_parameters(
            configuration.get(API_TOKEN_PARAM),
            "API Token",
            required=False,
            context=CONFIG_CONTEXT,
        ):
            return result

        return self._validate_auth_params(configuration)

    # ------------------------------------------------------------------ #
    # Action execution
    # ------------------------------------------------------------------ #
    def _get_action_ids(self, actions: List[Dict]) -> List[str]:
        """Get the non-empty action IDs from the actions.

        Args:
            actions (List[Dict]): Actions as {"id": ..., "params": ...}.

        Returns:
            List[str]: De-duplicated action IDs.
        """
        return list(
            dict.fromkeys(
                action.get("id")
                for action in actions
                if isinstance(action, dict) and action.get("id") is not None
            )
        )

    def execute_actions(
        self, actions: List[Dict], revert: bool = False
    ) -> Optional[ActionResult]:
        """Execute the actions in bulk.

        CE may send entries to perform and entries to revert in one call
        with a single revert flag taken from the first entry. Hence each
        entry is routed by its own 'performRevert' attribute (the revert
        argument is used only when the attribute is missing), and the
        results of both parts are merged.

        Args:
            actions (List[Dict]): Actions as {"id": str, "params": Action}
                dicts, one per action log entry.
            revert (bool): If True, undo the previously executed actions.
                Reverting 'Add to Address Group' removes the IPs from that
                Address Group, and reverting 'Remove from Address Group'
                adds the IPs back to it. Defaults to False.

        Returns:
            Optional[ActionResult]: None when every record succeeded,
                else an ActionResult with the failed action IDs.
        """
        forward_actions, revert_actions = [], []
        for action_dict in actions or []:
            params = (
                action_dict.get("params")
                if isinstance(action_dict, dict)
                else None
            )
            perform_revert = getattr(params, "performRevert", None)
            is_revert = revert if perform_revert is None else bool(
                perform_revert
            )
            if is_revert:
                revert_actions.append(action_dict)
            else:
                forward_actions.append(action_dict)
        if forward_actions and revert_actions:
            self.logger.debug(
                f"{self.log_prefix}: Received {len(forward_actions)} "
                f"record(s) to perform and {len(revert_actions)} record(s) "
                "to revert in one batch, hence processing them separately."
            )
        results = [
            self._execute_actions_safely(part, part_revert)
            for part, part_revert in (
                (forward_actions, False),
                (revert_actions, True),
            )
            if part
        ]
        return self._merge_action_results(results, actions or [])

    def _merge_action_results(
        self,
        results: List[Optional[ActionResult]],
        actions: List[Dict],
    ) -> Optional[ActionResult]:
        """Merge the results of the forward and revert parts of a batch.

        Args:
            results (List[Optional[ActionResult]]): Result of each part.
            actions (List[Dict]): All the actions of the batch.

        Returns:
            Optional[ActionResult]: None when every part returned None,
                else one ActionResult with the union of the failed action
                IDs. It is unsuccessful only when every action of the
                batch failed.
        """
        part_results = [result for result in results if result is not None]
        if not part_results:
            return None
        if len(results) == 1:
            return part_results[0]
        failed_ids = list(
            dict.fromkeys(
                action_id
                for result in part_results
                for action_id in (result.failed_action_ids or [])
            )
        )
        all_ids = set(self._get_action_ids(actions))
        return ActionResult(
            success=bool(all_ids - set(failed_ids)),
            message=" ".join(result.message for result in part_results),
            failed_action_ids=failed_ids,
        )

    def _execute_actions_safely(
        self, actions: List[Dict], revert: bool = False
    ) -> Optional[ActionResult]:
        """Execute the actions, converting unexpected errors to a result.

        Args:
            actions (List[Dict]): Actions as {"id": str, "params": Action}
                dicts that share the same revert flag.
            revert (bool): Whether to revert the actions.

        Returns:
            Optional[ActionResult]: None when every record succeeded,
                else an ActionResult with the failed action IDs.
        """
        try:
            return self._execute_actions(actions, revert)
        except Exception as exp:
            action_label = "action"
            try:
                action_label = f"'{actions[0]['params'].label}' action"
            except Exception:
                action_label = "action"
            err_msg = (
                f"Error occurred while "
                f"{'reverting' if revert else 'executing'} the "
                f"{action_label}. Error: {exp}"
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=traceback.format_exc(),
            )
            return ActionResult(
                success=False,
                message=err_msg,
                failed_action_ids=self._get_action_ids(actions or []),
            )

    def _build_action_buckets(
        self, action_value: str, actions: List[Dict]
    ) -> Dict[Tuple, List[Dict]]:
        """Group the actions by their target Address Group.

        CE batches actions by configuration and action value only, so
        records of one batch may carry different Address Group values.

        Args:
            action_value (str): Action value.
            actions (List[Dict]): Actions as {"id": ..., "params": ...}.

        Returns:
            Dict[Tuple, List[Dict]]: Actions per bucket key. The key is
                ('create', name, description) for a new Address Group,
                else ('id', address_group_id).
        """
        buckets: Dict[Tuple, List[Dict]] = {}
        for action_dict in actions:
            parameters = action_dict.get("params").parameters or {}
            address_group = parameters.get(ADDRESS_GROUP_PARAM, "")
            address_group = str(address_group or "").strip()
            if (
                action_value == ADD_TO_ADDRESS_GROUP
                and address_group == CREATE_NEW_ADDRESS_GROUP_VALUE
            ):
                key = (
                    BUCKET_CREATE,
                    self._normalize_group_name(
                        parameters.get(NEW_ADDRESS_GROUP_NAME_PARAM)
                    ),
                    str(parameters.get(DESCRIPTION_PARAM) or "").strip(),
                )
            else:
                key = (BUCKET_EXISTING, address_group)
            buckets.setdefault(key, []).append(action_dict)
        return buckets

    def _resolve_address_group(
        self,
        bucket_key: Tuple,
        action_label: str,
        groups_by_id: Dict[str, Dict],
        groups_by_name: Dict[str, Dict],
        revert: bool = False,
    ) -> Optional[Dict]:
        """Resolve the target Address Group of a bucket.

        For 'Create New Address Group', an existing Address Group with
        the same name is reused, else a new Address Group is created.
        While reverting, the Address Group is only looked up by name and
        never created, since a newly created Address Group would never
        contain the IPs to remove.

        Args:
            bucket_key (Tuple): Bucket key.
            action_label (str): Action label.
            groups_by_id (Dict[str, Dict]): Address Groups by ID.
            groups_by_name (Dict[str, Dict]): Address Groups by name.
            revert (bool): Whether the action is being reverted.

        Returns:
            Optional[Dict]: Address Group with 'id' and 'name', or None
                when it could not be resolved (error already logged).
        """
        operation = "reverting" if revert else "executing"
        if bucket_key[0] == BUCKET_EXISTING:
            group = groups_by_id.get(bucket_key[1])
            if not group:
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: Error occurred while {operation}"
                        f" the '{action_label}' action. Address Group with "
                        f"ID '{bucket_key[1]}' does not exist on "
                        f"{PLATFORM_NAME}."
                    ),
                    resolution=RESOLUTION_ADDRESS_GROUP_NOT_FOUND,
                )
            return group

        _, name, description = bucket_key
        if not name:
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Error occurred while {operation} "
                    f"the '{action_label}' action. "
                    f"'{NEW_ADDRESS_GROUP_NAME_LABEL}' is required when "
                    f"'{CREATE_NEW_ADDRESS_GROUP_LABEL}' is selected in "
                    "'Address Group'."
                ),
                resolution=RESOLUTION_NEW_ADDRESS_GROUP,
            )
            return None
        if revert:
            # Only reachable when the created Address Group ID was not
            # stored back into the action parameters.
            group = groups_by_name.get(name)
            if not group:
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: Error occurred while reverting"
                        f" the '{action_label}' action. Address Group "
                        f"'{name}' created for this action does not exist "
                        f"on {PLATFORM_NAME}."
                    ),
                    resolution=RESOLUTION_REVERT_ADDRESS_GROUP_NOT_FOUND,
                )
            return group
        if name in groups_by_name:
            self.logger.info(
                f"{self.log_prefix}: Address Group '{name}' already exists "
                f"on {PLATFORM_NAME}. Hence using the existing Address "
                "Group."
            )
            return groups_by_name[name]
        try:
            group = self._create_address_group(
                self.configuration, name, description
            )
        except NetskopeBwanPluginException:
            return None
        groups_by_name[name] = group
        groups_by_id[group["id"]] = group
        return group

    def _collect_bucket_ips(
        self,
        bucket_actions: List[Dict],
        failed_ids: Set[str],
        invalid_values: List[str],
    ) -> Dict[str, Set[str]]:
        """Parse the IPs of every record in a bucket.

        Records without any valid IPv4 value are marked as failed.

        Args:
            bucket_actions (List[Dict]): Actions of the bucket.
            failed_ids (Set[str]): Failed action IDs (updated in place).
            invalid_values (List[str]): Invalid IP values (updated in
                place).

        Returns:
            Dict[str, Set[str]]: Canonical IP to action IDs, in order.
        """
        ip_to_ids: Dict[str, Set[str]] = {}
        for action_dict in bucket_actions:
            action_id = action_dict.get("id")
            parameters = action_dict.get("params").parameters or {}
            valid_ips, invalid = self._parse_ip_values(
                parameters.get(IP_ADDRESS_PARAM)
            )
            invalid_values.extend(invalid)
            if not valid_ips:
                if action_id is not None:
                    failed_ids.add(action_id)
                continue
            for ip in valid_ips:
                ids = ip_to_ids.setdefault(ip, set())
                if action_id is not None:
                    ids.add(action_id)
        return ip_to_ids

    def _build_address_map(
        self, address_objects: List[Dict]
    ) -> Dict[str, List[str]]:
        """Map the canonical IP of each Address Object to its IDs.

        Address Objects without an 'id' or an 'address' are ignored.

        Args:
            address_objects (List[Dict]): Address Objects of a group.

        Returns:
            Dict[str, List[str]]: Canonical IP to Address Object IDs.
        """
        address_map: Dict[str, List[str]] = {}
        for address_object in address_objects:
            if not (
                address_object.get("id") and address_object.get("address")
            ):
                continue
            canonical_ip = self._get_canonical_ip(address_object["address"])
            if canonical_ip:
                address_map.setdefault(canonical_ip, []).append(
                    address_object["id"]
                )
        return address_map

    def _log_address_group_limit(
        self, group: Dict, skipped_ips: List[str]
    ):
        """Log the IPs skipped because the Address Group limit is reached.

        Args:
            group (Dict): Target Address Group with 'id' and 'name'.
            skipped_ips (List[str]): IPs that could not be added.
        """
        self.logger.error(
            message=(
                f"{self.log_prefix}: Error occurred while adding IP(s) to "
                f"Address Group '{group['name']}'. The Address Group "
                f"reached its limit of {MAX_ADDRESS_OBJECTS_PER_GROUP} "
                f"IP(s), hence {len(skipped_ips)} IP(s) were skipped."
            ),
            details=f"Skipped IP(s): {', '.join(skipped_ips)}",
            resolution=RESOLUTION_ADDRESS_GROUP_LIMIT,
        )

    def _log_exists_on_tenant(self, group: Dict, ips: List[str]):
        """Log the IPs rejected because they already exist on the tenant.

        Args:
            group (Dict): Target Address Group with 'id' and 'name'.
            ips (List[str]): IPs rejected by Netskope Borderless WAN with 409.
        """
        if len(ips) == 1:
            err_msg = (
                f"Error occurred while adding IP '{ips[0]}' to Address "
                f"Group '{group['name']}'. The IP already exists as an "
                f"Address Object on the {PLATFORM_NAME} tenant, hence it "
                "cannot be added again."
            )
        else:
            err_msg = (
                f"Error occurred while adding {len(ips)} IP(s) to Address "
                f"Group '{group['name']}'. The IP(s) already exist as "
                f"Address Objects on the {PLATFORM_NAME} tenant, hence "
                "they cannot be added again."
            )
        self.logger.error(
            message=f"{self.log_prefix}: {err_msg}",
            details=f"IP(s) existing on the tenant: {', '.join(ips)}",
            resolution=RESOLUTION_EXISTS_ON_TENANT,
        )

    def _log_skipped_after_fatal_error(
        self,
        group: Dict,
        action_value: str,
        error: NetskopeBwanFatalAPIException,
        failed_ip: str,
        skipped_ips: List[str],
    ):
        """Log once the IPs skipped after a non-recoverable API error.

        Args:
            group (Dict): Target Address Group with 'id' and 'name'.
            action_value (str): Action value being executed.
            error (NetskopeBwanFatalAPIException): Error received for
                failed_ip.
            failed_ip (str): IP whose request failed.
            skipped_ips (List[str]): IPs not sent to the API.
        """
        if action_value == ADD_TO_ADDRESS_GROUP:
            operation = f"adding IP(s) to Address Group '{group['name']}'"
        else:
            operation = (
                f"removing IP(s) from Address Group '{group['name']}'"
            )
        self.logger.error(
            message=(
                f"{self.log_prefix}: Error occurred while {operation}. The "
                f"request for IP '{failed_ip}' {error.reason}, hence "
                f"skipped the remaining {len(skipped_ips)} IP(s) without "
                "calling the API."
            ),
            details=f"Skipped IP(s): {', '.join(skipped_ips)}",
            **(
                {"resolution": error.resolution} if error.resolution else {}
            ),
        )

    def _add_ips_to_group(
        self, group: Dict, ips: List[str]
    ) -> Optional[Dict[str, List[str]]]:
        """Add the IPs to an Address Group, one API call per IP.

        The Address Objects of the group are fetched first, so that IPs
        already present are not sent again. New IPs are then sent one by
        one while the group is below MAX_ADDRESS_OBJECTS_PER_GROUP. Only
        an IP that is actually added uses up a slot; an IP rejected with
        409 (already exists) or a failed call does not. Once the group
        is full, the remaining IPs are marked as limit exceeded without
        any API call. After a non-recoverable error (retries exhausted
        on 429/5xx, or 401/403), the remaining IPs are marked as failed
        without any API call.

        Args:
            group (Dict): Target Address Group with 'id' and 'name'.
            ips (List[str]): Canonical IPs.

        Returns:
            Optional[Dict[str, List[str]]]: IPs per outcome key, or None
                when the Address Objects could not be fetched.
        """
        try:
            address_objects = self._get_all_address_objects(
                self.configuration, group["id"], group["name"]
            )
        except NetskopeBwanPluginException:
            return None
        existing_ips = self._build_address_map(address_objects)
        # Every Address Object uses a slot of the Address Group limit.
        existing_count = len(address_objects)

        outcomes = {
            OUTCOME_ADDED: [],
            OUTCOME_ALREADY_EXISTS: [],
            OUTCOME_EXISTS_ON_TENANT: [],
            OUTCOME_LIMIT_EXCEEDED: [],
            OUTCOME_FAILED: [],
        }
        new_ips = []
        for ip in ips:
            if ip in existing_ips:
                outcomes[OUTCOME_ALREADY_EXISTS].append(ip)
            else:
                new_ips.append(ip)
        capacity = max(0, MAX_ADDRESS_OBJECTS_PER_GROUP - existing_count)
        for index, ip in enumerate(new_ips):
            if capacity <= 0:
                outcomes[OUTCOME_LIMIT_EXCEEDED] = new_ips[index:]
                break
            try:
                outcome = self._add_address_object(
                    self.configuration, group["id"], group["name"], ip
                )
            except NetskopeBwanFatalAPIException as error:
                skipped_ips = new_ips[index + 1:]
                outcomes[OUTCOME_FAILED].extend([ip] + skipped_ips)
                if skipped_ips:
                    self._log_skipped_after_fatal_error(
                        group, ADD_TO_ADDRESS_GROUP, error, ip, skipped_ips
                    )
                break
            except NetskopeBwanPluginException:
                outcome = OUTCOME_FAILED
            outcomes[outcome].append(ip)
            if outcome == OUTCOME_ADDED:
                capacity -= 1

        if outcomes[OUTCOME_EXISTS_ON_TENANT]:
            self._log_exists_on_tenant(
                group, outcomes[OUTCOME_EXISTS_ON_TENANT]
            )
        if outcomes[OUTCOME_LIMIT_EXCEEDED]:
            self._log_address_group_limit(
                group, outcomes[OUTCOME_LIMIT_EXCEEDED]
            )
        return outcomes

    def _remove_ips_from_group(
        self, group: Dict, ips: List[str]
    ) -> Optional[Dict[str, List[str]]]:
        """Remove the IPs from an Address Group.

        All the Address Objects of the group are fetched once and each
        matching Address Object is deleted with a separate API call.
        After a non-recoverable error (retries exhausted on 429/5xx, or
        401/403), the remaining IPs present in the group are marked as
        failed without any API call.

        Args:
            group (Dict): Target Address Group with 'id' and 'name'.
            ips (List[str]): Canonical IPs.

        Returns:
            Optional[Dict[str, List[str]]]: IPs per outcome key, or None
                when the Address Objects could not be fetched.
        """
        try:
            objects = self._get_all_address_objects(
                self.configuration, group["id"], group["name"]
            )
        except NetskopeBwanPluginException:
            return None
        address_map = self._build_address_map(objects)

        outcomes = {
            OUTCOME_REMOVED: [],
            OUTCOME_NOT_FOUND: [],
            OUTCOME_FAILED: [],
        }
        fatal_error, fatal_ip, skipped_ips = None, None, []
        for ip in ips:
            if ip not in address_map:
                outcomes[OUTCOME_NOT_FOUND].append(ip)
                continue
            if fatal_error:
                skipped_ips.append(ip)
                continue
            ip_outcomes = set()
            for object_id in address_map[ip]:
                try:
                    ip_outcomes.add(
                        self._delete_address_object(
                            self.configuration,
                            group["id"],
                            group["name"],
                            object_id,
                            ip,
                        )
                    )
                except NetskopeBwanFatalAPIException as error:
                    ip_outcomes.add(OUTCOME_FAILED)
                    fatal_error, fatal_ip = error, ip
                    break
                except NetskopeBwanPluginException:
                    ip_outcomes.add(OUTCOME_FAILED)
            if OUTCOME_FAILED in ip_outcomes:
                outcomes[OUTCOME_FAILED].append(ip)
            elif OUTCOME_REMOVED in ip_outcomes:
                outcomes[OUTCOME_REMOVED].append(ip)
            else:
                outcomes[OUTCOME_NOT_FOUND].append(ip)
        if skipped_ips:
            outcomes[OUTCOME_FAILED].extend(skipped_ips)
            self._log_skipped_after_fatal_error(
                group,
                REMOVE_FROM_ADDRESS_GROUP,
                fatal_error,
                fatal_ip,
                skipped_ips,
            )
        return outcomes

    def _process_bucket(
        self,
        action_value: str,
        group: Dict,
        ip_to_ids: Dict[str, Set[str]],
        bucket_actions: List[Dict],
        failed_ids: Set[str],
    ):
        """Execute the action for every record of one bucket.

        A record is failed when any of its IPs failed.

        Args:
            action_value (str): Action value being executed.
            group (Dict): Target Address Group with 'id' and 'name'.
            ip_to_ids (Dict[str, Set[str]]): Canonical IP to action IDs,
                as returned by _collect_bucket_ips.
            bucket_actions (List[Dict]): Actions of the bucket.
            failed_ids (Set[str]): Failed action IDs (updated in place).
        """
        ips = list(ip_to_ids)
        if action_value == ADD_TO_ADDRESS_GROUP:
            outcomes = self._add_ips_to_group(group, ips)
        else:
            outcomes = self._remove_ips_from_group(group, ips)
        if outcomes is None:
            failed_ids.update(self._get_action_ids(bucket_actions))
            return

        failed_ips = (
            outcomes[OUTCOME_FAILED]
            + outcomes.get(OUTCOME_LIMIT_EXCEEDED, [])
            + outcomes.get(OUTCOME_EXISTS_ON_TENANT, [])
        )
        bucket_failed_ids: Set[str] = set()
        for ip in failed_ips:
            bucket_failed_ids.update(ip_to_ids.get(ip, set()))
        failed_ids.update(bucket_failed_ids)
        changed_key = (
            OUTCOME_ADDED
            if action_value == ADD_TO_ADDRESS_GROUP
            else OUTCOME_REMOVED
        )
        changed_ips = set(outcomes.get(changed_key, []))
        # A record is failed when any of its IPs failed, but its other
        # IPs may have been applied. They are listed so that an admin
        # can clean them up, since CE does not revert failed records.
        applied_ips_of_failed_records = [
            ip
            for ip in ips
            if ip in changed_ips
            and ip_to_ids.get(ip, set()) & bucket_failed_ids
        ]
        message, details = self.bwan_helper.build_bucket_summary(
            action_value,
            group["name"],
            outcomes,
            applied_ips_of_failed_records,
        )
        self.logger.info(
            message=f"{self.log_prefix}: {message}", details=details
        )

    def _log_invalid_ips(self, invalid_values: List[str]):
        """Log the invalid IP values skipped across the whole batch.

        Args:
            invalid_values (List[str]): Invalid IP values.
        """
        unique_values = list(dict.fromkeys(invalid_values))
        if not unique_values:
            return
        if len(unique_values) == 1:
            err_msg = (
                f"Error occurred while parsing IP '{unique_values[0]}'. "
                "Only IPv4 addresses and IPv4 CIDR ranges are supported, "
                "hence skipping it."
            )
        else:
            err_msg = (
                f"Error occurred while parsing IP '{unique_values[0]}' "
                f"and {len(unique_values) - 1} other value(s). Only IPv4 "
                "addresses and IPv4 CIDR ranges are supported, hence "
                "skipping them."
            )
        self.logger.error(
            message=f"{self.log_prefix}: {err_msg}",
            details=f"Skipped value(s): {', '.join(unique_values)}",
            resolution=RESOLUTION_INVALID_IP,
        )

    def _build_action_result(
        self,
        action_label: str,
        failed_ids: Set[str],
        actions: List[Dict],
        revert: bool = False,
    ) -> Optional[ActionResult]:
        """Build the final result of the action execution.

        The result is unsuccessful (success=False) when every record of
        the batch failed.

        Args:
            action_label (str): Action label.
            failed_ids (Set[str]): Failed action IDs.
            actions (List[Dict]): Actions of the batch.
            revert (bool): Whether the action was reverted.

        Returns:
            Optional[ActionResult]: None when every record succeeded,
                else an ActionResult with the failed action IDs.
        """
        total = len(actions)
        performed = "reverted" if revert else "performed"
        if not failed_ids:
            self.logger.info(
                f"{self.log_prefix}: Successfully {performed} "
                f"'{action_label}' action on {total} record(s)."
            )
            return None
        message = (
            f"{performed.capitalize()} '{action_label}' action with "
            f"{len(failed_ids)} failed record(s) out of {total}."
        )
        self.logger.info(f"{self.log_prefix}: {message}")
        all_ids = set(self._get_action_ids(actions))
        return ActionResult(
            success=not all_ids.issubset(failed_ids),
            message=message,
            failed_action_ids=list(failed_ids),
        )

    def _store_created_address_group(
        self, bucket_actions: List[Dict], group: Dict
    ):
        """Store the resolved Address Group ID in the action parameters.

        This way, a later revert of a 'Create New Address Group' action
        targets the actual Address Group instead of the placeholder.

        Args:
            bucket_actions (List[Dict]): Actions of the bucket.
            group (Dict): Resolved Address Group with 'id' and 'name'.
        """
        for action_dict in bucket_actions:
            parameters = action_dict.get("params").parameters
            if isinstance(parameters, dict):
                parameters[ADDRESS_GROUP_PARAM] = group["id"]

    def _execute_actions(
        self, actions: List[Dict], revert: bool = False
    ) -> Optional[ActionResult]:
        """Execute the actions in bulk (core implementation).

        The target Address Group is resolved (or created) once per
        bucket and the Address Groups are fetched once per batch.
        Reverting 'Add to Address Group' removes the IPs from the same
        Address Group and vice-versa.

        Args:
            actions (List[Dict]): Non-empty list of actions as
                {"id": str, "params": Action} dicts.
            revert (bool): Whether to revert the actions.

        Returns:
            Optional[ActionResult]: None when every record succeeded,
                else an ActionResult with the failed action IDs.
        """
        first_action = actions[0]["params"]
        action_label, action_value = first_action.label, first_action.value
        if action_value == NO_ACTION:
            self.logger.info(
                f"{self.log_prefix}: Successfully "
                f"{'reverted' if revert else 'performed'} "
                f"'{NO_ACTION_LABEL}' action on {len(actions)} record(s). "
                "Note: No processing will be done from plugin for the "
                f"'{NO_ACTION_LABEL}' action."
            )
            return None
        if action_value not in SUPPORTED_ACTIONS:
            err_msg = (
                f"Error occurred while "
                f"{'reverting' if revert else 'executing'} the action. "
                f"Unsupported action '{action_value}' provided."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                resolution=RESOLUTION_UNSUPPORTED_ACTION,
            )
            return ActionResult(
                success=False,
                message=err_msg,
                failed_action_ids=self._get_action_ids(actions),
            )

        # Reverting an action performs the opposite operation on the
        # same Address Group.
        effective_value = action_value
        if revert:
            effective_value = (
                REMOVE_FROM_ADDRESS_GROUP
                if action_value == ADD_TO_ADDRESS_GROUP
                else ADD_TO_ADDRESS_GROUP
            )
        buckets = self._build_action_buckets(action_value, actions)
        try:
            groups = self._get_all_address_groups(self.configuration)
        except NetskopeBwanPluginException:
            return self._build_action_result(
                action_label,
                set(self._get_action_ids(actions)),
                actions,
                revert,
            )
        groups_by_id = {group["id"]: group for group in groups}
        groups_by_name = {}
        for group in groups:
            groups_by_name.setdefault(
                self._normalize_group_name(group["name"]), group
            )

        failed_ids: Set[str] = set()
        invalid_values: List[str] = []
        for bucket_key, bucket_actions in buckets.items():
            # Parse the IPs first so that no Address Group is created
            # for a bucket without any valid IP (its records are already
            # marked as failed).
            ip_to_ids = self._collect_bucket_ips(
                bucket_actions, failed_ids, invalid_values
            )
            if not ip_to_ids:
                continue
            group = self._resolve_address_group(
                bucket_key,
                action_label,
                groups_by_id,
                groups_by_name,
                revert,
            )
            if not group:
                failed_ids.update(self._get_action_ids(bucket_actions))
                continue
            if bucket_key[0] == BUCKET_CREATE:
                self._store_created_address_group(bucket_actions, group)
            self._process_bucket(
                effective_value, group, ip_to_ids, bucket_actions, failed_ids
            )

        self._log_invalid_ips(invalid_values)
        return self._build_action_result(
            action_label, failed_ids, actions, revert
        )
