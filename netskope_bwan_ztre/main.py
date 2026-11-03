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
import json
import traceback
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

from netskope.common.utils import AlertsHelper, resolve_secret
from netskope.common.models import ActionType
from netskope.common.utils.plugin_provider_helper import PluginProviderHelper
from netskope.integrations.crev2.models import Action, ActionWithoutParams
from netskope.integrations.crev2.utils import get_latest_values
from netskope.integrations.crev2.plugin_base import (
    ActionResult,
    Entity,
    EntityField,
    EntityFieldType,
    PluginBase,
    ValidationResult,
)

from .utils.constants import (
    ACTION_CONTEXT,
    ADDRESS_GROUPS_ENDPOINT,
    ADDRESS_GROUP_ACTIONS,
    ADDRESS_GROUP_PARAM,
    ADDRESS_OBJECTS_ENDPOINT,
    ADDRESS_OBJECT_ENDPOINT,
    ADDRESS_OBJECT_TYPE,
    ADD_TO_ADDRESS_GROUP,
    ADD_TO_ADDRESS_GROUP_LABEL,
    ADD_TO_CUSTOM_APP,
    ADD_TO_CUSTOM_APP_LABEL,
    API_TOKEN_PARAM,
    APP_CATEGORIES_ENDPOINT,
    BUCKET_CREATE,
    BUCKET_CUSTOM_APP,
    BUCKET_EXISTING,
    CATEGORY_LABEL,
    CATEGORY_PARAM,
    CLIENTS_ENTITY,
    CRE_ENTITY_CHECKPOINT_KEYS,
    ENTITY_SUBTYPE,
    CLIENT_ID_FIELD,
    CONFIG_CONTEXT,
    CREATE_NEW_ADDRESS_GROUP_LABEL,
    CREATE_NEW_ADDRESS_GROUP_VALUE,
    CREATE_NEW_CUSTOM_APP_LABEL,
    CREATE_NEW_CUSTOM_APP_VALUE,
    CUSTOM_APPS_ENDPOINT,
    CUSTOM_APP_ENDPOINT,
    CUSTOM_APP_NAME_LABEL,
    CUSTOM_APP_NAME_PARAM,
    DEFAULT_CATEGORY_NAME,
    DEFAULT_MAX_HOSTS,
    DEFAULT_PROTOCOLS,
    DESCRIPTION_PARAM,
    ENTITY_ACCESS_RESOLUTIONS,
    ENTITY_FIELD_MAPPINGS,
    ENTITY_LIST_ENDPOINTS,
    GATEWAYS_ENTITY,
    GATEWAY_ID_FIELD,
    HOST_PARAM,
    HOST_PARAM_LABEL,
    IP_ADDRESS_PARAM,
    IP_PARAM_LABEL,
    MAX_ADDRESS_OBJECTS_PER_GROUP,
    MAX_HOSTS_LABEL,
    MAX_HOSTS_PARAM,
    MIN_CUSTOM_APP_NAME_LENGTH,
    MIN_MAX_HOSTS,
    MODULE_NAME,
    NEW_ADDRESS_GROUP_NAME_LABEL,
    NEW_ADDRESS_GROUP_NAME_PARAM,
    NEW_CUSTOM_APP_NAME_LABEL,
    NEW_CUSTOM_APP_NAME_PARAM,
    NO_ACTION,
    NO_ACTION_LABEL,
    OUTCOME_ADDED,
    OUTCOME_ALREADY_EXISTS,
    OUTCOME_EXISTS_ON_TENANT,
    OUTCOME_FAILED,
    OUTCOME_LIMIT_EXCEEDED,
    OUTCOME_NOT_FOUND,
    OUTCOME_PLACED,
    OUTCOME_REMOVED,
    PLATFORM_NAME,
    PLUGIN_VERSION,
    PROTOCOL_CHOICES,
    PROTOCOL_ICMP,
    PROTOCOL_IPV4,
    PROTOCOL_LABEL,
    PROTOCOL_PARAM,
    PROTOCOL_PORT_LABELS,
    PROTOCOL_PORT_PARAMS,
    PROTOCOL_TCP,
    PROTOCOL_UDP,
    PROTOCOL_VALUES,
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
    RESOLUTION_CUSTOM_APP_IN_POLICY,
    RESOLUTION_CUSTOM_APP_NAME_LENGTH,
    RESOLUTION_CUSTOM_APP_NOT_FOUND,
    RESOLUTION_ENTITY,
    RESOLUTION_EXISTS_ON_TENANT,
    RESOLUTION_FETCH_ADDRESS_GROUPS,
    RESOLUTION_FETCH_ADDRESS_OBJECTS,
    RESOLUTION_FETCH_CATEGORIES,
    RESOLUTION_FETCH_CUSTOM_APPS,
    RESOLUTION_FETCH_USERS,
    RESOLUTION_INVALID_HOST,
    RESOLUTION_INVALID_IP,
    RESOLUTION_INVALID_PORTS,
    RESOLUTION_MAX_HOSTS,
    RESOLUTION_NEW_ADDRESS_GROUP,
    RESOLUTION_NEW_CUSTOM_APP,
    RESOLUTION_NO_ADDRESS_GROUPS,
    RESOLUTION_NO_CUSTOM_APPS,
    RESOLUTION_NO_HOST,
    RESOLUTION_NO_IP,
    RESOLUTION_NO_PROTOCOL,
    RESOLUTION_RECORD_TOO_LARGE,
    RESOLUTION_REMOVE_IP,
    RESOLUTION_REVERT_ADDRESS_GROUP_NOT_FOUND,
    RESOLUTION_SKIP_EXCESS_HOSTS,
    RESOLUTION_TENANT,
    RESOLUTION_UNSUPPORTED_ACTION,
    RESOLUTION_UPDATE_CUSTOM_APP,
    RESOLUTION_WEB_ACCESS,
    SKIP_EXCESS_HOSTS_LABEL,
    SKIP_EXCESS_HOSTS_PARAM,
    SPEC_ONLY_CATEGORIES,
    STATUS_PRECONDITION_FAILED,
    SUPPORTED_ACTIONS,
    SUPPORTED_ENTITIES,
    TCP_PORTS_LABEL,
    TCP_PORTS_PARAM,
    TENANT_CONTEXT,
    UDP_PORTS_LABEL,
    UDP_PORTS_PARAM,
    USERS_ENDPOINT,
    USER_CACHE_KEY,
    USER_CACHE_TTL,
    USER_CACHE_TTL_KEY,
    USER_EMAIL_FIELD,
    USER_EMAIL_KEY,
    VALIDATION_PAGE_SIZE,
    VALIDATION_SUCCESS_MSG,
    WEB_ACCESS_LABEL,
    WEB_ACCESS_PARAM,
)
from .utils.helper import (
    NetskopeBwanFatalAPIException,
    NetskopeBwanPluginException,
    NetskopeBwanPluginHelper,
)


class NetskopeBwanPlugin(PluginBase):
    """Netskope Borderless WAN CRE plugin implementation.

    The plugin fetches Clients and Gateways from the Netskope Borderless
    WAN platform as entity records, appends hosts to the traffic
    definitions of a Custom Application, and adds IPv4 addresses and IPv4 CIDR ranges to Address
    Groups or removes them from Address Groups.
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

        Neither entity carries a Netskope Normalized Score: the Netskope
        Borderless WAN platform exposes no risk score, severity, device
        status, last seen timestamp or health signal on Clients or
        Gateways.

        Returns:
            list[Entity]: Clients and Gateways entities.
        """
        return [
            Entity(
                name=CLIENTS_ENTITY,
                fields=[
                    EntityField(
                        name=CLIENT_ID_FIELD,
                        type=EntityFieldType.STRING,
                        required=True,
                        description=(
                            "Unique identifier of the Client on the "
                            f"{PLATFORM_NAME} platform."
                        ),
                    ),
                    EntityField(
                        name="Name",
                        type=EntityFieldType.STRING,
                        description="Name of the Client.",
                    ),
                    EntityField(
                        name=USER_EMAIL_FIELD,
                        type=EntityFieldType.STRING,
                        description=(
                            "Email address of the user the Client "
                            "configuration is assigned to."
                        ),
                    ),
                    EntityField(
                        name="Created At",
                        type=EntityFieldType.DATETIME,
                        description=(
                            "Time at which the Client was created."
                        ),
                    ),
                    EntityField(
                        name="Modified At",
                        type=EntityFieldType.DATETIME,
                        description=(
                            "Time at which the Client was last modified."
                        ),
                    ),
                    EntityField(
                        name="Template ID",
                        type=EntityFieldType.STRING,
                        description=(
                            "Identifier of the template applied to the "
                            "Client."
                        ),
                    ),
                    EntityField(
                        name="Labels",
                        type=EntityFieldType.LIST,
                        description="Labels applied to the Client.",
                    ),
                    EntityField(
                        name="Overlay IPv4 Address",
                        type=EntityFieldType.STRING,
                        description=(
                            "Overlay IPv4 address of the Client, unique "
                            "per device."
                        ),
                    ),
                    EntityField(
                        name="Serial Number",
                        type=EntityFieldType.STRING,
                        required=True,
                        description=(
                            "Serial value reported by the Client."
                        ),
                    ),
                    EntityField(
                        name="City",
                        type=EntityFieldType.STRING,
                        description="City the Client is located in.",
                    ),
                    EntityField(
                        name="Country",
                        type=EntityFieldType.STRING,
                        description="Country the Client is located in.",
                    ),
                    EntityField(
                        name="IOT Security",
                        type=EntityFieldType.BOOLEAN,
                        description=(
                            "Whether IoT security is enabled on the "
                            "Client."
                        ),
                    ),
                ],
            ),
            Entity(
                name=GATEWAYS_ENTITY,
                fields=[
                    EntityField(
                        name=GATEWAY_ID_FIELD,
                        type=EntityFieldType.STRING,
                        required=True,
                        description=(
                            "Unique identifier of the Gateway on the "
                            f"{PLATFORM_NAME} platform."
                        ),
                    ),
                    EntityField(
                        name="Name",
                        type=EntityFieldType.STRING,
                        description="Name of the Gateway.",
                    ),
                    EntityField(
                        name=USER_EMAIL_FIELD,
                        type=EntityFieldType.STRING,
                        description=(
                            "Email address of the user the Gateway "
                            "configuration is assigned to."
                        ),
                    ),
                    EntityField(
                        name="Created At",
                        type=EntityFieldType.DATETIME,
                        description=(
                            "Time at which the Gateway was created."
                        ),
                    ),
                    EntityField(
                        name="Modified At",
                        type=EntityFieldType.DATETIME,
                        description=(
                            "Time at which the Gateway was last modified."
                        ),
                    ),
                    EntityField(
                        name="Labels",
                        type=EntityFieldType.LIST,
                        description="Labels applied to the Gateway.",
                    ),
                    EntityField(
                        name="Tags",
                        type=EntityFieldType.LIST,
                        description="Tag names applied to the Gateway.",
                    ),
                    EntityField(
                        name="Overlay ID",
                        type=EntityFieldType.NUMBER,
                        description="Overlay identifier of the Gateway.",
                    ),
                    EntityField(
                        name="Is Activated",
                        type=EntityFieldType.BOOLEAN,
                        description=(
                            "Whether the Gateway has been activated."
                        ),
                    ),
                    EntityField(
                        name="Managed",
                        type=EntityFieldType.BOOLEAN,
                        description=(
                            "Whether the Gateway is managed by the "
                            f"{PLATFORM_NAME} platform."
                        ),
                    ),
                    EntityField(
                        name="Config Updates Enabled",
                        type=EntityFieldType.BOOLEAN,
                        description=(
                            "Whether configuration updates are enabled "
                            "on the Gateway."
                        ),
                    ),
                    EntityField(
                        name="Overlay IPv4 Address",
                        type=EntityFieldType.STRING,
                        description=(
                            "Overlay IPv4 address of the Gateway, unique "
                            "per device."
                        ),
                    ),
                    EntityField(
                        name="Role",
                        type=EntityFieldType.STRING,
                        description=(
                            "Role of the Gateway, either 'hub' or "
                            "'spoke'."
                        ),
                    ),
                    EntityField(
                        name="Hardware Model",
                        type=EntityFieldType.STRING,
                        description="Hardware model of the Gateway.",
                    ),
                    EntityField(
                        name="Model Display Name",
                        type=EntityFieldType.STRING,
                        description=(
                            "Display name of the Gateway hardware model."
                        ),
                    ),
                    EntityField(
                        name="Software Version",
                        type=EntityFieldType.STRING,
                        description=(
                            "Software version running on the Gateway."
                        ),
                    ),
                    EntityField(
                        name="Serial Number",
                        type=EntityFieldType.STRING,
                        required=True,
                        description=(
                            "Serial value reported by the Gateway."
                        ),
                    ),
                    EntityField(
                        name="City",
                        type=EntityFieldType.STRING,
                        description="City the Gateway is located in.",
                    ),
                    EntityField(
                        name="Country",
                        type=EntityFieldType.STRING,
                        description="Country the Gateway is located in.",
                    ),
                    EntityField(
                        name="IOT Security",
                        type=EntityFieldType.BOOLEAN,
                        description=(
                            "Whether IoT security is enabled on the "
                            "Gateway."
                        ),
                    ),
                ],
            ),
        ]

    def fetch_records(self, entity: str) -> list:
        """Map the entity records the Tenant delivered.

        The netskope_bwan_tenant provider performs the pull, incremental
        on 'modified_at' against the checkpoint it keeps on the Tenant,
        and Cloud Exchange dispatches each batch here. This method only
        maps the batch that matches the entity it was called for.

        The user fields are the only ones not carried by the record
        itself: the configuration holds the ID of the user it is
        assigned to, which is resolved against the user list endpoint
        before the batch is mapped.

        Args:
            entity (str): Entity name.

        Returns:
            list: Entity records.

        Raises:
            NetskopeBwanPluginException: When the entity is not
                supported.
        """
        mapped_entities = getattr(self, "mappedEntities", []) or []
        self.logger.warn(f"{self.log_prefix}: MAPPED", details=f"{mapped_entities}")
        self._validate_entity(entity)
        # Netskope CRE flow: the netskope_bwan_tenant provider pulls the
        # entity via common.pull and hands the raw records to this plugin
        # as self.data, tagged with self.sub_type. Transform only the batch
        # that matches this entity; the other entity is delivered in its
        # own batch.
        provider_data = getattr(self, "data", None)
        if not provider_data:
            # The plugin never pulls on its own. Cloud Exchange schedules
            # 'cre.update_records' rather than 'cre.fetch_records' for a
            # 'netskope' plugin, and the common pull dispatches only a
            # non-empty batch, hence this method runs only with provider
            # data.
            self.logger.debug(
                f"{self.log_prefix}: No {entity} record was received from "
                f"the {PLATFORM_NAME} Tenant, hence no record was stored."
            )
            return []
        if getattr(self, "sub_type", None) != ENTITY_SUBTYPE.get(entity):
            return []
        if self._user_fields_mapped(entity):
            self._load_user_cache(provider_data)
        else:
            # Neither user field is mapped on this entity, so the user
            # listing is not read at all. Cloud Exchange drops a field the
            # configuration does not map, hence the lookup would be pure
            # overhead -- and a failing listing would otherwise retry and
            # log on every batch of every pull.
            self.bwan_helper.user_cache = {}
            self.logger.debug(
                f"{self.log_prefix}: '{USER_EMAIL_FIELD}' is not "
                f"mapped on the {entity} entity, hence the users were "
                f"not fetched from {PLATFORM_NAME}."
            )
        field_mapping = ENTITY_FIELD_MAPPINGS[entity]
        records = [
            self.bwan_helper.extract_entity_fields(record, field_mapping)
            for record in provider_data
            if isinstance(record, dict)
        ]
        self.logger.info(
            f"{self.log_prefix}: Successfully fetched {len(records)} "
            f"{entity} record(s) from {PLATFORM_NAME}."
        )
        return records

    def update_records(self, entity: str, records: list[dict]) -> list[dict]:
        """Return nothing to refresh.

        Every mapped field already arrives on the entity list endpoint
        that the provider pulls and fetch_records stores, and neither
        entity carries a score, so there is nothing for this hook to
        re-read or recompute. It is intentionally a no-op and makes no
        call to Netskope Borderless WAN.
        """
        return []

    # ------------------------------------------------------------------ #
    # User resolution
    # ------------------------------------------------------------------ #
    def _load_user_cache(self, records: List[Dict]) -> None:
        """Fill the cache the user fields of a batch are resolved from.

        A Client or Gateway configuration carries the ID of the user it
        is assigned to, not the user itself, hence the email and the
        name are read from the user list endpoint. The resolved users
        are kept on the tenant (provider) storage, which outlives the
        pull, so the listing is read only when a batch carries a user
        ID the cache does not hold yet.

        The batch is always mapped with whatever the cache holds. A
        listing that could not be read leaves the user fields of that
        batch empty instead of failing it.

        Args:
            records (List[Dict]): Records of the batch.
        """
        self.bwan_helper.user_cache = {}
        self.bwan_helper.user_lookup_failed = False
        user_ids = self.bwan_helper.collect_user_ids(records)
        if not user_ids:
            # No record of the batch is assigned to a user, hence the
            # user listing is not read at all.
            return
        try:
            tenant_name = self._get_tenant(self.configuration).name
        except Exception:
            self.bwan_helper.user_lookup_failed = True
            self._log_user_fields_skipped(
                f"the {PLATFORM_NAME} Tenant could not be resolved",
                details=traceback.format_exc(),
            )
            return
        cache, expires_at = self._read_user_cache(tenant_name)
        expired = expires_at is None or datetime.now() > expires_at
        missing = bool(user_ids - set(cache))
        if expired or missing:
            # Read the listing when the cache has gone stale, and also
            # when the batch names a user it does not hold yet.
            users = self._get_all_users()
            if users is None:
                # Keep serving the cache, but record that the listing
                # was not read: a user the cache does not hold is then
                # left out of the record rather than cleared.
                self.bwan_helper.user_cache = cache
                self.bwan_helper.user_lookup_failed = True
                return
            # The listing carries every user, hence a cached user it
            # does not carry was deleted and is dropped.
            if expired:
                # On a TTL refresh the whole cache is rebuilt from the
                # listing, so the IDs recorded as unresolvable are
                # pruned: a user created since the last read would
                # otherwise never resolve.
                cache = {}
            else:
                # A refresh triggered by an unknown ID keeps them, so a
                # record assigned to a deleted user does not read the
                # listing again on every batch that carries it.
                cache = {
                    user_id: user
                    for user_id, user in cache.items()
                    if not user
                }
            cache.update(users)
            for user_id in user_ids - set(cache):
                cache[user_id] = {}
            # The expiry is measured from the moment the listing was
            # read, not from the start of the batch.
            self._write_user_cache(
                tenant_name, cache, datetime.now() + USER_CACHE_TTL
            )
        self.bwan_helper.user_cache = cache

    def _get_all_users(self) -> Optional[Dict[str, Dict]]:
        """Read every user from Netskope Borderless WAN.

        Returns:
            Optional[Dict[str, Dict]]: User ID to email and name
                mapping, or None when the listing could not be read.
        """
        logger_msg = f"fetching the users from {PLATFORM_NAME}"
        try:
            base_url, _ = self._get_config_params(self.configuration)
            users = self.bwan_helper.fetch_paginated_data(
                logger_msg=logger_msg,
                url=USERS_ENDPOINT.format(base_url=base_url),
                headers=self._get_headers(self.configuration),
                is_config_token=self._is_config_token(self.configuration),
                verify=self.ssl_validation,
                proxies=self.proxy,
                resolution=RESOLUTION_FETCH_USERS,
                entity_label="user",
            )
        except Exception:
            # A token that cannot read the users still pulls the
            # entity: the batch is stored without the user fields
            # rather than being failed.
            self._log_user_fields_skipped(
                f"they could not be fetched from {PLATFORM_NAME}",
                details=traceback.format_exc(),
            )
            return None
        resolved = {}
        for user in users:
            user_id = user.get("id")
            if not isinstance(user_id, str) or not user_id.strip():
                continue
            resolved[user_id.strip()] = {
                USER_EMAIL_KEY: self._get_user_text(user, USER_EMAIL_KEY),
            }
        self.logger.debug(
            f"{self.log_prefix}: Successfully fetched {len(resolved)} "
            f"user(s) from {PLATFORM_NAME}."
        )
        return resolved

    def _get_user_text(self, user: Dict, key: str) -> str:
        """Get a text value of a user, empty when it carries none.

        Args:
            user (Dict): User record.
            key (str): Key to read.

        Returns:
            str: Value of the key, or an empty string.
        """
        value = user.get(key)
        return value.strip() if isinstance(value, str) else ""

    def _read_user_cache(
        self, tenant_name: str
    ) -> Tuple[Dict[str, Dict], Optional[datetime]]:
        """Get the user cache kept on the tenant storage.

        Args:
            tenant_name (str): Name of the Tenant.

        Returns:
            Tuple[Dict[str, Dict], Optional[datetime]]: Cached users and
                the moment the cache expires. The users are empty when
                the tenant holds none or the storage could not be read,
                and the expiry is None when none is stored, which makes
                the cache stale.
        """
        try:
            tenant_details = (
                PluginProviderHelper().get_tenant_details(tenant_name)
                or {}
            )
            storage = tenant_details.get("storage") or {}
            cache = storage.get(USER_CACHE_KEY)
            expires_at = storage.get(USER_CACHE_TTL_KEY)
            if not isinstance(expires_at, datetime):
                # No expiry stored, or one written before this key
                # existed: treat the cache as stale and read again.
                expires_at = None
            if isinstance(cache, dict):
                return (
                    {
                        user_id: user
                        for user_id, user in cache.items()
                        if isinstance(user_id, str)
                        and isinstance(user, dict)
                    },
                    expires_at,
                )
        except Exception:
            # The cache only saves a read of the user listing, hence it
            # is treated as empty and the listing is read instead.
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Error occurred while reading "
                    f"the user cache from tenant '{tenant_name}'. The "
                    f"users are read from {PLATFORM_NAME} instead."
                ),
                details=traceback.format_exc(),
            )
        return {}, None

    def _write_user_cache(
        self,
        tenant_name: str,
        cache: Dict[str, Dict],
        expires_at: datetime,
    ) -> None:
        """Store the user cache and its expiry on the tenant storage.

        Args:
            tenant_name (str): Name of the Tenant.
            cache (Dict[str, Dict]): Users to store.
            expires_at (datetime): When the cache goes stale and the
                listing is read again.
        """
        try:
            PluginProviderHelper().update_tenant_storage(
                tenant_name,
                update_set={
                    USER_CACHE_KEY: cache,
                    USER_CACHE_TTL_KEY: expires_at,
                },
            )
        except Exception:
            # The batch is already mapped from this cache, hence a
            # failed write only costs another read of the listing.
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Error occurred while storing "
                    f"the user cache on tenant '{tenant_name}'. The "
                    "users are read again on the next batch."
                ),
                details=traceback.format_exc(),
            )

    def _log_user_fields_skipped(
        self, reason: str, details: Optional[str] = None
    ) -> None:
        """Log that a batch is stored without the user fields.

        Args:
            reason (str): Why the users could not be read.
            details (str, optional): Traceback of the failure.
        """
        self.logger.warn(
            message=(
                f"{self.log_prefix}: The {PLATFORM_NAME} users could "
                f"not be read because {reason}, hence the "
                f"'{USER_EMAIL_FIELD}' field is left empty on the "
                "record(s) of this batch. Every other field is stored."
            ),
            details=details,
            resolution=RESOLUTION_FETCH_USERS,
        )

    # ------------------------------------------------------------------ #
    # Configuration helpers
    # ------------------------------------------------------------------ #
    def _get_mapped_entity_names(self) -> Set[str]:
        """Get the names of the entities mapped on this configuration.

        CE sets 'mappedEntities' on the plugin instance before it calls
        get_types_to_pull, and only when the configuration has at least
        one mapping, hence the attribute is read defensively.

        Returns:
            Set[str]: Mapped entity names, empty when none are mapped.
        """
        names = set()
        for entry in getattr(self, "mappedEntities", None) or []:
            name = (
                entry.get("entity")
                if isinstance(entry, dict)
                else getattr(entry, "entity", None)
            )
            if name:
                names.add(name)
        return names

    def _user_fields_mapped(self, entity: str) -> bool:
        """Get whether an entity maps a field that needs the user lookup.

        'User Email' is the only field resolved from the user
        listing. Cloud Exchange drops a field the configuration
        does not map, so reading the listing for an entity that maps
        neither is pure overhead, and a listing that fails would retry
        and log once per batch for as long as the pull runs.

        Every mapping of the entity is examined, because the same entity
        can be mapped to more than one destination.

        Args:
            entity (str): Entity name.

        Returns:
            bool: True when at least one mapping of the entity maps a
                user field.
        """
        for entry in getattr(self, "mappedEntities", None) or []:
            name = (
                entry.get("entity")
                if isinstance(entry, dict)
                else getattr(entry, "entity", None)
            )
            if name != entity:
                continue
            fields = (
                entry.get("fields")
                if isinstance(entry, dict)
                else getattr(entry, "fields", None)
            )
            for field in fields or []:
                source = (
                    field.get("source")
                    if isinstance(field, dict)
                    else getattr(field, "source", None)
                )
                if source == USER_EMAIL_FIELD:
                    return True
        return False

    def get_types_to_pull(self, data_type: str) -> List[str]:
        """Get the Netskope Borderless WAN Tenant data types to pull.

        CE calls this for every active CRE configuration of a Netskope
        tenant to schedule the tenant's common pull tasks. The Clients and
        Gateways are pulled by the netskope_bwan_tenant provider and
        delivered to fetch_records through the netskope CRE common pull
        flow. Declaring the entity subtypes here (under the 'events' data
        type) schedules the tenant.<name>.events pull task and routes each
        entity batch to this plugin with the matching sub_type.

        Only the mapped entities are declared. An unmapped entity would
        otherwise be pulled from the tenant, cross the broker and be
        dropped by fetch_records, while the provider still advanced that
        entity's checkpoint. Mapping it later would then deliver only the
        records modified after that point.

        Args:
            data_type (str): Type of data ('alerts' or 'events').

        Returns:
            List[str]: The subtypes of the mapped entities under 'events';
                [] for any other data type or when nothing is mapped.
        """
        if data_type != "events":
            return []
        mapped = self._get_mapped_entity_names()
        return [
            ENTITY_SUBTYPE[entity]
            for entity in SUPPORTED_ENTITIES
            if entity in mapped
        ]

    def cleanup(self, action_type: str = ActionType.DELETE.value) -> None:
        """Reset the state kept on the tenant on delete.

        The Client and Gateway high water marks and the resolved user
        cache live on the shared tenant (provider) storage, which
        outlives this plugin configuration. Clearing them on delete
        makes a later re-configure treat its first pull as new and fetch
        the entities in full before resuming the incremental,
        'modified_at' based pulls. On disable they are kept, so
        re-enabling the plugin resumes incrementally.

        Args:
            action_type (str): Lifecycle action, 'delete' or 'disable'.
        """
        if action_type != ActionType.DELETE.value:
            return
        try:
            tenant = self._get_tenant(self.configuration)
            PluginProviderHelper().update_tenant_storage(
                tenant.name,
                update_unset={
                    key: ""
                    for key in CRE_ENTITY_CHECKPOINT_KEYS
                    + [USER_CACHE_KEY, USER_CACHE_TTL_KEY]
                },
            )
            self.logger.info(
                f"{self.log_prefix}: Cleared the Client and Gateway pull "
                f"checkpoints and the user cache on tenant "
                f"'{tenant.name}', so a re-configure of the plugin "
                "performs a full pull."
            )
        except Exception:
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Error occurred while clearing the "
                    "entity pull checkpoints and the user cache during "
                    "cleanup."
                ),
                details=traceback.format_exc(),
            )

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
        """Normalize an Address Group or Custom Application name.

        The same rule is used everywhere a group is matched by name: the
        name is converted to a string and stripped. Matching stays
        case-sensitive.

        Args:
            name (Any): Address Group or Custom Application name.

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
            # A Gateway tag write action is intentionally not
            # offered; see DESIGN_NOTES.md, "Why there is no Gateway
            # tag write action". Reading tags is unaffected.
            ActionWithoutParams(
                label=ADD_TO_CUSTOM_APP_LABEL, value=ADD_TO_CUSTOM_APP
            ),
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
        if action.value == ADD_TO_CUSTOM_APP:
            return self._get_custom_app_action_params()
        if action.value not in ADDRESS_GROUP_ACTIONS:
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
        if self.bwan_helper.has_source_field(address_group):
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
        if self.bwan_helper.has_source_field(new_group_name):
            return self._source_field_error(NEW_ADDRESS_GROUP_NAME_LABEL)

        description = parameters.get(DESCRIPTION_PARAM, "")
        if result := self._validate_parameters(
            description,
            "Description",
            required=False,
            context=ACTION_CONTEXT,
        ):
            return result
        if self.bwan_helper.has_source_field(description):
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
        if self.bwan_helper.has_source_field(
            self._flatten_ip_values(ip_address)
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
            parameters = action.parameters or {}
            if action_value == ADD_TO_CUSTOM_APP:
                return self._validate_custom_app_action(parameters)
            action_label = (
                ADD_TO_ADDRESS_GROUP_LABEL
                if action_value == ADD_TO_ADDRESS_GROUP
                else REMOVE_FROM_ADDRESS_GROUP_LABEL
            )
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
    def _get_entities_to_validate(self) -> List[str]:
        """Get the entities a configuration check has to cover.

        Only the entities mapped on the configuration are checked, so a
        configuration is never refused over an endpoint it does not read:
        one that maps Gateways alone needs no access to Clients. When
        nothing is mapped yet, both entities are checked, so that the
        configuration is validated against the access it will need once an
        entity is mapped.

        Returns:
            List[str]: Entity names, in the order they are declared.
        """
        mapped = self._get_mapped_entity_names()
        return [
            entity
            for entity in SUPPORTED_ENTITIES
            if not mapped or entity in mapped
        ]

    def _validate_auth_params(self, configuration: Dict) -> ValidationResult:
        """Validate the credentials against the entities that are mapped.

        Args:
            configuration (Dict): Configuration parameters.

        Returns:
            ValidationResult: Validation result, failed for the first
                entity that could not be read.
        """
        for entity in self._get_entities_to_validate():
            result = self._validate_entity_access(configuration, entity)
            if not result.success:
                return result
        return ValidationResult(success=True, message=VALIDATION_SUCCESS_MSG)

    def _validate_entity_access(
        self, configuration: Dict, entity: str
    ) -> ValidationResult:
        """Read one record from an entity's list endpoint.

        This exercises an endpoint the plugin actually pulls from, rather
        than a generic health endpoint, so a token that cannot read the
        entity is rejected while the configuration is saved instead of
        silently delivering no record at pull time.

        Args:
            configuration (Dict): Configuration parameters.
            entity (str): Entity name.

        Returns:
            ValidationResult: Validation result.
        """
        logger_msg = f"validating the credentials for the {entity} entity"
        try:
            base_url, _ = self._get_config_params(configuration)
            response = self.bwan_helper.api_helper(
                logger_msg=logger_msg,
                url=ENTITY_LIST_ENDPOINTS[entity].format(base_url=base_url),
                method="GET",
                params={"first": VALIDATION_PAGE_SIZE},
                headers=self._get_headers(configuration),
                is_config_token=self._is_config_token(configuration),
                verify=self.ssl_validation,
                proxies=self.proxy,
                is_validation=True,
                resolution=ENTITY_ACCESS_RESOLUTIONS[entity],
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
                f"{self.log_prefix}: Successfully validated the "
                f"credentials for the {entity} entity."
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

        auth_result = self._validate_auth_params(configuration)
        if not auth_result.success:
            return auth_result
        return self._validate_entity_permissions(configuration)

    def _validate_entity_permissions(
        self, configuration: Dict
    ) -> ValidationResult:
        """Validate read access to each mapped entity through the provider.

        _validate_auth_params already reads each mapped entity's own list
        endpoint directly. This check repeats it through the provider's
        ``permission_check``, which is the path the pull itself runs on,
        mirroring the Netskope CRE plugin. Both checks cover the same
        entities: the mapped ones, or both when nothing is mapped.

        Args:
            configuration (Dict): Configuration parameters.

        Returns:
            ValidationResult: Validation result.
        """
        selected = [
            ENTITY_SUBTYPE[entity]
            for entity in self._get_entities_to_validate()
        ]
        logger_msg = "validating the entity permissions on the Tenant"
        try:
            tenant = self._get_tenant(configuration)
            provider = PluginProviderHelper().get_provider(
                tenant_name=tenant.name
            )
            if provider is None:
                # get_provider returns None rather than raising, so
                # calling through it would surface an AttributeError to
                # the user with nothing in the logs.
                return self._validation_error(
                    (
                        f"Error occurred while {logger_msg}. The "
                        f"{PLATFORM_NAME} Tenant could not be loaded."
                    ),
                    RESOLUTION_TENANT,
                )
            provider.permission_check(
                {"events": selected},
                plugin_name=self.plugin_name,
                configuration_name=self.name,
            )
        except NetskopeBwanPluginException as exp:
            return ValidationResult(success=False, message=str(exp))
        except Exception as exp:
            return self._validation_error(
                (
                    f"Error occurred while {logger_msg}. Check logs for "
                    "more details."
                ),
                RESOLUTION_TENANT,
                details=f"{traceback.format_exc()}\nError: {exp}",
            )
        return ValidationResult(
            success=True, message=VALIDATION_SUCCESS_MSG
        )

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

        if action_value == ADD_TO_CUSTOM_APP:
            return self._execute_custom_app_actions(actions, revert)

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

    # ------------------------------------------------------------------ #
    # Entity pull
    # ------------------------------------------------------------------ #
    def _validate_entity(self, entity: str):
        """Check that the entity is supported by the plugin.

        Args:
            entity (str): Entity name.

        Raises:
            NetskopeBwanPluginException: When the entity is not
                supported.
        """
        if entity in SUPPORTED_ENTITIES:
            return
        err_msg = (
            f"Invalid entity '{entity}' found. Only "
            f"'{CLIENTS_ENTITY}' and '{GATEWAYS_ENTITY}' entities are "
            f"supported by the {PLATFORM_NAME} plugin."
        )
        self.logger.error(
            message=f"{self.log_prefix}: {err_msg}",
            resolution=RESOLUTION_ENTITY,
        )
        raise NetskopeBwanPluginException(err_msg)

    # ------------------------------------------------------------------ #
    # Action parameters (2.0.0)
    # ------------------------------------------------------------------ #
    def _get_custom_app_choices(self) -> List[Dict]:
        """Get the Custom Application dropdown choices sorted by name.

        The value of a choice is the name of the Custom Application
        rather than its identifier, because the name is what the
        roll-over siblings of the group are derived from.

        Returns:
            List[Dict]: Choices as {"key": name, "value": name}.

        Raises:
            NetskopeBwanPluginException: When the Custom Applications
                could not be fetched (already logged).
        """
        custom_apps = self._get_all_custom_apps(is_validation=True)
        names = sorted(
            {
                str(custom_app.get("name")).strip()
                for custom_app in custom_apps
                if custom_app.get("name")
            },
            key=lambda name: name.lower(),
        )
        return [{"key": name, "value": name} for name in names]

    def _get_category_choices(self) -> List[Dict]:
        """Get the Category dropdown choices sorted by name.

        'GET /v2/app-categories' returns fewer categories than the API
        accepts, hence the ones the endpoint omits are added from the API
        specification; see DESIGN_NOTES.md, "The two categories missing
        from 'GET /v2/app-categories'".

        Returns:
            List[Dict]: Choices as {"key": name, "value": id}.

        Raises:
            NetskopeBwanPluginException: When the categories could not be
                fetched (already logged).
        """
        logger_msg = f"fetching App Categories from {PLATFORM_NAME}"
        base_url, _ = self._get_config_params(self.configuration)
        categories = self.bwan_helper.fetch_paginated_data(
            logger_msg=logger_msg,
            url=APP_CATEGORIES_ENDPOINT.format(base_url=base_url),
            headers=self._get_headers(self.configuration),
            is_config_token=self._is_config_token(self.configuration),
            verify=self.ssl_validation,
            proxies=self.proxy,
            required_keys=("id", "name"),
            is_validation=True,
            resolution=RESOLUTION_FETCH_CATEGORIES,
            entity_label="App Category",
        )
        by_id = {
            str(category["id"]): str(category["name"])
            for category in categories
        }
        for category in SPEC_ONLY_CATEGORIES:
            by_id.setdefault(category["id"], category["name"])
        return [
            {"key": name, "value": category_id}
            for category_id, name in sorted(
                by_id.items(), key=lambda item: item[1].lower()
            )
        ]

    def _get_custom_app_action_params(self) -> List[Dict]:
        """Get the action parameters of the Add to Custom App action.

        Returns:
            List[Dict]: Action parameters.

        Raises:
            NetskopeBwanPluginException: When the Custom Applications or
                the App Categories could not be fetched.
        """
        app_choices = self._get_custom_app_choices()
        app_choices.append(
            {
                "key": CREATE_NEW_CUSTOM_APP_LABEL,
                "value": CREATE_NEW_CUSTOM_APP_VALUE,
            }
        )
        category_choices = self._get_category_choices()
        default_category = next(
            (
                choice["value"]
                for choice in category_choices
                if choice["key"] == DEFAULT_CATEGORY_NAME
            ),
            category_choices[0]["value"] if category_choices else "",
        )
        return [
            {
                "label": CUSTOM_APP_NAME_LABEL,
                "key": CUSTOM_APP_NAME_PARAM,
                "type": "choice",
                "choices": app_choices,
                "default": app_choices[0]["value"],
                "mandatory": True,
                "description": (
                    "Select an existing Custom Application from the "
                    "available options, or select "
                    f"'{CREATE_NEW_CUSTOM_APP_LABEL}' to create one. "
                    "Select it from the Static field dropdown only."
                ),
            },
            {
                "label": NEW_CUSTOM_APP_NAME_LABEL,
                "key": NEW_CUSTOM_APP_NAME_PARAM,
                "type": "text",
                "default": "",
                "mandatory": False,
                "description": (
                    "Name of the Custom Application to create. Required "
                    f"only when '{CREATE_NEW_CUSTOM_APP_LABEL}' is "
                    f"selected in '{CUSTOM_APP_NAME_LABEL}', and ignored "
                    "otherwise. If a Custom Application with this name "
                    "already exists, it is used instead. Must be at "
                    f"least {MIN_CUSTOM_APP_NAME_LENGTH} characters long. "
                    "Provide it in the Static field only."
                ),
            },
            {
                "label": CATEGORY_LABEL,
                "key": CATEGORY_PARAM,
                "type": "choice",
                "choices": category_choices,
                "default": default_category,
                "mandatory": False,
                "description": (
                    "Category the Custom Application is reported under. "
                    "It is applied to every Custom Application the "
                    "action writes, including an existing one, so the "
                    "base Custom Application and its roll-over siblings "
                    "always carry the same category. Select it from the "
                    "Static field dropdown only."
                ),
            },
            {
                "label": HOST_PARAM_LABEL,
                "key": HOST_PARAM,
                "type": "text",
                "default": "",
                "placeholder": "e.g. 10.0.0.5, app.example.com",
                "mandatory": True,
                "allowMultipleSource": True,
                "description": (
                    "Host address to append to the Custom Application. "
                    "Each value must be an IPv4 address, an IPv4 CIDR "
                    "range, or a fully-qualified domain names or domain:"
                    " at least two labels, letters/digits/hyphens only"
                    " (no underscores), at most 100 characters total, "
                    "optionally with a leftmost wildcard such as "
                    "'*.example.com'. One or more Source fields can be "
                    "selected, and multiple comma-separated values are "
                    "supported."
                ),
            },
            {
                "label": MAX_HOSTS_LABEL,
                "key": MAX_HOSTS_PARAM,
                "type": "number",
                "default": DEFAULT_MAX_HOSTS,
                "mandatory": True,
                "description": (
                    "Maximum number of host slots one Custom "
                    "Application may hold before the action rolls over "
                    "into a sibling or skips the remainder. A slot is "
                    "one host inside one traffic definition, hence a "
                    "host counts once per selected protocol: with all "
                    "four protocols selected a host costs four slots. "
                    "The value must be at least "
                    f"{MIN_MAX_HOSTS}; the upper limit is whatever the "
                    "tenant accepts. Provide it in the Static field "
                    "only."
                ),
            },
            {
                "label": SKIP_EXCESS_HOSTS_LABEL,
                "key": SKIP_EXCESS_HOSTS_PARAM,
                "type": "choice",
                "choices": [
                    {"key": "No", "value": "no"},
                    {"key": "Yes", "value": "yes"},
                ],
                "default": "no",
                "mandatory": True,
                "description": (
                    "A Custom Application holds at most the configured "
                    f"'{MAX_HOSTS_LABEL}' host slots. Select 'No' to "
                    "create roll-over sibling Custom Applications until "
                    "all the hosts are accommodated. Select 'Yes' to "
                    "create no siblings and skip the hosts beyond the "
                    "existing capacity. Select it from the Static field "
                    "dropdown only."
                ),
            },
            {
                "label": PROTOCOL_LABEL,
                "key": PROTOCOL_PARAM,
                "type": "multichoice",
                "choices": PROTOCOL_CHOICES,
                "default": DEFAULT_PROTOCOLS,
                "mandatory": False,
                "description": (
                    "IP protocols the traffic definition matches. One "
                    "traffic definition is written per selected "
                    "protocol. The port parameters apply to TCP and UDP "
                    "only. Select them from the Static field dropdown "
                    "only."
                ),
            },
            {
                "label": TCP_PORTS_LABEL,
                "key": TCP_PORTS_PARAM,
                "type": "text",
                "default": "",
                "placeholder": "e.g. 443, 8080-8090",
                "mandatory": False,
                "description": (
                    "Comma-separated ports or port ranges for the TCP "
                    f"protocol. Enter a value only when 'TCP' is "
                    f"selected in '{PROTOCOL_LABEL}'. When left empty, "
                    "the port range is omitted from the TCP definition "
                    "entirely and the definition matches the protocol "
                    "without a port constraint. Provide it in the "
                    "Static field only."
                ),
            },
            {
                "label": UDP_PORTS_LABEL,
                "key": UDP_PORTS_PARAM,
                "type": "text",
                "default": "",
                "placeholder": "e.g. 53, 5000-5010",
                "mandatory": False,
                "description": (
                    "Comma-separated ports or port ranges for the UDP "
                    f"protocol. Enter a value only when 'UDP' is "
                    f"selected in '{PROTOCOL_LABEL}'. When left empty, "
                    "the port range is omitted from the UDP definition "
                    "entirely and the definition matches the protocol "
                    "without a port constraint. Provide it in the "
                    "Static field only."
                ),
            },
            {
                "label": WEB_ACCESS_LABEL,
                "key": WEB_ACCESS_PARAM,
                "type": "choice",
                "choices": [
                    {"key": "No", "value": "no"},
                    {"key": "Yes", "value": "yes"},
                ],
                "default": "no",
                "mandatory": True,
                "description": (
                    "Whether the traffic definition matches web "
                    "traffic. It is part of the traffic definition, so "
                    f"together with '{PROTOCOL_LABEL}' and the port "
                    "parameters it decides which existing definition "
                    "the hosts are appended to. Select it from the "
                    "Static field dropdown only."
                ),
            },
        ]

    # ------------------------------------------------------------------ #
    # Action validation (2.0.0)
    # ------------------------------------------------------------------ #
    def _get_yes_no_param(self, value: Any) -> Optional[bool]:
        """Get the boolean carried by a Yes or No action parameter.

        Args:
            value (Any): Action parameter value.

        Returns:
            Optional[bool]: True for 'yes', False for 'no', None when
                the value is neither.
        """
        if isinstance(value, bool):
            return value
        if isinstance(value, str):
            normalized = value.strip().lower()
            if normalized in ("yes", "true"):
                return True
            if normalized in ("no", "false"):
                return False
        return None

    def _validate_static_param(
        self, value: Any, field_label: str, is_choice: bool = False
    ) -> Optional[ValidationResult]:
        """Reject a Source field on a Static-only action parameter.

        Args:
            value (Any): Action parameter value.
            field_label (str): Label of the field.
            is_choice (bool, optional): Whether the field is a dropdown.

        Returns:
            Optional[ValidationResult]: None when valid, else a failed
                ValidationResult.
        """
        if self.bwan_helper.has_source_field(value):
            return self._source_field_error(field_label, is_choice=is_choice)
        return None

    def _validate_custom_app_action(
        self, parameters: Dict
    ) -> ValidationResult:
        """Validate the configuration of the Add to Custom App action.

        Args:
            parameters (Dict): Action parameters.

        Returns:
            ValidationResult: Validation result.
        """
        if result := self._validate_custom_app_target(parameters):
            return result
        if result := self._validate_custom_app_capacity(parameters):
            return result
        if result := self._validate_custom_app_definition(parameters):
            return result
        if result := self._validate_custom_app_hosts(parameters):
            return result
        self.logger.debug(
            f"{self.log_prefix}: Successfully validated action "
            f"configuration for '{ADD_TO_CUSTOM_APP_LABEL}'."
        )
        return ValidationResult(success=True, message=VALIDATION_SUCCESS_MSG)

    def _validate_custom_app_target(
        self, parameters: Dict
    ) -> Optional[ValidationResult]:
        """Validate the Custom Application the action writes to.

        Args:
            parameters (Dict): Action parameters.

        Returns:
            Optional[ValidationResult]: None when valid, else a failed
                ValidationResult.
        """
        custom_app_name = parameters.get(CUSTOM_APP_NAME_PARAM, "")
        if isinstance(custom_app_name, str):
            custom_app_name = custom_app_name.strip()
        if result := self._validate_parameters(
            custom_app_name, CUSTOM_APP_NAME_LABEL, context=ACTION_CONTEXT
        ):
            return result
        if result := self._validate_static_param(
            custom_app_name, CUSTOM_APP_NAME_LABEL, is_choice=True
        ):
            return result

        if custom_app_name == CREATE_NEW_CUSTOM_APP_VALUE:
            new_name = parameters.get(NEW_CUSTOM_APP_NAME_PARAM, "")
            if isinstance(new_name, str):
                new_name = new_name.strip()
            if not new_name:
                return self._validation_error(
                    (
                        "Error occurred while validating action "
                        f"parameters. '{NEW_CUSTOM_APP_NAME_LABEL}' is "
                        f"required when '{CREATE_NEW_CUSTOM_APP_LABEL}' "
                        f"is selected in '{CUSTOM_APP_NAME_LABEL}'."
                    ),
                    RESOLUTION_NEW_CUSTOM_APP,
                )
            if result := self._validate_static_param(
                new_name, NEW_CUSTOM_APP_NAME_LABEL
            ):
                return result
            if len(new_name) < MIN_CUSTOM_APP_NAME_LENGTH:
                return self._validation_error(
                    (
                        "Error occurred while validating action "
                        f"parameters. '{NEW_CUSTOM_APP_NAME_LABEL}' must "
                        f"be at least {MIN_CUSTOM_APP_NAME_LENGTH} "
                        "characters long."
                    ),
                    RESOLUTION_CUSTOM_APP_NAME_LENGTH,
                    details=f"Provided value: '{new_name}'",
                )
        else:
            try:
                custom_apps = self._get_all_custom_apps(is_validation=True)
            except NetskopeBwanPluginException as exp:
                return ValidationResult(success=False, message=str(exp))
            existing_names = {
                str(custom_app.get("name")).strip()
                for custom_app in custom_apps
            }
            if not existing_names:
                return self._validation_error(
                    (
                        "Error occurred while validating action "
                        f"parameters. No Custom Applications found on "
                        f"{PLATFORM_NAME}."
                    ),
                    RESOLUTION_NO_CUSTOM_APPS,
                )
            if custom_app_name not in existing_names:
                return self._validation_error(
                    (
                        "Error occurred while validating action "
                        "parameters. The selected Custom Application "
                        f"'{custom_app_name}' does not exist on "
                        f"{PLATFORM_NAME}. It may have been deleted."
                    ),
                    RESOLUTION_CUSTOM_APP_NOT_FOUND,
                )

        category = parameters.get(CATEGORY_PARAM, "")
        if category:
            if result := self._validate_static_param(
                category, CATEGORY_LABEL, is_choice=True
            ):
                return result
            if not str(category).strip().isdigit():
                return self._validation_error(
                    (
                        "Error occurred while validating action "
                        f"parameters. Invalid '{CATEGORY_LABEL}' "
                        "provided."
                    ),
                    f"Ensure that '{CATEGORY_LABEL}' is selected from "
                    "the Static field dropdown only.",
                    details=f"Provided value: '{category}'",
                )
        return None

    def _validate_custom_app_capacity(
        self, parameters: Dict
    ) -> Optional[ValidationResult]:
        """Validate the host cap and the roll-over behaviour.

        Args:
            parameters (Dict): Action parameters.

        Returns:
            Optional[ValidationResult]: None when valid, else a failed
                ValidationResult.
        """
        max_hosts = parameters.get(MAX_HOSTS_PARAM)
        if result := self._validate_static_param(max_hosts, MAX_HOSTS_LABEL):
            return result
        if max_hosts is None or max_hosts == "":
            return self._validation_error(
                (
                    "Error occurred while validating action parameters. "
                    f"'{MAX_HOSTS_LABEL}' is a required action parameter."
                ),
                RESOLUTION_MAX_HOSTS,
            )
        try:
            max_hosts = int(str(max_hosts).strip())
        except (TypeError, ValueError):
            return self._validation_error(
                (
                    "Error occurred while validating action parameters. "
                    f"Invalid '{MAX_HOSTS_LABEL}' provided."
                ),
                RESOLUTION_MAX_HOSTS,
            )
        if max_hosts < MIN_MAX_HOSTS:
            return self._validation_error(
                (
                    "Error occurred while validating action parameters. "
                    f"'{MAX_HOSTS_LABEL}' must be at least "
                    f"{MIN_MAX_HOSTS}."
                ),
                RESOLUTION_MAX_HOSTS,
                details=f"Provided value: '{max_hosts}'",
            )

        skip_excess = parameters.get(SKIP_EXCESS_HOSTS_PARAM, "")
        if result := self._validate_static_param(
            skip_excess, SKIP_EXCESS_HOSTS_LABEL, is_choice=True
        ):
            return result
        if self._get_yes_no_param(skip_excess) is None:
            return self._validation_error(
                (
                    "Error occurred while validating action parameters. "
                    f"Invalid '{SKIP_EXCESS_HOSTS_LABEL}' provided."
                ),
                RESOLUTION_SKIP_EXCESS_HOSTS,
                details=f"Provided value: '{skip_excess}'",
            )
        return None

    def _validate_custom_app_definition(
        self, parameters: Dict
    ) -> Optional[ValidationResult]:
        """Validate the traffic definition the action writes.

        Args:
            parameters (Dict): Action parameters.

        Returns:
            Optional[ValidationResult]: None when valid, else a failed
                ValidationResult.
        """
        protocols = parameters.get(PROTOCOL_PARAM, [])
        if result := self._validate_static_param(
            protocols, PROTOCOL_LABEL, is_choice=True
        ):
            return result
        if isinstance(protocols, str):
            protocols = self.bwan_helper.normalize_values(protocols)
        if not isinstance(protocols, list) or not protocols:
            return self._validation_error(
                (
                    "Error occurred while validating action parameters. "
                    f"No protocol selected in '{PROTOCOL_LABEL}'."
                ),
                RESOLUTION_NO_PROTOCOL,
            )
        invalid_protocols = [
            protocol
            for protocol in protocols
            if protocol not in PROTOCOL_VALUES
        ]
        if invalid_protocols:
            return self._validation_error(
                (
                    "Error occurred while validating action parameters. "
                    f"Invalid '{PROTOCOL_LABEL}' provided."
                ),
                RESOLUTION_NO_PROTOCOL,
                details=(
                    f"Invalid value(s): {', '.join(invalid_protocols)}"
                ),
            )

        # Both port parameters are validated only for a protocol that is
        # actually selected. Cloud Exchange defaults a parameter's field
        # toggle to Source even for a Static-only parameter, so an
        # operator who leaves an unused protocol's port field untouched
        # - the common case, since they only care about the protocol
        # they selected - would otherwise be forced to switch it to
        # Static and clear it just to pass validation. See
        # DESIGN_NOTES.md, "TCP and UDP ports are only validated when
        # their protocol is selected".
        for protocol in (PROTOCOL_TCP, PROTOCOL_UDP):
            if protocol not in protocols:
                continue
            port_param = PROTOCOL_PORT_PARAMS[protocol]
            port_label = PROTOCOL_PORT_LABELS[protocol]
            ports = parameters.get(port_param, "")
            if result := self._validate_static_param(ports, port_label):
                return result
            if not ports:
                continue
            _, invalid_ports = self.bwan_helper.parse_port_ranges(ports)
            if invalid_ports:
                return self._validation_error(
                    (
                        "Error occurred while validating action "
                        f"parameters. '{port_label}' contains invalid "
                        "value(s)."
                    ),
                    RESOLUTION_INVALID_PORTS,
                    details=f"Invalid value(s): {', '.join(invalid_ports)}",
                )

        web_access = parameters.get(WEB_ACCESS_PARAM, "")
        if result := self._validate_static_param(
            web_access, WEB_ACCESS_LABEL, is_choice=True
        ):
            return result
        if self._get_yes_no_param(web_access) is None:
            return self._validation_error(
                (
                    "Error occurred while validating action parameters. "
                    f"Invalid '{WEB_ACCESS_LABEL}' provided."
                ),
                RESOLUTION_WEB_ACCESS,
                details=f"Provided value: '{web_access}'",
            )
        return None

    def _validate_custom_app_hosts(
        self, parameters: Dict
    ) -> Optional[ValidationResult]:
        """Validate the Host action parameter.

        A Static field is validated here, while a Source field is
        validated when the action is executed, where the invalid values
        of a record are skipped and the valid ones are pushed.

        Args:
            parameters (Dict): Action parameters.

        Returns:
            Optional[ValidationResult]: None when valid, else a failed
                ValidationResult.
        """
        host = parameters.get(HOST_PARAM, "")
        if result := self._validate_parameters(
            host, HOST_PARAM_LABEL, field_type=None, context=ACTION_CONTEXT
        ):
            return result
        if self.bwan_helper.has_source_field(host):
            self.logger.debug(
                f"{self.log_prefix}: '{HOST_PARAM_LABEL}' contains the "
                "Source Field, hence validation for this field will be "
                "performed while executing the "
                f"'{ADD_TO_CUSTOM_APP_LABEL}' action."
            )
            return None
        valid_hosts, invalid_hosts = self.bwan_helper.parse_hosts(host)
        if invalid_hosts:
            return self._validation_error(
                (
                    "Error occurred while validating action parameters. "
                    f"'{HOST_PARAM_LABEL}' contains invalid value(s)."
                ),
                RESOLUTION_INVALID_HOST,
                details=f"Invalid value(s): {', '.join(invalid_hosts)}",
            )
        if not valid_hosts:
            return self._validation_error(
                (
                    "Error occurred while validating action parameters. "
                    f"No host provided in '{HOST_PARAM_LABEL}'."
                ),
                RESOLUTION_NO_HOST,
            )
        return None

    # ------------------------------------------------------------------ #
    # Add to Custom App - API wrappers
    # ------------------------------------------------------------------ #
    def _get_all_custom_apps(
        self, is_validation: bool = False
    ) -> List[Dict]:
        """Fetch all the Custom Applications from Netskope Borderless WAN.

        The whole list is fetched rather than filtered by name, because
        'filter=name:' matches a name exactly and therefore cannot
        return the numbered siblings of a roll-over group. It also
        returns zero results for a name holding a space unless the value
        is quoted, which makes it unsafe for sibling names such as
        '<App> 2'.

        Args:
            is_validation (bool, optional): Whether called from
                validation. Validation calls are not retried.

        Returns:
            List[Dict]: Custom Applications having both 'id' and 'name'.

        Raises:
            NetskopeBwanPluginException: When the fetch fails.
        """
        logger_msg = f"fetching Custom Applications from {PLATFORM_NAME}"
        try:
            base_url, _ = self._get_config_params(self.configuration)
            custom_apps = self.bwan_helper.fetch_paginated_data(
                logger_msg=logger_msg,
                url=CUSTOM_APPS_ENDPOINT.format(base_url=base_url),
                headers=self._get_headers(self.configuration),
                is_config_token=self._is_config_token(self.configuration),
                verify=self.ssl_validation,
                proxies=self.proxy,
                required_keys=("id", "name"),
                is_validation=is_validation,
                resolution=RESOLUTION_FETCH_CUSTOM_APPS,
                entity_label="Custom Application",
            )
            self.logger.debug(
                f"{self.log_prefix}: Successfully fetched "
                f"{len(custom_apps)} Custom Application(s) from "
                f"{PLATFORM_NAME}."
            )
            return custom_apps
        except NetskopeBwanPluginException:
            raise
        except Exception as exp:
            raise self.bwan_helper.handle_unexpected_error(logger_msg, exp)

    def _get_custom_app(self, app_id: str, name: str) -> Optional[Dict]:
        """Read one Custom Application from Netskope Borderless WAN.

        Args:
            app_id (str): Identifier of the Custom Application.
            name (str): Name of the Custom Application.

        Returns:
            Optional[Dict]: The Custom Application, or None when it no
                longer exists on the platform.

        Raises:
            NetskopeBwanPluginException: When it could not be read.
        """
        logger_msg = (
            f"reading Custom Application '{name}' from {PLATFORM_NAME}"
        )
        base_url, _ = self._get_config_params(self.configuration)
        try:
            response = self.bwan_helper.api_helper(
                logger_msg=logger_msg,
                url=CUSTOM_APP_ENDPOINT.format(
                    base_url=base_url, custom_app_id=app_id
                ),
                method="GET",
                headers=self._get_headers(self.configuration),
                is_config_token=self._is_config_token(self.configuration),
                verify=self.ssl_validation,
                proxies=self.proxy,
                is_handle_error_required=False,
                resolution=RESOLUTION_CUSTOM_APP_NOT_FOUND,
            )
            if 200 <= response.status_code < 300:
                return self.bwan_helper.get_json_body(response)
            if response.status_code == 404:
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: Error occurred while "
                        f"{logger_msg}. The Custom Application does not "
                        f"exist on {PLATFORM_NAME}."
                    ),
                    resolution=RESOLUTION_CUSTOM_APP_NOT_FOUND,
                )
                return None
            # handle_error always raises for a non-2xx status code.
            self.bwan_helper.handle_error(
                response,
                logger_msg,
                resolution=RESOLUTION_CUSTOM_APP_NOT_FOUND,
            )
        except NetskopeBwanPluginException:
            raise
        except Exception as exp:
            raise self.bwan_helper.handle_unexpected_error(logger_msg, exp)

    def _patch_custom_app(
        self,
        app_id: str,
        name: str,
        definitions: List[Dict],
        category_id: Optional[int] = None,
    ) -> str:
        """Write the traffic definitions of a Custom Application.

        An HTTP 500 carrying 'connect_err_unavailable' means the write
        was applied in full and only the response timed out, hence the
        Custom Application is re-read and compared instead of being
        written again.

        Args:
            app_id (str): Identifier of the Custom Application.
            name (str): Name of the Custom Application.
            definitions (List[Dict]): Traffic definitions to store.
            category_id (int, optional): Category to apply. When given,
                it is written alongside the definitions, so that every
                member of a group carries the category the action is
                configured with. None leaves the stored category as it
                is, which is what the revert and compaction paths need.

        Returns:
            str: 'placed' or 'failed'.
        """
        logger_msg = (
            f"updating the traffic definitions of Custom Application "
            f"'{name}' on {PLATFORM_NAME}"
        )
        base_url, _ = self._get_config_params(self.configuration)
        try:
            response = self.bwan_helper.api_helper(
                logger_msg=logger_msg,
                url=CUSTOM_APP_ENDPOINT.format(
                    base_url=base_url, custom_app_id=app_id
                ),
                method="PATCH",
                json_data=(
                    {"definitions_v2": definitions}
                    if category_id is None
                    else {
                        "definitions_v2": definitions,
                        # See _create_custom_app: the category is applied
                        # from 'type_id', so both fields carry it.
                        "category_id": category_id,
                        "type_id": category_id,
                    }
                ),
                headers=self._get_headers(self.configuration),
                is_config_token=self._is_config_token(self.configuration),
                verify=self.ssl_validation,
                proxies=self.proxy,
                is_handle_error_required=False,
                resolution=RESOLUTION_UPDATE_CUSTOM_APP,
                is_write=True,
            )
            if 200 <= response.status_code < 300:
                return OUTCOME_PLACED
            if response.status_code == 404:
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: Error occurred while "
                        f"{logger_msg}. The Custom Application does not "
                        f"exist on {PLATFORM_NAME}."
                    ),
                    resolution=RESOLUTION_CUSTOM_APP_NOT_FOUND,
                )
                return OUTCOME_FAILED
            if self.bwan_helper.is_write_applied(response):
                return self._verify_custom_app(
                    app_id, name, definitions, logger_msg
                )
            # handle_error always raises for a non-2xx status code.
            self.bwan_helper.handle_error(
                response,
                logger_msg,
                resolution=RESOLUTION_UPDATE_CUSTOM_APP,
            )
        except NetskopeBwanPluginException:
            return OUTCOME_FAILED
        except Exception as exp:
            self.bwan_helper.handle_unexpected_error(logger_msg, exp)
            return OUTCOME_FAILED

    def _verify_custom_app(
        self,
        app_id: str,
        name: str,
        definitions: List[Dict],
        logger_msg: str,
    ) -> str:
        """Check whether a timed out definition write was applied anyway.

        Hosts are compared as sets, because Netskope Borderless WAN does
        not preserve their order.

        Args:
            app_id (str): Identifier of the Custom Application.
            name (str): Name of the Custom Application.
            definitions (List[Dict]): Definitions the write intended to
                store.
            logger_msg (str): Logger message of the write.

        Returns:
            str: 'placed' when the Custom Application carries the
                intended hosts, else 'failed'.
        """
        try:
            stored_app = self._get_custom_app(app_id, name)
        except NetskopeBwanPluginException:
            return OUTCOME_FAILED
        if stored_app is None:
            return OUTCOME_FAILED
        stored = self.bwan_helper.get_definitions(stored_app)
        for wanted in definitions:
            match = next(
                (
                    definition
                    for definition in stored
                    if self.bwan_helper.definition_matches(
                        definition, wanted
                    )
                ),
                None,
            )
            wanted_hosts = set(wanted.get("hosts") or [])
            if match is None:
                if wanted_hosts:
                    break
                continue
            if not wanted_hosts.issubset(set(match.get("hosts") or [])):
                break
        else:
            self.logger.info(
                f"{self.log_prefix}: The traffic definitions of Custom "
                f"Application '{name}' were applied on {PLATFORM_NAME} "
                "before the request timed out, hence no retry was made "
                f"while {logger_msg}."
            )
            return OUTCOME_PLACED
        self.logger.error(
            message=(
                f"{self.log_prefix}: Error occurred while {logger_msg}. "
                "The request timed out and the traffic definitions of "
                f"Custom Application '{name}' on {PLATFORM_NAME} do not "
                "hold the hosts the action intended to add."
            ),
            resolution=RESOLUTION_UPDATE_CUSTOM_APP,
        )
        return OUTCOME_FAILED

    def _create_custom_app(
        self, name: str, category_id: Optional[int], definitions: List[Dict]
    ) -> Tuple[Optional[str], bool]:
        """Create a Custom Application already holding its definitions.

        'POST /v2/custom-apps' accepts the traffic definitions inline, so
        a roll-over sibling is created already populated and no window
        exists in which an empty sibling is visible. A duplicate name
        returns HTTP 409, which means an application of that name
        already exists; it is then adopted into the group.

        Args:
            name (str): Name of the Custom Application.
            category_id (int, optional): Category to report it under.
            definitions (List[Dict]): Traffic definitions to store.

        Returns:
            Tuple[Optional[str], bool]: Identifier of the Custom
                Application and whether an existing one was adopted.
                The identifier is None when the create failed.

        Raises:
            NetskopeBwanPluginException: When the tenant will not accept
                another Custom Application.
        """
        logger_msg = (
            f"creating Custom Application '{name}' on {PLATFORM_NAME}"
        )
        base_url, _ = self._get_config_params(self.configuration)
        payload = {"name": name, "definitions_v2": definitions}
        if category_id is not None:
            # The tenant reads the category from 'type_id'. 'category_id'
            # is accepted by the API but is not applied to the stored
            # Custom Application, hence the same value is sent in both
            # fields so that the category is set whichever field the
            # tenant honours.
            payload["category_id"] = category_id
            payload["type_id"] = category_id
        try:
            response = self.bwan_helper.api_helper(
                logger_msg=logger_msg,
                url=CUSTOM_APPS_ENDPOINT.format(base_url=base_url),
                method="POST",
                json_data=payload,
                headers=self._get_headers(self.configuration),
                is_config_token=self._is_config_token(self.configuration),
                verify=self.ssl_validation,
                proxies=self.proxy,
                is_handle_error_required=False,
                resolution=RESOLUTION_UPDATE_CUSTOM_APP,
                is_write=True,
            )
        except NetskopeBwanPluginException:
            # Retries exhausted or a transport error, already logged. An
            # earlier attempt may have created it.
            return self._find_custom_app_by_name(name), True

        if 200 <= response.status_code < 300:
            app_id = self.bwan_helper.get_json_body(response).get("id")
            if not app_id:
                return self._find_custom_app_by_name(name), True
            self.logger.info(
                f"{self.log_prefix}: Successfully created Custom "
                f"Application '{name}' on {PLATFORM_NAME}."
            )
            return app_id, False
        if response.status_code == 409:
            self.logger.info(
                f"{self.log_prefix}: Custom Application '{name}' already "
                f"exists on {PLATFORM_NAME}, hence using the existing "
                "Custom Application."
            )
            return self._find_custom_app_by_name(name), True
        if self.bwan_helper.is_write_applied(response):
            # A slow HTTP 500 carrying 'connect_err_unavailable' means
            # the create was applied in full and only the response timed
            # out, hence the Custom Application is looked up instead of
            # the record being reported as failed.
            app_id = self._find_custom_app_by_name(name)
            if app_id:
                self.logger.info(
                    f"{self.log_prefix}: Custom Application '{name}' was "
                    f"created on {PLATFORM_NAME} before the request "
                    "timed out, hence no retry was made while "
                    f"{logger_msg}."
                )
                return app_id, True
        try:
            # handle_error always raises for a non-2xx status code.
            self.bwan_helper.handle_error(
                response,
                logger_msg,
                resolution=RESOLUTION_UPDATE_CUSTOM_APP,
            )
        except NetskopeBwanPluginException:
            pass
        return None, False

    def _find_custom_app_by_name(self, name: str) -> Optional[str]:
        """Re-fetch the Custom Applications and find one by exact name.

        Args:
            name (str): Name of the Custom Application.

        Returns:
            Optional[str]: Its identifier, or None when no Custom
                Application carries that name.
        """
        try:
            custom_apps = self._get_all_custom_apps()
        except NetskopeBwanPluginException:
            return None
        for custom_app in custom_apps:
            if self._normalize_group_name(custom_app.get("name")) == name:
                return custom_app.get("id")
        self.logger.error(
            message=(
                f"{self.log_prefix}: Error occurred while resolving "
                f"Custom Application '{name}'. It was not found on "
                f"{PLATFORM_NAME} after the create request."
            ),
            resolution=RESOLUTION_CUSTOM_APP_NOT_FOUND,
        )
        return None

    def _delete_custom_app(self, app_id: str, name: str) -> bool:
        """Delete a member of a group left holding no hosts.

        Deleting is the only way to clear a Custom Application:
        Netskope Borderless WAN answers HTTP 200 to a PATCH carrying an
        empty 'definitions_v2' array and leaves the stored definitions
        exactly as they were. A failed delete is therefore not an empty
        Custom Application but one still holding its hosts, which the
        revert path reports as a failed record; compaction treats it as
        best effort and leaves it for a later run.

        Args:
            app_id (str): Identifier of the Custom Application.
            name (str): Name of the Custom Application.

        Returns:
            bool: True when the Custom Application was deleted.
        """
        logger_msg = (
            f"deleting Custom Application '{name}' from {PLATFORM_NAME}"
        )
        base_url, _ = self._get_config_params(self.configuration)
        try:
            response = self.bwan_helper.api_helper(
                logger_msg=logger_msg,
                url=CUSTOM_APP_ENDPOINT.format(
                    base_url=base_url, custom_app_id=app_id
                ),
                method="DELETE",
                headers=self._get_headers(self.configuration),
                is_config_token=self._is_config_token(self.configuration),
                verify=self.ssl_validation,
                proxies=self.proxy,
                is_handle_error_required=False,
                resolution=RESOLUTION_UPDATE_CUSTOM_APP,
                is_write=True,
            )
        except NetskopeBwanPluginException:
            return False
        if 200 <= response.status_code < 300 or response.status_code == 404:
            return True
        if response.status_code == STATUS_PRECONDITION_FAILED:
            # The platform refuses to delete a Custom Application that a
            # policy references, which protects an object still in use.
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Error occurred while "
                    f"{logger_msg}. The Custom Application is referenced "
                    f"by one or more policies on {PLATFORM_NAME}, which "
                    "do not allow it to be deleted."
                ),
                details=f"API response: {response.text}",
                resolution=RESOLUTION_CUSTOM_APP_IN_POLICY,
            )
            return False
        self.logger.error(
            message=(
                f"{self.log_prefix}: Error occurred while {logger_msg}. "
                f"Received exit code {response.status_code}."
            ),
            details=f"API response: {response.text}",
            resolution=RESOLUTION_UPDATE_CUSTOM_APP,
        )
        return False

    # ------------------------------------------------------------------ #
    # Add to Custom App - group model
    # ------------------------------------------------------------------ #
    def _get_custom_app_config(self, parameters: Dict) -> Dict:
        """Read the Add to Custom App parameters into one config.

        Args:
            parameters (Dict): Action parameters of one record.

        Returns:
            Dict: Normalized configuration of the action.
        """
        custom_app_name = str(
            parameters.get(CUSTOM_APP_NAME_PARAM) or ""
        ).strip()
        if custom_app_name == CREATE_NEW_CUSTOM_APP_VALUE:
            base_name = self._normalize_group_name(
                parameters.get(NEW_CUSTOM_APP_NAME_PARAM)
            )
        else:
            base_name = self._normalize_group_name(custom_app_name)

        category_id = None
        category = str(parameters.get(CATEGORY_PARAM) or "").strip()
        if category.isdigit():
            category_id = int(category)

        try:
            max_hosts = int(str(parameters.get(MAX_HOSTS_PARAM)).strip())
        except (TypeError, ValueError):
            max_hosts = DEFAULT_MAX_HOSTS

        protocols = parameters.get(PROTOCOL_PARAM) or []
        if isinstance(protocols, str):
            protocols = self.bwan_helper.normalize_values(protocols)
        protocols = [
            protocol
            for protocol in PROTOCOL_VALUES
            if protocol in protocols
        ]

        web_access = bool(
            self._get_yes_no_param(parameters.get(WEB_ACCESS_PARAM))
        )
        definitions = []
        for protocol in protocols:
            port_ranges = []
            port_param = PROTOCOL_PORT_PARAMS.get(protocol)
            if port_param:
                port_ranges, _ = self.bwan_helper.parse_port_ranges(
                    parameters.get(port_param)
                )
            definitions.append(
                self.bwan_helper.build_definition(
                    protocol, web_access, port_ranges
                )
            )
        return {
            "base_name": base_name,
            "is_create": custom_app_name == CREATE_NEW_CUSTOM_APP_VALUE,
            "category_id": category_id,
            "max_hosts": max(max_hosts, MIN_MAX_HOSTS),
            "skip_excess": bool(
                self._get_yes_no_param(
                    parameters.get(SKIP_EXCESS_HOSTS_PARAM)
                )
            ),
            "definitions": definitions,
        }

    def _get_custom_app_bucket_key(self, config: Dict) -> Tuple:
        """Build the grouping key of one Add to Custom App configuration.

        Records of one batch can carry different configurations, hence
        they are grouped by everything that decides where their hosts
        land.

        Args:
            config (Dict): Normalized configuration of the action.

        Returns:
            Tuple: Grouping key.
        """
        return (
            BUCKET_CUSTOM_APP,
            config["base_name"],
            config["is_create"],
            config["max_hosts"],
            config["skip_excess"],
            config["category_id"],
            json.dumps(config["definitions"], sort_keys=True),
        )

    def _enumerate_group(self, base_name: str) -> List[Dict]:
        """Enumerate the members of a roll-over group, in order.

        The base Custom Application counts as member 1 and the siblings
        are named '<base name> 2', '<base name> 3' and so on. A gap in
        the numbering is tolerated: the group is whatever matches the
        pattern, ordered by number.

        Args:
            base_name (str): Name of the base Custom Application.

        Returns:
            List[Dict]: Members ordered by their number.

        Raises:
            NetskopeBwanPluginException: When the Custom Applications
                could not be fetched.
        """
        members = []
        for custom_app in self._get_all_custom_apps():
            number = self.bwan_helper.get_member_number(
                custom_app.get("name"), base_name
            )
            if number is None:
                continue
            members.append(
                {
                    "id": custom_app.get("id"),
                    "name": self._normalize_group_name(
                        custom_app.get("name")
                    ),
                    "number": number,
                    "definitions": None,
                    "changed": False,
                    "record_ids": set(),
                }
            )
        members.sort(key=lambda member: member["number"])
        return members

    def _load_member_definitions(self, members: List[Dict]) -> bool:
        """Read the traffic definitions of every member of a group.

        Args:
            members (List[Dict]): Members of the group (updated in
                place).

        Returns:
            bool: True when every member was read.
        """
        for member in members:
            if member["definitions"] is not None:
                continue
            try:
                custom_app = self._get_custom_app(
                    member["id"], member["name"]
                )
            except NetskopeBwanPluginException:
                return False
            if custom_app is None:
                return False
            member["definitions"] = self.bwan_helper.get_definitions(
                custom_app
            )
        return True

    def _find_definition(
        self, definitions: List[Dict], wanted: Dict
    ) -> Optional[Dict]:
        """Find the definition the hosts may be appended to.

        Args:
            definitions (List[Dict]): Definitions of one member.
            wanted (Dict): Definition the action is configured for.

        Returns:
            Optional[Dict]: Matching definition, or None.
        """
        for definition in definitions:
            if self.bwan_helper.definition_matches(definition, wanted):
                return definition
        return None

    def _merge_definitions(
        self, existing: List[Dict], incoming: List[Dict]
    ) -> List[Dict]:
        """Merge definitions into the ones a Custom Application holds.

        Used when a create returned HTTP 409 and the existing Custom
        Application is adopted into the group: its definitions are kept
        and the hosts of the action are appended to them.

        Args:
            existing (List[Dict]): Definitions already stored.
            incoming (List[Dict]): Definitions the action built.

        Returns:
            List[Dict]: Merged definitions.
        """
        merged = [dict(definition) for definition in existing]
        for definition in incoming:
            match = self._find_definition(merged, definition)
            if match is None:
                merged.append(dict(definition))
                continue
            hosts = list(match.get("hosts") or [])
            known = set(hosts)
            for host in definition.get("hosts") or []:
                if host not in known:
                    known.add(host)
                    hosts.append(host)
            match["hosts"] = hosts
        return merged

    # ------------------------------------------------------------------ #
    # Add to Custom App - placement
    # ------------------------------------------------------------------ #
    def _collect_custom_app_records(
        self, bucket_actions: List[Dict], failed_ids: Set[str]
    ) -> Tuple[List[Dict], List[str]]:
        """Parse the hosts of every record of one bucket.

        A record whose Host field resolves to no valid value is failed,
        rather than issuing a write that would change nothing.

        Args:
            bucket_actions (List[Dict]): Actions of the bucket.
            failed_ids (Set[str]): Failed action IDs (updated in place).

        Returns:
            Tuple[List[Dict], List[str]]: Records as
                {"id": action_id, "hosts": [...]}, and the invalid host
                values of the whole bucket.
        """
        records, invalid_values = [], []
        for action_dict in bucket_actions:
            action_id = action_dict.get("id")
            parameters = action_dict.get("params").parameters or {}
            hosts, invalid = self.bwan_helper.parse_hosts(
                parameters.get(HOST_PARAM)
            )
            invalid_values.extend(invalid)
            if not hosts:
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: Error occurred while "
                        f"executing the '{ADD_TO_CUSTOM_APP_LABEL}' "
                        f"action. No valid host found in "
                        f"'{HOST_PARAM_LABEL}' for a record, hence "
                        "skipping it."
                    ),
                    resolution=RESOLUTION_NO_HOST,
                )
                if action_id is not None:
                    failed_ids.add(action_id)
                continue
            records.append({"id": action_id, "hosts": hosts})
        return records, invalid_values

    def _get_placed_hosts(
        self, members: List[Dict], definitions: List[Dict]
    ) -> List[Set[str]]:
        """Collect the hosts already present anywhere in the group.

        A host already held by any member satisfies its slot, so it is
        never added to a second member. This is what makes the action
        idempotent across a roll-over.

        Args:
            members (List[Dict]): Members of the group.
            definitions (List[Dict]): Definitions the action is
                configured for.

        Returns:
            List[Set[str]]: Hosts present per configured definition.
        """
        placed = []
        for wanted in definitions:
            hosts: Set[str] = set()
            for member in members:
                member_definitions = member["definitions"] or []
                candidates = list(
                    self._find_relaxed_definitions(
                        member_definitions, wanted
                    )
                )
                exact = self._find_definition(member_definitions, wanted)
                if exact is not None and not any(
                    exact is candidate for candidate in candidates
                ):
                    candidates.append(exact)
                for match in candidates:
                    hosts.update(match.get("hosts") or [])
            placed.append(hosts)
        return placed

    def _add_host_to_member(
        self, member: Dict, wanted: Dict, host: str
    ) -> None:
        """Append one host to a member, creating the definition if absent.

        Args:
            member (Dict): Member of the group.
            wanted (Dict): Definition the action is configured for.
            host (str): Host to append.
        """
        definitions = member["definitions"]
        match = self._find_definition(definitions, wanted)
        if match is None:
            relaxed = self._find_relaxed_definitions(definitions, wanted)
            # A duplicate ICMP/IPv4 definition is never written to beyond
            # the first: every duplicate is still checked for the host
            # (see '_get_placed_hosts'), so nothing is ever duplicated,
            # but new hosts only ever grow the first one, rather than
            # writing - and so keeping alive - every duplicate found.
            match = relaxed[0] if relaxed else None
        if match is None:
            match = dict(wanted)
            match["hosts"] = []
            definitions.append(match)
        # The definition dicts are copies the plugin already made, hence
        # the list is appended to in place. Rebuilding it per host made
        # the placement quadratic in the number of hosts.
        match.setdefault("hosts", []).append(host)
        member["changed"] = True

    def _find_relaxed_definitions(
        self, definitions: List[Dict], wanted: Dict
    ) -> List[Dict]:
        """Find every ICMP/IPv4 definition a host may already be present in.

        ICMP and IPv4 definitions carry no ports, so any definition
        sharing protocol and 'Web Access' is the same logical traffic
        regardless of a stray port range an exact match would reject,
        and a tenant can hold more than one such definition, for example
        from a manual edit on the platform. Every one of them is
        returned here so a host already present in any of them is never
        added again, without writing to - or deleting - the duplicates
        themselves.

        TCP and UDP are not given a relaxed match here: a definition's
        'hosts' and 'port_range' are a cross product with no per-host
        port mapping, so appending a host to a definition whose ports
        only cover - rather than exactly equal - the wanted ports would
        silently grant that host every port of the broader definition.
        Only an exact match (handled by '_find_definition') is safe for
        appending a new host to an existing TCP/UDP definition.

        Args:
            definitions (List[Dict]): Definitions of one member.
            wanted (Dict): Definition the action is configured for.

        Returns:
            List[Dict]: Qualifying definitions, in the order they appear
                on the Custom Application. Empty when none qualify and a
                new one must be created.
        """
        protocol = wanted.get("protocol")
        if protocol not in (PROTOCOL_ICMP, PROTOCOL_IPV4):
            return []
        return [
            definition
            for definition in definitions
            if definition.get("protocol") == protocol
            and bool(definition.get("web_access", False))
            == bool(wanted.get("web_access", False))
        ]

    def _place_records(
        self,
        config: Dict,
        records: List[Dict],
        members: List[Dict],
        failed_ids: Set[str],
    ) -> Dict:
        """Place the hosts of every record into the group.

        The slots of one record all land in one member: a half placed
        record is not correct, so a member is used only when it has room
        for every slot the record still needs. A record whose demand
        exceeds the cap outright can never be placed and is failed.

        Args:
            config (Dict): Normalized configuration of the action.
            records (List[Dict]): Records of the bucket.
            members (List[Dict]): Members of the group (updated in
                place).
            failed_ids (Set[str]): Failed action IDs (updated in place).

        Returns:
            Dict: Counts of the placement outcome.
        """
        definitions = config["definitions"]
        max_hosts = config["max_hosts"]
        placed_hosts = self._get_placed_hosts(members, definitions)
        used = [
            self.bwan_helper.count_slots(member["definitions"])
            for member in members
        ]
        counts = {
            "placed_slots": 0,
            "already_present": 0,
            "skipped_records": 0,
            "oversized_records": 0,
            "new_members": 0,
        }
        skipped_hosts: List[str] = []
        for record in records:
            needed = [
                (index, host)
                for index, wanted in enumerate(definitions)
                for host in record["hosts"]
                if host not in placed_hosts[index]
            ]
            if not needed:
                counts["already_present"] += 1
                continue
            if len(needed) > max_hosts:
                counts["oversized_records"] += 1
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: Error occurred while "
                        f"executing the '{ADD_TO_CUSTOM_APP_LABEL}' "
                        f"action. A record needs {len(needed)} host "
                        f"slot(s) while '{MAX_HOSTS_LABEL}' is "
                        f"{max_hosts}, hence it can never be placed in "
                        "a Custom Application."
                    ),
                    resolution=RESOLUTION_RECORD_TOO_LARGE,
                )
                if record["id"] is not None:
                    failed_ids.add(record["id"])
                continue

            target_index = next(
                (
                    index
                    for index in range(len(members))
                    if max_hosts - used[index] >= len(needed)
                ),
                None,
            )
            if target_index is None:
                if config["skip_excess"]:
                    counts["skipped_records"] += 1
                    skipped_hosts.extend(record["hosts"])
                    if record["id"] is not None:
                        failed_ids.add(record["id"])
                    continue
                members.append(self._build_new_member(config, members))
                used.append(0)
                counts["new_members"] += 1
                target_index = len(members) - 1

            member = members[target_index]
            for index, host in needed:
                self._add_host_to_member(member, definitions[index], host)
                placed_hosts[index].add(host)
            used[target_index] += len(needed)
            counts["placed_slots"] += len(needed)
            if record["id"] is not None:
                member["record_ids"].add(record["id"])
        if skipped_hosts:
            self.logger.info(
                message=(
                    f"{self.log_prefix}: Skipped "
                    f"{counts['skipped_records']} record(s) while "
                    f"executing the '{ADD_TO_CUSTOM_APP_LABEL}' action, "
                    f"since '{SKIP_EXCESS_HOSTS_LABEL}' is set to 'Yes' "
                    f"and the Custom Application group "
                    f"'{config['base_name']}' is full."
                ),
                details=(
                    "Skipped host(s): "
                    f"{', '.join(dict.fromkeys(skipped_hosts))}"
                ),
            )
        return counts

    def _build_new_member(
        self, config: Dict, members: List[Dict]
    ) -> Dict:
        """Build the next roll-over sibling of a group.

        The next number is one above the highest existing number, never
        the lowest free gap: reusing a gap races with a concurrent
        delete and risks adopting an application another run is still
        writing to.

        Args:
            config (Dict): Normalized configuration of the action.
            members (List[Dict]): Members of the group.

        Returns:
            Dict: New member, not yet created on the platform.
        """
        next_number = max(
            [member["number"] for member in members] or [1]
        ) + 1
        return {
            "id": None,
            "name": f"{config['base_name']} {next_number}",
            "number": next_number,
            "definitions": [],
            "changed": True,
            "record_ids": set(),
        }

    def _write_member(self, config: Dict, member: Dict) -> str:
        """Create or update one member of a group.

        Args:
            config (Dict): Normalized configuration of the action.
            member (Dict): Member to write.

        Returns:
            str: 'placed' or 'failed'.
        """
        if member["id"]:
            return self._patch_custom_app(
                member["id"],
                member["name"],
                member["definitions"],
                config["category_id"],
            )
        app_id, adopted = self._create_custom_app(
            member["name"], config["category_id"], member["definitions"]
        )
        if not app_id:
            return OUTCOME_FAILED
        member["id"] = app_id
        if not adopted:
            return OUTCOME_PLACED
        # The Custom Application already existed, hence its own traffic
        # definitions are kept and the hosts of the action are merged
        # into them.
        try:
            existing = self._get_custom_app(app_id, member["name"])
        except NetskopeBwanPluginException:
            return OUTCOME_FAILED
        if existing is None:
            return OUTCOME_FAILED
        member["definitions"] = self._merge_definitions(
            self.bwan_helper.get_definitions(existing),
            member["definitions"],
        )
        return self._patch_custom_app(
            member["id"],
            member["name"],
            member["definitions"],
            config["category_id"],
        )

    # ------------------------------------------------------------------ #
    # Add to Custom App - compaction
    # ------------------------------------------------------------------ #
    def _compact_group(self, config: Dict, members: List[Dict]):
        """Re-pack a roll-over group into the fewest Custom Applications.

        Reverts remove hosts in place, so a group drifts toward members
        holding far fewer hosts than they could. Compaction runs once per
        'execute_actions' call, after that batch's writes, and only when
        the re-pack would actually free a member: a merely fragmented
        group is left alone, because re-packing it would cost several
        large writes for no reclaimed Custom Application.

        Only the traffic definitions the action is configured for are
        moved. Any other definition stays in the member that holds it,
        so configuration this action does not own is never relocated
        into the roll-over siblings it created.

        It is best effort - a failure is logged and never fails the
        action that triggered it.

        Args:
            config (Dict): Normalized configuration of the action.
            members (List[Dict]): Members of the group.
        """
        base_name = config["base_name"]
        try:
            max_hosts = config["max_hosts"]
            managed, pinned = self._split_group_definitions(
                members, config["definitions"]
            )
            managed_slots = sum(len(bucket["hosts"]) for bucket in managed)
            capacity = sum(
                max(0, max_hosts - self.bwan_helper.count_slots(entry))
                for entry in pinned
            )
            if managed_slots > capacity:
                self.logger.debug(
                    f"{self.log_prefix}: Skipped compaction of the "
                    f"Custom Application group '{base_name}', since "
                    f"{managed_slots} host slot(s) do not fit in the "
                    f"{capacity} slot(s) the group has free."
                )
                return
            packed = self._pack_layout(
                managed, pinned, max_hosts, len(members)
            )
            freeable = [
                index
                for index, entry in enumerate(packed)
                if not entry and members[index]["number"] != 1
            ]
            if not freeable:
                total_slots = managed_slots + sum(
                    self.bwan_helper.count_slots(entry)
                    for entry in pinned
                )
                self.logger.debug(
                    f"{self.log_prefix}: Skipped compaction of the "
                    f"Custom Application group '{base_name}', since "
                    f"{total_slots} host slot(s) still need every one "
                    f"of its {len(members)} Custom Application(s)."
                )
                return
            self._apply_compaction(config, members, packed)
        except Exception as exp:
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Error occurred while compacting "
                    f"the Custom Application group '{base_name}'. The "
                    f"group was left unchanged. Error: {exp}"
                ),
                details=traceback.format_exc(),
            )

    def _split_group_definitions(
        self, members: List[Dict], wanted: List[Dict]
    ) -> Tuple[List[Dict], List[List[Dict]]]:
        """Split a group's definitions into the action's own and the rest.

        Compaction only redistributes the traffic definitions the action
        is configured for. Every other definition - one an operator
        created by hand, or one left by an action configured differently
        - is pinned to the member that holds it and merely consumes its
        slots. Without this, re-packing would relocate configuration
        this action does not own into the roll-over siblings it created.

        Args:
            members (List[Dict]): Members of the group.
            wanted (List[Dict]): Definitions the action is configured
                for.

        Returns:
            Tuple[List[Dict], List[List[Dict]]]: Buckets of the action's
                own definitions as {"definition": ..., "hosts": [...]},
                and the pinned definitions per member.
        """
        managed: List[Dict] = []
        pinned: List[List[Dict]] = []
        for member in members:
            member_pinned = []
            for definition in member["definitions"] or []:
                if not any(
                    self.bwan_helper.definition_matches(definition, want)
                    for want in wanted
                ):
                    member_pinned.append(definition)
                    continue
                bucket = next(
                    (
                        candidate
                        for candidate in managed
                        if self.bwan_helper.definition_matches(
                            candidate["definition"], definition
                        )
                    ),
                    None,
                )
                if bucket is None:
                    bucket = {
                        "definition": {
                            key: value
                            for key, value in definition.items()
                            if key != "hosts"
                        },
                        "hosts": [],
                        "seen": set(),
                    }
                    managed.append(bucket)
                for host in definition.get("hosts") or []:
                    if host in bucket["seen"]:
                        continue
                    bucket["seen"].add(host)
                    bucket["hosts"].append(host)
            pinned.append(member_pinned)
        return managed, pinned

    def _pack_layout(
        self,
        managed: List[Dict],
        pinned: List[List[Dict]],
        max_hosts: int,
        member_count: int,
    ) -> List[List[Dict]]:
        """Lay the action's host slots out greedily, lowest member first.

        Every member starts holding the definitions pinned to it, which
        already consume slots, so only the capacity they leave over is
        available to the action's hosts.

        Args:
            managed (List[Dict]): Buckets of the action's definitions.
            pinned (List[List[Dict]]): Pinned definitions per member.
            max_hosts (int): Host slot cap of one member.
            member_count (int): Number of members in the group.

        Returns:
            List[List[Dict]]: Traffic definitions per member, one entry
                per existing member. An entry is empty when the member
                holds nothing after the re-pack.
        """
        packed: List[List[Dict]] = [
            [
                dict(definition, hosts=list(definition.get("hosts") or []))
                for definition in member_pinned
            ]
            for member_pinned in pinned
        ]
        used = [
            self.bwan_helper.count_slots(entry) for entry in packed
        ]
        index = 0
        for bucket in managed:
            for host in bucket["hosts"]:
                while (
                    index < member_count and used[index] >= max_hosts
                ):
                    index += 1
                if index >= member_count:
                    # Only reachable if the capacity check was wrong;
                    # keeping the host in the last member never drops it.
                    index = member_count - 1
                definitions = packed[index]
                match = self._find_definition(
                    definitions, bucket["definition"]
                )
                if match is None:
                    match = dict(bucket["definition"])
                    match["hosts"] = []
                    definitions.append(match)
                match["hosts"].append(host)
                used[index] += 1
        return packed

    def _apply_compaction(
        self,
        config: Dict,
        members: List[Dict],
        packed: List[List[Dict]],
    ):
        """Write the re-packed group and delete the emptied siblings.

        Every write lands before any delete is issued. When a write
        fails the group keeps its pre-compaction shape and nothing is
        deleted, so the cost of a partial failure is a wasted Custom
        Application rather than a lost host.

        Args:
            config (Dict): Normalized configuration of the action.
            members (List[Dict]): Members of the group.
            packed (List[List[Dict]]): Definitions per member.
        """
        base_name = config["base_name"]
        to_write, to_delete = [], []
        for member, definitions in zip(members, packed):
            if self._definitions_equal(member["definitions"], definitions):
                continue
            if definitions:
                to_write.append((member, definitions))
            else:
                to_delete.append(member)

        if not to_write and not to_delete:
            return
        for member, definitions in to_write:
            if self._patch_custom_app(
                member["id"], member["name"], definitions
            ) != OUTCOME_PLACED:
                self.logger.info(
                    f"{self.log_prefix}: Compaction of the Custom "
                    f"Application group '{base_name}' was abandoned, "
                    f"since Custom Application '{member['name']}' could "
                    "not be updated. No Custom Application was deleted."
                )
                return
            member["definitions"] = definitions

        deleted, kept = [], []
        for member in to_delete:
            if self._delete_custom_app(member["id"], member["name"]):
                deleted.append(member["name"])
                member["definitions"] = []
                continue
            # The platform refuses to delete a Custom Application that a
            # policy references, and it cannot be emptied in its place:
            # Netskope Borderless WAN answers HTTP 200 to a PATCH
            # carrying an empty 'definitions_v2' array and leaves the
            # Custom Application exactly as it was. It is therefore left
            # holding the hosts that now also live in the members they
            # were packed into, and a later run reclaims it once the
            # policy no longer references it.
            kept.append(member["name"])
        message = (
            f"Successfully compacted the Custom Application group "
            f"'{base_name}' into {len(members) - len(deleted)} Custom "
            f"Application(s) and deleted {len(deleted)} empty Custom "
            "Application(s)."
        )
        if kept:
            message += (
                f" {len(kept)} Custom Application(s) could not be "
                "deleted and were left unchanged."
            )
        self.logger.info(
            message=f"{self.log_prefix}: {message}",
            details=json.dumps({"deleted": deleted, "kept": kept}),
        )

    def _definitions_equal(
        self, left: List[Dict], right: List[Dict]
    ) -> bool:
        """Compare two definition lists by content.

        Hosts are compared as sets, since Netskope Borderless WAN does
        not preserve their order.

        Args:
            left (List[Dict]): Definitions.
            right (List[Dict]): Definitions.

        Returns:
            bool: True when both describe the same traffic and hosts.
        """
        if len(left or []) != len(right or []):
            return False
        for definition in left or []:
            match = self._find_definition(right or [], definition)
            if match is None:
                return False
            if set(definition.get("hosts") or []) != set(
                match.get("hosts") or []
            ):
                return False
        return True

    # ------------------------------------------------------------------ #
    # Add to Custom App - execution and revert
    # ------------------------------------------------------------------ #
    def _execute_custom_app_actions(
        self, actions: List[Dict], revert: bool
    ) -> Optional[ActionResult]:
        """Append the hosts of the records to Custom Applications.

        Args:
            actions (List[Dict]): Actions as {"id": ..., "params": ...}.
            revert (bool): Whether the actions are being reverted.

        Returns:
            Optional[ActionResult]: None when every record succeeded,
                else an ActionResult with the failed action IDs.
        """
        failed_ids: Set[str] = set()
        buckets: Dict[Tuple, Dict] = {}
        for action_dict in actions:
            parameters = action_dict.get("params").parameters or {}
            config = self._get_custom_app_config(parameters)
            key = self._get_custom_app_bucket_key(config)
            bucket = buckets.setdefault(
                key, {"config": config, "actions": []}
            )
            bucket["actions"].append(action_dict)

        for bucket in buckets.values():
            config = bucket["config"]
            bucket_actions = bucket["actions"]
            if not config["base_name"]:
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: Error occurred while "
                        f"executing the '{ADD_TO_CUSTOM_APP_LABEL}' "
                        "action. No Custom Application name found in "
                        f"'{CUSTOM_APP_NAME_LABEL}'."
                    ),
                    resolution=RESOLUTION_NEW_CUSTOM_APP,
                )
                failed_ids.update(self._get_action_ids(bucket_actions))
                continue
            if not config["definitions"]:
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: Error occurred while "
                        f"executing the '{ADD_TO_CUSTOM_APP_LABEL}' "
                        f"action on Custom Application "
                        f"'{config['base_name']}'. No protocol selected "
                        f"in '{PROTOCOL_LABEL}'."
                    ),
                    resolution=RESOLUTION_NO_PROTOCOL,
                )
                failed_ids.update(self._get_action_ids(bucket_actions))
                continue
            try:
                if revert:
                    self._revert_custom_app_bucket(
                        config, bucket_actions, failed_ids
                    )
                else:
                    self._perform_custom_app_bucket(
                        config, bucket_actions, failed_ids
                    )
            except NetskopeBwanPluginException:
                failed_ids.update(self._get_action_ids(bucket_actions))
        return self._build_action_result(
            ADD_TO_CUSTOM_APP_LABEL, failed_ids, actions, revert
        )

    def _load_group(
        self, config: Dict, allow_create: bool
    ) -> Optional[List[Dict]]:
        """Enumerate a group and read the definitions of its members.

        Args:
            config (Dict): Normalized configuration of the action.
            allow_create (bool): Whether the base Custom Application may
                be created when the group does not exist yet.

        Returns:
            Optional[List[Dict]]: Members of the group, or None when the
                group could not be read.

        Raises:
            NetskopeBwanPluginException: When the Custom Applications
                could not be fetched.
        """
        base_name = config["base_name"]
        members = self._enumerate_group(base_name)
        if not members:
            if not allow_create:
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: Error occurred while "
                        f"executing the '{ADD_TO_CUSTOM_APP_LABEL}' "
                        f"action. Custom Application '{base_name}' does "
                        f"not exist on {PLATFORM_NAME}."
                    ),
                    resolution=RESOLUTION_CUSTOM_APP_NOT_FOUND,
                )
                return None
            return [
                {
                    "id": None,
                    "name": base_name,
                    "number": 1,
                    "definitions": [],
                    "changed": True,
                    "record_ids": set(),
                }
            ]
        if not self._load_member_definitions(members):
            return None
        return members

    def _perform_custom_app_bucket(
        self,
        config: Dict,
        bucket_actions: List[Dict],
        failed_ids: Set[str],
    ):
        """Place the hosts of one bucket and compact the group.

        Args:
            config (Dict): Normalized configuration of the action.
            bucket_actions (List[Dict]): Actions of the bucket.
            failed_ids (Set[str]): Failed action IDs (updated in place).
        """
        base_name = config["base_name"]
        records, invalid_values = self._collect_custom_app_records(
            bucket_actions, failed_ids
        )
        self._log_invalid_hosts(invalid_values)
        if not records:
            return
        members = self._load_group(config, allow_create=config["is_create"])
        if members is None:
            failed_ids.update(self._get_action_ids(bucket_actions))
            return

        counts = self._place_records(config, records, members, failed_ids)
        written, write_failed = 0, 0
        for member in members:
            if not member["changed"]:
                continue
            if self._write_member(config, member) == OUTCOME_PLACED:
                written += 1
                member["changed"] = False
            else:
                write_failed += 1
                failed_ids.update(member["record_ids"])

        message = (
            f"Successfully added {counts['placed_slots']} host slot(s) "
            f"to {written} Custom Application(s) of the group "
            f"'{base_name}'."
        )
        if counts["already_present"]:
            message += (
                f" {counts['already_present']} record(s) were already "
                "present in the group."
            )
        if counts["new_members"]:
            message += (
                f" {counts['new_members']} roll-over Custom "
                "Application(s) were created."
            )
        if counts["skipped_records"]:
            message += (
                f" {counts['skipped_records']} record(s) were skipped, "
                f"since '{SKIP_EXCESS_HOSTS_LABEL}' is set to 'Yes' and "
                "the group is full."
            )
        if counts["oversized_records"]:
            message += (
                f" {counts['oversized_records']} record(s) need more "
                f"host slot(s) than '{MAX_HOSTS_LABEL}' allows."
            )
        if write_failed:
            message += (
                f" Failed to update {write_failed} Custom Application(s)."
            )
        self.logger.info(
            message=f"{self.log_prefix}: {message}",
            details=json.dumps(counts),
        )
        if not write_failed:
            self._compact_group(config, members)

    def _revert_custom_app_bucket(
        self,
        config: Dict,
        bucket_actions: List[Dict],
        failed_ids: Set[str],
    ):
        """Remove the hosts of one bucket from the group.

        Args:
            config (Dict): Normalized configuration of the action.
            bucket_actions (List[Dict]): Actions of the bucket.
            failed_ids (Set[str]): Failed action IDs (updated in place).
        """
        hosts: Set[str] = set()
        for action_dict in bucket_actions:
            parameters = action_dict.get("params").parameters or {}
            valid_hosts, _ = self.bwan_helper.parse_hosts(
                parameters.get(HOST_PARAM)
            )
            hosts.update(valid_hosts)
        if not hosts:
            self.logger.info(
                f"{self.log_prefix}: No valid host found in "
                f"'{HOST_PARAM_LABEL}' while reverting the "
                f"'{ADD_TO_CUSTOM_APP_LABEL}' action, hence there is "
                "nothing to remove."
            )
            return
        if not self._remove_hosts_from_group(config, hosts):
            failed_ids.update(self._get_action_ids(bucket_actions))

    def _remove_hosts_from_group(
        self, config: Dict, hosts: Set[str]
    ) -> bool:
        """Remove hosts from every member of a roll-over group.

        Removal is in place: hosts are never moved between members,
        because moving during a revert would race with compaction. A
        definition left with no host is dropped, a sibling left with no
        definition is deleted, and the base Custom Application is kept
        with empty traffic definitions.

        Args:
            config (Dict): Normalized configuration of the action.
            hosts (Set[str]): Hosts to remove.

        Returns:
            bool: True when every member that changed was written.
        """
        base_name = config["base_name"]
        try:
            members = self._load_group(config, allow_create=False)
        except NetskopeBwanPluginException:
            return False
        if members is None:
            return False

        removed_slots = 0
        for member in members:
            kept_definitions = []
            for definition in member["definitions"]:
                if not any(
                    self.bwan_helper.definition_matches(definition, wanted)
                    for wanted in config["definitions"]
                ):
                    kept_definitions.append(definition)
                    continue
                current = list(definition.get("hosts") or [])
                remaining = [
                    host for host in current if host not in hosts
                ]
                if len(remaining) != len(current):
                    member["changed"] = True
                    removed_slots += len(current) - len(remaining)
                if remaining:
                    definition["hosts"] = remaining
                    kept_definitions.append(definition)
            member["definitions"] = kept_definitions

        written, deleted, failed = 0, [], 0
        for member in members:
            if not member["changed"]:
                continue
            if not member["definitions"]:
                # A member left holding nothing is deleted rather than
                # written empty, the base Custom Application included:
                # Netskope Borderless WAN answers HTTP 200 to a PATCH
                # carrying an empty 'definitions_v2' array and leaves
                # the Custom Application exactly as it was, so writing
                # it empty would report a removal that never happened.
                # A delete the platform refuses - a policy references
                # the Custom Application - leaves the hosts on the
                # tenant, hence it counts as a failure rather than as a
                # successful revert.
                if self._delete_custom_app(member["id"], member["name"]):
                    deleted.append(member["name"])
                else:
                    failed += 1
                continue
            if self._patch_custom_app(
                member["id"], member["name"], member["definitions"]
            ) == OUTCOME_PLACED:
                written += 1
            else:
                failed += 1

        message = (
            f"Successfully removed {removed_slots} host slot(s) from "
            f"{written} Custom Application(s) of the group "
            f"'{base_name}'."
        )
        if deleted:
            message += (
                f" {len(deleted)} empty Custom Application(s) were "
                "deleted."
            )
        if failed:
            message += (
                f" Failed to update or delete {failed} Custom "
                "Application(s)."
            )
        self.logger.info(
            message=f"{self.log_prefix}: {message}",
            details=json.dumps(
                {"deleted": deleted, "removed_slots": removed_slots}
            ),
        )
        return failed == 0

    def _log_invalid_hosts(self, invalid_values: List[str]):
        """Log the invalid host values skipped across the whole batch.

        Args:
            invalid_values (List[str]): Invalid host values.
        """
        unique_values = list(dict.fromkeys(invalid_values))
        if not unique_values:
            return
        self.logger.error(
            message=(
                f"{self.log_prefix}: Error occurred while parsing "
                f"{len(unique_values)} host value(s) provided in "
                f"'{HOST_PARAM_LABEL}'. Only IPv4 addresses, IPv4 CIDR "
                "ranges, and fully-qualified domain name or domains (at "
                "least two labels, letters/digits/hyphens only, at most "
                "100 characters) are supported, hence skipping them."
            ),
            details=f"Skipped value(s): {', '.join(unique_values)}",
            resolution=RESOLUTION_INVALID_HOST,
        )

    def revert_action(self, action: Action):
        """Remove the hosts of one record that stopped matching a rule.

        The framework calls this once per record that no longer matches
        the business rule. Only the Add to Custom App action implements
        it: a Custom Application membership is enforcement state, so a
        host must come out as soon as its record stops matching.

        Args:
            action (Action): Action to revert, carrying the resolved
                parameters of one record.

        Raises:
            NotImplementedError: For every action that does not support
                a per-record revert.
            NetskopeBwanPluginException: When the hosts could not be
                removed.
        """
        if action.value != ADD_TO_CUSTOM_APP:
            raise NotImplementedError(
                f"Revert action is not supported for the action "
                f"'{action.value}' in the {PLATFORM_NAME} plugin."
            )
        # Keep the multi-value fields intact, so the full set of the
        # record's hosts is available rather than its latest value only.
        action.parameters = get_latest_values(
            action.parameters or {},
            exclude_keys=[HOST_PARAM, PROTOCOL_PARAM],
        )
        config = self._get_custom_app_config(action.parameters)
        if not config["base_name"] or not config["definitions"]:
            self.logger.info(
                f"{self.log_prefix}: Skipped reverting the "
                f"'{ADD_TO_CUSTOM_APP_LABEL}' action for a record, "
                "since the action is not configured with a Custom "
                "Application and a protocol."
            )
            return
        hosts, _ = self.bwan_helper.parse_hosts(
            action.parameters.get(HOST_PARAM)
        )
        if not hosts:
            self.logger.info(
                f"{self.log_prefix}: Skipped reverting the "
                f"'{ADD_TO_CUSTOM_APP_LABEL}' action for a record, "
                f"since no valid host was found in "
                f"'{HOST_PARAM_LABEL}'."
            )
            return
        if not self._remove_hosts_from_group(config, set(hosts)):
            err_msg = (
                f"Error occurred while reverting the "
                f"'{ADD_TO_CUSTOM_APP_LABEL}' action for the Custom "
                f"Application group '{config['base_name']}'."
            )
            raise NetskopeBwanPluginException(err_msg)
