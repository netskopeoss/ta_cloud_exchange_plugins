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

LDAP CREv2 plugin.
"""

import json
import re
import ssl
import time
import traceback
from typing import Dict, List, Optional

from netskope.integrations.crev2.models import Action, ActionWithoutParams
from netskope.integrations.crev2.plugin_base import (
    Entity,
    EntityField,
    EntityFieldType,
    PluginBase,
    ValidationResult,
)

from .lib.ldap3 import Connection, Server, Tls
from .lib.ldap3.core.exceptions import (
    LDAPBindError,
    LDAPInsufficientAccessRightsResult,
    LDAPInvalidCredentialsResult,
    LDAPInvalidDnError,
    LDAPInvalidPortError,
    LDAPNoSuchObjectResult,
    LDAPOperationsErrorResult,
    LDAPSocketOpenError,
    LDAPSocketReceiveError,
)
from .lib.ldap3.extend.microsoft.addMembersToGroups import (  # noqa
    ad_add_members_to_groups,
)
from .lib.ldap3.extend.microsoft.removeMembersFromGroups import (
    ad_remove_members_from_groups,
)
from .utils.constants import (
    DEFAULT_WAIT_TIME,
    DNA_REGEX,
    EMAIL_FIELD,
    GROUP_REGEX,
    IP_REGEX,
    MAX_RETRIES,
    MODULE_NAME,
    PAGE_SIZE,
    PLATFORM_NAME,
    PLUGIN_NAME,
    PLUGIN_VERSION,
    TIMEOUT,
    USER_MAPPING,
    USER_PRINCIPAL_NAME,
    USER_SEARCH_FILTER,
    VALIDATION_TIMEOUT,
)


class LDAPPluginException(Exception):
    """LDAP Plugin Exception class."""

    pass


class LDAPPlugin(PluginBase):
    """LDAP CRE plugin implementation."""

    def __init__(
        self,
        name,
        *args,
        **kwargs,
    ):
        """LDAP plugin initializer.

        Args:
            name (str): Plugin configuration name.
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

    def _get_plugin_info(self) -> tuple:
        """Get plugin name and version from manifest.

        Returns:
            tuple: tuple of plugin's name and version fetched from manifest.
        """
        try:
            manifest_json = LDAPPlugin.metadata
            plugin_name = manifest_json.get("name", PLUGIN_NAME)
            plugin_version = manifest_json.get("version", PLUGIN_VERSION)
            return plugin_name, plugin_version
        except Exception as exp:
            self.logger.error(
                message=(
                    "{} {}: Error occurred while"
                    " getting plugin details. Error: {}".format(
                        MODULE_NAME, PLUGIN_NAME, exp
                    )
                ),
                details=traceback.format_exc(),
            )
        return (PLUGIN_NAME, PLUGIN_VERSION)

    def get_connection_object(
        self,
        configuration: Dict,
        is_validation: bool = False,
        logger_msg: str = "",
    ) -> Connection:
        """Get connection object for LDAP server.

        Args:
            configuration (Dict): Configuration dictionary.

        Returns:
            Connection: Connection object
        """
        server_ip = configuration.get("server", "").strip()
        port = int(configuration.get("port"))
        username = configuration.get("username", "").strip()
        password = configuration.get("password", "")
        ldap_cert = configuration.get("ldap_certificate", "")
        tls = Tls(
            validate=ssl.CERT_REQUIRED,
            version=ssl.PROTOCOL_TLS,
            ca_certs_data=ldap_cert,
        )
        server = Server(
            host=(
                f"ldaps://{server_ip}" if ldap_cert else f"ldap://{server_ip}"
            ),
            port=port,
            use_ssl=True if ldap_cert else self.ssl_validation,
            tls=tls if ldap_cert else None,
            connect_timeout=VALIDATION_TIMEOUT if is_validation else TIMEOUT,
        )
        for attempt in range(1, MAX_RETRIES + 1):
            try:
                if ldap_cert:
                    return Connection(
                        server,
                        username,
                        password,
                        auto_bind=True,
                        authentication="SIMPLE",
                        raise_exceptions=True,
                        receive_timeout=(
                            VALIDATION_TIMEOUT if is_validation else TIMEOUT
                        ),
                    )
                else:
                    conn = Connection(
                        server,
                        username,
                        password,
                        auto_bind=True,
                        authentication="SIMPLE",
                        raise_exceptions=True,
                        receive_timeout=(
                            VALIDATION_TIMEOUT if is_validation else TIMEOUT
                        ),
                    )
                    conn.start_tls()
                    return conn
            except LDAPBindError as error:
                if is_validation:
                    err_msg = (
                        "Invalid LDAP Server Username/Password provided in "
                        "configuration parameters."
                    )
                    self.logger.error(
                        message=f"{self.log_prefix}: {err_msg} Error: {error}",
                        details=traceback.format_exc(),
                    )
                    raise LDAPPluginException(err_msg)
                if attempt == MAX_RETRIES:
                    err_msg = (
                        "LDAP Bind error occurred, unable to connect to "
                        "LDAP Server. Maximum retries for rate limit "
                        "handler exceeded hence raising error."
                    )
                    self.logger.error(
                        message=f"{self.log_prefix}: {err_msg} Error: {error}",
                        details=traceback.format_exc(),
                    )
                    raise LDAPPluginException(err_msg)
                elif not is_validation and attempt < MAX_RETRIES:
                    err_msg = (
                        "LDAP Bind error occurred, unable to connect to "
                        f"LDAP Server. Retrying in {DEFAULT_WAIT_TIME}"
                        " seconds."
                    )
                    self.logger.error(
                        message=f"{self.log_prefix}: {err_msg} Error: {error}",
                        details=traceback.format_exc(),
                    )
                    time.sleep(DEFAULT_WAIT_TIME)
                    continue

            except LDAPInvalidCredentialsResult as error:
                err_msg = (
                    "Invalid LDAP Server Username or Password provided in "
                    "configuration parameters."
                )
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg} Error: {error}",
                    details=traceback.format_exc(),
                )
                raise LDAPPluginException(err_msg)
            except LDAPSocketOpenError as error:
                if is_validation:
                    err_msg = (
                        "Invalid LDAP Server, Port, Certificate or Search Base"
                        " provided in configuration parameters."
                    )
                    self.logger.error(
                        message=f"{self.log_prefix}: {err_msg} Error: {error}",
                        details=traceback.format_exc(),
                    )
                    raise LDAPPluginException(err_msg)
                if attempt == MAX_RETRIES:
                    err_msg = (
                        "LDAP Socket Open error occurred, unable to connect to"
                        " LDAP Server. Maximum retries for rate limit "
                        "handler exceeded hence raising error."
                    )
                    self.logger.error(
                        message=f"{self.log_prefix}: {err_msg} Error: {error}",
                        details=traceback.format_exc(),
                    )
                    raise LDAPPluginException(err_msg)
                err_msg = (
                    "LDAP Socket Open error occurred, unable to connect to"
                    f" LDAP Server. Retrying in {DEFAULT_WAIT_TIME}"
                    " seconds."
                )
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg} Error: {error}",
                    details=traceback.format_exc(),
                )
                time.sleep(DEFAULT_WAIT_TIME)
                continue
            except LDAPInvalidPortError as error:
                err_msg = (
                    "Invalid LDAP Port provided in configuration parameters."
                )
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg} Error: {error}",
                    details=traceback.format_exc(),
                )
                raise LDAPPluginException(err_msg)
            except LDAPInvalidDnError as error:
                err_msg = (
                    "Invalid Search Base provided in configuration"
                    " parameters."
                )
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg} Error: {error}",
                    details=traceback.format_exc(),
                )
                raise LDAPPluginException(err_msg)
            except LDAPNoSuchObjectResult as error:
                err_msg = (
                    "Search Base does not exist on LDAP server. Provide "
                    "a valid Search Base in configuration parameters."
                )
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg} Error: {error}",
                    details=traceback.format_exc(),
                )
                raise LDAPPluginException(err_msg)
            except LDAPSocketReceiveError as error:
                if is_validation:
                    err_msg = (
                        "LDAP Certificate is required parameter for TLS"
                        " connection."
                    )
                    self.logger.error(
                        message=f"{self.log_prefix}: {err_msg} Error: {error}",
                        details=traceback.format_exc(),
                    )
                    raise LDAPPluginException(err_msg)
                if attempt == MAX_RETRIES:
                    err_msg = (
                        "LDAP Socket Receive error occurred, unable to "
                        "connect to LDAP Server. Maximum retries for rate"
                        " limit handler exceeded hence raising error."
                    )
                    self.logger.error(
                        message=f"{self.log_prefix}: {err_msg} Error: {error}",
                        details=traceback.format_exc(),
                    )
                    raise LDAPPluginException(err_msg)

                err_msg = (
                    "LDAP Socket Receive error occurred, unable to connect"
                    f" to LDAP Server. Retrying in {DEFAULT_WAIT_TIME}"
                    " seconds."
                )
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg} Error: {error}",
                    details=traceback.format_exc(),
                )
                time.sleep(DEFAULT_WAIT_TIME)
                continue
            except Exception as error:
                if is_validation:
                    err_msg = (
                        "Unable to create connection object"
                        f" for {logger_msg}."
                    )
                    self.logger.error(
                        message=f"{self.log_prefix}: {err_msg} Error: {error}",
                        details=traceback.format_exc(),
                    )
                    raise LDAPPluginException(
                        f"{err_msg} Check logs for more details."
                    )
                if attempt == MAX_RETRIES:
                    err_msg = (
                        "Unable to connect to LDAP Server. Maximum "
                        "retries for rate limit handler exceeded "
                        "hence raising error."
                    )
                    self.logger.error(
                        message=f"{self.log_prefix}: {err_msg} Error: {error}",
                        details=traceback.format_exc(),
                    )
                    raise LDAPPluginException(err_msg)
                err_msg = (
                    "Unable to connect to LDAP Server. Retrying in "
                    f"{DEFAULT_WAIT_TIME} seconds."
                )
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg} Error: {error}",
                    details=traceback.format_exc(),
                )
                time.sleep(DEFAULT_WAIT_TIME)

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
        elif transformation and transformation == "list":
            return list(event)
        return event

    def add_field(self, fields_dict: dict, field_name: str, value):
        """Function to add field to the extracted_fields dictionary.

        Args:
            fields_dict (dict): Field dictionary to update.
            field_name (str): Field name to add.
            value: Field to add.
        """
        if isinstance(value, int):
            fields_dict[field_name] = value
            return
        if value:
            fields_dict[field_name] = value

    def extract_user_fields(
        self,
        event: dict,
    ) -> dict:
        """Extract User Fields.

        Args:
            event (dict): event dictionary.

        Returns:
            Dict: Dictionary of extracted fields.
        """
        extracted_fields = {}
        for (
            field_name,
            field_value,
        ) in USER_MAPPING.items():
            key, default, transformation = (
                field_value.get("key"),
                field_value.get("default"),
                field_value.get("transformation"),
            )
            self.add_field(
                extracted_fields,
                field_name,
                self._extract_field_from_event(
                    key, event, default, transformation
                ),
            )
        return extracted_fields

    def get_users(self) -> list:
        """Get users from LDAP.

        Returns:
            list: List of users fetched.
        """
        records = []
        skip_count = 0
        search_base = self.configuration.get("search_base", "").strip()
        try:
            conn = self.get_connection_object(
                configuration=self.configuration,
                logger_msg=f"getting users from {PLATFORM_NAME} server.",
            )
            # Search users having objectClass=User and get required attributes.
            attributes = conn.extend.standard.paged_search(
                search_base=search_base,
                search_filter=USER_SEARCH_FILTER,  #
                attributes={
                    "userPrincipalName",
                    "mail",
                    "distinguishedName",
                    "name",
                    "memberOf",
                },
                search_scope="SUBTREE",
                paged_size=PAGE_SIZE,
                generator=True,
                time_limit=TIMEOUT,
            )
            for attribute in attributes:
                try:
                    userPrincipalName = attribute.get("attributes", {}).get(
                        "userPrincipalName"
                    )
                    if userPrincipalName and isinstance(
                        userPrincipalName, str
                    ):
                        records.append(self.extract_user_fields(attribute))
                    else:
                        skip_count += 1
                except LDAPPluginException:
                    skip_count += 1
                except Exception as exp:
                    skip_count += 1
                    self.logger.error(
                        message=(
                            f"{self.log_prefix}: Error occurred while getting "
                            f"{userPrincipalName} user from {PLATFORM_NAME}."
                            f" Error: {exp}"
                        ),
                        details=traceback.format_exc(),
                    )
            if skip_count > 0:
                self.logger.info(
                    f"{self.log_prefix}: Skipped {skip_count} users(s) "
                    f"because they might not contain userPrincipalName in "
                    "their response or fields could not be extracted from"
                    " them."
                )
            self.logger.info(
                f"{self.log_prefix}: Successfully fetched {len(records)} "
                f"user(s) from {PLATFORM_NAME}."
            )
            return records
        except LDAPPluginException:
            raise
        except Exception as exp:
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Error occurred while getting "
                    f"users from {PLATFORM_NAME}. Error: {exp}"
                ),
                details=traceback.format_exc(),
            )

    def fetch_records(self, entity: Entity) -> list:
        """Fetch and extract list of new users from Netskope alerts."""
        entity_name = entity.lower()
        self.logger.info(
            f"{self.log_prefix}: Fetching {entity_name} records from "
            f"{PLATFORM_NAME} platform."
        )
        records = []
        try:
            if entity == "Users":
                records = self.get_users()
            else:
                err_msg = (
                    f"Invalid entity found, {PLUGIN_NAME} only supports "
                    "Users entity."
                )
                self.logger.error(f"{self.log_prefix}: {err_msg}")
                raise LDAPPluginException(err_msg)
            return records
        except LDAPPluginException:
            raise
        except Exception as exp:
            err_msg = (
                f"Unexpected error occurred while pulling {entity_name} "
                f"records from {PLATFORM_NAME}."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {exp}",
                details=traceback.format_exc(),
            )
            raise LDAPPluginException(err_msg)

    def create_ldap_filter(self, user_principal_names):
        # Construct an OR filter for multiple userPrincipalNames
        or_filter = "".join(
            [f"(userPrincipalName={upn})" for upn in user_principal_names]
        )
        return f"(&{USER_SEARCH_FILTER}(|{or_filter}))"

    def update_records(self, entity: str, records: list[dict]) -> list[dict]:
        """Update records."""
        entity_name = entity.lower()
        self.logger.info(
            f"{self.log_prefix}: Fetching {entity_name} records from "
            f"{PLATFORM_NAME} platform."
        )
        if entity != "Users":
            err_msg = (
                f"Invalid entity found. {PLUGIN_NAME} supports only"
                " Users entity."
            )
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            raise LDAPPluginException(err_msg)

        skip_count = 0
        updated_records = []
        users = [
            record.get(USER_PRINCIPAL_NAME)
            for record in records
            if record.get(USER_PRINCIPAL_NAME)
        ]
        log_msg = (
            f"{len(users)} user record(s) will be updated out"
            f" of {len(records)} records."
        )

        if len(records) - len(users) > 0:
            log_msg += (
                f" Skipped {len(records) - len(users)} user(s) as they"
                f" do not have {USER_PRINCIPAL_NAME} field in them."
            )

        self.logger.info(f"{self.log_prefix}: {log_msg}")
        conn = self.get_connection_object(
            configuration=self.configuration,
            logger_msg=f"updating users from {PLATFORM_NAME}",
        )
        page_count = 1
        search_base = self.configuration.get("search_base", "").strip()
        for i in range(0, len(users), PAGE_SIZE):
            page_users_count = 0
            page_skip_count = 0
            batch = users[i : i + PAGE_SIZE]  # noqa
            user_batch = self.create_ldap_filter(batch)  # noqa
            try:
                attributes = conn.extend.standard.paged_search(
                    search_base=search_base,
                    search_filter=user_batch,
                    attributes={
                        "userPrincipalName",
                        "mail",
                        "distinguishedName",
                        "name",
                        "memberOf",
                    },
                    search_scope="SUBTREE",
                    time_limit=TIMEOUT,
                    paged_size=PAGE_SIZE,
                    generator=True,
                )
                for attribute in attributes:
                    userPrincipalName = attribute.get("attributes", {}).get(
                        "userPrincipalName"
                    )
                    if userPrincipalName and isinstance(
                        userPrincipalName, str
                    ):
                        updated_records.append(
                            self.extract_user_fields(attribute)
                        )
                        page_users_count += 1
                    else:
                        page_skip_count += 1
            except LDAPPluginException:
                page_skip_count += 1
            except Exception as exp:
                page_skip_count += 1
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: Error occurred while updating "
                        f"{len(batch)} user(s) for page {page_count} from "
                        f"{PLATFORM_NAME}. Error: {exp}"
                    ),
                    details=traceback.format_exc(),
                )
            self.logger.info(
                f"{self.log_prefix}: Successfully updated {page_users_count} "
                f"user(s) and skipped {skip_count} user(s) in page "
                f"{page_count}. Total user(s) updated: {len(updated_records)}"
            )
            page_count += 1
            skip_count += page_skip_count
        if skip_count > 0:
            self.logger.info(
                f"{self.log_prefix}: Skipped {skip_count} users(s) "
                "because for update as they might not contain "
                "userPrincipalName in their response or fields could"
                " not be extracted from them."
            )
        self.logger.info(
            f"{self.log_prefix}: Successfully updated {len(updated_records)} "
            f"user record(s) from {PLATFORM_NAME}."
        )
        return updated_records

    def _get_all_groups(
        self,
        configuration: Dict,
        conn: Connection,
        is_validation: bool = False,
    ) -> List:
        """Get list of all the groups.

        Args:
            configuration (Dict): Configuration parameters.

        Returns:
            List: List of all the groups.
        """
        self.logger.info(
            f"{self.log_prefix}: Fetching groups from {PLATFORM_NAME}."
        )
        groups = []
        skip_count = 0
        attributes = conn.extend.standard.paged_search(
            search_base=configuration.get("search_base", "").strip(),
            search_scope="SUBTREE",
            search_filter="(objectClass=group)",
            attributes={"name", "distinguishedName"},
            paged_size=PAGE_SIZE,
            generator=True,
            time_limit=VALIDATION_TIMEOUT if is_validation else TIMEOUT,
        )

        for attribute in attributes:
            try:
                if attribute.get("attributes", {}).get(
                    "name"
                ) and attribute.get("attributes", {}).get(
                    "distinguishedName"
                ):
                    groups.append(
                        {
                            "name": attribute.get("attributes", {}).get(
                                "name",
                            ),
                            "dn": attribute.get("attributes", {}).get(
                                "distinguishedName",
                            ),
                        }
                    )
                else:
                    skip_count += 1
            except json.JSONDecodeError as exp:
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: Unable to create "
                        f"JSON for group. Error: {exp}"
                    ),
                    details=traceback.format_exc(),
                )
                skip_count += 1
            except Exception as exp:
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: Error occurred while"
                        f"fetching groups. Error: {exp}"
                    ),
                    details=traceback.format_exc(),
                )
                skip_count += 1
        if skip_count > 0:
            self.logger.info(
                f"{self.log_prefix}: Skipped {skip_count} group(s) from"
                f" {PLATFORM_NAME}. They might not have name or "
                "distinguishedName fields in them or fields could "
                "not be extracted from them."
            )
        self.logger.info(
            f"{self.log_prefix}: Successfully fetched {len(groups)} groups"
            f" from {PLATFORM_NAME}."
        )
        return groups

    def _get_group_match(
        self,
        conn: Connection,
        group_name: str,
    ):
        """Get list of all the users.

        Args:
            conn (Connection): LDAP server Connection object.
            group_name (str): Group name.
        """
        self.logger.info(
            f"{self.log_prefix}: Verifying the existence of {group_name}"
            f" on the {PLATFORM_NAME} server."
        )
        response = conn.extend.standard.paged_search(
            search_base=self.configuration.get("search_base", "").strip(),
            search_filter=f"(&(objectClass=group)(name={group_name}))",
            attributes={"name", "distinguishedName"},
            search_scope="SUBTREE",
            paged_size=PAGE_SIZE,
            time_limit=TIMEOUT,
        )

        for entry in response:
            try:
                group_name = entry.get("attributes", {}).get(
                    "name",
                )
                dn = entry.get("attributes", {}).get(
                    "distinguishedName",
                )
                if group_name and dn:
                    self.logger.info(
                        f"{self.log_prefix}: Group {group_name} "
                        f"exists on {PLATFORM_NAME} platform."
                    )
                    return {"name": group_name, "dn": dn}
            except Exception as exp:
                err_msg = (
                    "Error occurred while getting group match"
                    f" for group {group_name}."
                )
                self.logger.error(
                    message=(f"{self.log_prefix}: {err_msg} Error: {exp}"),
                    details=traceback.format_exc(),
                )
                raise LDAPPluginException(err_msg)

        self.logger.info(
            f"{self.log_prefix}: Group {group_name} does not exists "
            f"on {PLATFORM_NAME} platform."
        )
        return False

    def _get_user_match(
        self,
        conn: Connection,
        user_email: str,
    ) -> List:
        """Verify whether user with given email exist on LDAP platform or not.

        Args:
            conn (Connection): LDAP server Connection object.
            user_email (str): User email id.

        Returns:
            List: List of matched users.
        """
        self.logger.info(
            f"{self.log_prefix}: Getting match for user having"
            f" email {user_email}."
        )
        try:
            response = conn.extend.standard.paged_search(
                search_base=self.configuration.get("search_base"),
                search_filter=f"(&{USER_SEARCH_FILTER}(mail={user_email}))",
                # search only users with given email.
                attributes={
                    "mail",
                    "distinguishedName",
                },  # return only mail and distinguishedName in response.
                search_scope="SUBTREE",  # find in subtree of current path
                time_limit=TIMEOUT,
            )
            matched_users = []

            for entry in response:
                mail = entry.get("attributes", {}).get(
                    "mail",
                )  # Fetch mailof user
                dn = entry.get("attributes", {}).get(
                    "distinguishedName",
                )  # Fetch DN of user
                if mail and dn:
                    matched_users.append(
                        {
                            "mail": mail,
                            "dn": dn,
                        }
                    )
            if matched_users:
                self.logger.info(
                    f"{self.log_prefix}: User with email {user_email} exist on"
                    f" {PLATFORM_NAME} server. Total {len(matched_users)} "
                    "match(es) found."
                )
            return matched_users
        except Exception as exp:
            err_msg = (
                "Error occurred while getting match for"
                f" user having email {user_email}"
                f"from {PLATFORM_NAME}."
            )
            self.logger.error(
                message=(f"{self.log_prefix}: {err_msg} Error: {exp}"),
                details=traceback.format_exc(),
            )
            raise LDAPPluginException(err_msg)

    def _find_group_by_name(self, groups: List, name: str) -> Optional[Dict]:
        """Find group from list by name.

        Args:
            groups (List): List of groups dictionaries.
            name (str): Name to find.

        Returns:
            Optional[Dict]: Group dictionary if found, None otherwise.
        """
        for group in groups:
            if group["name"] == name:
                return group

    def _remove_from_all_group(self, user: Dict, conn: Connection) -> None:
        """Remove user from all the group in which it exists.

        Args:
            user (Dict): User dictionary
            conn (Connection): Connection object.
        """
        mail = user.get("mail")
        self.logger.info(
            f"{self.log_prefix}: Removing user {mail} from existing groups."
        )
        response = conn.extend.standard.paged_search(
            search_base=self.configuration["search_base"],
            search_filter=f"(&(objectClass=User)(mail={mail}))",
            attributes={"memberOf", "name"},
            search_scope="SUBTREE",
            paged_size=PAGE_SIZE,
            time_limit=TIMEOUT,
            generator=True,
        )

        for entry in response:
            try:
                groups = {
                    "groups": entry.get("attributes", {}).get("memberOf", []),
                    "name": entry.get("attributes", {}).get("name"),
                }
                if groups:
                    for group in groups.get("groups", []):
                        try:
                            self._remove_from_group(
                                user_id=user.get("dn"),
                                group_id=group,
                                conn=conn,
                            )
                        except LDAPNoSuchObjectResult as exp:
                            err_msg = (
                                f"Group with Distinguished Name(DN) {group}"
                                f" does not exist on {PLATFORM_NAME} "
                                f" server. Error: {exp}"
                            )
                            self.logger.error(
                                message=(
                                    f"{self.log_prefix}: {err_msg}"
                                    f" Error: {exp}"
                                ),
                                details=traceback.format_exc(),
                            )
                        except LDAPInsufficientAccessRightsResult as exp:
                            username = self.configuration.get(
                                "username", ""
                            ).strip()
                            err_msg = (
                                f"User {username} does not have enough "
                                f"permission to remove {mail} users from "
                                f"group with Distinguished Name(DN)"
                                f" {group}."
                            )
                            self.logger.error(
                                message=(
                                    f"{self.log_prefix}: {err_msg}"
                                    f" Error: {exp}"
                                ),
                                details=traceback.format_exc(),
                            )
                            raise LDAPPluginException(err_msg)
                    self.logger.info(
                        f"{self.log_prefix}: Successfully removed "
                        f"{mail} from existing groups."
                    )
            except Exception as exp:
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: Error occurred removing"
                        " users from groups."
                    ),
                    details=traceback.format_exc(),
                )
                raise LDAPPluginException(exp)

    def _remove_from_group(
        self,
        user_id: str,
        group_id: str,
        conn: Connection,
    ):
        """Remove specified user from the specified group.

        Args:
            user_id (str): User DN.
            group_id (str): Group Dn.
            conn (Connection): Connection object.
        """
        ad_remove_members_from_groups(
            connection=conn,
            members_dn=user_id,
            groups_dn=group_id,
            fix={
                "member": user_id,
                "group": group_id,
            },
            raise_error=True,
        )

    def _add_to_group(
        self,
        user_info: dict,
        group_info: dict,
        conn: Connection,
    ):
        """Add specified user to the specified group.

        Args:
            user_info (dict): Dictionary containing user email and DN.
            group_info (dict): Dictionary containing group name and DN.
            conn (Connection): LDAP server connection object.

        Raises:
            LDAPOperationsErrorResult: If operation is getting failure.
            LDAPNoSuchObjectResult: If the group does not exist on ldap server.
            Exception: If any unexpected error occurs.
        """
        user_mail = user_info.get("mail")
        group_name = group_info.get("name")
        self.logger.info(
            f"{self.log_prefix}: Adding user {user_mail} to group"
            f" {group_name}."
        )
        try:
            ad_add_members_to_groups(
                connection=conn,
                members_dn=user_info.get("dn"),
                groups_dn=group_info.get("dn"),
                raise_error=True,
            )
            self.logger.info(
                f"{self.log_prefix}: Successfully added user "
                f"{user_mail} to group {group_name}."
            )
        except LDAPOperationsErrorResult as error:
            err_msg = (
                f"User with mail {user_mail} or"
                f"selected group {group_name} does not exist on "
                f"{PLATFORM_NAME} Server."
            )
            self.logger.error(
                message=(f"{self.log_prefix}: {err_msg} Error: {error}"),
                details=traceback.format_exc(),
            )
            raise LDAPPluginException(err_msg)
        except LDAPNoSuchObjectResult as error:
            err_msg = (
                f"Group {group_name} does not exist on "
                f"{PLATFORM_NAME} server."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {error}",
                details=traceback.format_exc(),
            )
            raise LDAPPluginException(err_msg)
        except LDAPInsufficientAccessRightsResult as exp:
            user = self.configuration.get("username")
            err_msg = (
                f"{user} does not have enough permission to "
                f"add user {user_mail} to group. {group_name}."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {exp}",
                details=traceback.format_exc(),
            )
            raise LDAPPluginException(err_msg)
        except Exception as exp:
            err_msg = (
                f"Unexpected error occurred while adding user {user_mail} to "
                f"group {group_name}."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {exp}",
                details=traceback.format_exc(),
            )
            raise LDAPPluginException(err_msg)

    def _create_group(self, group_name: str, conn: Connection) -> Dict:
        """Create a new group with name.

        Args:
            group_name (str): Name of the group to create.
            conn (Connection): Connection object.

        Returns:
            Dict: Newly created group dictionary.
        """
        self.logger.info(
            f"{self.log_prefix}: Create a new group {group_name} on "
            f"{PLATFORM_NAME} server."
        )
        search_base = self.configuration.get("search_base", "").strip()
        result = conn.add(
            f"cn={group_name},{search_base}",
            attributes={"objectClass": ["group"], "name": group_name},
        )

        if result:
            response = conn.extend.standard.paged_search(
                search_base=search_base,
                search_scope="SUBTREE",
                search_filter=f"(&(objectClass=group)(name={group_name}))",
                # Search for group in groups named by given name.
                attributes={"name", "distinguishedName"},
                time_limit=TIMEOUT,
                paged_size=PAGE_SIZE,
            )
            for entry in response:
                try:
                    group_info = {
                        "name": entry.get("attributes", {}).get(
                            "name",
                        ),
                        "dn": entry.get("attributes", {}).get(
                            "distinguishedName"
                        ),
                    }
                    self.logger.info(
                        f"{self.log_prefix}: Successfully created group "
                        f"{group_name} on {PLATFORM_NAME} server."
                    )
                    return group_info
                except LDAPInsufficientAccessRightsResult as exp:
                    user = self.configuration.get("username")
                    err_msg = (
                        f"User {user} does not have permission to"
                        " create new group."
                    )
                    self.logger.error(
                        message=f"{self.log_prefix}: {err_msg} Error: {exp}",
                        details=traceback.format_exc(),
                    )
                    raise LDAPInsufficientAccessRightsResult(err_msg)
                except Exception as exp:
                    err_msg = (
                        "Error occurred while creating group "
                        f"{group_name} on {PLATFORM_NAME}."
                    )
                    self.logger.error(
                        message=f"{self.log_prefix}: {err_msg} Error: {exp}",
                        detail=traceback.format_exc(),
                    )
                    raise LDAPPluginException(exp)

    def _validate_port(self, port):
        """Validates LDAP port.

        Args:
            port: The LDAP port to be validated

        Returns:
            True in case of valid value, False otherwise
        """
        if port or port == 0:
            try:
                if not (0 <= port <= 65535):
                    return False
                return True
            except ValueError:
                return False
        else:
            return False

    def _validate_auth(self, config: Dict) -> ValidationResult:
        """Validates authorization parameters.

        Args:
            config (Dict): Configuration dictionary.

        Returns:
            ValidationResult: True if validation is successful else False.
        """
        try:
            conn = self.get_connection_object(
                configuration=config,
                logger_msg=(
                    f"validating connectivity to {PLATFORM_NAME} server"
                ),
                is_validation=True,
            )
            conn.extend.standard.paged_search(
                search_base=config.get("search_base", "").strip(),
                search_filter="(objectClass=User)",
                attributes={"mail", "distinguishedName"},
                search_scope="SUBTREE",
                time_limit=VALIDATION_TIMEOUT,
                paged_size=1,
                size_limit=1,
            )
            log_msg = (
                f"Successfully validated {PLUGIN_NAME} plugin configuration."
            )
            self.logger.debug(f"{self.log_prefix}: {log_msg}")
            return ValidationResult(success=True, message=log_msg)
        except LDAPPluginException as exp:
            return ValidationResult(
                success=False,
                message=str(exp),
            )
        except Exception as error:
            err_msg = "Unexpected error occurred while authenticating."
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {error}",
                details=traceback.format_exc(),
            )
            return ValidationResult(
                success=False,
                message=f"{err_msg} Check logs for details.",
            )

    def _validate_server_address(self, server_address: str) -> bool:
        """Validate Server address.

        Args:
            server_address (str): Server IP or DNS.

        Returns:
            bool: True if server address is valid else False.
        """
        is_ip_valid = re.match(IP_REGEX, server_address)
        is_dns_valid = re.match(DNA_REGEX, server_address)
        return is_ip_valid or is_dns_valid

    def validate(self, configuration: Dict) -> ValidationResult:
        """Validate LDAP configuration.

        Args:
            configuration (Dict): Configurations dictionary.

        Returns:
            ValidationResult: ValidationResult object.
        """
        validation_err_msg = "Validation error occurred."
        server = configuration.get("server", "").strip()
        if not server:
            err_msg = "Server Address is a required configuration parameter."
            self.logger.error(
                f"{self.log_prefix}: {validation_err_msg} {err_msg}"
            )
            return ValidationResult(success=False, message=err_msg)
        elif not self._validate_server_address(server):
            err_msg = (
                "Invalid Server Address provided in configuration parameters."
            )
            self.logger.error(
                f"{self.log_prefix}: {validation_err_msg} {err_msg}"
            )
            return ValidationResult(success=False, message=err_msg)

        try:
            port = configuration.get("port")
            if port is None:
                err_msg = "LDAP Port is a required configuration parameter."
                self.logger.error(f"{self.log_prefix}: {err_msg}")
                return ValidationResult(
                    success=False,
                    message=err_msg,
                )
            elif not isinstance(port, int) or not self._validate_port(
                int(port)
            ):
                err_msg = (
                    "Invalid LDAP Port provided in configuration"
                    " parameters. Valid value must be an integer in"
                    " range of 0 to 65535."
                )
                self.logger.error(
                    f"{self.log_prefix}: {validation_err_msg} {err_msg}"
                )
                return ValidationResult(success=False, message=err_msg)
        except ValueError:
            err_msg = (
                "Invalid LDAP Port provided in configuration"
                " parameters. Valid value must be an integer in"
                " range of 0 to 65535."
            )
            self.logger.error(
                message=(
                    f"{self.log_prefix}: {validation_err_msg} {err_msg}"
                ),
                details=traceback.format_exc(),
            )
            return ValidationResult(success=False, message=err_msg)

        username = configuration.get("username", "").strip()
        if not username:
            err_msg = (
                "LDAP Server Username is a required configuration parameter."
            )
            self.logger.error(
                f"{self.log_prefix}: {validation_err_msg} {err_msg}"
            )
            return ValidationResult(success=False, message=err_msg)
        elif not isinstance(username, str):
            err_msg = (
                "Invalid LDAP Server Username provided in configuration"
                " parameters."
            )
            self.logger.error(
                f"{self.log_prefix}: {validation_err_msg} {err_msg}"
            )
            return ValidationResult(success=False, message=err_msg)

        password = configuration.get("password")
        if not password:
            err_msg = (
                "LDAP Server Password is a required configuration parameter."
            )
            self.logger.error(
                f"{self.log_prefix}: {validation_err_msg} {err_msg}"
            )
            return ValidationResult(success=False, message=err_msg)
        elif not isinstance(password, str):
            err_msg = (
                "Invalid LDAP Server Password provided in configuration"
                " parameters."
            )
            self.logger.error(
                f"{self.log_prefix}: {validation_err_msg} {err_msg}"
            )
            return ValidationResult(success=False, message=err_msg)

        search_base = configuration.get("search_base", "").strip()
        if not search_base:
            err_msg = "Search Base is a required configuration parameter."
            self.logger.error(
                f"{self.log_prefix}: {validation_err_msg} {err_msg}"
            )
            return ValidationResult(success=False, message=err_msg)
        elif not isinstance(search_base, str):
            err_msg = (
                "Invalid Search Base provided in configuration parameters."
            )
            self.logger.error(
                f"{self.log_prefix}: {validation_err_msg} {err_msg}"
            )
            return ValidationResult(success=False, message=err_msg)

        ldap_certificate = configuration.get("ldap_certificate")
        if ldap_certificate:
            if not isinstance(ldap_certificate, str):
                err_msg = (
                    "Invalid LDAP Certificate provided in configuration"
                    " parameters."
                )
                self.logger.error(
                    f"{self.log_prefix}: {validation_err_msg} {err_msg}"
                )
                return ValidationResult(success=False, message=err_msg)
            elif not self._validate_ldap_certificate(ldap_certificate):
                err_msg = (
                    "Invalid LDAP Certificate provided in configuration"
                    " parameters. LDAP Certificate should be in valid PEM "
                    "format."
                )
                self.logger.error(
                    f"{self.log_prefix}: {validation_err_msg} {err_msg}"
                )
                return ValidationResult(success=False, message=err_msg)

        return self._validate_auth(configuration)

    def _validate_ldap_certificate(self, ldap_certificate: str) -> bool:
        """Validate LDAP certificate.

        Args:
            ldap_certificate (str): LDAP certificate.

        Returns:
            bool: True if LDAP certificate is valid, False otherwise.
        """
        try:
            ssl.PEM_cert_to_DER_cert(ldap_certificate)
            return True
        except Exception as err:
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Unable to load provided "
                    f"LDAP certificate. Error: {err}"
                ),
                details=traceback.format_exc(),
            )
            return False

    def validate_action(self, action: Action) -> ValidationResult:
        """Validate actions.

        Args:
            action (Action): actions provided by users.

        Returns:
            ValidationResult: ValidationResult object.
        """
        try:
            action_value = action.value
            action_params = action.parameters
            if action_value not in ["add", "remove", "generate"]:
                log_msg = (
                    "Valid values are Add to group, Remove from group and"
                    " No actions."
                )
                self.logger.error(
                    f"{self.log_prefix}: Unsupported action value found "
                    "in action configuration. Valid values are "
                    "Add to group, Remove from group and No actions."
                )
                return ValidationResult(
                    success=False,
                    message=(
                        "Unsupported action provided in action "
                        f"configuration. {log_msg}"
                    ),
                )
            if action_value == "generate":
                log_msg = (
                    "Successfully validated "
                    f"{action_value} action for {PLATFORM_NAME}."
                )
                self.logger.debug(f"{self.log_prefix}: {log_msg}")
                return ValidationResult(success=True, message=log_msg)
            conn = self.get_connection_object(
                configuration=self.configuration,
                logger_msg=f"getting groups from {PLATFORM_NAME} server",
                is_validation=True,
            )
            groups = self._get_all_groups(
                configuration=self.configuration,
                conn=conn,
                is_validation=True,
            )
            create_dict = json.dumps({"name": "create"})
            groups = [group.get("dn") for group in groups]
            email = action_params.get("user_email", "")
            if not email:
                err_msg = f"{EMAIL_FIELD} is a required action parameter."
                self.logger.error(f"{self.log_prefix}: {err_msg}")
                return ValidationResult(success=False, message=err_msg)
            elif not isinstance(email, str):
                err_msg = (
                    f"Invalid {EMAIL_FIELD} provided in action parameters."
                )
                self.logger.error(f"{self.log_prefix}: {err_msg}")
                return ValidationResult(success=False, message=err_msg)

            if action_value == "add":
                if not action_params.get("group"):
                    err_msg = "Select a group to perform action on."
                    self.logger.error(f"{self.log_prefix}: {err_msg}")
                    return ValidationResult(success=False, message=err_msg)
                elif (
                    create_dict in action_params.get("group")
                    and len(action_params.get("new_group_name", "").strip())
                    == 0
                ):
                    err_msg = "New Group Name can not be empty field."
                    self.logger.error(f"{self.log_prefix}: {err_msg}")
                    return ValidationResult(
                        success=False,
                        message=err_msg,
                    )
                elif create_dict not in action_params.get("group", "") and (
                    "$" in action_params.get("group")
                ):
                    err_msg = (
                        "Group contains the Business Rule Record Field."
                        " Please select group from Static field dropdown only."
                    )
                    self.logger.error(f"{self.log_prefix}: {err_msg}")
                    return ValidationResult(success=False, message=err_msg)
                elif (create_dict not in action_params.get("group")) and (
                    not any(
                        map(
                            lambda group: json.loads(group)["dn"] in groups,
                            action_params.get("group"),
                        )
                    )
                ):
                    err_msg = (
                        "Invalid Group Name provided in action configuration."
                    )
                    self.logger.error(f"{self.log_prefix}: {err_msg}")
                    return ValidationResult(success=False, message=err_msg)

                remove_from_other_groups = action_params.get(
                    "remove_from_other_groups"
                )
                if not remove_from_other_groups:
                    err_msg = (
                        "Remove From All Other Groups is a required action "
                        "parameter for Add to group action supported."
                    )
                    self.logger.error(f"{self.log_prefix}: {err_msg}")
                    return ValidationResult(success=False, message=err_msg)
                elif "$" in remove_from_other_groups:
                    err_msg = (
                        "Remove From All Other Groups contains the Business "
                        "Rule Record Field. Please select group from Static"
                        " field dropdown only."
                    )
                    self.logger.error(f"{self.log_prefix}: {err_msg}")
                    return ValidationResult(success=False, message=err_msg)
                elif remove_from_other_groups not in ["yes", "no"]:
                    err_msg = (
                        "Invalid value provided for Remove From All Other "
                        "Groups. Valid values are yes or no."
                    )
                    self.logger.error(f"{self.log_prefix}: {err_msg}")
                    return ValidationResult(success=False, message=err_msg)

            elif action_value == "remove":
                if (
                    f"No groups found on {PLATFORM_NAME} server"
                    in action_params.get("group")
                ):
                    err_msg = (
                        "Action will not be saved as no groups found on"
                        f" {PLATFORM_NAME} server."
                    )
                    self.logger.error(f"{self.log_prefix}: {err_msg}")
                    return ValidationResult(success=False, message=err_msg)
                elif not any(
                    map(
                        lambda g: json.loads(g)["dn"] in groups,
                        action_params.get("group"),
                    )
                ):
                    err_msg = (
                        "Invalid Group Name provided in action configuration."
                    )
                    self.logger.error(f"{self.log_prefix}: {err_msg}")
                    return ValidationResult(success=False, message=err_msg)

            log_msg = (
                "Successfully validated action parameters for"
                f" {action_value} action."
            )
            self.logger.debug(f"{self.log_prefix}: {log_msg}")
            return ValidationResult(success=True, message=log_msg)
        except LDAPPluginException as exp:
            return ValidationResult(success=True, message=str(exp))
        except Exception as exp:
            err_msg = "Error occurred while validating action parameters."
            self.logger.error(
                message=(f"{self.log_prefix}: {err_msg} Error: {exp}"),
                details=traceback.format_exc(),
            )
            return ValidationResult(
                success=False,
                message=f"{err_msg} Check logs for more details.",
            )

    def get_action_params(self, action: Action) -> List:
        """Get fields required for an action.

        Args:
            action (Action): Action provided by user.

        Returns:
            List: list containing action fields for respective action.
        """
        if action.value == "generate":
            return []
        try:
            conn = self.get_connection_object(
                configuration=self.configuration,
                logger_msg=f"getting groups from {PLATFORM_NAME} server",
                is_validation=True,
            )
            groups = self._get_all_groups(
                configuration=self.configuration,
                conn=conn,
                is_validation=True,
            )

            groups = sorted(groups, key=lambda g: g.get("name").lower())

            for group in groups:
                dn = group.get("dn", "")
                new_dn = re.sub(GROUP_REGEX, "/", dn.replace(",", ""))
                group["display_name"] = "/".join(
                    new_dn.strip("/").split("/")[::-1]
                )
            new_group_dict = json.dumps({"name": "create"})
            if action.value == "add":
                return [
                    {
                        "label": EMAIL_FIELD,
                        "key": "user_email",
                        "type": "text",
                        "default": "",
                        "mandatory": True,
                        "description": (
                            f"{EMAIL_FIELD} of the user to perform"
                            " the action on."
                        ),
                    },
                    {
                        "label": "Groups",
                        "key": "group",
                        "type": "multichoice",
                        "choices": [
                            {"key": g["display_name"], "value": json.dumps(g)}
                            for g in groups
                        ]
                        + [
                            {
                                "key": "Create new group",
                                "value": new_group_dict,
                            }
                        ],
                        "default": (
                            [json.dumps(groups[0])]
                            if groups
                            else [new_group_dict]
                        ),
                        "mandatory": True,
                        "description": (
                            "Select groups to which you want to add the user."
                        ),
                    },
                    {
                        "label": "New Group Name",
                        "key": "new_group_name",
                        "type": "text",
                        "default": "",
                        "mandatory": False,
                        "description": (
                            f"Create new {PLATFORM_NAME} group. This will be "
                            "only applied when Create new group is selected in"
                            " Groups parameter."
                        ),
                    },
                    {
                        "label": "Remove From All Other Groups",
                        "key": "remove_from_other_groups",
                        "type": "choice",
                        "choices": [
                            {"key": "Yes", "value": "yes"},
                            {"key": "No", "value": "no"},
                        ],
                        "default": "No",
                        "mandatory": True,
                        "description": (
                            "Do you want to remove this user from all"
                            " other Groups?"
                        ),
                    },
                ]
            elif action.value == "remove":
                return [
                    {
                        "label": EMAIL_FIELD,
                        "key": "user_email",
                        "type": "text",
                        "default": "",
                        "mandatory": True,
                        "description": (
                            f"{EMAIL_FIELD} of the user to perform"
                            " the action on."
                        ),
                    },
                    {
                        "label": "Groups",
                        "key": "group",
                        "type": "multichoice",
                        "choices": [
                            {
                                "key": g.get("display_name"),
                                "value": json.dumps(g),
                            }
                            for g in groups
                        ],
                        "default": (
                            [json.dumps(groups[0])]
                            if groups
                            else [
                                f"No groups found on {PLATFORM_NAME} server"
                            ]
                        ),
                        "mandatory": True,
                        "description": (
                            "Select group(s) from which the user should"
                            " be removed."
                        ),
                    },
                ]
        except Exception as exp:
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Error occurred while getting"
                    f" action params. Error: {exp}"
                ),
                details=traceback.format_exc(),
            )
            raise LDAPPluginException(exp)

    def get_actions(self) -> List[ActionWithoutParams]:
        """Get available actions.

        Returns:
            List[ActionWithoutParams]: List containing action label and value.
        """
        return [
            ActionWithoutParams(label="Add to group", value="add"),
            ActionWithoutParams(label="Remove from group", value="remove"),
            ActionWithoutParams(label="No actions", value="generate"),
        ]

    def execute_action(self, action: Action):
        """Execute action on the user.

        Args:
            record (Record): records of user
            action (Action): action fields
        """
        action_label = action.label
        action_parameters = action.parameters
        action_value = action.value
        if action_value == "generate":
            return
        user_email = action_parameters.get("user_email", "").strip()
        if not user_email:
            err_msg = (
                f"{EMAIL_FIELD} not found in the action parameters. "
                f"Hence, skipping execution of '{action_label}' action."
            )
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            raise LDAPPluginException(err_msg)
        elif not isinstance(user_email, str):
            err_msg = (
                f"Invalid {EMAIL_FIELD} found in the action parameters. "
                f"Hence, skipping execution of '{action_label}' action."
            )
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            raise LDAPPluginException(err_msg)

        conn = self.get_connection_object(
            configuration=self.configuration,
            logger_msg=f"executing {action_label} on {PLATFORM_NAME} server",
        )  # Get connection object.

        match = self._get_user_match(
            conn=conn, user_email=user_email
        )  # Check if user exist of not on LDAP platform.
        if not match:
            self.logger.warn(
                f"{self.log_prefix}: User with email {user_email}"
                f" does not exist on {PLATFORM_NAME} server."
            )
            return

        for user_info in match:
            if action.value == "add":
                remove_from_other_groups = action.parameters.get(
                    "remove_from_other_groups"
                )
                if remove_from_other_groups == "yes":
                    self._remove_from_all_group(user=user_info, conn=conn)

                for group_info in action.parameters.get("group"):
                    group_info = json.loads(group_info)
                    try:
                        if group_info.get("name") == "create":
                            group_name = action.parameters.get(
                                "new_group_name"
                            ).strip()
                            match_group = self._get_group_match(
                                conn=conn, group_name=group_name
                            )

                            if (
                                not match_group
                            ):  # check if group exist or not.
                                match_group = self._create_group(
                                    group_name=group_name,
                                    conn=conn,
                                )
                            group_info = match_group

                        self._add_to_group(
                            user_info=user_info,
                            group_info=group_info,
                            conn=conn,
                        )

                    except LDAPPluginException:
                        raise
                    except Exception as exp:
                        err_msg = (
                            "Unexpected error occurred"
                            f" while adding user {user_email} to group "
                            f" {group_info.get('name')}."
                        )
                        self.logger.error(
                            message=(
                                f"{self.log_prefix}: {err_msg} Error: {exp}"
                            ),
                            details=traceback.format_exc(),
                        )
                        raise LDAPPluginException(err_msg)

            elif action.value == "remove":
                for group_info in action.parameters.get("group"):
                    group_info = json.loads(group_info)
                    group_name = group_info.get(
                        "name"
                    )  # get group name from group info dict
                    try:
                        self.logger.info(
                            f"{self.log_prefix}: Removing user {user_email} "
                            f"from group {group_name}."
                        )
                        self._remove_from_group(
                            user_id=user_info.get("dn"),
                            group_id=group_info.get("dn"),
                            conn=conn,
                        )
                        self.logger.info(
                            f"{self.log_prefix}: Successfully removed user"
                            f" {user_email} from group {group_name}"
                        )
                    except LDAPInsufficientAccessRightsResult as exp:
                        user = self.configuration.get("username")
                        err_msg = (
                            f" User {user} does not have "
                            f"enough permission to remove {user_email} "
                            f"from group {group_name}."
                        )
                        self.logger.error(
                            message=(
                                f"{self.log_prefix}: {err_msg} Error:"
                                f" {exp}"
                            ),
                            details=traceback.format_exc(),
                        )
                    except LDAPNoSuchObjectResult as exp:
                        err_msg = (
                            f"Group {group_name} does not exist on"
                            f" {PLATFORM_NAME} server."
                        )
                        self.logger.error(
                            message=(
                                f"{self.log_prefix}: {err_msg} Error:"
                                f" {exp}"
                            ),
                            details=traceback.format_exc(),
                        )
                    except Exception as exp:
                        err_msg = (
                            "Unexpected error occurred"
                            f" while removing user {user_email} to group "
                            f" {group_info.get('name')}."
                        )
                        self.logger.error(
                            message=(
                                f"{self.log_prefix}: {err_msg} Error: {exp}"
                            ),
                            details=traceback.format_exc(),
                        )
                        raise LDAPPluginException(err_msg)

    def get_entities(self) -> list[Entity]:
        """Get available entities."""
        return [
            Entity(
                name="Users",
                fields=[
                    EntityField(
                        name=USER_PRINCIPAL_NAME,
                        type=EntityFieldType.STRING,
                        required=True,
                    ),
                    EntityField(
                        name="Distinguished Name (DN)",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name=EMAIL_FIELD, type=EntityFieldType.STRING
                    ),
                    EntityField(
                        name="User Groups", type=EntityFieldType.LIST
                    ),
                    EntityField(
                        name="User Name", type=EntityFieldType.STRING
                    ),
                ],
            )
        ]
