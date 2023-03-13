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
"""

"""LDAP URE plugin."""
import json
import re
import ssl
from typing import Dict, List, Optional

from netskope.integrations.cre.models import (
    Action,
    ActionWithoutParams,
    Record,
)
from netskope.integrations.cre.plugin_base import PluginBase, ValidationResult

from .lib.ldap3 import Connection, Server, Tls
from .lib.ldap3.core.exceptions import (
    LDAPBindError,
    LDAPInvalidCredentialsResult,
    LDAPInvalidDnError,
    LDAPInvalidPortError,
    LDAPOperationsErrorResult,
    LDAPSocketOpenError,
    LDAPSocketReceiveError,
    LDAPNoSuchObjectResult,
    LDAPInsufficientAccessRightsResult,
)
from .lib.ldap3.extend.microsoft.addMembersToGroups import (
    ad_add_members_to_groups,
)
from .lib.ldap3.extend.microsoft.removeMembersFromGroups import (
    ad_remove_members_from_groups,
)

PLUGIN_NAME = "LDAP URE Plugin"


class LDAPException(Exception):
    """LDAP Plugin Exception class."""

    pass


class LDAPPlugin(PluginBase):
    """LDAP URE plugin implementation."""

    def get_connection_object(self, configuration: Dict) -> Connection:
        """Get connection object for LDAP server.

        Args:
            configuration (Dict): Configuration dictionary.

        Returns:
            Connection: Connection object
        """
        try:
            server_ip = configuration.get("server", "").strip()
            port = int(configuration.get("port"))
            username = configuration.get("username", "").strip()
            password = configuration.get("password", "").strip()
            ldap_cert = configuration.get("ldap_certificate", "").strip()
            if ldap_cert:
                tls = Tls(
                    validate=ssl.CERT_REQUIRED,
                    version=ssl.PROTOCOL_TLS,
                    ca_certs_data=ldap_cert,
                )
                server = Server(
                    host=f"ldaps://{server_ip}",
                    port=port,
                    use_ssl=self.ssl_validation,
                    tls=tls,
                )
                conn = Connection(
                    server,
                    username,
                    password,
                    auto_bind=True,
                    authentication="SIMPLE",
                    raise_exceptions=True,
                )
                return conn
            else:
                server = Server(
                    host=f"ldap://{server_ip}",
                    port=port,
                    use_ssl=self.ssl_validation,
                )
                conn = Connection(
                    server,
                    username,
                    password,
                    auto_bind=True,
                    authentication="SIMPLE",
                    raise_exceptions=True,
                )
                conn.start_tls()
                return conn
        except Exception as error:
            raise error

    def fetch_records(self):
        """Fetch and extract list of new users from Netskope alerts."""
        return []

    def fetch_scores(self, records: List[Record]):
        """Fetch user scores."""
        return []

    def _get_all_groups(self, configuration: Dict, conn: Connection) -> List:
        """Get list of all the groups.

        Args:
            configuration (Dict): Configuration parameters.

        Returns:
            List: List of all the groups.
        """
        response = conn.search(
            search_base=configuration.get("search_base", "").strip(),
            search_scope="SUBTREE",
            search_filter="(objectClass=group)",
            attributes={"name", "distinguishedName"},
        )
        groups = []
        if response:
            for entry in conn.entries:
                try:
                    response = json.loads(entry.entry_to_json())
                    if response.get("attributes", {}).get(
                        "name"
                    ) and response.get("attributes", {}).get(
                        "distinguishedName"
                    ):
                        groups.append(
                            {
                                "name": response.get("attributes", {}).get(
                                    "name",
                                    [""],  # change default to empty string
                                )[0],
                                "dn": response.get("attributes", {}).get(
                                    "distinguishedName", [""]
                                )[0],
                            }
                        )
                except json.JSONDecodeError as exp:
                    self.logger.error(
                        message=f"{PLUGIN_NAME}: Can't create JSON for group.",
                        details=str(exp),
                    )
                except Exception as exp:
                    self.logger.error(
                        message=f"{PLUGIN_NAME}: Error occurred while\
                            fetching groups.",
                        details=str(exp),
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
            f"{PLUGIN_NAME}: Verifying the existence of {group_name} on the ldap server."
        )
        response = conn.search(
            search_base=self.configuration.get("search_base", "").strip(),
            search_filter=f"(&(objectClass=group)(name={group_name}))",
            attributes={"name", "distinguishedName"},
            search_scope="SUBTREE",
        )
        if response:
            for entry in conn.entries:
                try:
                    response = json.loads(entry.entry_to_json())
                    group_name = response.get("attributes", {}).get(
                        "name", [""]
                    )[0]
                    dn = response.get("attributes", {}).get(
                        "distinguishedName", [""]
                    )[0]
                    if group_name and dn:
                        self.logger.info(
                            f"{PLUGIN_NAME}: Group {group_name} "
                            "exists on ldap platform."
                        )
                        return {"name": group_name, "dn": dn}

                except Exception as exp:
                    self.logger.error(
                        message=f"{PLUGIN_NAME}: Error occurred while getting group match.",
                        details=str(exp),
                    )
                    raise LDAPException(exp)

        self.logger.info(
            f"{PLUGIN_NAME}: Group {group_name} does not exists on ldap platform."
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
            f"{PLUGIN_NAME}: Getting match for user {user_email}."
        )
        response = conn.search(
            search_base=self.configuration.get("search_base"),
            search_filter=f"(&(objectClass=User)(mail={user_email}))",  # search only users with given email.
            attributes={
                "mail",
                "distinguishedName",
            },  # return only mail and distinguishedName in response.
            search_scope="SUBTREE",  # find in subtree of current path
        )
        matched_users = []
        if response:
            for entry in conn.entries:
                try:
                    response = json.loads(entry.entry_to_json())
                    mail = response.get("attributes", {}).get(
                        "mail", [""]
                    )  # Fetch mailof user
                    dn = response.get("attributes", {}).get(
                        "distinguishedName", [""]
                    )  # Fetch DN of user
                    if mail and dn:
                        matched_users.append(
                            {
                                "mail": mail[0],
                                "dn": dn[0],
                            }
                        )

                except Exception as exp:
                    self.logger.error(
                        message=f"{PLUGIN_NAME}: Error occurred while getting match for user {user_email}",
                        details=str(exp),
                    )
                    raise

        if matched_users:
            self.logger.info(
                f"{PLUGIN_NAME}: User with email {user_email} exist on "
                f"ldap server. Total {len(matched_users)} match(es) found."
            )

        return matched_users

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
        self.logger.info(
            f"{PLUGIN_NAME}: Removing user {user.get('mail')} from existing groups."
        )
        response = conn.search(
            search_base=self.configuration["search_base"],
            search_filter=f"(&(objectClass=User)(mail={user.get('mail')}))",
            attributes={"memberOf", "name"},
            search_scope="SUBTREE",
        )
        if response:
            for entry in conn.entries:
                try:

                    response = json.loads(entry.entry_to_json())
                    groups = {
                        "groups": response.get("attributes", {}).get(
                            "memberOf", []
                        ),
                        "name": response.get("attributes", {}).get("name", []),
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
                                err_msg = f"{PLUGIN_NAME}: Group with distiguished name(DN) {group} does not exist on ldap server."
                                self.logger.error(
                                    message=err_msg, details=str(exp)
                                )
                            except LDAPInsufficientAccessRightsResult as exp:
                                username = self.configuration.get("username")
                                err_msg = (
                                    f"{PLUGIN_NAME}: User {username} does "
                                    "not have enough permission to remove "
                                    f"{user.get('mail')} users from group with"
                                    f" distiguished name(DN) {group}."
                                )
                                self.logger.error(
                                    message=f"{PLUGIN_NAME}: {err_msg}",
                                    details=str(exp),
                                )
                                raise LDAPException(err_msg)
                        self.logger.info(
                            f"{PLUGIN_NAME}: Successfully removed "
                            f"{user.get('mail')} from existing groups."
                        )

                except Exception as exp:
                    self.logger.error(
                        message=f"{PLUGIN_NAME}: Error occurred removing users from groups.",
                        details=str(exp),
                    )
                    raise LDAPException(exp)

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
            Exception: If any unexpected error occurrs.
        """
        user_mail = user_info.get("mail")
        group_name = group_info.get("name")
        self.logger.info(
            f"{PLUGIN_NAME}: Adding user {user_mail} to group {group_name}."
        )
        try:
            ad_add_members_to_groups(
                connection=conn,
                members_dn=user_info.get("dn"),
                groups_dn=group_info.get("dn"),
                raise_error=True,
            )
            self.logger.info(
                f"{PLUGIN_NAME}: Successfully added user "
                f"{user_mail} to group {group_name}."
            )
        except LDAPOperationsErrorResult as error:
            self.logger.warn(
                message=f"{PLUGIN_NAME}: User with mail {user_mail} or \
                    selected group {group_name} does not exist on ldap Server.",
                details=str(error),
            )
            raise LDAPException(error)
        except LDAPNoSuchObjectResult as error:
            err_msg = f"{PLUGIN_NAME}: Group {group_name} does not exist on ldap server."
            self.logger.error(message=err_msg, details=str(error))
            raise LDAPException(err_msg)
        except LDAPInsufficientAccessRightsResult as exp:
            user = self.configuration.get("username")
            err_msg = (
                f"{PLUGIN_NAME}: {user} does not have enough permission to "
                f"add user {user_mail} to group. {group_name}."
            )
            self.logger.error(message=err_msg, details=str(exp))
            raise LDAPException(err_msg)
        except Exception as exp:
            self.logger.error(
                message=f"{PLUGIN_NAME}: Error occurred while adding user \
                    {user_mail} to group {group_name}",
                details=str(exp),
            )
            raise LDAPException(exp)

    def _create_group(self, group_name: str, conn: Connection) -> Dict:
        """Create a new group with name.

        Args:
            group_name (str): Name of the group to create.
            conn (Connection): Connection object.

        Returns:
            Dict: Newly created group dictionary.
        """
        self.logger.info(
            f"{PLUGIN_NAME}: Create a new group {group_name} on ldap server."
        )
        search_base = self.configuration.get("search_base").strip()
        result = conn.add(
            f"cn={group_name},{search_base}",
            attributes={"objectClass": ["group"], "name": group_name},
        )

        if result:
            response = conn.search(
                search_base=search_base,
                search_scope="SUBTREE",
                search_filter=f"(&(objectClass=group)(name={group_name}))",  # Search for group in groups named by given name.
                attributes={"name", "distinguishedName"},
            )
            if response:
                for entry in conn.entries:
                    try:
                        response = entry.entry_to_json()
                        response = json.loads(response)
                        group_info = {
                            "name": response.get("attributes", {}).get(
                                "name", [""]
                            )[0],
                            "dn": response.get("attributes", {}).get(
                                "distinguishedName"
                            )[0],
                        }
                        self.logger.info(
                            f"{PLUGIN_NAME}: Successfully created group "
                            f"{group_name} on ldap server."
                        )
                        return group_info
                    except LDAPInsufficientAccessRightsResult as exp:
                        user = self.configuration.get("username")
                        err_msg = f"{PLUGIN_NAME}: User {user} does not have permission to create new group."
                        self.logger.error(message=err_msg, details=str(exp))
                        raise LDAPInsufficientAccessRightsResult(err_msg)
                    except Exception as exp:
                        self.logger.error(
                            message=f"{PLUGIN_NAME}: Error occurred while creating group.",
                            detail=str(exp),
                        )
                        raise LDAPException(exp)

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
            conn = self.get_connection_object(configuration=config)
            conn.search(
                search_base=config.get("search_base", "").strip(),
                search_filter="(objectClass=User)",
                attributes={"mail", "distinguishedName"},
                search_scope="SUBTREE",
            )
        except LDAPBindError as error:
            err_msg = "Invalid Username/Password Provided."
            self.logger.error(
                message=f"{PLUGIN_NAME}: {err_msg}",
                details=str(error),
            )
            return ValidationResult(success=False, message=err_msg)
        except LDAPInvalidCredentialsResult as error:
            err_msg = "Invalid Username/Password Provided."
            self.logger.error(
                message=f"{PLUGIN_NAME}: {err_msg}",
                details=str(error),
            )
            return ValidationResult(success=False, message=err_msg)
        except LDAPSocketOpenError as error:
            err_msg = "Invalid LDAP Server,Port, Certificate or Search Base Provided."
            self.logger.error(
                message=f"{PLUGIN_NAME}: {err_msg}",
                details=str(error),
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        except LDAPInvalidPortError as error:
            err_msg = "Invalid LDAP Port Provided."
            self.logger.error(
                message=f"{PLUGIN_NAME}: {err_msg}",
                details=str(error),
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        except LDAPInvalidDnError as error:
            err_msg = "Invalid Search Base Provided."
            self.logger.error(
                message=f"{PLUGIN_NAME}: {err_msg}",
                details=str(error),
            )
            return ValidationResult(success=False, message=err_msg)
        except LDAPNoSuchObjectResult as error:
            err_msg = (
                "Search Base does not exist. Provide a valid Search Base."
            )
            self.logger.error(
                message=f"{PLUGIN_NAME}: {err_msg}", details=str(error)
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        except LDAPSocketReceiveError as error:
            err_msg = "LDAP Certificate is required for TLS connection."
            self.logger.error(
                message=f"{PLUGIN_NAME}: {err_msg}",
                details=str(error),
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        except Exception as error:
            err_msg = "Error occurred while authentication."
            self.logger.error(
                message=err_msg,
                details=str(error),
            )
            return ValidationResult(
                success=False,
                message=f"{err_msg} Check logs for details.",
            )
        return ValidationResult(
            success=True, message="Validation Successfull."
        )

    def _validate_server_address(self, server_address: str) -> bool:
        """Validate Server address.

        Args:
            server_address (str): Server IP or DNS.

        Returns:
            bool: True if server address is valid else False.
        """
        regex_ip = r"^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$"
        regex_dns = r"^((?!-))(xn--)?[A-Za-z0-9][A-Za-z0-9-_]{0,61}[A-Za-z0-9]{0,1}\.(xn--)?([A-Za-z0-9\-]{1,61}|[A-Za-z0-9-]{1,30}\.[A-Za-z]{2,})$"
        is_ip_valid = re.match(regex_ip, server_address)
        is_dns_valid = re.match(regex_dns, server_address)
        return is_ip_valid or is_dns_valid

    def validate(self, configuration: Dict) -> ValidationResult:
        """Validate LDAP configuration.

        Args:
            configuration (Dict): Configurations dictionary.

        Returns:
            ValidationResult: ValidationResult object.
        """
        if (
            "server" not in configuration
            or type(configuration["server"]) != str
            or not configuration["server"].strip()
        ):
            err_msg = "Server Address is a required field."
            self.logger.error(f"{PLUGIN_NAME}: {err_msg}")

            return ValidationResult(success=False, message=err_msg)

        if not self._validate_server_address(configuration["server"].strip()):
            err_msg = "Invalid Server Address provided."
            self.logger.error(f"{PLUGIN_NAME}: {err_msg}")
            return ValidationResult(success=False, message=err_msg)

        try:
            if (
                "port" not in configuration
                or not configuration["port"]
                or not isinstance(configuration["port"], int)
            ):
                err_msg = "Port is a required field."
                self.logger.error(f"{PLUGIN_NAME}: {err_msg}")
                return ValidationResult(
                    success=False,
                    message=err_msg,
                )
            if not self._validate_port(int(configuration.get("port"))):
                err_msg = "LDAP Port must be in range of 0 to 65535."
                self.logger.error(f"{PLUGIN_NAME}: {err_msg}")
                return ValidationResult(
                    success=False,
                    message=err_msg,
                )
        except ValueError:
            self.logger.error(
                f"{PLUGIN_NAME}: Invalid LDAP Server Port Provided."
            )
            return ValidationResult(
                success=False,
                message="Invalid LDAP Server Port Provided.",
            )
        if (
            "username" not in configuration
            or not configuration["username"].strip()
        ):
            err_msg = "Username is a required field."
            self.logger.error(f"{PLUGIN_NAME}: {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        if (
            "password" not in configuration
            or not configuration["password"].strip()
        ):
            err_msg = "Password is a required field."
            self.logger.error(f"{PLUGIN_NAME}: {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )

        if (
            "search_base" not in configuration
            or not configuration["search_base"].strip()
        ):
            err_msg = "Search Base is a required field."
            self.logger.error(f"{PLUGIN_NAME}: {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )

        return self._validate_auth(configuration)

    def validate_action(self, action: Action) -> ValidationResult:
        """Validate actions.

        Args:
            action (Action): actions provided by users.

        Returns:
            ValidationResult: ValidationResult object.
        """
        try:
            conn = self.get_connection_object(configuration=self.configuration)
            if action.value not in ["add", "remove", "generate"]:
                self.logger.error(
                    f"{PLUGIN_NAME}: Invalid Action Value Provided."
                )
                return ValidationResult(
                    success=False, message="Unsupported Action Provided."
                )
            groups = self._get_all_groups(
                configuration=self.configuration, conn=conn
            )

            create_dict = json.dumps({"name": "create"})
            groups = [group.get("dn") for group in groups]
            if (
                action.value == "add"
                and create_dict in action.parameters.get("group")
                and len(action.parameters.get("new_group_name", "").strip())
                == 0
            ):
                self.logger.error(
                    f"{PLUGIN_NAME}: New Group Name can not be empty field."
                )
                return ValidationResult(
                    success=False,
                    message="New Group Name can not be empty field.",
                )
            if not action.parameters.get("group"):
                err_msg = "Select a group to perform action on."
                self.logger.error(f"{PLUGIN_NAME}: {err_msg}")
                return ValidationResult(success=False, message=err_msg)

            elif (
                action.value == "add"
                and create_dict not in action.parameters.get("group")
            ) and (
                not any(
                    map(
                        lambda group: json.loads(group)["dn"] in groups,
                        action.parameters.get("group"),
                    )
                )
            ):
                err_msg = "Invalid Group Name Provided."
                self.logger.error(f"{PLUGIN_NAME}: {err_msg}")
                return ValidationResult(success=False, message=err_msg)

            elif (
                action.value == "remove"
                and "No groups found on ldap server"
                in action.parameters.get("group")
            ):
                err_msg = "Action will not be saved as no groups found on ldap server."
                self.logger.error(f"{PLUGIN_NAME}: {err_msg}")
                return ValidationResult(success=False, message=err_msg)

            elif action.value == "remove" and not any(
                map(
                    lambda g: json.loads(g)["dn"] in groups,
                    action.parameters.get("group"),
                )
            ):
                err_msg = "Invalid Group Name Provided."
                self.logger.error(f"{PLUGIN_NAME}: {err_msg}")
                return ValidationResult(success=False, message=err_msg)

            return ValidationResult(
                success=True, message="Validation successful."
            )
        except Exception as exp:
            self.logger.error(
                message=f"{PLUGIN_NAME}: Error occurred while validating action.",
                details=str(exp),
            )
            raise LDAPException(exp)

    def get_action_fields(self, action: Action) -> List:
        """Get fields required for an action.

        Args:
            action (Action): Action provided by user.

        Returns:
            List: list containing action fields for respective action.
        """
        conn = self.get_connection_object(configuration=self.configuration)
        if action.value == "generate":
            return []

        groups = self._get_all_groups(
            configuration=self.configuration, conn=conn
        )

        groups = sorted(groups, key=lambda g: g.get("name").lower())

        for group in groups:
            dn = group.get("dn", "")
            regex = (
                "(CN=)|(DC=)|(OU=)|(O=)|(UID=)|(C=)|(SN=)|(L=)|(ST=)|(STREET=)"
            )
            new_dn = re.sub(regex, "/", dn.replace(",", ""))
            group["display_name"] = "/".join(
                new_dn.strip("/").split("/")[::-1]
            )
        new_group_dict = json.dumps({"name": "create"})
        if action.value == "add":
            return [
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
                    "default": [json.dumps(groups[0])]
                    if groups
                    else [new_group_dict],
                    "mandatory": True,
                    "description": "Select groups to which you want to add the user.",
                },
                {
                    "label": "New Group Name",
                    "key": "new_group_name",
                    "type": "text",
                    "default": "",
                    "mandatory": False,
                    "description": "Create new ldap group. This will be only applied when Create new group is selected in Groups parameter.",
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
                    "description": "Do you want to remove this user from all other groups?",
                },
            ]
        elif action.value == "remove":
            return [
                {
                    "label": "Groups",
                    "key": "group",
                    "type": "multichoice",
                    "choices": [
                        {"key": g.get("display_name"), "value": json.dumps(g)}
                        for g in groups
                    ],
                    "default": [json.dumps(groups[0])]
                    if groups
                    else ["No groups found on ldap server"],
                    "mandatory": True,
                    "description": "Select group(s) from which the user should be removed.",
                }
            ]

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

    def execute_action(self, record: Record, action: Action):
        """Execute action on the user.

        Args:
            record (Record): records of user
            action (Action): action fields
        """
        conn = self.get_connection_object(
            self.configuration
        )  # Get connection object.
        if action.value == "generate":
            pass

        email = record.uid

        match = self._get_user_match(
            conn=conn, user_email=email
        )  # Check if user exist of not on LDAP platform.
        if not match:
            self.logger.warn(
                f"{PLUGIN_NAME}: User with email {email} not found on ldap server."
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

                            if not match_group:  # check if group exist or not.
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

                    except Exception as exp:
                        self.logger.error(
                            message=f"{PLUGIN_NAME}: Error occurred while adding "
                            f"user {email} to group with {group_info.get('name')} ",
                            details=str(exp),
                        )

            elif action.value == "remove":

                for group_info in action.parameters.get("group"):
                    group_info = json.loads(group_info)
                    group_name = group_info.get(
                        "name"
                    )  # get group name from group info dict
                    try:
                        self.logger.info(
                            f"{PLUGIN_NAME}: Removing user {email} "
                            f"from group {group_name}."
                        )
                        self._remove_from_group(
                            user_id=user_info.get("dn"),
                            group_id=group_info.get("dn"),
                            conn=conn,
                        )
                        self.logger.info(
                            f"{PLUGIN_NAME}: Successfully removed user {email} "
                            f"from group {group_name}"
                        )
                    except LDAPInsufficientAccessRightsResult as exp:
                        user = self.configuration.get("username")
                        err_msg = (
                            f"{PLUGIN_NAME}: User {user} does not have "
                            f"enough permission to remove {email} "
                            f"from group {group_name}."
                        )
                        self.logger.error(message=err_msg, details=str(exp))
                    except LDAPNoSuchObjectResult as exp:
                        err_msg = f"{PLUGIN_NAME}: Group {group_name} does not exist on ldap server."
                        self.logger.error(message=err_msg, details=str(exp))
                    except Exception as exp:
                        self.logger.error(
                            message=f"Error occurred while removing user \
                                {email} from group {group_name}",
                            details=str(exp),
                        )
