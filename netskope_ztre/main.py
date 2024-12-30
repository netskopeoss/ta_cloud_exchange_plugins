"""Netskope CRE plugin."""

import json
import re
import traceback
import os
import time
from typing import Dict, List, Optional, Union
import requests
from requests.exceptions import ConnectionError

from netskope.integrations.crev2.models import ActionWithoutParams, Action
from netskope.integrations.crev2.plugin_base import (
    Entity,
    EntityField,
    EntityFieldType,
    PluginBase,
    ValidationResult,
)

from netskope.common.utils import (
    AlertsHelper,
    add_user_agent,
    add_installation_id,
    resolve_secret,
)
from netskope.common.utils.handle_exception import (
    handle_exception,
    handle_status_code,
)
from netskope.integrations.crev2.utils import get_latest_values
from netskope.common.utils.plugin_provider_helper import PluginProviderHelper


MAX_RETRY_COUNT = 4
PAGE_SIZE = 100
MAX_HOSTS_PER_PRIVATE_APP = 500
REGEX_HOST = (
    r"^(?!:\/\/)([a-z0-9-]{1,63}\.)?[a-z0-9-]{1,63}(?:\.[a-z]{2,})?$|"
    r"^(?:(?:25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\.){3}(?:25[0-5]|(?:2[0-4]|1\d|[1-9]|)\d)$"
)
REGEX_EMAIL = r"[^@]+@[^@]+\.[^@]+"
MODULE_NAME = "CRE"
PLUGIN = "Netskope CRE"
PLUGIN_VERSION = "1.1.0"
URLS = {
    "V2_PRIVATE_APP": "{}/api/v2/steering/apps/private",
    "V2_PRIVATE_APP_PATCH": "{}/api/v2/steering/apps/private/{}",
    "V2_PUBLISHER": "{}/api/v2/infrastructure/publishers",
    "V2_CCI_TAG_CREATE": "{}/api/v2/services/cci/tags",
    "V2_CCI_TAG_UPDATE": "{}/api/v2/services/cci/tags/{}",
    "V1_APP_INSTANCE": "{}/api/v1/app_instances",
}
ERROR_TAG_EXISTS = (
    "Tag provided is already present. Hence use PATCH method to add "
    "existing tag to the list of apps/ids"
)
ERROR_APP_DOES_NOT_EXIST = "No records matched"
SUCCESS = "Success"
plugin_provider_helper = PluginProviderHelper()


class NetskopeException(Exception):
    """Netskope exception class."""

    pass


class NetskopePlugin(PluginBase):
    """Netskope plugin implementation."""

    def __init__(
        self,
        name,
        configuration,
        storage,
        last_run_at,
        logger,
        use_proxy=False,
        ssl_validation=True,
    ):
        """Initialize."""
        super().__init__(
            name,
            configuration,
            storage,
            last_run_at,
            logger,
            use_proxy,
            ssl_validation,
        )
        self.plugin_name, self.plugin_version = self._get_plugin_info()
        self.log_prefix = f"{MODULE_NAME} {self.plugin_name}"
        if name:
            self.log_prefix = f"{self.log_prefix} [{name}]"

    def _get_plugin_info(self) -> tuple:
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
                plugin_name = manifest_json.get("name", PLUGIN)
                plugin_version = manifest_json.get("version", PLUGIN)
                return (plugin_name, plugin_version)
        except Exception as exp:
            self.logger.error(
                message=(
                    f"{MODULE_NAME} {PLUGIN}: Error occurred while"
                    f" getting plugin details. Error: {exp}"
                ),
                details=str(traceback.format_exc()),
            )
        return (PLUGIN, PLUGIN_VERSION)

    def get_entities(self) -> List[Entity]:
        """Get available entities."""
        return [
            Entity(
                name="Users",
                fields=[
                    EntityField(
                        name="email",
                        type=EntityFieldType.STRING,
                        required=True,
                    ),
                    EntityField(name="ubaScore", type=EntityFieldType.NUMBER),
                    EntityField(
                        name="policyName", type=EntityFieldType.STRING
                    ),
                ],
            ),
            Entity(
                name="Applications",
                fields=[
                    EntityField(
                        name="applicationId", type=EntityFieldType.STRING
                    ),
                    EntityField(
                        name="applicationName",
                        type=EntityFieldType.STRING,
                        required=True,
                    ),
                    EntityField(name="vendor", type=EntityFieldType.STRING),
                    EntityField(name="source", type=EntityFieldType.STRING),
                    EntityField(name="cci", type=EntityFieldType.NUMBER),
                    EntityField(name="ccl", type=EntityFieldType.STRING),
                    EntityField(
                        name="categoryName", type=EntityFieldType.STRING
                    ),
                    EntityField(name="users", type=EntityFieldType.LIST),
                    EntityField(name="deepLink", type=EntityFieldType.STRING),
                    EntityField(name="customTags", type=EntityFieldType.LIST),
                    EntityField(
                        name="discoveryDomains", type=EntityFieldType.LIST
                    ),
                    EntityField(
                        name="steeringDomains", type=EntityFieldType.LIST
                    ),
                ],
            ),
        ]

    def fetch_records(self, entity: str) -> list[dict]:
        """Fetch and extract list of new users from Netskope alerts."""
        helper = AlertsHelper()
        self.tenant = helper.get_tenant_crev2(self.name)
        if entity == "Users":
            return self._fetch_users()
        elif entity == "Applications":
            return self._fetch_applications()
        else:
            raise ValueError(f"Unsupported entity '{entity}'")

    def _get_applications_dict(self, application_events: List):
        """Convert the application event to dict.

        Args:
            application_events (list): Events of application type.

        Return:
            application_dict (dict): application dictionary.
        """
        application_dict = {}
        for application_event in application_events:
            existing_user = application_dict.get(
                application_event["app"].lower(), {}
            ).get("user", [])
            if not existing_user:
                users = (
                    [application_event.get("user")]
                    if application_event.get("user")
                    else []
                )
            else:
                existing_user.append(application_event.get("user", []))
                users = existing_user
            application_dict[application_event["app"].lower()] = {
                "applicationName": application_event.get("app"),
                "cci": application_event.get("cci", None),
                "ccl": application_event.get("ccl", "unknown"),
                "users": users,
                "categoryName": application_event.get("appcategory"),
            }
        return application_dict

    def _api_call_helper(
        self,
        endpoint,
        method,
        error_codes,
        message="",
        params={},
        data=None,
        auth=None,
    ):
        """Call the API helper for getting application related data."""
        request_func = getattr(requests, method)

        tenant_name = self.tenant.parameters.get("tenantName").replace(" ", "")
        token = resolve_secret(self.tenant.parameters.get("v2token"))
        url = f"{tenant_name}/api/v2{endpoint}"
        headers = {
            "Netskope-API-Token": token,
            "Content-Type": "application/json",
        }
        response = {}

        for attempt in range(MAX_RETRY_COUNT):
            success, response = handle_exception(
                request_func,
                error_code=error_codes[0],
                custom_message=message,
                plugin=PLUGIN,
                url=url,
                headers=add_installation_id(add_user_agent(headers)),
                json=data,
                params=params,
                proxies=self.proxy,
            )
            if not success:
                raise response

            if response.status_code == 429 and attempt < (MAX_RETRY_COUNT - 1):
                self.logger.error(
                    f"{self.log_prefix}: Received Too Many Requests error. "
                    f"Performing retry for url {url}. "
                    f"Retry count: {attempt + 1}.",
                    details=f"Retrying for url {url}.",
                )
                time.sleep(60)
                continue
            response = handle_status_code(
                response,
                error_code=error_codes[1],
                custom_message=message,
                plugin=PLUGIN,
                notify=False,
            )
            return response
        else:
            raise requests.exceptions.HTTPError("Maximum retry limit reached")

    def _fetch_app_details(self, applications):
        """Fetch the application details."""
        endpoint = "/services/cci/app"
        max_applications = 100
        application_names = []
        last_element_counter = 0
        total_event_len = len(applications.keys())
        for application in applications.keys():
            application_names.append(application)
            last_element_counter += 1
            if (
                len(application_names) == max_applications
                or last_element_counter >= total_event_len
            ):
                app_names_req = ";".join(application_names)
                params = {"apps": app_names_req}
                response = self._api_call_helper(
                    endpoint=endpoint,
                    method="get",
                    params=params,
                    error_codes=["CRE_1033", "CRE_1034"],
                    message="Error occurred while fetching the application details of the applications",
                )

                if response.get("data"):
                    for apps in response["data"]:
                        if apps.get("app_name").lower() not in applications:
                            continue
                        applications[apps.get("app_name").lower()][
                            "applicationId"
                        ] = (str(apps["id"]) if "id" in apps else None)
                        applications[apps.get("app_name").lower()][
                            "vendor"
                        ] = apps.get("organisation", None)
                        if apps.get("cci", None) is not None:
                            applications[apps.get("app_name").lower()][
                                "cci"
                            ] = apps.get("cci", None)
                        if apps.get("ccl", None):
                            applications[apps.get("app_name").lower()][
                                "ccl"
                            ] = apps.get("ccl", None)
                        if apps.get("category_name", None):
                            applications[apps.get("app_name").lower()][
                                "categoryName"
                            ] = apps.get("category_name", None)
                application_names = []

    def _create_applications(self, applications):
        """Pull the app information from Netskope Tenant.

        Returns:
            List[grc.models.Application]: List of app data received from the Netskope.
        """
        app_data = []

        try:
            skip_app_count = 0
            for app in applications.values():
                deeplink = "-"
                if app.get("applicationId", None):
                    deeplink = (
                        f"{self.tenant.parameters.get('tenantName')}/ns#/"
                        f"app_index_detail/index/{app['applicationId']}"
                    )
                try:
                    app_obj = {
                        "applicationId": app.get("applicationId", None),
                        "applicationName": app.get("applicationName"),
                        "vendor": app.get("vendor"),
                        "source": self.name,
                        "cci": app.get("cci"),
                        "ccl": app.get("ccl"),
                        "categoryName": app.get("categoryName"),
                        "users": app.get("users"),
                        "deepLink": deeplink,
                        "customTags": app.get("tag_details", []),
                        "discoveryDomains": app.get("domain_details", {}).get(
                            "discovery_domains", []
                        ),
                        "steeringDomains": app.get("domain_details", {}).get(
                            "steering_domains", []
                        ),
                    } | ({} if "_id" not in app else {"_id": app.get("_id")})
                    app_data.append(app_obj)
                except Exception:
                    skip_app_count += 1
            self.logger.info(
                f"{self.log_prefix}: Successfully extracted"
                f" {len(app_data)} application(s) from "
                f"Netskope Tenant. Skipped {skip_app_count} application(s) due to invalid data."
            )
            return app_data
        except Exception as e:
            self.logger.info(
                f"{self.log_prefix}: Polling is disabled, skipping. {e}"
            )
        return app_data

    def _fetch_app_domains(self, applications):
        """Fetch the domain details for each application."""
        endpoint = "/services/cci/domain"
        max_applications = 100
        application_ids = []
        last_element_counter = 0
        total_event_len = len(applications.keys())
        for _, application_details in applications.items():
            application_ids.append(str(application_details["applicationId"]))
            last_element_counter += 1
            if (
                len(application_ids) == max_applications
                or last_element_counter >= total_event_len
            ):
                app_ids_req = ";".join(application_ids)
                params = {"ids": app_ids_req}

                response = self._api_call_helper(
                    endpoint=endpoint,
                    method="get",
                    params=params,
                    error_codes=["CRE_1026", "CRE_1027"],
                    message="Error occurred while fetching the domain details of the applications",
                )

                if response.get("data"):
                    for domain_details in response["data"]:
                        app_name = domain_details.get("app_name", "").lower()
                        if app_name not in applications:
                            continue
                        applications[app_name]["domain_details"] = {
                            "id": domain_details.get("id", ""),
                            "discovery_domains": domain_details.get(
                                "discovery_domains", []
                            ),
                            "steering_domains": domain_details.get(
                                "steering_domains", []
                            ),
                        }

                application_ids = []

    def _fetch_app_tags(self, applications):
        """Fetch the tag details for each applications."""
        endpoint = "/services/cci/tags"
        max_applications = 100
        application_names = []
        last_element_counter = 0
        total_event_len = len(applications.keys())
        for application in applications.keys():
            application_names.append(application)
            last_element_counter += 1
            if (
                len(application_names) == max_applications
                or last_element_counter >= total_event_len
            ):
                app_names_req = ";".join(application_names)
                params = {"apps": app_names_req}
                response = self._api_call_helper(
                    endpoint=endpoint,
                    method="get",
                    params=params,
                    error_codes=["CRE_1028", "CRE_1029"],
                    message="Error occurred while fetching the tag details of the applications",
                )

                if response.get("data"):
                    for app_name, tag_details in response["data"].items():
                        tag_dict_with_sanctioned = {
                            "id": tag_details.get("id"),
                            "tags": [],
                        }
                        sanction_value = tag_details.get(
                            "sanctioned", ""
                        ).lower()
                        app_type = tag_details.get("app_type")
                        custom_tags = tag_details.get("tags", [])
                        if sanction_value == "no":
                            tag_dict_with_sanctioned["tags"].append(
                                "Unsanctioned"
                            )
                        elif sanction_value == "yes":
                            tag_dict_with_sanctioned["tags"].append(
                                "Sanctioned"
                            )

                        tag_dict_with_sanctioned["tags"].append(app_type)
                        tag_dict_with_sanctioned["tags"].extend(custom_tags)
                        applications[app_name.lower()]["tag_details"] = (
                            tag_dict_with_sanctioned["tags"]
                        )

                application_names = []

    def _fetch_applications(self) -> list[dict]:
        applications_dict = self._get_applications_dict(
            self.data if self.data_type == "events" else []
        )
        self._fetch_app_details(applications_dict)
        applications = self._create_applications(applications_dict)

        return applications

    def _fetch_users(self) -> list[dict]:
        alerts = self.data if self.data_type == "alerts" else []
        self.logger.info(
            f"{self.log_prefix}: Processing {len(alerts)} UBA alerts."
        )
        return [
            {
                "email": alert.get("userkey", None),
                "policyName": alert.get("policy_name", None),
            }
            for alert in alerts
            if alert.get("userkey", None) is not None
        ]

    def _update_users(self, records: list[dict]):
        """Update user scores."""
        tenant_name = self.tenant.parameters["tenantName"].replace(" ", "")
        url = f"{tenant_name}/api/v2/incidents/uba/getuci"
        token = resolve_secret(self.tenant.parameters["v2token"])
        headers = {
            "Netskope-API-Token": token,
            "Content-Type": "application/json",
        }
        out = []
        for i in range(0, len(records), 512):
            users = []
            for record in records[i : i + 512]:  # noqa: E203
                users.append(record["email"])
            payload = json.dumps(
                {"users": users, "fromTime": 0, "capPerUser": 1}
            )
            success, response = handle_exception(
                requests.post,
                error_code="CRE_1014",
                custom_message=f"Error occurred while fetching score for user(s): {','.join(users)}",
                plugin=PLUGIN,
                url=url,
                headers=add_installation_id(add_user_agent(headers)),
                data=payload,
                proxies=self.proxy,
            )
            if not success:
                raise response
            try:
                response = handle_status_code(
                    response,
                    error_code="CRE_1027",
                    custom_message=f"Error occurred while fetching score for user(s): {','.join(users)}",
                    plugin=PLUGIN,
                    notify=False,
                )
                for record in records[i : i + 512]:  # noqa
                    match = list(
                        filter(
                            lambda user: user["userId"] in record["email"],
                            response.get("usersUci", []),
                        )
                    )
                    if "confidences" in match[0] and match[0]["confidences"]:
                        record["ubaScore"] = match[0]["confidences"][-1][
                            "confidenceScore"
                        ]
                        record.pop("policyName")
                        out.append(record)
            except Exception:
                pass
        return out

    def _update_applications(self, records: list[dict]):
        """Update application scores."""
        applications = {}
        for app in records:
            applications[app["applicationName"].lower()] = app
        self._fetch_app_details(applications)
        self._fetch_app_domains(applications)
        self._fetch_app_tags(applications)
        apps = self._create_applications(applications)
        return apps
        # return self._create_applications(applications)

    def update_records(self, entity: str, records: List[dict]):
        """Fetch user scores."""
        helper = AlertsHelper()
        self.tenant = helper.get_tenant_crev2(self.name)
        if entity == "Users":
            return self._update_users(records)
        elif entity == "Applications":
            return self._update_applications(records)
        else:
            raise ValueError(f"Unsupported entity '{entity}'")

    def get_actions(self):
        """Get available actions."""
        return [
            ActionWithoutParams(label="Add user to group", value="add"),
            ActionWithoutParams(
                label="Remove user from group", value="remove"
            ),
            ActionWithoutParams(label="Update UCI score", value="impact"),
            ActionWithoutParams(
                label="Add host to Private App", value="private_app"
            ),
            ActionWithoutParams(
                label="Create or Update App Instance", value="app_instance"
            ),
            ActionWithoutParams(label="Tag application", value="tag_app"),
            ActionWithoutParams(label="No actions", value="generate"),
        ]

    def _get_all_groups(
        self, configuration: Dict, log_in_status_check=False
    ) -> List:
        """Get list of all the groups.

        Args:
            configuration (Dict): Configuration parameters.

        Returns:
            List: List of all the groups.
        """
        all_groups = []
        start_at = 1
        while True:
            headers = {
                "Netskope-API-Token": resolve_secret(
                    self.tenant.parameters.get("v2token")
                )
            }
            success, groups = handle_exception(
                requests.get,
                error_code="CRE_1015",
                custom_message="Error occurred while fetching groups",
                plugin=PLUGIN,
                url=f"{self.tenant.parameters.get('tenantName').replace(' ', '')}/api/v2/scim/Groups",
                headers=add_installation_id(add_user_agent(headers)),
                params={"count": PAGE_SIZE, "startIndex": start_at},
                proxies=self.proxy,
            )
            if not success:
                raise groups
            groups = handle_status_code(
                groups,
                error_code="CRE_1028",
                custom_message="Error occurred while fetching groups",
                plugin=PLUGIN,
                notify=False,
                log=log_in_status_check,
            )
            if not isinstance(groups, dict):
                groups = json.loads(groups)
            groups_in_page = groups.get("Resources", [])
            if not groups_in_page:
                break
            all_groups += groups_in_page
            start_at += PAGE_SIZE
        return all_groups

    def _get_all_users(self, configuration: Dict) -> List:
        """Get list of all the users.

        Args:
            configuration (Dict): Configuration parameters.

        Returns:
            List: List of all the users.
        """
        all_users = []
        start_at = 1
        while True:
            headers = {
                "Netskope-API-Token": resolve_secret(
                    self.tenant.parameters.get("v2token")
                )
            }
            success, users = handle_exception(
                requests.get,
                error_code="CRE_1016",
                custom_message="Error occurred while fetching users",
                plugin=PLUGIN,
                url=f"{self.tenant.parameters.get('tenantName').replace(' ', '')}/api/v2/scim/Users",
                headers=add_installation_id(add_user_agent(headers)),
                params={"count": PAGE_SIZE, "startIndex": start_at},
                proxies=self.proxy,
            )
            if not success:
                raise users
            users = handle_status_code(
                users,
                error_code="CRE_1029",
                custom_message="Error occurred while fetching users",
                plugin=PLUGIN,
                notify=False,
            )
            if not isinstance(users, dict):
                users = json.loads(users)
            users_in_page = users.get("Resources", [])
            if not users_in_page:
                break
            all_users += users_in_page
            start_at += PAGE_SIZE
        return all_users

    def _find_user_by_email(self, users: List, email: str) -> Optional[Dict]:
        """Find user from list by email.

        Args:
            users (List): List of user dictionaries.
            email (str): Email to find.

        Returns:
            Optional[Dict]: User dictionary if found, None otherwise.
        """
        for user in users:
            for e in user.get("emails", []):
                if e.get("value") == email:
                    return user
        return None

    def _find_group_by_name(self, groups: List, name: str) -> Optional[Dict]:
        """Find group from list by name.

        Args:
            groups (List): List of groups dictionaries.
            name (str): Name to find.

        Returns:
            Optional[Dict]: Group dictionary if found, None otherwise.
        """
        for group in groups:
            if group.get("displayName") == name:
                return group
        return None

    def _remove_from_group(
        self, configuration: Dict, user_id: str, group_id: str
    ):
        """Remove specified user from the specified group.

        Args:
            configuration (Dict): Configuration parameters.
            user_id (str): User ID of the user.
            group_id (str): Group ID of the group.

        Raises:
            NetskopeException: If the group does not exist on Netskope.
        """
        headers = {
            "Netskope-API-Token": resolve_secret(
                self.tenant.parameters.get("v2token")
            )
        }
        body = {
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
            "Operations": [
                {
                    "op": "remove",
                    "path": "members",
                    "value": [{"value": user_id}],
                }
            ],
        }
        success, response = handle_exception(
            requests.patch,
            error_code="CRE_1017",
            custom_message="Error occurred while removing user from group",
            plugin=PLUGIN,
            url=f"{self.tenant.parameters.get('tenantName').replace(' ', '')}/api/v2/scim/Groups/{group_id}",
            headers=add_installation_id(add_user_agent(headers)),
            json=body,
            proxies=self.proxy,
        )
        if not success:
            raise response
        if response.status_code == 404:
            raise NetskopeException(
                f"{self.log_prefix}: Group with id {group_id} does not exist."
            )
        response = handle_status_code(
            response,
            error_code="CRE_1030",
            custom_message="Error occurred while removing user from group",
            plugin=PLUGIN,
            notify=False,
        )

    def _add_to_group(self, configuration: Dict, user_id: str, group_id: str):
        """Add specified user to the specified group.

        Args:
            configuration (Dict): Configuration parameters.
            user_id (str): User ID of the user.
            group_id (str): Group ID of the group.

        Raises:
            NetskopeException: If the group does not exist on Netskope.
        """
        headers = {
            "Netskope-API-Token": resolve_secret(
                self.tenant.parameters.get("v2token")
            )
        }
        body = {
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
            "Operations": [
                {"op": "add", "path": "members", "value": [{"value": user_id}]}
            ],
        }
        success, response = handle_exception(
            requests.patch,
            error_code="CRE_1018",
            custom_message="Error occurred while adding user to group",
            plugin=PLUGIN,
            url=f"{self.tenant.parameters.get('tenantName').replace(' ', '')}/api/v2/scim/Groups/{group_id}",
            headers=add_installation_id(add_user_agent(headers)),
            json=body,
            proxies=self.proxy,
        )
        if not success:
            raise response
        if response.status_code == 404:
            raise NetskopeException(
                f"{self.log_prefix}: Group with id {group_id} does not exist."
            )
        response = handle_status_code(
            response,
            error_code="CRE_1031",
            custom_message="Error occurred while removing user from group",
            plugin=PLUGIN,
            notify=False,
        )

    def _update_impact_score(
        self,
        user: str,
        score: int,
        source: str = "",
        reason: str = "",
    ):
        data = {
            "user": user.strip(),
            "score": score,
            "timestamp": int(time.time()) * 1000,
            "source": source.strip(),
            "reason": reason.strip(),
        }
        self._api_call_helper(
            endpoint="/incidents/user/uciimpact",
            method="post",
            data=data,
            error_codes=["CRE_1028", "CRE_1029"],
            message="Error occurred while updating the impact score.",
        )

    def _create_group(self, configuration: Dict, name: str) -> Dict:
        """Create a new group with name.

        Args:
            configuration (Dict): Configuration parameters.
            name (str): Name of the group to create.

        Returns:
            Dict: Newly created group dictionary.
        """
        headers = {
            "Netskope-API-Token": resolve_secret(
                self.tenant.parameters.get("v2token")
            )
        }
        body = {
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
            "displayName": name,
            "meta": {"resourceType": "Group"},
            "externalId": None,
        }
        success, response = handle_exception(
            requests.post,
            error_code="CRE_1019",
            custom_message="Error occurred while creating group",
            plugin=PLUGIN,
            url=f"{self.tenant.parameters.get('tenantName').replace(' ', '')}/api/v2/scim/Groups",
            headers=add_installation_id(add_user_agent(headers)),
            json=body,
            proxies=self.proxy,
        )
        if not success:
            raise response
        if response.status_code == 409:
            raise NetskopeException(
                f"{self.log_prefix}: Group {name} already exists."
            )
        response = handle_status_code(
            response,
            error_code="CRE_1032",
            custom_message="Error occurred while creating group",
            plugin=PLUGIN,
            notify=False,
        )
        if not isinstance(response, dict):
            response = json.loads(response)
        return response

    def get_types_to_pull(self, data_type):
        """Get the types of data to pull.

        Returns:
            List of sub types to pull
        """
        sub_types = []
        if data_type == "alerts":
            sub_types.extend(["uba"])
        elif data_type == "events":
            sub_types.extend(["application"])
        return sub_types

    def get_target_fields(self, plugin_id, plugin_parameters):
        """Get available Target fields."""
        return []

    def validate(self, configuration: Dict):
        """Validate Netskope configuration."""
        initial_range = configuration.get("initial_range")
        if initial_range is None:
            err_msg = "Initial Range for Events is a required configuration parameter."
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        elif not isinstance(initial_range, int):
            err_msg = "Invalid Initial Range for Events provided in configuration parameter."
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        elif initial_range < 0 or initial_range > 8760:
            err_msg = (
                "Invalid Initial Range for Events provided in configuration"
                " parameters. Valid value should be in range 0 to 8760."
            )
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        days = configuration.get("days")
        if days is None:
            err_msg = "Initial Range for Alerts is a required configuration parameter."
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        elif not isinstance(days, int):
            err_msg = "Invalid Initial Range for Alerts provided in configuration parameter."
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        elif days < 0 or days > 365:
            err_msg = (
                "Invalid Initial Range for Alerts provided in configuration"
                " parameters. Valid value should be in range 0 to 365."
            )
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        helper = AlertsHelper()
        self.tenant = helper.get_tenant(configuration["tenant"])
        token = resolve_secret(self.tenant.parameters["v2token"])
        try:
            if token is None:
                return ValidationResult(
                    success=False,
                    message="V2 token is required in the tenant configuration to configure Netskope CRE plugin."
                    " It can be configured from Settings > Tenants.",
                )
            provider = plugin_provider_helper.get_provider(
                tenant_name=self.tenant.name
            )
            type_map = {
                "events": ["application"],
                "alerts": ["uba"],
            }
            provider.permission_check(type_map, plugin_name=self.plugin_name, configuration_name=self.name)
            return ValidationResult(
                success=True, message="Validation successful."
            )
        except ConnectionError:
            return ValidationResult(
                success=False,
                message="Could not connect validate the credentials.",
            )

    def _validate_port(self, port):
        """Validate the port."""
        try:
            port = int(port)
        except ValueError:
            return False
        if not 0 <= port <= 65535:
            return False
        return True

    def validate_action(self, action: Action):
        """Validate Netskope configuration."""

        helper = AlertsHelper()
        self.tenant = helper.get_tenant_crev2(self.name)
        if action.value == "generate":
            return ValidationResult(
                success=True, message="Validation successful."
            )
        elif action.value == "impact":
            try:
                self._process_params_for_impact_action(action.parameters)
            except NetskopeException as ex:
                return ValidationResult(success=False, message=str(ex))
            return ValidationResult(
                success=True, message="Validation successful."
            )
        elif action.value == "tag_app":
            try:
                self._process_params_for_add_tag_action(action.parameters)
            except NetskopeException as ex:
                return ValidationResult(success=False, message=str(ex))
            return ValidationResult(
                success=True, message="Validation successful."
            )
        elif action.value == "app_instance":
            try:
                self._process_params_for_app_instance_action(action.parameters)
            except NetskopeException as ex:
                return ValidationResult(success=False, message=str(ex))
            return ValidationResult(
                success=True, message="Validation successful."
            )
        elif action.value == "private_app":
            self.session = requests.Session()
            self.session.headers.update(
                add_installation_id(
                    add_user_agent(
                        {
                            "Netskope-API-Token": resolve_secret(
                                self.tenant.parameters["v2token"]
                            ),
                        }
                    )
                )
            )
            try:
                existing_private_apps = self._get_private_apps()
                existing_publishers = self._get_publishers()
            except Exception as e:
                self.logger.info(
                    f"{self.log_prefix}: "
                    f"Exception occurred while validating action parameters.",
                    details=traceback.format_exc(),
                    error_code="CRE_1042",
                )
                return ValidationResult(success=False, message=str(e))

            list_of_private_apps_list = list(existing_private_apps.keys())
            list_of_private_apps_list.append("create")
            if (
                action.parameters.get("private_app_name")
                not in list_of_private_apps_list
            ):
                return ValidationResult(
                    success=False, message="Invalid private app provided."
                )
            if (
                action.parameters.get("private_app_name") == "create"
            ):
                if (action.parameters.get("name") or "").strip() == "":
                    return ValidationResult(
                        success=False,
                        message="If you have selected 'Create new private app' in Private App Name,"
                        " New Private App Name should not be empty.",
                    )

                if "$" in (action.parameters.get("name") or "").strip():
                    return ValidationResult(
                        success=False,
                        message=(
                            "'Create New Private App' contains Source field value. "
                            "Please provide new private app name in Static field only."
                        ),
                    )

            protocols = action.parameters.get("protocol", [])
            if action.parameters.get("private_app_name") == "create" and not protocols:
                return ValidationResult(
                    success=False,
                    message="Protocol is a required field to create a new private app.",
                )
            if not all(protocol in ["TCP", "UDP"] for protocol in protocols):
                return ValidationResult(
                    success=False,
                    message="Invalid Protocol provided. Valid values are TCP or UDP.",
                )
            tcp_port = action.parameters.get("tcp_ports") or ""
            tcp_port_list = [
                port.strip() for port in tcp_port.split(",") if port.strip()
            ]
            udp_port = action.parameters.get("udp_ports") or ""
            udp_port_list = [
                port.strip() for port in udp_port.split(",") if port.strip()
            ]

            if "TCP" in protocols:
                if not tcp_port_list:
                    return ValidationResult(
                        success=False,
                        message="If you have selected 'TCP' in Protocols, TCP Port should not be empty.",
                    )
                if not all(
                    self._validate_port(port) for port in tcp_port_list
                ):
                    return ValidationResult(
                        success=False,
                        message="Invalid TCP Port provided. Valid values are between 0 and 65535.",
                    )
            if "UDP" in protocols:
                if not udp_port_list:
                    return ValidationResult(
                        success=False,
                        message="If you have selected 'UDP' in Protocols, UDP Port should not be empty.",
                    )
                if not all(
                    self._validate_port(port) for port in udp_port_list
                ):
                    return ValidationResult(
                        success=False,
                        message="Invalid UDP Port provided. Valid values are between 0 and 65535.",
                    )

            publishers = action.parameters.get("publishers", [])
            if publishers and not all(
                publisher in existing_publishers for publisher in publishers
            ):
                return ValidationResult(
                    success=False, message="Invalid publisher provided."
                )

            use_publisher_dns = action.parameters.get(
                "use_publisher_dns", False
            )
            if use_publisher_dns is None or use_publisher_dns not in [
                True,
                False,
            ]:
                return ValidationResult(
                    success=False,
                    message="Invalid Use Publisher DNS provided.",
                )

            default_url = action.parameters.get("default_url", "")
            if action.parameters.get("private_app_name") == "create":
                if not default_url:
                    return ValidationResult(
                        success=False,
                        message="If you have selected 'Create new private app' in Private App Name,"
                        " Default Host should not be empty.",
                    )
                if "$" in default_url:
                    return ValidationResult(
                        success=False,
                        message=(
                            "'Default Host' contains Source field value. "
                            "Please provide default host in Static field only."
                        ),
                    )
                if not re.compile(REGEX_HOST).match(default_url.strip()):
                    return ValidationResult(
                        success=False,
                        message="Invalid Default Host provided.",
                    )
            return ValidationResult(
                success=True, message="Validation successful."
            )
        elif action.value in ["add", "remove"]:
            groups = self._get_all_groups(
                self.configuration, log_in_status_check=True
            )
            if action.parameters.get("group") != "create" and len(groups) <= 0:
                return ValidationResult(
                    success=False, message="No groups available."
                )
            if action.parameters.get("group") != "create" and not any(
                map(
                    lambda g: g["id"] == action.parameters.get("group"), groups
                )
            ):
                return ValidationResult(
                    success=False, message="Invalid group ID provided."
                )
            if (
                action.value == "add"
                and action.parameters.get("group") == "create"
                and len(action.parameters.get("name", "").strip()) == 0
            ):
                return ValidationResult(
                    success=False, message="Group Name can not be empty."
                )
            return ValidationResult(
                success=True, message="Validation successful."
            )
        return ValidationResult(
            success=False, message="Invalid action provided."
        )

    def _get_publishers(self) -> Dict:
        """Retrieve a dictionary of publishers.

        :return: A dictionary containing publisher names as keys and publisher IDs as values.
        :rtype: dict
        """
        dict_publishers = {}
        tenant_name = self.tenant.parameters["tenantName"].strip()
        success, publishers_resp = handle_exception(
            self.session.get,
            error_code="CRE_1047",
            custom_message="Error occurred while fetching publishers",
            plugin=self.log_prefix,
            url=URLS["V2_PUBLISHER"].format(tenant_name),
            params={
                "fields": "publisher_id,publisher_name"
            },  # we need only 2 fields
        )
        if not success:
            raise publishers_resp
        publishers_json = handle_status_code(
            publishers_resp,
            error_code="CRE_1048",
            custom_message="Error occurred while fetching publishers",
            plugin=self.log_prefix,
            notify=False,
        )

        existing_publishers = publishers_json.get("data", {}).get(
            "publishers", []
        )
        # Private app from netskope.
        for x in existing_publishers:
            dict_publishers[x["publisher_name"]] = x["publisher_id"]
        return dict_publishers

    def _get_private_apps(
        self, get_hosts_of: Optional[str] = None
    ) -> Union[dict, tuple]:
        """Check private app present in Netskope and create a new one if not found."""
        dict_of_private_apps = {}
        tenant_name = self.tenant.parameters["tenantName"].strip()
        success, private_app_netskope = handle_exception(
            self.session.get,
            error_code="CRE_1040",
            custom_message="Error occurred while checking private apps",
            plugin=self.log_prefix,
            url=URLS["V2_PRIVATE_APP"].format(tenant_name),
            params={"fields": "app_id,app_name,host"},  # we need only 3 fields
        )
        if not success:
            raise private_app_netskope
        private_app_netskope_json = handle_status_code(
            private_app_netskope,
            error_code="CRE_1041",
            custom_message="Error occurred while checking private apps",
            plugin=self.log_prefix,
            notify=False,
        )

        existing_private_apps = private_app_netskope_json.get("data", {}).get(
            "private_apps", []
        )
        # Private app from netskope.
        for x in existing_private_apps:
            dict_of_private_apps[x["app_name"]] = {
                "id": x["app_id"],
                "host_count": len(x["host"].split(",")),
            } | (
                {"hosts": x["host"].split(",")}
                if get_hosts_of
                and x["app_name"].startswith(get_hosts_of.removesuffix("]"))
                else {}
            )
        return dict_of_private_apps

    def _get_private_app(
        self,
        prefix: str,
        has_host: Optional[str] = None,
    ) -> Union[dict, tuple]:
        """Check private app present in Netskope and create a new one if not found."""
        dict_of_private_apps = {}
        tenant_name = self.tenant.parameters["tenantName"].strip()
        success, private_app_netskope = handle_exception(
            self.session.get,
            error_code="CRE_1040",
            custom_message="Error occurred while checking private apps",
            plugin=self.log_prefix,
            url=URLS["V2_PRIVATE_APP"].format(tenant_name),
            params={"fields": "app_id,app_name,host"},  # we need only 3 fields
        )
        if not success:
            raise private_app_netskope
        private_app_netskope_json = handle_status_code(
            private_app_netskope,
            error_code="CRE_1041",
            custom_message="Error occurred while checking private apps",
            plugin=self.log_prefix,
            notify=False,
        )

        existing_private_apps = private_app_netskope_json.get("data", {}).get(
            "private_apps", []
        )
        # Private app from netskope.
        for app in existing_private_apps:
            split_hosts = app["host"].split(",")
            if not app["app_name"].startswith(prefix.removesuffix("]")):
                continue
            if has_host not in split_hosts:
                continue
            return app
        return None

    def get_action_params(self, action: Action) -> list:
        """Get fields required for an action."""
        helper = AlertsHelper()
        self.tenant = helper.get_tenant_crev2(self.name)
        if action.value == "generate":
            return []
        if action.value in ["add", "remove"]:
            groups = self._get_all_groups(self.configuration)
            groups = sorted(
                groups, key=lambda g: g.get("displayName", "").lower()
            )
            if action.value == "add":
                return [
                    {
                        "label": "User Email",
                        "key": "user",
                        "type": "text",
                        "default": "",
                        "mandatory": True,
                        "description": (
                            "Email address of the user to add to group. "
                            "It must exist in SCIM."
                        ),
                    },
                    {
                        "label": "Group",
                        "key": "group",
                        "type": "choice",
                        "choices": [
                            {"key": g["displayName"], "value": g["id"]}
                            for g in groups
                        ]
                        + [{"key": "Create new group", "value": "create"}],
                        "default": (
                            groups[0]["id"] if len(groups) > 0 else "create"
                        ),
                        "mandatory": True,
                        "description": "Select a group to add the user to.",
                    },
                    {
                        "label": "Group Name",
                        "key": "name",
                        "type": "text",
                        "default": "",
                        "mandatory": False,
                        "description": "Name of the SCIM group to create if it does not exist.",
                    },
                ]
            elif action.value == "remove":
                return [
                    {
                        "label": "User Email",
                        "key": "user",
                        "type": "text",
                        "default": "",
                        "mandatory": True,
                        "description": (
                            "Email address of the user to remove from group. "
                            "It must exist in SCIM."
                        ),
                    },
                    {
                        "label": "Group",
                        "key": "group",
                        "type": "choice",
                        "choices": [
                            {"key": g["displayName"], "value": g["id"]}
                            for g in groups
                        ]
                        + [{"key": "No groups available", "value": "group"}],
                        "default": (
                            groups[0]["id"] if len(groups) > 0 else "group"
                        ),
                        "mandatory": True,
                        "description": "Select a group to remove the user from.",
                    },
                ]
        elif action.value == "impact":
            return [
                {
                    "label": "User Email",
                    "key": "user",
                    "type": "text",
                    "default": "",
                    "mandatory": True,
                    "description": "Email of the user to send the impact request for.",
                },
                {
                    "label": "Score (Reduction)",
                    "key": "score",
                    "type": "number",
                    "default": "",
                    "mandatory": True,
                    "description": "Score to be reduced from UCI.",
                },
                {
                    "label": "Source",
                    "key": "source",
                    "type": "text",
                    "default": "",
                    "mandatory": False,
                    "description": "Name of the source reporting this.",
                },
                {
                    "label": "Reason",
                    "key": "reason",
                    "type": "text",
                    "default": "",
                    "mandatory": True,
                    "description": "Reason for this score change.",
                },
            ]
        elif action.value == "private_app":
            self.session = requests.Session()
            self.session.headers.update(
                add_installation_id(
                    add_user_agent(
                        {
                            "Netskope-API-Token": resolve_secret(
                                self.tenant.parameters["v2token"]
                            ),
                        }
                    )
                )
            )
            existing_private_apps = self._get_private_apps()
            existing_publishers = self._get_publishers()
            return [
                {
                    "label": "Host",
                    "key": "host",
                    "type": "text",
                    "default": "",
                    "placeholder": "i.e. 127.0.0.1",
                    "mandatory": True,
                    "description": (
                        "Host address to append to the private app. "
                        "Multiple comma-separated values are supported. "
                        "Example: host-1, host-2"
                    ),
                },
                {
                    "label": "Tags",
                    "key": "tags",
                    "type": "text",
                    "default": "",
                    "placeholder": "i.e. tag-1, tag-2",
                    "mandatory": False,
                    "description": (
                        "Tags to set for the private app. These tags will overwrite existing "
                        "tags available on your tenant. "
                        "Multiple comma-separated values are supported. "
                        "Example: tag-1, tag-2"
                    ),
                },
                {
                    "label": "Private App Name",
                    "key": "private_app_name",
                    "type": "choice",
                    "choices": [
                        {"key": key, "value": key}
                        for key in sorted(existing_private_apps.keys())
                    ]
                    + [{"key": "Create new private app", "value": "create"}],
                    "default": "",
                    "mandatory": True,
                    "description": "Select a private app from Static field dropdown.",
                },
                {
                    "label": "Create New Private App",
                    "key": "name",
                    "type": "text",
                    "default": "",
                    "mandatory": False,
                    "description": "Create private app with given name. \
Provide private app name in Static field if you have selected 'Create new private app' in Private App Name.",
                },
                {
                    "label": "Protocol",
                    "key": "protocol",
                    "type": "multichoice",
                    "choices": [
                        {"key": "UDP", "value": "UDP"},
                        {"key": "TCP", "value": "TCP"},
                    ],
                    "default": ["TCP", "UDP"],
                    "mandatory": False,
                    "description": "Select Protocol from Static field dropdown. Valid values are TCP and UDP.",
                },
                {
                    "label": "TCP Ports",
                    "key": "tcp_ports",
                    "type": "text",
                    "default": "",
                    "mandatory": False,
                    "description": "Comma-separated ports for the TCP protocol. \
Only enter in Static field if you have selected 'TCP' in Protocol.",
                },
                {
                    "label": "UDP Ports",
                    "key": "udp_ports",
                    "type": "text",
                    "default": "",
                    "mandatory": False,
                    "description": "Comma-separated ports for the UDP protocol. \
Only enter in Static field if you have selected 'UDP' in Protocol.",
                },
                {
                    "label": "Publisher",
                    "key": "publishers",
                    "type": "multichoice",
                    "choices": [
                        {"key": key, "value": key}
                        for key in sorted(existing_publishers.keys())
                    ],
                    "default": (
                        []
                        if not existing_publishers.keys()
                        else [list(existing_publishers.keys())[0]]
                    ),
                    "mandatory": False,
                    "description": "Select Publishers from Static field dropdown only.",
                },
                {
                    "label": "Use Publisher DNS",
                    "key": "use_publisher_dns",
                    "type": "choice",
                    "choices": [
                        {"key": "No", "value": False},
                        {"key": "Yes", "value": True},
                    ],
                    "default": False,
                    "mandatory": True,
                    "description": "Select Yes or No from Static field dropdown for Use Publishers DNS.",
                },
                {
                    "label": "Default Host",
                    "key": "default_url",
                    "type": "text",
                    "default": "cedefaultpush.io",
                    "mandatory": False,
                    "description": "The default Host to be used when new private app is created. \
Provide Default Host in Static field if you have selected 'Create new private app' in Private App Name.",
                },
            ]
        elif action.value == "tag_app":
            return [
                {
                    "label": "Tags",
                    "key": "tags",
                    "type": "text",
                    "default": "",
                    "placeholder": "i.e. tag-1, tag-2",
                    "mandatory": True,
                    "description": "Comma separated tag values.",
                },
                {
                    "label": "Application Names",
                    "key": "apps",
                    "type": "text",
                    "default": "",
                    "placeholder": "i.e. Dropbox, Google Drive",
                    "mandatory": False,
                    "description": "Comma separated application names. 100 is the max allowed input size.",
                },
                {
                    "label": "Application Ids",
                    "key": "ids",
                    "type": "text",
                    "default": "",
                    "placeholder": "i.e. 3324, 1233",
                    "mandatory": False,
                    "description": "Comma separated application ids. 100 is the max allowed input size.",
                },
            ]
        elif action.value == "app_instance":
            return [
                {
                    "label": "Instance ID",
                    "key": "instance_id",
                    "type": "text",
                    "default": "",
                    "mandatory": True,
                    "placeholder": "i.e. 123451234512",
                    "description": (
                        "For AWS, use the account ID. For Azure, use the "
                        "Subscription. For GCP, use the Project. The "
                        "`app + instance_id` combo must be new."
                    ),
                },
                {
                    "label": "Instance Name",
                    "key": "instance_name",
                    "type": "text",
                    "default": "",
                    "placeholder": "i.e. MYAWS_GOSKOPE",
                    "mandatory": True,
                    "description": (
                        "Used to change instance name, and must be unique. "
                        "Name should be unique within `app + instance_id` or "
                        "`app + instance_name`."
                    ),
                },
                {
                    "label": "Application Name",
                    "key": "app_name",
                    "type": "text",
                    "default": "",
                    "placeholder": "i.e. Dropbox",
                    "mandatory": True,
                    "description": "Name of the application.",
                },
                {
                    "label": "Tag",
                    "key": "tag",
                    "type": "choice",
                    "choices": [
                        {"key": "None", "value": "None"},
                        {"key": "Sanctioned", "value": "Sanctioned"},
                        {"key": "Unsanctioned", "value": "Unsanctioned"},
                    ],
                    "default": "None",
                    "mandatory": False,
                    "description": "Tags to add.",
                },
            ]
        return []

    def _push_private_app(
        self,
        host: str,
        existing_private_app_name: str,
        new_private_app_name: str,
        protocol_type: list[str],
        tcp_ports: list[str],
        udp_ports: list[str],
        publishers: list[str],
        use_publisher_dns: bool,
        default_url: str,
        tags: list[str] = [],
    ):
        """Push a private app to Netskope with the provided indicators, app names, protocols, and publishers.

        Args:
            indicators (List[Indicator]): The list of indicators to be pushed.
            existing_private_app_name (str): The name of an existing private app.
            new_private_app_name (str): The name of a new private app.
            protocol_type (List[str]): The list of protocol types.
            tcp_ports (List[int]): The list of TCP ports.
            udp_ports (List[int]): The list of UDP ports.
            publishers (List[str]): The list of publishers.
            use_publisher_dns (bool): A boolean indicating whether to use the publisher DNS.
            enable_tagging (bool): A boolean indicating whether to enable tagging.
            default_url (str): The default host.
        """
        tenant_name = self.tenant.parameters["tenantName"].strip()

        try:
            if existing_private_app_name == "create":
                private_app_name = f"[{new_private_app_name}]"
            else:
                private_app_name = existing_private_app_name
            existing_private_apps = self._get_private_apps(
                get_hosts_of=private_app_name
            )
            final_name = private_app_name
            counter = 2
            while True:
                if final_name not in existing_private_apps:
                    existing_private_app_name = final_name.removeprefix(
                        "["
                    ).removesuffix("]")
                    break
                if (
                    existing_private_apps[final_name]["host_count"]
                    < MAX_HOSTS_PER_PRIVATE_APP
                ):
                    break
                final_name = f"[{private_app_name.removeprefix('[').removesuffix(']')} {counter}]"
                counter += 1
            private_app_name = final_name
            existing_publishers = self._get_publishers()
            protocols_list = []
            for protocol in protocol_type:
                if protocol == "TCP":
                    protocols_list.append(
                        {"type": "tcp", "ports": ",".join(tcp_ports)}
                    )
                if protocol == "UDP":
                    protocols_list.append(
                        {"type": "udp", "ports": ",".join(udp_ports)}
                    )

            publishers_list = []
            skipped_publishers = []
            for publisher in publishers:
                if publisher in existing_publishers:
                    publishers_list.append(
                        {
                            "publisher_id": existing_publishers[publisher],
                            "publisher_name": publisher,
                        }
                    )
                else:
                    skipped_publishers.append(publisher)

            if not publishers_list and skipped_publishers:
                self.logger.error(
                    f"{self.log_prefix}: Unable to find the provided publishers [{','.join(skipped_publishers)}]."
                )
                raise NetskopeException(
                    f"{self.log_prefix}: Could not create new private app to share host."
                )

            if skipped_publishers:
                self.logger.error(
                    f"{self.log_prefix}: Unable to find the following publishers [{','.join(skipped_publishers)}]."
                    f" Hence ignoring them while creating the private app '{private_app_name}'."
                )
            # Check if the private app already exists
            if private_app_name not in existing_private_apps:
                # Creating URL List
                self.logger.debug(
                    f"{self.log_prefix}: Private app '{private_app_name}' does not exist. Creating a new private app."
                )

                if existing_private_app_name == "create":
                    app_name_to_create = new_private_app_name
                else:
                    app_name_to_create = existing_private_app_name

                data = {
                    "app_name": app_name_to_create,
                    "host": default_url,
                    "publishers": publishers_list,
                    "use_publisher_dns": use_publisher_dns,
                }
                if protocols_list:
                    data["protocols"] = protocols_list
                success, create_private_app = handle_exception(
                    self.session.post,
                    error_code="CRE_1043",
                    custom_message="Error occurred while creating private app in Netskope",
                    plugin=self.log_prefix,
                    url=URLS["V2_PRIVATE_APP"].format(tenant_name),
                    json=data,
                )
                if not success or create_private_app.status_code not in [
                    200,
                    201,
                ]:
                    self.logger.error(
                        f"{self.log_prefix}: Error occurred while creating private app.",
                        details=(
                            repr(create_private_app)
                            if not success
                            else create_private_app.text
                        ),
                    )
                    raise NetskopeException(
                        f"{self.log_prefix}: Could not create new private app to share host.",
                    )

                create_private_app_json = handle_status_code(
                    create_private_app,
                    error_code="CRE_1044",
                    custom_message="Error occurred while creating private app in Netskope",
                    plugin=self.log_prefix,
                    notify=False,
                )

                if create_private_app_json.get("status", "") != "success":
                    self.logger.error(
                        f"{self.log_prefix}: Error occurred while creating private app. "
                        f"Received exit code {create_private_app.status_code}.",
                        details=repr(create_private_app_json),
                    )
                    raise NetskopeException(
                        f"{self.log_prefix}: Could not create new private app to share the host."
                    )

                existing_private_apps[
                    create_private_app_json["data"]["app_name"]
                ] = {
                    "id": create_private_app_json["data"]["app_id"],
                    "host_count": 0,
                    "hosts": [],
                }

            if host and isinstance(host, str):
                host = list(map(lambda x: x.strip(), host.split(",")))
            data = {
                "host": ",".join(
                    list(
                        set(
                            existing_private_apps[private_app_name]["hosts"]
                        ).union(host)
                    )
                ),
                "tags": list(map(lambda t: {"tag_name": t}, tags)) if tags else [],
                "publishers": publishers_list,
                "use_publisher_dns": use_publisher_dns,
            }
            if protocols_list:
                data["protocols"] = protocols_list
            return self._patch_private_app(
                tenant_name,
                existing_private_apps[private_app_name]["id"],
                data,
            )
        except Exception as e:
            self.logger.error(
                f"{self.log_prefix}: "
                f"Exception occurred while pushing data to Netskope.",
                details=re.sub(
                    r"token=([0-9a-zA-Z]*)",
                    "token=********&",
                    traceback.format_exc(),
                ),
                error_code="CRE_1021",
            )
            raise NetskopeException(f"{self.log_prefix}: {str(e)}")

    def _tag_application(
        self, tags: list[str], apps: list[str], ids: list[int]
    ):
        tenant_name = self.tenant.parameters["tenantName"].strip()
        for tag in tags:
            data = (
                {"tag": tag}
                | ({"apps": apps} if apps else {})
                | ({"ids": ids} if ids else {})
            )
            add_tags_success, add_tags = handle_exception(
                self.session.post,
                error_code="CRE_1043",
                custom_message="Error occurred while creating the tag.",
                plugin=self.log_prefix,
                url=URLS["V2_CCI_TAG_CREATE"].format(tenant_name),
                json=data,
            )
            if not add_tags_success:
                raise NetskopeException(
                    f"{self.log_prefix}: Error occurred while tagging the application on Netskope."
                ) from add_tags
            add_tags_response = handle_status_code(
                add_tags,
                error_code="CRE1046",
                custom_message="Error occurred while creating a tag on Netskope.",
                plugin=self.log_prefix,
                notify=False,
            )
            if add_tags_response.get("message") == ERROR_APP_DOES_NOT_EXIST:
                raise NetskopeException(
                    f"{self.log_prefix}: Error occurred while tagging the application on Netskope. "
                    f"Invalid app provided."
                )
            elif add_tags_response.get("status_code") == 400:
                # either the tag is one of the pre-defined ones or
                # the tag already exists;
                # try updating the existing record
                update_tags_success, update_tags = handle_exception(
                    self.session.patch,
                    error_code="CRE_1043",
                    custom_message=f"Error occurred while creating the {tag} tag.",
                    plugin=self.log_prefix,
                    url=URLS["V2_CCI_TAG_UPDATE"].format(tenant_name, tag),
                    json=data,
                )
                if not update_tags_success:
                    raise NetskopeException(
                        f"{self.log_prefix}: Error occurred while tagging the application on Netskope."
                    ) from update_tags
                update_tags_response = handle_status_code(
                    update_tags,
                    error_code="CRE1047",
                    custom_message=f"Error occurred while updating the {tag} tag on Netskope.",
                    plugin=self.log_prefix,
                    notify=False,
                )

                if update_tags_response.get("message_status") != SUCCESS:
                    self.logger.error(
                        f"{self.log_prefix}: Error occurred while tagging the application on Netskope. "
                        f"Received exit code {update_tags.status_code}.",
                        details=json.dumps(update_tags_response),
                    )

            elif add_tags_response.get("status") != SUCCESS:
                self.logger.error(
                    f"{self.log_prefix}: Error occurred while tagging the application on Netskope. "
                    f"Received exit code {add_tags.status_code}.",
                    details=json.dumps(add_tags_response),
                )
                raise NetskopeException(
                    f"{self.log_prefix}: Error occurred while tagging the application on Netskope."
                )

    def _create_app_instance(
        self, instance_id: str, instance_name: str, app: str, tags: list[str]
    ):
        """Create an app instance.

        Args:
            instance_id (str): Instance ID.
            instance_name (str): Instance name.
            app (str): App name.
            tags (str): Tag.
        """
        tenant_name = self.tenant.parameters["tenantName"].strip()
        list_instances_success, list_instances = handle_exception(
            self.session.get,
            error_code="CRE_1045",
            custom_message="Error occurred while listing app instances.",
            plugin=self.log_prefix,
            url=URLS["V1_APP_INSTANCE"].format(tenant_name),
            params={
                "op": "list",
                "app": app,
                "instance_id": instance_id,
                "instance_name": instance_name,
            },
        )
        if not list_instances_success:
            raise NetskopeException(
                f"{self.log_prefix}: Error occurred while listing "
                f"app instances on Netskope."
            ) from list_instances
        list_instances_response = handle_status_code(
            list_instances,
            error_code="CRE1049",
            custom_message=(
                "Error occurred while listing app instances from Netskope."
            ),
            plugin=self.log_prefix,
            notify=False,
        )
        if list_instances_response.get("status").lower() != SUCCESS.lower():
            self.logger.error(
                f"{self.log_prefix}: Error occurred while listing "
                f"app instances from Netskope. "
                f"Received exit code {list_instances.status_code}.",
                details=json.dumps(list_instances_response),
            )
            raise NetskopeException(
                f"{self.log_prefix}: Error occurred while listing "
                f"app instances from Netskope."
            )
        if len(list_instances_response.get("data")):
            op = "update"
        else:
            op = "add"
        create_instance_success, create_instance = handle_exception(
            self.session.post,
            error_code="CRE_1044",
            custom_message=(
                f"Error occurred while "
                f"{'updating' if op == 'update' else 'adding'} app instance."
            ),
            plugin=self.log_prefix,
            url=URLS["V1_APP_INSTANCE"].format(tenant_name),
            params={"op": op},
            json={
                "instances": [
                    {
                        "instance_id": instance_id,
                        "instance_name": instance_name,
                        "app": app,
                        "tags": tags,
                    }
                ]
            },
        )
        if not create_instance_success:
            raise NetskopeException(
                f"{self.log_prefix}: Error occurred while "
                f"{'updating' if op == 'update' else 'adding'} app instance "
                "on Netskope."
            ) from create_instance
        create_instance_response = handle_status_code(
            create_instance,
            error_code="CRE1048",
            custom_message=(
                f"Error occurred while "
                f"{'updating' if op == 'update' else 'adding'} app instance "
                f"on Netskope."
            ),
            plugin=self.log_prefix,
            notify=False,
        )
        if create_instance_response.get("status").lower() != SUCCESS.lower():
            self.logger.error(
                f"{self.log_prefix}: Error occurred while "
                f"{'updating' if op == 'update' else 'adding'} app instance "
                f"on Netskope. "
                f"Received exit code {create_instance.status_code}.",
                details=json.dumps(create_instance_response),
            )
            raise NetskopeException(
                f"{self.log_prefix}: Error occurred while "
                f"{'updating' if op == 'update' else 'adding'} app instance "
                f"on Netskope."
            )

    def _process_params_for_app_instance_action(
        self, params: dict
    ) -> tuple[str, str, str, list[str]]:
        """Procss parameters.

        Args:
            params (dict): Params dictionary.

        Returns:
            tuple[str, str, str, list[str]]: Processed params.
        """
        tag = str(params.get("tag") or "")
        skip_tag_validation = isinstance(tag, str) and tag.startswith("$")
        instance_id = str(params.get("instance_id") or "")
        skip_instance_id_validation = isinstance(
            instance_id, str
        ) and instance_id.startswith("$")
        instance_name = str(params.get("instance_name") or "")
        skip_instance_name_validation = isinstance(
            instance_name, str
        ) and instance_name.startswith("$")
        app_name = str(params.get("app_name") or "")
        skip_app_name_validation = isinstance(
            app_name, str
        ) and app_name.startswith("$")

        if not skip_tag_validation and (
            tag.strip() not in ["Unsanctioned", "Sanctioned", "None", ""]
        ):
            raise NetskopeException(
                "Invalid value for Tag provided. It must be empty or one of "
                "the following: None, Sanctioned, Unsanctioned."
            )

        if not skip_app_name_validation and not app_name.strip():
            raise NetskopeException(
                "Empty value for Application Name provided."
            )

        if not skip_instance_name_validation and not instance_name.strip():
            raise NetskopeException("Empty value for Instance Name provided.")

        if not skip_instance_id_validation and not instance_id.strip():
            raise NetskopeException("Empty value for Instance ID provided.")

        if tag.strip() in ["Sanctioned", "Unsanctioned"]:
            tags = [tag.strip()]
        else:
            tags = []

        instance_id = instance_id.strip()
        instance_name = instance_name.strip()
        app_name = app_name.strip()

        return (
            instance_id,
            instance_name,
            app_name,
            tags,
        )

    def _process_params_for_impact_action(
        self, params: dict
    ) -> tuple[str, str, str, str]:
        """Procss parameters.

        Args:
            params (dict): Params dictionary.

        Returns:
            tuple[str, str, str, str]: Processed params.
        """
        user = str(params.get("user") or "")
        score = params.get("score")
        source = str(params.get("source") or "")
        reason = str(params.get("reason") or "")

        skip_user_validation = isinstance(user, str) and user.startswith("$")
        skip_score_validation = isinstance(score, str) and score.startswith(
            "$"
        )
        skip_source_validation = isinstance(source, str) and source.startswith(
            "$"
        )
        skip_reason_validation = isinstance(reason, str) and reason.startswith(
            "$"
        )

        if not skip_user_validation:
            user = user.strip()
            if not re.match(REGEX_EMAIL, user):
                raise NetskopeException(
                    "Invalid value for User Email provided. It must be a valid email address."
                )

        if not skip_score_validation:
            try:
                score = int(score)
            except Exception:
                raise NetskopeException(
                    "Invalid value for Score (Reduction) provided. It must be an integer."
                )
            if not 1 <= score <= 1000:
                raise NetskopeException(
                    "Invalid value for Score (Reduction) provided. It must be between 1 and 1000."
                )

        if not skip_source_validation:
            source = source.strip()
            if not source:
                raise NetskopeException(
                    "Invalid value for Source provided. It must not be empty."
                )

        if not skip_reason_validation:
            reason = reason.strip()
            if not reason:
                raise NetskopeException(
                    "Invalid value for Reason provided. It must not be empty."
                )

        return (
            user,
            score,
            source,
            reason,
        )

    def _process_params_for_add_tag_action(self, params: dict) -> tuple:

        def convert_to_list(value: Union[str, list[str]]) -> list[str]:
            """Convert to list.

            :param value: Value to be converted.
            :type value: Union[str, list[str]]
            :return: Convrted list.
            :rtype: list[str]
            """
            if isinstance(value, list):
                return value
            if isinstance(value, str):
                return list(
                    filter(
                        lambda x: len(x) != 0,
                        map(lambda x: x.strip(), value.split(",")),
                    )
                )
            return []

        tags = params.get("tags") or ""
        skip_tag_validation = isinstance(tags, str) and tags.startswith("$")
        tags = convert_to_list(tags)
        apps = params.get("apps") or ""
        skip_apps_validation = isinstance(apps, str) and apps.startswith("$")
        apps = convert_to_list(apps)
        ids = params.get("ids") or ""
        skip_ids_validation = isinstance(ids, str) and ids.startswith("$")
        ids = convert_to_list(ids)

        if not tags and not skip_tag_validation:
            raise NetskopeException(
                "Invalid value for tags provided. Tags can not be empty."
            )
        if (not apps and not ids) and not (
            skip_apps_validation or skip_ids_validation
        ):
            raise NetskopeException(
                "Invalid value for apps/ids provided. "
                "Application Names and Ids can not both be empty."
            )

        if apps and ids and not (skip_apps_validation or skip_ids_validation):
            raise NetskopeException(
                "Invalid value for apps/ids provided. "
                "Application Names and Ids both can not be provided at the same time."
            )

        try:
            ids = list(map(int, ids))
        except ValueError as ex:
            if not skip_ids_validation:
                raise NetskopeException(
                    "Invalid value for Application Ids provided. "
                    "One of the id is not a valid integer."
                ) from ex

        return tags, apps, ids

    def revert_action(self, action: Action):
        """Revert the action."""
        helper = AlertsHelper()
        self.tenant = helper.get_tenant_crev2(self.name)
        action.parameters = get_latest_values(
            action.parameters, exclude_keys=["tags", "protocol", "publishers"]
        )
        if action.value == "private_app":
            self.session = requests.Session()
            self.session.headers.update(
                add_installation_id(
                    add_user_agent(
                        {
                            "Netskope-API-Token": resolve_secret(
                                self.tenant.parameters["v2token"]
                            ),
                        }
                    )
                )
            )
            action_dict = action.parameters
            existing_private_app_name = action_dict.get("private_app_name", "")
            new_private_app_name = action_dict.get("name", "")
            host = action_dict["host"]
            if existing_private_app_name == "create":
                private_app_name = f"[{new_private_app_name}]"
            else:
                private_app_name = existing_private_app_name
            if not host:
                self.logger.info(
                    f"{self.log_prefix}: Host value not found in the "
                    f"record for private app {private_app_name}. "
                    "Hence, skipped execution of revert action."
                )
                return
            self.logger.info(
                f"{self.log_prefix}: Attempting to remove the host {host} from private app {private_app_name}."
            )
            app = self._get_private_app(
                prefix=private_app_name, has_host=action_dict["host"]
            )
            if not app:
                self.logger.info(
                    f"{self.log_prefix}: Host {host} not found in {private_app_name}. "
                    "Hence, skipped execution of revert action."
                )
                return
            data = {
                "host": ",".join(
                    list(filter(lambda x: x != host, app["host"].split(",")))
                )
            }
            return self._patch_private_app(
                self.tenant.parameters["tenantName"].strip(),
                app["app_id"],
                data,
            )
        raise NotImplementedError()

    def _patch_private_app(self, tenant: str, app_id: str, data: dict):
        """Patch an existing private app.

        Args:
            tenant (str): Tenant base URL.
            app_id (str): Existing app id.
            data (dict): Request body.

        Raises:
            NetskopeException: Error in the response.
            NetskopeException: Non-2xx status code.
        """
        (
            success,
            append_privateapp_netskope,
        ) = handle_exception(
            self.session.patch,
            error_code="CRE_1045",
            custom_message="Error occurred while adding host to private app to Netskope",
            plugin=self.log_prefix,
            url=URLS["V2_PRIVATE_APP_PATCH"].format(tenant, app_id),
            json=data,
        )
        if not success or append_privateapp_netskope.status_code not in [
            200,
            201,
        ]:
            self.logger.error(
                f"{self.log_prefix}: Error occurred while adding host to private app.",
                details=repr(success),
            )
            raise NetskopeException(
                f"{self.log_prefix}: Could not share host."
            )

        patch_private_app_json = handle_status_code(
            append_privateapp_netskope,
            error_code="CRE_1046",
            custom_message="Error occurred while updating private app in Netskope",
            plugin=self.log_prefix,
            notify=False,
        )

        if patch_private_app_json.get("status", "") != "success":
            self.logger.error(
                f"{self.log_prefix}: Error occurred while adding host to private app. "
                f"Received exit code {append_privateapp_netskope.status_code}.",
                details=repr(patch_private_app_json),
            )
            raise NetskopeException(
                f"{self.log_prefix}: Could not add host to private app."
            )

        self.logger.info(
            f"{self.log_prefix}: Successfully updated the private app for "
            f"configuration {self.plugin_name}."
        )
        return

    def execute_action(self, action: Action):
        """Execute action on the user."""
        helper = AlertsHelper()
        self.tenant = helper.get_tenant_crev2(self.name)
        action.parameters = get_latest_values(
            action.parameters, exclude_keys=["host", "tags", "protocol", "publishers"]
        )
        if action.value == "generate":
            return
        elif action.value == "impact":
            user, score, source, reason = (
                self._process_params_for_impact_action(action.parameters)
            )
            self._update_impact_score(
                user,
                score,
                source,
                reason,
            )
            self.logger.info(
                f"{self.log_prefix}: UCI score updated for user {user} successfully."
            )
            return
        elif action.value in ["add", "remove"]:
            user = action.parameters.get("user", "")
            users = self._get_all_users(self.configuration)
            match = self._find_user_by_email(users, user)
            if match is None:
                self.logger.info(
                    f"{self.log_prefix}: User with email {user} not found on Netskope via SCIM."
                )
                return
            if action.value == "add":
                group_id = action.parameters.get("group", "")
                if group_id == "create":
                    groups = self._get_all_groups(self.configuration)
                    group_name = action.parameters.get("name", "").strip()
                    group_match = self._find_group_by_name(groups, group_name)
                    if group_match is None:  # create group
                        group = self._create_group(
                            self.configuration, group_name
                        )
                        group_id = group["id"]
                    else:
                        group_id = group_match["id"]
                self._add_to_group(self.configuration, match["id"], group_id)
                self.logger.info(
                    f"{self.log_prefix}: Added {user} to group with ID {group_id} successfully."
                )
            if action.value == "remove":
                self._remove_from_group(
                    self.configuration,
                    match["id"],
                    action.parameters.get("group", ""),
                )
                self.logger.info(
                    f"{self.log_prefix}: Removed {user} from group with ID "
                    f"{action.parameters.get('group')} successfully."
                )
        elif action.value == "private_app":
            action_dict = action.parameters
            self.session = requests.Session()
            self.session.headers.update(
                add_installation_id(
                    add_user_agent(
                        {
                            "Netskope-API-Token": resolve_secret(
                                self.tenant.parameters["v2token"]
                            ),
                        }
                    )
                )
            )
            protocols = action_dict.get("protocol", [])
            tcp_port = action_dict.get("tcp_ports", "") or ""
            tcp_port_list = [
                port.strip() for port in tcp_port.split(",") if port.strip()
            ]
            udp_port = action_dict.get("udp_ports", "") or ""
            udp_port_list = [
                port.strip() for port in udp_port.split(",") if port.strip()
            ]
            use_publisher_dns = action_dict.get("use_publisher_dns", False)
            if not action_dict.get("host"):
                raise NetskopeException("Host can not be empty.")
            tags = action_dict.get("tags", [])
            if tags and isinstance(tags, str):
                tags = list(map(lambda x: x.strip(), tags.split(",")))

            return self._push_private_app(
                action_dict["host"],
                existing_private_app_name=action_dict.get(
                    "private_app_name", ""
                ),
                new_private_app_name=action_dict.get("name", ""),
                protocol_type=protocols,
                tcp_ports=tcp_port_list,
                udp_ports=udp_port_list,
                publishers=action_dict.get("publishers", []),
                use_publisher_dns=use_publisher_dns,
                default_url=action_dict.get("default_url", "").strip(),
                tags=tags,
            )
        elif action.value == "tag_app":
            self.session = requests.Session()
            self.session.headers.update(
                add_installation_id(
                    add_user_agent(
                        {
                            "Netskope-API-Token": resolve_secret(
                                self.tenant.parameters["v2token"]
                            ),
                        }
                    )
                )
            )

            tags, apps, ids = self._process_params_for_add_tag_action(
                action.parameters
            )

            self._tag_application(tags, apps, ids)
            self.logger.info(
                f"{self.log_prefix}: Added tag(s) {','.join(tags)} to application(s) successfully."
            )
        elif action.value == "app_instance":
            instance_id, instance_name, app, tags = (
                self._process_params_for_app_instance_action(action.parameters)
            )

            self.session = requests.Session()
            self.session.headers.update(
                add_installation_id(add_user_agent({}))
            )
            self.session.params.update(
                {"token": resolve_secret(self.tenant.parameters["token"])}
            )

            self._create_app_instance(instance_id, instance_name, app, tags)

            self.logger.info(
                f"{self.log_prefix}: Created/updated app instance {instance_name} successfully."
            )
