"""
BSD 3-Clause License.

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

CRE ServiceNow plugin.
"""

import datetime
import traceback
from typing import List, Tuple, Union
from pydantic import ValidationError
from urllib.parse import urlparse

from netskope.integrations.crev2.models import (
    Action,
    ActionWithoutParams,
)
from netskope.integrations.crev2.plugin_base import PluginBase, ValidationResult, Entity

from .utils.constants import (
    MODULE_NAME,
    PLATFORM_NAME,
    PLUGIN_VERSION,
    LIMIT,
)
from .utils.helper import (
    ServiceNowZTREPluginHelper,
    ServiceNowZTREPluginException,
    ServiceNowQuery,
)


class ServiceNowZTREPlugin(PluginBase):
    """CRE ServiceNow plugin implementation."""

    def __init__(
        self,
        name,
        *args,
        **kwargs,
    ):
        """Service Now plugin initializer.

        Args:
            name (str): Plugin configuration name.
        """
        super().__init__(
            name,
            *args,
            **kwargs,
        )
        self.plugin_name, self.plugin_version = self._get_plugin_info()
        self.log_prefix = f"{MODULE_NAME} {self.plugin_name} [{name}]"
        self.servicenow_helper = ServiceNowZTREPluginHelper(
            logger=self.logger,
            log_prefix=self.log_prefix,
            plugin_name=self.plugin_name,
            plugin_version=self.plugin_version,
        )

    def _get_plugin_info(self) -> Tuple:
        """Get plugin name and version from manifest.

        Returns:
            tuple: Tuple of plugin's name and version fetched from manifest.
        """
        try:
            manifest_json = ServiceNowZTREPlugin.metadata
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

    def get_actions(self) -> List[ActionWithoutParams]:
        """Get available actions.

        Args:
            None

        Returns:
            [...] list of ActionWithoutParams: List of ActionWithoutParams
                which has label and value defined

        """
        return [
            ActionWithoutParams(label="Share application data", value="share_app_data"),
            ActionWithoutParams(label="No action", value="generate"),
        ]

    def get_action_params(self, action: Action) -> List:
        """Get fields required for an action.

        Args:
            action (Action): The type of action

        Returns:
            [...] (list): Returns a list of details for UI to display group

        """
        tooltip = f"Value of this field will be shared to {PLATFORM_NAME} platform."
        if action.value in ["generate"]:
            return []

        if action.value == "share_app_data":
            return [
                {
                    "label": "Company Name",
                    "key": "company_name",
                    "type": "text",
                    "default": "",
                    "description": (
                        "Select field for Company Name from Source or "
                        "provide Company Name in Static field. Used for "
                        f"fetching Vendor details from {PLATFORM_NAME} platform."
                    ),
                },
                {
                    "label": "Parent Company Name",
                    "key": "parent_company_name",
                    "type": "text",
                    "default": "",
                    "description": (
                        "Select field for Parent Company Name from Source or "
                        "provide Parent Company Name in Static field. Used for "
                        f"fetching Vendor details from {PLATFORM_NAME} platform."
                    ),
                },
                {
                    "label": "Operator",
                    "key": "operator",
                    "type": "choice",
                    "choices": [
                        {"key": "AND", "value": "and"},
                        {"key": "OR", "value": "or"},
                    ],
                    "default": "and",
                    "description": (
                        "Select operator from Static field drop down to perform operation between "
                        "Company Name and Parent Company Name. Required when both "
                        "Company Name and Parent Company Name are provided to make "
                        "query for ServiceNow API to fetch Vendors. e.g. "
                        "name=ABC^ORparent.name=XYZ"
                    ),
                },
                {
                    "label": "Application Name",
                    "key": "application_name",
                    "type": "text",
                    "default": "",
                    "description": (
                        f"Select field for Application name from Source or "
                        f"provide Application name in Static field. {tooltip}"
                    ),
                },
                {
                    "label": "CCI",
                    "key": "cci",
                    "type": "number",
                    "default": "",
                    "description": (
                        f"Select field for Application CCI from Source or "
                        f"provide CCI in Static field. Value should be "
                        f"between 0 and 100. {tooltip}"
                    ),
                },
                {
                    "label": "CCL",
                    "key": "ccl",
                    "type": "text",
                    "default": "",
                    "description": (
                        f"Select field for Application CCL from Source or "
                        f"provide CCL in Static field. {tooltip}"
                    ),
                },
                {
                    "label": "Category Name",
                    "key": "category_name",
                    "type": "text",
                    "default": "",
                    "description": (
                        f"Select field for Application Category from Source or "
                        f"provide Category Name in Static field. {tooltip}"
                    ),
                },
                {
                    "label": "Deep Link",
                    "key": "deep_link",
                    "type": "text",
                    "default": "",
                    "description": (
                        f"Select field for Application Deep Link from Source or "
                        f"provide Deep Link in Static field. {tooltip}"
                    ),
                },
            ]

    def validate_action(self, action: Action) -> ValidationResult:
        """Validate Wiz action configuration.

        Args:
            action (Action): The type of action

        Returns:
            ValidationResult: validation result true or false with message
        """
        action_value = action.value
        action_params = action.parameters
        if action_value not in ["generate", "share_app_data"]:
            self.logger.error(
                f'{self.log_prefix}: Unsupported action "{action_value}" '
                "provided in the action configuration. "
            )
            return ValidationResult(
                success=False, message="Unsupported action provided."
            )

        if action_value == "share_app_data":
            company_name = action_params.get("company_name", "")
            parent_company_name = action_params.get("parent_company_name", "")
            operator = action_params.get("operator", "")
            cci = action_params.get("cci", None)

            if not (company_name or parent_company_name):
                err_msg = (
                    "Either Company Name or Parent Company Name is a required "
                    "in the action parameters. Both can not be empty."
                )
                self.logger.error(f"{self.log_prefix}: {err_msg}")
                return ValidationResult(success=False, message=err_msg)

            if company_name and not isinstance(company_name, str):
                err_msg = "Invalid Company Name provided in the action parameters."
                self.logger.error(f"{self.log_prefix}: {err_msg}")
                return ValidationResult(success=False, message=err_msg)
            if parent_company_name and not isinstance(parent_company_name, str):
                err_msg = (
                    "Invalid Parent Company Name provided in the action parameters."
                )
                self.logger.error(f"{self.log_prefix}: {err_msg}")
                return ValidationResult(success=False, message=err_msg)

            if company_name and parent_company_name:
                if not operator:
                    err_msg = (
                        "Operator is a required action parameter "
                        "when Company Name and Parent Company Name are provided."
                    )
                    self.logger.error(f"{self.log_prefix}: {err_msg}")
                    return ValidationResult(success=False, message=err_msg)
                elif "$" in operator:
                    err_msg = (
                        "Operator contains the Source Field. "
                        "Please select Operator from Static Field dropdown only."
                    )
                    self.logger.error(f"{self.log_prefix}: {err_msg}")
                    return ValidationResult(success=False, message=err_msg)
                elif operator not in [
                    "or",
                    "and",
                ]:
                    err_msg = (
                        "Invalid Operator provided in the action parameters. "
                        "Supported operators are: 'AND', 'OR'."
                    )
                    self.logger.error(f"{self.log_prefix}: {err_msg}")
                    return ValidationResult(success=False, message=err_msg)
            if cci:
                if isinstance(cci, str) and "$" in cci:
                    log_msg = (
                        "CCI contains the Source Field "
                        "hence validation for this field will be performed "
                        "while executing the Sharing app data action."
                    )
                    self.logger.info(f"{self.log_prefix}: {log_msg}")
                    return ValidationResult(
                        success=True, message="Validation successful."
                    )
                try:
                    cci = int(cci)
                    if not isinstance(cci, int) or (cci < 0 or cci > 100):
                        err_msg = (
                            "Invalid CCI provided in the action parameters. "
                            "Valid range should be between 0 to 100."
                        )
                        self.logger.error(f"{self.log_prefix}: {err_msg}")
                        return ValidationResult(success=False, message=err_msg)
                except Exception:
                    err_msg = (
                        "Invalid CCI provided in the action parameters. "
                        "Valid should be an integer in range 0 to 100."
                    )
                    self.logger.error(
                        message=f"{self.log_prefix}: {err_msg}",
                        details=str(traceback.format_exc()),
                    )
                    return ValidationResult(success=False, message=err_msg)

        return ValidationResult(success=True, message="Validation successful.")

    def execute_action(self, action: Action):
        """Execute action on the application.

        Args:
            action (Action): Action that needs to be perform on application.

        Returns:
            None
        """
        action_label = action.label
        action_parameters = action.parameters

        if action.value == "generate":
            self.logger.info(
                f"{self.log_prefix}: Successfully executed '{action_label}' "
                "action. Note: No processing will be done from plugin for "
                f"the '{action_label}' action."
            )
            return

        company_name = action_parameters.get("company_name", "NA")
        parent_company_name = action_parameters.get("parent_company_name", "NA")
        operator = action_parameters.get("operator", "and")
        application_name = action_parameters.get("application_name", "NA")
        cci = action_parameters.get("cci", None)
        ccl = action_parameters.get("ccl", "NA")
        category_name = action_parameters.get("category_name", "NA")
        deep_link = action_parameters.get("deep_link", "NA")

        try:
            _ = ServiceNowQuery(
                company_name=company_name,
                parent_company_name=parent_company_name,
                operator=operator,
                cci=cci if cci else None,
            )
        except ValidationError as e:
            err_msg = (
                f"{e.errors()[0]['msg']} "
                f"Hence, skipping execution of '{action_label}' action "
                f"for application '{application_name}'."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=str(e),
            )
            return

        final_query = self.make_query_list(action_parameters=action_parameters)
        snow_records = self.apply_query(final_query)

        if not snow_records:
            logger_msg = (
                f"Vendor is not found for application '{application_name}' "
                f"on {PLATFORM_NAME}, sharing of this application will be skipped."
            )
            self.logger.info(f"{self.log_prefix}: {logger_msg}")
            return

        self.logger.info(
            f"{self.log_prefix}: Found {len(snow_records)} matches "
            f"for application '{application_name}'."
        )

        self.logger.info(
            f"{self.log_prefix}: Executing '{action_label}' action "
            f"for application '{application_name}'."
        )

        instance_url, username, password = self.servicenow_helper.get_config_params(
            self.configuration
        )
        headers = self.servicenow_helper.basic_auth(username, password)
        current_time = datetime.datetime.now()
        current_time = current_time.strftime("%Y-%m-%d %H:%M:%SZ")

        for record in snow_records:
            name = record.get("name")
            sys_id = record.get("sys_id")
            existing_notes = record.get("notes")
            api_endpoint = f"{instance_url}/api/now/table/core_company/{sys_id}"

            new_notes = (
                f"[Netskope CE] Last shared at: {current_time}\n"
                f"Application Name: {application_name if application_name else 'NA'}, "
                f"Cloud Confidence Index: {cci if cci else 'NA'}, "
                f"CCL: {ccl if ccl else 'NA'}, "
                f"Category Name: {category_name if category_name else 'NA'}, "
                f"Deep Link: {deep_link if deep_link else 'NA'}\n"
            )
            if existing_notes:
                notes = new_notes + "\n\n" + existing_notes
            else:
                notes = new_notes
            payload = {"notes": notes}
            try:
                logger_msg = (
                    f"performing '{action_label}' action on application "
                    f"'{application_name}' for company '{name}'"
                )
                _ = self.servicenow_helper.api_helper(
                    url=api_endpoint,
                    method="PATCH",
                    headers=headers,
                    json=payload,
                    verify=self.ssl_validation,
                    proxies=self.proxy,
                    logger_msg=logger_msg,
                )
                self.logger.info(
                    f"{self.log_prefix}: Successfully shared the data of application "
                    f"'{application_name}' for company '{name}' with {PLATFORM_NAME}."
                )
            except ServiceNowZTREPluginException as err:
                raise ServiceNowZTREPluginException(err)
            except Exception as err:
                err_msg = (
                    f"Error occurred while sharing the data of "
                    f"application '{application_name}'. Error: {err}"
                )
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg}",
                    details=traceback.format_exc(),
                )
                raise ServiceNowZTREPluginException(err_msg)

    def make_query_list(
        self,
        action_parameters: dict,
    ):
        """Make query list.

        Args:
            action_parameters (dict): Action parameters.

        Returns:
            List: List of queries.
        """
        company_name = action_parameters.get("company_name", "")
        parent_company_name = action_parameters.get("parent_company_name", "")
        operator = action_parameters.get("operator", "")
        operator = "or" if not operator else operator.strip().lower()

        query_list = []
        if company_name and parent_company_name and operator:
            for field in ["company_name", "parent_company_name"]:
                snow_field_name = "name" if field == "company_name" else "parent.name"
                ce_field_value = action_parameters.get(field, "")
                query = self.get_query(
                    snow_field_name=snow_field_name,
                    ce_field_value=ce_field_value,
                )
                query_list.append(query)
        if company_name and not parent_company_name:
            snow_field_name = "name"
            ce_field_value = action_parameters.get("company_name", "")
            query = self.get_query(
                snow_field_name=snow_field_name,
                ce_field_value=ce_field_value,
            )
            query_list.append(query)

        if not company_name and parent_company_name:
            snow_field_name = "parent.name"
            ce_field_value = action_parameters.get("parent_company_name", "")
            query = self.get_query(
                snow_field_name=snow_field_name,
                ce_field_value=ce_field_value,
            )
            query_list.append(query)

        if operator == "and":
            final_query = "^".join(query_list)
        else:
            final_query = "^OR".join(query_list)

        return final_query

    def get_query(
        self,
        snow_field_name: str,
        ce_field_value: Union[str, List],
    ):
        """Get query.

        Args:
            snow_field_name (str): ServiceNow field name.
            ce_field_value (Union[str, List]): Company name or parent company name.

        Returns:
            List: List of queries.
        """
        if ce_field_value is None:
            ce_field_value = ""
        if isinstance(ce_field_value, list):
            sub_query = ",".join(ce_field_value)
            query = f"{snow_field_name}IN{sub_query}"
        else:
            query = f"{snow_field_name}={ce_field_value}"
        return query

    def apply_query(self, query):
        """Fetch the vendors from ServiceNow that matches the query.

        Args:
            query (str): Query.

        Returns:
            List: List of vendors.
        """
        try:
            instance_url, username, password = self.servicenow_helper.get_config_params(
                self.configuration
            )
            headers = self.servicenow_helper.basic_auth(username, password)
            api_endpoint = f"{instance_url}/api/now/table/core_company"
            params = {
                "sysparm_limit": LIMIT,
                "sysparm_offset": 0,
                "sysparm_query": query,
                "sysparm_fields": "sys_id,notes,name",
            }
            logger_msg = (
                f"the list of vendors that matches the query "
                f" '{query}' from {PLATFORM_NAME}"
            )
            total_vendors = []
            page_count = 1
            while True:
                self.logger.debug(
                    f"{self.log_prefix}: Fetching {logger_msg} for page {page_count}."
                )
                resp_json = self.servicenow_helper.api_helper(
                    url=api_endpoint,
                    method="GET",
                    params=params,
                    headers=headers,
                    verify=self.ssl_validation,
                    proxies=self.proxy,
                    logger_msg=(f"fetching {logger_msg}"),
                )

                vendors = resp_json.get("result", [])
                total_vendors.extend(vendors)

                self.logger.info(
                    f"{self.log_prefix}: Successfully fetched "
                    f"{len(vendors)} vendors in page {page_count}. "
                    f"Total vendors fetched: {len(total_vendors)}."
                )
                page_count += 1
                if len(vendors) < LIMIT:
                    break
                params["sysparm_offset"] += LIMIT

            self.logger.info(
                f"{self.log_prefix}: Successfully fetched {len(total_vendors)} "
                f"vendors that matches the query '{query}' "
                f"from {PLATFORM_NAME} platform."
            )
            return total_vendors
        except ServiceNowZTREPluginException:
            raise
        except Exception as exp:
            err_msg = (
                "Error occurred while fetching the list of "
                f"vendors from {PLATFORM_NAME} platform. Error: {exp}"
            )
            self.logger.error(
                message=(f"{self.log_prefix}: {err_msg}"),
                details=str(traceback.format_exc()),
            )
            raise ServiceNowZTREPluginException(err_msg)

    def fetch_records(self, entity: str) -> List:
        """Pull records from ServiceNow.

        Args:
            entity (str): Entity to be fetched.

        Returns:
            List: List of records to be stored on the platform.
        """
        return []

    def update_records(self, entity: str, records: list[dict]) -> List:
        """Update records.

        Args:
            entity (str): Entity to be updated.
            records (list): Records to be updated.

        Returns:
            List: List of updated records.
        """
        return []

    def validate(self, configuration) -> ValidationResult:
        """Validate the Plugin configuration parameters.

        Args:
            configuration (dict): Plugin configuration parameters.

        Returns:
            ValidateResult: ValidateResult object with success
            flag and message.
        """
        # Validate Instance URL
        instance_url = configuration.get("instance_url", "").strip().strip("/")
        if not instance_url:
            err_msg = "Instance URL is required configuration parameter."
            self.logger.error(
                f"{self.log_prefix}: Validation error occurred. {err_msg}"
            )
            return ValidationResult(success=False, message=err_msg)
        elif not (isinstance(instance_url, str) and self._validate_url(instance_url)):
            err_msg = "Invalid Instance URL provided in configuration parameters."
            self.logger.error(
                f"{self.log_prefix}: Validation error occurred. {err_msg}"
            )
            return ValidationResult(success=False, message=err_msg)

        # Validate username
        username = configuration.get("username", "").strip()
        if not username:
            err_msg = "Username is required configuration parameter."
            self.logger.error(
                f"{self.log_prefix}: Validation error occurred. {err_msg}"
            )
            return ValidationResult(success=False, message=err_msg)
        elif not isinstance(username, str):
            err_msg = "Invalid Username provided in configuration parameters."
            self.logger.error(
                f"{self.log_prefix}: Validation error occurred. {err_msg}"
            )
            return ValidationResult(success=False, message=err_msg)

        # Validate password
        password = configuration.get("password")
        if not password:
            err_msg = "Password is required configuration parameter."
            self.logger.error(
                f"{self.log_prefix}: Validation error occurred. {err_msg}"
            )
            return ValidationResult(success=False, message=err_msg)
        elif not isinstance(password, str):
            err_msg = "Invalid Password provided in configuration parameters."
            self.logger.error(
                f"{self.log_prefix}: Validation error occurred. {err_msg}"
            )
            return ValidationResult(success=False, message=err_msg)

        # Validate connectivity to the ServiceNow server.
        return self._validate_connectivity(
            instance_url=instance_url,
            username=username,
            password=password,
        )

    def _validate_connectivity(
        self,
        instance_url: str,
        username: str,
        password: str,
    ) -> ValidationResult:
        """Validate connectivity with ServiceNow server.

        Args:
            url (str): Instance URL.
            username (str): Instance username.
            password (str): Instance password.

        Returns:
            ValidationResult: Validation Result.
        """
        try:
            logger_msg = f"connectivity with {PLATFORM_NAME} server"
            self.logger.debug(f"{self.log_prefix}: Validating {logger_msg}.")
            headers = self.servicenow_helper.basic_auth(
                username=username, password=password
            )

            api_endpoint = f"{instance_url}/api/now/table/core_company"
            params = {"sysparm_limit": 1}
            self.servicenow_helper.api_helper(
                url=api_endpoint,
                method="GET",
                params=params,
                headers=headers,
                verify=self.ssl_validation,
                proxies=self.proxy,
                logger_msg=(f"validating {logger_msg}"),
                is_validation=True,
            )

            self.logger.debug(
                f"{self.log_prefix}: Successfully validated "
                f"{logger_msg}."
            )
            return ValidationResult(
                success=True,
                message=(
                    f"Validation successful for {MODULE_NAME} "
                    f"{self.plugin_name} plugin configuration."
                ),
            )
        except ServiceNowZTREPluginException as exp:
            return ValidationResult(success=False, message=f"{str(exp)}")
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

    def _validate_url(self, url: str) -> bool:
        """Validate the given URL.

        Args:
            url (str): URL to validate.

        Returns:
            bool: True if URL is valid else False.
        """
        parsed_url = urlparse(url.strip())
        return parsed_url.scheme and parsed_url.netloc

    def get_entities(self) -> list[Entity]:
        """Get available entities."""
        return [Entity(name="", fields=[])]
