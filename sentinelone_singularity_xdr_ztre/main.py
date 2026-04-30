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

3. Neither the name of the copyright holder nor the names of its
   contributors may be used to endorse or promote products derived from
   this software without specific prior written permission.

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

CRE SentinelOne Singularity XDR plugin.
"""

import time
import traceback
from typing import Callable, Dict, List, Literal, Optional, Tuple, Union

from netskope.integrations.crev2.models import Action, ActionWithoutParams
from netskope.integrations.crev2.plugin_base import (
    ActionResult,
    Entity,
    EntityField,
    EntityFieldType,
    PluginBase,
    ValidationResult,
)

from .utils.constants import (
    APPLICATION_ENDPOINT,
    APPLICATION_VULNERABILITY_ENDPOINT,
    APPLICATION_VULNERABILITY_MAPPING,
    ASSET_ACTION_ENDPOINT,
    ASSET_CRITICALITY_MAP,
    DEVICE_ENTITY_MAPPING,
    ENDPOINT_PULL_ENDPOINT,
    GROUP_PAGE_SIZE,
    GROUPS_ENDPOINT,
    IDENTITY_PULL_ENDPOINT,
    MANAGE_TAGS_ENDPOINT,
    MODULE_NAME,
    MOVE_AGENTS_ENDPOINT,
    NETWORK_CONNECT_ENDPOINT,
    NETWORK_DISCONNECT_ENDPOINT,
    PAGE_SIZE,
    PLATFORM_NAME,
    PLUGIN_VERSION,
    REBOOT_ENDPOINT,
    SCAN_ENDPOINT,
    SITES_ENDPOINT,
    TAG_MANAGER_ENDPOINT,
    TAGS_ENDPOINT,
    USER_ENTITY_MAPPING,
    VULN_SCAN_ENDPOINT,
)
from .utils.exceptions import (
    SentinelOneSingularityXDRPluginException,
    exception_handler,
)
from .utils.helper import SentinelOnePluginHelper


class SentinelOnePlugin(PluginBase):
    """SentinelOne Singularity XDR plugin class."""

    def __init__(self, name, *args, **kwargs):
        """SentinelOne plugin initializer.

        Args:
            name (str): Plugin configuration name.
        """
        super().__init__(name, *args, **kwargs)
        self.plugin_name, self.plugin_version = (
            self._get_plugin_info()
        )
        self.log_prefix = (
            f"{MODULE_NAME} {self.plugin_name}"
        )
        if name:
            self.log_prefix = f"{self.log_prefix} [{name}]"
        self.s1_singularity_xdr_helper = SentinelOnePluginHelper(
            logger=self.logger,
            log_prefix=self.log_prefix,
            plugin_name=self.plugin_name,
            plugin_version=self.plugin_version,
        )
        self.provide_action_id = True

    def _get_plugin_info(self) -> tuple:
        """Get plugin name and version from manifest.

        Returns:
            tuple: Plugin name and version.
        """
        try:
            manifest_json = SentinelOnePlugin.metadata
            plugin_name = manifest_json.get("name", PLATFORM_NAME)
            plugin_version = manifest_json.get(
                "version", PLUGIN_VERSION
            )
            return plugin_name, plugin_version
        except Exception as exp:
            self.logger.error(
                message=(
                    f"{MODULE_NAME} {PLATFORM_NAME}: Error occurred"
                    " while getting plugin details."
                    f" Error: {exp}"
                ),
                details=traceback.format_exc(),
            )
        return (PLATFORM_NAME, PLUGIN_VERSION)

    def get_entities(self) -> List:
        """Get available entities.

        Returns:
            list: List of Entity objects.
        """
        return [
            Entity(
                name="Devices (Endpoints)",
                fields=[
                    EntityField(
                        name="Agent ID",
                        type=EntityFieldType.STRING,
                        required=True,
                    ),
                    EntityField(
                        name="Asset ID",
                        type=EntityFieldType.STRING,
                        required=True,
                    ),
                    EntityField(
                        name="Asset Name",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="Serial Number",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="Network Status",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="IP Address (Public)",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="Internal IPv4 Addresses",
                        type=EntityFieldType.LIST,
                    ),
                    EntityField(
                        name="Internal IPv6 Addresses",
                        type=EntityFieldType.LIST,
                    ),
                    EntityField(
                        name="MAC Addresses",
                        type=EntityFieldType.LIST,
                    ),
                    EntityField(
                        name="Domain",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="Device Review Status",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="Asset Criticality",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="Infection Status",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="Risk Factors",
                        type=EntityFieldType.LIST,
                    ),
                    EntityField(
                        name="Asset Status",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="Tags",
                        type=EntityFieldType.LIST,
                    ),
                    EntityField(
                        name="Last Logged In User",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="OS Username",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="AD User DN",
                        type=EntityFieldType.REFERENCE,
                    ),
                    EntityField(
                        name="Asset Contact Email",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="Operating System",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="OS Family",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="Site Name",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="Member Of",
                        type=EntityFieldType.STRING,
                    ),
                ],
            ),
            Entity(
                name="Users (Identity)",
                fields=[
                    EntityField(
                        name="Asset ID",
                        type=EntityFieldType.STRING,
                        required=True,
                    ),
                    EntityField(
                        name="Distinguished Name",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="User Principal Name",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="Domain",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="Risk Factors",
                        type=EntityFieldType.LIST,
                    ),
                    EntityField(
                        name="Infection Status",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="Asset Status",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="Privileged Account",
                        type=EntityFieldType.BOOLEAN,
                    ),
                    EntityField(
                        name="Account Enabled",
                        type=EntityFieldType.BOOLEAN,
                    ),
                    EntityField(
                        name="Service Account",
                        type=EntityFieldType.BOOLEAN,
                    ),
                    EntityField(
                        name="Asset Criticality",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="Member Of Groups",
                        type=EntityFieldType.LIST,
                    ),
                    EntityField(
                        name="Bad Password Count",
                        type=EntityFieldType.NUMBER,
                    ),
                    EntityField(
                        name="Deleted",
                        type=EntityFieldType.BOOLEAN,
                    ),
                    EntityField(
                        name="Tags",
                        type=EntityFieldType.LIST,
                    ),
                    EntityField(
                        name="Asset Contact Email",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="Email",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="Site Name",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="Display Name",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="Sam Account Name",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="Last Logon Time",
                        type=EntityFieldType.DATETIME,
                    ),
                ],
            ),
            Entity(
                name="Applications",
                fields=[
                    EntityField(
                        name="Application ID",
                        type=EntityFieldType.STRING,
                        required=True,
                    ),
                    EntityField(
                        name="Application Vulnerability ID",
                        type=EntityFieldType.STRING,
                        required=True,
                    ),
                    EntityField(
                        name="Application Name",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="Application Vendor",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="CVE ID",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="Endpoint ID",
                        type=EntityFieldType.REFERENCE,
                    ),
                    EntityField(
                        name="Endpoint Name",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="Application Version",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="NVD Base Score",
                        type=EntityFieldType.NUMBER,
                    ),
                    EntityField(
                        name="Severity",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="Risk Score",
                        type=EntityFieldType.NUMBER,
                    ),
                    EntityField(
                        name="Exploit Maturity",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="Remediation Availability",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="Confidence Level",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="Vulnerability Status",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="Mitigation Status",
                        type=EntityFieldType.STRING,
                    ),
                    EntityField(
                        name="Detection Date",
                        type=EntityFieldType.DATETIME,
                    ),
                    EntityField(
                        name="Published Date",
                        type=EntityFieldType.DATETIME,
                    ),
                    EntityField(
                        name="OS Type",
                        type=EntityFieldType.STRING,
                    ),
                ],
            ),
        ]

    @exception_handler
    def get_site_id(
        self,
        base_url: str,
        auth_header: Dict,
        site_name: str,
        is_validation: bool = False,
        context: Dict = {},
    ) -> str:
        """Get SentinelOne site ID by site name.

        Fetches paginated site data and returns the site ID for the
        matching site name. Raises if the site is not found or is
        not active.

        Args:
            base_url (str): Base URL.
            auth_header (Dict): Authorization header.
            site_name (str): Site name to look up.
            is_validation (bool): Is this a validation call?
            context (Dict): Context dictionary.

        Returns:
            str: Site ID corresponding to the given site name.

        Raises:
            SentinelOneSingularityXDRPluginException: If site not found or
            inactive.
        """
        url = f"{base_url}{SITES_ENDPOINT}"
        page_number = 1
        query_params = {
            "sortBy": "name",
            "sortOrder": "asc",
            "limit": PAGE_SIZE,
        }
        site_id = None
        is_active = None
        match_found = False
        while True:
            logger_msg = (
                f"fetching site details for page {page_number}"
                f" from {PLATFORM_NAME}"
            )
            context["logger_msg"] = logger_msg
            resp_json = self.s1_singularity_xdr_helper.api_helper(
                logger_msg=logger_msg,
                url=url,
                method="GET",
                headers=auth_header,
                params=query_params,
                is_handle_error_required=True,
                is_validation=is_validation,
                ssl_validation=self.ssl_validation,
                proxy=self.proxy,
            )
            site_data_list = (
                resp_json.get("data", {}).get("sites", [])
            )
            if not site_data_list:
                break
            for site_data in site_data_list:
                if site_data.get("name") == site_name:
                    site_id = site_data.get("id")
                    is_active = (
                        site_data.get("state", "") == "active"
                    )
                    match_found = True
                    break
            if match_found:
                break
            cursor = (
                resp_json.get("pagination", {}).get("nextCursor", "")
            )
            if not cursor:
                break
            query_params["cursor"] = cursor
            page_number += 1

        if site_id is None:
            err_msg = (
                f"Site '{site_name}' not found on {PLATFORM_NAME}."
                " Verify the Site Name provided in the configuration"
                " parameters."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                resolution=(
                    "Ensure that the Site Name provided in the"
                    " configuration parameters matches an existing"
                    f" site on {PLATFORM_NAME}."
                ),
            )
            raise SentinelOneSingularityXDRPluginException(err_msg)

        # Expired or deleted sites cannot be accessed on the UI.
        if not is_active:
            err_msg = (
                f"Site '{site_name}' provided in the configuration"
                f" parameter is not active on {PLATFORM_NAME}."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                resolution=(
                    "Ensure that the site provided in the"
                    " configuration is active."
                ),
            )
            raise SentinelOneSingularityXDRPluginException(err_msg)

        return site_id

    def _get_storage(self) -> Dict:
        """Get storage object.

        Returns:
            Dict: Storage object.
        """
        return self.storage if self.storage is not None else {}

    def _get_locally_cached_site_id(self) -> str:
        """Get site ID from configuration, using cached storage when
        the configuration has not changed.

        Computes a SHA-256 hash of the current configuration parameters
        (base URL, API token, and site name) and compares it against the
        previously stored hash. If they match and a cached site ID exists,
        the cached value is returned immediately, avoiding an API call.
        Otherwise, a live API call is made to fetch the site ID, and both
        the site ID and the new config hash are persisted to storage for
        future calls.

        Returns:
            str: The site ID corresponding to the configured site name.
        """
        base_url, api_token, site_name = (
            self.s1_singularity_xdr_helper.get_configuration_parameters(
                self.configuration
            )
        )
        storage = self._get_storage()
        storage_site_id = storage.get("site_id")
        if storage_site_id:
            return storage_site_id
        auth_header = self.s1_singularity_xdr_helper.get_auth_header(
            api_token
        )
        site_id = self.get_site_id(
            base_url=base_url,
            auth_header=auth_header,
            site_name=site_name,
        )
        storage.update({"site_id": site_id})
        return site_id

    @exception_handler
    def _get_basic_api_parameters(
        self,
        configuration: Dict = {},
        context: Dict = {},
    ) -> Tuple[str, Dict, str, str]:
        """Get base URL, auth header, site name, and site ID from
        configuration.

        Returns:
            Tuple[str, Dict, str, str]: base_url, auth_header,
                site_name, site_id.
        """
        base_url, api_token, site_name = (
            self.s1_singularity_xdr_helper.get_configuration_parameters(
                configuration=configuration
            )
        )
        auth_header = self.s1_singularity_xdr_helper.get_auth_header(
            api_token
        )
        site_id = self._get_locally_cached_site_id()
        return base_url, auth_header, site_name, site_id

    @exception_handler
    def _get_endpoint_data(
        self,
        base_url: str,
        auth_header: Dict,
        site_id: str,
        context: Dict = {},
    ) -> List:
        """Fetch device records from SentinelOne.

        Args:
            base_url (str): Base URL.
            auth_header (Dict): Authorization header.
            site_id (str): SentinelOne site ID.

        Returns:
            list: List of device records.
        """
        url = f"{base_url}{ENDPOINT_PULL_ENDPOINT}"
        records = []
        page_count = 1
        total_success = 0

        params = {
            "siteIds": site_id,
            "limit": PAGE_SIZE,
            "skipCount": "true",
        }
        self.logger.info(
            f"{self.log_prefix}: Fetching device records from {PLATFORM_NAME}"
            " platform."
        )
        while True:
            page_success = 0
            page_skip = 0

            logger_msg = (
                f"fetching device records for page"
                f" {page_count} from {PLATFORM_NAME}"
            )
            context["logger_msg"] = logger_msg
            resp_json = self.s1_singularity_xdr_helper.api_helper(
                logger_msg=logger_msg,
                url=url,
                method="GET",
                headers=auth_header,
                params=params,
                is_handle_error_required=True,
                ssl_validation=self.ssl_validation,
                proxy=self.proxy,
            )
            page_records = resp_json.get("data", [])
            if not page_records:
                break
            for endpoint in page_records:
                extracted = (
                    self.s1_singularity_xdr_helper.extract_entity_fields(
                        endpoint, DEVICE_ENTITY_MAPPING, "endpoints"
                    )
                )
                if extracted:
                    records.append(extracted)
                    page_success += 1
                else:
                    page_skip += 1
            total_success += page_success
            page_logger = (
                f"Successfully fetched {page_success} device record(s)"
            )
            if page_skip > 0:
                page_logger += (
                    f", skipped fetching {page_skip} device record(s)"
                )
            self.logger.info(
                f"{self.log_prefix}: {page_logger} in page"
                f" {page_count}. Total records fetched:"
                f" {total_success}."
            )
            next_cursor = resp_json.get("pagination", {}).get("nextCursor")
            if not next_cursor:
                break
            params["cursor"] = next_cursor
            page_count += 1

        self.logger.info(
            f"{self.log_prefix}: Successfully fetched"
            f" {total_success} device record(s) from"
            f" {PLATFORM_NAME}."
        )
        return records

    @exception_handler
    def _get_identity_data(
        self,
        base_url: str,
        auth_header: Dict,
        site_id: str,
        context: Dict = {},
    ) -> List:
        """Fetch user records from SentinelOne.

        Args:
            base_url (str): Base URL.
            auth_header (Dict): Authorization header.
            site_id (str): SentinelOne site ID.

        Returns:
            list: List of user records.
        """
        url = f"{base_url}{IDENTITY_PULL_ENDPOINT}"
        records = []
        page_count = 1
        total_success = 0

        params = {
            "siteIds": site_id,
            "limit": PAGE_SIZE,
            "skipCount": "true",
            "resourceType": "AD User",
        }
        self.logger.info(
            f"{self.log_prefix}: Fetching user records from {PLATFORM_NAME}"
            " platform."
        )

        while True:
            page_success = 0
            page_skip = 0

            logger_msg = (
                f"fetching user records for page"
                f" {page_count} from {PLATFORM_NAME}"
            )
            context["logger_msg"] = logger_msg
            resp_json = self.s1_singularity_xdr_helper.api_helper(
                logger_msg=logger_msg,
                url=url,
                method="GET",
                headers=auth_header,
                params=params,
                is_handle_error_required=True,
                ssl_validation=self.ssl_validation,
                proxy=self.proxy,
            )
            page_records = resp_json.get("data", [])
            if not page_records:
                break
            for identity_record in page_records:
                extracted = (
                    self.s1_singularity_xdr_helper.extract_entity_fields(
                        identity_record, USER_ENTITY_MAPPING, "identity"
                    )
                )
                if extracted:
                    page_success += 1
                    records.append(extracted)
                else:
                    page_skip += 1
            total_success += page_success
            page_logger = (
                f"Successfully fetched {page_success} user record(s)"
            )
            if page_skip > 0:
                page_logger += (
                    f", skipped fetching {page_skip} user record(s)"
                )
            self.logger.info(
                f"{self.log_prefix}: {page_logger} in page"
                f" {page_count}. Total records fetched:"
                f" {total_success}."
            )
            next_cursor = resp_json.get("pagination", {}).get("nextCursor")
            if not next_cursor:
                break
            params["cursor"] = next_cursor
            page_count += 1

        self.logger.info(
            f"{self.log_prefix}: Successfully fetched"
            f" {total_success} user record(s) from"
            f" {PLATFORM_NAME}."
        )
        return records

    @exception_handler
    def _get_application_data(
        self,
        base_url: str,
        auth_headers: Dict,
        site_id: str,
        context: Dict = {},
    ) -> Dict:
        """Step 1: Fetch basic application info and build a name→ID map.

        Calls the risks/applications device and returns a mapping of
        application complete name to its applicationId.

        Args:
            base_url (str): Base URL of the SentinelOne platform.
            auth_headers (Dict): Auth headers for API requests.
            site_id (str): Site ID to filter results.
            context (Dict): Context dictionary for logger_msg passing.

        Returns:
            Dict: Mapping of app complete name to {"Application ID": ...}.
        """
        # This API is used to get the
        # application id and filter application type = Application since the
        # application vulnerability endpoint does not have any such filter
        # Fetch Application every-time and fetch vulnerabilities incrementally
        # This is because we are merging the application and vulnerability
        # records using application name, so if we pull application
        # incrementally during subsequent sync we will might get vulnerability
        # records but we wont get the application record since it is already
        # detected.
        app_url = f"{base_url}{APPLICATION_ENDPOINT}"
        page_number = 1
        query_params = {
            "siteIds": site_id,
            "limit": PAGE_SIZE,
            "applicationTypes": "Application",
            "sortBy": "name",
            "sortOrder": "asc",
            "skipCount": True,
        }
        app_basic_map = {}
        total_app_success = 0
        while True:
            page_success = 0
            page_skip = 0
            logger_msg = (
                f"fetching application for page {page_number} from"
                f" {PLATFORM_NAME}"
            )
            context["logger_msg"] = logger_msg
            response = self.s1_singularity_xdr_helper.api_helper(
                logger_msg=logger_msg,
                method="GET",
                url=app_url,
                params=query_params,
                headers=auth_headers,
                proxy=self.proxy,
                ssl_validation=self.ssl_validation,
                is_handle_error_required=True,
                is_validation=False,
            )
            app_list = response.get("data", [])
            if not app_list:
                break
            for record in app_list:
                # app_complete_name = application name + version
                app_complete_name = record.get("name")
                application_id = record.get("applicationId")
                if app_complete_name and application_id:
                    app_basic_map[app_complete_name] = {
                        "Application ID": application_id
                    }
                    page_success += 1
                else:
                    page_skip += 1
            total_app_success += page_success
            page_logger = (
                f"Successfully fetched {page_success} Application record(s)"
            )
            if page_skip > 0:
                page_logger += (
                    f", skipped fetching {page_skip} Application record(s)"
                )
            self.logger.info(
                f"{self.log_prefix}: {page_logger} in page"
                f" {page_number}. Total records fetched:"
                f" {total_app_success}."
            )
            cursor = response.get("pagination", {}).get("nextCursor", "")
            if not cursor:
                break
            query_params.update({"cursor": cursor})
            page_number += 1

        self.logger.info(
            f"{self.log_prefix}: Successfully fetched"
            f" {total_app_success} Application record(s) from"
            f" {PLATFORM_NAME}."
        )
        return app_basic_map

    @exception_handler
    def _get_application_vulnerability_data(
        self,
        base_url: str,
        auth_headers: Dict,
        site_id: str,
        context: Dict = {},
    ) -> List:
        """Fetch application vulnerability data from SentinelOne Singularity
        XDR.

        Fetches basic application info from the risks/applications endpoint,
        then fetches per-CVE vulnerability records from the risks endpoint and
        merges them by applicationId.

        Args:
            base_url (str): Base URL of the SentinelOne platform.
            auth_headers (Dict): Auth headers for API requests.
            site_id (str): Site ID to filter results.
            context (Dict): Context dictionary (unused, for consistency).

        Returns:
            List: List of merged application vulnerability entity field dicts.
        """
        self.logger.info(
            f"{self.log_prefix}: Fetching application vulnerability records"
            f" from {PLATFORM_NAME} platform."
        )

        # Step 1: Fetch basic application info.
        app_basic_map = self._get_application_data(
            base_url=base_url,
            auth_headers=auth_headers,
            site_id=site_id,
            context=context,
        )
        total_app_success = len(app_basic_map)

        if not app_basic_map:
            return []

        # Step 2: Fetch vulnerability records and merge with basic app info
        vuln_url = f"{base_url}{APPLICATION_VULNERABILITY_ENDPOINT}"
        page_number = 1
        query_params = {
            "siteIds": site_id,
            "limit": PAGE_SIZE,
            "skipCount": "true",
            "sortBy": "application",
            "sortOrder": "asc",
        }
        application_vulnerability = []
        total_vuln_success = 0
        while True:
            page_success = 0
            page_skip = 0
            logger_msg = (
                f"fetching application vulnerabilities for page {page_number}"
                f" from {PLATFORM_NAME}"
            )
            context["logger_msg"] = logger_msg
            response = self.s1_singularity_xdr_helper.api_helper(
                logger_msg=logger_msg,
                method="GET",
                url=vuln_url,
                params=query_params,
                headers=auth_headers,
                proxy=self.proxy,
                ssl_validation=self.ssl_validation,
                is_handle_error_required=True,
                is_validation=False,
            )
            vuln_list = response.get("data", [])
            if not vuln_list:
                break
            for record in vuln_list:
                app_complete_name = record.get("application")
                if not app_complete_name:
                    page_skip += 1
                    continue
                vuln_fields = (
                    self.s1_singularity_xdr_helper.extract_entity_fields(
                        record,
                        APPLICATION_VULNERABILITY_MAPPING,
                        "application vulnerabilities",
                    )
                )
                if not vuln_fields:
                    page_skip += 1
                    continue
                if app_id_field := app_basic_map.get(app_complete_name):
                    vuln_fields["Application ID"] = app_id_field.get(
                        "Application ID"
                    )
                    application_vulnerability.append(vuln_fields)
                    page_success += 1
                else:
                    page_skip += 1
            total_vuln_success += page_success
            page_logger = (
                f"Successfully fetched {page_success}"
                " Vulnerability record(s)"
            )
            if page_skip > 0:
                page_logger += (
                    f", skipped fetching {page_skip} Vulnerability"
                    " record(s) as they did not correspond to any application"
                )
            self.logger.info(
                f"{self.log_prefix}: {page_logger} in page"
                f" {page_number}. Total records fetched:"
                f" {total_vuln_success}."
            )
            cursor = response.get("pagination", {}).get("nextCursor", "")
            if not cursor:
                break
            query_params.update({"cursor": cursor})
            page_number += 1

        self.logger.info(
            f"{self.log_prefix}: Successfully fetched"
            f" {total_vuln_success} Vulnerability"
            f" record(s) from {PLATFORM_NAME}."
        )
        self.logger.info(
            f"{self.log_prefix}: Successfully created"
            f" {len(application_vulnerability)} Application Vulnerability"
            f" record(s) from {total_app_success} Application and"
            f" {total_vuln_success} Vulnerability record(s)."
        )
        return application_vulnerability

    def fetch_records(self, entity: str) -> List:
        """Fetch records from SentinelOne.

        Args:
            entity (str): Entity name (Endpoints, Identity, Application
                Vulnerabilities).

        Returns:
            list: List of fetched records.
        """
        entity_name = entity.lower()
        fetched_records = []
        base_url, auth_headers, _, site_id = (
            self._get_basic_api_parameters(
                configuration=self.configuration
            )
        )
        if entity_name == "users (identity)":
            fetched_records = self._get_identity_data(
                base_url=base_url,
                auth_header=auth_headers,
                site_id=site_id,
                context={}
            )
            return fetched_records
        elif entity_name == "devices (endpoints)":
            fetched_records = self._get_endpoint_data(
                base_url=base_url,
                auth_header=auth_headers,
                site_id=site_id,
                context={}
            )
            return fetched_records
        elif entity_name == "applications":
            fetched_records = self._get_application_vulnerability_data(
                base_url=base_url,
                auth_headers=auth_headers,
                site_id=site_id,
                context={}
            )
            return fetched_records
        else:
            err_msg = (
                f"Invalid entity found. {PLATFORM_NAME} plugin "
                "only supports 'Devices (Endpoints)', 'Users (Identity)'"
                " or 'Applications' Entity."
            )
            resolution = (
                "Ensure that the entity is 'Devices (Endpoints)', 'Users"
                " (Identity)' or 'Applications'.")
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                resolution=resolution,
            )
            raise SentinelOneSingularityXDRPluginException(err_msg)

    def update_records(
        self, entity: str, records: List
    ) -> List:
        """Update records with latest data from SentinelOne.

        For Endpoints: refreshes network status, tags, infection
        status, and risk factors.
        For Identity: refreshes infection status, asset criticality,
        tags, and risk factors.
        For Application Vulnerabilities: re-fetches vulnerability details.

        Args:
            entity (str): Entity name.
            records (list): Existing records to update.

        Returns:
            list: Updated records.
        """
        return []

    def _validate_parameters(
        self,
        field_name: str,
        field_value,
        field_type: type,
        parameter_type: Literal["configuration", "action"],
        allowed_values: Dict = None,
        custom_validation_func: Callable = None,
        is_required: bool = True,
        validation_err_msg: str = "Validation error occurred. ",
        check_dollar: bool = False,
        is_source_field_allowed: bool = True,
    ) -> Union[ValidationResult, None]:
        """Validate a configuration or action parameter.

        Args:
            field_name (str): Parameter name.
            field_value: Parameter value.
            field_type (type): Expected type.
            allowed_values (Dict, optional): Dict of allowed values.
            custom_validation_func (Callable, optional): Custom
                validation function.
            is_required (bool): Whether the field is required.
            validation_err_msg (str): Error message prefix.
            check_dollar (bool): Skip validation if source field.
            is_source_field_allowed (bool): Whether source fields
                are allowed.

        Returns:
            ValidationResult or None.
        """
        if (
            not is_source_field_allowed
            and isinstance(field_value, str)
            and "$" in field_value
        ):
            err_msg = (
                f"'{field_name}' can only contain the Static Field."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                resolution=(
                    f"Ensure that Static is selected for the field"
                    f" '{field_name}' in the action configuration."
                ),
            )
            return ValidationResult(success=False, message=err_msg)

        if field_type is str and isinstance(field_value, str):
            field_value = field_value.strip()

        if (
            check_dollar
            and isinstance(field_value, str)
            and "$" in field_value
        ):
            self.logger.info(
                message=(
                    f"{self.log_prefix}: '{field_name}' contains"
                    " the Source Field hence validation for this"
                    " field will be performed while executing the"
                    " action."
                ),
            )
            return None

        if (
            is_required
            and not isinstance(field_value, (int, float))
            and not field_value
        ):
            err_msg = (
                f"'{field_name}' is a required {parameter_type} parameter."
            )
            self.logger.error(
                message=(
                    f"{self.log_prefix}: {validation_err_msg}{err_msg}"
                ),
                resolution=(
                    "Ensure that some value is provided for field"
                    f" {field_name}."
                ),
            )
            return ValidationResult(success=False, message=err_msg)

        if is_required and not isinstance(field_value, field_type):
            err_msg = (
                f"Invalid value provided for the {parameter_type}"
                f" parameter '{field_name}'."
            )
            self.logger.error(
                message=(
                    f"{self.log_prefix}:"
                    f" {validation_err_msg}{err_msg}"
                ),
                resolution=(
                    f"Ensure that a valid value is provided for {field_name}"
                    " field."
                )
            )
            return ValidationResult(success=False, message=err_msg)

        if custom_validation_func and not custom_validation_func(
            field_value
        ):
            err_msg = (
                f"Invalid value provided for the {parameter_type}"
                f" parameter '{field_name}'."
            )
            self.logger.error(
                message=(
                    f"{self.log_prefix}:"
                    f" {validation_err_msg}{err_msg}"
                ),
                resolution=(
                    f"Ensure that a valid value is provided for {field_name}"
                    " field."
                )
            )
            return ValidationResult(success=False, message=err_msg)

        if allowed_values and isinstance(field_value, str):
            if field_value not in allowed_values:
                if len(allowed_values) <= 5:
                    err_msg = (
                        f"Invalid value provided for the {parameter_type}"
                        f" parameter '{field_name}'. Allowed values"
                        f" are {', '.join(str(v) for v in allowed_values)}."
                    )
                else:
                    err_msg = (
                        f"Invalid value for '{field_name}' provided"
                        f" in the {parameter_type} parameters."
                    )
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: {validation_err_msg}"
                        f"{err_msg}"
                    ),
                    resolution=(
                        "Ensure that a valid value is provided from the"
                        " allowed values."
                    )
                )
                return ValidationResult(
                    success=False, message=err_msg
                )
        return None

    def get_actions(self) -> List[ActionWithoutParams]:
        """Get available actions.

        Returns:
            List[ActionWithoutParams]: List of supported actions.
        """
        return [
            ActionWithoutParams(
                label="Manage Device Tags",
                value="manage_endpoint_tags",
            ),
            ActionWithoutParams(
                label="Move Device to Group",
                value="group_management",
            ),
            ActionWithoutParams(
                label="Isolate/Undo Isolate",
                value="network_isolation",
            ),
            ActionWithoutParams(
                label="Update Asset Criticality",
                value="update_criticality",
            ),
            ActionWithoutParams(
                label="Run Scan",
                value="scan_endpoint",
            ),
            ActionWithoutParams(
                label="Reboot Device",
                value="reboot_endpoint",
            ),
            ActionWithoutParams(
                label="No Action",
                value="generate",
            ),
        ]

    def get_action_params(self, action: Action) -> List:
        """Get action parameters for the given action.

        Args:
            action (Action): Action object.

        Returns:
            list: List of action parameter configurations.
        """
        if action.value == "generate":
            return []

        base_url, auth_header, _, site_id = (
            self._get_basic_api_parameters(
                configuration=self.configuration
            )
        )

        if action.value == "manage_endpoint_tags":
            return [
                {
                    "label": "Action Type",
                    "key": "tag_action_type",
                    "type": "choice",
                    "choices": [
                        {"key": "Add Tag(s)", "value": "add"},
                        {"key": "Remove Tag(s)", "value": "remove"},
                    ],
                    "default": "add",
                    "mandatory": True,
                    "description": (
                        "Select action to perform on device(s)."
                    ),
                },
                {
                    "label": "Tag Key",
                    "key": "tag_key",
                    "type": "text",
                    "default": "Netskope CE",
                    "mandatory": False,
                    "description": (
                        "Key of the tag to add or remove."
                    ),
                },
                {
                    "label": "Tag Value",
                    "key": "tag_value",
                    "type": "text",
                    "default": "",
                    "mandatory": True,
                    "description": (
                        "Value of the tag to add or remove."
                    ),
                },
                {
                    "label": "Agent ID",
                    "key": "agent_id",
                    "type": "text",
                    "default": "",
                    "mandatory": True,
                    "description": (
                        "Agent ID of the device to perform the"
                        " tag action on."
                    ),
                },
            ]

        if action.value == "group_management":
            groups = self._get_groups(
                base_url, auth_header, site_id
            )
            groups.update({"Create New Group": "create_new_group"})
            choices = [
                {"key": group_name, "value": f"{group_name}##+##{group_id}"}
                for group_name, group_id in groups.items()
            ]
            default = choices[0]["value"] if choices else "create_new_group"
            return [
                {
                    "label": "Group Name",
                    "key": "group_name",
                    "type": "choice",
                    "choices": choices,
                    "default": default,
                    "mandatory": True,
                    "description": (
                        "Name of group to move the device to."
                        " Select 'Create New Group' to create a new"
                        " group."
                    ),
                },
                {
                    "label": "Create Group",
                    "key": "create_group",
                    "type": "text",
                    "default": "",
                    "mandatory": False,
                    "description": (
                        "Name of group to be created. Applicable only"
                        " when 'Create New Group' is selected in"
                        " 'Group Name' action parameter."
                    ),
                },
                {
                    "label": "Group Type",
                    "key": "group_type",
                    "type": "choice",
                    "choices": [
                        {"key": "Manual Group", "value": "static"},
                        {"key": "Pinned Group", "value": "pinned"},
                    ],
                    "default": "static",
                    "mandatory": False,
                    "description": (
                        "Type of group to create. Applicable only"
                        " when 'Create New Group' is selected in"
                        " 'Group Name' action parameter."
                    ),
                },
                {
                    "label": "Agent ID",
                    "key": "agent_id",
                    "type": "text",
                    "default": "",
                    "mandatory": True,
                    "description": (
                        "Agent ID of the device to move to the"
                        " group."
                    ),
                },
            ]

        if action.value == "network_isolation":
            return [
                {
                    "label": "Action Type",
                    "key": "network_action_type",
                    "type": "choice",
                    "choices": [
                        {
                            "key": "Isolate (Disconnect from network)",
                            "value": "isolate",
                        },
                        {
                            "key": "Undo Isolate (Reconnect to Network)",
                            "value": "undo_isolate",
                        },
                    ],
                    "default": "isolate",
                    "mandatory": True,
                    "description": "The action type to perform.",
                },
                {
                    "label": "Agent ID",
                    "key": "agent_id",
                    "type": "text",
                    "default": "",
                    "mandatory": True,
                    "description": (
                        "The ID of device to perform the action on."
                    ),
                },
            ]

        if action.value == "update_criticality":
            return [
                {
                    "label": "Criticality Value",
                    "key": "criticality_value",
                    "type": "choice",
                    "choices": [
                        {"key": "Low", "value": "low"},
                        {"key": "Medium", "value": "medium"},
                        {"key": "High", "value": "high"},
                        {"key": "Critical", "value": "critical"},
                        {"key": "Clear", "value": "clear"},
                    ],
                    "default": "low",
                    "mandatory": True,
                    "description": (
                        "Criticality level to assign to the asset."
                    ),
                },
                {
                    "label": "Asset ID",
                    "key": "asset_id",
                    "type": "text",
                    "default": "",
                    "mandatory": True,
                    "description": (
                        "The ID of asset whose criticality is to be"
                        " changed."
                    ),
                },
            ]

        if action.value == "scan_endpoint":
            return [
                {
                    "label": "Scan Type",
                    "key": "scan_type",
                    "type": "choice",
                    "choices": [
                        {
                            "key": "Full Disk Scan",
                            "value": "full_disk_scan",
                        },
                        {
                            "key": "Application Vulnerability Scan",
                            "value": "app_vulnerability_scan",
                        },
                    ],
                    "default": "full_disk_scan",
                    "mandatory": True,
                    "description": "Type of scan to run.",
                },
                {
                    "label": "Agent ID",
                    "key": "agent_id",
                    "type": "text",
                    "default": "",
                    "mandatory": True,
                    "description": (
                        "The ID of device to run the scan on."
                    ),
                },
            ]

        if action.value == "reboot_endpoint":
            return [
                {
                    "label": "Agent ID",
                    "key": "agent_id",
                    "type": "text",
                    "default": "",
                    "mandatory": True,
                    "description": (
                        "The ID of device to reboot."
                    ),
                },
            ]

        return []

    def validate_action(
        self, action: Action
    ) -> ValidationResult:
        """Validate action configuration.

        Args:
            action (Action): Action object.

        Returns:
            ValidationResult: Validation result.
        """
        supported_actions = [
            "manage_endpoint_tags",
            "group_management",
            "network_isolation",
            "update_criticality",
            "scan_endpoint",
            "reboot_endpoint",
            "generate",
        ]
        action_value = action.value
        action_params = action.parameters

        if action_value not in supported_actions:
            err_msg = (
                f"Unsupported action '{action_value}' provided in"
                " the action configuration. Supported actions are:"
                " 'Manage Device Tags', 'Move Device to Group',"
                " 'Isolate/Undo Isolate', 'Update Asset Criticality',"
                " 'Run Scan', 'Reboot Device', 'No Action'."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                resolution=(
                    "Ensure that the action is selected from the"
                    " list of supported actions in the action"
                    " configuration."
                ),
            )
            return ValidationResult(
                success=False, message=err_msg
            )

        if action_value == "generate":
            return ValidationResult(
                success=True, message="Validation successful."
            )

        if action_value == "manage_endpoint_tags":
            tag_action_type = action_params.get(
                "tag_action_type", ""
            )
            if validation_result := self._validate_parameters(
                field_name="Action Type",
                field_value=tag_action_type,
                field_type=str,
                parameter_type="action",
                is_required=True,
                is_source_field_allowed=False,
                allowed_values=["add", "remove"],
            ):
                return validation_result
            tag_key = action_params.get("tag_key", "")
            if validation_result := self._validate_parameters(
                field_name="Tag Key",
                field_value=tag_key,
                field_type=str,
                parameter_type="action",
                is_required=False,
                is_source_field_allowed=False,
            ):
                return validation_result
            if not self.s1_singularity_xdr_helper._validate_tag_string(
                "Tag Key", tag_key
            ):
                self.logger.error(
                    message="'Tag Key' must not exceed 500 characters.",
                    resolution=(
                        "Ensure the length for 'Tag Key' parameter"
                        " is less than 500 characters."
                    ),
                )
                return ValidationResult(
                    success=False,
                    message="'Tag Key' must not exceed 500 characters.",
                )
            if not self.s1_singularity_xdr_helper._validate_tag_no_colon(
                "Tag Key", tag_key
            ):
                self.logger.error(
                    message="'Tag Key' must not contain the character ':'.",
                    resolution=(
                        "Ensure that 'Tag Key' action parameter value does"
                        " not contain the ':' character."
                    ),
                )
                return ValidationResult(
                    success=False,
                    message="'Tag Key' must not contain the character ':'.",
                )
            tag_value = action_params.get("tag_value", "")
            if validation_result := self._validate_parameters(
                field_name="Tag Value",
                field_value=tag_value,
                field_type=str,
                parameter_type="action",
                is_required=True,
                check_dollar=True,
                custom_validation_func=self.s1_singularity_xdr_helper._validate_tag_not_empty,
            ):
                return validation_result
            if not self.s1_singularity_xdr_helper._validate_tag_string(
                "Tag Value", tag_value
            ):
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: Invalid value for the action"
                        " parameter 'Tag Value'."
                    ),
                    resolution=(
                        "Ensure the length for 'Tag Value' parameter"
                        " is less than 500 characters."
                    ),
                )
                return ValidationResult(
                    success=False,
                    message=(
                        "'Tag Value' must not exceed 500 characters"
                        " per tag."
                    ),
                )
            if not self.s1_singularity_xdr_helper._validate_tag_no_colon(
                "Tag Value", tag_value
            ):
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: Invalid value for the action"
                        " parameter 'Tag Value'."
                    ),
                    resolution=(
                        "Ensure that 'Tag Value' action parameter value does"
                        " not contain the ':' character."
                    ),
                )
                return ValidationResult(
                    success=False,
                    message=(
                        "'Tag Value' must not contain the character ':'."
                    ),
                )
            agent_id = action_params.get("agent_id", "")
            if validation_result := self._validate_parameters(
                field_name="Agent ID",
                field_value=agent_id,
                field_type=str,
                parameter_type="action",
                is_required=True,
                check_dollar=True,
            ):
                return validation_result

        if action_value == "group_management":
            group_name = action_params.get("group_name", "")
            if validation_result := self._validate_parameters(
                field_name="Group Name",
                field_value=group_name,
                field_type=str,
                parameter_type="action",
                is_required=True,
                is_source_field_allowed=False,
            ):
                return validation_result
            group_id_part = (
                group_name.split("##+##")[1]
                if "##+##" in group_name
                else ""
            )
            if group_id_part == "create_new_group":
                create_group = action_params.get(
                    "create_group", ""
                )
                if validation_result := self._validate_parameters(
                    field_name="Create Group",
                    field_value=create_group,
                    field_type=str,
                    parameter_type="action",
                    is_required=True,
                    check_dollar=True,
                    is_source_field_allowed=False,
                ):
                    return validation_result
                if not self.s1_singularity_xdr_helper._validate_group_name(
                    create_group
                ):
                    self.logger.error(
                        message=(
                            f"{self.log_prefix}: Invalid value for the action"
                            " parameter 'Create Group'."
                        ),
                        resolution=(
                            "'Create Group' action parameter must not contain"
                            " angular brackets (< or >)."
                        )
                    )
                    return ValidationResult(
                        success=False,
                        message=(
                            "'Create Group' must not contain"
                            " angular brackets (< or >)."
                        ),
                    )
                group_type = action_params.get(
                    "group_type", ""
                )
                if validation_result := self._validate_parameters(
                    field_name="Group Type",
                    field_value=group_type,
                    field_type=str,
                    parameter_type="action",
                    is_required=True,
                    is_source_field_allowed=False,
                    allowed_values=["static", "pinned"],
                ):
                    return validation_result
            agent_id = action_params.get(
                "agent_id", ""
            )
            if validation_result := self._validate_parameters(
                field_name="Agent ID",
                field_value=agent_id,
                field_type=str,
                parameter_type="action",
                is_required=True,
                check_dollar=True,
            ):
                return validation_result

        if action_value == "network_isolation":
            network_action_type = action_params.get(
                "network_action_type", ""
            )
            if validation_result := self._validate_parameters(
                field_name="Action Type",
                field_value=network_action_type,
                field_type=str,
                parameter_type="action",
                is_required=True,
                is_source_field_allowed=False,
                allowed_values=["isolate", "undo_isolate"],
            ):
                return validation_result
            agent_id = action_params.get("agent_id", "")
            if validation_result := self._validate_parameters(
                field_name="Agent ID",
                field_value=agent_id,
                field_type=str,
                parameter_type="action",
                is_required=True,
                check_dollar=True,
            ):
                return validation_result

        if action_value == "update_criticality":
            criticality_value = action_params.get(
                "criticality_value", ""
            )
            if validation_result := self._validate_parameters(
                field_name="Criticality Value",
                field_value=criticality_value,
                field_type=str,
                parameter_type="action",
                is_required=True,
                is_source_field_allowed=True,
                check_dollar=True,
                allowed_values=list(
                    ASSET_CRITICALITY_MAP.keys()
                ),
            ):
                return validation_result
            asset_id = action_params.get("asset_id", "")
            if validation_result := self._validate_parameters(
                field_name="Asset ID",
                field_value=asset_id,
                field_type=str,
                parameter_type="action",
                is_required=True,
                check_dollar=True,
            ):
                return validation_result

        if action_value == "scan_endpoint":
            scan_type = action_params.get("scan_type", "")
            if validation_result := self._validate_parameters(
                field_name="Scan Type",
                field_value=scan_type,
                field_type=str,
                parameter_type="action",
                is_required=True,
                is_source_field_allowed=False,
                allowed_values=[
                    "full_disk_scan",
                    "app_vulnerability_scan",
                ],
            ):
                return validation_result
            agent_id = action_params.get("agent_id", "")
            if validation_result := self._validate_parameters(
                field_name="Agent ID",
                field_value=agent_id,
                field_type=str,
                parameter_type="action",
                is_required=True,
                check_dollar=True,
            ):
                return validation_result

        if action_value == "reboot_endpoint":
            agent_id = action_params.get("agent_id", "")
            if validation_result := self._validate_parameters(
                field_name="Agent ID",
                field_value=agent_id,
                field_type=str,
                parameter_type="action",
                is_required=True,
                check_dollar=True,
            ):
                return validation_result

        return ValidationResult(
            success=True, message="Validation successful."
        )

    # ----------------------------------------------------------------
    # Action helper methods
    # ----------------------------------------------------------------

    @exception_handler
    def _get_groups(
        self,
        base_url: str,
        auth_header: Dict,
        site_id: str,
        context: Dict = {},
    ) -> Dict[str, str]:
        """Fetch groups from SentinelOne.

        Args:
            base_url (str): Base URL.
            auth_header (Dict): Authorization header.
            site_id (str): Site ID.

        Returns:
            Dict: Dict with group 'name' as the key and 'id' as the value.
        """
        context["log_in_custom_error"] = True
        url = f"{base_url}{GROUPS_ENDPOINT}"
        page_number = 1
        query_params = {
            "siteIds": site_id,
            "limit": GROUP_PAGE_SIZE,
            "skipCount": True,
            "sortBy": "name",
            "sortOrder": "asc",
            "types": "static,pinned",
        }
        groups = {}
        while True:
            logger_msg = (
                f"fetching groups for page {page_number}"
                f" from {PLATFORM_NAME}"
            )
            context["logger_msg"] = logger_msg
            response = self.s1_singularity_xdr_helper.api_helper(
                logger_msg=logger_msg,
                url=url,
                method="GET",
                params=query_params,
                headers=auth_header,
                is_handle_error_required=True,
                ssl_validation=self.ssl_validation,
                proxy=self.proxy,
            )
            group_list = response.get("data", [])
            if not group_list:
                break
            for group in group_list:
                group_id = group.get("id")
                group_name = group.get("name")
                if group_id and group_name:
                    groups[group_name] = str(group_id)
            cursor = response.get("pagination", {}).get("nextCursor", "")
            if not cursor:
                break
            query_params.update({"cursor": cursor})
            page_number += 1
        self.logger.info(
            f"{self.log_prefix}: Successfully fetched {len(groups)} groups"
            f" from {PLATFORM_NAME}."
        )
        return groups

    @exception_handler
    def _get_tags(
        self,
        base_url: str,
        auth_header: Dict,
        site_id: str,
        context: Dict = {},
    ) -> Dict[str, Dict[str, str]]:
        """Fetch agent tags from SentinelOne.

        Args:
            base_url (str): Base URL.
            auth_header (Dict): Authorization header.
            site_id (str): SentinelOne site ID.
            context (Dict): Logging context dictionary.

        Returns:
            Dict[str, Dict[str, str]]: Nested dict mapping
                tag_key -> {tag_value: tag_id}.
        """
        context["log_in_custom_error"] = True
        url = f"{base_url}{TAGS_ENDPOINT}"
        page_number = 1
        query_params = {
            "siteIds": site_id,
            "limit": PAGE_SIZE,
            "skipCount": True,
            "sortBy": "key",
            "sortOrder": "asc",
            "includeEndpointCounters": False,
            "includeChildren": True,
        }
        tags = {}
        count = 0
        while True:
            logger_msg = (
                f"fetching tags for page {page_number}"
                f" from {PLATFORM_NAME}"
            )
            context["logger_msg"] = logger_msg
            response = self.s1_singularity_xdr_helper.api_helper(
                logger_msg=logger_msg,
                url=url,
                method="GET",
                params=query_params,
                headers=auth_header,
                is_handle_error_required=True,
                ssl_validation=self.ssl_validation,
                proxy=self.proxy,
            )
            tag_list = response.get("data", [])
            if not tag_list:
                break
            for tag in tag_list:
                tag_id = tag.get("id")
                tag_key = tag.get("key") if tag.get("key") is not None else ""
                tag_value = tag.get("value")
                if tag_id:
                    count += 1
                    tags.setdefault(tag_key, {}).update(
                        {tag_value: str(tag_id)}
                    )
            cursor = response.get("pagination", {}).get("nextCursor", "")
            if not cursor:
                break
            query_params.update({"cursor": cursor})
            page_number += 1
        self.logger.info(
            f"{self.log_prefix}: Successfully fetched {count}"
            f" tags from {PLATFORM_NAME}."
        )
        return tags

    @exception_handler
    def _create_group(
        self,
        base_url: str,
        auth_header: Dict,
        site_id: str,
        group_name: str,
        group_type: str,
        context: Dict = {},
    ) -> str:
        """Create a new group on SentinelOne.

        Args:
            base_url (str): Base URL.
            auth_header (Dict): Authorization header.
            site_id (str): Site ID.
            group_name (str): Name of the group.
            group_type (str): Type of the group (static/pinned).

        Returns:
            str: ID of the created group.
        """
        context["log_in_custom_error"] = True
        url = f"{base_url}{GROUPS_ENDPOINT}"
        logger_msg = (
            f"creating {group_type} group '{group_name}' on {PLATFORM_NAME}"
        )
        context["logger_msg"] = logger_msg
        request_body = {
            "data": {
                "name": group_name,
                "description": (
                    "Group Created via Cloud Exchange"
                ),
                "inherits": True,
                "siteId": site_id,
                "type": group_type,
            }
        }
        auth_header["Content-Type"] = "application/json"
        resp_json = self.s1_singularity_xdr_helper.api_helper(
            logger_msg=logger_msg,
            url=url,
            method="POST",
            headers=auth_header,
            json=request_body,
            is_handle_error_required=True,
            ssl_validation=self.ssl_validation,
            proxy=self.proxy,
        )
        return resp_json.get("data", {}).get("id", "")

    @exception_handler
    def _create_tag(
        self,
        base_url: str,
        auth_header: Dict,
        site_id: str,
        tag_key: str,
        tag_value: str,
        context: Dict = {},
    ) -> str:
        """Create a new agent tag on SentinelOne.

        Args:
            base_url (str): Base URL.
            auth_header (Dict): Authorization header.
            site_id (str): Site ID.
            tag_key (str): Tag key.
            tag_value (str): Tag value.

        Returns:
            str: ID of the created tag.
        """
        context["log_in_custom_error"] = True
        url = f"{base_url}{TAG_MANAGER_ENDPOINT}"
        logger_msg = (
            f"creating tag '{tag_key}:{tag_value}' on {PLATFORM_NAME}"
        )
        context["logger_msg"] = logger_msg
        request_body = {
            "data": {
                "key": tag_key,
                "type": "agents",
                "value": tag_value,
                "description": (
                    "Tag created from Cloud Exchange"
                ),
            },
            "filter": {
                "siteIds": [site_id],
            },
        }
        auth_header["Content-Type"] = "application/json"
        resp_json = self.s1_singularity_xdr_helper.api_helper(
            logger_msg=logger_msg,
            url=url,
            method="POST",
            headers=auth_header,
            json=request_body,
            is_handle_error_required=True,
            ssl_validation=self.ssl_validation,
            proxy=self.proxy,
        )
        return resp_json.get("data", {}).get("id", "")

    @exception_handler
    def _move_agent_to_group(
        self,
        base_url: str,
        auth_header: Dict,
        site_id: str,
        group_id: str,
        group_name: str,
        agent_ids: List,
        batch_number: int = 1,
        context: Dict = {},
    ) -> int:
        """Move agents to a group.

        Args:
            base_url (str): Base URL.
            auth_header (Dict): Authorization header.
            site_id (str): Site ID.
            group_id (str): Group ID.
            agent_ids (list): List of agent IDs.
            batch_number (int): Current batch number.

        Returns:
            int: Number of agents moved.
        """
        context["log_in_custom_error"] = True
        url = f"{base_url}{MOVE_AGENTS_ENDPOINT.format(group_id=group_id)}"
        logger_msg = (
            f"moving {len(agent_ids)} device(s) to group '{group_name}'"
            f" in batch {batch_number}"
        )
        context["logger_msg"] = logger_msg
        request_body = {
            "filter": {
                "agentIds": agent_ids,
                "siteIds": [site_id],
            }
        }
        auth_header["Content-Type"] = "application/json"
        resp_json = self.s1_singularity_xdr_helper.api_helper(
            logger_msg=logger_msg,
            url=url,
            method="PUT",
            headers=auth_header,
            json=request_body,
            is_handle_error_required=True,
            ssl_validation=self.ssl_validation,
            proxy=self.proxy,
        )
        return resp_json.get("data", {}).get("agentsMoved", 0)

    @exception_handler
    def _manage_tag(
        self,
        base_url: str,
        auth_header: Dict,
        site_id: str,
        tag_id: str,
        tag_key_value: str,
        agent_ids: List,
        operation: str,
        batch_number: int = 1,
        context: Dict = {},
    ) -> int:
        """Add or remove a tag from agents.

        Args:
            base_url (str): Base URL.
            auth_header (Dict): Authorization header.
            site_id (str): Site ID.
            tag_id (str): Tag ID.
            agent_ids (list): List of agent IDs.
            operation (str): 'add' or 'remove'.
            batch_number (int): Current batch number.

        Returns:
            int: Number of agents affected.
        """
        context["log_in_custom_error"] = True
        url = f"{base_url}{MANAGE_TAGS_ENDPOINT}"
        operation_logger = (
            f"removing tag '{tag_key_value}' from"
            if operation == "remove"
            else f"adding tag '{tag_key_value}' to"
        )
        logger_msg = (
            f"{operation_logger} devices in batch {batch_number}"
        )
        context["logger_msg"] = logger_msg
        request_body = {
            "data": [
                {
                    "operation": operation,
                    "tagId": tag_id,
                }
            ],
            "filter": {
                "siteIds": [site_id],
                "ids": agent_ids,
            },
        }
        auth_header["Content-Type"] = "application/json"
        resp_json = self.s1_singularity_xdr_helper.api_helper(
            logger_msg=logger_msg,
            url=url,
            method="POST",
            headers=auth_header,
            json=request_body,
            is_handle_error_required=True,
            ssl_validation=self.ssl_validation,
            proxy=self.proxy,
        )
        return resp_json.get("data", {}).get("affected", 0)

    @exception_handler
    def _network_action(
        self,
        base_url: str,
        auth_header: Dict,
        site_id: str,
        agent_ids: List,
        action: Literal["connect", "disconnect"],
        batch_number: int = 1,
        context: Dict = {},
    ) -> int:
        """Isolate or reconnect device(s).

        Args:
            base_url (str): Base URL.
            auth_header (Dict): Authorization header.
            site_id (str): Site ID.
            agent_ids (list): List of agent IDs.
            action (Literal): 'disconnect' or 'connect'.
            batch_number (int): Current batch number.

        Returns:
            int: Number of agents affected.
        """
        context["log_in_custom_error"] = True
        if action == "disconnect":
            action_logger = "performing network isolation on"
            endpoint = NETWORK_DISCONNECT_ENDPOINT
        elif action == "connect":
            action_logger = "removing network isolation for"
            endpoint = NETWORK_CONNECT_ENDPOINT
        else:
            err_msg = (
                "Invalid value received for action parameter. Valid values are"
                " 'connect' or 'disconnect'."
            )
            raise SentinelOneSingularityXDRPluginException(err_msg)
        url = f"{base_url}{endpoint}"
        logger_msg = (
            f"{action_logger} devices in batch {batch_number}"
        )
        context["logger_msg"] = logger_msg
        request_body = {
            "filter": {
                "ids": agent_ids,
                "siteIds": [site_id],
            }
        }
        auth_header["Content-Type"] = "application/json"
        resp_json = self.s1_singularity_xdr_helper.api_helper(
            logger_msg=logger_msg,
            url=url,
            method="POST",
            headers=auth_header,
            json=request_body,
            is_handle_error_required=True,
            ssl_validation=self.ssl_validation,
            proxy=self.proxy,
        )
        return resp_json.get("data", {}).get("affected", len(agent_ids))

    @exception_handler
    def _update_asset_criticality_action(
        self,
        base_url: str,
        auth_header: Dict,
        site_id: str,
        asset_ids: List,
        batch_number: int,
        criticality_action_value: str,
        criticality_label: str,
        context: Dict = {},
    ) -> None:
        """Update asset criticality.

        Args:
            base_url (str): Base URL.
            auth_header (Dict): Authorization header.
            site_id (str): Site ID.
            asset_ids (list): List of asset IDs.
            criticality (str): Criticality level key.
        """
        context["log_in_custom_error"] = True
        url = f"{base_url}{ASSET_ACTION_ENDPOINT}"
        if not criticality_action_value:
            err_msg = (
                f"Invalid criticality value '{criticality_label}'."
                f" Allowed: {', '.join(ASSET_CRITICALITY_MAP.keys())}."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}"
            )
            raise SentinelOneSingularityXDRPluginException(err_msg)

        operation_logger = (
            "clearing criticality"
            if criticality_label == "clear"
            else f"updating criticality to '{criticality_label}'"
        )
        logger_msg = (
            f"{operation_logger} for {len(asset_ids)} asset(s) in batch"
            f" {batch_number}"
        )
        context["logger_msg"] = logger_msg
        request_body = {
            "actionName": criticality_action_value,
            "id__in": asset_ids,
        }
        auth_header["Content-Type"] = "application/json"
        self.s1_singularity_xdr_helper.api_helper(
            logger_msg=logger_msg,
            url=url,
            method="POST",
            headers=auth_header,
            params={"siteIds": site_id},
            json=request_body,
            is_handle_error_required=True,
            ssl_validation=self.ssl_validation,
            proxy=self.proxy,
        )

    @exception_handler
    def _scan_action(
        self,
        base_url: str,
        auth_header: Dict,
        site_id: str,
        agent_ids: List,
        scan_type: Literal["disk", 'vuln'],
        batch_number: int = 1,
        context: Dict = {},
    ) -> int:
        """Initiate a scan on device(s).

        Args:
            base_url (str): Base URL.
            auth_header (Dict): Authorization header.
            site_id (str): Site ID.
            agent_ids (list): List of agent IDs.
            scan_type (str): 'disk' or 'vuln'.
            batch_number (int): Current batch number.
        """
        context["log_in_custom_error"] = True
        if scan_type == "disk":
            scan_label = "Full Disk"
            url = f"{base_url}{SCAN_ENDPOINT}"
            request_body = {
                "filter": {
                    "ids": agent_ids,
                    "siteIds": [site_id],
                }
            }
        elif scan_type == "vuln":
            scan_label = "Application Vulnerability"
            url = f"{base_url}{VULN_SCAN_ENDPOINT}"
            request_body = {
                "filter": {
                    "siteIds": [site_id],
                    "agentIds": agent_ids,
                }
            }
        else:
            err_msg = (
                "Invalid value received for scan_type parameter. Valid values"
                " are 'disk' or 'vuln'."
            )
            raise SentinelOneSingularityXDRPluginException(err_msg)
        logger_msg = (
            f"initiating {scan_label} scan on {len(agent_ids)} devices in"
            f" batch {batch_number}"
        )
        context["logger_msg"] = logger_msg
        auth_header["Content-Type"] = "application/json"
        response = self.s1_singularity_xdr_helper.api_helper(
            logger_msg=logger_msg,
            url=url,
            method="POST",
            headers=auth_header,
            json=request_body,
            is_handle_error_required=True,
            ssl_validation=self.ssl_validation,
            proxy=self.proxy,
        )
        if scan_type == "disk":
            affected = int(
                response.get("data", {}).get("affected", len(agent_ids))
            )
        elif scan_type == "vuln":
            affected = len(agent_ids)
        return affected

    @exception_handler
    def _reboot_action(
        self,
        base_url: str,
        auth_header: Dict,
        site_id: str,
        agent_ids: List,
        batch_number: int = 1,
        context: Dict = {},
    ) -> int:
        """Reboot device(s).

        Args:
            base_url (str): Base URL.
            auth_header (Dict): Authorization header.
            site_id (str): Site ID.
            agent_ids (list): List of agent IDs.
            batch_number (int): Current batch number.

        Returns:
            int: Number of agents affected.
        """
        context["log_in_custom_error"] = True
        url = f"{base_url}{REBOOT_ENDPOINT}"
        logger_msg = (
            f"rebooting {len(agent_ids)} devices in batch {batch_number}"
        )
        context["logger_msg"] = logger_msg
        request_body = {
            "filter": {
                "siteIds": [site_id],
                "ids": agent_ids,
            }
        }
        auth_header["Content-Type"] = "application/json"
        resp_json = self.s1_singularity_xdr_helper.api_helper(
            logger_msg=logger_msg,
            url=url,
            method="POST",
            headers=auth_header,
            json=request_body,
            is_handle_error_required=True,
            ssl_validation=self.ssl_validation,
            proxy=self.proxy,
        )
        return resp_json.get("data", {}).get("affected", 0)

    def execute_actions(self, actions: List[Action]):
        """Execute bulk actions.

        Platform calls this method once with all Action objects.

        Args:
            actions (List[Action]): List of Action objects.
        """
        if not actions:
            return

        # Get first action to determine action value
        first_action_dict = actions[0]
        action_value = first_action_dict.get(
            "params", {}
        ).value
        action_label = first_action_dict.get("params", {}).label

        if action_value == "generate":
            self.logger.debug(
                f"{self.log_prefix}: Skipping 'No Action' for"
                f" {len(actions)} record(s)."
            )
            return ActionResult(
                success=True,
                message="No action performed.",
                failed_action_ids=[],
            )

        base_url, auth_header, _, site_id = (
            self._get_basic_api_parameters(
                configuration=self.configuration
            )
        )

        action_handlers: Dict[str, Callable] = {
            "network_isolation": self._execute_network_isolation_action,
            "scan_endpoint": self._execute_scan_endpoint_action,
            "reboot_endpoint": self._execute_reboot_endpoint_action,
            "manage_endpoint_tags": self._execute_manage_tags_action,
            "group_management": self._execute_group_management_action,
            "update_criticality": self._execute_update_criticality_action,
        }

        handler = action_handlers.get(action_value)
        if handler is None:
            err_msg = (
                f"Unsupported action '{action_value}' provided in"
                " the action configuration. Supported actions are:"
                " 'Manage Device Tags', 'Move Device to Group',"
                " 'Isolate/Undo Isolate', 'Update Asset Criticality',"
                " 'Run Scan', 'Reboot Device', 'No Action'."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                resolution=(
                    "Ensure that the action is selected from the"
                    " list of supported actions in the action"
                    " configuration."
                ),
            )
            raise SentinelOneSingularityXDRPluginException(err_msg)

        return handler(
            actions=actions,
            action_label=action_label,
            base_url=base_url,
            auth_header=auth_header,
            site_id=site_id,
        )

    def _collect_agent_ids(
        self, actions: List[Action]
    ) -> Tuple[List[str], Dict[str, Optional[str]]]:
        """Collect all agent IDs and map each to its first action ID.

        Args:
            actions (List[Action]): List of Action objects.

        Returns:
            Tuple[List[str], Dict[str, Optional[str]]]:
                (flat list of agent IDs, agent_id -> action_id mapping).
        """
        agent_id_to_action_ids: Dict[str, Optional[str]] = {}
        all_agent_ids: List[str] = []
        for action_dict in actions:
            params, act_id = self._extract_action_params(action_dict)
            agent_ids_local = self.s1_singularity_xdr_helper._parse_ids(
                params.get("agent_id", "")
            )
            for aid in agent_ids_local:
                if aid not in agent_id_to_action_ids:
                    agent_id_to_action_ids[aid] = act_id
            all_agent_ids.extend(agent_ids_local)
        return all_agent_ids, agent_id_to_action_ids

    def _failed_ids_for_batch(
        self,
        batch: List[str],
        id_to_action_ids: Dict[str, Optional[str]],
    ) -> List[Optional[str]]:
        """Return the non-null action IDs for the given batch of IDs."""
        return [
            id_to_action_ids[aid]
            for aid in batch
            if id_to_action_ids.get(aid) is not None
        ]

    def _execute_network_isolation_action(
        self,
        actions: List[Action],
        action_label: str,
        base_url: str,
        auth_header: dict,
        site_id: str,
    ) -> ActionResult:
        """Execute the network isolation bulk action."""
        failed_action_ids: List[Optional[str]] = []
        first_action_params, _ = self._extract_action_params(actions[0])
        net_type = first_action_params.get("network_action_type")
        net_op = "disconnect" if net_type == "isolate" else "connect"

        all_agent_ids, agent_id_to_action_ids = self._collect_agent_ids(
            actions
        )

        for batch, batch_number in (
            self.s1_singularity_xdr_helper._batch_ids(all_agent_ids)
        ):
            try:
                count = self._network_action(
                    base_url=base_url,
                    auth_header=auth_header,
                    site_id=site_id,
                    agent_ids=batch,
                    action=net_op,
                    batch_number=batch_number,
                    context={},
                )
                action_label = (
                    "Isolated"
                    if net_op == "disconnect"
                    else "Removed isolation for"
                )
                self.logger.info(
                    f"{self.log_prefix}: {action_label}"
                    f" {count} device(s) in batch"
                    f" {batch_number}."
                )
            except Exception:
                failed_action_ids.extend(
                    self._failed_ids_for_batch(batch, agent_id_to_action_ids)
                )

        self.logger.info(
            f"{self.log_prefix}: Completed execution of {action_label} action."
        )

        return ActionResult(
            success=True,
            message=f"Action '{action_label}' executed.",
            failed_action_ids=list(set(failed_action_ids)),
        )

    def _execute_scan_endpoint_action(
        self,
        actions: List[Action],
        action_label: str,
        base_url: str,
        auth_header: dict,
        site_id: str,
    ) -> ActionResult:
        """Execute the endpoint scan bulk action."""
        failed_action_ids: List[Optional[str]] = []
        first_action_params, _ = self._extract_action_params(actions[0])
        scan_type = first_action_params.get("scan_type")

        all_agent_ids, agent_id_to_action_ids = self._collect_agent_ids(
            actions
        )

        for batch, batch_number in (
            self.s1_singularity_xdr_helper._batch_ids(all_agent_ids)
        ):
            try:
                if scan_type == "full_disk_scan":
                    count = self._scan_action(
                        base_url=base_url,
                        auth_header=auth_header,
                        site_id=site_id,
                        agent_ids=batch,
                        scan_type="disk",
                        batch_number=batch_number,
                        context={}
                    )
                    self.logger.info(
                        f"{self.log_prefix}: Initiated full"
                        f" disk scan on {count}"
                        f" device(s) in batch {batch_number}."
                    )
                else:
                    count = self._scan_action(
                        base_url,
                        auth_header,
                        site_id,
                        batch,
                        "vuln",
                        batch_number=batch_number,
                        context={},
                    )
                    self.logger.info(
                        f"{self.log_prefix}: Initiated"
                        " vulnerability scan on"
                        f" {count} device(s) for"
                        f" batch {batch_number}."
                    )
            except Exception:
                failed_action_ids.extend(
                    self._failed_ids_for_batch(batch, agent_id_to_action_ids)
                )

        self.logger.info(
            f"{self.log_prefix}: Completed execution of {action_label} action."
        )
        return ActionResult(
            success=True,
            message=f"Action '{action_label}' executed.",
            failed_action_ids=list(set(failed_action_ids)),
        )

    def _execute_reboot_endpoint_action(
        self,
        actions: List[Action],
        action_label: str,
        base_url: str,
        auth_header: dict,
        site_id: str,
    ) -> ActionResult:
        """Execute the endpoint reboot bulk action."""
        failed_action_ids: List[Optional[str]] = []
        all_agent_ids, agent_id_to_action_ids = self._collect_agent_ids(
            actions
        )

        for batch, batch_number in (
            self.s1_singularity_xdr_helper._batch_ids(all_agent_ids)
        ):
            try:
                count = self._reboot_action(
                    base_url=base_url,
                    auth_header=auth_header,
                    site_id=site_id,
                    agent_ids=batch,
                    batch_number=batch_number,
                    context={},
                )
                self.logger.info(
                    f"{self.log_prefix}: Rebooted"
                    f" {count} device(s) in batch"
                    f" {batch_number}."
                )
            except Exception:
                failed_action_ids.extend(
                    self._failed_ids_for_batch(batch, agent_id_to_action_ids)
                )

        self.logger.info(
            f"{self.log_prefix}: Completed execution of {action_label} action."
        )
        return ActionResult(
            success=True,
            message=f"Action '{action_label}' executed.",
            failed_action_ids=list(set(failed_action_ids)),
        )

    def _execute_manage_tags_action(
        self,
        actions: List[Action],
        action_label: str,
        base_url: str,
        auth_header: dict,
        site_id: str,
    ) -> ActionResult:
        """Execute the manage endpoint tags bulk action."""
        failed_action_ids: List[Optional[str]] = []
        action_stats: Dict[str, Dict[str, int]] = {}
        tag_groups: Dict[Tuple[str, str], dict] = {}
        agent_id_to_action_ids: Dict[str, Optional[str]] = {}
        first_action_params, _ = self._extract_action_params(actions[0])
        operation = first_action_params.get("tag_action_type")

        for action_dict in actions:
            params, act_id = self._extract_action_params(action_dict)
            tag_key = (
                params.get("tag_key", "")
                if params.get("tag_key", "") is not None
                else ""
            )
            action_tag_value = params.get("tag_value", "")
            tag_values = self.s1_singularity_xdr_helper._parse_tags(
                action_tag_value
            )
            agent_ids_local = self.s1_singularity_xdr_helper._parse_ids(
                params.get("agent_id", "")
            )

            for tag in tag_values:
                group_key = (tag_key, tag)
                if group_key not in tag_groups:
                    tag_groups[group_key] = {
                        "tag_key": tag_key,
                        "tag_value": tag,
                        "agent_ids": [],
                        "action_ids": [],
                    }
                tag_groups[group_key]["agent_ids"].extend(agent_ids_local)
                if act_id:
                    tag_groups[group_key]["action_ids"].append(act_id)
            for aid in agent_ids_local:
                if aid not in agent_id_to_action_ids:
                    agent_id_to_action_ids[aid] = act_id

        try:
            existing_tags = self._get_tags(
                base_url=base_url,
                auth_header=auth_header,
                site_id=site_id,
                context={},
            )
        except Exception:
            # Fail action if fetch tags produces API error.
            failed_action_ids.extend(
                list(set(agent_id_to_action_ids.values()))
            )
            skip_msg = (
                f"Skipped executing {action_label} action due to error"
                f" while fetching existing tags from {PLATFORM_NAME}"
                " platform."
            )
            self.logger.info(
                f"{self.log_prefix}: {skip_msg}"
            )
            return ActionResult(
                success=False,
                message=skip_msg,
                failed_action_ids=list(set(failed_action_ids)),
            )

        for group_key, group_data in tag_groups.items():
            tag_key = group_data["tag_key"]
            tag_value_str = group_data["tag_value"]
            group_agent_ids = group_data["agent_ids"]
            group_action_ids = group_data["action_ids"]
            tag_key_value = f"{tag_key}:{tag_value_str}"
            action_stats[tag_key_value] = {
                "success": 0, "skipped": 0, "failed": 0
            }

            # Look up tag ID from fetched tags
            tag_id = None
            if tag_values := existing_tags.get(tag_key):
                if tag_values.get(tag_value_str):
                    tag_id = tag_values.get(tag_value_str)

            if not tag_id and operation == "add":
                try:
                    tag_id = self._create_tag(
                        base_url=base_url,
                        auth_header=auth_header,
                        site_id=site_id,
                        tag_key=tag_key,
                        tag_value=tag_value_str,
                        context={}
                    )
                    self.logger.info(
                        f"{self.log_prefix}: Successfully created new tag"
                        f" '{tag_key_value}'."
                    )
                except Exception:
                    failed_action_ids.extend(group_action_ids)
                    action_stats[
                        tag_key_value
                    ]["failed"] += len(group_action_ids)
                    continue

            if not tag_id:
                self.logger.info(
                    f"{self.log_prefix}: Tag '{tag_key_value}'"
                    f" not found on {PLATFORM_NAME} platform. Skipping"
                    f" {operation} tag for {len(group_agent_ids)} device(s)."
                )
                failed_action_ids.extend(group_action_ids)
                action_stats[
                    tag_key_value
                ]["skipped"] += len(group_action_ids)
                continue

            for batch, batch_number in (
                self.s1_singularity_xdr_helper._batch_ids(group_agent_ids)
            ):
                agent_ids_len = len(batch)
                try:
                    count = self._manage_tag(
                        base_url=base_url,
                        auth_header=auth_header,
                        site_id=site_id,
                        tag_id=tag_id,
                        tag_key_value=tag_key_value,
                        agent_ids=batch,
                        operation=operation,
                        batch_number=batch_number,
                        context={}
                    )
                    operation_logger = (
                        f"removed tag '{tag_key_value}' from"
                        if operation == "remove"
                        else f"added tag '{tag_key_value}' to"
                    )
                    self.logger.info(
                        f"{self.log_prefix}: Successfully"
                        f" {operation_logger} {count} device(s) in"
                        f" batch {batch_number}."
                    )
                    if count < len(batch):
                        action_stats[tag_key_value]["failed"] += (
                            agent_ids_len - count
                        )
                    action_stats[tag_key_value]["success"] += count
                except Exception:
                    action_stats[tag_key_value]["failed"] += agent_ids_len
                    failed_action_ids.extend(
                        self._failed_ids_for_batch(
                            batch, agent_id_to_action_ids
                        )
                    )

        self.logger.info(
            message=(
                f"{self.log_prefix}: Completed execution of {operation}"
                " tag. Expand the log to view action stats."
            ),
            details=f"{action_stats}"
        )

        return ActionResult(
            success=True,
            message=f"Action '{action_label}' executed.",
            failed_action_ids=list(set(failed_action_ids)),
        )

    def _execute_group_management_action(
        self,
        actions: List[Action],
        action_label: str,
        base_url: str,
        auth_header: dict,
        site_id: str,
    ) -> ActionResult:
        """Execute the group management bulk action."""
        failed_action_ids: List[Optional[str]] = []
        all_action_ids: List[str] = []
        agent_id_to_action_ids: Dict[str, Optional[str]] = {}
        all_agent_ids: List[str] = []

        first_action_params, _ = self._extract_action_params(actions[0])
        action_group = first_action_params.get(
            "group_name", ""
        ).split("##+##")
        group_name = action_group[0]
        group_id = action_group[1]
        create_group_name = first_action_params.get("create_group")
        group_type = first_action_params.get("group_type")

        for action_dict in actions:
            params, act_id = self._extract_action_params(action_dict)
            agent_ids_local = self.s1_singularity_xdr_helper._parse_ids(
                params.get("agent_id", "")
            )
            all_agent_ids.extend(agent_ids_local)
            if act_id:
                all_action_ids.append(act_id)
            for aid in agent_ids_local:
                if aid not in agent_id_to_action_ids:
                    agent_id_to_action_ids[aid] = act_id

        # Create group if needed
        if group_id == "create_new_group":
            existing_groups = self._get_groups(
                base_url=base_url,
                auth_header=auth_header,
                site_id=site_id,
                context={}
            )
            if create_group_name in existing_groups:
                self.logger.info(
                    f"{self.log_prefix}: Skipped creation of group"
                    f" {create_group_name} as it exists on the platform."
                )
                group_id = existing_groups[create_group_name]
            else:
                try:
                    group_id = self._create_group(
                        base_url=base_url,
                        auth_header=auth_header,
                        site_id=site_id,
                        group_name=create_group_name,
                        group_type=group_type,
                        context={}
                    )
                    self.logger.info(
                        f"{self.log_prefix}: Successfully created new"
                        f" {group_type} group '{create_group_name}'."
                    )
                except Exception:
                    failed_action_ids.extend(
                        list(set(agent_id_to_action_ids.values()))
                    )
                    return ActionResult(
                        success=False,
                        message=f"Action '{action_label}' executed.",
                        failed_action_ids=failed_action_ids,
                    )

        if group_id and group_id != "create_new_group":
            for batch, batch_number in (
                self.s1_singularity_xdr_helper._batch_ids(all_agent_ids)
            ):
                try:
                    moved = self._move_agent_to_group(
                        base_url=base_url,
                        auth_header=auth_header,
                        site_id=site_id,
                        group_id=group_id,
                        group_name=group_name,
                        agent_ids=batch,
                        batch_number=batch_number,
                        context={}
                    )
                    self.logger.info(
                        f"{self.log_prefix}: Successfully moved {moved}"
                        f" device(s) to group '{group_name}'"
                        f" in batch {batch_number}."
                    )
                except Exception:
                    failed_action_ids.extend(
                        self._failed_ids_for_batch(
                            batch, agent_id_to_action_ids
                        )
                    )
        else:
            failed_action_ids = all_action_ids

        self.logger.info(
            f"{self.log_prefix}: Completed execution of {action_label} action."
        )

        return ActionResult(
            success=True,
            message=f"Action '{action_label}' executed.",
            failed_action_ids=list(set(failed_action_ids)),
        )

    def _execute_update_criticality_action(
        self,
        actions: List[Action],
        action_label: str,
        base_url: str,
        auth_header: dict,
        site_id: str,
    ) -> ActionResult:
        """Execute the update asset criticality bulk action."""
        failed_action_ids: List[Optional[str]] = []
        criticality_groups: Dict[str, dict] = {}
        asset_id_to_action_id: Dict[str, Optional[str]] = {}

        for action_dict in actions:
            params, act_id = self._extract_action_params(action_dict)
            criticality_label = params.get(
                "criticality_value", ""
            ).lower()
            asset_ids_local = self.s1_singularity_xdr_helper._parse_ids(
                params.get("asset_id", "")
            )
            local_action_ids = set()
            for asset_id in asset_ids_local:
                asset_id_to_action_id[asset_id] = act_id
                local_action_ids.add(act_id)

            if ASSET_CRITICALITY_MAP.get(criticality_label):
                criticality = ASSET_CRITICALITY_MAP[criticality_label]
            else:
                self.logger.error(
                    f"{self.log_prefix}: Skipping updating asset"
                    f" criticality of {len(asset_ids_local)} asset(s)"
                    f" due to unsupported criticality value"
                    f" '{criticality_label}'."
                )
                failed_action_ids.extend(local_action_ids)
                continue

            ck = criticality
            if ck not in criticality_groups:
                criticality_groups[ck] = {
                    "criticality": criticality,
                    "criticality_label": criticality_label,
                    "asset_ids": [],
                }
            criticality_groups[ck]["asset_ids"].extend(asset_ids_local)

        for ck, crit_data in criticality_groups.items():
            all_asset_ids = crit_data["asset_ids"]
            for batch, batch_number in (
                self.s1_singularity_xdr_helper._batch_ids(all_asset_ids)
            ):
                criticality_label = crit_data["criticality_label"]
                try:
                    operation_logger = (
                        "Cleared criticality"
                        if criticality_label == "clear"
                        else (
                            f"Updated criticality to '{criticality_label}'"
                        )
                    )
                    self._update_asset_criticality_action(
                        base_url=base_url,
                        auth_header=auth_header,
                        site_id=site_id,
                        asset_ids=batch,
                        batch_number=batch_number,
                        criticality_action_value=crit_data["criticality"],
                        criticality_label=criticality_label,
                        context={},
                    )
                    self.logger.info(
                        f"{self.log_prefix}: {operation_logger}"
                        f" for {len(batch)} asset(s) in batch"
                        f" {batch_number}."
                    )
                except Exception:
                    failed_action_ids.extend(
                        self._failed_ids_for_batch(
                            batch, asset_id_to_action_id
                        )
                    )

        self.logger.info(
            f"{self.log_prefix}: Completed execution of {action_label} action."
        )
        return ActionResult(
            success=True,
            message=f"Action '{action_label}' executed.",
            failed_action_ids=list(set(failed_action_ids)),
        )

    def _extract_action_params(
        self, action_dict: Dict
    ):
        """Extract params and action ID from an action dict.

        Args:
            action_dict: A single action object from the actions list.

        Returns:
            Tuple[dict, Optional[str]]: (parameters dict, action id or None)
        """
        params = action_dict.get("params", {}).parameters
        act_id = action_dict.get("id")
        return params, act_id

    def _validate_auth_params(
        self,
        base_url: str,
        api_token: str,
        site_name: str,
        is_validation: bool = True,
    ) -> ValidationResult:
        """Validate API credentials and site name.

        Args:
            base_url (str): Base URL.
            api_token (str): API Token.
            site_name (str): Site Name.
            is_validation (bool): Is this a validation call?

        Returns:
            ValidationResult: Validation result.
        """
        try:
            storage = self._get_storage()
            auth_header = self.s1_singularity_xdr_helper.get_auth_header(
                api_token
            )
            site_id = self.get_site_id(
                base_url=base_url,
                auth_header=auth_header,
                site_name=site_name,
                is_validation=is_validation,
            )
            storage.update({"site_id": site_id})
            self.logger.debug(
                f"{self.log_prefix}: Successfully validated connectivity"
                f" with {PLATFORM_NAME}."
            )
            return ValidationResult(
                success=True,
                message="Validation successful.",
            )
        except SentinelOneSingularityXDRPluginException as err:
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Error occurred while validating"
                    f" connectivity with {PLATFORM_NAME} platform. Error:"
                    f" {err}"
                )
            )
            return ValidationResult(
                success=False,
                message=str(err),
            )
        except Exception as exp:
            err_msg = (
                "Unexpected error occurred while validating"
                f" connectivity with {PLATFORM_NAME} platform."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}"
                f" Error: {exp}",
                details=traceback.format_exc(),
            )
            return ValidationResult(
                success=False,
                message=(
                    f"{err_msg} Check logs for more details."
                ),
            )

    def validate(
        self, configuration: dict
    ) -> ValidationResult:
        """Validate plugin configuration.

        Args:
            configuration (dict): Configuration dictionary.

        Returns:
            ValidationResult: Validation result.
        """
        validation_err_msg = "Validation error occurred. "
        base_url, api_token, site_name = (
            self.s1_singularity_xdr_helper.get_configuration_parameters(
                configuration=configuration
            )
        )

        # Validate Base URL
        if validation_result := self._validate_parameters(
            field_name="Base URL",
            field_value=base_url,
            field_type=str,
            parameter_type="configuration",
            is_required=True,
            validation_err_msg=validation_err_msg,
            custom_validation_func=self.s1_singularity_xdr_helper._validate_url
        ):
            return validation_result

        # Validate API Token
        if not api_token:
            err_msg = (
                "'API Token' is a required configuration parameter."
            )
            self.logger.error(
                message=(
                    f"{self.log_prefix}:"
                    f" {validation_err_msg}{err_msg}"
                ),
            )
            return ValidationResult(
                success=False, message=err_msg
            )
        if not isinstance(api_token, str):
            err_msg = (
                "Invalid value provided for the configuration"
                " parameter 'API Token'."
            )
            self.logger.error(
                message=(
                    f"{self.log_prefix}:"
                    f" {validation_err_msg}{err_msg}"
                ),
            )
            return ValidationResult(
                success=False, message=err_msg
            )

        # Validate Site Name
        if validation_result := self._validate_parameters(
            field_name="Site Name",
            field_value=site_name,
            field_type=str,
            parameter_type="configuration",
            is_required=True,
            validation_err_msg=validation_err_msg,
        ):
            return validation_result

        # Validate credentials and site name by calling API
        return self._validate_auth_params(
            base_url=base_url,
            api_token=api_token,
            site_name=site_name,
        )
