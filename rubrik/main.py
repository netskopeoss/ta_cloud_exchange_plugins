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

CTE Rubrik Plugin's main file which contains the implementation of all the
plugin's methods.
"""

import traceback
import ipaddress
import re
from typing import Dict, List, Tuple

from netskope.integrations.cte.models import (
    Indicator,
    IndicatorType,
)
from netskope.integrations.cte.models.business_rule import (
    Action,
    ActionWithoutParams,
)
from netskope.integrations.cte.plugin_base import (
    PluginBase,
    PushResult,
    ValidationResult,
)
from urllib.parse import urlparse

from .utils.constants import (
    PLATFORM_NAME,
    PLUGIN_NAME,
    PLUGIN_VERSION,
    MODULE_NAME,
    HUNT_SOURCE_TAG,
    FILE_SIZE_LIMIT,
    MAX_IOC_MATCHES,
    GET_CLUSTER_UUID_AND_LIST_QUERY,
    GET_TOTAL_OBJECT_FIDS_QUERY,
    START_THREAT_HUNT_QUERY,
    INCLUDE_FILE_LIST,
    BATCH_SIZE,
    BIFURCATE_INDICATOR_TYPES,
)

from .utils.helper import (
    RubrikPluginException,
    RubrikPluginHelper,
)


class RubrikPlugin(PluginBase):
    """
    RubrikPlugin class having implementation all plugin's methods.
    """

    def __init__(
        self,
        name,
        *args,
        **kwargs,
    ):
        """Rubrik plugin initializer.

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
        self.helper = RubrikPluginHelper(
            logger=self.logger,
            log_prefix=self.log_prefix,
            plugin_name=self.plugin_name,
            plugin_version=self.plugin_version,
        )
        self.total_indicators = 0

    def _get_plugin_info(self) -> Tuple[str, str]:
        """Get plugin name and version from manifest.

        Returns:
            tuple: Tuple of plugin's name and version fetched from manifest.
        """
        try:
            manifest_json = RubrikPlugin.metadata
            plugin_name = manifest_json.get("name", PLUGIN_NAME)
            plugin_version = manifest_json.get("version", PLUGIN_VERSION)
            return plugin_name, plugin_version
        except Exception as exp:
            self.logger.error(
                message=(
                    f"{MODULE_NAME} {PLUGIN_NAME}: Error occurred while"
                    f" getting plugin details. Error: {exp}"
                ),
                details=str(traceback.format_exc()),
            )
        return PLUGIN_NAME, PLUGIN_VERSION

    def _validate_url(self, url: str) -> bool:
        """Validate the URL using parsing.

        Args:
            url (str): Given URL.

        Returns:
            bool: True or False { Valid or not Valid URL }.
        """
        parsed = urlparse(url)
        return (
            parsed.scheme.strip() != ""
            and parsed.netloc.strip() != ""
            and (parsed.path.strip() == "/" or parsed.path.strip() == "")
        )

    def get_action_parameters(self, action_dict: Dict):
        """
        Get action parameters.
        args:
            action_dict: action parameters
        """
        action_parameters = action_dict.get("parameters", {})

        threat_hunt_name = (
            action_parameters.get("threat_hunt_name", "").strip()
            + " "
            + HUNT_SOURCE_TAG
        )
        cluster_name = action_parameters.get("cluster_name")
        max_file_size = action_parameters.get("max_file_size", 1024)
        min_file_size = action_parameters.get("min_file_size", 5)
        max_ioc_matches = action_parameters.get("max_ioc_matches", 1)
        include_files = action_parameters.get(
            "include_files", INCLUDE_FILE_LIST
        )
        exclude_files = action_parameters.get("exclude_files")
        do_not_exclude_files = action_parameters.get("do_not_exclude_files")

        return (
            threat_hunt_name,
            cluster_name,
            max_file_size,
            min_file_size,
            max_ioc_matches,
            include_files,
            exclude_files,
            do_not_exclude_files,
        )

    def _get_cluster_uuid_and_list_from_rubrik(
        self, cluster_name: str, get_cluster_list_from_rubrik: bool
    ):
        """
        Get cluster uuid from rubrik.

        args:
            cluster_name: cluster name
            get_cluster_list_from_rubrik: get cluster list from rubrik

        """
        query = GET_CLUSTER_UUID_AND_LIST_QUERY
        variables = {
            "sortBy": "ClusterName",
            "sortOrder": "ASC",
            "filter": {"type": [], "name": [""]},
            "first": 50,
        }
        (base_url, client_id, client_secret) = self.helper.get_credentials(
            self.configuration
        )
        auth_url = f"{base_url}/api/client_token"
        query_endpoint = f"{base_url}/api/graphql"
        cluster_list = []
        next_page = True
        cluster_uuid = None
        headers = self.helper.get_auth_header(
            client_id, client_secret, auth_url
        )
        while next_page:
            request_json = {"query": query, "variables": variables}

            response = self.helper.api_helper(
                url=query_endpoint,
                method="POST",
                headers=headers,
                json=request_json,
                is_validation=False,
                logger_msg="getting cluster UUID",
                regenerate_auth_token=True,
                verify=self.ssl_validation,
                proxies=self.proxy,
            )

            data = response.get("data")
            cluster_connection = None
            page_info = None
            if data:
                cluster_connection = data.get("clusterConnection")

            edges_list = []
            if cluster_connection:
                edges_list = cluster_connection.get("edges", [])
                page_info = cluster_connection.get("pageInfo")

            if page_info:
                if page_info.get("hasNextPage") and page_info.get("endCursor"):
                    variables.update({"after": page_info.get("endCursor")})
                else:
                    next_page = False
            else:
                next_page = False

            for edge in edges_list:
                node = edge.get("node")
                if (
                    node
                    and node.get("name") == cluster_name
                    and not get_cluster_list_from_rubrik
                ):
                    cluster_uuid = node.get("id")
                    return cluster_uuid
                else:
                    if (
                        node
                        and node.get("name")
                        and get_cluster_list_from_rubrik
                    ):
                        fetched_cluster_name = node.get("name")
                        cluster_list.append(fetched_cluster_name)

        if get_cluster_list_from_rubrik:
            return cluster_list
        else:
            return cluster_uuid

    def _get_total_object_fids_from_rubrik(self, cluster_uuid):
        """Get total object fids from rubrik.

        Args:
            cluster_uuid (str): Cluster UUID.
        """
        self.logger.debug(
            f"{self.log_prefix}: Performing API call to get the "
            f"total objectFids from {PLATFORM_NAME}."
        )

        query = GET_TOTAL_OBJECT_FIDS_QUERY
        variables = {
            "first": 50,
            "filter": [
                {"texts": ["false"], "field": "IS_GHOST"},
                {
                    "texts": [cluster_uuid],
                    "field": "CLUSTER_ID",
                },
            ],
            "sortBy": "NAME",
            "sortOrder": "ASC",
            "typeFilter": [
                "LinuxFileset",
                "ShareFileset",
                "VmwareVirtualMachine",
                "WindowsFileset",
                "HypervVirtualMachine",
                "NutanixVirtualMachine",
                "NAS_FILESET",
            ],
        }

        (base_url, client_id, client_secret) = self.helper.get_credentials(
            self.configuration
        )
        auth_url = f"{base_url}/api/client_token"
        query_endpoint = f"{base_url}/api/graphql"
        object_fids_list = []
        next_page = True
        headers = self.helper.get_auth_header(
            client_id, client_secret, auth_url
        )
        while next_page:
            request_json = {"query": query, "variables": variables}

            response = self.helper.api_helper(
                url=query_endpoint,
                method="POST",
                headers=headers,
                json=request_json,
                is_validation=False,
                logger_msg="getting objectFids list",
                regenerate_auth_token=True,
                verify=self.ssl_validation,
                proxies=self.proxy,
            )

            data = response.get("data")
            inventory_root = None
            descendant_conncetion = None
            page_info = None
            edges_list = []

            if data:
                inventory_root = data.get("inventoryRoot")

            if inventory_root:
                descendant_conncetion = inventory_root.get(
                    "descendantConnection"
                )

            if descendant_conncetion:
                edges_list = descendant_conncetion.get("edges", [])
                page_info = descendant_conncetion.get("pageInfo")

            if page_info:
                if page_info.get("hasNextPage") and page_info.get("endCursor"):
                    variables.update({"after": page_info.get("endCursor")})
                else:
                    next_page = False
            else:
                next_page = False

            for edge in edges_list:
                node = edge.get("node")
                if node and node.get("id"):
                    object_fids_list.append(node.get("id"))

        return object_fids_list

    def _validate_domain(self, value: str) -> bool:
        """Validate domain name.

        Args:
            value (str): Domain name.

        Returns:
            bool: Whether the name is valid or not.
        """
        if re.match(
            r"^((?=[a-z0-9-]{1,63}\.)(xn--)?[a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,63}$",  # noqa
            value,
        ):
            return True
        else:
            return False

    def _is_valid_ipv4(self, address: str) -> bool:
        """Validate IPv4 address.

        Args:
            address (str): Address to validate.

        Returns:
            bool: True if valid else False.
        """
        try:
            ipaddress.IPv4Address(address)
            return True
        except Exception:
            return False

    def _is_valid_ipv6(self, address: str) -> bool:
        """Validate IPv6 address.

        Args:
            address (str): Address to validate.

        Returns:
            bool: True if valid else False.
        """
        try:
            ipaddress.IPv6Address(address)
            return True
        except Exception:
            return False

    def _is_valid_fqdn(self, fqdn: str) -> bool:
        """Validate FQDN (Absolute domain).

        Args:
            - fqdn (str): FQDN to validate.

        Returns:
            - bool: True if valid else False.
        """
        if re.match(
            r"^(?!.{255}|.{253}[^.])([a-z0-9](?:[-a-z-0-9]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[-a-z0-9]{0,61}[a-z0-9])?[.]?$",  # noqa
            fqdn,
            re.IGNORECASE,
        ):
            return True
        else:
            return False

    def divide_in_chunks(self, indicators, chunk_size):
        """Return Fixed size chunks from list."""
        for i in range(0, len(indicators), chunk_size):
            yield indicators[i : i + chunk_size]  # noqa

    def prepare_payload(self, indicators: List[Indicator]):
        """
        Prepare the payload for threat hunt.

        args:
            indicators (List[Indicator]): List of indicators.
        """
        self.logger.info(
            f"{self.log_prefix}: Filtering indicators for Threat Hunt."
        )

        indicator_of_compromise = []
        sha256_payload = {
            "iocKind": "IOC_HASH",
            "iocValue": None,
        }

        md5_payload = {
            "iocKind": "IOC_HASH",
            "iocValue": None,
        }
        sha256_list = []
        md5_list = []
        skip_count = {
            "domain": 0,
            "ipv4": 0,
            "ipv6": 0,
            "fqdn": 0,
            "invalid": 0,
        }
        for indicator in indicators:
            if indicator.type == IndicatorType.SHA256:
                sha256_list.append(indicator.value)
            elif indicator.type == IndicatorType.MD5:
                md5_list.append(indicator.value)
            elif indicator.type in BIFURCATE_INDICATOR_TYPES:
                try:
                    if self._validate_domain(indicator.value):
                        skip_count["domain"] += 1
                    elif self._is_valid_ipv4(indicator.value):
                        skip_count["ipv4"] += 1
                    elif self._is_valid_ipv6(indicator.value):
                        skip_count["ipv6"] += 1
                    elif self._is_valid_fqdn(indicator.value):
                        skip_count["fqdn"] += 1
                    else:
                        skip_count["invalid"] += 1
                        continue
                except Exception:
                    skip_count["invalid"] += 1
                    continue

        sha256_string = ",".join(
            [f"sha256:{sha_value}" for sha_value in sha256_list]
        )
        md5_string = ",".join([f"md5:{md5_value}" for md5_value in md5_list])

        if len(sha256_list) > 0:
            sha256_payload["iocValue"] = sha256_string
            indicator_of_compromise.append(sha256_payload)

        if len(md5_list) > 0:
            md5_payload["iocValue"] = md5_string
            indicator_of_compromise.append(md5_payload)

        skipped = (
            skip_count.get("domain")
            + skip_count.get("ipv4")
            + skip_count.get("ipv6")
            + skip_count.get("fqdn")
            + skip_count.get("invalid")
        )
        log_msg = (
            f"Successfully created payload for {len(sha256_list)} SHA256 "
            f"indicators and {len(md5_list)} MD5 indicators and skipped "
            f"{skip_count.get('domain')} domain, "
            f"{skip_count.get('ipv4')} IPv4, {skip_count.get('ipv6')} IPv6, "
            f"{skip_count.get('fqdn')} FQDN and {skip_count.get('invalid')} "
            f"invalid indicators."
        )
        self.logger.info(f"{self.log_prefix}: {log_msg}")

        return (
            indicator_of_compromise,
            len(sha256_list),
            len(md5_list),
            skipped,
        )

    def start_threat_hunt(
        self,
        threat_hunt_name,
        cluster_uuid,
        ioc_payload,
        total_object_fids_list,
        max_file_size,
        min_file_size,
        max_ioc_matches,
        include_files,
        exclude_files,
        do_not_exclude_files,
    ):
        """
        Start threat hunt.

        args:
            threat_hunt_name (str): Name of threat hunt.
            cluster_uuid (str): UUID of cluster.
            ioc_payload (List[dict]): List of IOC payload.
            total_object_fids_list (List[str]): List of object FIDs.
            max_file_size (int): Maximum file size.
            min_file_size (int): Minimum file size.
            max_ioc_matches (int): Maximum IOC matches.
        """
        include_files_list = include_files
        exclude_files_list = exclude_files
        do_not_exclude_files_list = do_not_exclude_files

        # converting the KB into bytes
        max_file_size = max_file_size * 1000
        min_file_size = min_file_size * 1000

        query = START_THREAT_HUNT_QUERY
        variables = {
            "input": {
                "clusterUuid": cluster_uuid,
                "indicatorsOfCompromise": ioc_payload,
                "objectFids": total_object_fids_list,
                "fileScanCriteria": {
                    "fileSizeLimits": {
                        "maximumSizeInBytes": max_file_size,
                        "minimumSizeInBytes": min_file_size,
                    },
                    "pathFilter": {
                        "includes": include_files_list,
                        "excludes": exclude_files_list,
                        "exceptions": do_not_exclude_files_list,
                    },
                },
                "maxMatchesPerSnapshot": max_ioc_matches,
                "name": threat_hunt_name,
                "shouldTrustFilesystemTimeInfo": True,
                "snapshotScanLimit": {"maxSnapshotsPerObject": 1},
            }
        }

        (base_url, client_id, client_secret) = self.helper.get_credentials(
            self.configuration
        )
        auth_url = f"{base_url}/api/client_token"
        headers = self.helper.get_auth_header(
            client_id, client_secret, auth_url
        )

        request_json = {"query": query, "variables": variables}
        query_endpoint = f"{base_url}/api/graphql"

        response = self.helper.api_helper(
            url=query_endpoint,
            method="POST",
            headers=headers,
            json=request_json,
            is_validation=False,
            logger_msg="starting Threat Hunt",
            regenerate_auth_token=True,
            verify=self.ssl_validation,
            proxies=self.proxy,
        )

        data = response.get("data")
        start_threat_hunt_response = None
        is_sync_successful = False
        hunt_ID = None

        if data:
            start_threat_hunt_response = data.get("startThreatHunt")
            if start_threat_hunt_response:
                hunt_ID = start_threat_hunt_response.get("huntId")
                is_sync_successful = start_threat_hunt_response.get(
                    "isSyncSuccessful"
                )
        else:
            err_msg = "No data found in API response."
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=str(response),
            )

        return is_sync_successful, hunt_ID

    def pull(self) -> List[Indicator]:
        """Pull the Indicator list from Rubrik.

        Returns:
            List[cte.models.Indicators]: List of Indicator objects
        """
        return []

    def push(self, indicators: List[Indicator], action_dict: Dict):
        """Push the Indicator list to Rubrik.

        Args:
            indicators (List[cte.models.Indicators]): List of Indicator
            objects to be pushed.
            action_dict (dict): Action dictionary with action label and

        Returns:
            cte.plugin_base.PushResult: PushResult object with success
            flag and Push result message.
        """
        try:
            action_label = action_dict.get("label")
            action_value = action_dict.get("value")
            get_cluster_list_from_rubrik = False
            cluster_uuid = None
            total_object_fids_list = []
            ioc_payload = []

            self.logger.info(
                f"{self.log_prefix}: Executing push method for "
                f'"{action_label}" target action.'
            )

            (
                threat_hunt_name,
                cluster_name,
                max_file_size,
                min_file_size,
                max_ioc_matches,
                include_files,
                exclude_files,
                do_not_exclude_files,
            ) = self.get_action_parameters(action_dict)

            if action_value == "start_threat_hunt":

                cluster_uuid = self._get_cluster_uuid_and_list_from_rubrik(
                    cluster_name, get_cluster_list_from_rubrik
                )

                if not cluster_uuid:
                    err_msg = (
                        f"Unable to fetch cluster UUID for cluster: "
                        f"{cluster_name}."
                    )
                    self.logger.error(f"{self.log_prefix}: {err_msg}")
                    raise RubrikPluginException(err_msg)

                total_object_fids_list = (
                    self._get_total_object_fids_from_rubrik(cluster_uuid)
                )

                if not total_object_fids_list:
                    err_msg = (
                        f"Unable to fetch objectFids for cluster: "
                        f"{cluster_name}."
                    )
                    self.logger.error(f"{self.log_prefix}: {err_msg}")
                    raise RubrikPluginException(err_msg)

                total_indicators_count = 0
                push_success, push_failed = 0, 0
                total_sha256_pushed, total_md5_pushed = 0, 0
                total_skipped = 0
                batch_count = 0
                indicator_list = list(indicators)
                for ioc_payload in self.divide_in_chunks(
                    indicator_list, BATCH_SIZE
                ):
                    payload, total_sha256, total_md5, skipped = (
                        self.prepare_payload(ioc_payload)
                    )
                    total_indicators_count += len(ioc_payload)
                    batch_count += 1
                    if len(ioc_payload) == 0:
                        err_msg = (
                            f"Cannot initiate Threat Hunt: {threat_hunt_name}."
                            f" for batch {batch_count} of {len(ioc_payload)} "
                            "indicator(s). Atleast 1 indicator(SHA256 or MD5)"
                            " is required, found 0."
                        )
                        self.logger.error(f"{self.log_prefix}: {err_msg}")
                        continue

                    is_sync_successful, hunt_ID = self.start_threat_hunt(
                        threat_hunt_name,
                        cluster_uuid,
                        payload,
                        total_object_fids_list,
                        max_file_size,
                        min_file_size,
                        max_ioc_matches,
                        include_files,
                        exclude_files,
                        do_not_exclude_files,
                    )

                    if is_sync_successful is True and hunt_ID:
                        push_success += len(ioc_payload)
                        total_sha256_pushed += total_sha256
                        total_md5_pushed += total_md5
                        total_skipped += skipped
                        log_msg = (
                            "Successfully initiated Threat Hunt: "
                            f"{threat_hunt_name} with huntID: {hunt_ID} "
                            f"for {total_sha256} SHA256 indicator(s) and "
                            f"{total_md5} MD5 indicator(s) in batch "
                            f"{batch_count} of {len(ioc_payload)} "
                            "indicator(s)."
                        )
                        self.logger.info(f"{self.log_prefix}: {log_msg}")
                    else:
                        push_failed += len(ioc_payload)
                        err_msg = (
                            "Unable to initiate Threat "
                            f"Hunt: {threat_hunt_name} for batch "
                            f"{batch_count} of "
                            f"{len(ioc_payload)} indicator(s)."
                        )
                        self.logger.error(f"{self.log_prefix}: {err_msg}")

                log_msg = (
                    f"Total indicator(s) fetched: {total_indicators_count}. "
                    f"Successfully initiated Threat Hunt "
                    f"for {total_sha256_pushed} SHA256, "
                    f"{total_md5_pushed} MD5, and skipped "
                    f"{total_skipped} indicator(s) out of "
                    f"{push_success} indicator(s). "
                    f"Failed to initiate Threat Hunt for "
                    f"{push_failed} indicator(s)."
                )
                self.logger.info(f"{self.log_prefix}: {log_msg}")

                return PushResult(
                    success=True,
                    message=log_msg,
                )

        except RubrikPluginException:
            raise
        except Exception as err:
            err_msg = (
                "An unexpected error occurred while initiating Threat Hunt."
            )
            self.logger.error(
                f"{self.log_prefix}: {err_msg} Error: {err}",
                details=str(traceback.format_exc()),
            )
            return PushResult(success=False, message=err_msg)

    def validate(self, configuration) -> ValidationResult:
        """Validate the Plugin configuration parameters.

        Args:
            configuration (dict): Dict object having all the Plugin
            configuration parameters.
        Returns:
            cte.plugin_base.ValidateResult: ValidateResult object with
            success flag and message.
        """

        validation_err_msg = "Validation error occurred"
        self.logger.debug(
            f"{self.log_prefix}: Validating configuration parameters."
        )
        base_url = configuration.get("base_url", "").strip().strip("/")
        if not base_url:
            err_msg = "Base URL is a required configuration parameter."
            self.logger.error(
                f"{self.log_prefix}: {validation_err_msg}. {err_msg}"
            )
            return ValidationResult(success=False, message=err_msg)

        elif not isinstance(base_url, str) or not self._validate_url(base_url):
            err_msg = "Invalid Base URL provided in configuration parameters."
            self.logger.error(
                f"{self.log_prefix}: {validation_err_msg}. {err_msg}"
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )

        client_id = configuration.get("client_id", "").strip()
        if not client_id:
            err_msg = "Client ID is a required configuration parameter."
            self.logger.error(
                f"{self.log_prefix}: {validation_err_msg}. {err_msg}"
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        elif not isinstance(client_id, str):
            err_msg = "Invalid Client ID provided in configuration parameters."
            self.logger.error(
                f"{self.log_prefix}: {validation_err_msg}. {err_msg}"
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )

        client_secret = configuration.get("client_secret")
        if not client_secret:
            err_msg = "Client Secret is a required configuration parameter."
            self.logger.error(
                f"{self.log_prefix}: {validation_err_msg}. {err_msg}"
            )
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        elif not isinstance(client_secret, str):
            err_msg = (
                "Invalid Client Secret provided in configuration parameters."
            )
            self.logger.error(
                f"{self.log_prefix}: {validation_err_msg}."
                f"{err_msg} Client Secret should be an non-empty string."
            )
            return ValidationResult(
                success=False,
                message=(
                    f"{err_msg} Client Secret should be an non-empty string."
                ),
            )

        return self._validate_auth_params(configuration)

    def _validate_auth_params(self, configuration: dict) -> ValidationResult:
        """Validate the authentication params with Rubrik platform.

        Args:
            configuration (dict): Configuration parameters dictionary.

        Returns:
            ValidationResult: ValidationResult object having validation
            results after making an API call.
        """

        try:
            (base_url, client_id, client_secret) = self.helper.get_credentials(
                configuration
            )
            auth_url = f"{base_url}/api/client_token"
            _ = self.helper.get_auth_header(
                client_id, client_secret, auth_url, is_validation=True
            )
            self.logger.debug(
                f"{self.log_prefix}: Validation successful "
                f"for {PLATFORM_NAME}."
            )
            return ValidationResult(
                success=True, message="Validation successful."
            )
        except RubrikPluginException as exp:
            return ValidationResult(success=False, message=str(exp))
        except Exception as exp:
            err_msg = "Unexpected validation error occurred."
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {exp}",
                details=str(traceback.format_exc()),
            )
            return ValidationResult(
                success=False,
                message=f"{err_msg}. Check logs for more details.",
            )

    def get_actions(self):
        """Get available actions."""
        return [
            ActionWithoutParams(
                label="Start Threat Hunt",
                value="start_threat_hunt",
            ),
        ]

    def get_action_fields(self, action: Action):
        """
        Get fields required for an action.

        Args:
            action (Action): Action object.

        Returns:
            list: List of ActionField objects.

        """

        cluster_list = self._get_cluster_uuid_and_list_from_rubrik("", True)
        default = None
        if len(cluster_list) > 0:
            default = cluster_list[0]
        action_value = action.value
        if action_value == "start_threat_hunt":
            return [
                {
                    "label": "Threat Hunt Name",
                    "key": "threat_hunt_name",
                    "type": "text",
                    "default": None,
                    "mandatory": True,
                    "description": (
                        "Enter the name of the Threat Hunt. A Threat Hunt "
                        f"with this name will be initiated on {PLATFORM_NAME}."
                    ),
                },
                {
                    "label": "Cluster Name",
                    "key": "cluster_name",
                    "type": "choice",
                    "choices": [
                        {"key": name, "value": name} for name in cluster_list
                    ],
                    "default": default,
                    "mandatory": True,
                    "description": (
                        "Rubrik Cluster for which you want to "
                        "initiate Threat Hunt."
                    ),
                },
                {
                    "label": "Max File Size to Scan (in KB)",
                    "key": "max_file_size",
                    "type": "number",
                    "default": 1024,
                    "mandatory": True,
                    "description": (
                        "Maximum file size in KB to scan. "
                        "Default is 1024 KB. Maximum supported size is "
                        f"{FILE_SIZE_LIMIT} KB and minimum supported size "
                        "is 1 KB."
                    ),
                },
                {
                    "label": "Min File Size to Scan (in KB)",
                    "key": "min_file_size",
                    "type": "number",
                    "default": 5,
                    "mandatory": True,
                    "description": (
                        "Minimum file size in KB to scan. Default is 5 KB. "
                        f"Maximum supported size is {FILE_SIZE_LIMIT} KB"
                        " and minimum supported size is 1 KB."
                    ),
                },
                {
                    "label": "Max IOC Matches (Per Snapshot)",
                    "key": "max_ioc_matches",
                    "type": "number",
                    "default": 1,
                    "mandatory": True,
                    "description": (
                        "Maximum IOC matches per snapshot. Default is 1. "
                        f"Maximum supported value is {MAX_IOC_MATCHES} and "
                        "minimum supported value is 1."
                    ),
                },
                {
                    "label": "Include Files",
                    "key": "include_files",
                    "type": "multichoice",
                    "choices": [
                        {"key": name.strip('"'), "value": name}
                        for name in INCLUDE_FILE_LIST
                    ],
                    "default": INCLUDE_FILE_LIST,
                    "mandatory": False,
                    "description": "Files to include in Threat Hunt.",
                },
                {
                    "label": "Exclude Files",
                    "key": "exclude_files",
                    "type": "multichoice",
                    "choices": [
                        {"key": name.strip('"'), "value": name}
                        for name in INCLUDE_FILE_LIST
                    ],
                    "default": [],
                    "mandatory": False,
                    "description": "Files to exclude from Threat Hunt.",
                },
                {
                    "label": "Do Not Exclude Files",
                    "key": "do_not_exclude_files",
                    "type": "multichoice",
                    "choices": [
                        {"key": name.strip('"'), "value": name}
                        for name in INCLUDE_FILE_LIST
                    ],
                    "default": [],
                    "mandatory": False,
                    "description": (
                        "File which should not be excluded from Threat Hunt."
                    ),
                },
            ]

    def validate_action(self, action: Action) -> ValidationResult:
        """Validate Rubrik configuration.

        Args:
            action (Action): Action to perform on IoCs.

        Returns:
            ValidationResult: Validation result.
        """

        action_value = action.value
        if action_value != "start_threat_hunt":
            err_msg = (
                f"Unsupported action {action_value} provided. "
                "Supported action is Start Threat Hunt."
            )
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            return ValidationResult(success=False, message=err_msg)

        if action_value == "start_threat_hunt":

            threat_hunt_name = action.parameters.get(
                "threat_hunt_name", ""
            ).strip()

            if not threat_hunt_name:
                err_msg = "Threat Hunt Name is a required action parameter."
                self.logger.error(f"{self.log_prefix}: {err_msg}")
                return ValidationResult(success=False, message=err_msg)

            elif not isinstance(threat_hunt_name, str):
                err_msg = (
                    "Invalid Threat Hunt Name provided, Threat Hunt "
                    "Name should be String."
                )
                self.logger.error(f"{self.log_prefix}: {err_msg}")
                return ValidationResult(success=False, message=err_msg)

            cluster_name = action.parameters.get("cluster_name")
            if cluster_name is None:
                err_msg = "Cluster name is a required action parameter."
                self.logger.error(f"{self.log_prefix}: {err_msg}")
                return ValidationResult(success=False, message=err_msg)

            elif not isinstance(cluster_name, str):
                err_msg = (
                    "Invalid Cluster Name provided, Cluster "
                    "Name should be String."
                )
                self.logger.error(f"{self.log_prefix}: {err_msg}")
                return ValidationResult(success=False, message=err_msg)

            max_file_size = action.parameters.get("max_file_size")

            if max_file_size is None:
                err_msg = "Max File Size is a required action parameter."
                self.logger.error(f"{self.log_prefix}: {err_msg}")
                return ValidationResult(success=False, message=err_msg)

            elif (
                not isinstance(max_file_size, int)
                or max_file_size > FILE_SIZE_LIMIT
                or max_file_size < 1
            ):
                err_msg = (
                    "Invalid Max File Size provided in action parameters. "
                    "Max File Size should be an valid integer in "
                    f"range 1 to {FILE_SIZE_LIMIT}."
                )
                self.logger.error(f"{self.log_prefix}: {err_msg}")
                return ValidationResult(success=False, message=err_msg)

            min_file_size = action.parameters.get("min_file_size")
            if min_file_size is None:
                err_msg = "Min File Size is a required action parameter."
                self.logger.error(f"{self.log_prefix}: {err_msg}")
                return ValidationResult(success=False, message=err_msg)

            elif (
                not isinstance(min_file_size, int)
                or min_file_size > FILE_SIZE_LIMIT
                or min_file_size < 1
            ):
                err_msg = (
                    "Invalid Min File Size provided in action parameters. "
                    "Min File Size should be an valid integer in "
                    f"range 1 to {FILE_SIZE_LIMIT}."
                )
                self.logger.error(f"{self.log_prefix}: {err_msg}")
                return ValidationResult(success=False, message=err_msg)

            if max_file_size < min_file_size:
                err_msg = (
                    "Invalid Max/Min File Size provided. Max File Size"
                    " should be greater than or equal to "
                    "Min File Size."
                )
                self.logger.error(f"{self.log_prefix}: {err_msg}")
                return ValidationResult(success=False, message=err_msg)

            max_ioc_matches = action.parameters.get("max_ioc_matches")
            if max_ioc_matches is None:
                err_msg = "Max IOC Matches is a required action parameter."
                self.logger.error(f"{self.log_prefix}: {err_msg}")
                return ValidationResult(success=False, message=err_msg)

            elif (
                not isinstance(max_ioc_matches, int)
                or max_ioc_matches > MAX_IOC_MATCHES
                or max_ioc_matches < 1
            ):
                err_msg = (
                    "Invalid Max IOC Matches provided in action parameters. "
                    "Max IOC Matches should be an valid integer in "
                    f"range 1 to {MAX_IOC_MATCHES}."
                )
                self.logger.error(f"{self.log_prefix}: {err_msg}")
                return ValidationResult(success=False, message=err_msg)

            include_files = action.parameters.get("include_files")
            if include_files and not all(
                x in INCLUDE_FILE_LIST for x in include_files
            ):
                err_msg = (
                    "Invalid Include Files provided. "
                    "It should be from the following: "
                    f"{INCLUDE_FILE_LIST}."
                )
                self.logger.error(f"{self.log_prefix}: {err_msg}")
                return ValidationResult(success=False, message=err_msg)

            exclude_files = action.parameters.get("exclude_files")
            if exclude_files and not all(
                x in INCLUDE_FILE_LIST for x in exclude_files
            ):
                err_msg = (
                    "Invalid Exclude Files provided. "
                    "It should be from the following: "
                    f"{INCLUDE_FILE_LIST}."
                )
                self.logger.error(f"{self.log_prefix}: {err_msg}")
                return ValidationResult(success=False, message=err_msg)

            do_not_exclude_files = action.parameters.get(
                "do_not_exclude_files"
            )
            if do_not_exclude_files and not all(
                x in INCLUDE_FILE_LIST for x in do_not_exclude_files
            ):
                err_msg = (
                    "Invalid Do Not Include Files provided. "
                    "It should be from the following: "
                    f"{INCLUDE_FILE_LIST}."
                )
                self.logger.error(f"{self.log_prefix}: {err_msg}")
                return ValidationResult(success=False, message=err_msg)

            self.logger.info(
                f"{self.log_prefix}: Successfully validated the "
                f"action parameters for action {action_value}."
            )
            return ValidationResult(
                success=True,
                message="Validation successful.",
            )
