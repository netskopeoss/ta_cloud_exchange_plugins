# -*- coding: utf-8 -*-

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

CRE Illumio plugin helper module.

Portions of the PCE connection and label-scope parsing utilities are
derived from the Illumio SDK (© 2023 Illumio, Apache-2.0 License).
"""

import json
import traceback
from typing import Callable, Dict, List, Literal, Tuple, Union
from urllib.parse import urlparse

from netskope.common.utils import add_user_agent
from netskope.integrations.crev2.plugin_base import ValidationResult

from illumio import PolicyComputeEngine
from illumio.exceptions import IllumioApiException

from .constants import (
    HOST_FIELD_MAPPING,
    MAX_PORT_NUMBER,
    MIN_PORT_NUMBER,
    MODULE_NAME,
    PLUGIN_NAME,
)
from .exceptions import IllumioPluginException


class IllumioPluginHelper(object):
    """IllumioPluginHelper class.

    Args:
        object (object): Object class.
    """

    def __init__(
        self,
        logger,
        log_prefix: str,
        plugin_name: str,
        plugin_version: str,
    ):
        """IllumioPluginHelper initializer.

        Args:
            logger (logger object): Logger object.
            log_prefix (str): log prefix.
            plugin_name (str): Plugin name.
            plugin_version (str): Plugin version.
        """
        self.log_prefix = log_prefix
        self.logger = logger
        self.plugin_name = plugin_name
        self.plugin_version = plugin_version

    def _add_user_agent(self, headers: Union[Dict, None] = None) -> Dict:
        """Add User-Agent in the headers for third-party requests.

        Args:
            headers (Dict): Headers needed to pass to the Third Party
                Platform.

        Returns:
            Dict: Dictionary after adding User-Agent.
        """
        if headers and "User-Agent" in headers:
            return headers

        headers = add_user_agent(header=headers)
        ce_added_agent = headers.get("User-Agent", "netskope-ce")
        user_agent = "{}-{}-{}-v{}".format(
            ce_added_agent,
            MODULE_NAME.lower(),
            self.plugin_name.lower().replace(" ", "-"),
            self.plugin_version,
        )
        headers.update({"User-Agent": user_agent})
        return headers

    def _validate_url(self, url: str) -> bool:
        """Validate the given URL using parsing.

        Args:
            url (str): Given URL.

        Returns:
            bool: True if the URL is valid, False otherwise.
        """
        parsed = urlparse(url.strip())
        return parsed.scheme.strip() != "" and parsed.netloc.strip() != ""

    def get_credentials(self, configuration: dict) -> Tuple:
        """Extract credential/config fields from the plugin configuration.

        Args:
            configuration (dict): Plugin configuration parameter map.

        Returns:
            Tuple: (base_url, pce_port, org_id, api_username, api_secret,
                label_scope).
        """
        base_url = configuration.get("pce_url", "").strip().strip("/")
        pce_port = configuration.get("pce_port")
        org_id = configuration.get("org_id")
        api_username = configuration.get("api_username", "").strip()
        api_secret = configuration.get("api_secret")
        label_scope = configuration.get("label_scope", "").strip()

        return (
            base_url,
            pce_port,
            org_id,
            api_username,
            api_secret,
            label_scope,
        )

    def validate_port_number(self, port: int) -> Union[bool, str]:
        """Validate that the PCE port number is within the allowed range.

        Args:
            port (int): PCE Port Number to validate.

        Returns:
            bool | str: True if valid, else a specific error message.
        """
        if MIN_PORT_NUMBER <= port <= MAX_PORT_NUMBER:
            return True
        return (
            "Invalid PCE Port Number provided in the configuration"
            " parameters. PCE Port Number should be between"
            f" {MIN_PORT_NUMBER} and {MAX_PORT_NUMBER}."
        )

    def validate_org_id(self, org_id: int) -> Union[bool, str]:
        """Validate that the PCE Organization ID is a positive integer.

        Args:
            org_id (int): PCE Organization ID to validate.

        Returns:
            bool | str: True if valid, else a specific error message.
        """
        if org_id > 0:
            return True
        return (
            "Invalid PCE Organization ID provided in the configuration"
            " parameters. PCE Organization ID should be an integer"
            " greater than 0."
        )

    def validate_label_scope_format(
        self, label_scope: str
    ) -> Union[bool, str]:
        """Validate that the Label Scope is in the expected format.

        Args:
            label_scope (str): Label Scope to validate.

        Returns:
            bool | str: True if valid, else a specific error message.
        """
        try:
            self.parse_label_scope(
                "parsing label references for validation",
                label_scope,
                is_validation=True,
            )
            return True
        except Exception as err:
            return str(err)

    def validate_parameters(
        self,
        field_name: str,
        field_value,
        field_type: type,
        parameter_type: Literal["configuration", "action"] = "configuration",
        allowed_values: Union[List, Dict] = None,
        custom_validation_func: Callable = None,
        is_required: bool = True,
        validation_err_msg: str = "Validation error occurred. ",
    ) -> Union[ValidationResult, None]:
        """Validate a configuration or action parameter.

        Args:
            field_name (str): Parameter name.
            field_value: Parameter value.
            field_type (type): Expected type.
            parameter_type (Literal): "configuration" or "action".
            allowed_values (List | Dict, optional): Allowed values.
            custom_validation_func (Callable, optional): Custom validation
                function. Should return True when the field is valid, or
                either False or a specific error message string when it
                is not.
            is_required (bool): Whether the field is required.
            validation_err_msg (str): Error message prefix.

        Returns:
            ValidationResult or None: ValidationResult on failure, else None.
        """
        if field_type is str and isinstance(field_value, str):
            field_value = field_value.strip()

        # Required check. Integers/floats (including 0) are treated as
        # provided so that a genuine 0 is not reported as missing.
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
                    "Ensure that a value is provided for the"
                    f" '{field_name}' {parameter_type} parameter."
                ),
            )
            return ValidationResult(success=False, message=err_msg)

        # Type check.
        if is_required and not isinstance(field_value, field_type):
            err_msg = (
                f"Invalid value provided for the {parameter_type}"
                f" parameter '{field_name}'."
            )
            self.logger.error(
                message=(
                    f"{self.log_prefix}: {validation_err_msg}{err_msg}"
                ),
                resolution=(
                    "Ensure that a valid value is provided for the"
                    f" '{field_name}' {parameter_type} parameter."
                ),
            )
            return ValidationResult(success=False, message=err_msg)

        # Custom validation.
        if custom_validation_func:
            validation_outcome = custom_validation_func(field_value)
            if validation_outcome is not True:
                err_msg = (
                    validation_outcome
                    if isinstance(validation_outcome, str)
                    else (
                        f"Invalid value provided for the {parameter_type}"
                        f" parameter '{field_name}'."
                    )
                )
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: {validation_err_msg}{err_msg}"
                    ),
                    resolution=(
                        "Ensure that a valid value is provided for the"
                        f" '{field_name}' {parameter_type} parameter."
                    ),
                )
                return ValidationResult(success=False, message=err_msg)

        # Allowed values check.
        if allowed_values and isinstance(field_value, str):
            if field_value not in allowed_values:
                err_msg = (
                    f"Invalid value provided for the {parameter_type}"
                    f" parameter '{field_name}'. Allowed values are"
                    f" {', '.join(str(v) for v in allowed_values)}."
                )
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: {validation_err_msg}{err_msg}"
                    ),
                    resolution=(
                        "Ensure that a valid value is provided from the"
                        " allowed values."
                    ),
                )
                return ValidationResult(success=False, message=err_msg)
        return None

    def validate_entity(self, entity: str, supported_entity: str) -> None:
        """Ensure the requested entity is supported by this plugin.

        Args:
            entity (str): Name of the entity requested by the caller.
            supported_entity (str): Name of the entity this plugin supports.

        Raises:
            IllumioPluginException: if the entity is not supported.
        """
        if entity != supported_entity:
            err_msg = (
                f"Invalid entity found. {PLUGIN_NAME}"
                f" only supports {supported_entity} entity."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                resolution=(
                    f"Ensure that the selected entity is"
                    f" '{supported_entity}'."
                ),
            )
            raise IllumioPluginException(err_msg)

    def add_field(self, fields_dict: dict, field_name: str, value):
        """Add field to the extracted_fields dictionary.

        Empty dicts/lists are stored as None (MongoDB safety) so that the
        record shape stays consistent instead of persisting an empty
        container for a field that is populated in other records.

        Args:
            fields_dict (dict): Field dictionary to update.
            field_name (str): Field name to add.
            value: Field value to add.
        """
        if isinstance(value, (dict, list)) and not value:
            fields_dict[field_name] = None
            return

        if isinstance(value, int):
            fields_dict[field_name] = value
            return

        if value:
            fields_dict[field_name] = value

    def _extract_field_from_event(
        self, key: str, workload, default=None, transformation=None
    ):
        """Extract a (possibly nested) field value from a workload object.

        Dotted keys (e.g. "agent.config.mode") are resolved one attribute at
        a time via ``getattr`` since the workload is an SDK dataclass object
        rather than a dict. An optional ``transformation`` (the name of a
        method on this helper) is applied to the resolved value, mirroring
        the data-driven mapping used by the reference SentinelOne plugin.

        Args:
            key (str): Attribute path to fetch (supports dotted notation).
            workload (Workload): Workload object.
            default (Any, None): Default value when the path is absent.
            transformation (str, None, optional): Name of a helper method to
                apply to the resolved value. Defaults to None.

        Returns:
            Any: Resolved (and optionally transformed) value, or ``default``.
        """
        value = workload
        for part in key.split("."):
            value = getattr(value, part, None)
            if value is None:
                return default

        if key == "href" and isinstance(value, str):
            value = value.split("/")[-1]

        if transformation:
            transformation_func = getattr(self, transformation)
            return transformation_func(value)

        if isinstance(value, (str, bool, int, float)):
            return value

        return default

    def _extract_labels(self, workload) -> Tuple[List[str], List[str]]:
        """Extract a workload's labels as 'key:value' strings.

        Args:
            workload (Workload): Workload object.

        Returns:
            Tuple[List[str], List[str]]: A tuple of (labels, skipped_labels)
                where labels have both a key and value, and skipped_labels
                are those missing a key.
        """
        labels = getattr(workload, "labels", None) or []
        label_list = list(
            {
                f"{label.key}:{label.value}"
                for label in labels
                if label.key and label.value
            }
        )
        skipped_tags = list(
            {
                f"{label.key}:{label.value}"
                for label in labels
                if not label.key and label.value
            }
        )
        return label_list, skipped_tags

    def extract_entity_fields(
        self,
        workload=None,
        hostname=None,
        include_tags=False,
    ) -> Tuple[dict, int]:
        """Extract required entity fields from a workload.

        Args:
            workload (Workload, optional): Workload object.
            hostname (str, optional): Workload hostname or interface address.
            include_tags (bool, optional): Include tags or not.
                Defaults to False.

        Returns:
            Tuple[dict, int]: Extracted fields dictionary and the count of
                skipped tags.
        """
        extracted_fields = {}
        skipped_tags = []
        for field_name, field_value in HOST_FIELD_MAPPING.items():
            self.add_field(
                extracted_fields,
                field_name,
                self._extract_field_from_event(
                    field_value.get("key"),
                    workload,
                    field_value.get("default"),
                    field_value.get("transformation"),
                ),
            )
        self.add_field(extracted_fields, "Host", hostname)
        if include_tags:
            label_list, skipped_tags = self._extract_labels(workload)
            self.add_field(extracted_fields, "Labels", label_list)

        return extracted_fields, len(skipped_tags)

    def _extract_single_host_record(
        self, hostname: str, workload, workload_id: str, include_tags: bool
    ) -> Tuple[Union[dict, None], int]:
        """Extract entity fields for a single hostname/address of a workload.

        Args:
            hostname (str): Hostname or interface address to record the
                extracted fields under.
            workload (Workload): Workload object the hostname belongs to.
            workload_id (str): Workload ID (used for logging).
            include_tags (bool): Whether to include Labels in the extracted
                fields.

        Returns:
            Tuple[dict | None, int]: Extracted fields (None on failure or
                when nothing was extracted) and the count of skipped tags.
        """
        try:
            extracted_fields, skipped_tags = self.extract_entity_fields(
                hostname=hostname,
                workload=workload,
                include_tags=include_tags,
            )
            return extracted_fields or None, skipped_tags
        except IllumioPluginException:
            return None, 0
        except Exception as err:
            err_msg = (
                f"Unable to extract fields from host {hostname} having"
                f' Workload ID "{workload_id}".'
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {err}",
                details=str(traceback.format_exc()),
            )
            return None, 0

    def extract_records_from_workloads(
        self, workloads: List, include_tags: bool = False
    ) -> Tuple[List[dict], Dict[str, int]]:
        """Extract entity records for every hostname/address in workloads.

        A record is extracted for the workload's hostname (if any) and for
        each of its interface addresses.

        Args:
            workloads (List[Workload]): Workloads fetched from the PCE.
            include_tags (bool, optional): Include Labels in the extracted
                fields. Defaults to False.

        Returns:
            Tuple[List[dict], Dict[str, int]]: Extracted records, and a
                stats dict with keys "hostname_count", "address_count" and
                "skipped_records", "skipped_tags".
        """
        records = []
        stats = {
            "hostname_count": 0,
            "address_count": 0,
            "skipped_records": 0,
            "skipped_tags": 0,
        }
        for workload in workloads:
            workload_id = workload.href.split("/")[-1]
            self.logger.debug(
                f"{self.log_prefix}: Extracting record(s) from workload"
                f" with ID '{workload_id}'."
            )
            interfaces = getattr(workload, "interfaces", None) or []
            addresses = [str(intf.address) for intf in interfaces]

            if workload.hostname:
                fields, skipped_tags = self._extract_single_host_record(
                    workload.hostname, workload, workload_id, include_tags
                )
                stats["skipped_tags"] += skipped_tags
                if fields:
                    records.append(fields)
                    stats["hostname_count"] += 1
                else:
                    stats["skipped_records"] += 1

            address_count = 0
            for address in addresses:
                fields, skipped_tags = self._extract_single_host_record(
                    address, workload, workload_id, include_tags
                )
                stats["skipped_tags"] += skipped_tags
                if fields:
                    records.append(fields)
                    address_count += 1
                else:
                    stats["skipped_records"] += 1
            stats["address_count"] += address_count

            self.logger.info(
                f"{self.log_prefix}: Successfully extracted {address_count}"
                f" address(es) with hostname {workload.hostname} and"
                f" workload ID '{workload_id}'. Total addresses extracted"
                f' till now - {stats["address_count"]}. Total hostnames'
                f' extracted till now - {stats["hostname_count"]}.'
            )
        return records, stats

    def count_matchable_records(self, records: List[dict]) -> int:
        """Count records that carry both a Workload ID and a Host field.

        Args:
            records (List[dict]): Records received for the update call.

        Returns:
            int: Number of records that can be matched to a workload.
        """
        return sum(
            1
            for record in records
            if record.get("Workload ID") and record.get("Host")
        )

    def get_label_refs(self, pce, labels: dict) -> List[List[str]]:
        """Retrieve Label object HREFs from the PCE.

        Args:
            pce (PolicyComputeEngine): PCE API client object.
            labels (dict): label key:value pairs to look up.

        Returns:
            List[List[str]]: Nested list of HREFs, one inner list per
                label - the format expected by the PCE workloads "labels"
                query param.

        Raises:
            IllumioPluginException: if a label with the given key:value
                can't be found.
        """
        refs = []
        try:
            for key, value in labels.items():
                fetched_labels = pce.labels.get(
                    params={"key": key, "value": value}
                )
                if fetched_labels and fetched_labels[0].value == value:
                    # only expect to match a single label for each k:v pair
                    refs.append([fetched_labels[0].href])
                else:
                    # if we don't raise an error, we risk pulling workloads
                    # outside the expected scope and blocking legitimate
                    # access
                    msg = f"Failed to find label Href for {key}:{value}."
                    self.logger.error(
                        message=f"{self.log_prefix}: {msg}",
                        resolution=(
                            "Verify that the provided Label Scope is"
                            f" present on the {PLUGIN_NAME} platform."
                        ),
                    )
                    raise IllumioPluginException(msg)
            return refs
        except IllumioPluginException:
            raise
        except Exception as err:
            err_msg = "Error occurred while fetching label reference."
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {err}",
                details=str(traceback.format_exc()),
                resolution=(
                    "Verify that the provided Label Scope is present on"
                    f" the {PLUGIN_NAME} platform and that the PCE is"
                    " reachable."
                ),
            )
            raise IllumioPluginException(err_msg)

    @staticmethod
    def is_duplicate_async_job_error(err: Exception) -> bool:
        """Check if an IllumioApiException was caused by a 409 conflict due
        to a duplicate async job already in progress/queued on the PCE.

        The PCE SDK wraps the underlying error in nested exceptions (and
        sometimes drops the message along the way), so walk the exception's
        `__cause__` chain looking for the PCE's error token.

        Args:
            err (Exception): Exception raised while fetching workloads.

        Returns:
            bool: True if the error is a duplicate async job conflict.
        """
        seen = err
        while seen is not None:
            if "duplicate_async_jobs" in str(seen):
                return True
            seen = seen.__cause__
        return False

    def get_workloads(self, pce, label_scope: str) -> List:
        """Fetch the workloads within a label scope from the PCE.

        Args:
            pce (PolicyComputeEngine): PCE API client object.
            label_scope (str): Label scope as a comma-separated
                key1:value1,key2:value2... string.

        Returns:
            List[Workload]: Workloads matching the label scope.
        """
        labels = self.parse_label_scope("parsing label scopes", label_scope)
        refs = self.get_label_refs(pce, labels)
        return pce.workloads.get_async(
            # the labels query param takes a JSON-formatted nested list of
            # label HREFs - each inner list represents a separate scope
            params={
                "labels": json.dumps(refs),
                # include label keys/values in the response data
                "representation": "workload_labels",
            }
        )

    def connect_and_fetch_workloads(
        self,
        configuration: dict,
        ssl_validation,
        proxies: dict,
        label_scope: str,
    ) -> Tuple[PolicyComputeEngine, List]:
        """Connect to the PCE and fetch workloads within a label scope.

        Args:
            configuration (dict): Plugin configuration parameter map.
            ssl_validation: SSL validation setting for PCE requests.
            proxies (dict): HTTP/S proxy server settings.
            label_scope (str): Label scope to fetch workloads for.

        Returns:
            Tuple[PolicyComputeEngine, List[Workload]]: Connected PCE
                client and the workloads found within the label scope.
        """
        pce = self.connect_to_pce(
            "connecting to PCE",
            configuration,
            verify=ssl_validation,
            proxies=proxies,
            headers=self._add_user_agent(),
        )
        workloads = self.get_workloads(pce, label_scope)
        if not workloads:
            self.logger.info(
                f"{self.log_prefix}: No Workloads found containing the"
                f" Label Scope(s) - '{label_scope}'."
            )
        else:
            self.logger.debug(
                f"{self.log_prefix}: Total {len(workloads)} Workload(s)"
                " fetched containing the Label Scope(s) -"
                f" '{label_scope}'. These Workloads will be used to check"
                " for updates."
            )
        return pce, workloads

    def parse_label_scope(
        self, logger_message, scope: str, is_validation=False
    ) -> dict:
        """Parse label scopes passed as a string of the form k1:v1,k2:v2,...

        Args:
            logger_message (str): Logger message describing the operation.
            scope (str): Policy scope as a comma-separated key:value pair list.
            is_validation (bool): Is this a validation call?

        Returns:
            dict: dict containing label key:value pairs.

        Raises:
            IllumioPluginException: if the given scope format is invalid.
        """
        try:
            label_dimensions = scope.split(",")
            labels = {}
            for label in label_dimensions:
                if not label.strip():
                    continue

                try:
                    k, v = label.split(":")
                except Exception:
                    raise IllumioPluginException(
                        "Invalid format provided for the Label Scope: "
                        "must be key1:value1,key2:value2..."
                    )

                if not k.strip() or not v.strip():
                    raise IllumioPluginException(
                        "Invalid format provided for the Label Scope:"
                        " Both the key and value are required"
                        " and cannot be empty."
                    )

                if k.strip() in labels:
                    raise IllumioPluginException(
                        "Label Scope keys must be unique, "
                        "duplicate keys are not allowed."
                    )

                labels[k.strip()] = v.strip()
            if not labels:
                raise IllumioPluginException(
                    "Label Scope is a required field."
                )
            return labels
        except IllumioPluginException as err:
            # the caller logs validation failures, to avoid a duplicate
            # log entry for the same error
            if is_validation:
                raise
            err_msg = f"Error occurred while {logger_message}."
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {err}",
                resolution=(
                    "Ensure that the Label Scope is provided in the"
                    " 'key1:value1,key2:value2' format with unique keys."
                ),
            )
            raise
        except Exception as err:
            err_msg = f"Error occurred while {logger_message}."
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {err}",
                details=str(traceback.format_exc()),
                resolution=(
                    "Ensure that the Label Scope is provided in the"
                    " 'key1:value1,key2:value2' format with unique keys."
                ),
            )
            raise IllumioPluginException(
                f"{err_msg} Check logs for more details."
            )

    def connect_to_pce(
        self,
        logger_msg,
        configuration: dict,
        headers: dict = None,
        verify=None,
        proxies=None,
        **kwargs,
    ) -> PolicyComputeEngine:  # noqa: E501
        """Connect to the PCE, returning the PolicyComputeEngine client.

        Args:
            logger_msg (str): Logger message describing the operation.
            configuration (dict): dict containing plugin configuration values.
            headers (dict): dict containing request headers.
            verify (bool): if False, disables TLS verification for PCE
                          requests.
            proxies (dict): dict containing HTTP/S proxy server settings.

        Returns:
            PolicyComputeEngine: PCE API client object.

        Raises:
            IllumioPluginException: if the PCE connection fails.
        """
        try:
            pce = PolicyComputeEngine(
                url=configuration.get("pce_url", "").strip().strip("/"),
                port=configuration.get("pce_port"),
                org_id=configuration.get("org_id"),
                **kwargs,
            )
            pce._session.headers.update(headers)
            pce.set_credentials(
                configuration.get("api_username", "").strip(),
                configuration.get("api_secret"),
            )
            pce.set_tls_settings(verify=verify)
            if proxies:
                pce.set_proxies(
                    http_proxy=proxies.get("http", ""),
                    https_proxy=proxies.get("https", ""),
                )
            pce.must_connect()
            return pce
        except IllumioApiException as err:
            err_msg = (
                f"Illumio API Exception occurred while {logger_msg}."
                " Validate the provided configuration parameters."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {str(err)}",
                details=str(traceback.format_exc()),
                resolution=(
                    "Ensure that the PCE URL, PCE Port Number, PCE"
                    " Organization ID, API Authentication Username and API"
                    " Secret provided in the configuration parameters are"
                    " correct and that the PCE server is reachable."
                ),
            )
            raise IllumioPluginException(err_msg)
        except Exception as exp:
            err_msg = f"Unexpected error occurred while {logger_msg}."
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {str(exp)}",
                details=str(traceback.format_exc()),
                resolution=(
                    "Ensure that the configuration parameters provided are"
                    " correct and that the PCE server is reachable."
                ),
            )
            raise IllumioPluginException(err_msg)
