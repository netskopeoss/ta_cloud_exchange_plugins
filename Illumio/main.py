# -*- coding: utf-8 -*-

"""This module provides the Illumio plugin for Netskope Threat Exchange.

Copyright:
    © 2023 Illumio

License:
    Apache2
"""
import json
import traceback
from typing import List

from netskope.common.utils import add_user_agent
from netskope.integrations.cte.models import Indicator, IndicatorType, TagIn
from netskope.integrations.cte.plugin_base import PluginBase, ValidationResult
from netskope.integrations.cte.utils import TagUtils

from illumio import PolicyComputeEngine, IllumioException

from .utils import (
    IllumioPluginConfig,
    parse_label_scope,
    connect_to_pce,
    load_manifest
)

ILO_ORANGE_HEX_CODE = "#f96425"


class IllumioPlugin(PluginBase):
    """Netskope Threat Exchange plugin for the Illumio PCE.

    Retrieves threat IoCs from Illumio based on a provided policy scope.
    """

    def __init__(self, name, *args, **kwargs) -> None:  # noqa: D107
        super().__init__(name, *args, **kwargs)
        self.pce: PolicyComputeEngine = None
        self.tag_utils: TagUtils = None
        manifest = load_manifest()
        self._version = manifest.get('version', '')
        plugin_name = manifest.get('name', '')
        self.log_prefix = f'CTE {plugin_name}' + (f' [{name}]' if name else '')

    def pull(self) -> List[Indicator]:
        """Pull workloads matching the configured scope from the Illumio PCE.

        Queries the PCE based on the given label scope, creating threat
        indicators for each interface on workloads matching the scope.

        Raises:
            IllumioException: if an error occurs while pulling IoCs.
        """
        try:
            conf = IllumioPluginConfig(**self.configuration)
            self.pce = connect_to_pce(
                conf, proxies=self.proxy, verify=self.ssl_validation,
                headers=self._get_connection_headers()
            )

            return self._get_threat_indicators(conf.label_scope)
        except Exception as e:
            msg = f"{self.log_prefix}: Failed to pull threat IoCs: {str(e)}"
            self.logger.error(msg, details=traceback.format_exc())
            raise IllumioException(msg) from e

    def _get_connection_headers(self) -> dict:
        """Set the Netskope User-Agent headers on the PCE HTTP session."""
        headers = add_user_agent()
        headers['User-Agent'] = '{}-cte-illumio-v{}'.format(
            headers.get('User-Agent', 'netskope-ce'), self._version
        )
        return headers

    def _get_threat_indicators(self, label_scope: str) -> List[Indicator]:
        """Retrieve threat workload IPs from the Illumio PCE.

        Given a PCE connection client and policy scope, we call the PCE APIs to
        get workloads matching the scope and return all interface IP addresses.

        Args:
            pce (PolicyComputeEngine): PCE API client object.
            label_scope (string): Policy scope as a comma-separated key:value
                pair list.

        Returns:
            List[str]: List of IP addresses from threat workloads.
        """
        refs = self._get_label_refs(parse_label_scope(label_scope))
        workloads = self.pce.workloads.get_async(
            # the labels query param takes a JSON-formatted nested list of
            # label HREFs - each inner list represents a separate scope
            params={
                'labels': json.dumps([refs]),
                # include label keys/values in the response data
                'representation': 'workload_labels'
            }
        )

        indicators = []

        for workload in workloads:
            workload_id = workload.href.split('/')[-1]
            pce_url = "{}://{}:{}".format(
                self.pce._scheme, self.pce._hostname, self.pce._port
            )
            workload_uri = f'{pce_url}/#/workloads/{workload_id}'
            desc = f'Illumio Workload - {workload.name}' \
                f'\n{workload.description}'

            uris = [str(intf.address) for intf in workload.interfaces]
            uris.append(workload.hostname)  # include the hostname as an IoC

            for uri in uris:
                if uri:
                    indicators.append(
                        Indicator(
                            value=uri,
                            type=IndicatorType.URL,
                            firstSeen=workload.created_at,
                            lastSeen=workload.updated_at,
                            comments=desc,
                            extendedInformation=workload_uri,
                            tags=self._create_label_tags(workload.labels)
                        )
                    )

        return indicators

    def _get_label_refs(self, labels: dict) -> List[str]:
        """Retrieve Label object HREFs from the PCE.

        Args:
            labels (dict): label key:value pairs to look up.

        Returns:
            List[str]: List of HREFs.

        Raises:
            ValueError: if a label with the given key:value can't be found.
        """
        refs = []

        for key, value in labels.items():
            labels = self.pce.labels.get(
                params={"key": key, "value": value}
            )
            if len(labels) > 0 and labels[0].value == value:
                # only expect to match a single label for each k:v pair
                refs.append(labels[0].href)
            else:
                # if we don't raise an error, we risk pulling workloads
                # outside the expected scope and blocking legitimate access
                msg = f'Failed to find label {key}:{value}'
                self.notifier.error(f'{self.log_prefix}: {msg}')
                raise ValueError(msg)

        return refs

    def _create_label_tags(self, labels: list) -> List[str]:
        """Create and return a list of tag names based on workload labels.

        If a tag for the label doesn't exist in Netskope, one is created.

        Args:
            labels (list): label objects for a given workload.

        Returns:
            List[str]: the label tag names, of the form key:value.
        """
        if str(self.configuration.get('enable_tagging', '')).lower() != 'yes':
            return []

        if not self.tag_utils:
            self.tag_utils = TagUtils()

        tags = []

        for label in labels:
            label_tag = f'{label.key}:{label.value}'

            if not self.tag_utils.exists(label_tag):
                self.tag_utils.create_tag(
                    TagIn(name=label_tag, color=ILO_ORANGE_HEX_CODE)
                )

            tags.append(label_tag)

        return tags

    def validate(self, configuration: dict) -> ValidationResult:
        """Validate the plugin configuration parameters.

        Args:
            configuration (dict): Plugin configuration parameter map.

        Returns:
            ValidationResult: Validation result with success flag and message.
        """
        self.logger.info(f"{self.log_prefix}: validating plugin instance")

        # read the configuration into a dataclass - type checking is performed
        # as a post-init on all fields. Implicitly checks existence, where the
        # TypeError falls through to the catch-all Exception case
        try:
            conf = IllumioPluginConfig(**configuration)
        except ValueError as e:
            self.logger.error(
                f"{self.log_prefix}: {str(e)}",
                details=traceback.format_exc()
            )
            return ValidationResult(success=False, message=str(e))
        except Exception as e:
            self.logger.error(
                f"{self.log_prefix}: Failed to read config: {str(e)}",
                details=traceback.format_exc()
            )
            return ValidationResult(
                success=False,
                message="Missing one or more configuration parameters"
            )

        error_message = ""

        if not conf.pce_url.strip():
            error_message = "PCE URL cannot be empty"
        elif not conf.api_username.strip():
            error_message = "API Username cannot be empty"
        elif not conf.api_secret.strip():
            error_message = "API Secret cannot be empty"
        elif conf.org_id <= 0:
            error_message = "Org ID must be a positive integer"
        elif not (1 <= conf.pce_port <= 65535):
            error_message = "PCE Port must be an integer in the range 1-65535"
        elif not conf.label_scope.strip():
            error_message = "Label Scope cannot be empty"
        else:
            try:
                parse_label_scope(conf.label_scope)
            except Exception as e:
                error_message = f"Failed to parse Label Scope: {str(e)}"

        # only try to connect if the configuration is valid
        if not error_message:
            try:
                connect_to_pce(
                    conf, proxies=self.proxy, verify=self.ssl_validation,
                    headers=self._get_connection_headers(),
                    # fail quickly if PCE connection params are invalid
                    retry_count=1, request_timeout=5
                )
            except Exception as e:
                error_message = f"Unable to connect to PCE: {str(e)}"

        error_message = error_message.strip()

        if error_message:
            self.logger.error(
                f"{self.log_prefix}: Validation error: {error_message}",
                details=traceback.format_exc()
            )

        return ValidationResult(
            success=error_message == "",
            message=error_message or "Validation successful"
        )
