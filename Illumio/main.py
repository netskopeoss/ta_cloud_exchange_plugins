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
from urllib.parse import urlparse, parse_qs

from netskope.common.utils import add_user_agent
from netskope.integrations.cte.models import Indicator, IndicatorType, TagIn
from netskope.integrations.cte.plugin_base import PluginBase, ValidationResult
from netskope.integrations.cte.utils import TagUtils
from typing import Dict, List, Tuple

from illumio import PolicyComputeEngine
from pydantic import ValidationError

from .utils.functions import (
    IllumioPluginHelper
)
from .utils.exceptions import IllumioPluginException


from .utils.constants import (
    MODULE_NAME,
    PLUGIN_NAME,
    PLUGIN_VERSION
)

ILO_ORANGE_HEX_CODE = "#f96425"


class IllumioPlugin(PluginBase):
    """Netskope Threat Exchange plugin for the Illumio PCE.

    Retrieves threat IoCs from Illumio based on a provided policy scope.
    """

    def __init__(self, name, *args, **kwargs) -> None:  # noqa: D107
        super().__init__(
            name,
            *args,
            **kwargs,
        )
        self.pce: PolicyComputeEngine = None
        self.tag_utils: TagUtils = None
        self.plugin_name, self.plugin_version = self._get_plugin_info()
        self.log_prefix = f"{MODULE_NAME} {self.plugin_name}"
        if name:
            self.log_prefix = f"{self.log_prefix} [{name}]"
        self.illumio_helper = IllumioPluginHelper(
            logger=self.logger,
            log_prefix=self.log_prefix,
            plugin_name=self.plugin_name,
            plugin_version=self.plugin_version,
            ssl_validation=self.ssl_validation,
            proxy=self.proxy,
        )
        

    def _get_plugin_info(self) -> Tuple:
        """Get plugin name and version from manifest.

        Returns:
            tuple: Tuple of plugin's name and version fetched from manifest.
        """
        try:
            manifest_json = IllumioPlugin.metadata
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

    def pull(self) -> List[Indicator]:
        """Pull workloads matching the configured scope from the Illumio PCE.

        Queries the PCE based on the given label scope, creating threat
        indicators for each interface on workloads matching the scope.

        Raises:
            IllumioException: if an error occurs while pulling IoCs.
        """
        if hasattr(self, "sub_checkpoint"):

            def wrapper(self):
                yield from self._get_threat_indicators()
            return wrapper(self)

        else:
            indicators = []
            for batch in self._get_threat_indicators():
                indicators.extend(batch)
            return indicators

    def _get_connection_headers(self, headers=None) -> dict:
        """Set the Netskope User-Agent headers on the PCE HTTP session."""
        if headers and "User-Agent" in headers:
            return headers
        headers = add_user_agent(headers)
        user_agent = "{}-{}-{}-v{}".format(
            headers.get("User-Agent", "netskope-ce"),
            MODULE_NAME.lower(),
            self.plugin_name.lower().replace(" ", "-"),
            self.plugin_version,
        )
        headers["User-Agent"] = user_agent
        return headers

    def _get_threat_indicators(self):
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
        try:
            logger_msg = "connecting to PCE for fetching indicators"
            self.pce = self.illumio_helper.connect_to_pce(
                logger_msg,
                self.configuration,
                headers=self._get_connection_headers()
            )
            logger_msg = "parsing label scopes"
            label = self.illumio_helper.parse_label_scope(logger_msg, self.configuration.get("label_scope").strip())
            logger_msg = "get label reference"
            refs = self._get_label_refs(label)
            workloads = self.pce.workloads.get_async(
                # the labels query param takes a JSON-formatted nested list of
                # label HREFs - each inner list represents a separate scope
                params={
                    'labels': json.dumps(refs),
                    # include label keys/values in the response data
                    'representation': 'workload_labels'
                }
            )
            if not workloads:
                self.logger.info(
                    f"No Workloads found containing the Label Scope(s) - "
                    f"'{self.configuration.get('label_scope')}'."
                )
                if hasattr(self, "sub_checkpoint"):
                    yield [], None
                else:
                    yield []
            
            self.logger.debug(
                f"{self.log_prefix}: Total {len(workloads)} Workload(s) "
                "fetched containing the Label Scope(s) - "
                f"'{self.configuration.get('label_scope')}'."
            )
            indicators = []
            skip_iocs = 0
            total_skipped_tags = set()
            successfully_fetched_ioc_count = 0
            url_count = 0

            for key, value in label.items():
                # Removing the <config_name> Latest tag from the existing indicators
                query = {"sources": {"$elemMatch": {"source": f"{self.name}"}}}
                if not self.tag_utils:
                    self.tag_utils = TagUtils()
                self.tag_utils.on_indicators(query).remove(f"{key}:{value}")
            for workload in workloads:
                workload_id = workload.href.split('/')[-1]
                pce_url = "{}://{}:{}".format(
                    self.pce._scheme, self.pce._hostname, self.pce._port
                )
                workload_uri = f'{pce_url}/#/workloads/{workload_id}'
                desc = (
                    f'Illumio Workload - {workload.name}'
                    f'\n{workload.description}'
                )

                uris = [str(intf.address) for intf in workload.interfaces]
                uris.append(workload.hostname)  # include the hostname as an IoC
                self.logger.debug(
                    f"{self.log_prefix}: Extracting Indicator(s) "
                    f"from workload with ID '{workload_id}'."
                )
                url_count = 0
                for uri in uris:
                    if uri:
                        tags, skipped_tags = self._create_label_tags(workload.labels)
                        total_skipped_tags.update(skipped_tags)
                        try:
                            indicators.append(
                                Indicator(
                                    value=uri,
                                    type=IndicatorType.URL,
                                    firstSeen=workload.created_at,
                                    lastSeen=workload.updated_at,
                                    comments=desc,
                                    extendedInformation=workload_uri,
                                    tags=tags
                                )
                            )
                            url_count += 1
                            successfully_fetched_ioc_count += 1
                        except (ValidationError, Exception) as error:
                            skip_iocs += 1
                            error_message = (
                                "Validation error occurred"
                                if isinstance(error, ValidationError)
                                else "Unexpected error occurred"
                            )
                            self.logger.error(
                                message=(
                                    f"{self.log_prefix}: {error_message} while"
                                    " creating indicator. This record "
                                    f"will be skipped. Error: {error}"
                                ),
                                details=str(traceback.format_exc()),
                            )
                self.logger.info(
                    f"{self.log_prefix}: Successfully fetched {url_count} "
                    f"indicator(s) with workload ID '{workload_id}'. "
                    f"Total indicator(s) fetched till now - {successfully_fetched_ioc_count}."
                )
            if len(total_skipped_tags) > 0:
                self.logger.info(
                    f"{self.log_prefix}: {len(total_skipped_tags)} tag(s) "
                    "skipped as they were longer than expected size or due"
                    " to some other exceptions that occurred while "
                    "creation of them. tags: "
                    f"({', '.join(total_skipped_tags)})."
                )
            info_msg = (
                f"Successfully fetched {successfully_fetched_ioc_count} indicator(s)."
            )
            if skip_iocs:
                info_msg += f" Skipped {skip_iocs} indicator(s)."
            self.logger.info(
                f"{self.log_prefix}: {info_msg}"
            )
            if hasattr(self, "sub_checkpoint"):
                yield indicators, None
            else:
                yield indicators
        except IllumioPluginException:
            raise
        except Exception as err:
            error_msg = (
                f"Error occurred while {logger_msg}."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {error_msg} Error: {err}",
                details=traceback.format_exc()
            )
            raise IllumioPluginException(error_msg)

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
        try:
            for key, value in labels.items():
                labels = self.pce.labels.get(
                    params={"key": key, "value": value}
                )
                if labels and labels[0].value == value:
                    # only expect to match a single label for each k:v pair
                    refs.append([labels[0].href])
                else:
                    # if we don't raise an error, we risk pulling workloads
                    # outside the expected scope and blocking legitimate access
                    msg = f'Failed to find label Href for {key}:{value} - Verify that the provided Label Scope is present on the {PLUGIN_NAME} platform.'
                    self.logger.error(f'{self.log_prefix}: {msg}')
                    raise IllumioPluginException(msg)
            return refs
        except IllumioPluginException:
            raise
        except Exception as err:
            err_msg = (
                f"Error occurred while fetching label reference."
            )
            self.logger.error(
                f"{self.log_prefix}: {err_msg}. Error: {err}"
            )
            raise IllumioPluginException(err_msg)

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

        created_tags, skipped_tags = set(), set()

        for label in labels:
            label_tag = f'{label.key}:{label.value}'
            try:
                if not self.tag_utils.exists(label_tag):
                    self.tag_utils.create_tag(
                        TagIn(name=label_tag, color=ILO_ORANGE_HEX_CODE)
                    )

                created_tags.add(label_tag)
            except ValueError:
                skipped_tags.add(label_tag)
            except Exception as exp:
                self.logger.error(
                    message=(
                        "{}: Unexpected error occurred"
                        " while creating tag {}. Error: {}".format(
                            self.log_prefix_with_name, label_tag, exp
                        )
                    ),
                    details=str(traceback.format_exc()),
                )
                skipped_tags.add(label_tag)

        return list(created_tags), list(skipped_tags)
    
    def _validate_url(self, url: str) -> bool:
        """Validate the given URL."""
        parsed = urlparse(url.strip())
        return parsed.scheme.strip() != "" and parsed.netloc.strip() != ""

    def validate(self, configuration: dict) -> ValidationResult:
        """Validate the plugin configuration parameters.

        Args:
            configuration (dict): Plugin configuration parameter map.

        Returns:
            ValidationResult: Validation result with success flag and message.
        """

        # read the configuration into a dataclass - type checking is performed
        # as a post-init on all fields. Implicitly checks existence, where the
        # TypeError falls through to the catch-all Exception case
        validation_msg = "Validation error occurred."
        base_url = configuration.get("pce_url", "").strip().strip("/")
        pce_port = configuration.get("pce_port")
        org_id = configuration.get("org_id")
        api_username = configuration.get("api_username", "").strip()
        api_secret = configuration.get("api_secret")
        label_scope = configuration.get("label_scope", "").strip()
        enable_tagging = configuration.get("enable_tagging", "")

        # BASE URL
        if not base_url:
            error_message = "PCE URL is a required configuration parameter."
            self.logger.error(f"{validation_msg} {error_message}")
            return ValidationResult(
                success=False, message=error_message
            )
        elif not (
            isinstance(base_url, str)
            and self._validate_url(base_url)
        ):
            error_message = "Invalid PCE URL provided in the configuration parameters."
            self.logger.error(f"{validation_msg} {error_message}")
            return ValidationResult(
                success=False, message=error_message
            )

        # PCE PORT
        if pce_port is None:
            error_message = "PCE Port Number is a required configuration parameter."
            self.logger.error(f"{validation_msg} {error_message}")
            return ValidationResult(
                success=False, message=error_message
            )
        elif not isinstance(pce_port, int) or not (1 <= pce_port <= 65535):
            error_message = "Invalid PCE Port Number found in the configuration parameters. PCE Port Number should be between 1 to 65535."
            self.logger.error(f"{validation_msg} {error_message}")
            return ValidationResult(
                success=False, message=error_message
            )

        # Organization ID
        if org_id is None:
            error_message = "PCE Organization ID is a required configuration parameter."
            self.logger.error(f"{validation_msg} {error_message}")
            return ValidationResult(
                success=False, message=error_message
            )
        elif not isinstance(org_id, int) or org_id <= 0:
            error_message = "Invalid PCE Organization ID found in the configuration parameters. PCE Organization ID should be greater than 0."
            self.logger.error(f"{validation_msg} {error_message}")
            return ValidationResult(
                success=False, message=error_message
            )

        # API Username
        if not api_username:
            error_message = "API Authentication Username is a required configuration parameter."
            self.logger.error(f"{validation_msg} {error_message}")
            return ValidationResult(
                success=False, message=error_message
            )
        elif not isinstance(api_username, str):
            error_message = "Invalid API Authentication Username found in the configuration parameters."
            self.logger.error(f"{validation_msg} {error_message}")
            return ValidationResult(
                success=False, message=error_message
            )
        
        # API Secret
        if not api_secret:
            error_message = "API Secret is a required configuration parameter."
            self.logger.error(f"{validation_msg} {error_message}")
            return ValidationResult(
                success=False, message=error_message
            )
        elif not isinstance(api_secret, str):
            error_message = "Invalid API Secret found in the configuration parameters."
            self.logger.error(f"{validation_msg} {error_message}")
            return ValidationResult(
                success=False, message=error_message
            )

        # Label Scope
        if not label_scope:
            error_message = "Label Scope is a required configuration parameter."
            self.logger.error(f"{validation_msg} {error_message}")
            return ValidationResult(
                success=False, message=error_message
            )
        elif not isinstance(label_scope, str):
            error_message = "Invalid Label Scope found in the configuration parameters."
            self.logger.error(f"{validation_msg} {error_message}")
            return ValidationResult(
                success=False, message=error_message
            )
        else:
            try:
                logger_message = "parsing label references for validation"
                self.illumio_helper.parse_label_scope(logger_message, label_scope, is_validation=True)
            except IllumioPluginException as err:
                return ValidationResult(
                    success=False, message=str(err)
                )
            except Exception as e:
                return ValidationResult(
                    success=False, message=str(e)
                )

        # Enable Tagging
        if not enable_tagging:
            error_message = "Enable Tagging is a required configuration parameter."
            self.logger.error(f"{validation_msg} {error_message}")
            return ValidationResult(
                success=False, message=error_message
            )
        elif not isinstance(enable_tagging, str) or enable_tagging not in ["yes", "no"]:
            error_message = "Invalid Enable Tagging found in the configuration parameters. Valid values are 'Yes' or 'No'."
            self.logger.error(f"{validation_msg} {error_message}")
            return ValidationResult(
                success=False, message=error_message
            )

        # only try to connect if the configuration is valid
        try:
            logger_msg = "connecting to PCE for validating credentials"
            self.illumio_helper.connect_to_pce(
                logger_msg,
                configuration,
                headers=self._get_connection_headers(),
                # fail quickly if PCE connection params are invalid
                retry_count=1,
                request_timeout=5
            )
        except IllumioPluginException as err:
            return ValidationResult(
                success=False,
                message=str(err)
            )
        except Exception as err:
            err_msg =(
                "Error occurred while Connecting to PCE."
                "Validate the provided configuration parameters."
            )

            self.logger.error(
                f"{self.log_prefix}: "
                f"{err_msg} "
                f"Error: {err}",
                details=traceback.format_exc()
            )
            return ValidationResult(
                success=False,
                message=f"{err_msg}"
            )
        return ValidationResult(
            success=True,
            message="Validation successful"
        )
