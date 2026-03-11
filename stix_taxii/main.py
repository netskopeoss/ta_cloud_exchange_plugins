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

TAXIIPlugin implementation to push and pull the data."""

import pytz
from cabby import create_client, exceptions
from datetime import datetime, timedelta
from typing import Dict, List
from stix.core import STIXPackage
from cybox.objects.file_object import File
from cybox.objects.uri_object import URI
from cybox.objects.domain_name_object import DomainName
from urllib.parse import urlparse
import re
import requests
import tempfile
import traceback
from .lib.taxii2client.v20 import ApiRoot as ApiRoot20, as_pages as as_pages20
from .lib.taxii2client.v21 import ApiRoot as ApiRoot21, as_pages as as_pages21

from netskope.integrations.cte.plugin_base import PluginBase, ValidationResult
from netskope.integrations.cte.models import Indicator, IndicatorType
from netskope.integrations.cte.models.indicator import SeverityType
from netskope.integrations.cte.models.business_rule import (
    Action,
    ActionWithoutParams,
)

from .utils.helper import (
    str_to_datetime,
    get_configuration_parameters,
    STIXTAXIIException,
    add_ce_user_agent,
)
from .utils.constants import (
    CONFIDENCE_TO_REPUTATION_MAPPINGS,
    LIKELY_IMPACT_TO_SEVERITY,
    OBSERVABLE_REGEXES,
    MODULE_NAME,
    PLATFORM_NAME,
    PLUGIN_VERSION,
    LIMIT,
    BUNDLE_LIMIT,
    STIX_VERSION_1,
    STIX_VERSION_20,
    STIX_VERSION_21,
    SERVICE_TYPE,
    DATE_CONVERSION_STRING,
)


class STIXTAXIIPlugin(PluginBase):
    """The TAXIIPlugin implementation."""

    def __init__(
        self,
        name,
        *args,
        **kwargs,
    ):
        """Init function.

        Args:
            name (str): Configuration Name.
        """
        super().__init__(
            name,
            *args,
            **kwargs,
        )
        self.plugin_name, self.plugin_version = self._get_plugin_info()
        self.log_prefix = f"{MODULE_NAME} {self.plugin_name}"
        self.config_name = name
        if name:
            self.log_prefix = f"{self.log_prefix} [{name}]"

    def _get_plugin_info(self):
        """Get plugin name and version from manifest.

        Returns:
            tuple: Tuple of plugin's name and version fetched from manifest.
        """
        try:
            metadata = STIXTAXIIPlugin.metadata
            plugin_name = metadata.get("name", PLATFORM_NAME)
            plugin_version = metadata.get("version", PLUGIN_VERSION)
            return plugin_name, plugin_version
        except Exception as exp:
            self.logger.info(
                message=(
                    f"{MODULE_NAME} {PLATFORM_NAME}: Error occurred while"
                    " getting plugin details."
                ),
                details=str(exp),
            )
        return (PLATFORM_NAME, PLUGIN_VERSION)

    def _filter_collections(self, all_collections, selected_collections):
        """Create or filter collection names.
        Args:
            all_collections (list): List of all available collections.
            selected_collections (str): Comma-separated string of selected
            collections.
        Returns:
            list: List of filtered collection names.
        """
        selected_collections = [
            x.strip() for x in selected_collections.split(",") if x.strip()
        ]
        if not selected_collections:
            return all_collections
        else:
            missing_collections = set(selected_collections) - set(
                all_collections
            )
            if missing_collections:
                self.logger.error(
                    f"{self.log_prefix}: Following collections could not be "
                    f"found - {', '.join(missing_collections)}."
                )
            return list(
                set(selected_collections).intersection(set(all_collections))
            )

    def _extract_fields_from_indicator(self, indicator, observable):
        """Extract severity and reputation from indicator for future usage.
        Args:
            indicator (Indicator): Indicator object.
            observable (Observable): Observable object.
        Returns:
            dict: Dictionary containing severity and reputation.
        """

        # Choose the output dict
        if observable.idref is None:
            data = {}
            data["firstSeen"] = indicator.timestamp
            data["lastSeen"] = indicator.timestamp
            if indicator.confidence:
                data["reputation"] = CONFIDENCE_TO_REPUTATION_MAPPINGS.get(
                    str(indicator.confidence.value), 5
                )
            if indicator.likely_impact:
                data["severity"] = LIKELY_IMPACT_TO_SEVERITY.get(
                    str(indicator.likely_impact.value),
                    SeverityType.UNKNOWN,
                )
            return data
        self._ids[observable.idref] = {}
        self._ids[observable.idref]["firstSeen"] = indicator.timestamp
        self._ids[observable.idref]["lastSeen"] = indicator.timestamp
        if indicator.confidence:
            self._ids[observable.idref]["reputation"] = (
                CONFIDENCE_TO_REPUTATION_MAPPINGS.get(
                    str(indicator.confidence.value), 5
                )
            )
        if indicator.likely_impact:
            self._ids[observable.idref]["severity"] = (
                LIKELY_IMPACT_TO_SEVERITY.get(
                    str(indicator.likely_impact.value),
                    SeverityType.UNKNOWN,
                )
            )
        return self._ids[observable.idref]

    def _extract_from_indicator(self, package_indicators):
        """Extract ioc from indicators.
        Args:
            package_indicators (list): List of indicators.
        Returns:
            list: List of indicators.
            bool: True if all indicators are skipped.
        """
        indicators = []
        is_skipped_final = False
        for indicator in package_indicators:
            for observable in indicator.observables:
                data = self._extract_fields_from_indicator(
                    indicator, observable
                )
                if not observable.object_:
                    is_skipped_final = True
                    continue
                properties = observable.object_.properties
                if not properties:
                    is_skipped_final = True
                    continue
                try:
                    if (
                        type(properties) is File
                        and properties.hashes
                        and properties.hashes.md5
                    ):
                        indicators.append(
                            Indicator(
                                value=str(properties.hashes.md5),
                                type=IndicatorType.MD5,
                                **data,
                                comments=str(
                                    observable.description
                                    or indicator.description
                                    or ""
                                ),
                            )
                        )
                    elif (
                        type(properties) is File
                        and properties.hashes
                        and properties.hashes.sha256
                    ):
                        indicators.append(
                            Indicator(
                                value=str(properties.hashes.sha256),
                                type=IndicatorType.SHA256,
                                **data,
                                comments=str(
                                    observable.description
                                    or indicator.description
                                    or ""
                                ),
                            )
                        )
                    elif type(properties) is URI and properties.value:
                        indicators.append(
                            Indicator(
                                value=str(properties.value),
                                type=IndicatorType.URL,
                                **data,
                                comments=str(
                                    observable.description
                                    or indicator.description
                                    or ""
                                ),
                            )
                        )
                    elif type(properties) is DomainName and properties.value:
                        indicators.append(
                            Indicator(
                                value=str(properties.value),
                                type=getattr(
                                    IndicatorType, "DOMAIN", IndicatorType.URL
                                ),
                                **data,
                                comments=str(
                                    observable.description
                                    or indicator.description
                                    or ""
                                ),
                            )
                        )
                    else:
                        is_skipped_final = True
                except Exception:
                    is_skipped_final = True
        return indicators, is_skipped_final

    def _extract_from_observables(self, observables):
        """Extract iocs from observables.

        Args:
            observables (list): List of observables.
        Returns:
            list: List of indicators.
            bool: True if all indicators are skipped.
        """
        indicators = []
        is_skipped = False
        for observable in observables:
            if not observable.object_:
                is_skipped = True
                continue
            properties = observable.object_.properties
            if not properties:
                is_skipped = True
                continue
            try:
                if (
                    type(properties) is File
                    and properties.hashes
                    and properties.hashes.md5
                ):
                    indicators.append(
                        Indicator(
                            value=str(properties.hashes.md5),
                            type=IndicatorType.MD5,
                            **self._ids.get(observable.id_, {}),
                            comments=str(observable.description or ""),
                        )
                    )
                elif (
                    type(properties) is File
                    and properties.hashes
                    and properties.hashes.sha256
                ):
                    indicators.append(
                        Indicator(
                            value=str(properties.hashes.sha256),
                            type=IndicatorType.SHA256,
                            **self._ids.get(observable.id_, {}),
                            comments=str(observable.description or ""),
                        )
                    )
                elif type(properties) is URI and properties.value:
                    indicators.append(
                        Indicator(
                            value=str(properties.value),
                            type=IndicatorType.URL,
                            comments=str(observable.description or ""),
                        )
                    )
                elif type(properties) is DomainName and properties.value:
                    indicators.append(
                        Indicator(
                            value=str(properties.value),
                            type=getattr(
                                IndicatorType, "DOMAIN", IndicatorType.URL
                            ),
                            comments=str(observable.description or ""),
                        )
                    )
                else:
                    is_skipped = True
            except Exception:
                is_skipped = True
        return indicators, is_skipped

    def _extract_indicators(self, package):
        """Extract iocs from a STIX package."""
        if package.indicators:
            return self._extract_from_indicator(package.indicators)
        elif package.observables:
            return self._extract_from_observables(package.observables)
        else:
            return [], True

    def _build_client(self, configuration):
        """Build client for TAXII.

        Args:
            configuration (dict): Configuration dictionary.
        Returns:
            client: Client object.
        """
        (
            _,
            discovery_url,
            username,
            password,
            _,
            _,
            _,
            _,
            _,
            _,
            _,
        ) = get_configuration_parameters(configuration)
        parsed_url = urlparse(discovery_url)
        discovery_url = parsed_url.path
        if len(parsed_url.netloc.split(":")) > 1:
            base, port = parsed_url.netloc.split(":")
            port = int(port)
            client = create_client(
                base,
                port=port,
                use_https=True if parsed_url.scheme == "https" else False,
                discovery_path=discovery_url,
            )
        else:
            client = create_client(
                parsed_url.netloc,
                use_https=True if parsed_url.scheme == "https" else False,
                discovery_path=discovery_url,
            )
        client.set_proxies(self.proxy)

        if username and password:
            client.set_auth(
                username=username,
                password=password,
                verify_ssl=self.ssl_validation,
            )
        else:
            client.set_auth(verify_ssl=self.ssl_validation)
        return client

    def _get_collections(self, client):
        """Get collections from the server.

        Args:
            client (cabby.Client): The client object.

        Returns:
            list: List of collection names.
        """
        collection_uri = None
        services = client.discover_services()
        for service in services:
            if service.type == SERVICE_TYPE:
                collection_uri = service.address
                break
        if collection_uri is None:
            err_msg = "Failed to find collection management."
            raise STIXTAXIIException(err_msg)
        # to get collection form server
        return [c.name for c in client.get_collections(uri=collection_uri)]

    def convert_string_to_datetime(self, collections_dict):
        """Convert string to datetime.

        Args:
            collections_dict (dict): Dictionary of collection names and
              datetime values.

        Returns:
            dict: Dictionary of collection names and datetime values.
        """
        try:
            if collections_dict and isinstance(collections_dict, dict):
                for (
                    collection_name,
                    str_datetime_value,
                ) in collections_dict.items():
                    if isinstance(str_datetime_value, str):
                        collections_dict[collection_name] = str_to_datetime(
                            string=str_datetime_value,
                            date_format=DATE_CONVERSION_STRING,
                            replace_dot=False,
                        )
        except Exception as err:
            err_msg = "Error occurred while fetching the collection details."
            details = f"Collection details: {collections_dict}"
            self.handle_and_raise(
                err=err, err_msg=err_msg, details_msg=details
            )

        return collections_dict

    def convert_datetime_to_string(self, collections_dict):
        """Convert datetime to string.

        Args:
            collections_dict (dict): Dictionary of collection names and
            datetime values.

        Returns:
            dict: Dictionary of collection names and datetime values.
        """
        try:
            if collections_dict and isinstance(collections_dict, dict):
                for (
                    collection_name,
                    datetime_value,
                ) in collections_dict.items():
                    if isinstance(datetime_value, datetime):
                        collections_dict[collection_name] = (
                            datetime_value.strftime(DATE_CONVERSION_STRING)
                        )
        except Exception as err:
            err_msg = (
                "Error occurred while creating the collection"
                " details to store."
            )
            details = f"Collection details: {collections_dict}"
            self.handle_and_raise(
                err=err, err_msg=err_msg, details_msg=details
            )

        return collections_dict

    def handle_and_raise(
        self,
        err: Exception,
        err_msg: str,
        details_msg: str = "",
        exc_type: Exception = STIXTAXIIException,
        if_raise: bool = True,
    ):
        """Handle and raise an exception.

        Args:
            err (Exception): Exception object.
            err_msg (str): Error message.
            details_msg (str): Details message.
            exc_type (Exception, optional): Exception type. Defaults to
                STIXTAXIIException.
            if_raise (bool, optional): Whether to raise the exception.
                Defaults to True.
        """
        self.logger.error(
            message=f"{self.log_prefix}: {err_msg} Error: {err}",
            details=details_msg,
        )
        if if_raise:
            raise exc_type(err_msg)

    def pull_1x(self, configuration, start_time):
        """Pull implementation for version 1.x.

        Args:
            configuration (dict): Configuration dictionary.
            start_time (datetime): Start time.

        Returns:
            ValidationResult: Validation result.
        """
        (
            _,
            _,
            _,
            _,
            collection_names,
            _,
            _,
            delay_config,
            _,
            _,
            _,
        ) = get_configuration_parameters(configuration)

        self._ids = {}
        try:
            client = self._build_client(configuration)
            collections = self._get_collections(client)
        except requests.exceptions.ProxyError as err:
            err_msg = "Invalid proxy configuration."
            self.handle_and_raise(
                err=err,
                err_msg=err_msg,
                details_msg=str(traceback.format_exc()),
            )
        except requests.exceptions.ConnectionError as err:
            err_msg = (
                "Connection Error occurred. Check the Discovery"
                " URL/API Root URL provided."
            )
            self.handle_and_raise(
                err=err,
                err_msg=err_msg,
                details_msg=str(traceback.format_exc()),
            )
        except requests.exceptions.RequestException as err:
            err_msg = "Request Exception occurred."
            self.handle_and_raise(
                err=err,
                err_msg=err_msg,
                details_msg=str(traceback.format_exc()),
            )
        except STIXTAXIIException:
            raise
        except Exception as err:
            err_msg = "Exception occurred while fetching the collections."
            self.handle_and_raise(
                err=err,
                err_msg=err_msg,
                details_msg=str(traceback.format_exc()),
            )

        filtered_collections = self._filter_collections(
            collections, collection_names
        )
        self.logger.info(
            f"{self.log_prefix}: Following collections will be"
            f" fetched - {', '.join(filtered_collections)}."
        )
        indicators = []

        delay_time = int(delay_config)

        start_time = pytz.utc.localize(
            start_time - timedelta(minutes=delay_time)
        )

        for collection in filtered_collections:
            self.logger.debug(
                f"{self.log_prefix}: Parsing collection - "
                f"'{collection}'. Start time: {start_time}."
            )
            try:
                content_blocks = client.poll(
                    collection_name=collection,
                    begin_date=start_time,
                )
            except requests.exceptions.ProxyError as err:
                err_msg = (
                    "Proxy Error occurred. Check the proxy configuration."
                )
                self.handle_and_raise(
                    err=err,
                    err_msg=err_msg,
                    details_msg=str(traceback.format_exc()),
                )
            except requests.exceptions.ConnectionError as err:
                err_msg = (
                    "Connection Error occurred. Check the Discovery"
                    " URL/API Root URL provided."
                )
                self.handle_and_raise(
                    err=err,
                    err_msg=err_msg,
                    details_msg=str(traceback.format_exc()),
                )
            except requests.exceptions.RequestException as err:
                err_msg = "Request Exception occurred."
                self.handle_and_raise(
                    err=err,
                    err_msg=err_msg,
                    details_msg=str(traceback.format_exc()),
                )
            except Exception as err:
                err_msg = (
                    "Exception occurred while fetching the"
                    " objects from collection."
                )
                self.handle_and_raise(
                    err=err,
                    err_msg=err_msg,
                    details_msg=str(traceback.format_exc()),
                )

            block_id = 1
            collection_indicator_count = 0
            for block in content_blocks:
                try:
                    temp = tempfile.TemporaryFile()
                    temp.write(block.content)
                    temp.seek(0)
                    stix_package = STIXPackage.from_xml(temp)
                    extracted, is_skipped = self._extract_indicators(
                        stix_package
                    )
                    indicators += extracted
                    collection_indicator_count += len(extracted)
                    total_log = (
                        f"Total {collection_indicator_count} "
                        "indicator(s) pulled till now."
                    )
                    if is_skipped is True:
                        self.logger.info(
                            f"{self.log_prefix}: Pulled {len(extracted)} "
                            f"indicator(s) from Block-{block_id}, some "
                            "indicator(s) might have been discarded."
                            f" {total_log}"
                        )
                    else:
                        self.logger.info(
                            f"{self.log_prefix}: Pulled {len(extracted)} "
                            f"indicator(s) from Block-{block_id}."
                            f" {total_log}"
                        )
                    temp.close()
                except Exception as e:
                    err_msg = (
                        "Error occurred while extracting indicator(s)"
                        f" from Block-{block_id}."
                    )
                    self.handle_and_raise(
                        err=e,
                        err_msg=err_msg,
                        details_msg=str(traceback.format_exc()),
                        if_raise=False,
                    )
                    block_id += 1
                    continue
                block_id += 1
            self.logger.info(
                f"{self.log_prefix}: Completed pulling of"
                f"indicator(s) from collection - '{collection}'."
                f" Total {collection_indicator_count}"
                " indicator(s) pulled."
            )

        self.logger.info(
            f"{self.log_prefix}: Completed pulling of"
            " indicator(s) from collection(s) - "
            f"{', '.join(filtered_collections)}."
            f" Total {len(indicators)} indicator(s) pulled."
        )
        return indicators

    def _extract_observables_2x(self, pattern: str, data: dict):
        """Extract observables from a pattern.

        Args:
            pattern (str): The pattern to extract observables from.
            data (dict): The data to extract observables from.

        Returns:
            list: List of observables.
        """
        sha256_count = 0
        md5_count = 0
        observables = []
        is_skipped = False
        for kind in OBSERVABLE_REGEXES:
            matches = re.findall(kind["regex"], pattern, re.IGNORECASE)
            if len(matches) == 0:
                is_skipped = is_skipped or False
            else:
                is_skipped = is_skipped or True
            for match in matches:
                try:
                    if (
                        kind["type"] == IndicatorType.SHA256
                        or kind["type"] == IndicatorType.MD5
                    ):
                        observables.append(
                            Indicator(
                                value=match.replace("'", ""),
                                type=kind["type"],
                                **data,
                            )
                        )
                        if kind["type"] == IndicatorType.SHA256:
                            sha256_count += 1
                        elif kind["type"] == IndicatorType.MD5:
                            md5_count += 1
                    else:
                        if "ipv4" in pattern or "ipv6" in pattern:
                            observables.append(
                                Indicator(
                                    value=match.replace("'", ""),
                                    type=kind["type"],
                                    **data,
                                )
                            )
                        else:
                            observables.append(
                                Indicator(
                                    value=match[1].replace("'", ""),
                                    type=kind["type"],
                                    **data,
                                )
                            )
                except Exception:
                    is_skipped = True
        return observables, not (is_skipped), sha256_count, md5_count

    def _extract_indicators_2x(self, objects):
        """Extract indicators from a list of objects.

        Args:
            objects (list): List of objects.

        Returns:
            list: List of indicators.
        """
        indicators = []
        is_skipped_final = False
        modified_time = None
        total_sha256_count = 0
        total_md5_count = 0
        for o in objects:
            if o.get("type").lower() != "indicator":
                is_skipped_final = True
                continue
            created_time = str_to_datetime(o.get("created"))
            modified_time = str_to_datetime(o.get("modified"))
            data = {
                "comments": o.get("description") or o.get("pattern") or "",
                "reputation": int(o.get("confidence", 50) / 10),
                "firstSeen": created_time,
                "lastSeen": modified_time,
            }
            sha256 = 0
            md5 = 0
            extracted, is_skipped, sha256, md5 = (
                self._extract_observables_2x(o.get("pattern", ""), data)
            )
            total_sha256_count += sha256
            total_md5_count += md5
            if is_skipped:
                is_skipped_final = True
            indicators += extracted
        return (
            indicators,
            is_skipped_final,
            total_sha256_count,
            total_md5_count
        )

    def update_storage(
        self,
        configuration,
        bundle,
        last_added_date,
        storage,
        collection,
        execution_details,
        bundle_id,
    ):
        """Update storage with new indicators.

        Args:
            configuration (dict): Configuration dictionary.
            bundle (dict): Bundle dictionary.
            last_added_date (datetime): Last added date.
            storage (dict): Storage dictionary.
            collection (str): Collection name.
            execution_details (dict): Execution details.
            bundle_id (str): Bundle ID.

        Returns:
            dict: Storage dictionary.
        """
        (
            version,
            _,
            _,
            _,
            _,
            pagination_method,
            _,
            _,
            _,
            _,
            _,
        ) = get_configuration_parameters(configuration)

        next_value_21 = bundle.get("next")
        objects = bundle.get("objects", [])

        if objects:
            if pagination_method == "next":
                if (
                    version == STIX_VERSION_21
                    and next_value_21
                ):
                    storage["in_execution"] = {
                        collection: {
                            "next": next_value_21,
                            "last_added_date": last_added_date,
                        }
                    }
                elif (
                    version == STIX_VERSION_20
                    and len(objects) >= LIMIT
                ):
                    try:
                        next_value_20 = int(
                            storage.get("in_execution", {})
                            .get(collection, {})
                            .get("next", 0)
                        ) + (LIMIT * bundle_id)
                    except Exception:
                        next_value_20 = 0
                    storage["in_execution"] = {
                        collection: {
                            "next": next_value_20,
                            "last_added_date": last_added_date,
                        }
                    }
                else:
                    storage["in_execution"] = {}
                    execution_details[collection] = pytz.utc.localize(
                        datetime.now()
                    )
            else:
                if (
                    version == STIX_VERSION_21
                    and bundle.get("more")
                    and last_added_date
                ):
                    storage["in_execution"] = {
                        collection: {
                            "next": next_value_21,
                            "last_added_date": last_added_date,
                        }
                    }
                elif (
                    version == STIX_VERSION_20
                    and len(objects) >= LIMIT
                    and last_added_date
                ):
                    try:
                        next_value_20 = int(
                            storage.get("in_execution", {})
                            .get(collection, {})
                            .get("next", 0)
                        ) + (LIMIT * bundle_id)
                    except Exception:
                        next_value_20 = 0
                    storage["in_execution"] = {
                        collection: {
                            "next": next_value_20,
                            "last_added_date": last_added_date,
                        }
                    }
                else:
                    storage["in_execution"] = {}
                    execution_details[collection] = pytz.utc.localize(
                        datetime.now()
                    )
        else:
            storage["in_execution"] = {}
            execution_details[collection] = pytz.utc.localize(datetime.now())

        return

    def paginate(
        self,
        configuration,
        pages,
        collection,
        storage,
        execution_details,
        indicators,
    ):
        """Paginate through the collection.

        Args:
            configuration (dict): Configuration dictionary.
            pages (list): List of pages.
            collection (str): Collection name.
            storage (dict): Storage dictionary.
            execution_details (dict): Execution details.
            indicators (list): List of indicators.

        Returns:
            list: List of indicators.
        """
        bundle_id = 1
        collection_indicator_count = 0
        collection_skip_count = 0
        total_sha256_count = 0
        total_md5_count = 0
        sha256_count = 0
        md5_count = 0
        for bundle, last_added_date in pages:
            objects = bundle.get("objects", [])
            extracted, is_skipped, sha256_count, md5_count = (
                self._extract_indicators_2x(objects)
            )
            total_sha256_count += sha256_count
            total_md5_count += md5_count
            indicators += extracted
            extracted_count = len(extracted)
            skip_count = len(objects) - extracted_count
            collection_indicator_count += extracted_count
            self.total_indicators += extracted_count
            collection_skip_count += skip_count
            self.total_skipped += skip_count

            incremental_hash_msg = ""
            if sha256_count > 0 or md5_count > 0:
                incremental_hash_msg = (
                    f"(SHA256: {sha256_count}, MD5: {md5_count}) "
                )
            total_log = (
                f"Total {collection_indicator_count} indicators"
                f" pulled from '{collection}' collection till now."
            )
            if is_skipped is True:
                self.logger.info(
                    f"{self.log_prefix}: Pulled {extracted_count} "
                    f"{incremental_hash_msg}"
                    f"indicator(s) from '{collection}' collection "
                    f"Bundle-{bundle_id}, {skip_count} indicator(s) "
                    "have been discarded."
                    f" {total_log}"
                )
            else:
                self.logger.info(
                    f"{self.log_prefix}: Pulled {extracted_count} "
                    f"{incremental_hash_msg}"
                    f"indicator(s) from '{collection}' collection "
                    f"Bundle-{bundle_id}. {total_log}"
                )

            self.total_bundle_count += 1

            if self.total_bundle_count == BUNDLE_LIMIT:
                self.logger.info(
                    f"{self.log_prefix}: Bundle limit of {BUNDLE_LIMIT}"
                    f" is reached while executing '{collection}' collection."
                    "The execution will be continued in the next cycle."
                    f" Total {collection_indicator_count} indicators "
                    f"pulled and {collection_skip_count} indicators"
                    f" skipped for '{collection}' collection."
                )
                self.logger.debug(
                    f"{self.log_prefix}: Updating the collection"
                    " execution details with the next page details"
                )
                self.update_storage(
                    configuration=configuration,
                    bundle=bundle,
                    last_added_date=last_added_date,
                    storage=storage,
                    collection=collection,
                    execution_details=execution_details,
                    bundle_id=bundle_id,
                )
                storage["collections"] = self.convert_datetime_to_string(
                    execution_details
                )
                self.logger.debug(
                    f"{self.log_prefix}: Updated the collection execution"
                    " details successfully. Collection execution"
                    f" details: {storage}."
                )
                return indicators
            bundle_id += 1

        hash_msg = ""
        if total_sha256_count > 0 or total_md5_count > 0:
            hash_msg = (
                f"(SHA256: {total_sha256_count}, MD5: {total_md5_count}) "
            )
        self.logger.info(
            f"{self.log_prefix}: Completed pulling of"
            f" indicator(s) from collection(s) - "
            f"'{collection}'."
            f" Total {collection_indicator_count} {hash_msg}"
            "indicator(s) pulled"
            f" and {collection_skip_count} skipped."
        )
        self.logger.debug(
            f"{self.log_prefix}: Successfully pulled "
            f"{self.total_bundle_count} bundle(s)."
        )
        return

    def get_page(self, func, configuration, start_time, next=None, start=0):
        """Get a page of indicators.

        Args:
            func (function): Function to get indicators.
            configuration (dict): Configuration dictionary.
            start_time (datetime): Start time.
            next (str, optional): Next value. Defaults to None.
            start (int, optional): Start index. Defaults to 0.

        Returns:
            list: List of indicators.
        """
        version, _, _, _, _, _, _, _, _, _, _, = get_configuration_parameters(
            configuration
        )
        headers = add_ce_user_agent(
            plugin_name=self.plugin_name, plugin_version=self.plugin_version
        )
        if version == STIX_VERSION_21:
            pages = as_pages21(
                func,
                plugin=self,
                per_request=LIMIT,
                added_after=start_time,
                next=next,
                with_header=True,
                headers=headers,
            )
        else:
            pages = as_pages20(
                func,
                plugin=self,
                per_request=LIMIT,
                added_after=start_time,
                start=start,
                with_header=True,
                headers=headers,
            )

        return pages

    def pull_2x(self, configuration, start_time):
        """Pull implementation for version 2.x.

        Args:
            configuration (dict): Configuration dictionary.
            start_time (datetime): Start time.

        Returns:
            list: List of indicators.
        """
        (
            version,
            discovery_url,
            username,
            password,
            collection_names,
            pagination_method,
            _,
            delay,
            _,
            _,
            _,
        ) = get_configuration_parameters(configuration)
        indicators = []
        collection_execution_details = {}
        new_collection_details = {}
        collection_name_object = {}
        storage = {}
        self.total_indicators = 0
        self.total_skipped = 0
        self.total_bundle_count = 0

        if self.storage is not None:
            storage = self.storage
            if storage.get("collections", {}):
                collection_execution_details = self.convert_string_to_datetime(
                    storage.get("collections", {})
                )
        else:
            storage = {}

        delay_time = int(delay)
        if version == STIX_VERSION_21:
            apiroot = ApiRoot21(
                discovery_url,
                user=username,
                password=password,
                verify=self.ssl_validation,
                proxies=self.proxy,
            )
        else:
            apiroot = ApiRoot20(
                discovery_url,
                user=username,
                password=password,
                verify=self.ssl_validation,
                proxies=self.proxy,
            )
        all_collections = []
        for c in apiroot.collections:
            all_collections.append(c.title)
            collection_name_object[c.title] = c

        filtered_collections = self._filter_collections(
            all_collections, collection_names
        )
        self.logger.info(
            f"{self.log_prefix}: Following collections will"
            f" be fetched - {', '.join(filtered_collections)}."
        )

        self.logger.debug(
            f"{self.log_prefix}: Collection execution details - {storage}."
        )

        if storage.get("in_execution", {}):
            for collection, next_page_details in storage.get(
                "in_execution"
            ).items():
                if collection not in filtered_collections:
                    break
                collection_object = collection_name_object[collection]

                if pagination_method == "next":
                    next_start_time = collection_execution_details[collection]
                    next_value = next_page_details.get("next")
                    next_val = next_value
                    start_val = next_value
                else:
                    next_value = next_page_details.get("last_added_date")
                    next_start_time = str_to_datetime(next_value)
                    next_val = None
                    start_val = 0

                try:
                    next_start_time = next_start_time - timedelta(
                        minutes=delay_time
                    )
                    next_start_time = pytz.utc.localize(next_start_time)
                except Exception:
                    pass
                self.logger.debug(
                    f"{self.log_prefix}: Executing the collection "
                    f"'{collection}' with start time {next_start_time}."
                )
                try:
                    pages = self.get_page(
                        func=collection_object.get_objects,
                        configuration=configuration,
                        start_time=next_start_time,
                        next=next_val,
                        start=start_val,
                    )

                    fetched_indicators = self.paginate(
                        configuration,
                        pages,
                        collection,
                        storage,
                        collection_execution_details,
                        indicators,
                    )
                    if fetched_indicators is not None:
                        self.logger.debug(
                            f"{self.log_prefix}: Successfully pulled"
                            f" {self.total_indicators} indicator(s)"
                            f" and {self.total_skipped} "
                            "indicator(s) were skipped."
                        )
                        return indicators, self.total_skipped
                except requests.exceptions.ProxyError as err:
                    err_msg = "Invalid proxy configuration."
                    self.handle_and_raise(
                        err=err,
                        err_msg=err_msg,
                        details_msg=str(traceback.format_exc()),
                    )
                except requests.exceptions.ConnectionError as err:
                    err_msg = (
                        "Connection Error occurred. Check the "
                        "Discovery URL/API Root URL provided."
                    )
                    self.handle_and_raise(
                        err=err,
                        err_msg=err_msg,
                        details_msg=str(traceback.format_exc()),
                    )
                except requests.exceptions.RequestException as err:
                    if not (
                        "416" in str(err)
                        or "request range not satisfiable" in str(err).lower()
                    ):
                        err_msg = "Request Exception occurred."
                        self.handle_and_raise(
                            err=err,
                            err_msg=err_msg,
                            details_msg=str(traceback.format_exc()),
                        )
                    self.logger.info(
                        f"{self.log_prefix}: Received status code 416,"
                        f" exiting the pulling of '{collection}' collection. "
                        f"Response: {str(err)}."
                    )
                except Exception as err:
                    if not (
                        "416" in str(err)
                        or "request range not satisfiable" in str(err).lower()
                    ):
                        err_msg = (
                            "Exception occurred while fetching the"
                            " objects of collection."
                        )
                        self.handle_and_raise(
                            err=err,
                            err_msg=err_msg,
                            details_msg=str(traceback.format_exc()),
                        )
                    self.logger.info(
                        f"{self.log_prefix}: Received status code 416, "
                        f"exiting the pulling of '{collection}' collection. "
                        f"Response: {str(err)}."
                    )

                collection_execution_details[collection] = datetime.now()
            storage["in_execution"] = {}

        for collection in apiroot.collections:
            collection_name = collection.title
            if collection_name not in filtered_collections:
                continue

            new_collection_details[collection_name] = pytz.utc.localize(
                collection_execution_details.get(collection_name, start_time)
            )

        sorted_collection = sorted(
            new_collection_details, key=lambda k: new_collection_details[k]
        )

        for collection in sorted_collection:
            collection_object = collection_name_object[collection]
            start_time = new_collection_details[collection] - timedelta(
                minutes=delay_time
            )
            try:
                self.logger.debug(
                    f"{self.log_prefix}: Parsing collection - "
                    f"'{collection}'. Start time: {start_time} (UTC)"
                )
                pages = self.get_page(
                    func=collection_object.get_objects,
                    configuration=configuration,
                    start_time=start_time,
                )

                fetched_indicators = self.paginate(
                    configuration,
                    pages,
                    collection,
                    storage,
                    new_collection_details,
                    indicators,
                )
                if fetched_indicators is not None:
                    self.logger.debug(
                        f"{self.log_prefix}: Successfully pulled"
                        f" {self.total_indicators} indicator(s)"
                        f" and {self.total_skipped} indicator(s) were skipped."
                    )
                    return indicators, self.total_skipped

                storage["in_execution"] = {}
                new_collection_details[collection] = pytz.utc.localize(
                    datetime.now()
                )
            except KeyError:
                # if there is no data in a collection
                storage["in_execution"] = {}
                new_collection_details[collection] = pytz.utc.localize(
                    datetime.now()
                )
            except requests.exceptions.ProxyError as err:
                err_msg = "Invalid proxy configuration."
                self.handle_and_raise(
                    err=err,
                    err_msg=err_msg,
                    details_msg=str(traceback.format_exc()),
                )
            except requests.exceptions.ConnectionError as err:
                err_msg = (
                    "Connection Error occurred. Check the "
                    "Discovery URL/API Root URL provided."
                )
                self.handle_and_raise(
                    err=err,
                    err_msg=err_msg,
                    details_msg=str(traceback.format_exc()),
                )
            except requests.exceptions.RequestException as err:
                if (
                    "416" in str(err)
                    or "request range not satisfiable" in str(err).lower()
                ):
                    storage["in_execution"] = {}
                    self.logger.info(
                        f"{self.log_prefix}: Received status code 416, "
                        f"exiting the pulling of '{collection}' "
                        f"collection. Response: {str(err)}."
                    )
                    new_collection_details[collection] = pytz.utc.localize(
                        datetime.now()
                    )
                else:
                    err_msg = (
                        "Exception occurred while fetching the "
                        "objects of collection."
                    )
                    self.handle_and_raise(
                        err=err,
                        err_msg=err_msg,
                        details_msg=str(traceback.format_exc()),
                    )
            except Exception as err:
                if (
                    "416" in str(err)
                    or "request range not satisfiable" in str(err).lower()
                ):
                    storage["in_execution"] = {}
                    self.logger.info(
                        f"{self.log_prefix}: Received status code 416, "
                        f"exiting the pulling of '{collection}' "
                        f"collection. Response: {str(err)}."
                    )
                    new_collection_details[collection] = pytz.utc.localize(
                        datetime.now()
                    )
                else:
                    err_msg = (
                        "Exception occurred while fetching the "
                        "objects of collection."
                    )
                    self.handle_and_raise(
                        err=err,
                        err_msg=err_msg,
                        details_msg=str(traceback.format_exc()),
                    )

        storage["collections"] = self.convert_datetime_to_string(
            new_collection_details
        )
        self.logger.debug(
            f"{self.log_prefix}: Storage value after"
            f" completion of the pull cycle: {storage}."
        )
        self.logger.debug(
            f"{self.log_prefix}: Successfully pulled {self.total_indicators}"
            f" indicator(s) and {self.total_skipped} "
            "indicator(s) were skipped."
        )
        return indicators, self.total_skipped

    def _pull(self, configuration, last_run_at):
        """Pull implementation.

        Args:
            configuration (dict): Configuration dictionary.
            last_run_at (datetime): Last run time.

        Returns:
            list: List of indicators.
        """
        (
            version,
            discovery_url,
            _,
            _,
            _,
            _,
            initial_range,
            _,
            type_to_pull,
            severity,
            reputation,
        ) = get_configuration_parameters(configuration)

        skipped = 0
        if not last_run_at:
            start_time = datetime.now() - timedelta(
                days=int(initial_range)
            )
            self.logger.debug(
                f"{self.log_prefix}: Starting the initial pull execution "
                "for Discovery URL: "
                f"{discovery_url},"
                f" Version: {version}"
                f" and start time: {start_time}."
            )
        else:
            start_time = last_run_at
            self.logger.debug(
                f"{self.log_prefix}: Starting the pull execution for "
                f"Discovery URL: "
                f"{discovery_url},"
                f" Version: {version} and"
                f" start time: {start_time}."
            )

        self.logger.debug(
            f"{self.log_prefix}: Filter details - Type:"
            f" {type_to_pull},"
            f" Severity: {severity},"
            f" Reputation: {reputation}."
        )

        if version == STIX_VERSION_1:
            indicators = self.pull_1x(configuration, start_time)
        else:
            indicators, skipped = self.pull_2x(configuration, start_time)

        filtered_list = list(
            filter(
                lambda x: x.severity.value in severity
                and x.reputation >= int(reputation)
                and (
                    (
                        x.type is IndicatorType.SHA256
                        and "sha256" in type_to_pull
                    )
                    or (
                        x.type is IndicatorType.MD5
                        and "md5" in type_to_pull
                    )
                    or (
                        x.type is IndicatorType.URL
                        and "url" in type_to_pull
                    )
                    or (
                        x.type
                        is getattr(IndicatorType, "IPV4", IndicatorType.URL)
                        and "ipv4" in type_to_pull
                    )
                    or (
                        x.type
                        is getattr(IndicatorType, "IPV6", IndicatorType.URL)
                        and "ipv6" in type_to_pull
                    )
                    or (
                        x.type
                        is getattr(IndicatorType, "DOMAIN", IndicatorType.URL)
                        and "domain" in type_to_pull
                    )
                ),
                indicators,
            )
        )
        skipped_filtered = len(indicators) - len(filtered_list)

        log_msg_without_skip = (
            f"{self.log_prefix}: Pulled {len(filtered_list)}"
            " indicator(s) successfully."
        )

        log_msg_with_skip = (
            f"{self.log_prefix}: Pulled {len(filtered_list)}"
            " indicator(s) successfully, "
            f"skipped {skipped_filtered} indicator(s) "
            "due to filter(s) in configuration"
        )
        if version == STIX_VERSION_21 or version == STIX_VERSION_20:
            if skipped > 0 or skipped_filtered > 0:
                self.logger.info(
                    log_msg_with_skip + ", "
                    f"and {skipped} indicator(s) were skipped "
                    "due to invalid or unsupported type."
                )
            else:
                self.logger.info(log_msg_without_skip)
        else:
            if skipped_filtered > 0:
                self.logger.info(log_msg_with_skip + ".")
            else:
                self.logger.info(log_msg_without_skip)

        return filtered_list

    def pull(self):
        """Pull indicators from TAXII server."""
        try:
            return self._pull(self.configuration, self.last_run_at)
        except STIXTAXIIException as err:
            raise err
        except Exception as err:
            err_msg = "Error occurred while pulling the indicators."
            self.handle_and_raise(
                err=err,
                err_msg=err_msg,
                details_msg=str(traceback.format_exc()),
            )

    def _validate_collections(self, configuration):
        """Validate collections.
        Args:
            configuration (dict): Configuration dictionary.
        Returns:
            list: List of collections.
        """
        try:
            (
                version,
                discovery_url,
                username,
                password,
                collection_names,
                _,
                _,
                _,
                _,
                _,
                _,
            ) = get_configuration_parameters(configuration)

            if version == STIX_VERSION_1:
                client = self._build_client(configuration)
                all_collections = self._get_collections(client)
            elif version == STIX_VERSION_20:
                apiroot = ApiRoot20(
                    discovery_url,
                    user=username,
                    password=password,
                    verify=self.ssl_validation,
                    proxies=self.proxy,
                )
                all_collections = [c.title for c in apiroot.collections]
            elif version == STIX_VERSION_21:
                apiroot = ApiRoot21(
                    discovery_url,
                    user=username,
                    password=password,
                    verify=self.ssl_validation,
                    proxies=self.proxy,
                )
                all_collections = [c.title for c in apiroot.collections]
            collections = [c.strip() for c in collection_names.split(",")]
            collections = list(filter(lambda x: len(x) > 0, collections))
            if collections and set(collections) - set(all_collections):
                return ValidationResult(
                    success=False,
                    message=(
                        f"Could not find the collection(s): "
                        f"{', '.join(set(collections) - set(all_collections))}"
                    ),
                )
            return ValidationResult(
                success=True, message="Validated successfully."
            )
        except requests.exceptions.ProxyError as err:
            err_msg = "Invalid proxy configuration."
            self.handle_and_raise(
                err=err,
                err_msg=err_msg,
                details_msg=str(traceback.format_exc()),
                if_raise=False,
            )
            return ValidationResult(success=False, message=err_msg)
        except requests.exceptions.ConnectionError as err:
            err_msg = (
                "Connection Error occurred. Check the "
                "Discovery URL/API Root URL provided."
            )
            self.handle_and_raise(
                err=err,
                err_msg=err_msg,
                details_msg=str(traceback.format_exc()),
                if_raise=False,
            )
            return ValidationResult(success=False, message=err_msg)
        except requests.exceptions.RequestException as ex:
            err_msg = "Exception occurred while connecting to the the server."
            self.handle_and_raise(
                err=ex,
                err_msg=err_msg,
                details_msg=str(traceback.format_exc()),
                if_raise=False,
            )
            return ValidationResult(
                success=False,
                message=err_msg + ". Check logs for more details.",
            )
        except exceptions.UnsuccessfulStatusError as ex:
            self.logger.error(
                f"{self.log_prefix}: {str(ex)}", details=traceback.format_exc()
            )
            if ex.status == "UNAUTHORIZED":
                return ValidationResult(
                    success=False,
                    message="Invalid/Blank Username/Password provided.",
                )
            else:
                return ValidationResult(
                    success=False, message="Check logs for more details."
                )
        except STIXTAXIIException as ex:
            err_msg = (
                "Could not fetch the collection list "
                "from the server. Check logs"
            )
            self.handle_and_raise(
                err=ex,
                err_msg=err_msg,
                details_msg=str(traceback.format_exc()),
                if_raise=False,
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        except Exception as ex:
            err_msg = "Could not fetch the collection list from the server."
            self.handle_and_raise(
                err=ex,
                err_msg=err_msg,
                details_msg=str(traceback.format_exc()),
                if_raise=False,
            )
            return ValidationResult(
                success=False,
                message=err_msg + ". Check all of the parameters.",
            )

    def validate(self, configuration: Dict) -> ValidationResult:
        """Validate the configuration.

        Args:
            configuration (Dict): Configuration dictionary.

        Returns:
            ValidationResult: Validation result.
        """
        (
            version,
            discovery_url,
            username,
            password,
            collection_names,
            pagination_method,
            initial_range,
            delay_config,
            type_to_pull,
            severity,
            reputation,
        ) = get_configuration_parameters(configuration, is_validation=True)

        # Discovery URL
        if not discovery_url:
            err_msg = (
                "Discovery URL/API Root URL is a "
                "required configuration parameter."
            )
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        elif not isinstance(discovery_url, str):
            err_msg = (
                "Invalid Discovery URL/API Root URL Provided "
                "in configuration parameters."
            )
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )

        # Username
        if not isinstance(username, str):
            err_msg = "Invalid Username Provided in configuration parameters."
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )

        # Password
        if not isinstance(password, str):
            err_msg = "Invalid Password Provided in configuration parameters."
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )

        # STIX/TAXII Version
        if not version:
            err_msg = (
                "STIX/TAXII Version is a required configuration parameter."
            )
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            return ValidationResult(success=False, message=err_msg)
        elif not isinstance(version, str) or version not in [
            STIX_VERSION_1,
            STIX_VERSION_20,
            STIX_VERSION_21,
        ]:
            err_msg = (
                "Invalid value for STIX/TAXII Version provided."
                " Available values are '1', '2.0', or '2.1'."
            )
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            return ValidationResult(success=False, message=err_msg)
        elif version == STIX_VERSION_1 and (
            "ipv4" in type_to_pull or "ipv6" in type_to_pull
        ):
            err_msg = (
                "IPv4/IPv6 is not supported in the plugin for"
                " STIX Version 1.x."
            )
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            return ValidationResult(success=False, message=err_msg)

        # Collection Names
        if not isinstance(collection_names, str):
            err_msg = (
                "Invalid Collection Names provided in"
                " configuration parameters."
            )
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            return ValidationResult(success=False, message=err_msg)

        # Type of Threat data to pull
        if not type_to_pull:
            err_msg = (
                "Type of Threat data to pull is a required"
                " configuration parameter."
            )
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            return ValidationResult(success=False, message=err_msg)
        elif not isinstance(type_to_pull, list) or not all(
            item in ["sha256", "md5", "url", "ipv4", "ipv6", "domain"]
            for item in type_to_pull
        ):
            err_msg = (
                "Invalid value for Type of Threat data to pull"
                " provided in configuration parameters. "
                "Available values are 'sha256', 'md5',"
                " 'url', 'ipv4', 'ipv6', 'domain'."
            )
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            return ValidationResult(success=False, message=err_msg)

        # Pagination Method
        if not pagination_method:
            err_msg = (
                "Pagination Method is a required configuration parameter."
            )
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            return ValidationResult(success=False, message=err_msg)
        elif not isinstance(
            pagination_method, str
        ) or pagination_method not in ["next", "last_added_date"]:
            err_msg = (
                "Invalid value for Pagination Method provided. Available"
                " values are 'next' or 'last_added_date'."
            )
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            return ValidationResult(success=False, message=err_msg)

        # Reputation
        if not reputation:
            err_msg = "Reputation is a required configuration parameter."
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            return ValidationResult(success=False, message=err_msg)
        elif (
            not isinstance(reputation, int)
            or int(reputation) < 1
            or int(reputation) > 10
        ):
            err_msg = (
                "Invalid value for Reputation provided. "
                "Must be an integer in range 1 - 10."
            )
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            return ValidationResult(success=False, message=err_msg)

        # Initial Range
        if initial_range != 0 and not initial_range:
            err_msg = (
                "Initial Range (in days) is a required "
                "configuration parameter."
            )
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            return ValidationResult(success=False, message=err_msg)
        elif (
            not isinstance(initial_range, int)
            or int(initial_range) < 1
            or int(initial_range) > 365
        ):
            err_msg = (
                "Invalid value for Initial Range (in days) provided"
                " in configuration parameters. "
                "Must be an integer in range 1 - 365."
            )
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            return ValidationResult(success=False, message=err_msg)

        # Delay
        if (
            not isinstance(delay_config, int)
            or int(delay_config) < 0
            or int(delay_config) > 1440
        ):
            err_msg = (
                "Invalid value for Look Back provided"
                " in configuration parameters. "
                "Must be an integer in range 0 - 1440."
            )
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            return ValidationResult(success=False, message=err_msg)

        # severity
        if not severity:
            err_msg = (
                "Severity is a required configuration parameter."
            )
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            return ValidationResult(success=False, message=err_msg)
        elif not isinstance(severity, list) or not (
            all(
                sev in ["unknown", "low", "medium", "high", "critical"]
                for sev in severity
            )
        ):
            err_msg = (
                "Invalid value for Severity provided in "
                "configuration parameters. "
                "Available values are 'unknown', "
                "'low', 'medium', 'high' and 'critical'."
            )
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            return ValidationResult(success=False, message=err_msg)

        # validating the configuration parameters
        # Validate collections
        validate_collections = self._validate_collections(configuration)
        if validate_collections.success is False:
            return validate_collections

        self.logger.info(
            f"{self.log_prefix}: Successfully validated"
            " configuration parameters."
        )
        return ValidationResult(
            success=True, message="Validated successfully."
        )

    def get_actions(self) -> List[ActionWithoutParams]:
        """Get available actions."""
        return []

    def validate_action(self, action: Action) -> ValidationResult:
        """Validate STIX/TAXII action configuration."""
        return ValidationResult(success=True, message="Validation successful.")

    def get_action_fields(self, action: Action) -> List[Dict]:
        """Get fields required for an action."""
        return []
