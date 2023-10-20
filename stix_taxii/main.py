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

"""TAXIIPlugin implementation to push and pull the data."""


import re
import requests
import tempfile
import traceback
import json
import os
from urllib.parse import urlparse
from datetime import datetime, timedelta
import pytz
from cabby import create_client, exceptions
from .lib.taxii2client.v20 import ApiRoot as ApiRoot20, as_pages as as_pages20
from .lib.taxii2client.v21 import ApiRoot as ApiRoot21, as_pages as as_pages21
from stix.core import STIXPackage
from cybox.objects.file_object import File
from cybox.objects.uri_object import URI
from cybox.objects.domain_name_object import DomainName

from netskope.integrations.cte.plugin_base import PluginBase, ValidationResult
from netskope.integrations.cte.models import Indicator, IndicatorType
from netskope.integrations.cte.models.indicator import SeverityType
from netskope.integrations.cte.models.business_rule import Action
from netskope.common.utils import add_user_agent


CONFIDENCE_TO_REPUTATION_MAPPINGS = {
    "High": 10,
    "Medium": 6,
    "Low": 3,
    "None": 1,
    "Unknown": 5,
}

LIKELY_IMPACT_TO_SEVERITY = {
    "High": SeverityType.CRITICAL,
    "Medium": SeverityType.HIGH,
    "Low": SeverityType.MEDIUM,
    "None": SeverityType.LOW,
    "Unknown": SeverityType.UNKNOWN,
}

OBSERVABLE_REGEXES = [
    {
        "regex": r"file:hashes\.(?:'SHA-256'|\"SHA-256\")\s*=\s*('[a-z0-9]*'|\"[a-z0-9]*\")",
        "type": IndicatorType.SHA256,
    },
    {
        "regex": r"file:hashes\.(?:MD5|'MD5'|\"MD5\")\s*=\s*('[a-z0-9]*'|\"[a-z0-9]*\")",
        "type": IndicatorType.MD5,
    },
    {
        "regex": r"url:value\s*=\s*(?:\"((?:[^\"\\]|\\.)*)\"|'((?:[^'\\]|\\.)*)')",
        "type": IndicatorType.URL,
    },
    {
        "regex": r"domain-name:value\s*=\s*(?:\"((?:[^\"\\]|\\.)*)\"|'((?:[^'\\]|\\.)*)')",
        "type": IndicatorType.URL,
    },
]
DATE_CONVERSION_STRING = '%Y-%m-%dT%H:%M:%S.%fZ'
# page size
LIMIT = 1000
# page
BUNDLE_LIMIT = 100
MODULE_NAME = "CTE"
PLUGIN_VERSION = "3.0.0"
PLATFORM_NAME = "STIX/TAXII Plugin"


class STIXTAXIIException(Exception):
    pass


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
        if name:
            self.log_prefix = f"{self.log_prefix} [{name}]"
            
    def _get_plugin_info(self):
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
                plugin_name = manifest_json.get("name", PLATFORM_NAME)
                plugin_version = manifest_json.get("version", PLUGIN_VERSION)
                return (plugin_name, plugin_version)
        except Exception as exp:
            self.logger.info(
                message=(
                    f"{MODULE_NAME} {PLATFORM_NAME}: Error occurred while"
                    " getting plugin details."
                ),
                details=str(exp),
            )
        return (PLATFORM_NAME, PLUGIN_VERSION)
    
    def _add_user_agent(self, headers=None):
        """Add User-Agent in the headers of any request.

        Returns:
            Dict: Dictionary after adding User-Agent.
        """
        headers = add_user_agent(headers)
        plugin_name = self.plugin_name.lower().replace(" ", "-")
        ce_added_agent = headers.get("User-Agent", "netskope-ce")
        user_agent = "{}-{}-{}-v{}".format(
            ce_added_agent, MODULE_NAME.lower(), plugin_name, self.plugin_version
        )
        headers.update({"User-Agent": user_agent})
        return headers

    def _str_to_datetime(self, string: str) -> datetime:
        """Convert ISO formatted string to datetime object.

        Args:
            string (str): ISO formatted string.

        Returns:
            datetime: Converted datetime object.
        """
        try:
            return datetime.strptime(
                string.replace(".", ""), "%Y-%m-%dT%H:%M:%S%fZ"
            )
        except:
            return datetime.now()

    def _filter_collections(self, all_collections, selected_collections):
        """Create or filter collection names."""
        selected_collections = [
            x.strip() for x in selected_collections.split(",")
        ]
        selected_collections = list(
            filter(lambda x: len(x) > 0, selected_collections)
        )
        if not selected_collections:
            return all_collections
        else:
            if set(selected_collections) - set(all_collections):
                self.logger.error(
                    f"{self.log_prefix}: Following collections could not be "
                    f"found - {', '.join(set(selected_collections) - set(all_collections))}."
                )
            return set(selected_collections).intersection(set(all_collections))

    def _extract_fields_from_indicator(self, indicator, observable):
        """Extract severity and reputation from indicator for future usage."""
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
            self._ids[observable.idref][
                "reputation"
            ] = CONFIDENCE_TO_REPUTATION_MAPPINGS.get(
                str(indicator.confidence.value), 5
            )
        if indicator.likely_impact:
            self._ids[observable.idref][
                "severity"
            ] = LIKELY_IMPACT_TO_SEVERITY.get(
                str(indicator.likely_impact.value),
                SeverityType.UNKNOWN,
            )
        return self._ids[observable.idref]

    def _extract_from_indicator(self, package_indicators):
        """Extract ioc from indicators."""
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
                if (
                    type(properties) is File
                    and properties.hashes
                    and properties.hashes.md5
                ):
                    try:
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
                    except:
                        is_skipped_final = True
                elif (
                    type(properties) is File
                    and properties.hashes
                    and properties.hashes.sha256
                ):
                    try:
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
                    except:
                        is_skipped_final = True
                elif (
                    type(properties) in [URI, DomainName] and properties.value
                ):
                    try:
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
                    except:
                        is_skipped_final = True
                else:
                    is_skipped_final = True
        return indicators, is_skipped_final

    def _extract_from_observables(self, observables):
        """Extract iocs from observables."""
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
            if (
                type(properties) is File
                and properties.hashes
                and properties.hashes.md5
            ):
                try:
                    indicators.append(
                        Indicator(
                            value=str(properties.hashes.md5),
                            type=IndicatorType.MD5,
                            **self._ids.get(observable.id_, {}),
                            comments=str(observable.description or ""),
                        )
                    )
                except:
                    is_skipped = True
            elif (
                type(properties) is File
                and properties.hashes
                and properties.hashes.sha256
            ):
                try:
                    indicators.append(
                        Indicator(
                            value=str(properties.hashes.sha256),
                            type=IndicatorType.SHA256,
                            **self._ids.get(observable.id_, {}),
                            comments=str(observable.description or ""),
                        )
                    )
                except:
                    is_skipped = True
            elif type(properties) in [URI, DomainName] and properties.value:
                try:
                    indicators.append(
                        Indicator(
                            value=str(properties.value),
                            type=IndicatorType.URL,
                            comments=str(observable.description or ""),
                        )
                    )
                except:
                    is_skipped = True
            else:
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
        parsed_url = urlparse(configuration["discovery_url"].strip())
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
        username = configuration.get("username", "").strip()
        password = configuration.get("password", "")

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
        collection_uri = None
        services = client.discover_services()
        for service in services:
            if service.type == "COLLECTION_MANAGEMENT":
                collection_uri = service.address
                break
        if collection_uri is None:
            err_msg = "Failed to find collection management."
            raise STIXTAXIIException(err_msg)
        # to get collection form server
        return [c.name for c in client.get_collections(uri=collection_uri)]

    def convert_string_to_datetime(self, collections_dict):
        if collections_dict and isinstance(collections_dict, dict):
            for collection_name, str_datetime_value in collections_dict.items():
                if isinstance(str_datetime_value, str):
                    collections_dict[collection_name] = datetime.strptime(str_datetime_value, DATE_CONVERSION_STRING)
        else:
            err_msg = "Error occurred while fetching the collection details."
            self.logger.error(
                f"{self.log_prefix}: {err_msg}",
                details=f"Collection details: {collections_dict}"
            )
            raise STIXTAXIIException(err_msg)

        return collections_dict

    def convert_datetime_to_string(self, collections_dict):
        if collections_dict and isinstance(collections_dict, dict):
            for collection_name, datetime_value in collections_dict.items():
                if isinstance(datetime_value, datetime):
                    collections_dict[collection_name] = datetime_value.strftime(DATE_CONVERSION_STRING)
        else:
            err_msg = "Error occurred while creating the collection details to store."
            self.logger.error(
                f"{self.log_prefix}: {err_msg}",
                details=f"Collection details: {collections_dict}"
            )
            raise STIXTAXIIException(err_msg)

        return collections_dict

    def pull_1x(self, configuration, start_time):
        """Pull implementation for version 1.x."""
        self._ids = {}
        try:
            client = self._build_client(configuration)
            collections = self._get_collections(client)
        except requests.exceptions.ProxyError as err:
            err_msg = (
                "Invalid proxy configuration."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {err}",
                details=traceback.format_exc(),
            )
            raise STIXTAXIIException(err_msg)
        except requests.exceptions.ConnectionError as err:
            err_msg = (
                "Connection Error occurred. Check the Discovery URL / API Root URL provided."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {err}",
                details=traceback.format_exc(),
            )
            raise STIXTAXIIException(err_msg)
        except requests.exceptions.RequestException as err:
            err_msg = "Request Exception occurred."
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {err}",
                details=traceback.format_exc(),
            )
            raise STIXTAXIIException(err_msg)
        except STIXTAXIIException as err:
            err_msg = "Exception occurred while fetching the collections"
            self.logger.error(
                f"{self.log_prefix}: {err_msg}. Error: {err}",
                details=traceback.format_exc()
            )
            raise STIXTAXIIException(err_msg)
        except Exception as err:
            err_msg = "Exception occurred while fetching the collections."
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {err}",
                details=traceback.format_exc(),
            )
            raise STIXTAXIIException(err_msg)
        filtered_collections = self._filter_collections(
            collections, configuration["collection_names"]
        )
        self.logger.info(
            f"{self.log_prefix}: Following collections will be fetched - {', '.join(filtered_collections)}."
        )
        indicators = []

        delay_config = configuration.get("delay", 0) or 0
        delay_time = int(delay_config)

        start_time = pytz.utc.localize(start_time - timedelta(minutes=delay_time))

        for collection in filtered_collections:
            self.logger.info(
                f"{self.log_prefix}: Parsing collection - '{collection}'. Start time: {start_time}"
            )
            try:
                content_blocks = client.poll(
                    collection_name=collection,
                    begin_date=start_time,
                )
            except requests.exceptions.ProxyError as err:
                err_msg = (
                    "Invalid proxy configuration."
                )
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg} Error: {err}",
                    details=traceback.format_exc(),
                )
                return ValidationResult(
                    success=False,
                    message=err_msg
                )
            except requests.exceptions.ConnectionError as err:
                err_msg = (
                    "Connection Error occurred. Check the Discovery URL / API Root URL provided."
                )
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg} Error: {err}",
                    details=traceback.format_exc(),
                )
                raise STIXTAXIIException(err_msg)
            except requests.exceptions.RequestException as err:
                err_msg = "Request Exception occurred."
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg} Error: {err}",
                    details=traceback.format_exc(),
                )
                raise STIXTAXIIException(err_msg)
            except Exception as err:
                err_msg = "Exception occurred while fetching the objects from collection"
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg} Error: {err}",
                    details=traceback.format_exc(),
                )
                raise STIXTAXIIException(err_msg)
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
                    total_log = f"Total {collection_indicator_count} indicators pulled till now"
                    if is_skipped is True:
                        self.logger.info(
                            f"{self.log_prefix}: Block-{block_id} parsed, {len(extracted)} indicator(s) pulled, some indicators might have been discarded."
                            f" {total_log}"
                        )
                    else:
                        self.logger.info(
                            f"{self.log_prefix}: Block-{block_id} parsed, {len(extracted)} indicator(s) pulled."
                            f" {total_log}"
                        )
                    temp.close()
                except Exception as e:
                    self.logger.info(
                        f"{self.log_prefix}: Couldn't parse Block-{block_id}."
                    )
                    self.logger.error(
                        f"{self.log_prefix}: Following exception occured while extracting indicator(s) from Block-{block_id} - {repr(e)}",
                        details=traceback.format_exc()
                    )
                    block_id += 1
                    continue
                block_id += 1
                
            self.logger.info(
                f"{self.log_prefix}: Completed parsing of '{collection}' collection."
                f" Total {collection_indicator_count} indicators parsed successfully."
            )
            
        self.logger.info(
            f"{self.log_prefix}: Completed parsing of ({', '.join(filtered_collections)}) collections."
            f" Total {len(indicators)} indicators parsed successfully."
        )
        return indicators

    def _extract_observables_2x(self, pattern: str, data: dict):
        observables = []
        is_skipped = False
        for kind in OBSERVABLE_REGEXES:
            matches = re.findall(kind["regex"], pattern, re.IGNORECASE)
            if len(matches) == 0:
                is_skipped = is_skipped or False
            else:
                is_skipped = is_skipped or True
            for match in matches:
                if (
                    kind["type"] == IndicatorType.SHA256
                    or kind["type"] == IndicatorType.MD5
                ):
                    try:
                        observables.append(
                            Indicator(
                                value=match.replace("'", ""),
                                type=kind["type"],
                                **data,
                            )
                        )
                    except:
                        is_skipped = True
                else:
                    try:
                        observables.append(
                            Indicator(value=match[1], type=kind["type"], **data)
                        )
                    except:
                        is_skipped = True
        return observables, not (is_skipped)

    def _extract_indicators_2x(self, objects):
        indicators = []
        is_skipped_final = False
        modified_time = None
        for o in objects:
            if o.get("type").lower() != "indicator":
                is_skipped_final = True
                continue
            created_time = self._str_to_datetime(o.get("created"))
            modified_time = self._str_to_datetime(o.get("modified"))
            data = {
                "comments": o.get("description") or o.get("pattern") or "",
                "reputation": int(o.get("confidence", 50) / 10),
                "firstSeen": created_time,
                "lastSeen": modified_time,
            }
            extracted, is_skipped = self._extract_observables_2x(
                o.get("pattern", ""), data
            )
            if is_skipped:
                is_skipped_final = True
            indicators += extracted
        return indicators, is_skipped_final
    
    def update_storage(self, configuration, bundle, last_added_date, storage, collection, execution_details, bundle_id):
        next_value_21 = bundle.get("next")
        objects = bundle.get("objects", [])
        
        if objects:
            if configuration["pagination_method"] == "next":
                if configuration["version"] == "2.1" and next_value_21:
                    storage["in_execution"] = {
                        collection: {
                            "next": next_value_21,
                            "last_added_date": last_added_date
                        }
                    }
                elif configuration["version"] == "2.0" and len(objects) >= LIMIT:
                    try:
                        next_value_20 = int(storage.get("in_execution", {}).get(collection, {}).get("next", 0)) + (LIMIT * bundle_id)
                    except:
                        next_value_20 = 0
                    storage["in_execution"] = {
                        collection: {
                            "next": next_value_20,
                            "last_added_date": last_added_date
                        }
                    }
                else:
                    storage["in_execution"] = {}
                    execution_details[collection] = pytz.utc.localize(datetime.now())
            else:
                if configuration["version"] == "2.1" and bundle.get("more") and last_added_date:
                    storage["in_execution"] = {
                        collection: {
                            "next": next_value_21,
                            "last_added_date": last_added_date
                        }
                    }
                elif configuration["version"] == "2.0" and len(objects) >= LIMIT and last_added_date:
                    try:
                        next_value_20 = int(storage.get("in_execution", {}).get(collection, {}).get("next", 0)) + (LIMIT * bundle_id)
                    except:
                        next_value_20 = 0
                    # next_value_20 = int(storage.get("in_execution", {}).get(collection, 0)) + (LIMIT * bundle_id)
                    storage["in_execution"] = {
                        collection: {
                            "next": next_value_20,
                            "last_added_date": last_added_date
                        }
                    }
                else:
                    storage["in_execution"] = {}
                    execution_details[collection] = pytz.utc.localize(datetime.now())
        else:
            storage["in_execution"] = {}
            execution_details[collection] = pytz.utc.localize(datetime.now())
            
        return

    def paginate(self, configuration, pages, collection, storage, execution_details, indicators):
        bundle_id = 1
        collection_indicator_count = 0
        collection_skip_count = 0
        for bundle, last_added_date in pages:
            objects = bundle.get("objects", [])
            extracted, is_skipped = self._extract_indicators_2x(
                objects
            )
            indicators += extracted
            extracted_count = len(extracted)
            skip_count = len(objects) - extracted_count
            collection_indicator_count += extracted_count
            self.total_indicators += extracted_count
            collection_skip_count += skip_count
            self.total_skipped += skip_count
            total_log = f"Total {collection_indicator_count} indicators pulled for '{collection}' collection till now."
            if is_skipped is True:
                self.logger.info(
                    f"{self.log_prefix}: Collection: '{collection}' Bundle-{bundle_id} parsed, {extracted_count} indicator(s) pulled, {skip_count} indicators have been discarded."
                    f" {total_log}"
                )
            else:
                self.logger.info(
                    f"{self.log_prefix}: Collection: '{collection}' Bundle-{bundle_id} parsed, {extracted_count} indicator(s) pulled."
                    f" {total_log}"
                )

            self.total_bundle_count += 1

            if self.total_bundle_count == BUNDLE_LIMIT:
                self.logger.info(
                    f"{self.log_prefix}: Bundle limit of {BUNDLE_LIMIT} is reached while executing '{collection}' collection."
                    "The execution will be continued in the next cycle."
                    f" Total {collection_indicator_count} indicators parsed and {collection_skip_count} indicators skipped for '{collection}' collection."
                )
                self.logger.debug(
                    f"{self.log_prefix}: Updating the collection execution details with the next page details"
                )
                self.update_storage(
                    configuration=configuration,
                    bundle=bundle,
                    last_added_date=last_added_date,
                    storage=storage,
                    collection=collection,
                    execution_details=execution_details,
                    bundle_id=bundle_id
                )
                storage["collections"] = self.convert_datetime_to_string(execution_details)
                self.logger.debug(
                    f"{self.log_prefix}: Updated the collection execution details successfully. Collection execution details: {storage}"
                )
                return indicators
            bundle_id += 1

        self.logger.info(
            f"{self.log_prefix}: Completed parsing of '{collection}' collection."
            f" Total {collection_indicator_count} indicators parsed and {collection_skip_count} indicators skipped."
        )
        self.logger.debug(
            f"{self.log_prefix}: Successfully parsed {self.total_bundle_count} bundles."
        )
        return
    
    def get_page(self, func, configuration, start_time, next=None, start=0):
        headers = self._add_user_agent()
        if configuration["version"] == "2.1":
            pages = as_pages21(
                func,
                plugin=self,
                per_request=LIMIT,
                added_after=start_time,
                next=next,
                with_header=True,
                headers=headers
            )
        else:
            pages = as_pages20(
                func,
                plugin=self,
                per_request=LIMIT,
                added_after=start_time,
                start=start,
                with_header=True,
                headers=headers
            )

        return pages

    def pull_2x(self, configuration, start_time):
        """Pull implementation for version 2.x."""
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
                collection_execution_details = self.convert_string_to_datetime(storage.get("collections", {}))
        else:
            storage = {}

        delay_config = configuration.get("delay", 0) or 0
        delay_time = int(delay_config)
        username = configuration.get("username", "").strip()
        password = configuration.get("password", "")
        if configuration["version"] == "2.1":
            apiroot = ApiRoot21(
                configuration["discovery_url"].strip(),
                user=username,
                password=password,
                verify=self.ssl_validation,
                proxies=self.proxy,
            )
        else:
            apiroot = ApiRoot20(
                configuration["discovery_url"].strip(),
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
            all_collections, configuration["collection_names"]
        )
        self.logger.info(
            f"{self.log_prefix}: Following collections will be fetched - {', '.join(filtered_collections)}."
        )

        self.logger.debug(
            f"{self.log_prefix}: Collection execution details - {storage}."
        )

        if storage.get("in_execution", {}):
            for collection, next_page_details in storage.get("in_execution").items():
                if collection not in filtered_collections:
                    break
                collection_object = collection_name_object[collection]
                
                if configuration["pagination_method"] == "next":
                    next_start_time = collection_execution_details[collection]
                    next_value = next_page_details.get("next")
                    next_val = next_value
                    start_val = next_value
                else:
                    next_value = next_page_details.get("last_added_date")
                    next_start_time = self._str_to_datetime(next_value)
                    next_val = None
                    start_val = 0

                try:
                    next_start_time = next_start_time - timedelta(minutes=delay_time)
                    next_start_time = pytz.utc.localize(next_start_time)
                except:
                    pass
                self.logger.info(
                    f"{self.log_prefix}: Executing the collection '{collection}' with start time {next_start_time}"
                )
                try:
                    pages = self.get_page(
                        func=collection_object.get_objects,
                        configuration=configuration,
                        start_time=next_start_time,
                        next=next_val,
                        start=start_val
                    )

                    fetched_indicators = self.paginate(configuration, pages, collection, storage, collection_execution_details, indicators)
                    if fetched_indicators is not None:
                        self.logger.info(
                            f"{self.log_prefix}: Successfully parsed {self.total_indicators} indicators"
                            f" and {self.total_skipped} indicators were skipped."
                        )
                        return indicators
                except requests.exceptions.ProxyError as err:
                    err_msg = (
                        "Invalid proxy configuration."
                    )
                    self.logger.error(
                        message=f"{self.log_prefix}: {err_msg} Error: {err}",
                        details=traceback.format_exc(),
                    )
                    raise STIXTAXIIException(err_msg)
                except requests.exceptions.ConnectionError as err:
                    err_msg = (
                        "Connection Error occurred. Check the Discovery URL / API Root URL provided."
                    )
                    self.logger.error(
                        message=f"{self.log_prefix}: {err_msg} Error: {err}",
                        details=traceback.format_exc(),
                    )
                    raise STIXTAXIIException(err_msg)
                except requests.exceptions.RequestException as err:
                    if not("416" in str(err) or "request range not satisfiable" in str(err).lower()):
                        err_msg = "Request Exception occurred."
                        self.logger.error(
                            message=f"{self.log_prefix}: {err_msg} Error: {err}",
                            details=traceback.format_exc(),
                        )
                        raise STIXTAXIIException(err_msg)
                    self.logger.info(
                        f"{self.log_prefix}: Received status code 416, exiting the pulling of '{collection}' collection. Response: {str(err)}."
                    )
                except Exception as err:
                    if not("416" in str(err) or "request range not satisfiable" in str(err).lower()):
                        err_msg = "Exception occurred while fetching the objects of collection"
                        self.logger.error(
                            message=f"{self.log_prefix}: {err_msg} Error: {err}",
                            details=traceback.format_exc(),
                        )
                        raise STIXTAXIIException(err_msg)
                    self.logger.info(
                        f"{self.log_prefix}: Received status code 416, exiting the pulling of '{collection}' collection. Response: {str(err)}."
                    )

                collection_execution_details[collection] = datetime.now()
            storage["in_execution"] = {}

        for collection in apiroot.collections:
            collection_name = collection.title
            if collection_name not in filtered_collections:
                continue

            new_collection_details[collection_name] = pytz.utc.localize(collection_execution_details.get(collection_name, start_time))

        sorted_collection = sorted(new_collection_details, key=lambda k: new_collection_details[k])

        for collection in sorted_collection:
            collection_object = collection_name_object[collection]
            start_time = new_collection_details[collection] - timedelta(minutes=delay_time)
            try:
                self.logger.info(
                    f"{self.log_prefix}: Parsing collection - '{collection}'. Start time: {start_time} (UTC)"
                )
                pages = self.get_page(
                    func=collection_object.get_objects,
                    configuration=configuration,
                    start_time=start_time
                )

                fetched_indicators = self.paginate(configuration, pages, collection, storage, new_collection_details, indicators)
                if fetched_indicators is not None:
                    self.logger.info(
                        f"{self.log_prefix}: Successfully parsed {self.total_indicators} indicators"
                        f" and {self.total_skipped} indicators were skipped."
                    )
                    return indicators

                storage["in_execution"] = {}
                new_collection_details[collection] = pytz.utc.localize(datetime.now())
            except KeyError:
                # if there is no data in a collection
                storage["in_execution"] = {}
                new_collection_details[collection] = pytz.utc.localize(datetime.now())
            except requests.exceptions.ProxyError as err:
                err_msg = (
                    "Invalid proxy configuration."
                )
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg} Error: {err}.",
                    details=traceback.format_exc(),
                )
                raise STIXTAXIIException(err_msg)
            except requests.exceptions.ConnectionError as err:
                err_msg = (
                    "Connection Error occurred. Check the Discovery URL / API Root URL provided."
                )
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg} Error: {err}.",
                    details=traceback.format_exc(),
                )
                raise STIXTAXIIException(err_msg)
            except requests.exceptions.RequestException as err:
                if "416" in str(err) or "request range not satisfiable" in str(err).lower():
                    storage["in_execution"] = {}
                    self.logger.info(
                        f"{self.log_prefix}: Received status code 416, exiting the pulling of '{collection}' collection. Response: {str(err)}."
                    )
                    new_collection_details[collection] = pytz.utc.localize(datetime.now())
                else:
                    err_msg = "Exception occurred while fetching the objects of collection."
                    self.logger.error(
                        message=f"{self.log_prefix}: {err_msg} Error: {err}.",
                        details=traceback.format_exc(),
                    )
                    raise STIXTAXIIException(err_msg)
            except Exception as err:
                if "416" in str(err) or "request range not satisfiable" in str(err).lower():
                    storage["in_execution"] = {}
                    self.logger.info(
                        f"{self.log_prefix}: Received status code 416, exiting the pulling of '{collection}' collection. Response: {str(err)}."
                    )
                    new_collection_details[collection] = pytz.utc.localize(datetime.now())
                else:
                    err_msg = "Exception occurred while fetching the objects of collection."
                    self.logger.error(
                        message=f"{self.log_prefix}: {err_msg} Error: {err}",
                        details=traceback.format_exc(),
                    )
                    raise STIXTAXIIException(err_msg)

        storage["collections"] = self.convert_datetime_to_string(new_collection_details)
        self.logger.debug(f"{self.log_prefix}: Storage value after completion of the pull cycle: {storage}")
        self.logger.info(
            f"{self.log_prefix}: Successfully parsed {self.total_indicators} indicators"
            f" and {self.total_skipped} indicators were skipped."
        )
        return indicators

    def _pull(self, configuration, last_run_at):
        if not last_run_at:
            start_time = datetime.now() - timedelta(days=int(configuration["days"]))
            self.logger.info(
                f"{self.log_prefix}: Starting the initial pull execution for Discovery URL: {configuration.get('discovery_url', 'Not found')},"
                f" Version: {configuration.get('version', 'Not found')}"
                f" and start time: {start_time}."
            )
        else:
            start_time = last_run_at
            self.logger.info(
                f"{self.log_prefix}: Starting the pull execution for Discovery URL: {configuration.get('discovery_url', 'Not found')},"
                f" Version: {configuration.get('version', 'Not found')} and"
                f" start time: {start_time}."
            )
            
        self.logger.debug(
            f"{self.log_prefix}: Filter details - Type: {configuration.get('type', 'Not found')},"
            f" Severity: {configuration.get('severity', 'Not found')}, Reputation: {configuration.get('reputation', 'Not found')}."
        )

        if configuration["version"] == "1":
            indicators = self.pull_1x(configuration, start_time)
        else:
            indicators = self.pull_2x(configuration, start_time)
            
        filtered_list = list(
            filter(
                lambda x: x.severity.value in configuration["severity"]
                and x.reputation >= int(configuration["reputation"])
                and (
                    (
                        x.type in [IndicatorType.SHA256, IndicatorType.MD5]
                        and configuration["type"] in ["both", "malware"]
                    )
                    or (
                        x.type is IndicatorType.URL
                        and configuration["type"] in ["both", "url"]
                    )
                ),
                indicators,
            )
        )
        self.logger.info(
            f"{self.log_prefix}: Pulled {len(filtered_list)} indicators successfully and"
            f" skipped {len(indicators) - len(filtered_list)} indicators because of the applied filters"
        )
        return filtered_list

    def pull(self):
        """Pull indicators from TAXII server."""
        try:
            return self._pull(self.configuration, self.last_run_at)
        except STIXTAXIIException as err:
            raise err
        except Exception as err:
            self.logger.error(
                f"{self.log_prefix}: Error occurred while pulling the indicators. Error: {err}",
                details=traceback.format_exc()
            )

    def _validate_collections(self, configuration):
        try:
            version = configuration["version"]
            discovery_url = configuration["discovery_url"].strip()
            username = configuration.get("username", "").strip()
            password = configuration.get("password", "")
            if version == "1":
                client = self._build_client(configuration)
                all_collections = self._get_collections(client)
            elif version == "2.0":
                apiroot = ApiRoot20(
                    discovery_url,
                    user=username,
                    password=password,
                    verify=self.ssl_validation,
                    proxies=self.proxy,
                )
                all_collections = [c.title for c in apiroot.collections]
            elif version == "2.1":
                apiroot = ApiRoot21(
                    discovery_url,
                    user=username,
                    password=password,
                    verify=self.ssl_validation,
                    proxies=self.proxy,
                )
                all_collections = [c.title for c in apiroot.collections]
            collections = [
                c.strip() for c in configuration["collection_names"].split(",")
            ]
            collections = list(filter(lambda x: len(x) > 0, collections))
            if collections and set(collections) - set(all_collections):
                return ValidationResult(
                    success=False,
                    message=f"Could not find the collections {', '.join(set(collections) - set(all_collections))}",
                )
            return ValidationResult(
                success=True, message="Validated successfully."
            )
        except requests.exceptions.ProxyError as err:
            err_msg = (
                "Invalid proxy configuration."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {err}",
                details=traceback.format_exc(),
            )
            return ValidationResult(
                success=False,
                message=err_msg
            )
        except requests.exceptions.ConnectionError as err:
            err_msg = (
                "Connection Error occurred. Check the Discovery URL / API Root URL provided."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {err}",
                details=traceback.format_exc(),
            )
            return ValidationResult(
                success=False,
                message=err_msg
            )
        except requests.exceptions.RequestException as ex:
            self.logger.error(
                f"{self.log_prefix}: Exception occurred while connecting to the the server. Error: {str(ex)}.",
                details=traceback.format_exc()
            )
            return ValidationResult(
                success=False,
                message="Exception occurred while connecting to the the server. Check logs",
            )
        except exceptions.UnsuccessfulStatusError as ex:
            self.logger.error(
                f"{self.log_prefix}: {str(ex)}",
                details=traceback.format_exc()
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
            self.logger.error(
                f"{self.log_prefix}: Could not fetch the collection list from the server. Error: {str(ex)}",
                details=traceback.format_exc()
            )
            return ValidationResult(
                success=False,
                message=str(ex),
            )
        except Exception as ex:
            self.logger.error(
                f"{self.log_prefix}: Could not fetch the collection list from the server. Error: {str(ex)}.",
                details=traceback.format_exc()
            )
            return ValidationResult(
                success=False,
                message="Could not fetch the collection list from the server. Check all of the parameters.",
            )

    def _validate_uname_pass(self, configuration):
        try:
            self._pull(configuration, datetime.now())
        except requests.exceptions.ProxyError as err:
            err_msg = (
                "Invalid proxy configuration."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {err}",
                details=traceback.format_exc(),
            )
            return ValidationResult(
                success=False,
                message=err_msg
            )
        except requests.exceptions.ConnectionError as err:
            err_msg = (
                "Connection Error occurred. Check the Discovery URL / API Root URL provided."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {err}",
                details=traceback.format_exc(),
            )
            return ValidationResult(
                success=False,
                message=err_msg
            )
        except requests.exceptions.RequestException as ex:
            self.logger.error(
                f"{self.log_prefix}: Validation error occurred while connecting to the the server. Error: {str(ex)}.",
                details=traceback.format_exc()
            )
            return ValidationResult(
                success=False,
                message="Error occurred while connecting to the the server. Check logs",
            )
        except exceptions.UnsuccessfulStatusError as ex:
            self.logger.error(
                f"{self.log_prefix}: Validation error occurred. Error: {str(ex)}",
                details=traceback.format_exc()
            )
            if ex.status == "UNAUTHORIZED":
                return ValidationResult(
                    success=False,
                    message="Invalid Username/Password provided.",
                )
            else:
                return ValidationResult(
                    success=False, message="Check logs for more details."
                )
        except STIXTAXIIException as ex:
            # self.logger.error(
            #     f"{self.log_prefix}: Validation error occurred. Error: {str(ex)}",
            #     details=traceback.format_exc()
            # )
            return ValidationResult(
                success=False,
                message=ex,
            )
        except Exception as ex:
            self.logger.error(
                f"{self.log_prefix}: Validation error occurred. Error: {str(ex)}",
                details=traceback.format_exc()
            )
            return ValidationResult(
                success=False,
                message="Validation error occurred. Check logs for more details.",
            )
        else:
            return ValidationResult(
                success=True, message="Validated successfully."
            )

    def validate(self, configuration):
        """Validate the configuration."""
        # Discovery URL
        discovery_url = configuration.get("discovery_url", "").strip()
        if (
            "discovery_url" not in configuration
            or not discovery_url
        ):
            err_msg = "Discovery URL / API Root URL is a required field."
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        elif not isinstance(discovery_url, str):
            err_msg = "Invalid Discovery URL / API Root URL Provided."
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )
            
        # Username
        username = configuration.get("username", "").strip()
        if not isinstance(username, str):
            err_msg = "Invalid Username Provided."
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )
            
        # Password
        password = configuration.get("password", "")
        if not isinstance(password, str):
            err_msg = "Invalid Password Provided."
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )

        # STIX/TAXII Version
        version = configuration.get("version", "").strip()
        if "version" not in configuration or not version:
            err_msg = "STIX/TAXII Version is a required field."
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            return ValidationResult(success=False, message=err_msg)
        elif version not in ["1", "2.0", "2.1"]:
            err_msg = "Invalid value for STIX/TAXII Version provided. Avialable values are '1', '2.0', or '2.1'."
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            return ValidationResult(success=False, message=err_msg)

        # Collection Names
        collection_names = configuration.get("collection_names", "").strip()
        if (
            "collection_names" not in configuration
            or not isinstance(collection_names, str)
        ):
            err_msg = "Invalid Collection Names provided."
            self.logger.error(
                f"{self.log_prefix}: {err_msg}"
            )
            return ValidationResult(
                success=False, message=err_msg
            )

        # Type of Threat data to pull
        type = configuration.get("type", [])
        if "type" not in configuration or not type:
            err_msg = "Type of Threat data to pull is a required field."
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            return ValidationResult(success=False, message=err_msg)
        elif type not in ["both", "malware", "url"]:
            err_msg = "Invalid value for Type of Threat data to pull provided. Avialable values are 'both', 'malware' or 'url'."
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            return ValidationResult(success=False, message=err_msg)
        
        # Pagination Method
        pagination_method = configuration.get("pagination_method", "").strip()
        if "pagination_method" not in configuration or not pagination_method:
            err_msg = "Pagination Method is a required field."
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            return ValidationResult(success=False, message=err_msg)
        elif pagination_method not in ["next", "last_added_date"]:
            err_msg = "Invalid value for Pagination Method provided. Avialable values are 'next' or 'last_added_date'."
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            return ValidationResult(success=False, message=err_msg)
        
        # Reputation
        reputation = configuration.get("reputation", 0)
        if "reputation" not in configuration or reputation is None:
            err_msg = "Reputation is a required field."
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            return ValidationResult(success=False, message=err_msg)
        elif not isinstance(reputation, int):
            err_msg = (
                "Invalid value for Reputation provided. "
                "Must be an integer."
            )
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            return ValidationResult(success=False, message=err_msg)
        elif int(reputation) < 1 or int(reputation) > 10:
            err_msg = (
                "Invalid value for Reputation provided. "
                "Select a value between 1 - 10."
            )
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            return ValidationResult(success=False, message=err_msg)

        # Initial Range
        initial_range = configuration.get("days", 0)
        if "days" not in configuration or initial_range is None:
            err_msg = "Initial Range (in days) is a required field."
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            return ValidationResult(success=False, message=err_msg)
        elif not isinstance(initial_range, int):
            err_msg = (
                "Invalid value for Initial Range (in days) provided. "
                "Must be an integer."
            )
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            return ValidationResult(success=False, message=err_msg)
        elif int(initial_range) <= 0 or int(initial_range) > 365:
            err_msg = (
                "Invalid value for Initial Range (in days) provided. "
                "Select a value between 1 - 365."
            )
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            return ValidationResult(success=False, message=err_msg)

        # Delay
        delay_config = configuration.get("delay", 0) or 0
        if not isinstance(delay_config, int):
            err_msg = (
                "Invalid value for Look Back provided. "
                "Must be an integer."
            )
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            return ValidationResult(success=False, message=err_msg)
        elif not (0 <= int(delay_config) <= 1440):
            err_msg = (
                "Invalid value for Look Back provided. "
                "Select a value between 0 - 1440."
            )
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            return ValidationResult(success=False, message=err_msg)
        
        severity = configuration.get("severity", [])
        if "severity" not in configuration or not severity:
            err_msg = "Severity is a required field."
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            return ValidationResult(success=False, message=err_msg)
        elif not (
            all(
                sev in ["unknown", "low", "medium", "high", "critical"]
                for sev in severity
            )
        ):
            err_msg = "Invalid value for Severity provided. Avialable values are 'unknown', 'low', 'medium', 'high' or 'critical'."
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            return ValidationResult(success=False, message=err_msg)

        validate_collections = self._validate_collections(configuration)
        if validate_collections.success == False:
            return validate_collections

        validate_uname_pass = self._validate_uname_pass(configuration)
        if validate_uname_pass.success == False:
            return validate_uname_pass

        self.logger.info(f"{self.log_prefix}: Successfully validated configuration parameters.")
        return ValidationResult(
            success=True, message="Validated successfully."
        )

    def get_actions(self):
        """Get available actions."""
        return []

    def validate_action(self, action: Action):
        """Validate STIX configuration."""
        return ValidationResult(success=True, message="Validation successful.")

    def get_action_fields(self, action: Action):
        """Get fields required for an action."""
        return []
