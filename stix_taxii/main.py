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


class STIXTAXIIPlugin(PluginBase):
    """The TAXIIPlugin implementation."""

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
        except Exception:
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
                    f"Plugin STIX/TAXII: Following collections could not be "
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
        is_skipped = False
        for indicator in package_indicators:
            for observable in indicator.observables:
                data = self._extract_fields_from_indicator(
                    indicator, observable
                )
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
                elif (
                    type(properties) in [URI, DomainName] and properties.value
                ):
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
                else:
                    is_skipped = True
        return indicators, is_skipped

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
            elif type(properties) in [URI, DomainName] and properties.value:
                indicators.append(
                    Indicator(
                        value=str(properties.value),
                        type=IndicatorType.URL,
                        comments=str(observable.description or ""),
                    )
                )
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

        if configuration["username"].strip() and configuration["password"]:
            client.set_auth(
                username=configuration["username"].strip(),
                password=configuration["password"],
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
            self.logger.error(
                "Plugin STIX/TAXII: Failed to find collection management."
            )
            return None
        # to get collection form server
        return [c.name for c in client.get_collections(uri=collection_uri)]

    def pull_1x(self, configuration, start_time):
        """Pull implementation for version 1.x."""
        self._ids = {}
        client = self._build_client(configuration)
        collections = self._get_collections(client)
        filtered_collections = self._filter_collections(
            collections, configuration["collection_names"]
        )
        self.logger.info(
            f"Plugin STIX/TAXII: Following collections will be fetched - {', '.join(filtered_collections)}."
        )
        indicators = []

        for collection in filtered_collections:
            self.logger.info(
                f"Plugin STIX/TAXII: Parsing collection - {collection}."
            )
            content_blocks = client.poll(
                collection_name=collection,
                begin_date=start_time,
            )
            block_id = 1
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
                    if is_skipped is True:
                        self.logger.info(
                            f"Plugin STIX/TAXII: Block-{block_id} parsed, {len(extracted)} indicator(s) pulled, some indicators might have been discarded."
                        )
                    else:
                        self.logger.info(
                            f"Plugin STIX/TAXII: Block-{block_id} parsed, {len(extracted)} indicator(s) pulled."
                        )
                    temp.close()
                except Exception as e:
                    self.logger.info(
                        f"Plugin STIX/TAXII: Couldn't parse Block-{block_id}."
                    )
                    self.logger.error(
                        f"Plugin STIX/TAXII: Following exception occured while extracting indicator(s) from Block-{block_id} - {repr(e)}"
                    )
                    block_id += 1
                    continue
                block_id += 1
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
                    observables.append(
                        Indicator(
                            value=match.replace("'", ""),
                            type=kind["type"],
                            **data,
                        )
                    )
                else:
                    observables.append(
                        Indicator(value=match[1], type=kind["type"], **data)
                    )
        return observables, not (is_skipped)

    def _extract_indicators_2x(self, objects):
        indicators = []
        is_skipped = False
        for o in objects:
            if o.get("type").lower() != "indicator":
                is_skipped = True
                continue
            data = {
                "comments": o.get("description") or o.get("pattern") or "",
                "reputation": int(o.get("confidence", 50) / 10),
                "firstSeen": self._str_to_datetime(o.get("created")),
                "lastSeen": self._str_to_datetime(o.get("modified")),
            }
            extracted, is_skipped = self._extract_observables_2x(
                o.get("pattern", ""), data
            )
            indicators += extracted
        return indicators, is_skipped

    def pull_20x(self, configuration, start_time):
        """Pull implementation for version 2.x."""
        indicators = []
        apiroot = ApiRoot20(
            configuration["discovery_url"].strip(),
            user=configuration["username"].strip(),
            password=configuration["password"],
            verify=self.ssl_validation,
            proxies=self.proxy,
        )
        all_collections = [c.title for c in apiroot.collections]
        filtered_collections = self._filter_collections(
            all_collections, configuration["collection_names"]
        )
        self.logger.info(
            f"Plugin STIX/TAXII: Following collections will be fetched - {', '.join(filtered_collections)}."
        )
        for collection in filter(
            lambda x: x.title in filtered_collections, apiroot.collections
        ):
            bundle_id = 1
            try:
                self.logger.info(
                    f"Plugin STIX/TAXII: Parsing collection - {collection.title}."
                )
                for bundle in as_pages20(
                    collection.get_objects,
                    per_request=100,
                    added_after=start_time,
                ):
                    extracted, is_skipped = self._extract_indicators_2x(
                        bundle.get("objects", [])
                    )
                    indicators += extracted
                    if is_skipped is True:
                        self.logger.info(
                            f"Plugin STIX/TAXII: Bundle-{bundle_id} parsed, {len(extracted)} indicator(s) pulled, some indicators might have been discarded."
                        )
                    else:
                        self.logger.info(
                            f"Plugin STIX/TAXII: Bundle-{bundle_id} parsed, {len(extracted)} indicator(s) pulled."
                        )
                    bundle_id += 1
            except KeyError:
                # if there is no data in a collection
                pass
        return indicators

    def pull_21x(self, configuration, start_time):
        """Pull implementation for version 2.x."""
        indicators = []
        apiroot = ApiRoot21(
            configuration["discovery_url"].strip(),
            user=configuration["username"].strip(),
            password=configuration["password"],
            verify=self.ssl_validation,
            proxies=self.proxy,
        )
        all_collections = [c.title for c in apiroot.collections]
        filtered_collections = self._filter_collections(
            all_collections, configuration["collection_names"]
        )
        self.logger.info(
            f"Plugin STIX/TAXII: Following collections will be fetched - {', '.join(filtered_collections)}."
        )
        for collection in filter(
            lambda x: x.title in filtered_collections, apiroot.collections
        ):
            bundle_id = 1
            try:
                self.logger.info(
                    f"Plugin STIX/TAXII: Parsing collection - {collection.title}."
                )
                for bundle in as_pages21(
                    collection.get_objects,
                    per_request=100,
                    added_after=start_time,
                ):
                    extracted, is_skipped = self._extract_indicators_2x(
                        bundle.get("objects", [])
                    )
                    indicators += extracted
                    if is_skipped is True:
                        self.logger.info(
                            f"Plugin STIX/TAXII: Bundle-{bundle_id} parsed, {len(extracted)} indicator(s) pulled, some indicators might have been discarded."
                        )
                    else:
                        self.logger.info(
                            f"Plugin STIX/TAXII: Bundle-{bundle_id} parsed, {len(extracted)} indicator(s) pulled."
                        )
                    bundle_id += 1
            except KeyError:
                # if there is no data in a collection
                pass
        return indicators

    def _pull(self, configuration, last_run_at):
        delay_config = configuration.get("delay", 0) or 0
        delay_time = int(delay_config)
        if not last_run_at:
            start_time = pytz.utc.localize(
                datetime.now() - timedelta(days=int(configuration["days"]))
            )
        else:
            start_time = pytz.utc.localize(last_run_at)

        start_time = start_time - timedelta(minutes=delay_time)
        self.logger.info(
            f"Plugin STIX/TAXII: Start time for the pull cycle - {start_time} (UTC)"
        )
        if configuration["version"] == "1":
            indicators = self.pull_1x(configuration, start_time)
        elif configuration["version"] == "2.0":
            indicators = self.pull_20x(configuration, start_time)
        elif configuration["version"] == "2.1":
            indicators = self.pull_21x(configuration, start_time)
        return list(
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

    def pull(self):
        """Pull indicators from TAXII server."""
        return self._pull(self.configuration, self.last_run_at)

    def _validate_collections(self, configuration):
        try:
            if configuration["version"] == "1":
                client = self._build_client(configuration)
                all_collections = self._get_collections(client)
            elif configuration["version"] == "2.0":
                apiroot = ApiRoot20(
                    configuration["discovery_url"].strip(),
                    user=configuration["username"].strip(),
                    password=configuration["password"],
                    verify=self.ssl_validation,
                    proxies=self.proxy,
                )
                all_collections = [c.title for c in apiroot.collections]
            elif configuration["version"] == "2.1":
                apiroot = ApiRoot21(
                    configuration["discovery_url"].strip(),
                    user=configuration["username"].strip(),
                    password=configuration["password"],
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
        except requests.exceptions.RequestException as ex:
            self.logger.error(f"Plugin STIX/TAXII: {repr(ex)}")
            return ValidationResult(
                success=False,
                message="Exception occurred while connecting to the the server. Check logs",
            )
        except exceptions.UnsuccessfulStatusError as ex:
            if ex.status == "UNAUTHORIZED":
                self.logger.error(f"Plugin STIX/TAXII: {repr(ex)}")
                return ValidationResult(
                    success=False,
                    message="Invalid/Blank Username/Password provided.",
                )
            else:
                self.logger.error(f"Plugin STIX/TAXII: {repr(ex)}")
                return ValidationResult(
                    success=False, message="Check logs for more details."
                )
        except Exception as ex:
            self.logger.error(f"Plugin STIX/TAXII: {repr(ex)}")
            return ValidationResult(
                success=False,
                message="Could not fetch the collection list from the server. Check all of the parameters.",
            )

    def _validate_uname_pass(self, configuration):
        try:
            self._pull(configuration, datetime.now())
        except requests.exceptions.RequestException as ex:
            self.logger.error(f"Plugin STIX/TAXII: {repr(ex)}")
            return ValidationResult(
                success=False,
                message="Exception occurred while connecting to the the server. Check logs",
            )
        except exceptions.UnsuccessfulStatusError as ex:
            if ex.status == "UNAUTHORIZED":
                self.logger.error(f"Plugin STIX/TAXII: {repr(ex)}")
                return ValidationResult(
                    success=False,
                    message="Invalid/Blank Username/Password provided.",
                )
            else:
                self.logger.error(f"Plugin STIX/TAXII: {repr(ex)}")
                return ValidationResult(
                    success=False, message="Check logs for more details."
                )
        except Exception as ex:
            self.logger.error(f"Plugin STIX/TAXII: {repr(ex)}")
            return ValidationResult(
                success=False,
                message="Check logs for more details.",
            )
        else:
            return ValidationResult(
                success=True, message="Validated successfully."
            )

    def validate(self, configuration):
        """Validate the configuration."""
        if (
            "discovery_url" not in configuration
            or type(configuration["discovery_url"]) != str
            or not configuration["discovery_url"].strip()
        ):
            self.logger.error(
                "Plugin STIX/TAXII: No discovery_url found in the configuration parameters."
            )
            return ValidationResult(
                success=False, message="Invalid Discovery URL provided."
            )

        if (
            "collection_names" not in configuration
            or type(configuration["collection_names"]) != str
        ):
            self.logger.error(
                "Plugin STIX/TAXII: No Collection Names  found in the configuration parameters."
            )
            return ValidationResult(
                success=False, message="Invalid Collection Names provided."
            )

        if "type" not in configuration or configuration["type"] not in [
            "both",
            "malware",
            "url",
        ]:
            self.logger.error(
                "Plugin STIX/TAXII: Invalid value for 'Type of Threat data to pull' provided. "
                "Allowed values are Both, Malware or URL."
            )
            return ValidationResult(
                success=False,
                message=(
                    "Invalid value for 'Type of Threat data to pull' provided."
                    "Allowed values are 'Both', 'Malware' or 'URL'."
                ),
            )

        try:
            if (
                "reputation" not in configuration
                or not configuration["reputation"]
                or int(configuration["reputation"]) < 1
                or int(configuration["reputation"]) > 10
            ):
                self.logger.error(
                    "Plugin STIX/TAXII: Validation error occured Error: Invalid reputation provided."
                )
                return ValidationResult(
                    success=False,
                    message="Invalid reputation provided. Must range from 1 to 10.",
                )
        except ValueError:
            return ValidationResult(
                success=False,
                message="Invalid reputation provided.",
            )

        try:
            if (
                "days" not in configuration
                or not configuration["days"]
                or int(configuration["days"]) <= 0
            ):
                self.logger.error(
                    "Plugin STIX/TAXII: Validation error occured Error: Invalid days provided."
                )
                return ValidationResult(
                    success=False,
                    message="Invalid Number of days provided.",
                )
        except ValueError:
            return ValidationResult(
                success=False,
                message="Invalid Number of days provided.",
            )

        try:
            delay_config = configuration.get("delay", 0) or 0
            if not (0 <= int(delay_config) <= 1440):
                self.logger.error(
                    "Plugin STIX/TAXII: Validation error occured Error: Invalid Look Back provided. Valid value is anything between 0 to 1440"
                )
                return ValidationResult(
                    success=False,
                    message="Invalid Look Back value provided.",
                )
        except Exception as exp:
            self.logger.error(
                message="Plugin STIX/TAXII: Validation error occured Error: Invalid Look Back provided. Valid value is anything between 0 to 1440",
                details=str(exp),
            )
            return ValidationResult(
                success=False,
                message="Invalid Look Back value provided.",
            )

        validate_collections = self._validate_collections(configuration)
        validate_uname_pass = self._validate_uname_pass(configuration)

        if validate_collections.success == False:
            return validate_collections
        elif validate_uname_pass.success == False:
            return validate_uname_pass

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
