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
import tempfile
from urllib.parse import urlparse
from datetime import datetime, timedelta
import pytz
from cabby import create_client
from taxii2client.v20 import ApiRoot, as_pages
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
                    f"found - {', '.join(set(selected_collections) - set(all_collections))}"
                )
            return set(selected_collections).intersection(set(all_collections))

    def _extract_fields_from_indicator(self, indicator, observable):
        """Extract severity and reputation from indicator for future usage."""
        if observable.idref is None:
            data = {}
            if indicator.confidence:
                data["reputation"] = CONFIDENCE_TO_REPUTATION_MAPPINGS.get(
                    str(indicator.confidence.value), 5
                )
            if indicator.likely_impact:
                data["severity"] = LIKELY_IMPACT_TO_SEVERITY.get(
                    str(indicator.likely_impact.value), SeverityType.UNKNOWN,
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
                str(indicator.likely_impact.value), SeverityType.UNKNOWN,
            )
        return self._ids[observable.idref]

    def _extract_from_indicator(self, package_indicators):
        """Extract ioc from indicators."""
        indicators = []
        for indicator in package_indicators:
            for observable in indicator.observables:
                data = self._extract_fields_from_indicator(
                    indicator, observable
                )
                if not observable.object_:
                    continue
                properties = observable.object_.properties
                if type(properties) is File and properties.hashes.md5:
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
                if type(properties) is File and properties.hashes.sha256:
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
                if type(properties) in [URI, DomainName]:
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
        return indicators

    def _extract_from_observables(self, observables):
        """Extract iocs from observables."""
        indicators = []
        for observable in observables:
            if not observable.object_:
                continue
            properties = observable.object_.properties
            if type(properties) is File and properties.hashes.md5:
                indicators.append(
                    Indicator(
                        value=str(properties.hashes.md5),
                        type=IndicatorType.MD5,
                        **self._ids.get(observable.id_, {}),
                        comments=str(observable.description or ""),
                    )
                )
            if type(properties) is File and properties.hashes.sha256:
                indicators.append(
                    Indicator(
                        value=str(properties.hashes.sha256),
                        type=IndicatorType.SHA256,
                        **self._ids.get(observable.id_, {}),
                        comments=str(observable.description or ""),
                    )
                )
            if type(properties) in [URI, DomainName]:
                indicators.append(
                    Indicator(
                        value=str(properties.value),
                        type=IndicatorType.URL,
                        comments=str(observable.description or ""),
                    )
                )
        return indicators

    def _extract_indicators(self, package):
        """Extract iocs from a STIX package."""
        if package.indicators:
            return self._extract_from_indicator(package.indicators)
        elif package.observables:
            return self._extract_from_observables(package.observables)
        else:
            return []

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
        client.set_auth(verify_ssl=self.ssl_validation)
        client.set_proxies(self.proxy)

        if configuration["username"].strip() and configuration["password"]:
            client.set_auth(
                username=configuration["username"].strip(),
                password=configuration["password"],
            )
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
                "Plugin STIX/TAXII: failed to find collection management."
            )
            return None
        # to get collection form server
        return [c.name for c in client.get_collections(uri=collection_uri)]

    def pull_1x(self, start_time):
        """Pull implementation for version 1.x."""
        self._ids = {}
        client = self._build_client(self.configuration)
        collections = self._get_collections(client)
        filtered_collections = self._filter_collections(
            collections, self.configuration["collection_names"]
        )
        self.logger.info(
            f"Plugin STIX/TAXII: Following collections will be fetched - {', '.join(filtered_collections)}"
        )
        indicators = []

        for collection in filtered_collections:
            content_blocks = client.poll(
                collection_name=collection, begin_date=start_time,
            )
            for block in content_blocks:
                temp = tempfile.TemporaryFile()
                temp.write(block.content)
                temp.seek(0)
                stix_package = STIXPackage.from_xml(temp)
                extracted = self._extract_indicators(stix_package)
                indicators = indicators + extracted
                temp.close()
        return indicators

    def _extract_observables_2x(self, pattern: str, data: dict):
        observables = []
        for kind in OBSERVABLE_REGEXES:
            matches = re.findall(kind["regex"], pattern, re.IGNORECASE)
            for match in matches:
                observables.append(
                    Indicator(value=match[1], type=kind["type"], **data)
                )
        return observables

    def _extract_indicators_2x(self, objects):
        indicators = []
        for o in objects:
            if o.get("type").lower() != "indicator":
                continue
            data = {
                "comments": o.get("description") or o.get("pattern") or "",
                "reputation": int(o.get("confidence", 50) / 10),
                "firstSeen": self._str_to_datetime(o.get("created")),
                "lastSeen": self._str_to_datetime(o.get("created")),
            }
            indicators = indicators + self._extract_observables_2x(
                o.get("pattern", ""), data
            )
        return indicators

    def pull_2x(self, start_time):
        """Pull implementation for version 2.x."""
        indicators = []
        apiroot = ApiRoot(
            self.configuration["discovery_url"].strip(),
            user=self.configuration["username"].strip(),
            password=self.configuration["password"],
            verify=self.ssl_validation,
            proxies=self.proxy,
        )
        all_collections = [c.title for c in apiroot.collections]
        filtered_collections = self._filter_collections(
            all_collections, self.configuration["collection_names"]
        )
        self.logger.info(
            f"Plugin STIX/TAXII: Following collections will be fetched - {', '.join(filtered_collections)}"
        )
        for collection in filter(
            lambda x: x.title in filtered_collections, apiroot.collections
        ):
            try:
                for bundle in as_pages(
                    collection.get_objects,
                    per_request=100,
                    added_after=start_time,
                ):
                    indicators = indicators + self._extract_indicators_2x(
                        bundle.get("objects", [])
                    )
            except KeyError:
                # if there is no data in a collection
                pass
        return indicators

    def pull(self):
        """Pull indicators from TAXII server."""
        if not self.last_run_at:
            start_time = pytz.utc.localize(
                datetime.now()
                - timedelta(days=int(self.configuration["days"]))
            )
        else:
            start_time = pytz.utc.localize(self.last_run_at)
        if self.configuration["version"] == "1":
            indicators = self.pull_1x(start_time)
        elif self.configuration["version"] == "2":
            indicators = self.pull_2x(start_time)
        return list(
            filter(
                lambda x: x.severity.value in self.configuration["severity"]
                and x.reputation >= int(self.configuration["reputation"])
                and (
                    (
                        x.type in [IndicatorType.SHA256, IndicatorType.MD5]
                        and self.configuration["type"] in ["both", "malware"]
                    )
                    or (
                        x.type is IndicatorType.URL
                        and self.configuration["type"] in ["both", "url"]
                    )
                ),
                indicators,
            )
        )

    def _validate_collections(self, configuration):
        try:
            if configuration["version"] == "1":
                client = self._build_client(configuration)
                all_collections = self._get_collections(client)
            elif configuration["version"] == "2":
                apiroot = ApiRoot(
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
        except Exception as ex:
            self.logger.error(f"Plugin STIX/TAXII: {repr(ex)}")
            return ValidationResult(
                success=False,
                message="Could not fetch the collection list from the server. Check all of the parameters.",
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
                    "Invalid value for 'Type of Threat data to pull' provided. "
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
                success=False, message="Invalid reputation provided.",
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
                    success=False, message="Invalid Number of days provided.",
                )
        except ValueError:
            return ValidationResult(
                success=False, message="Invalid Number of days provided.",
            )

        return self._validate_collections(configuration)

    def get_actions(self):
        """Get available actions."""
        return []

    def validate_action(self, action: Action):
        """Validate STIX configuration."""
        return ValidationResult(success=True, message="Validation successful.")

    def get_action_fields(self, action: Action):
        """Get fields required for an action."""
        return []
