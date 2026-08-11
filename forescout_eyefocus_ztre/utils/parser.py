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

CRE Forescout eyeFocus REM plugin parser.

Pure transform / normalization logic. This module intentionally has NO
dependency on the Netskope CE framework (or on ``requests``) so it can be
unit-tested in isolation.
"""

from datetime import datetime, timezone

from .constants import (
    ASSET_FIELD_MAPPING,
    DATE_FORMAT_NO_MS,
    DATE_FORMAT_WITH_MS,
)


class ForescoutEyeFocusParser:
    """Transforms Forescout REM asset entities into plugin records."""

    # ----------------------------------------------------------------- #
    # Field extraction helpers (mirror the CE helper idioms)
    # ----------------------------------------------------------------- #
    def _parse_datetime(self, value):
        """Parse a Forescout ISO-8601 UTC timestamp into a tz-aware datetime.

        Returns None when the value is falsy or cannot be parsed.
        """
        if not value or not isinstance(value, str):
            return None
        for fmt in (DATE_FORMAT_WITH_MS, DATE_FORMAT_NO_MS):
            try:
                return datetime.strptime(value, fmt).replace(
                    tzinfo=timezone.utc
                )
            except (ValueError, TypeError):
                continue
        return None

    def _extract_field_from_event(
        self, key, event, default=None, transformation=None
    ):
        """Extract a (possibly nested, dot-notation) field from an entity and
        apply an optional transformation.

        transformation:
            "string"   -> str(value)
            "float"    -> float(value) (default on failure)
            "list"     -> value as a list of non-empty items
            "datetime" -> tz-aware datetime (or default)
        """
        value = event
        for part in key.split("."):
            if isinstance(value, dict) and part in value:
                value = value[part]
            else:
                return default
        if value is None:
            return default
        if transformation == "string":
            return str(value)
        if transformation == "float":
            try:
                return float(value)
            except (TypeError, ValueError):
                return default
        if transformation == "list":
            if isinstance(value, list):
                return [item for item in value if item not in (None, "")]
            return [value]
        if transformation == "datetime":
            return self._parse_datetime(value)
        return value

    def _add_field(self, fields_dict, field_name, value):
        """Safely add a field to a record.

        - Empty dict/list -> stored as None (MongoDB safety).
        - int/float (including 0) -> always stored.
        - Other truthy values -> stored.
        - None / empty string -> omitted.
        """
        if isinstance(value, (dict, list)) and not value:
            fields_dict[field_name] = None
            return
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            fields_dict[field_name] = value
            return
        if value:
            fields_dict[field_name] = value

    # ----------------------------------------------------------------- #
    # Entity transform
    # ----------------------------------------------------------------- #
    def transform_entity(self, entity):
        """Build a record for a single Forescout REM asset entity using the
        ASSET_FIELD_MAPPING."""
        record = {}
        for field_name, spec in ASSET_FIELD_MAPPING.items():
            value = self._extract_field_from_event(
                key=spec["key"],
                event=entity,
                default=spec.get("default"),
                transformation=spec.get("transformation"),
            )
            self._add_field(record, field_name, value)
        return record

    # ----------------------------------------------------------------- #
    # Filters
    # ----------------------------------------------------------------- #
    def keep_category(self, entity, categories):
        """Return True when the entity's category should be kept.

        An empty / None ``categories`` keep-list keeps everything.
        """
        if not categories:
            return True
        return entity.get("rem_category") in categories

    # ----------------------------------------------------------------- #
    # Pipeline
    # ----------------------------------------------------------------- #
    def parse_entities(self, entities, categories):
        """Filter + transform a list of Forescout entities into records.

        Only the category keep-list is applied here; the risk-score bounds of
        the Advanced Filters are applied server-side by the REM Asset Search
        API, so filtered-out assets never reach the parser.

        Returns a tuple ``(records, skipped)`` where ``skipped`` is the number
        of entities dropped by the category filter (or for lacking an Asset
        ID).
        """
        records = []
        skipped = 0
        for entity in entities or []:
            if not isinstance(entity, dict):
                skipped += 1
                continue
            if not self.keep_category(entity, categories):
                skipped += 1
                continue
            record = self.transform_entity(entity)
            if record.get("Asset ID"):
                records.append(record)
            else:
                skipped += 1
        return records, skipped
