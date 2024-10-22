"""Webtx parser."""

import re

FIELD_REGEX = r"\"(?:(?:[^\"]|\"\")*)\"|(?:\S+)"


class WebtxParser:
    """Webtx parser class."""

    def __init__(self, allow_empty_values):
        """Webtx parser init."""
        self.allow_empty_values = allow_empty_values

    @property
    def fields(self):
        """Fields."""
        return self._fields

    @fields.setter
    def fields(self, fields: str):
        """Fields."""
        DIRECTIVE = "#Fields:"
        if fields.startswith(DIRECTIVE):
            fields = fields[len(DIRECTIVE):].strip()  # noqa: E203
        self._fields = fields.split(" ")

    def parse(self, log: str) -> dict:
        """Parse."""
        if self.allow_empty_values:
            return {
                self.fields[i]: (
                    v[1:-1] if v.startswith('"') and v.endswith('"') else v
                ).replace('""', '"') if v != "-" else None
                for i, v in enumerate(re.findall(FIELD_REGEX, log))
            }
        else:
            return {
                self.fields[i]: (
                    v[1:-1] if v.startswith('"') and v.endswith('"') else v
                ).replace('""', '"')
                for i, v in enumerate(re.findall(FIELD_REGEX, log))
                if v != "-"
            }
