"""Syslog service plugin."""

from typing import List

from netskope.integrations.cls.plugin_base import (
    PluginBase,
    ValidationResult
)

MODULE_NAME = "CLS"
PLUGIN_NAME = "Cloud Exchange Logs"
LOG_BATCH_SIZE = 10000


class SyslogServicePlugin(PluginBase):
    """Syslog Service Plugin Implementation class."""

    def __init__(
        self,
        name,
        *args,
        **kwargs,
    ):
        """Init function."""
        super().__init__(name, *args, **kwargs)
        self.log_prefix = f"{MODULE_NAME} {PLUGIN_NAME}"
        if name:
            self.log_prefix = f"{self.log_prefix} [{name}]"

    def transform(self, raw_data, data_type, subtype) -> List:
        """Transform the raw netskope JSON data into target platform supported data formats."""
        pass

    def pull(self, logs, start_time, end_time):
        """Pull logs from Logging section and ingest(push) it to syslog server."""
        count = 0
        logs_list = []
        for log in logs:
            try:
                prepared = {
                    "createdAt": log["createdAt"],
                    "ce_log_type": log.get("ce_log_type", log.get("type", "info")),
                    "message": log["message"],
                }
                if log.get("errorCode", None) is not None:
                    prepared["errorCode"] = log.get("errorCode", None)
                if log.get("details", None) is not None:
                    prepared["details"] = log.get("details", None)
                if log.get("resolution", None) is not None:
                    prepared["resolution"] = log.get("resolution", None)
                logs_list.append(prepared)
                count += 1
                if len(logs_list) >= LOG_BATCH_SIZE:
                    yield logs_list
                    logs_list = []
            except Exception as ex:
                self.logger.error(
                    f"Error occurred while getting logs from Netskope CE: {repr(ex)}",
                    error_code="CE_1117",
                )
        if len(logs_list) > 0:
            yield logs_list
        self.logger.info(
            f"{self.log_prefix}: Pulled {count} log(s) "
            f"from window {start_time} UTC to {end_time} UTC."
        )

    def validate(self, configuration: dict) -> ValidationResult:
        """Validate the configuration parameters dict."""
        if len(configuration["logs_type"]) == 0:
            return ValidationResult(
                success=False,
                message="Log Type(s) should not be empty."
            )
        try:
            if (
                "days" not in configuration
                or configuration["days"] is None
                or int(configuration["days"]) < 0
                or int(configuration["days"]) > 365
            ):
                self.logger.info(
                    f"{self.log_prefix}: Validation error occured Error: Invalid days provided."
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
        return ValidationResult(success=True, message="Validation successful.")

    def chunk_size(self) -> int:
        """Define the chunk size of data to be pushed in one go. Each plugin must implement this method."""
        return 2000
