"""CE Logs ITSM plugin."""

from typing import List

from netskope.common.utils import DBConnector, Collections
from netskope.integrations.itsm.plugin_base import PluginBase, ValidationResult
from netskope.integrations.itsm.models import Alert


connector = DBConnector()


class CELogsPlugin(PluginBase):
    """CE Logs plugin implementation."""

    def _validate_params(self, configuration):
        return ValidationResult(success=True, message="Validation successful.")

    def validate_step(self, name, configuration):
        """Validate a given step."""
        return ValidationResult(success=True, message="Validation successful.")

    def pull_alerts(self) -> List[Alert]:
        """Pull alerts from the Netskope platform."""
        alerts = []
        query = {}
        query["$and"] = [
            {"type": {"$in": self.configuration["params"]["logs_type"]}}
        ]
        if self.last_run_at is not None:
            query["$and"].append({"createdAt": {"$gte": self.last_run_at}})
        logs = connector.collection(Collections.LOGS).find(query)
        for log in logs:
            try:
                alerts.append(
                    Alert(
                        id=str(log["_id"]),
                        alertName="CE Log",
                        alertType="Log",
                        app="Cloud Exchange",
                        appCategory="CE",
                        type=log["type"],
                        user="",
                        timestamp=log["createdAt"],
                        rawAlert={"message": log["message"]},
                    )
                )
            except KeyError as ex:
                self.logger.error(
                    f"Error occurred while getting fields from alert with id={str(log.get('_id'))}. {repr(ex)}"
                )
        return alerts
