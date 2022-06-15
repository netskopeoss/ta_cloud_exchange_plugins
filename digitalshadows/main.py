"""Digital shadows plugin."""
import requests
from requests.auth import HTTPBasicAuth
from datetime import datetime
import urllib.parse
import re

import requests.exceptions
from netskope.integrations.cte.plugin_base import PluginBase, ValidationResult
from netskope.integrations.cte.models import (
    Indicator,
    IndicatorType,
    SeverityType,
)

# BASE_URL = "https://api.searchlight.app/v1"

DIGITAL_SHADOWS_TO_SEVERITY = {
    "none": SeverityType.LOW,
    "very-low": SeverityType.LOW,
    "low": SeverityType.LOW,
    "medium": SeverityType.MEDIUM,
    "high": SeverityType.HIGH,
    "very-high": SeverityType.CRITICAL,
}


class DigitalShadowsImpersonatingDomains(PluginBase):
    """DigitalShadows Class."""

    def _str_to_datetime(self, string: str) -> datetime:
        """Convert ISO formatted string to datetime object."""
        try:
            return datetime.strptime(
                string.replace(".", ""), "%Y-%m-%dT%H:%M:%S%fZ"
            )
        except Exception:
            return datetime.now()

    def _validate_credentials(self, configuration: dict) -> ValidationResult:
        url = "https://api.searchlight.app/v1/triage-item-events"
        try:
            response = requests.get(
                url=url,
                auth=HTTPBasicAuth(
                    f"{configuration['api_key']}",
                    f"{configuration['api_secret']}",
                ),
                headers={
                    "Content-Type": "application/json",
                    "searchlight-account-id": f"{configuration['searchlight_account_id']}",
                },
                proxies=self.proxy
            )
            if response.status_code == 200:
                return ValidationResult(
                    success=True, message="Validation successful."
                )
            elif response.status_code == 401:
                return ValidationResult(
                    success=False,
                    message="Incorrect API Key, API Secret, or Searchlight Account ID",
                )
            elif response.status_code == 403:
                return ValidationResult(
                    success=False,
                    message="Access Denied. Please confirm your API credentials grant you "
                    "access to the requested data.",
                )
            elif response.status_code == 500:
                return ValidationResult(
                    success=False,
                    message="Server-Side problem that likely requires support intervention to resolve. "
                    "Please contact Digital Shadows support",
                )
            elif response.status_code == 503:
                return ValidationResult(
                    success=False,
                    message="Temporary server-side issue. Please try again in a few minutes.",
                )
            else:
                return ValidationResult(
                    success=False,
                    message=(
                        f"HTTP error occurred while validating configuration "
                        f"parameters. Status code {response.status_code}."
                    ),
                )
        except Exception as ex:
            self.logger.error(repr(ex))
            return ValidationResult(
                success=False,
                message="Error occurred while validating configuration parameters. Check logs for more details",
            )

    def get_triage_item_ids(self, headers):
        """Get triage item ids."""
        var_continue = True
        triage_item_id_list = []
        event_num = 0
        param = {}
        try:
            if self.last_run_at:
                last_run_time = self.last_run_at
                last_run_time = last_run_time.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
                last_run_time = urllib.parse.quote(last_run_time)
                url = (
                        f"https://api.searchlight.app/v1/triage-item-events?" \
                        f"classification=impersonating-domain-alert&" \
                        f"classification=impersonating-subdomain-alert&" \
                        f"classification=phishing-site-alert&" \
                        f"limit=1000&" \
                        f"event-created-after={last_run_time}&"
                    )
            else:
                url = (
                        "https://api.searchlight.app/v1/triage-item-events?"
                        "classification=impersonating-domain-alert&"
                        "classification=impersonating-subdomain-alert&"
                        "classification=phishing-site-alert&"
                        "limit=1000&"
                    )
            while var_continue:
                param["event-num-after"] = event_num
                response = requests.get(
                    url,
                    auth=HTTPBasicAuth(
                        self.configuration["api_key"],
                        self.configuration["api_secret"],
                    ),
                    headers=headers,
                    params=param,
                    proxies=self.proxy
                )

                if response.status_code != 200:
                    self.logger.error(
                        f"Could not capture triage-item-events. Status Code: {response.status_code}"
                    )
                    raise
                results = response.json()

                for event in results:
                    if event["event-action"] == "create":
                        triage_item_id = event["triage-item-id"]
                        triage_item_id_list.append(triage_item_id)
                    event_num = event["event-num"]

                if len(results) % 1000 != 0 or len(results) == 0:
                    var_continue = False

            return triage_item_id_list
        except Exception as ex:
            self.logger.error(repr(ex))
            return ValidationResult(
                success=False,
                message="Error occurred while getting triage-item-ids. Check logs for more details",
            )

    def get_alert_ids(self, triage_item_ids, headers):
        """Get alert ids."""
        var_continue = True
        total_items = 0

        impersonating_domain_alert_list = []
        impersonating_subdomain_alert_list = []
        phishing_site_alert_list = []
        try:
            while var_continue:
                item_count = 0
                triage_items_string = ""
                list_length = len(triage_item_ids)

                if list_length < 100:
                    for i in range(list_length):
                        if i == (list_length - 1):
                            triage_items_string = (
                                f"{triage_items_string}id={triage_item_ids[i]}"
                            )
                        else:
                            triage_items_string = f"{triage_items_string}id={triage_item_ids[i]}&"
                        item_count += 1
                else:
                    for i in range(100):
                        if i == 99:
                            triage_items_string = (
                                f"{triage_items_string}id={triage_item_ids[i]}"
                            )
                        else:
                            triage_items_string = f"{triage_items_string}id={triage_item_ids[i]}&"
                        item_count += 1

                total_items += item_count

                if triage_items_string != "":

                    url = f"https://api.searchlight.app/v1/triage-items?{triage_items_string}"

                    response = requests.get(
                        url,
                        auth=HTTPBasicAuth(
                            self.configuration["api_key"],
                            self.configuration["api_secret"],
                        ),
                        headers=headers,
                        proxies=self.proxy
                    )

                    if response.status_code != 200:
                        self.logger.error(
                            f"Could not capture triage items. Status Code: {response.status_code}"
                        )
                        raise

                    results = response.json()

                    for item in results:
                        alert_id = item["source"]["alert-id"]

                        if (
                            item["classification"]
                            == "impersonating-domain-alert"
                        ):
                            impersonating_domain_alert_list.append(alert_id)
                        elif (
                            item["classification"]
                            == "impersonating-subdomain-alert"
                        ):
                            impersonating_subdomain_alert_list.append(alert_id)
                        elif item["classification"] == "phishing-site-alert":
                            phishing_site_alert_list.append(alert_id)
                        else:
                            self.logger.info(
                                "Invalid item classification found"
                            )
                    for i in sorted(range(item_count), reverse=True):
                        del triage_item_ids[i]

                if item_count != 100:
                    var_continue = False

            return (
                impersonating_domain_alert_list,
                impersonating_subdomain_alert_list,
                phishing_site_alert_list,
            )

        except Exception as ex:
            self.logger.error(repr(ex))
            return ValidationResult(
                success=False,
                message="Error occurred while getting alert ids. Check logs for more details",
            )

    def get_indicator_json(self, alert_ids_list, headers, endpoint):
        """Get indicator json from alerts."""
        results = []
        var_continue = True
        try:
            while var_continue:
                alert_count = 0
                list_length = len(alert_ids_list)
                alert_id_string = ""

                if list_length < 100:
                    for i in range(list_length):
                        if alert_ids_list[i] is not None:
                            if i == (list_length - 1):
                                alert_id_string = (
                                    f"{alert_id_string}id={alert_ids_list[i]}"
                                )
                            else:
                                alert_id_string = (
                                    f"{alert_id_string}id={alert_ids_list[i]}&"
                                )
                            alert_count += 1
                else:
                    for i in range(100):
                        if alert_ids_list[i] is not None:
                            if i == 99:
                                alert_id_string = (
                                    f"{alert_id_string}id={alert_ids_list[i]}"
                                )
                            else:
                                alert_id_string = (
                                    f"{alert_id_string}id={alert_ids_list[i]}&"
                                )
                            alert_count += 1

                if alert_id_string and alert_id_string != "":
                    url = f"https://api.searchlight.app/v1/{endpoint}?{alert_id_string}"

                    response = requests.get(
                        url,
                        auth=HTTPBasicAuth(
                            self.configuration["api_key"],
                            self.configuration["api_secret"],
                        ),
                        headers=headers,
                        proxies=self.proxy
                    )

                    if response.status_code != 200:
                        self.logger.error(
                            f"Could not capture data from the {endpoint} endpoint. Status Code: {response.status_code}"
                        )
                        raise
                    data = response.json()
                    results.extend(data)

                for i in sorted(range(alert_count), reverse=True):
                    del alert_ids_list[i]

                for alert in alert_ids_list:
                    if alert is None:
                        del alert_ids_list[alert]

                if alert_count != 100:
                    var_continue = False

            return results

        except Exception as ex:
            self.logger.error(repr(ex))
            return ValidationResult(
                success=False,
                message="Error occurred while getting indicator JSON. Check logs for more details",
            )

    def get_ioc_indicators(self, alert_json):
        """Get ioc indicators."""
        indicator_list = []

        try:
            for alert in alert_json:
                time_raised = alert["raised"]
                time_raised.replace(".", ""), "%Y-%m-%dT%H:%M:%S%fZ"

                time_updated = alert["updated"]
                time_updated.replace(".", ""), "%Y-%m-%dT%H:%M:%S%fZ"

                risk_level = alert["risk-assessment"]["risk-level"]

                if alert["classification"] == "phishing-site-alert":
                    description = alert["description"]
                    reg_next_link = re.search(
                        r"Phishing\sWebpage:\s+(?P<domains>.*)\n", description
                    )
                    value = reg_next_link.group("domains")
                else:
                    value = alert["domain"]

                indicator_list.append(
                    Indicator(
                        value=value,
                        type=IndicatorType.URL,
                        firstSeen=time_raised,
                        lastSeen=time_updated,
                        comments=f"{alert['classification']} | {alert['risk-factors']}",
                        severity=DIGITAL_SHADOWS_TO_SEVERITY[risk_level],
                        extendedInformation=f"https://portal-digitalshadows.com/triage/alerts/{alert['portal-id']}",
                    )
                )

            return indicator_list
        except Exception as ex:
            self.logger.error(repr(ex))
            return ValidationResult(
                success=False,
                message="Error occurred while getting ioc indicators. Check logs for more details",
            )

    def pull(self):
        """Pull domains from Digital Shadows."""
        try:
            headers = {
                "Content-Type": "application/json",
                "searchlight-account-id": f"{self.configuration['searchlight_account_id']}",
            }

            triage_item_ids = self.get_triage_item_ids(headers)
            (
                domain_alert_ids,
                subdomain_alert_ids,
                phishing_alert_ids,
            ) = self.get_alert_ids(triage_item_ids, headers)

            domain_alerts_json = self.get_indicator_json(
                domain_alert_ids, headers, "impersonating-domain-alerts"
            )

            subdomain_alerts_json = self.get_indicator_json(
                subdomain_alert_ids, headers, "impersonating-subdomain-alerts"
            )
            phishing_alerts_json = self.get_indicator_json(
                phishing_alert_ids, headers, "alerts"
            )

            all_alerts_json = []
            all_alerts_json.extend(domain_alerts_json)
            all_alerts_json.extend(subdomain_alerts_json)
            all_alerts_json.extend(phishing_alerts_json)

            return self.get_ioc_indicators(all_alerts_json)

        except requests.exceptions.ConnectionError as err:
            self.notifier.error(
                "Plugin: Digital Shadows unable to establish connection with Digital Shadows platform. "
                "Searchlight API is not reachable."
            )
            self.logger.error(
                "Plugin: Digital Shadows unable to establish connection with Digital Shadows platform. "
                "Searchlight API is not reachable."
            )
            raise requests.HTTPError(
                "Plugin: Digital Shadows unable to establish connection with Digital Shadows platform. "
                "Searchlight API is not reachable."
            ) from err
        except requests.exceptions.RequestException as e:
            self.logger.error(
                "Plugin: Digital Shadows"
                "Exception occurred while making an API call to Digital Shadows platform"
            )
            raise e

    def validate(self, configuration):
        """Validate the configuration."""
        if (
            "api_key" not in configuration
            or type(configuration["api_key"]) != str
            or not configuration["api_key"].strip()
        ):
            self.logger.error(
                "Digital Shadows Plugin: No api_key found in the configuration parameters."
            )
            return ValidationResult(
                success=False, message="Invalid API Key provided."
            )

        if (
            "api_secret" not in configuration
            or type(configuration["api_secret"]) != str
            or not configuration["api_secret"].strip()
        ):
            self.logger.error(
                "Digital Shadows Plugin: No api_secret found in the configuration"
            )
            return ValidationResult(
                success=False, message="Invalid API Secret provided."
            )

        if (
            "searchlight_account_id" not in configuration
            or type(configuration["searchlight_account_id"]) != str
            or not configuration["searchlight_account_id"].strip()
        ):
            self.logger.error(
                "Digital Shadows Plugin: No searchlight_account_id found in the configuration"
            )
            return ValidationResult(
                success=False,
                message="Invalid Searchlight Account ID provided.",
            )

        return self._validate_credentials(configuration)
