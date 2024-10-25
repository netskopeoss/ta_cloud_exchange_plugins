"""Webtx metrics collector."""
import time
import traceback
import requests
from netskope.common.utils import Logger, add_user_agent, resolve_secret
from netskope.common.utils.plugin_provider_helper import PluginProviderHelper

HOURS = 168
WEBTX_METRICS_URL = "{}/api/v2/events/metrics/transactionevents"
logger = Logger()
plugin_provider_helper = PluginProviderHelper()


def covert_message_age_to_minutes(message_age) -> int:
    """Convert message age to minutes."""
    try:
        if isinstance(message_age, int):
            return message_age
        hour, minute = map(int, message_age.replace("hours","").replace("minutes","").split(","))
        return hour * 60 + minute
    except ValueError:
        return 0


def convert_webtx_metrics_data(log_prefix, data: dict) -> dict:
    """Convert webtx metrics data."""
    try:
        if not data.get("result"):
            return {}
        result = data["result"]
        if not ("subscription/backlog_message_count" in result and
            "subscription/oldest_unacked_message_age" in result):
            return {}
        result_backlog_message_count = []
        result_oldest_unacked_message_age = []
        latest_utc_hour = None
        backlog_message_count = result["subscription/backlog_message_count"]
        oldest_unacked_message_age = result["subscription/oldest_unacked_message_age"]
        subscription_name = list(backlog_message_count.keys())[0]
        subscription_path = subscription_name.replace("subscription_name:","").strip()
        partition_num = list(backlog_message_count[subscription_name].keys())[0]
        backlog_message_count_data = backlog_message_count[subscription_name][partition_num]
        for oldest_unacked_message_age_data in oldest_unacked_message_age[subscription_name].values():
            for key in oldest_unacked_message_age_data:
                oldest_unacked_message_age_data[key] = covert_message_age_to_minutes(oldest_unacked_message_age_data[key])
        for partition, backlog_message_count_data in backlog_message_count[subscription_name].items():
            backlog_message_count_lst = []
            for key, value in backlog_message_count_data.items():
                backlog_message_count_lst.append({
                    "at": key,
                    "value": value
                })
                if not latest_utc_hour:
                    latest_utc_hour = key
            result_backlog_message_count.append({"name": partition, "data": backlog_message_count_lst})
        for partition, oldest_unacked_message_age_data in oldest_unacked_message_age[subscription_name].items():
            oldest_unacked_message_age_lst = []
            for key, value in oldest_unacked_message_age_data.items():
                oldest_unacked_message_age_lst.append({
                    "at": key,
                    "value": value
                })
            result_oldest_unacked_message_age.append({"name": partition, "data": oldest_unacked_message_age_lst})
        return {
            "backlog_message_count": result_backlog_message_count,
            "oldest_unacked_message_age": result_oldest_unacked_message_age,
            "subscription_path": subscription_path,
            "latest_utc_hour": latest_utc_hour
        }
    except Exception as e:
        logger.error(
            f"{log_prefix} : Failed to convert webtx metrics data, {e}", 
            error_code="CE_1138", 
            details=traceback.format_exc()
        )
        return {}


def get_webtx_metrics_data(log_prefix, tenant_name: str, v2token: str, proxies = None, retry=True) -> dict:
    """Get webtx metrics data."""
    try:
        url = WEBTX_METRICS_URL.format(tenant_name)
        headers = {
            "Netskope-Api-Token": resolve_secret(v2token),
            **add_user_agent()
        }
        response = requests.get(url, headers=headers, params={"hours": HOURS}, proxies=proxies)
        if response.status_code == 200:
            metrics_data = convert_webtx_metrics_data(log_prefix, response.json())
            return metrics_data, response.status_code
        elif response.status_code == 429 and retry:
            time.sleep(1)
            return get_webtx_metrics_data(log_prefix, tenant_name, v2token, proxies=proxies, retry=False)
        else:
            logger.error(
                f"{log_prefix} : Failed to get webtx metrics data, {response.status_code} - {response.text}",
                error_code="CE_1136",
                details=f"For URL: {url}\nError: {response.text}"
            )
            return {}, response.status_code
    except Exception as e:
        logger.error(
            f"{log_prefix} : Failed to get webtx metrics data, {e}",
            error_code="CE_1137",
            details=traceback.format_exc()
        )
        return {}, 500
