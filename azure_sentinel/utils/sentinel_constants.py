"""Provides constants for Azure Sentinel plugin."""

HTTP_METHOD = "POST"
CONTENT_TYPE = "application/json"
RESOURCE = "/api/logs"
API_BASE_URL = "https://{}.ods.opinsights.azure.com{}?api-version=2016-04-01"
MAX_RETRIES = 3
RETRY_SLEEP_TIME = 60
attribute_dtype_map = {
    "dlp_incident_id": "string",
    "app_session_id": "string",
    "transaction_id": "string",
    "md5": "string",
    "request_id": "string",
    "browser_session_id": "string",
    "page_id": "string",
    "dlp_parent_id": "string",
    "timestamp": "datetime",
    "_insertion_epoch_timestamp": "datetime",
    "bin_timestamp": "datetime",
    "last_timestamp": "datetime",
    "page_starttime": "datetime",
    "page_endtime": "datetime",
    "breach_date": "datetime",
    "suppression_end_time": "datetime",
    "suppression_start_time": "datetime",
    "conn_starttime": "datetime",
    "conn_endtime": "datetime",
    "malsite_first_seen ": "datetime",
    "malsite_last_seen": "datetime",
    "scan_time": "datetime",
    "modified_date": "datetime",
    "created_date": "datetime",
}
