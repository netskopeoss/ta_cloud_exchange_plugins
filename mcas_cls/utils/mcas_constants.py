"""MCAS Constants."""
SEVERITY_LOW = 'Low'
SEVERITY_MEDIUM = 'Medium'
SEVERITY_HIGH = 'High'
SEVERITY_VERY_HIGH = 'Very-High'
SEVERITY_UNKNOWN = 'Unknown'

SEVERITY_MAP = {
    'low': SEVERITY_LOW,
    'med': SEVERITY_MEDIUM,
    'medium': SEVERITY_MEDIUM,
    'high': SEVERITY_HIGH,
    'very-high': SEVERITY_VERY_HIGH,
    'critical': SEVERITY_VERY_HIGH,
    '0': SEVERITY_LOW,
    '1': SEVERITY_LOW,
    '2': SEVERITY_LOW,
    '3': SEVERITY_LOW,
    '4': SEVERITY_MEDIUM,
    '5': SEVERITY_MEDIUM,
    '6': SEVERITY_MEDIUM,
    '7': SEVERITY_HIGH,
    '8': SEVERITY_HIGH,
    '9': SEVERITY_VERY_HIGH,
    '10': SEVERITY_VERY_HIGH
}

API_GET_URL = "https://{}/api/v1/discovery/upload_url/"
API_POST_URL = "https://{}/api/v1/discovery/done_upload/"
MAX_RETRIES = 3
RETRY_SLEEP_TIME = 60
DATAFILE = '{}-ingestion_file.txt'
