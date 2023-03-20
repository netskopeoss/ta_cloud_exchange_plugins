import os
from datetime import datetime
import shutil
import gzip
import json
import time
import requests
from tempfile import NamedTemporaryFile

import requests.exceptions
from netskope.integrations.cte.plugin_base import (
    PluginBase,
    ValidationResult
)

from netskope.integrations.cte.models import (
    Indicator,
    IndicatorType,
    SeverityType
)

SECLYTICS_TO_IOC_TYPE = {
    'md5': IndicatorType.MD5,
    'sha256': IndicatorType.SHA256,
    'url': IndicatorType.URL,
    'ip': IndicatorType.URL,
    'cidr': IndicatorType.URL
}

PLUGIN_NAME = "CTE SecLytics Plugin:"

BASE_URL = "https://api.seclytics.com/bulk"


class Seclytics(PluginBase):

    def handle_error(self, response):
        if response.status_code == 200:
            try:
                return response.content
            except ValueError:
                err_msg = "Exception occurred while parsing JSON response"
                self.logger.error(
                    f"{PLUGIN_NAME} {err_msg}"
                )
                raise Exception(err_msg)
        
        try:
            resp_json = response.json()
            resp_err_msg = f"Error: {resp_json.get('error', {}).get('message', 'No error message found')}"
        except:
            resp_err_msg = "Error: No error message found."
        if response.status_code == 401:
            err_msg = "Received exit code 401, Authentication Error"
            self.logger.error(
                f"{PLUGIN_NAME} {err_msg}. {resp_err_msg}"
            )
            raise Exception(err_msg)
        elif response.status_code == 404:
            err_msg = "Received exit code 404, Resource Not Found"
            self.logger.error(
                f"{PLUGIN_NAME} {err_msg}. {resp_err_msg}"
            )
            raise Exception(err_msg)
        elif 400 <= response.status_code < 500:
            err_msg = f"Received exit code {response.status_code}, HTTP Client Error"
            self.logger.error(
                f"{PLUGIN_NAME} {err_msg}. {resp_err_msg}"
            )
            raise Exception(err_msg)
        elif 500 <= response.status_code < 600:
            err_msg = f"Received exit code {response.status_code}, HTTP Server Error"
            self.logger.error(
                f"{PLUGIN_NAME} {err_msg}. {resp_err_msg}"
            )
            raise Exception(err_msg)
        else:
            err_msg = f"Received exit code {response.status_code}, HTTP Error"
            self.logger.error(
                f"{PLUGIN_NAME} {err_msg}. {resp_err_msg}"
            )
            raise Exception(err_msg)

    def _validate_credentials(self, configuration: dict) -> ValidationResult:
        if configuration.get('custom_endpoint'):
            url = f"{BASE_URL}/{configuration.get('custom_endpoint').strip()}"
        else:
            threat_data_types = configuration.get('threat_data_type', [])

            if 'url' in threat_data_types:
                file_base = f"url-dump-c"
            elif 'ip' in threat_data_types or 'cidr' in threat_data_types:  # for ip or cidr
                file_base = "seen-predictions-dump-a"
            else:
                return ValidationResult(
                    success=False,
                    message="Invalid threat data type found"
                )

            url = f"{BASE_URL}/{file_base}.json.gz"

        body = {
            'access_token': configuration.get('access_token')
        }

        try:
            response = requests.get(
                url=url,
                params=body,
                verify=self.ssl_validation,
                proxies=self.proxy
            )
            ioc_file = self.handle_error(response)
            try:
                temp_archive_file = NamedTemporaryFile("wb", delete=False)
                temp_archive_file.write(ioc_file)
                temp_archive_file.seek(0)

                temp_json_file = NamedTemporaryFile("wb", delete=False)

                with gzip.open(temp_archive_file.name, 'rb') as f_in:
                    with temp_json_file as f_out:
                        shutil.copyfileobj(f_in, f_out)

                temp_archive_file.close()
                os.unlink(temp_archive_file.name)

                with open(temp_json_file.name) as f:
                    data = [next(f) for _ in range(1)]
                    
                if data:
                    _ = json.loads(data[0])
                
                temp_json_file.close()
                os.unlink(temp_json_file.name)
                
                return ValidationResult(
                    success=True,
                    message='Successfully validated credentials to SecLytics'
                )
            except Exception as e:
                err_msg = 'Error occurred while parsing the bulk endpoint. We only support json formatted bulk endpoints.'
                self.logger.error(
                    f"{PLUGIN_NAME} {err_msg}. Exception: {e}"
                )
                return ValidationResult(
                    success=False,
                    message=err_msg,
                )
        except requests.exceptions.ProxyError as e:
            err_msg = "Validation error, Invalid proxy configuration."
            self.logger.error(
                f"{PLUGIN_NAME} {err_msg}. Exception: {e}"
            )
            return ValidationResult(
                success=False,
                message=err_msg
            )
        except requests.exceptions.ConnectionError as e:
            err_msg = "Validation Error, Unable to establish connection to SecLytics BulkAPI."
            self.logger.error(
                f"{PLUGIN_NAME} {err_msg}. Exception: {e}"
            )
            return ValidationResult(
                success=False,
                message=err_msg
            )
        except Exception as exp:
            self.logger.error(
                f"{PLUGIN_NAME} Validation Error. "
                f"Exception: {exp}"
            )
            return ValidationResult(
                success=False,
                message="Validation Error. Please check logs for more details"
            )

    def get_ioc_file(self, indicator_type, custom_path=None):
        if custom_path:
            url = f"{BASE_URL}/{custom_path}"
        else:
            if indicator_type == 'url':
                url = f"{BASE_URL}/url-dump-c.json.gz"
            else:  # for ip or cidr
                url = f"{BASE_URL}/seen-predictions-dump-a.json.gz"

        body = {
            'access_token': self.configuration.get('access_token')
        }

        try:
            response = requests.get(
                url=url,
                params=body,
                verify=self.ssl_validation,
                proxies=self.proxy
            )
            try:
                bulk_file = self.handle_error(response)
                
                temp_archive_file = NamedTemporaryFile("wb", delete=False)
                temp_archive_file.write(bulk_file)
                temp_archive_file.seek(0)

                temp_json_file = NamedTemporaryFile("wb", delete=False)

                with gzip.open(temp_archive_file.name, 'rb') as f_in:
                    with temp_json_file as f_out:
                        shutil.copyfileobj(f_in, f_out)

                temp_archive_file.close()
                os.unlink(temp_archive_file.name)

                return temp_json_file
            except Exception as e:
                raise e

        except requests.exceptions.ProxyError as e:
            err_msg = "Invalid proxy configuration."
            self.logger.error(
                f"{PLUGIN_NAME} {err_msg}. Exception: {e}"
            )
            raise e
        except requests.exceptions.ConnectionError as e:
            err_msg = "Unable to establish connection to SecLytics BulkAPI."
            self.logger.error(
                f"{PLUGIN_NAME} {err_msg} Exception: {e}"
            )
            raise e
        except Exception as exp:
            self.logger.error(
                f"{PLUGIN_NAME} Validation Error. "
                f"Exception: {exp}"
            )
            raise exp

    def sort_and_filter_indicators(self, indicator_type, data):

        def sort_by_date(ioc_objects):
            ioc_objects = json.loads(ioc_objects)
            return ioc_objects.get('last_seen_at')

        ioc_list = []  # the set of indicators to be sent to CE

        data.sort(key=sort_by_date, reverse=True)

        try:
            if self.last_run_at:
                last_run_time = self.last_run_at
                last_run_time = last_run_time.strftime("%Y-%m-%dT%H:%M:%SfZ")
                target_timestamp = time.mktime(
                    datetime.strptime(last_run_time, "%Y-%m-%dT%H:%M:%SfZ").timetuple())
            else:
                current_timestamp = int(time.time())
                target_timestamp = current_timestamp - (self.configuration['lookback'] * 86400)

            for ioc in data:
                ioc_object = json.loads(ioc)
                ioc_last_seen = ioc_object.get('last_seen_at')

                last_seen_as_timestamp = time.mktime(
                    datetime.strptime(ioc_last_seen, "%Y-%m-%dT%H:%M:%S").timetuple())

                if last_seen_as_timestamp > target_timestamp:
                    if 'url' in indicator_type:
                        indicator = self.get_url_indicator(ioc_object)
                        if indicator:
                            ioc_list.append(indicator)

                    if 'ip' in indicator_type:
                        if 0 <= int(ioc_object['importance']) < 30:
                            severity = "low"
                        elif 30 <= int(ioc_object['importance']) < 69:
                            severity = "medium"
                        else:
                            severity = "high"

                        if severity in self.configuration.get('severity'):
                            indicator = self.get_ip_indicator(ioc_object)
                            if indicator:
                                ioc_list.append(indicator)

                    if 'cidr' in indicator_type:
                        indicator = self.get_cidr_indicator(ioc_object)
                        if indicator:
                            ioc_list.append(indicator)
                else:
                    break

            return ioc_list

        except Exception as e:
            self.logger.error(f"{PLUGIN_NAME} Error while sorting and filtering indicators: {e}")
            raise e

    def get_url_indicator(self, url_ioc):
        """Convert URLs into CE Indicators"""

        if url_ioc.get('url'):
            indicator = Indicator(
                value=url_ioc['url'],
                type=IndicatorType.URL,
                severity=SeverityType.UNKNOWN,
                firstSeen=url_ioc.get('first_seen_at'),
                lastSeen=url_ioc.get('last_seen_at'),
                comments=f"Categories: {', '.join(url_ioc.get('categories'))}" if url_ioc.get('categories') else ""
            )

            return indicator

    def get_ip_indicator(self, ip_ioc):
        """Convert IPs into CE Indicators"""

        if isinstance(ip_ioc.get('importance'), int):
            if 0 <= int(ip_ioc.get('importance')) < 30:
                ip_severity = SeverityType.LOW
            elif 30 <= int(ip_ioc.get('importance')) < 69:
                ip_severity = SeverityType.MEDIUM
            else:
                ip_severity = SeverityType.HIGH
        else:
            ip_severity = SeverityType.UNKNOWN

        if ip_ioc.get('ip'):
            indicator = Indicator(
                value=ip_ioc['ip'],
                type=IndicatorType.URL,
                severity=ip_severity,
                firstSeen=ip_ioc.get('detected_at'),
                lastSeen=ip_ioc.get('last_seen_at'),
                comments=f"Categories: {', '.join(ip_ioc.get('detected_categories'))}" if ip_ioc.get('detected_categories') else ""
            )

            return indicator

    def get_cidr_indicator(self, cidr_ioc):
        """Covert CIDRs into CE Indicators"""

        if cidr_ioc.get("predicted_netblock"):
            indicator = Indicator(
                value=cidr_ioc['predicted_netblock'],
                type=IndicatorType.URL,
                severity=SeverityType.UNKNOWN,
                firstSeen=cidr_ioc.get('detected_at'),
                lastSeen=cidr_ioc.get('last_seen_at'),
                comments=f"Categories: {', '.join(cidr_ioc.get('detected_categories'))}" if cidr_ioc.get('detected_categories') else ""
            )

            return indicator

    def pull(self):
        """Pull indicators from SecLytics"""

        config = self.configuration

        self.logger.info(f"{PLUGIN_NAME} Enabled")

        indicator_list = []

        if config.get('custom_endpoint'):
            custom_path = config.get('custom_endpoint')
            try:
                ioc_file = self.get_ioc_file(config.get('threat_data_type')[0], custom_path)
                with open(ioc_file.name) as f:
                    data = f.readlines()
                    
                ioc_types = config.get('threat_data_type', [])

                ioc_list = self.sort_and_filter_indicators(ioc_types, data)
                indicator_list.extend(ioc_list)

                ioc_file.close()
                os.unlink(ioc_file.name)

            except requests.exceptions.RequestException as e:
                self.logger.error(
                    f"{PLUGIN_NAME}"
                    " Exception occurred while making an API call to SecLytics custom endpoint."
                    f" Exception: {e}"
                )
                raise e
            except Exception as e:
                self.logger.error(
                    f"{PLUGIN_NAME}"
                    " Exception occurred while making an API call to SecLytics custom endpoint."
                    f" Exception: {e}"
                )
                raise e
        else:
            try:
                for ioc_type in config.get('threat_data_type', []):

                    ioc_file = self.get_ioc_file(ioc_type)

                    with open(ioc_file.name) as f:
                        data = f.readlines()

                    ioc_list = self.sort_and_filter_indicators([ioc_type], data)
                    indicator_list.extend(ioc_list)

                    ioc_file.close()
                    os.unlink(ioc_file.name)

            except requests.exceptions.RequestException as e:
                self.logger.error(
                    f"{PLUGIN_NAME}"
                    " Exception occurred while making an API call to SecLytics."
                    f"Exception: {e}"
                )
                raise e
            except Exception as e:
                self.logger.error(
                    f"{PLUGIN_NAME}"
                    " Exception occurred while making an API call to SecLytics custom endpoint."
                    f" Exception: {e}"
                )
                raise e

        return indicator_list

    def validate(self, configuration):
        """Validate the configuration"""
        if (
            "threat_data_type" not in configuration
            or not configuration.get('threat_data_type')
            or not set(configuration.get('threat_data_type')) & set([
                "url",
                "ip",
                "cidr"
            ])
        ):
            self.logger.error(
                f"{PLUGIN_NAME} No threat data type for the custom/default endpoint found in the configuration parameters."
            )
            return ValidationResult(
                success=False, message="threat data type(s) not provided."
            )

        if (
            "access_token" not in configuration
            or type(configuration.get('access_token')) != str
            or not configuration.get('access_token')
        ):
            self.logger.error(
                f"{PLUGIN_NAME} No access token found in the configuration."
            )
            return ValidationResult(
                success=False,
                message="Invalid Access Token provided."
            )

        if "ip" in configuration.get('threat_data_type'):
            if (
                "severity" not in configuration
                or not configuration.get('severity')
            ):
                self.logger.error(
                    f"{PLUGIN_NAME} IP indicators selected but no severity chosen."
                )
                return ValidationResult(
                    success=False,
                    message="No severity provided."
                )
        try:
            if (
                "lookback" not in configuration
                or not configuration["lookback"]
                or int(configuration["lookback"]) <= 0
            ):
                self.logger.error(
                    f"{PLUGIN_NAME} Validation error occured Error: Invalid days provided."
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

        return self._validate_credentials(configuration)
