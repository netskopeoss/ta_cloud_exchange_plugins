"""Mandiant Plugin implementation to pull data from Mandiant Platform."""

import datetime
import time
import base64
import traceback
from pydantic import ValidationError
from typing import List, Tuple

from netskope.integrations.cte.plugin_base import (
    PluginBase,
    ValidationResult,
)

from netskope.integrations.cte.utils import TagUtils

from netskope.integrations.cte.models import (
    Indicator,
    IndicatorType,
    SeverityType,
    TagIn,
)
from .utils.mandiant_constants import (
    MODULE_NAME,
    PLUGIN_NAME,
    PLUGIN_VERSION,
    PLATFORM_NAME,
    BASE_URL,
    PAGE_SIZE,
    PAGE_LIMIT,
    DATE_FORMAT_FOR_IOCS,
)
from .utils.mandiant_helper import MandiantPluginException, MandiantPluginHelper

MANDIANT_TO_INTERNAL_TYPE = {
    "md5": IndicatorType.MD5,
    "url": IndicatorType.URL,
    "fqdn": IndicatorType.URL,
    "ipv4": IndicatorType.URL,
    "ipv6": IndicatorType.URL,
}


class MandiantPlugin(PluginBase):
    """MandiantPlugin class for pulling threat information."""

    def __init__(
        self,
        name,
        *args,
        **kwargs,
    ):
        """Initialize Plugin class."""
        super().__init__(
            name,
            *args,
            **kwargs,
        )
        self.plugin_name, self.plugin_version = self._get_plugin_info()
        self.log_prefix = f"{MODULE_NAME} {self.plugin_name}"
        if name:
            self.log_prefix = f"{self.log_prefix} [{name}]"
        self.mandiant_helper = MandiantPluginHelper(
            logger=self.logger,
            log_prefix=self.log_prefix,
            plugin_name=self.plugin_name,
            plugin_version=self.plugin_version,
        )

    def _get_plugin_info(self) -> Tuple:
        """Get plugin name and version from manifest.

        Returns:
            tuple: Tuple of plugin's name and version fetched from manifest.
        """
        try:
            manifest_json = MandiantPlugin.metadata
            plugin_name = manifest_json.get("name", PLUGIN_NAME)
            plugin_version = manifest_json.get("version", PLUGIN_VERSION)
            return plugin_name, plugin_version
        except Exception as exp:
            self.logger.error(
                message=(
                    f"{MODULE_NAME} {PLUGIN_NAME}: Error occurred while"
                    f" getting plugin details. Error: {exp}"
                ),
                details=str(traceback.format_exc()),
            )
        return PLUGIN_NAME, PLUGIN_VERSION

    def get_severity_from_int(self, severity):
        """Get severity from score.

        None (0)
        Low (10-39)
        Medium (40-69)
        High (70-89)
        Critical (90-100)
        """
        if isinstance(severity, int) is False or severity == 0:
            return SeverityType.UNKNOWN
        if 10 <= severity <= 39:
            return SeverityType.LOW
        if 40 <= severity <= 69:
            return SeverityType.MEDIUM
        if 70 <= severity <= 89:
            return SeverityType.HIGH
        if 90 <= severity <= 100:
            return SeverityType.CRITICAL
        return SeverityType.UNKNOWN

    def create_tags(self, tags: List) -> tuple:
        """Create Tags.

        Args:
            tags (List): Tags list from API Response.

        Returns:
            tuple: Tuple of created tags and skipped tags.
        """
        tag_utils = TagUtils()
        created_tags, skipped_tags = set(), set()

        for tag in tags:
            tag_name = tag.strip()
            try:
                if not tag_utils.exists(tag_name):
                    tag_utils.create_tag(TagIn(name=tag_name, color="#ED3347"))
                created_tags.add(tag_name)
            except ValueError:
                skipped_tags.add(tag_name)
            except Exception as exp:
                self.logger.error(
                    message=(
                        "{}: Unexpected error occurred"
                        " while creating tag {}. Error: {}".format(
                            self.log_prefix_with_name, tag_name, exp
                        )
                    ),
                    details=str(traceback.format_exc()),
                )
                skipped_tags.add(tag_name)

        return list(created_tags), list(skipped_tags)

    def convert_into_date_time(self, date: str):
        """Convert str to datetime object.

        Args:
            date (str): str.

        Returns:
            datetime: datetime object.
        """
        try:
            return (
                datetime.datetime.strptime(date, DATE_FORMAT_FOR_IOCS) if date else None
            )
        except Exception:
            return None

    def get_indicators(self, headers):
        """
        Get the indicators from Mandiant platform.

        Args:
            headers(obj): headers for API call.
        Returns:
            list: List of indicators.
        """
        indicator_list = []
        total_skipped_tags = set()
        skipped_count = 0
        page_count = 0
        query_endpoint = f"{BASE_URL}/v4/indicator"
        self.logger.info(f"{self.log_prefix}: Pulling indicators from {PLATFORM_NAME}.")

        storage = self.storage if self.storage is not None else {}

        last_updated = storage.get("last_updated", "")
        exclude_osint = self.configuration.get("exclude_osint") == "Yes"
        mscore = self.configuration.get("mscore", 80)
        self.logger.debug(
            f"{self.log_prefix}: Pulling indicators. Filters: mscore: {mscore}"
            f", exclude_osint: {exclude_osint}. Storage: {storage}."
        )

        start_time = None
        if not self.last_run_at:
            start_time = datetime.datetime.now() - datetime.timedelta(
                hours=int(self.configuration["hours"])
            )
        elif last_updated:
            start_time = self.convert_into_date_time(last_updated)
        else:
            start_time = self.last_run_at

        epoch_time = (
            start_time.timestamp() if start_time else self.last_run_at.timestamp()
        )

        current_time = time.time()

        query_params = {
            "start_epoch": int(epoch_time),
            "end_epoch": int(current_time),
            "limit": PAGE_SIZE,
            "gte_mscore": mscore,
            "exclude_osint": exclude_osint,
            "sort_by": "last_updated:asc",
        }
        last_indicator_timestamp = None
        while True:
            try:
                page_count += 1
                current_page_skip_count = 0
                current_extracted_indicators = []
                headers = self.reload_auth_token(headers)

                resp_json = self.mandiant_helper.api_helper(
                    logger_msg=f"pulling indicators for page {page_count}",
                    url=query_endpoint,
                    method="GET",
                    headers=headers,
                    params=query_params,
                    verify=self.ssl_validation,
                    proxies=self.proxy,
                )
                indicators_json_list = resp_json.get("indicators", [])
                for indicator in indicators_json_list:
                    try:
                        last_indicator_timestamp = indicator.get("last_updated")
                        categories = []
                        if self.configuration["enable_tagging"] == "Yes":
                            for source in indicator.get("sources", []):
                                categories += source.get("category", [])

                            for attributed_association in indicator.get(
                                "attributed_associations", []
                            ):
                                if attributed_association.get("type") in [
                                    "malware",
                                    "threat-actor",
                                ]:
                                    categories.append(
                                        attributed_association.get("name")
                                    )

                        if (
                            indicator.get("value")
                            and indicator.get("type")
                            and indicator.get("type")
                            in ["md5", "url", "fqdn", "ipv4", "ipv6"]
                        ):
                            tags, skipped_tags = self.create_tags(categories)
                            total_skipped_tags.update(skipped_tags)

                            current_extracted_indicators.append(
                                Indicator(
                                    value=indicator.get("value").lower(),
                                    type=MANDIANT_TO_INTERNAL_TYPE.get(
                                        indicator.get("type")
                                    ),
                                    firstSeen=self.convert_into_date_time(
                                        indicator.get("first_seen")
                                    ),
                                    lastSeen=self.convert_into_date_time(
                                        indicator.get("last_seen")
                                    ),
                                    severity=self.get_severity_from_int(
                                        indicator.get("mscore", 0)
                                    ),
                                    tags=tags,
                                )
                            )
                        else:
                            current_page_skip_count += 1
                    except (ValidationError, Exception) as error:
                        current_page_skip_count += 1
                        error_message = (
                            "Validation error occurred"
                            if isinstance(error, ValidationError)
                            else "Unexpected error occurred"
                        )
                        self.logger.error(
                            message=(
                                f"{self.log_prefix}: {error_message} while"
                                f" creating indicator. This record "
                                f"will be skipped. Error: {error}."
                            ),
                            details=str(traceback.format_exc()),
                        )

                skipped_count += current_page_skip_count
                indicator_list.extend(current_extracted_indicators)
                self.logger.info(
                    f"{self.log_prefix}: Successfully fetched "
                    f"{len(current_extracted_indicators)} indicator(s) "
                    f"for page {page_count}. Total indicator(s) "
                    f"fetched - {len(indicator_list)}."
                )

                if not resp_json.get("next") or len(indicators_json_list) < PAGE_SIZE:
                    storage.clear()
                    break
                else:
                    query_params = {"next": resp_json.get("next"), "limit": PAGE_SIZE}

                if page_count >= PAGE_LIMIT:
                    storage.clear()
                    if last_indicator_timestamp:
                        storage["last_updated"] = last_indicator_timestamp
                    self.logger.info(
                        f"{self.log_prefix}: Page limit of {PAGE_LIMIT} has "
                        f"reached. Returning {len(indicator_list)} "
                        "indicator(s). The pulling of the indicators will be "
                        "resumed in the next pull cycle."
                    )
                    self.logger.info(
                        f"{self.log_prefix}: Completed fetching indicators for"
                        f" the plugin. Total indicator(s) fetched "
                        f"{len(indicator_list)}, skipped {skipped_count} "
                        f"indicator(s), total {len(total_skipped_tags)} "
                        "tag(s) skipped."
                    )
                    return indicator_list

            except MandiantPluginException as ex:
                storage.clear()
                if last_indicator_timestamp:
                    storage["last_updated"] = last_indicator_timestamp
                err_msg = (
                    f"{self.log_prefix}: Error occurred while executing "
                    "the pull cycle. The pulling of the indicators will be"
                    f" resumed in the next pull cycle. Error: {ex}."
                )
                self.logger.error(
                    message=err_msg, details=(str(traceback.format_exc()))
                )
                break

            except Exception as ex:
                storage.clear()
                if last_indicator_timestamp:
                    storage["last_updated"] = last_indicator_timestamp
                err_msg = (
                    f"{self.log_prefix}: Error occurred while executing "
                    "the pull cycle. The pulling of the indicators will be"
                    f" resumed in the next pull cycle. Error: {ex}."
                )
                self.logger.error(
                    message=err_msg, details=(str(traceback.format_exc()))
                )
                break

        self.logger.info(
            f"{self.log_prefix}: Total indicator(s) fetched "
            f"{len(indicator_list)}, skipped {skipped_count} "
            f"indicator(s), total {len(total_skipped_tags)} "
            "tag(s) skipped."
        )
        if skipped_count > 0:
            self.logger.info(
                f"{self.log_prefix}: Skipped {skipped_count} record(s)"
                " as indicator value might be None or invalid."
            )
        if len(total_skipped_tags) > 0:
            self.logger.info(
                f"{self.log_prefix}: {len(total_skipped_tags)} tag(s) "
                "skipped as they were longer than expected size or due"
                " to some other exceptions that occurred while "
                "creation of them. tags: "
                f"({', '.join(total_skipped_tags)})."
            )
        return indicator_list

    def pull(self):
        """Pull the Threat information from Mandiant platform.

        Returns : List[cte.models.Indicators] :
        List of indicator objects received from the Mandiant platform.
        """
        key_id = self.configuration["key_id"].strip()
        key_secret = self.configuration["key_secret"]

        try:
            auth_json = self.get_auth_json(key_id, key_secret, "pulling indicators")
            auth_token = auth_json.get("access_token")
            if not auth_token:
                raise MandiantPluginException(
                    f"Invalid access token received from {PLATFORM_NAME} platform."
                )
            headers = {
                "accept": "application/json",
                "Authorization": f"Bearer {auth_token}",
                "Content-Type": "application/x-www-form-urlencoded",
            }
            return self.get_indicators(headers)
        except MandiantPluginException as err:
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Error occurred while pulling"
                    f" indicators. Error: {err}"
                ),
                details=str(traceback.format_exc()),
            )
            raise err
        except Exception as exp:
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Error occurred while pulling"
                    f" indicators. Error: {exp}"
                ),
                details=str(traceback.format_exc()),
            )
            raise exp

    def reload_auth_token(self, headers):
        """Reload the access token after Expiry."""
        if (
            self.storage.get("token_expiry", datetime.datetime.now())
            < datetime.datetime.now()
        ):
            self.logger.info(
                f"{self.log_prefix}: Access token is expired. Generating new token."
            )
            auth_json = self.get_auth_json(
                self.configuration.get("key_id"),
                self.configuration.get("key_secret"),
                "re-generating the access token",
            )
            auth_token = auth_json.get("access_token")
            if not auth_token:
                raise MandiantPluginException(
                    f"Invalid access token received from {PLATFORM_NAME} platform."
                )
            headers["Authorization"] = f"Bearer {auth_token}"
        return headers

    def validate(self, data):
        """Validate the Plugin configuration parameters.

        Args:
            data (dict): Dict object having all
            the Plugin configuration parameters.
        Returns:
            cte.plugin_base.ValidateResult:
            ValidateResult object with success flag and message.
        """
        validation_err_msg = f"{self.log_prefix}: Validation error occurred."

        key_id = data.get("key_id", "").strip()
        if not key_id:
            err_msg = "Key ID is a required configuration parameter."
            self.logger.error(f"{validation_err_msg} {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        elif not isinstance(key_id, str):
            err_msg = "Invalid Key ID provided in configuration parameters."
            self.logger.error(f"{validation_err_msg} {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        key_secret = data.get("key_secret", "")
        if not key_secret:
            err_msg = "Key Secret is a required configuration parameter."
            self.logger.error(f"{validation_err_msg} {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        elif not isinstance(key_secret, str):
            err_msg = "Invalid Key Secret provided in configuration parameters."
            self.logger.error(f"{validation_err_msg} {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )

        initial_range = data.get("hours")
        if initial_range is None:
            err_msg = "Initial Range (in hours) is a required configuration parameter."
            self.logger.error(f"{validation_err_msg} {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        if not isinstance(initial_range, int):
            err_msg = (
                "Invalid value provided in Initial Range (in hours) "
                "in configuration parameter. Initial Range (in hours) "
                "should be positive integer value."
            )
            self.logger.error(f"{validation_err_msg} {err_msg}")
            return ValidationResult(success=False, message=err_msg)
        elif not (0 < initial_range <= 24):
            err_msg = (
                "Initial Range(in hours) should be non-zero"
                " positive integer less than or equal to 24."
            )
            self.logger.error(f"{validation_err_msg} {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )

        mscore = data.get("mscore")
        if mscore is None:
            err_msg = (
                "Minimum Indicator Confidential Score (IC-Score) is a"
                " required configuration parameter."
            )
            self.logger.error(f"{validation_err_msg} {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        elif not isinstance(mscore, int):
            err_msg = (
                "Invalid value provided in Minimum Indicator Confidential "
                "Score (IC-Score) configuration parameter. Minimum Indicator "
                "Confidential Score (IC-Score) should be positive integer "
                "value."
            )
            self.logger.error(f"{validation_err_msg} {err_msg}")
            return ValidationResult(success=False, message=err_msg)
        elif not (0 <= mscore <= 100):
            err_msg = (
                "Minimum Indicator Confidential Score (IC-Score) should be "
                "in range of 0 to 100."
            )
            self.logger.error(f"{validation_err_msg} {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        exclude_osint = data.get("exclude_osint")
        if exclude_osint and exclude_osint not in ["Yes", "No"]:
            self.logger.error(
                f"{validation_err_msg} Value of Exclude Open Source "
                "indicators should be 'Yes' or 'No'."
            )
            return ValidationResult(
                success=False,
                message="Invalid value for 'Exclude Open Source indicators' "
                "provided. Allowed values are 'Yes' or 'No'.",
            )
        enable_tagging = data.get("enable_tagging")
        if enable_tagging and enable_tagging not in ["Yes", "No"]:
            self.logger.error(
                f"{validation_err_msg} Value of Enable Tagging should "
                "be 'Yes' or 'No'."
            )
            return ValidationResult(
                success=False,
                message="Invalid value for 'Enable Tagging' provided."
                " Allowed values are 'Yes' or 'No'.",
            )

        return self.validate_auth_params(key_id, key_secret, validation_err_msg)

    def validate_auth_params(self, key_id, key_secret, validation_err_msg):
        """Validate the authentication params with Mandiant platform.

        Args:
            key_id (str): Client ID required to generate access token.
            key_secret (str): Client Secret required to generate access token.
            validation_err_msg (str): Validation error message.
        Returns:
            ValidationResult: ValidationResult object having
            validation results after making an API call.
        """
        try:
            self.get_auth_json(
                key_id, key_secret, "validating auth credentials", is_validation=True
            )
            return ValidationResult(
                success=True,
                message="Validation successfull.",
            )
        except MandiantPluginException as err:
            self.logger.error(
                message=(f"{validation_err_msg} Error: {err}"),
                details=str(traceback.format_exc()),
            )
            return ValidationResult(
                success=False,
                message=str(err),
            )
        except Exception as exp:
            err_msg = "Unexpected validation error occurred."
            self.logger.error(
                message=(f"{validation_err_msg} Error: {exp}"),
                details=str(traceback.format_exc()),
            )
            return ValidationResult(
                success=False,
                message=f"{err_msg} Check logs for more details.",
            )

    def get_auth_json(self, client_key, key_secret, logger_msg, is_validation=False):
        """Get the access token from Mandiant platform.

        Args:
            key_id (str): Client ID required to generate access token.
            key_secret (str): Client Secret required to generate access token.
            logger_msg: logger message.
            is_validation : API call from validation method or not
        Returns:
            json: JSON response data in case of Success.
        """
        auth_endpoint = f"{BASE_URL}/token"
        auth_token_bytes = f"{client_key}:{key_secret}".encode("ascii")
        base64_auth_token_bytes = base64.b64encode(auth_token_bytes)
        base64_auth_token = base64_auth_token_bytes.decode("ascii")
        headers = {
            "Authorization": f"Basic {base64_auth_token}",
            "Content-Type": "application/x-www-form-urlencoded",
            "accept": "application/json",
        }

        data = {"grant_type": "client_credentials"}

        try:
            resp = self.mandiant_helper.api_helper(
                url=auth_endpoint,
                method="POST",
                data=data,
                headers=headers,
                verify=self.ssl_validation,
                proxies=self.proxy,
                logger_msg=logger_msg,
                is_validation=is_validation,
            )
            if self.storage is not None:
                self.storage[
                    "token_expiry"
                ] = datetime.datetime.now() + datetime.timedelta(
                    seconds=int(resp.get("expires_in", 1799))
                )
            return resp
        except MandiantPluginException:
            raise
        except Exception:
            raise
