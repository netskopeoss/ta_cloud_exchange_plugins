"""CrowdStrike LogScale Plugin."""
import json
from typing import List
import requests
import os
import traceback
from datetime import datetime
from netskope.integrations.cls.plugin_base import PluginBase, ValidationResult
from .utils.crowdstrike_logscale_validator import CrowdStrikeLogScaleValidator
from .utils.crowdstrike_logscale_client import CrowdStrikeLogScaleClient
from .utils.crowdstrike_logscale_helper import (
    get_crowdstrike_logscale_mappings,
    _add_user_agent,
)
from .utils.crowdstrike_logscale_constant import (
    MODULE_NAME,
    PLATFORM_NAME,
    PLUGIN_VERSION,
)
from .utils.crowdstrike_logscale_exception import (
    MappingValidationError,
    CrowdStrikeLogScaleException,
)


class CrowdStrikeLogScalePlugin(PluginBase):
    """The CrowdStrike LogScale plugin implementation class."""

    def __init__(
        self,
        name,
        *args,
        **kwargs,
    ):
        """Initialize CrowdStrike LogScale plugin class."""
        super().__init__(
            name,
            *args,
            **kwargs,
        )
        self.plugin_name, self.plugin_version = self._get_plugin_info()
        self.log_prefix = f"{MODULE_NAME} {self.plugin_name} [{name}]"

    def _get_plugin_info(self) -> tuple:
        """Get plugin name and version from manifest.
        Returns:
            tuple: Tuple of plugin's name and version fetched from manifest.
        """
        try:
            file_path = os.path.join(
                str(os.path.dirname(os.path.abspath(__file__))),
                "manifest.json",
            )
            with open(file_path, "r") as manifest:
                manifest_json = json.load(manifest)
                plugin_name = manifest_json.get("name", PLATFORM_NAME)
                plugin_version = manifest_json.get("version", PLUGIN_VERSION)
                return (plugin_name, plugin_version)
        except Exception as exp:
            self.logger.info(
                message=(
                    f"{MODULE_NAME} {PLATFORM_NAME}: Error occurred while"
                    " getting plugin details. Error: {}".format(exp)
                ),
                details=traceback.format_exc(),
            )
        return (PLATFORM_NAME, PLUGIN_VERSION)

    @staticmethod
    def get_subtype_mapping(mappings, subtype):
        """Retrieve subtype mappings (mappings for subtypes of
        alerts/events/webtx) case insensitively.

        :param mappings: Mapping JSON from which subtypes are to be retrieved
        :param subtype: Subtype (e.g. DLP for alerts) for which
        the mapping is to be fetched
        :return: Fetched mapping JSON object
        """
        mappings = {k.lower(): v for k, v in mappings.items()}
        if subtype.lower() in mappings:
            return mappings[subtype.lower()]
        else:
            return mappings[subtype.upper()]

    def map_json_data(self, mappings, data, data_type, subtype):
        """Filter the raw data and returns the filtered data.

        :param mappings: List of fields to be pushed
        :param data: Data to be mapped (retrieved from Netskope)
        :param logger: Logger object for logging purpose
        :return: Mapped data based on fields given in mapping file
        """

        if mappings == [] or not data:
            return data

        mapped_dict = {}
        for key in mappings:
            if key in data:
                mapped_dict[key] = data[key]

        return mapped_dict

    def _convert_timestamp(self, events):
        skipped_logs_timestamp = 0
        skipped_logs_empty = 0
        data = []
        for event in events:
            if event:
                epoch_timestamp = event.get("x-cs-timestamp") or event.get(
                    "timestamp"
                )
                if not epoch_timestamp:
                    skipped_logs_timestamp += 1
                    continue
                formatted_timestamp = datetime.utcfromtimestamp(
                    int(epoch_timestamp)
                ).strftime("%Y-%m-%dT%H:%M:%SZ")
                try:
                    event.pop("timestamp")
                except KeyError:
                    event.pop("x-cs-timestamp")
                event["@timestamp"] = formatted_timestamp
                data.append(event)
            else:
                skipped_logs_empty += 1

        return skipped_logs_empty, skipped_logs_timestamp, data

    def transform(self, raw_data, data_type, subtype) -> List:
        """Transform Netskope data (alerts/events/webtx)
        into CrowdStrike LogScale Compatible data.

        :param data_type: Type of data to be transformed:
        Currently alerts and events
        :param raw_data: Raw data retrieved from Netskope
        which is supposed to be transformed
        :param subtype: The subtype of data being transformed

        :return List of alerts/events/webtx to be ingested

        Different cases related mapping file:

            1. If mapping file is not found or contains invalid JSON,
            all the data will be ingested
            2. If the file contains few valid fields, only that
            fields will be considered for ingestion
            3. Fields which are not in Netskope response,
            but are present in mappings file will be ignored with logs.
        """
        if not self.configuration.get("transformData", True):
            try:
                (
                    delimiter,
                    cef_version,
                    crowdstrike_logscale_mappings,
                ) = get_crowdstrike_logscale_mappings(self.mappings, "json")
            except KeyError as err:
                err_msg = "Error in {} mapping file.".format(PLATFORM_NAME)
                self.logger.error(
                    message="{}: {} Error: {}".format(
                        self.log_prefix, err_msg, err
                    ),
                    details=traceback.format_exc(),
                )
                raise CrowdStrikeLogScaleException(err_msg)
            except MappingValidationError as err:
                err_msg = (
                    "Validation error occurred for {} mapping file.".format(
                        PLATFORM_NAME
                    )
                )
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg} Error: {err}",
                    details=traceback.format_exc(),
                )
                raise CrowdStrikeLogScaleException(err_msg)
            except Exception as err:
                err_msg = (
                    "An error occurred while mapping data using "
                    "given json mappings."
                )
                self.logger.error(
                    message="{}: {} Error: {}".format(
                        self.log_prefix, err_msg, err
                    ),
                    details=traceback.format_exc(),
                )
                raise CrowdStrikeLogScaleException(err_msg)

            try:
                subtype_mapping = self.get_subtype_mapping(
                    crowdstrike_logscale_mappings["json"][data_type], subtype
                )
            except Exception:
                err_msg = (
                    "Error occurred while retrieving subtype mappings "
                    "for datatype: {} (subtype: {})".format(data_type, subtype)
                )
                self.logger.error(
                    message="{}: {} Transformation will be skipped.".format(
                        self.log_prefix, err_msg
                    ),
                    details=traceback.format_exc(),
                )
                raise CrowdStrikeLogScaleException(err_msg)

            transformed_data = []
            (
                skipped_logs_empty,
                skipped_logs_timestamp,
                data,
            ) = self._convert_timestamp(raw_data)

            if not subtype_mapping:
                if skipped_logs_empty + skipped_logs_timestamp > 0:
                    self.logger.info(
                        "{}: Plugin couldn't process {} record(s) because they "
                        "either had no data and "
                        "{} record(s) of raw data has no timestamp field. "
                        "Therefore, the transformation and ingestion for those "
                        "record(s) were skipped.".format(
                            self.log_prefix,
                            skipped_logs_empty,
                            skipped_logs_timestamp,
                        )
                    )
                return data

            for item in data:
                mapped_dict = self.map_json_data(
                    subtype_mapping, item, data_type, subtype
                )
                if mapped_dict:
                    transformed_data.append(mapped_dict)
                else:
                    skipped_logs_empty += 1

            if skipped_logs_empty + skipped_logs_timestamp > 0:
                self.logger.info(
                    "{}: Plugin couldn't process {} record(s) because they "
                    "either had no data or contained invalid/missing "
                    "fields according to the configured JSON mapping and "
                    "{} record(s) of raw data has no timestamp field. "
                    "Therefore, the transformation and ingestion for those "
                    "record(s) were skipped.".format(
                        self.log_prefix,
                        skipped_logs_empty,
                        skipped_logs_timestamp,
                    )
                )
            return transformed_data
        else:
            self.logger.error(
                "{}: The plugin only supports sharing raw JSON logs. "
                "Please disable the 'Transform the raw logs' toggle to save "
                "the configuration.".format(self.log_prefix)
            )
            raise CrowdStrikeLogScaleException(
                "This plugin only supports sending JSON(raw data) "
                "data to CrowdStrike LogScale. "
                "Please disable the transformation toggle."
            )

    def push(self, transformed_data, data_type, subtype):
        """Transform and ingests the given data chunks to
        CrowdStrike LogScale HTTP Event Collector.

        :param data_type: The type of data being pushed.
        Current possible values: alerts and events
        :param transformed_data: Transformed data to be ingested to
        CrowdStrike LogScale HTTP Event Collector in chunks
        :param subtype: The subtype of data being pushed.
        E.g. subtypes of alert is "dlp", "policy" etc.
        """
        crowdstrike_logscale_client = CrowdStrikeLogScaleClient(
            self.configuration,
            self.logger,
            self.log_prefix,
            self.plugin_name,
            self.ssl_validation,
            self.proxy,
        )
        try:
            crowdstrike_logscale_client.push(
                transformed_data, data_type, subtype
            )
        except Exception as err:
            # Raise this exception from here so that it does not update
            # the checkpoint, as this means data ingestion is failed
            # even after a few retries.
            err_msg = "Could not ingest data into CrowdStrike LogScale."
            self.logger.error(
                message="{}: {} Error: {}".format(
                    self.log_prefix, err_msg, err
                ),
                details=traceback.format_exc(),
            )
            raise CrowdStrikeLogScaleException(err_msg)

    def validate_auth(self, configuration: dict) -> ValidationResult:
        """Validate credentials of CrowdStrike LogScale plugin."""
        hostname = configuration.get("hostname")
        token = configuration.get("token")
        url = "{}/api/v1/ingest/hec".format(hostname.strip().strip("/"))
        payload = {"event": []}

        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        }
        crowdstrike_logscale_client = CrowdStrikeLogScaleClient(
            self.configuration,
            self.logger,
            self.log_prefix,
            self.plugin_name,
            self.ssl_validation,
            self.proxy,
        )

        try:
            response = crowdstrike_logscale_client._api_helper(
                lambda: requests.post(
                    url=url,
                    headers=_add_user_agent(headers),
                    data=json.dumps(payload),
                    proxies=self.proxy,
                ),
                "validating configuration parameters",
                False,
            )
        except CrowdStrikeLogScaleException as exp:
            self.logger.error(
                message="{}: Validation error occurred. Error: {}".format(
                    self.log_prefix, exp
                ),
                details=traceback.format_exc(),
            )
            return ValidationResult(success=False, message=str(exp))
        except Exception as exp:
            err_msg = "Validation error occurred."
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {exp}",
                details=traceback.format_exc(),
            )

            return ValidationResult(
                success=False,
                message=f"{err_msg} Check logs for more details.",
            )
        if response.status_code == 200:
            return ValidationResult(
                success=True, message="Validation successful."
            )
        elif response.status_code == 401:
            err_msg = "Invalid Ingest Token provided."
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=f"Received API response: {response.text}",
            )
            return ValidationResult(success=False, message=err_msg)
        elif response.status_code == 403:
            err_msg = (
                "Make sure provided token is "
                "ingest token with valid permission(s)."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=f"Received API response: {response.text}",
            )
            return ValidationResult(success=False, message=err_msg)
        else:
            msg = "Validation error occurred. Check logs for more details."

            self.logger.error(
                message=(
                    "{}: Validation error occurred with "
                    "response code {}.".format(
                        self.log_prefix, response.status_code
                    )
                ),
                details=f"Received API response: {response.text}",
            )
            return ValidationResult(success=False, message=msg)

    def validate(self, configuration: dict) -> ValidationResult:
        """Validate the configuration parameters dict."""
        crowdstrike_logscale_validator = CrowdStrikeLogScaleValidator(
            self.logger, self.log_prefix
        )
        configuration["hostname"] = configuration.get("hostname").rstrip()
        hostname = configuration.get("hostname")
        token = configuration.get("token")
        if configuration.get("transformData", True):
            self.logger.error(
                "{}: The plugin only supports sharing raw JSON logs. "
                "Please disable the 'Transform the raw logs' toggle to save "
                "the configuration.".format(self.log_prefix)
            )
            return ValidationResult(
                success=False,
                message=(
                    "This plugin only supports sending JSON(raw data) "
                    "data to CrowdStrike LogScale. "
                    "Please disable the transformation toggle."
                ),
            )

        if "hostname" not in configuration or not hostname:
            msg = "CrowdStrike LogScale Hostname should not be empty."
            self.logger.error(
                f"{self.log_prefix}:: Validation error occurred. Error: {msg}"
            )
            return ValidationResult(success=False, message=msg)
        elif type(hostname) != str:
            self.logger.error(
                "{}: Validation error occurred. Error: "
                "Invalid {} Hostname in the configuration parameters.".format(
                    self.log_prefix, PLATFORM_NAME
                )
            )
            return ValidationResult(
                success=False,
                message="Invalid CrowdStrike LogScale Hostname provided.",
            )
        if "token" not in configuration or not token:
            msg = "Ingest Token should not be empty."
            self.logger.error(
                f"{self.log_prefix}:: Validation error occurred. Error: {msg}"
            )
            return ValidationResult(success=False, message=msg)
        mappings = self.mappings.get("jsonData", None)
        mappings = json.loads(mappings)
        if type(
            mappings
        ) != dict or not crowdstrike_logscale_validator.validate_mappings(
            mappings
        ):
            self.logger.error(
                f"{self.log_prefix}: Validation error occurred. Error: "
                "Invalid CrowdStrike LogScale attribute mapping found in "
                "the configuration parameters."
            )
            return ValidationResult(
                success=False,
                message="Invalid {} attribute mapping provided.".format(
                    PLATFORM_NAME
                ),
            )

        return self.validate_auth(configuration=configuration)
