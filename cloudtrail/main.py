"""AWS CloudTrail Lake Plugin."""
import os
import subprocess
import json
import sys
from time import time
from typing import List
from jsonpath import jsonpath
import time
import re

from netskope.common.utils import AlertsHelper
from netskope.integrations.cls.plugin_base import (
    PluginBase,
    ValidationResult,
    PushResult,
)

from .utils.cloudtrail_exceptions import (
    MappingValidationError,
    EmptyExtensionError,
    FieldNotFoundError,
)

from .utils.cloudtrail_helper import (
    get_cloudtrail_mappings,
)
from .utils.cloudtrail_cef_generator import (
    CEFGenerator,
)

from .utils.cloudtrail_client import AWSCloudtrailClient

PLUGIN = "CLS AWS CloudTrail Lake Plugin"

class CloudtrailError(Exception):
    """Raised when the input value is too small"""
    pass

class CloudTrailPlugin(PluginBase):
    """The AWS Cloudtrail Lake plugin implementation class."""

    def get_mapping_value_from_json_path(self, data, json_path):
        """To Fetch the value from given JSON object using given JSON path.

        Args:
            data: JSON object from which the value is to be fetched
            json_path: JSON path indicating the path of the value in given JSON

        Returns:
            fetched value.
        """
        return jsonpath(data, json_path)

    def get_mapping_value_from_field(self, data, field):
        """To Fetch the value from given field.

        Args:
            data: JSON object from which the value is to be fetched
            field: Field whose value is to be fetched

        Returns:
            fetched value.
        """
        return data[field] if data[field] or isinstance(data[field], int) else "null"

    def get_subtype_mapping(self, mappings, subtype):
        """To Retrieve subtype mappings case insensitively.

        Args:
            mappings: Mapping JSON from which subtypes are to be retrieved
            subtype: Subtype (e.g. DLP for alerts) for which the
            mapping is to be fetched

        Returns:
            Fetched mapping JSON object
        """
        mappings = {k.lower(): v for k, v in mappings.items()}
        if subtype.lower() in mappings:
            return mappings[subtype.lower()]
        else:
            return mappings[subtype.upper()]

    def get_headers(self, header_mappings, data, data_type, subtype):
        """To Create a dictionary of CEF headers from given header mappings.

        Args:
            subtype: Subtype for which the headers are being transformed
            data_type: Data type for which the headers are being transformed
            header_mappings: CEF header mapping with Netskope fields
            data: The alert/event for which the CEF header is being generated

        Returns:
            header dict
        """
        headers = {}
        helper = AlertsHelper()
        tenant = helper.get_tenant_cls(self.source)
        mapping_variables = {"$tenant_name": tenant.name}

        missing_fields = []
        # Iterate over mapped headers
        for cef_header, header_mapping in header_mappings.items():
            try:
                headers[cef_header] = self.get_field_value_from_data(
                    header_mapping, data, data_type, subtype, False
                )
                # Handle variable mappings
                if (
                    isinstance(headers[cef_header], str)
                    and headers[cef_header].lower() in mapping_variables
                ):
                    headers[cef_header] = mapping_variables[headers[cef_header].lower()]
            except FieldNotFoundError as err:
                missing_fields.append(str(err))
        return headers

    def _get_from_data(self, data, mapping_fields, default_value):
        """Get data from the mapping fields supporting multiple mappings"""
        for field in mapping_fields:
            if field in data:
                return data.get(field)
            return default_value

    def get_extensions(self, extension_mappings, data, data_type, subtype):
        """Fetch extensions from given mappings.

        Args:
            subtype: Subtype for which the headers are being transformed
            data_type: Data type for which the headers are being transformed
            extension_mappings: Mapping of extensions
            data: The data to be transformed

        Returns:
            extensions (dict)
        """
        extension = {}
        missing_fields = []

        # Iterate over mapped extensions
        for cef_extension, extension_mapping in extension_mappings.items():
            try:
                extension[cef_extension] = self.get_field_value_from_data(
                    extension_mapping,
                    data,
                    data_type,
                    subtype,
                    is_json_path="is_json_path" in extension_mapping,
                )

            except FieldNotFoundError as err:
                missing_fields.append(str(err))
        if extension.get("userAgent", "").lower() == "native":
            extension["userAgent"] = "AWS CLI"
        if "UID" not in extension:
            extension["UID"] = self._get_from_data(
                data, ["_id"], "NA"
            )
        return extension

    def get_field_value_from_data(
        self, extension_mapping, data, data_type, subtype, is_json_path=False
    ):
        """To Fetch the value of extension based on "mapping" and "default" fields.

        Args:
            extension_mapping: Dict containing "mapping" and "default" fields
            data: Data instance retrieved from Netskope
            subtype: Subtype for which the extension are being transformed
            data_type: Data type for which the headers are being transformed
            is_json_path: Whether the mapped value is JSON path or direct
            field name

        Returns:
            Fetched values of extension

        ---------------------------------------------------------------------
             Mapping          |    Response    |    Retrieved Value
        ----------------------|                |
        default  |  Mapping   |                |
        ---------------------------------------------------------------------
           P     |     P      |        P       |           Mapped
           P     |     P      |        NP      |           Default
           P     |     NP     |        P       |           Default
           NP    |     P      |        P       |           Mapped
           P     |     NP     |        NP      |           Default
           NP    |     P      |        NP      |           -
           NP    |     NP     |        P       |           - (Not possible)
           NP    |     NP     |        NP      |           - (Not possible)
        -----------------------------------------------------------------------
        """
        if "mapping_field" in extension_mapping and extension_mapping["mapping_field"]:
            if is_json_path:
                value = self.get_mapping_value_from_json_path(
                    data, extension_mapping["mapping_field"]
                )
                if value:
                    return ",".join([str(val) for val in value])
                else:
                    raise FieldNotFoundError(extension_mapping["mapping_field"])
            else:
                # If mapping is present in data, map that field,
                # else skip by raising exception
                if extension_mapping["mapping_field"] in data:
                    return self.get_mapping_value_from_field(
                        data, extension_mapping["mapping_field"]
                    )
                elif "default_value" in extension_mapping:
                    # If mapped value is not found in response and default is
                    # mapped, map the default value (case #2)
                    return extension_mapping["default_value"]
                else:  # case #6
                    raise FieldNotFoundError(extension_mapping["mapping_field"])
        else:
            # If mapping is not present, 'default_value' must be there
            # because of validation (case #3 and case #5)
            return extension_mapping["default_value"]

    def transform(self, raw_data, data_type, subtype) -> List:
        """Transform the raw data into target platform supported formats."""
        try:
            cloudtrail_mappings = get_cloudtrail_mappings(self.mappings, data_type)
        except KeyError as err:
            self.logger.error(
                f"{PLUGIN}: Error in cloudtrail mapping file. Error: {str(err)}"
            )
            raise
        except MappingValidationError as err:
            self.logger.error(
                f"{PLUGIN}: {str(err)}"
            )
            raise
        except Exception as err:
            self.logger.error(
                f"{PLUGIN}: An error occurred while mapping data using given "
                "json mappings. Error: {}".format(str(err))
            )
            raise

        transformed_data = []
        cef_generator = CEFGenerator(
            self.mappings,
            self.logger,
        )

        for data in raw_data:
            if "_id" not in data.keys():
                self.logger.error(
                    f"{PLUGIN}: "
                    "Unable to find the required field '_id' from the Raw Data. "
                    f"Transformation of the current {subtype} {data_type} will be skipped."
                    f"Data: {data}"
                )
                continue
            # First retrieve the mapping of subtype being transformed
            try:
                subtype_mapping = self.get_subtype_mapping(
                    cloudtrail_mappings[data_type], subtype
                )
                if self.configuration.get("add_additional_data") == "Yes":
                    mapped_fields = ["_id"]
                    for mapping_field in subtype_mapping.get("extension", "").values():
                        mapped_fields.append(mapping_field.get("mapping_field", ""))
            except KeyError as err:
                self.logger.warn(
                    f"{PLUGIN}: Subtype {subtype} is not supported by configured mapping file. "
                    f"Transformation of current record will be skipped. Error {err}"
                )
                return []
            except Exception:
                self.logger.error(
                    f"{PLUGIN}: Error occurred while retrieving mappings for "
                    f'subtype "{subtype}". '
                    "Transformation of current record will be "
                    "skipped."
                )
                continue

            try:
                extension = self.get_extensions(
                    subtype_mapping["extension"], data, data_type, subtype
                )
            except Exception as err:
                self.logger.error(
                    f"{PLUGIN}: "
                    f"[{data_type}][{subtype}]: Error occurred while creating "
                    f"CEF extension: {str(err)}. Transformation of "
                    "the current record will be skipped"
                )
                continue

            try:
                transformed_log = cef_generator.get_cef_event(
                    extension, data_type, subtype
                )

                # adding all the unmapped  data to a seperate dictionary
                if self.configuration.get("add_additional_data") == "Yes":
                    additional_data = {}
                    for key, value in data.items():
                        if key not in mapped_fields:
                            additional_data[key] = value

                    # sending additional unmapped data in the field additionalEventData in cloudtrail
                    transformed_log["additionalEventData"] = additional_data

                transformed_log["userIdentity"] = transformed_log.get(
                    "userIdentity", {}
                )
                transformed_log["userIdentity"]["details"] = {
                    "access_method": data.get("access_method", None)
                }
                transformed_log["recipientAccountId"] = self.configuration[
                    "channel_arn"
                ].split(":")[4]  # extract AWS Account ID from the Channel ARN
                transformed_log["eventTime"] = str(
                    time.strftime(
                        "%Y-%m-%dT%H:%M:%SZ",
                        time.localtime(int(transformed_log["eventTime"])),
                    )
                )
                transformed_log["eventSource"] = (
                    f"netskope{data_type.rstrip(data_type[-1])}"
                    f".{(subtype.replace(' ', '')).lower()}"
                )

                audit_event = {
                    "id": data["_id"],
                    "eventData": json.dumps(transformed_log),
                }
                transformed_data.append(audit_event)

            except EmptyExtensionError:
                self.logger.error(
                    f"{PLUGIN}: "
                    f"[{data_type}][{subtype}]: Got empty extension during transformation."
                    "Transformation of current record will be skipped"
                )
            except Exception as err:
                self.logger.error(
                    f"{PLUGIN}: "
                    f"[{data_type}][{subtype}]: An error occurred during transformation."
                    f" Error: {str(err)}"
                )
        if transformed_data: return transformed_data

    def chunks(self, transformed_data):
        """Divide list of transformed data into chunks of 1mb each"""
        temp_chunks = []
        size_of_chunk = 0
        chunk_length_count = 0
        for data in transformed_data:
            size_of_chunk += sys.getsizeof(f"{data}") / (1024 * 1024)
            if size_of_chunk < 1 and chunk_length_count < 100:
                temp_chunks.append(data)
                chunk_length_count += 1
            else:
                if temp_chunks:
                    yield temp_chunks
                    temp_chunks = []
                    size_of_chunk = sys.getsizeof(f"{data}") / (1024 * 1024)
                    temp_chunks.append(data)
                    chunk_length_count = 1
        if temp_chunks:
            yield temp_chunks

    def push(self, transformed_data, data_type, subtype) -> PushResult:
        aws_client = AWSCloudtrailClient(self.configuration, self.logger, self.proxy)
        client = aws_client.get_cloudtrail_client("cloudtrail-data")
        success_count = 0
        failed_count = 0
        for chunk in self.chunks(transformed_data):
            try:
                resp = client.put_audit_events(
                    auditEvents=chunk,
                    channelArn=self.configuration.get("channel_arn")
                )
                if resp.get("failed", []):
                    failed_count += len(resp.get("failed"))
                    self.logger.error(
                        f"{PLUGIN}: "
                        "Error occured while ingesting "
                        f"{len(resp.get('failed'))} alert(s)/event(s) ,"
                        f"Error:{resp.get('failed')}"
                    )
                success_count += len(resp.get("successful", []))
            except Exception as e:
                if "(ChannelNotFound)" in str(e):
                    # as the raise msg was showing actual channel arn in the Logs: "Plugin: AWS CLoudtrail Lake ,
                    # Error occured while ingesting alert(s)/event(s), Error: An error occurred (ChannelNotFound)
                    # when calling the PutAuditEvents operation: The channel
                    # arn:aws:cloudtrail:eu-central-1:xxxxxxxxxxxx:channel/6f8a70de-908c-4ea6-9a96-43xxxxxxxxxx could not be found."
                    raise CloudtrailError(
                        f"{PLUGIN}: Channel not found in the selected region"
                    ) from None
                else:
                    raise CloudtrailError(f"{PLUGIN}: {e}")

        if success_count == 0:
            raise CloudtrailError(
                f"{PLUGIN}: "
                "Error occured while ingesting, "
                f"Error:{resp.get('failed')}"
            )

        self.logger.info(
            f"{PLUGIN}: {success_count} {subtype} {data_type} ingested sucessfully, "
            f"{failed_count} {subtype} {data_type} failed to ingest."
        )

    def validate(self, configuration: dict) -> ValidationResult:
        """Validate the configuration parameters dict."""
        if not configuration.get("transformData", True):
            self.logger.error(
                f"{PLUGIN}: Validation error occurred. Error: "
                "Cannot send raw data to AWS Cloudtrail Lake - "
                "Please enable the toggle 'Transform the raw logs'."
            )
            return ValidationResult(
                success=False,
                message="Cannot send raw data to AWS CloudTrail Lake - Please enable the toggle 'Transform the raw logs'.",
            )

        if (
            "aws_public_key" not in configuration
            or not configuration["aws_public_key"].strip()
        ):
            self.logger.error(
                f"{PLUGIN}: Validation error occurred. "
                "Error: AWS Access Key ID cannot be empty."
            )
            return ValidationResult(
                success=False, message="AWS Access Key ID cannot be empty."
            )

        elif (
            not isinstance(configuration["aws_public_key"], str)
        ):
            self.logger.error(
                f"{PLUGIN}: Validation error occurred. "
                "Error: Invalid AWS Access Key ID found in the "
                "configuration parameters."
            )
            return ValidationResult(
                success=False, message="Invalid AWS Access Key ID provided."
            )

        if (
            "aws_private_key" not in configuration
            or not configuration["aws_private_key"].strip()
        ):
            self.logger.error(
                f"{PLUGIN}: Validation error occurred. "
                "Error: AWS Secret Access Key cannot be empty."
            )
            return ValidationResult(
                success=False, message="AWS Secret Access Key cannot be empty."
            )

        elif (
            not isinstance(configuration["aws_private_key"], str)
        ):
            self.logger.error(
                f"{PLUGIN}: Validation error occurred. "
                "Error: Invalid AWS Secret Access Key found in the "
                "configuration parameters."
            )
            return ValidationResult(
                success=False, message="Invalid AWS Secret Access Key provided."
            )

        if (
            "channel_arn" not in configuration
            or not configuration["channel_arn"]
        ):
            self.logger.error(
                f"{PLUGIN}: Validation error occurred. "
                "Error: Channel Arn cannot be empty."
            )
            return ValidationResult(
                success=False, message="Channel ARN is a required parameter."
            )
        elif (
            not isinstance(configuration["channel_arn"], str)
        ):
            self.logger.error(
                f"{PLUGIN}: Validation error occurred. "
                "Error: Value of Channel Arn should be a string."
            )
            return ValidationResult(
                success=False, message="Invald Channel ARN provided."
            )
        elif not (
            re.match(
                "^arn:aws:cloudtrail:\w+(?:-\w+)+:\d{12}:channel\/[A-Za-z0-9]+(?:-[A-Za-z0-9]+)+$",  # ^[a-zA-Z0-9._/\-:]+$
                configuration["channel_arn"],
            )
        ):
            self.logger.error(
                f"{PLUGIN}: Validation error occurred "
                "Error: Invalid Channel ARN "
            )
            return ValidationResult(
                success=False,
                message="Channel ARN provided is not in the correct format.",
            )

        if (
            "add_additional_data" not in configuration
            or not configuration.get("add_additional_data", "No").strip()
        ):
            self.logger.error(
                f"{PLUGIN}: Validation error occurred. "
                "Error: Add Additional Data is a required field."
            )
            return ValidationResult(
                success=False, message="Add Additional Data is a required field."
            )

        elif (
            not isinstance(configuration.get("add_additional_data", "No"), str)
        ):
            self.logger.error(
                f"{PLUGIN}: Validation error occurred. "
                "Error: Value of Add Addiitonal Data field should be a string."
            )
            return ValidationResult(
                success=False, message="Invalid value for Add Addiitonal Data provided."
            )
        elif configuration.get("add_additional_data", "No") not in ["Yes", "No"]:
            self.logger.error(
                f"{PLUGIN}: Validation error occurred "
                "Error: Invalid value for Add Addiitonal Data provided. Allowed values are 'Yes' or 'No'."
            )
            return ValidationResult(
                success=False,
                message="Invalid value for Add Addiitonal Data provided. Allowed values are 'Yes' or 'No'.",
            )

        try:
            self.validate_credentials(configuration, self.logger, self.proxy)
        except Exception as err:
            self.logger.error(
                f"{PLUGIN}: Validation error occurred. "
                "Error: Invalid AWS Access Key ID (Public Key) or "
                "AWS Secret Access Key (Private Key) or Channel ARN "
                f"found in the configuration parameters.Error: {err}"
            )
            return ValidationResult(
                success=False,
                message="Invalid Credentials provided.",
            )
        return ValidationResult(success=True, message="Validation successful.")

    def setenv(self, configuration):
        try:

            my_env = os.environ.copy()
            subprocess.check_output(
                [
                    "aws",
                    "configure",
                    "set",
                    "aws_access_key_id",
                    f"{configuration['aws_public_key']}",
                ],
                env=my_env,
            )
            subprocess.check_output(
                [
                    "aws",
                    "configure",
                    "set",
                    "aws_secret_access_key",
                    f"{configuration['aws_private_key']}",
                ],
                env=my_env,
            )
            subprocess.check_output(
                [
                    "aws",
                    "configure",
                    "set",
                    "default.region",
                    f"{configuration['region_name']}",
                ],
                env=my_env,
            )
            subprocess.check_output(
                [
                    "aws",
                    "s3",
                    "cp",
                    "s3://open-audit-events-beta-artifacts/cloudtrail-2013-11-01.api.json",
                    ".",
                ],
                env=my_env,
                stderr=subprocess.STDOUT,
            )
            subprocess.check_output(
                [
                    "aws",
                    "s3",
                    "cp",
                    "s3://open-audit-events-beta-artifacts/cloudtraildata-2021-08-11.json",
                    ".",
                ],
                env=my_env,
                stderr=subprocess.STDOUT,
            )
            subprocess.check_output(
                [
                    "aws",
                    "configure",
                    "add-model",
                    "--service-model",
                    "file://cloudtrail-2013-11-01.api.json",
                ],
                env=my_env,
                stderr=subprocess.STDOUT,
            )
            subprocess.check_output(
                [
                    "aws",
                    "configure",
                    "add-model",
                    "--service-model",
                    "file://cloudtraildata-2021-08-11.json",
                ],
                env=my_env,
                stderr=subprocess.STDOUT,
            )
        except subprocess.CalledProcessError as e:
            self.logger.error(
                f"{PLUGIN}: {e.returncode}:{e.output}"
            )

    def validate_credentials(self, configuration, logger, proxy):
        """Validate credentials.

        Args:
            aws_public_key: the aws public key to establish
            connection with aws cloudtrail.
            aws_private_key: the aws private key to establish connection
            with aws cloudtrail.

        Returns:
            Whether the provided value is valid or not.
            True in case of valid value, False otherwise
        """
        try:
            aws_client = AWSCloudtrailClient(configuration, logger, proxy)
            # self.setenv(configuration)
            # creating client with service 'cloudtrail' to verify credentials
            cloudtrail_client = aws_client.get_cloudtrail_client("cloudtrail")
            # creating client with service 'cloudtrail-data' to verify credentials
            aws_client.get_cloudtrail_client("cloudtrail-data")
            cloudtrail_client.get_channel(
                Channel = configuration.get("channel_arn")
            )
            return ValidationResult(
                success=True,
                message="Validation successfull for CloudTrail Plugin",
            )
        except Exception:
            raise
