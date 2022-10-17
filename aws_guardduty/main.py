"""
BSD 3-Clause License

Copyright (c) 2021, Netskope OSS
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its
   contributors may be used to endorse or promote products derived from
   this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
"""

"""AWS GuardDuty CTE Plugin."""
import datetime
import time
from typing import Dict, List

from netskope.integrations.cte.models import SeverityType
from netskope.integrations.cte.models.indicator import Indicator, IndicatorType
from netskope.integrations.cte.models.tags import TagIn
from netskope.integrations.cte.plugin_base import PluginBase, ValidationResult
from netskope.integrations.cte.utils import TagUtils
from pydantic import ValidationError

from .lib import boto3
from .lib.botocore.exceptions import (
    ClientError,
    InvalidRegionError,
    NoRegionError,
    OperationNotPageableError,
    PaginationError,
)

BATCH = 50


class GuardDutyPlugin(PluginBase):
    """AWS GuardDutyPlugin Class."""

    def get_client(self, configuration: dict):
        """Get AWS GuardDuty client.

        Args:
            configuration (dict): Configuration dictionary.

        Returns:
            client: Client object.
        """
        try:
            client = boto3.Session(
                aws_access_key_id=configuration.get("aws_public_key").strip(),
                aws_secret_access_key=configuration.get(
                    "aws_private_key"
                ).strip(),
                aws_session_token=configuration.get(
                    "aws_session_token"
                ).strip()
                if configuration.get("aws_session_token").strip() != ""
                else None,
                region_name=configuration["region_name"].strip(),
            ).client("guardduty")

            return client
        except Exception as error:
            self.logger.error(
                "AWS GuardDuty Plugin: Error occurred while creating client. "
                f"Cause: {error}"
            )
            raise error

    def validate(self, configuration: dict) -> ValidationResult:
        """Validate the configurations of plugin.

        Args:
            configuration (dict): Configuration dictionary.

        Returns:
            ValidationResult: ValidationResult pydantic model.
        """
        if (
            "aws_public_key" not in configuration
            or type(configuration["aws_public_key"]) != str
            or len(configuration["aws_public_key"]) < 1
            or not configuration["aws_public_key"].strip()
        ):
            error_message = (
                "AWS Access Key ID (Public Key) is a required field."
            )
            self.logger.error(
                "AWS GuardDuty Plugin: Validation error occurred."
                f"{error_message}"
            )

            return ValidationResult(
                success=False,
                message=error_message,
            )
        if (
            "aws_private_key" not in configuration
            or type(configuration["aws_private_key"]) != str
            or len(configuration["aws_private_key"]) < 1
            or not configuration["aws_private_key"].strip()
        ):
            error_message = (
                "AWS Secret Access Key (Private Key) is a required field."
            )
            self.logger.error(
                "AWS GuardDuty Plugin: Validation error occurred."
                f" {error_message}"
            )
            return ValidationResult(
                success=False,
                message=error_message,
            )
        if (
            "region_name" not in configuration
            or type(configuration["region_name"]) != str
        ):
            error_message = "Region Name is a required field."
            self.logger.error("AWS GuardDuty Plugin: " f"{error_message}")
            return ValidationResult(
                success=False,
                message=error_message,
            )
        if (
            "aws_detector_id" not in configuration
            or type(configuration["aws_detector_id"]) != str
            or len(configuration["aws_detector_id"]) < 1
            or not configuration["aws_detector_id"].strip()
        ):
            error_message = "Detector ID is a required field."
            self.logger.error(f"AWS GuardDuty Plugin: {error_message}")
            return ValidationResult(
                success=False,
                message=error_message,
            )
        if (
            "aws_session_token" not in configuration
            or type(configuration["aws_session_token"]) != str
            or not configuration["aws_detector_id"].strip()
        ):
            error_message = "Invalid AWS Session Token Provided."
            self.logger.error(f"AWS GuardDuty Plugin: {error_message}")
            return ValidationResult(
                success=False,
                message=error_message,
            )

        if (
            "days" not in configuration
            or not configuration["days"]
            or int(configuration["days"]) <= 0
            or int(configuration["days"]) > 365
        ):
            self.logger.error(
                "AWS GuardDuty Plugin: "
                "Validation error occurred Error: "
                "Invalid Initial Range provided."
            )
            return ValidationResult(
                success=False,
                message="Invalid Initial Range provided.",
            )

        try:
            client = self.get_client(configuration=configuration)
            client.list_findings(
                DetectorId=configuration["aws_detector_id"].strip()
            )
        except ClientError:
            self.logger.error(
                "AWS GuardDuty Plugin: Invalid Credentials Provided."
            )
            return ValidationResult(
                success=False,
                message="Invalid Credentials Provided.",
            )
        except InvalidRegionError as error:
            self.logger.error(
                f"AWS GuardDuty Plugin: Invalid Region Name Provided."
                f" Cause: {error}"
            )
            return ValidationResult(
                success=False, message="Invalid Region Name Provided."
            )
        except NoRegionError as error:
            self.logger.error(
                "AWS GuardDuty Plugin: Region Name is not provided. "
                f"Cause: {error}"
            )
            return ValidationResult(
                success=False, message="Region Name is not Provided."
            )
        except Exception as exp:
            self.logger.error(
                f"AWS GuardDuty Plugin: Authentication Failed. {exp.args}"
            )
            return ValidationResult(
                success=False,
                message="Authentication Failed. Check logs for more details.",
            )
        return ValidationResult(success=True, message="Validation successful.")

    def get_findings_list(self, client) -> List:
        """Get Findings List.

        Args:
            client : Client Object

        Returns:
            List: Findings Ids
        """
        finding_ids = []
        last_run_time = None
        try:
            if self.last_run_at:
                last_run_time = self.last_run_at
            else:
                last_run_time = datetime.datetime.now() - datetime.timedelta(
                    days=self.configuration["days"]
                )

            paginator = client.get_paginator("list_findings")
            page_iterator = paginator.paginate(
                DetectorId=self.configuration["aws_detector_id"].strip(),
                FindingCriteria={
                    "Criterion": {
                        "updatedAt": {
                            "Gt": int(
                                time.mktime(last_run_time.timetuple()) * 1000
                            )
                        }
                    }
                },
            )
            for page in page_iterator:
                finding_ids += page["FindingIds"]
        except OperationNotPageableError:
            findings = client.list_findings(
                DetectorId=self.configuration["aws_detector_id"].strip()
            )
            for finding in findings:
                finding_ids += finding["FindingIds"]
        except PaginationError as error:
            self.logger.error(
                "AWS GuardDuty Plugin: Pagination Error occurred while "
                f"fetching findings. Cause: {error}"
            )
        except ClientError:
            self.logger.error(
                "AWS GuardDuty Plugin: Error occurred while fetching "
                "indicators. AWS Session Token expired. Please update the "
                "AWS Session Token from plugin configuration."
            )
        except Exception as exp:
            self.logger.error(
                "AWS GuardDuty Plugin: Error occurred while "
                f"fetching indicators. Cause: {exp}"
            )
        return finding_ids

    def get_indicators(self, finding: Dict) -> List:
        """Get indicators from findings.

        Args:
            finding (Dict): Finding dictionary fetched from AWS GuardDuty.

        Returns:
            List: List of indicators.
        """
        indicators = []

        gen_indicator = {
            "type": IndicatorType.SHA256,
            "firstSeen": finding.get("Service", {}).get("EventFirstSeen"),
            "lastSeen": finding.get("Service", {}).get("EventLastSeen"),
        }
        severity = (
            finding.get("Service", {})
            .get("EbsVolumeScanDetails", {})
            .get("ScanDetections", {})
            .get("HighestSeverityThreatDetails", {})
            .get("Severity", "unknown")
        )
        if isinstance(severity, str) and severity in [
            "unknown",
            "low",
            "medium",
            "high",
            "critical",
        ]:
            gen_indicator.update({"severity": severity})
        else:
            gen_indicator.update({"severity": SeverityType.UNKNOWN})
        tag_utils = TagUtils()
        tags = []
        for tag in (
            finding.get("Service", {})
            .get("EbsVolumeScanDetails", {})
            .get("Sources", [])
        ):
            try:
                if not tag_utils.exists(f"GuardDuty-{tag.strip()}"):
                    tag_utils.create_tag(
                        TagIn(name=f"GuardDuty-{tag.strip()}", color="#ED3347")
                    )
            except ValueError:
                self.logger.warn(
                    f"AWS GuardDuty Plugin: Invalid Tag found. Skipping {tag}."
                )
            else:
                tags.append(f"GuardDuty-{tag}")

        if "InstanceDetails" in finding.get("Resource", {}).keys():
            for tag in (
                finding.get("Resource", {})
                .get("InstanceDetails", {})
                .get("NetworkInterfaces", [])
            ):
                if "PrivateIpAddress" in tag.keys():
                    if not tag_utils.exists("GuardDuty-private"):
                        tag_utils.create_tag(
                            TagIn(name="GuardDuty-private", color="#ED3347")
                        )
                    tags.append("GuardDuty-private")

                if "PublicIp" in tag.keys():
                    if not tag_utils.exists("GuardDuty-public"):
                        tag_utils.create_tag(
                            TagIn(name="GuardDuty-public", color="#ED3347")
                        )
                    tags.append("GuardDuty-public")

        gen_indicator.update({"tags": tags})
        for files in (
            finding.get("Service", {})
            .get("EbsVolumeScanDetails", {})
            .get("ScanDetections", {})
            .get("ThreatDetectedByName", {})
            .get("ThreatNames", [])
        ):
            for filepath in files.get("FilePaths", []):
                gen_indicator.update(
                    {
                        "value": filepath.get("Hash"),
                        "comments": (
                            f'Arn: {finding.get("Arn", "Not Found")}, '
                            f"""TriggerFindingId: {
                                (
                                    finding.get("Service",{})
                                    .get("EbsVolumeScanDetails",{})
                                    .get("TriggerFindingId","Not Found")
                                )
                                }, """
                            f'Name: {filepath.get("FileName","Not Found")}, '
                            f"""Filepath: {
                                filepath.get("FilePath","Not Found")
                            }, """
                            f"""Description: {
                                finding.get("Description","Not Found")
                            }"""
                        ),
                    }
                )
                try:
                    indicators.append(Indicator(**gen_indicator))
                except ValidationError as error:
                    self.logger.error(
                        "AWS GuardDuty Plugin: Error occurred while "
                        f"fetching indicators. Cause: {error}"
                    )

        return indicators

    def pull(self) -> List[Indicator]:
        """Pull indicators.

        Returns:
            List[Indicator]: List of pulled indicators.
        """
        client = self.get_client(configuration=self.configuration)

        finding_ids = self.get_findings_list(client=client)
        indicators = []

        for i in range(0, len(finding_ids), BATCH):
            try:
                finding_details = client.get_findings(
                    DetectorId=self.configuration.get(
                        "aws_detector_id"
                    ).strip(),
                    FindingIds=finding_ids[i : i + BATCH],
                )
                for finding in finding_details.get("Findings", []):
                    if finding.get("Service", {}).get("EbsVolumeScanDetails"):
                        indicators += self.get_indicators(finding=finding)

            except Exception as exp:
                self.logger.error(
                    "AWS GuardDuty Plugin: Exception occurred while fetching "
                    f"indicators. Cause: {exp}"
                )
        return indicators
