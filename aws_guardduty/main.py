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

AWS GuardDuty CTE Plugin.
"""

import textwrap
from cryptography import x509
from cryptography.hazmat.primitives import serialization

from datetime import datetime, timedelta
import traceback
from typing import Dict, List, Tuple


from netskope.integrations.cte.models import SeverityType
from netskope.integrations.cte.models.indicator import Indicator, IndicatorType
from netskope.integrations.cte.models.tags import TagIn
from netskope.integrations.cte.plugin_base import PluginBase, ValidationResult
from netskope.integrations.cte.utils import TagUtils
from netskope.common.utils import add_user_agent

from pydantic import ValidationError

from .lib.botocore.exceptions import NoCredentialsError
from .utils.exceptions import AWSGuardDutyException
from .utils.client import AWDGuardDutyClient
from .utils.validator import AWSGuardDutyValidator
from .utils.constants import (
    PLUGIN_NAME,
    MODULE_NAME,
    PLUGIN_VERSION,
    TAG_PREFIX,
    DATE_FORMAT,
)


class GuardDutyPlugin(PluginBase):
    """AWS GuardDutyPlugin Class."""

    def __init__(
        self,
        name,
        *args,
        **kwargs,
    ):
        """GuardDuty plugin initializer.

        Args:
            name (str): Plugin configuration name.
        """
        super().__init__(
            name,
            *args,
            **kwargs,
        )
        self.plugin_name, self.plugin_version = self._get_plugin_info()
        self.log_prefix = f"{MODULE_NAME} {self.plugin_name}"
        if name:
            self.log_prefix = f"{self.log_prefix} [{name}]"

    def _get_plugin_info(self) -> Tuple:
        """Get plugin name and version from manifest.

        Returns:
            tuple: Tuple of plugin's name and version fetched from manifest.
        """
        try:
            manifest_json = GuardDutyPlugin.metadata
            plugin_name = manifest_json.get("name", PLUGIN_NAME)
            plugin_version = manifest_json.get("version", PLUGIN_VERSION)
            return plugin_name, plugin_version
        except Exception as exp:
            self.logger.error(
                message=(
                    "{} {}: Error occurred while"
                    " getting plugin details. Error: {}".format(
                        MODULE_NAME, PLUGIN_NAME, exp
                    )
                ),
                details=traceback.format_exc(),
            )
        return (PLUGIN_NAME, PLUGIN_VERSION)

    def _add_user_agent(self, header=None) -> str:
        """Add User-Agent to any request.

        Args:
            header: Headers needed to pass to the Third Party Platform.

        Returns:
            str: String containing user agent.
        """
        header = add_user_agent(header)
        ce_added_agent = header.get("User-Agent", "netskope-ce")
        user_agent = "{}-{}-{}-v{}".format(
            ce_added_agent,
            MODULE_NAME.lower(),
            self.plugin_name.lower().replace(" ", "-"),
            self.plugin_version,
        )
        return user_agent

    def reformat_encrypted_certificate(
        self, certificate: str, header: str, footer: str
    ) -> str:
        """Reformat the private key.

        Args:
            private_key (str): Private Key

        Returns:
            str: Reformed private key.
        """
        body_lines = (
            certificate.strip().replace(header, "").replace(footer, "")
        )

        lines = body_lines.splitlines()
        lines = [line.strip() for line in lines if line]
        # Reformat the body using 64 characters per line
        body = textwrap.fill("".join(lines), 64)

        # Reassemble the full key with a single header and footer
        formatted_key = f"{header}\n{body}\n{footer}"
        return formatted_key

    def validate(self, configuration: dict) -> ValidationResult:
        """Validate the configurations of plugin.

        Args:
            configuration (dict): Configuration dictionary.

        Returns:
            ValidationResult: ValidationResult pydantic model.
        """
        aws_validator = AWSGuardDutyValidator(
            configuration,
            self.logger,
            self.proxy,
            self.storage,
            self.log_prefix,
            self._add_user_agent(),
        )
        # Validate Authentication Method
        authentication_method = configuration.get(
            "authentication_method", ""
        ).strip()
        if not authentication_method:
            err_msg = (
                "Authentication Method is a required configuration parameter."
            )
            self.logger.error(
                f"{self.log_prefix}: Validation error occurred. "
                f"Error: {err_msg}"
            )
            return ValidationResult(success=False, message=err_msg)
        if authentication_method not in [
            "aws_iam_roles_anywhere",
            "deployed_on_aws",
        ]:
            error_msg = (
                "Invalid value for Authentication Method provided. "
                "Allowed values are "
                "'AWS IAM Roles Anywhere' or 'Deployed on AWS'."
            )
            self.logger.error(
                f"{self.log_prefix}: Validation error occurred."
                f" Error: {error_msg}"
            )
            return ValidationResult(
                success=False,
                message=f"{error_msg}",
            )
        if authentication_method == "aws_iam_roles_anywhere":
            pass_phrase = configuration.get("pass_phrase")
            if not pass_phrase:
                err_msg = (
                    "Password Phrase is a required configuration parameter"
                    " when 'AWS IAM Roles Anywhere' is selected as "
                    "Authentication Method."
                )
                self.logger.error(
                    f"{self.log_prefix}: Validation error occurred. "
                    f"Error: {err_msg}"
                )
                return ValidationResult(
                    success=False,
                    message=f"{err_msg}",
                )
            elif not isinstance(pass_phrase, str):
                self.logger.error(
                    f"{self.log_prefix}: Validation error occurred. "
                    "Error: Invalid Password Phrase found in the "
                    "configuration parameters."
                )
                return ValidationResult(
                    success=False,
                    message="Invalid Password Phrase provided.",
                )
            # Validate Private Key File.
            private_key_file = configuration.get(
                "private_key_file", ""
            ).strip()
            if not private_key_file:
                error_msg = (
                    "Private Key is a required configuration parameter"
                    " when 'AWS IAM Roles Anywhere' is selected as "
                    "Authentication Method."
                )
                self.logger.error(
                    f"{self.log_prefix} Validation error occurred. Error: "
                    f"{error_msg}"
                )
                return ValidationResult(
                    success=False,
                    message=f"{error_msg}",
                )
            elif not isinstance(private_key_file, str):
                self.logger.error(
                    f"{self.log_prefix}: Validation error occurred. "
                    "Error: Invalid Private Key found in the "
                    "configuration parameters."
                )
                return ValidationResult(
                    success=False,
                    message="Invalid Private Key provided.",
                )
            else:
                try:

                    private_key_file = self.reformat_encrypted_certificate(
                        certificate=private_key_file,
                        header="-----BEGIN ENCRYPTED PRIVATE KEY-----",
                        footer="-----END ENCRYPTED PRIVATE KEY-----",
                    )
                    configuration["private_key_file"] = private_key_file
                    serialization.load_pem_private_key(
                        private_key_file.encode("utf-8"), None
                    )
                except Exception:
                    try:
                        serialization.load_pem_private_key(
                            private_key_file.encode("utf-8"),
                            password=str.encode(pass_phrase),
                        )
                    except Exception:
                        err_msg = (
                            "Invalid Private Key or Password Phrase provided."
                            " Private Key should be in a valid PEM format."
                        )
                        self.logger.error(
                            message=(
                                f"{self.log_prefix}: Validation error "
                                f"occurred. Error: {err_msg}"
                            ),
                            details=traceback.format_exc(),
                        )
                        return ValidationResult(
                            success=False,
                            message=f"{err_msg}",
                        )

            # Validate Certificate Body.

            public_certificate_file = configuration.get(
                "public_certificate_file", ""
            ).strip()

            if not public_certificate_file:
                error_msg = (
                    "Certificate Body is a required configuration"
                    " parameter when 'AWS IAM Roles Anywhere' "
                    "is selected as Authentication Method."
                )
                self.logger.error(
                    f"{self.log_prefix} Validation error occurred. Error: "
                    f"{error_msg}"
                )
                return ValidationResult(
                    success=False,
                    message=f"{error_msg}",
                )
            elif not isinstance(public_certificate_file, str):
                self.logger.error(
                    f"{self.log_prefix}: Validation error occurred. Error: "
                    "Invalid Certificate Body found in "
                    "the configuration parameters."
                )
                return ValidationResult(
                    success=False,
                    message="Invalid Certificate Body provided.",
                )
            else:
                public_certificate_file = self.reformat_encrypted_certificate(
                    certificate=public_certificate_file,
                    header="-----BEGIN CERTIFICATE-----",
                    footer="-----END CERTIFICATE-----",
                )
                configuration["public_certificate_file"] = (
                    public_certificate_file
                )
                try:
                    x509.load_pem_x509_certificate(
                        public_certificate_file.encode()
                    )
                except Exception:
                    err_msg = (
                        "Invalid Certificate Body provided. "
                        "Certificate Body should be in valid Pem Format."
                    )
                    self.logger.error(
                        message=(
                            f"{self.log_prefix}: Validation error occurred. "
                            f"Error: {err_msg}"
                        ),
                        details=str(traceback.format_exc()),
                    )
                    return ValidationResult(
                        success=False,
                        message=f"{err_msg}",
                    )

            # Validate Profile ARN.
            profile_arn = configuration.get("profile_arn", "").strip()
            if not profile_arn:
                error_msg = (
                    "Profile ARN is a required configuration parameter when "
                    "'AWS IAM Roles Anywhere' is selected as "
                    "Authentication Method."
                )
                self.logger.error(
                    f"{self.log_prefix}: Validation error occurred. Error: "
                    f"{error_msg}"
                )
                return ValidationResult(success=False, message=f"{error_msg}")
            elif not isinstance(profile_arn, str):
                self.logger.error(
                    f"{self.log_prefix}: Validation error occurred. Error: "
                    "Invalid Profile ARN found in the "
                    "configuration parameters."
                )
                return ValidationResult(
                    success=False, message="Invalid Profile ARN provided."
                )

            # Validate Role ARN.
            role_arn = configuration.get("role_arn", "").strip()
            if not role_arn:
                error_msg = (
                    "Role ARN is a required configuration parameter when "
                    "'AWS IAM Roles Anywhere' is selected as "
                    "Authentication Method."
                )
                self.logger.error(
                    f"{self.log_prefix}: Validation error occurred. Error: "
                    f"{error_msg}"
                )
                return ValidationResult(success=False, message=f"{error_msg}")

            elif not isinstance(role_arn, str):
                self.logger.error(
                    f"{self.log_prefix}: Validation error occurred. Error: "
                    f"Invalid Role ARN found in the configuration parameters."
                )
                return ValidationResult(
                    success=False, message="Invalid Role ARN provided."
                )

            # Validate Trust Anchor ARN.
            trust_anchor_arn = configuration.get(
                "trust_anchor_arn", ""
            ).strip()
            if not trust_anchor_arn:
                error_msg = (
                    "Trust Anchor ARN is a required configuration parameter "
                    "when 'AWS IAM Roles Anywhere' is selected as "
                    "Authentication Method."
                )
                self.logger.error(
                    f"{self.log_prefix}: Validation error occurred. Error: "
                    f"{error_msg}"
                )
                return ValidationResult(success=False, message=f"{error_msg}")

            elif not isinstance(trust_anchor_arn, str):
                self.logger.error(
                    f"{self.log_prefix}: Validation error occurred. Error: "
                    "Invalid Trust Anchor ARN found in the "
                    "configuration parameters."
                )
                return ValidationResult(
                    success=False, message="Invalid Trust Anchor ARN provided."
                )

        # Validate Region Name.
        region_name = configuration.get("region_name", "").strip()
        if not region_name:
            error_msg = "Region Name is a required configuration parameter."
            self.logger.error(
                f"{self.log_prefix}: Validation error occurred. "
                f"Error: {error_msg}"
            )
            return ValidationResult(success=False, message=error_msg)
        elif not (
            isinstance(region_name, str)
            and aws_validator.validate_region_name(region_name)
        ):
            error_msg = (
                "Invalid Region Name found in the configuration parameters."
            )
            self.logger.error(
                f"{self.log_prefix}: Validation error occurred."
                f" Error: {error_msg}"
            )
            return ValidationResult(success=False, message=error_msg)

        # Validate Detector ID.
        detection_id = configuration.get("aws_detector_id", "").strip()
        if not detection_id:
            err_msg = "Detector ID is a required configuration parameter."
            self.logger.error(
                f"{self.log_prefix}: Validation error occurred. "
                f"Error: {err_msg}"
            )
            return ValidationResult(
                success=False,
                message=f"{err_msg}",
            )
        elif not isinstance(detection_id, str):
            err_msg = (
                "Invalid Detector ID found in the configuration parameters."
            )
            self.logger.error(
                f"{self.log_prefix}: Validation error occurred. {err_msg}"
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )

        # Validate Initial Range
        days = configuration.get("days")
        if days is None:
            err_msg = "Initial Range is a required configuration parameter."
            self.logger.error(
                f"{self.log_prefix}: Validation error occurred. {err_msg}"
            )
            return ValidationResult(success=False, message=err_msg)
        elif not isinstance(days, int) or days < 0:
            err_msg = (
                "Invalid Initial Range provided in configuration parameters."
                " Valid value should be an integer greater than zero."
            )
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        elif days > 4611686018427387904:
            err_msg = (
                "Invalid Initial Range provided in configuration"
                " parameters. Valid value should be less than 2^62."
            )
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        try:
            aws_client = AWDGuardDutyClient(
                configuration,
                self.logger,
                self.proxy,
                self.storage,
                self.log_prefix,
                self._add_user_agent(),
            )
            aws_client.set_credentials()
            aws_validator.validate_credentials(aws_client)
            guardduty_client = aws_client.get_aws_client()
        except AWSGuardDutyException as exp:
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Validation error occurred. {exp}"
                ),
                details=traceback.format_exc(),
            )
            return ValidationResult(
                success=False,
                message=f"Validation error occurred. {exp}",
            )
        except Exception as exp:
            self.logger.error(
                message=f"{self.log_prefix}: Authentication Failed. {exp}",
                details=traceback.format_exc(),
            )
            return ValidationResult(
                success=False,
                message="Authentication Failed. Check logs for more details.",
            )
        try:
            findings = guardduty_client.list_findings(
                DetectorId=detection_id,
                MaxResults=1,
                SortCriteria={"AttributeName": "updatedAt", "OrderBy": "ASC"},
            )
            finding_ids = findings.get("FindingIds", [])
            guardduty_client.get_findings(
                DetectorId=detection_id,
                FindingIds=finding_ids,
            )
        except NoCredentialsError as exp:
            err_msg = (
                "Unable to find the credentials from the host machine."
                " Verify the role attached to instance."
            )
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Validation error"
                    f" occurred, Error: {exp}"
                ),
                details=traceback.format_exc(),
            )
            return ValidationResult(success=False, message=err_msg)

        except Exception as exp:
            err_msg = ""
            if "AccessDeniedException" in str(exp):
                msg = (
                    "Certificates"
                    if authentication_method == "aws_iam_roles_anywhere"
                    else "IAM Role attached to the instance."
                )
                err_msg = (
                    "Access Denied, Verify the permissions provided"
                    f" to {msg}"
                )
            elif "BadRequestException" in str(exp):
                err_msg = (
                    "Bad Request, Verify Detector ID and Region Name provided"
                    " in the configuration parameters."
                )
            else:
                err_msg = (
                    "Validation error occurred. Check logs for more details."
                )
            self.logger.error(
                message=(
                    f"{self.log_prefix}: Validation error occurred. {exp}"
                ),
                details=traceback.format_exc(),
            )
            return ValidationResult(
                success=False,
                message=err_msg,
            )
        return ValidationResult(success=True, message="Validation successful.")

    def _create_tags(self, tags: List) -> tuple:
        """Create Tags.

        Args:
            tags (List): Tags list from API Response.

        Returns:
            tuple: Tuple of created tags and skipped tags.
        """
        tag_utils = TagUtils()
        created_tags, skipped_tags = set(), set()
        for tag_name in tags:
            try:
                if not tag_name:
                    continue
                tag_name = f"{TAG_PREFIX}-{tag_name}"
                if not tag_utils.exists(tag_name):
                    tag_utils.create_tag(TagIn(name=tag_name, color="#ED3347"))
                created_tags.add(tag_name)
            except ValueError:
                skipped_tags.add(tag_name)
            except Exception as exp:
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: Unexpected error occurred"
                        f" while creating tag {tag_name}. Error: {exp}"
                    ),
                    details=str(traceback.format_exc()),
                )
                skipped_tags.add(tag_name)

        return list(created_tags), list(skipped_tags)

    def map_severity(self, severity: int) -> str:
        """Map Severity.

        Args:
            severity (int): Severity received from AWS GuardDuty.

        Returns:
            str: Mapped severity level.
        """
        if severity is None:
            return SeverityType.UNKNOWN
        if severity < 1:
            return SeverityType.UNKNOWN
        elif severity < 4:
            return SeverityType.LOW
        elif severity < 7:
            return SeverityType.MEDIUM
        elif severity < 9:
            return SeverityType.HIGH
        elif severity < 10:
            return SeverityType.CRITICAL
        return SeverityType.UNKNOWN

    def _get_private_public_tags(self, NetworkInterfaces: List) -> List:
        """Get Private and public tags.

        Args:
            NetworkInterfaces (List): List of Network interfaces.

        Returns:
            List: List of created tags.
        """
        tags = set()
        for tag in NetworkInterfaces:
            if "PrivateIpAddress" in tag.keys():
                tags.add("private")

            if "PublicIp" in tag.keys():
                tags.add("public")
        return list(tags)

    def get_sha256_indicators(self, finding: Dict) -> List:
        """Get indicators from findings.

        Args:
            finding (Dict): Finding dictionary fetched from AWS GuardDuty.

        Returns:
            List: List of indicators.
        """
        indicators = []
        skip_counts = 0
        severity = (
            finding.get("Service", {})
            .get("EbsVolumeScanDetails", {})
            .get("ScanDetections", {})
            .get("HighestSeverityThreatDetails", {})
            .get("Severity", "unknown")
        )
        if isinstance(severity, str) and severity.lower() in [
            "unknown",
            "low",
            "medium",
            "high",
            "critical",
        ]:
            severity = severity.lower()
        else:
            severity = SeverityType.UNKNOWN
        tags, skipped_tags = [], []
        sources = (
            finding.get("Service", {})
            .get("EbsVolumeScanDetails", {})
            .get("Sources", [])
        )
        sources += self._get_private_public_tags(
            finding.get("Resource", {})
            .get("InstanceDetails", {})
            .get("NetworkInterfaces", [])
        )
        source_tags, source_skipped_tags = self._create_tags(sources)
        tags += source_tags
        skipped_tags += source_skipped_tags

        for files in (
            finding.get("Service", {})
            .get("EbsVolumeScanDetails", {})
            .get("ScanDetections", {})
            .get("ThreatDetectedByName", {})
            .get("ThreatNames", [])
        ):
            for filepath in files.get("FilePaths", []):
                arn = finding.get("Arn", "Not Found")
                trigger_finding_id = (
                    finding.get("Service", {})
                    .get("EbsVolumeScanDetails", {})
                    .get("TriggerFindingId", "Not Found")
                )
                filename = filepath.get("FileName", "Not Found")
                fpath = filepath.get("FilePath", "Not Found")
                description = finding.get("Description", "Not Found")
                try:
                    indicators.append(
                        Indicator(
                            value=filepath.get("Hash"),
                            type=IndicatorType.SHA256,
                            firstSeen=finding.get("Service", {}).get(
                                "EventFirstSeen"
                            ),
                            lastSeen=finding.get("Service", {}).get(
                                "EventLastSeen"
                            ),
                            severity=severity,
                            tags=tags,
                            comments=(
                                f"Finding Arn: {arn}, "
                                f"TriggerFindingId: {trigger_finding_id}, "
                                f"Name: {filename}, "
                                f"Filepath: {fpath}, "
                                f"Description: {description}"
                            ),
                        )
                    )
                except (ValidationError, Exception) as error:
                    error_message = (
                        "Validation error occurred"
                        if isinstance(error, ValidationError)
                        else "Unexpected error occurred"
                    )
                    self.logger.error(
                        message=(
                            f"{self.log_prefix}: {error_message} while "
                            f"creating indicator finding ARN: {arn} Hence "
                            f"skipping this indicator. Error: {error}"
                        ),
                        details=traceback.format_exc(),
                    )
                    skip_counts += 1

        return indicators, skipped_tags, skip_counts

    def get_network_connection_indicators(
        self, finding: Dict
    ) -> Tuple[Indicator, List, int]:
        """Get IPv4 addresses from NetworkConnectionAction findings.

        Args:
            finding (Dict): Finding dictionary fetched from AWS GuardDuty.

        Returns:
            Tuple[Indicator, List, int]: Tuple of indicator, skipped tags
            and skip counts.
        """

        url_value = (
            finding.get("Service", {})
            .get("Action", {})
            .get("NetworkConnectionAction", {})
            .get("RemoteIpDetails", {})
            .get("IpAddressV4")
        )
        if not url_value:
            return []

        severity = self.map_severity(finding.get("Severity"))
        first_seen = finding.get("Service", {}).get("EventFirstSeen")
        last_seen = finding.get("Service", {}).get("EventLastSeen")
        arn = finding.get("Arn", "Not Found")
        comment = (
            f"Finding ARN: {arn},"
            f" Finding Type: {finding.get('Type', 'Not Found')},"
            f" Description: {finding.get('Description')}"
        )
        tags = []
        net_tags = (
            finding.get("Resource", {})
            .get("InstanceDetails", {})
            .get("Tags", [])
        )
        new_tags = [tag.get("Value") for tag in net_tags]
        is_blocked = (
            finding.get("Service", {})
            .get("Action", {})
            .get("NetworkConnectionAction", {})
            .get("Blocked")
        )
        # If Blocked is true add the tag NetworkConnectionAction:Blocked
        if is_blocked:
            new_tags.append("NetworkConnectionAction:Blocked")

        # Get private/public tags
        new_tags += self._get_private_public_tags(
            finding.get("Resource", {})
            .get("InstanceDetails", {})
            .get("NetworkInterfaces", [])
        )
        created_tags, skipped_tags = self._create_tags(new_tags)
        tags += created_tags
        is_blocked = (
            finding.get("Service", {})
            .get("Action", {})
            .get("NetworkConnectionAction", {})
            .get("Blocked")
        )

        try:
            return (
                Indicator(
                    value=url_value,
                    type=IndicatorType.URL,
                    firstSeen=first_seen,
                    lastSeen=last_seen,
                    severity=severity,
                    tags=tags,
                    comments=comment,
                ),
                skipped_tags,
                0,
            )
        except (ValidationError, Exception) as error:
            error_message = (
                "Validation error occurred"
                if isinstance(error, ValidationError)
                else "Unexpected error occurred"
            )
            self.logger.error(
                message=(
                    f"{self.log_prefix}: {error_message} while "
                    f"creating indicator finding ARN: {arn} Hence "
                    f"skipping this indicator. Error: {error}"
                ),
                details=traceback.format_exc(),
            )
            return None, skipped_tags, 1

    def _get_port_probe_indicators(
        self, finding: Dict
    ) -> Tuple[List[Indicator], List, int]:
        """Get IPv4 address from PortProbeAction finding action.

        Args:
            finding (Dict): Finding dictionary fetched from AWS GuardDuty

        Returns:
            Tuple: Tuple of List of indicators, List of skipped tags and
            skip counts.
        """
        indicators = []
        skip_counts = 0
        severity = self.map_severity(finding.get("Severity"))
        first_seen = finding.get("Service", {}).get("EventFirstSeen")
        last_seen = finding.get("Service", {}).get("EventLastSeen")
        arn = finding.get("Arn", "Not Found")
        comment = (
            f"Finding ARN: {arn},"
            f" Finding Type: {finding.get('Type', 'Not Found')},"
            f" Description: {finding.get('Description')}"
        )
        tags = []
        net_tags = (
            finding.get("Resource", {})
            .get("InstanceDetails", {})
            .get("Tags", [])
        )
        net_tags = [tag.get("Value") for tag in net_tags]
        is_blocked = (
            finding.get("Service", {})
            .get("Action", {})
            .get("PortProbeAction", {})
            .get("Blocked")
        )
        if is_blocked:
            net_tags.append("PortProbeAction:Blocked")
        net_tags += self._get_private_public_tags(
            finding.get("Resource", {})
            .get("InstanceDetails", {})
            .get("NetworkInterfaces", [])
        )
        created_tags, skipped_tags = self._create_tags(net_tags)
        tags += created_tags
        for probe in (
            finding.get("Service", {})
            .get("Action", {})
            .get("PortProbeAction", {})
            .get("PortProbeDetails", [])
        ):
            try:
                value = probe.get("RemoteIpDetails", {}).get("IpAddressV4")
                indicators.append(
                    Indicator(
                        value=value,
                        type=IndicatorType.URL,
                        firstSeen=first_seen,
                        lastSeen=last_seen,
                        severity=severity,
                        tags=tags,
                        comments=comment,
                    )
                )

            except (ValidationError, Exception) as error:
                error_message = (
                    "Validation error occurred"
                    if isinstance(error, ValidationError)
                    else "Unexpected error occurred"
                )
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: {error_message} while "
                        f"creating indicator finding ARN: {arn} Hence "
                        f"skipping this indicator. Error: {error}"
                    ),
                    details=traceback.format_exc(),
                )
                skip_counts += 1
        return indicators, skipped_tags, skip_counts

    def get_dns_request_indicators(
        self, finding: Dict
    ) -> Tuple[Indicator, List, int]:
        """Get domains from DnsRequestAction.

        Args:
            finding (Dict): Finding dictionary fetched from AWS GuardDuty.

        Returns:
            Tuple: Tuple of indicator, skipped tags and skip counts.
        """
        url_value = (
            finding.get("Service", {})
            .get("Action", {})
            .get("DnsRequestAction", {})
            .get("Domain")
        )
        if not url_value:
            return []

        severity = self.map_severity(finding.get("Severity"))
        first_seen = finding.get("Service", {}).get("EventFirstSeen")
        last_seen = finding.get("Service", {}).get("EventLastSeen")
        arn = finding.get("Arn", "Not Found")
        comment = (
            f"Finding ARN: {arn},"
            f" Finding Type: {finding.get('Type', 'Not Found')},"
            f" Description: {finding.get('Description')}"
        )
        # Get tags from resource.
        net_tags = (
            finding.get("Resource", {})
            .get("InstanceDetails", {})
            .get("Tags", [])
        )
        net_tags = [tag.get("Value") for tag in net_tags]

        is_blocked = (
            finding.get("Service", {})
            .get("Action", {})
            .get("DnsRequestAction", {})
            .get("Blocked")
        )
        # Set DNSRequestAction:Blocked tag.
        if is_blocked:
            net_tags.append("DnsRequestAction:Blocked")
        net_tags += self._get_private_public_tags(
            finding.get("Resource", {})
            .get("InstanceDetails", {})
            .get("NetworkInterfaces", [])
        )
        created_tags, skipped_tags = self._create_tags(net_tags)
        try:
            return (
                Indicator(
                    value=url_value,
                    type=IndicatorType.URL,
                    firstSeen=first_seen,
                    lastSeen=last_seen,
                    severity=severity,
                    tags=created_tags,
                    comments=comment,
                ),
                skipped_tags,
                0,
            )
        except (ValidationError, Exception) as error:
            error_message = (
                "Validation error occurred"
                if isinstance(error, ValidationError)
                else "Unexpected error occurred"
            )
            self.logger.error(
                message=(
                    f"{self.log_prefix}: {error_message} while "
                    f"creating indicator finding ARN: {arn} Hence "
                    f"skipping this indicator. Error: {error}"
                ),
                details=traceback.format_exc(),
            )
            return None, skipped_tags, 1

    def pull(self) -> List[Indicator]:
        """Pull method.

        Returns:
            List[Indicator]: List of indicators fetched from AWS GuardDuty.

        Yields:
            Iterator[List[Indicator]]: List of indicators.
        """
        # Check for the sub_checkpoint
        self.configuration["private_key_file"] = (
            self.reformat_encrypted_certificate(
                certificate=self.configuration.get(
                    "private_key_file", ""
                ).strip(),
                header="-----BEGIN ENCRYPTED PRIVATE KEY-----",
                footer="-----END ENCRYPTED PRIVATE KEY-----",
            )
        )

        self.configuration["public_certificate_file"] = (
            self.reformat_encrypted_certificate(
                certificate=self.configuration.get(
                    "public_certificate_file", ""
                ).strip(),
                header="-----BEGIN CERTIFICATE-----",
                footer="-----END CERTIFICATE-----",
            )
        )
        if hasattr(self, "sub_checkpoint"):

            def wrapper(self):
                yield from self._pull()

            return wrapper(self)
        else:
            # If no sub_checkpoint is present pull all the indicators
            # from AWS GuardDuty in a sync interval.
            indicators = []
            for batch in self._pull():
                indicators.extend(batch)

            self.logger.info(
                f"{self.log_prefix}: Successfully pulled"
                f" {len(indicators)} indicator(s) from {PLUGIN_NAME}."
            )
            return indicators

    def _pull(self):
        """Pull indicators.

        Returns:
            List[Indicator]: List of pulled indicators.
        """
        page_count = 1
        try:
            client = AWDGuardDutyClient(
                configuration=self.configuration,
                logger=self.logger,
                proxy=self.proxy,
                storage=self.storage,
                log_prefix=self.log_prefix,
                user_agent=self._add_user_agent(),
            )
            client.set_credentials()
            guardduty_client = client.get_aws_client()
            checkpoint = None
            sub_checkpoint = getattr(self, "sub_checkpoint", None)
            if sub_checkpoint:
                checkpoint = sub_checkpoint.get("checkpoint")
            elif not self.last_run_at and not sub_checkpoint:
                # Initial Run
                days = self.configuration["days"]
                checkpoint = datetime.now() - timedelta(days=days)
                self.logger.info(
                    f"{self.log_prefix}: This is initial ran of plugin hence"
                    f" pulling indicators from last {days} days."
                )
            else:
                checkpoint = self.last_run_at

            self.logger.info(
                f"{self.log_prefix}: Pulling indicators from "
                f"{PLUGIN_NAME} using checkpoint: {str(checkpoint)}"
            )
            circuit_breaker_checkpoint = checkpoint
            paginator = guardduty_client.get_paginator("list_findings")
            page_iterator = paginator.paginate(
                DetectorId=self.configuration["aws_detector_id"].strip(),
                FindingCriteria={
                    "Criterion": {
                        "updatedAt": {
                            "Gte": int(checkpoint.timestamp() * 1000),
                        }
                    }
                },
                SortCriteria={"AttributeName": "updatedAt", "OrderBy": "ASC"},
            )
            total_ioc_count = 0
            for page in page_iterator:
                page_skip_counts = 0
                page_iocs, page_skipped_tags = [], []
                page_ioc_counts = {"sha256": 0, "ipv4": 0, "domain": 0}
                try:
                    finding_details = guardduty_client.get_findings(
                        DetectorId=self.configuration.get(
                            "aws_detector_id"
                        ).strip(),
                        FindingIds=page.get("FindingIds", []),  # noqa
                    )
                except Exception as exp:
                    err_msg = (
                        "Error occurred while fetching finding details"
                        f" for page {page_count} from {PLUGIN_NAME}."
                    )
                    self.logger.error(
                        message=f"{self.log_prefix}: {err_msg} Error: {exp}",
                        details=traceback.format_exc(),
                    )
                    raise AWSGuardDutyException(err_msg)
                for finding in finding_details.get("Findings", []):
                    try:
                        updated_at = finding.get("Service", {}).get(
                            "EventLastSeen",
                        )
                        circuit_breaker_checkpoint = (
                            datetime.strptime(updated_at, DATE_FORMAT)
                            if updated_at
                            else datetime.now()
                        )

                        if finding.get("Service", {}).get(
                            "EbsVolumeScanDetails"
                        ):
                            (
                                curr_volume_iocs,
                                curr_vol_skipped_tags,
                                curr_vol_skip_count,
                            ) = self.get_sha256_indicators(finding=finding)
                            page_skip_counts += curr_vol_skip_count
                            page_iocs += curr_volume_iocs
                            page_skipped_tags += curr_vol_skipped_tags
                            page_ioc_counts["sha256"] += len(curr_volume_iocs)

                        if (
                            finding.get("Service", {})
                            .get("Action", {})
                            .get("NetworkConnectionAction")
                        ):
                            (
                                curr_net_conn_ioc,
                                curr_net_skipped_tags,
                                curr_net_skip_count,
                            ) = self.get_network_connection_indicators(finding)
                            if curr_net_conn_ioc:
                                page_iocs.append(curr_net_conn_ioc)
                                page_skipped_tags += curr_net_skipped_tags
                                page_ioc_counts["ipv4"] += 1
                            else:
                                page_skip_counts += curr_net_skip_count
                                page_skipped_tags += curr_net_skipped_tags

                        if (
                            finding.get("Service", {})
                            .get("Action", {})
                            .get("PortProbeAction", {})
                            .get("PortProbeDetails", [])
                        ):
                            (
                                curr_probe_iocs,
                                curr_probe_skipped_tags,
                                curr_prob_skip_count,
                            ) = self._get_port_probe_indicators(finding)
                            page_iocs += curr_probe_iocs
                            page_skipped_tags += curr_probe_skipped_tags
                            page_skip_counts += curr_prob_skip_count
                            page_ioc_counts["ipv4"] += len(curr_probe_iocs)

                        if (
                            finding.get("Service", {})
                            .get("Action", {})
                            .get("DnsRequestAction", {})
                            .get("Domain")
                        ):
                            dns_iocs, dns_skipped_tags, dns_skip_count = (
                                self.get_dns_request_indicators(finding)
                            )
                            if dns_iocs:
                                page_iocs.append(dns_iocs)
                                page_skipped_tags += dns_skipped_tags
                                page_ioc_counts["domain"] += 1
                            else:
                                page_skip_counts += dns_skip_count
                                page_skipped_tags += dns_skipped_tags

                    except Exception as exp:
                        err_msg = (
                            "Error occurred while extracting indicators "
                            " from finding having ARN: "
                            f"{finding.get('Arn','Not Found')}. Error: {exp}"
                        )
                        self.logger.error(
                            message=f"{self.log_prefix}: {err_msg}",
                            details=traceback.format_exc(),
                        )
                        page_skip_counts += 1

                if page_skipped_tags:
                    self.logger.info(
                        (
                            f"{self.log_prefix}: Skipped following tags(s) in"
                            f" page {page_count} because they might be longer"
                            " than expected size or due to some other "
                            f"exceptions that occurred while creating "
                            f"them: {list(page_skipped_tags)}"
                        )
                    )
                sub_checkpoint = getattr(self, "sub_checkpoint", None)
                total_ioc_count += len(page_iocs)
                self.logger.info(
                    f"{self.log_prefix}: Successfully fetched "
                    f"{sum(page_ioc_counts.values())} indicator(s) and skipped"
                    f" {page_skip_counts} indicator(s) in page {page_count}. "
                    f"Pull Stats: SHA256={page_ioc_counts['sha256']}, "
                    f"IPv4={page_ioc_counts['ipv4']}, Domain="
                    f"{page_ioc_counts['domain']}. Total "
                    f"indicator(s) fetched: {total_ioc_count}"
                )
                if hasattr(self, "sub_checkpoint"):
                    yield page_iocs, {
                        "checkpoint": circuit_breaker_checkpoint,
                    }
                else:
                    yield page_iocs
                page_count += 1
        except AWSGuardDutyException as exp:
            err_msg = (
                "Error occurred while "
                f"pulling indicators from {PLUGIN_NAME}."
            )
            self.logger.error(
                message=(f"{self.log_prefix}: {err_msg} Error: {exp}"),
                details=traceback.format_exc(),
            )
            raise AWSGuardDutyException(err_msg)
        except Exception as exp:
            err_msg = (
                "Error occurred while pulling indicators from "
                f"{PLUGIN_NAME}."
            )
            self.logger.error(
                message=(f"{self.log_prefix}: {err_msg} Error: {exp}"),
                details=traceback.format_exc(),
            )
            raise AWSGuardDutyException(err_msg)
