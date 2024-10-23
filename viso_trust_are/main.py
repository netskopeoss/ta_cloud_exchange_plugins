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
ARE VISO TRUST Plugin.
"""

from itertools import chain, groupby
from operator import attrgetter
import traceback
import re
from typing import Dict, Iterable, List, Optional, Tuple
from urllib.parse import urlparse

from netskope.integrations.grc.models.configuration import (
    MappingType,
    TargetMappingFields,
)
from netskope.integrations.grc.models.application import Application
from netskope.integrations.grc.plugin_base import (
    PluginBase,
    PushResult,
    ValidationResult,
)
from .utils.constants import (
    MODULE_NAME,
    PLATFORM_NAME,
    PLUGIN_VERSION,
    PLUGIN_NAME,
)
from .utils.helper import VisoTrustPluginHelper, VisoTrustException

from .utils.models import (
    CCLTag,
    CCL_THRESHOLDS,
    RelationshipCreateUpdateInput,
    TagsCreateInput,
    PublicRelationshipSearchInput,
)
from .lib.tldextract import TLDExtract


class VisoTrustPlugin(PluginBase):
    """VisoTrustPlugin Class."""

    def __init__(
        self,
        name,
        *args,
        **kwargs,
    ):
        """VISO TRUST plugin initializer.

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
        self.viso_trust_helper = VisoTrustPluginHelper(
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
            manifest_json = VisoTrustPlugin.metadata
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

    def vendor_cci(
        self, apps: Iterable[Application]
    ) -> tuple[int, Optional[float]]:
        """Vendor CCI.

        Args:
            apps (Iterable[Application]): Applications.

        Returns:
            tuple[int, Optional[float]]: Tuple of count and average CCI.
        """
        has_one = False
        count = 0.0
        total = 0
        for app in apps:
            count += 1
            total += app.cci or 0
            has_one = has_one or app.cci is not None
        return (int(count), total / count if has_one else None)

    def cci_to_ccl(self, cci: Optional[float]) -> CCLTag:
        """CCI to CCL.

        Args:
            cci (Optional[float]): CCI value.

        Returns:
            CCLTag: CCL tag based on CCI.
        """
        if cci is None:
            return CCLTag.UNKNOWN
        for n, tag in CCL_THRESHOLDS:
            if cci <= n:
                return tag
        return CCLTag.EXCELLENT

    def app_domain(self, app: Application) -> str:
        """App Domain.

        Args:
            app (Application): Application.

        Returns:
            str: Finds the domain of the application.
        """
        try:
            return app.steeringDomains[0]
        except IndexError:
            try:
                return app.discoveryDomains[0]
            except IndexError:
                return None

    def push(self, applications: List[Application], mapping) -> PushResult:
        """Push relationships to VISO TRUST.

        Args:
            applications (List[Application]): List of applications.
            mapping (Any): Mapping.

        Returns:
            PushResult: Push result with success flag and message.
        """
        applications = sorted(
            (x for x in applications if x.vendor), key=attrgetter("vendor")
        )
        base_url = self.configuration.get("base_url", "").strip().strip("/")
        failed, skipped, already_exists = 0, 0, 0
        updated, created = 0, 0
        tldextract = TLDExtract()
        token = self.configuration.get("token")
        headers = {
            "Authorization": f"Bearer {token}",
            'Content-Type': 'application/json; charset=utf-8',
        }
        self.logger.info(
            f"{self.log_prefix}: Initializing the sharing of {len(applications)} "
            f"applications to {PLATFORM_NAME}. Applications will be "
            "grouped on the basis of vendors."
        )

        email = self.configuration.get("email").strip().strip("/")
        vendor_count = 0
        for vendor, apps in groupby(applications, attrgetter("vendor")):
            vendor_count += 1
            try:
                app = next(apps)
                (count, cci) = self.vendor_cci(chain([app], apps))
                if count == 0:
                    # Skipped as no apps found for the vendor
                    skipped += 1
                    continue
                ccl = self.cci_to_ccl(cci)
                domain = self.app_domain(app)

                if domain:
                    domain = "https://" + tldextract(domain).registered_domain
                else:
                    # Skipped as no domain available
                    skipped += 1
                    continue

                create = RelationshipCreateUpdateInput(
                    name=vendor,
                    homepage=domain,
                    tags=[ccl],
                    businessOwnerEmail=email,
                )
                hosts = set()
                for domain in set(app.steeringDomains) | set(
                    app.discoveryDomains
                ):
                    hosts.add(tldextract(domain).registered_domain)
                self.logger.debug(
                    f"{self.log_prefix}: Set of domains associated "
                    f"with the vendor '{vendor}': {hosts}"
                )

                existing_json = self.viso_trust_helper.api_helper(
                    method="GET",
                    url=f"{base_url}/api/v1/relationships/search",
                    headers=headers,
                    data=PublicRelationshipSearchInput(
                        name=create.name, domains=list(hosts)
                    ).json(),
                    verify=self.ssl_validation,
                    proxies=self.proxy,
                    is_handle_error_required=True,
                    logger_msg=(
                        f"getting existing relationship from {PLATFORM_NAME} for the vendor '{vendor}'"
                    ),
                )
                matches = list(
                    sorted(
                        existing_json,
                        key=lambda m: len(
                            [t for t in m["tags"] if t.startswith("CCI")]
                        ),
                        reverse=True,
                    )
                )
                status = matches[0].get('status', '') if matches else None
                if not matches or status == 'DELETED':
                    # Create a relationship if not already existing
                    resp = self.viso_trust_helper.api_helper(
                        method="POST",
                        url=f"{base_url}/api/v1/relationships",
                        headers=headers,
                        data=create.json(),
                        verify=self.ssl_validation,
                        proxies=self.proxy,
                        is_handle_error_required=False,
                        logger_msg=(
                            f"sharing vendor '{vendor}' with domain '{domain}'"
                        ),
                    )
                    if 200 <= resp.status_code <= 299:
                        created += 1
                        continue
                    else:
                        self.viso_trust_helper.handle_error(
                            resp=resp,
                            logger_msg=f"sharing vendor '{vendor}' with domain '{domain}'",  # noqa
                            is_validation=False,
                        )
                        failed += 1
                        continue
                domain = matches[0].get('homepage', '') if matches else None
                if create.tags and set(create.tags) <= set(matches[0].get("tags", [])):
                    self.logger.info(
                        f"{self.log_prefix}: Skipping updating of vendor '{vendor}' "
                        f"with domain '{domain}' to {PLATFORM_NAME} "
                        "as relationship with the same CCI tags already exists."  # noqa
                    )
                    # Log for already exists
                    # No changes in the CCI found hence skip the update.
                    already_exists += 1
                    continue

                self.logger.debug(
                    f"{self.log_prefix}: Updating the vendor '{vendor}' with domain '{domain}' to {PLATFORM_NAME} as the relationship already exists but CCI tags are updated."
                )
                update = self.viso_trust_helper.api_helper(
                    method="PATCH",
                    url=f"{base_url}/api/v1/relationships",
                    headers=headers,
                    data=RelationshipCreateUpdateInput(
                        id=matches[0].get("id", ""),
                        tags=create.tags,
                        homepage=domain,
                        businessOwnerEmail=email,
                        name=create.name,
                    ).json(),
                    verify=self.ssl_validation,
                    proxies=self.proxy,
                    is_handle_error_required=False,
                    logger_msg=(
                        f"updating vendor '{vendor}' with domain '{domain}'"
                    ),
                )
                if 200 <= update.status_code <= 299:
                    updated += 1
                else:
                    self.viso_trust_helper.handle_error(
                        resp=update,
                        logger_msg=f"updating vendor '{vendor}' with domain '{domain}'",  # noqa
                        is_validation=False,
                    )
                    failed += 1

            except VisoTrustException as err:
                failed += 1
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: Unable to share vendor '{vendor}' to "
                        f"{PLATFORM_NAME}. Error: {err}"
                    ),
                    details=str(traceback.format_exc()),
                )
                continue
            except Exception as exp:
                failed += 1
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: Unexpected error occurred while "
                        f"sharing vendor '{vendor}' to {PLATFORM_NAME}. "
                        f"Error: {exp}"
                    ),
                    details=str(traceback.format_exc()),
                )
                continue
        skip_log = f"{self.log_prefix}: Total {vendor_count} unique vendor(s) found for {len(applications)} application(s)."
        if skipped > 0:
            skip_log = skip_log + (
                f" Skipped sharing of {skipped} vendor(s)"
                f" to {PLATFORM_NAME} as no domain found associated with their vendors."
            )
        if already_exists > 0:
            skip_log = skip_log + (
                f" Skipped updating {already_exists} vendor(s) on {PLATFORM_NAME} platform "
                "as relationship with the same vendor already exists with the same CCI tags."
            )
        if failed > 0:
            skip_log = skip_log + (
                f" Failed to Create or Update {failed} "
                f"vendor(s) on the {PLATFORM_NAME} platform due to some exceptions."
            )
        self.logger.info(skip_log)
        logger_msg = (
            f"Successfully created application(s): {created}, successfully updated "
            f"application(s): {updated} on the {PLATFORM_NAME} platform."
        )
        self.logger.info(f"{self.log_prefix}: {logger_msg}")

        return PushResult(
            success=True,
            message=logger_msg,
        )

    def _validate_url(self, url: str) -> bool:
        """Validate the URL using parsing.

        Args:
            url (str): Given URL.

        Returns:
            bool: True or False { Valid or not Valid URL }.
        """
        parsed_url = urlparse(url)
        return parsed_url.scheme and parsed_url.netloc

    def validate_email(self, email):
        """Validate email using pydantic EmailStr."""
        try:
            email_regex = r"(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)"
            if re.match(email_regex, email):
                return True
            else:
                return False
        except Exception:
            return False

    def _validate_connectivity(
        self, base_url: str, token: str
    ) -> ValidationResult:
        """Validate connectivity with VISO TRUST.

        Args:
            base_url (str): Base URL.
            token (str): Token.

        Returns:
            ValidationResult: ValidationResult object with success flag
            and message.
        """
        api_endpoint = f"{base_url}/api/v1/tags"
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        }
        data = TagsCreateInput(
            tags=[
                CCLTag.UNKNOWN,
                CCLTag.POOR,
                CCLTag.LOW,
                CCLTag.MEDIUM,
                CCLTag.HIGH,
                CCLTag.EXCELLENT,
            ]
        ).json()
        try:
            logger_msg = "validating connectivity with VISO TRUST."
            resp = self.viso_trust_helper.api_helper(
                method="POST",
                url=api_endpoint,
                headers=headers,
                data=data,
                verify=self.ssl_validation,
                proxies=self.proxy,
                is_handle_error_required=False,
                is_validation=True,
                logger_msg=logger_msg,
            )

            if 200 <= resp.status_code <= 299:
                return ValidationResult(
                    success=True, message="Validation successful."
                )
            else:
                self.viso_trust_helper.handle_error(
                    resp=resp,
                    logger_msg=logger_msg,
                    is_validation=True,
                )
        except VisoTrustException as exp:
            return ValidationResult(
                success=False,
                message=str(exp)
            )
        except Exception as exp:
            err_msg = "Unexpected validation error occurred."
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {exp}",
                details=str(traceback.format_exc()),
            )
            return ValidationResult(
                success=False,
                message=f"{err_msg} Check logs for more details.",
            )

    def validate(self, configuration: Dict) -> ValidationResult:
        """
        Validate the Plugin configuration parameters.

        Args:
            configuration (dict): Plugin configuration parameters.

        Returns:
            ValidateResult: ValidateResult object with success
            flag and message.
        """
        # Validate VISO TRUST URL.
        viso_trust_url = configuration.get("base_url", "").strip().strip("/")
        if not viso_trust_url:
            err_msg = "VISO TRUST Base URL is a required configuration parameter."
            self.logger.error(
                f"{self.log_prefix}: Validation error occurred. {err_msg}"
            )
            return ValidationResult(success=False, message=err_msg)

        elif not (
            isinstance(viso_trust_url, str)
            and self._validate_url(viso_trust_url)
        ):
            err_msg = (
                "Invalid VISO TRUST Base URL provided in the configuration parameters."
            )
            self.logger.error(
                f"{self.log_prefix}: Validation error occurred. {err_msg}"
            )
            return ValidationResult(success=False, message=err_msg)

        # Validate VISO TRUST Business Owner Email.
        email_param_label = "VISO TRUST Business Owner Email"
        email = configuration.get("email", "").strip().strip("/")
        if not email:
            err_msg = (
                f"{email_param_label} is a required configuration parameter."
            )
            self.logger.error(
                f"{self.log_prefix}: Validation error occurred. {err_msg}"
            )
            return ValidationResult(success=False, message=err_msg)

        elif not isinstance(email, str) or not self.validate_email(email):
            err_msg = (
                f"Invalid {email_param_label} provided in "
                "the configuration parameters."
            )
            self.logger.error(
                f"{self.log_prefix}: Validation error occurred. {err_msg}"
            )
            return ValidationResult(success=False, message=err_msg)

        # Validate VISO TRUST API Token.
        token_param_label = "VISO TRUST API Token"
        token = configuration.get("token")
        if not token:
            err_msg = (
                f"{token_param_label} is a required configuration parameter."
            )
            self.logger.error(
                f"{self.log_prefix}: Validation error occurred. {err_msg}"
            )
            return ValidationResult(success=False, message=err_msg)

        elif not isinstance(token, str):
            err_msg = (
                f"Invalid {token_param_label} provided in "
                "the configuration parameters."
            )
            self.logger.error(
                f"{self.log_prefix}: Validation error occurred. {err_msg}"
            )
            return ValidationResult(success=False, message=err_msg)

        return self._validate_connectivity(
            base_url=viso_trust_url, token=token
        )

    def get_target_fields(self, plugin_id, plugin_parameters):
        """Get available Target fields."""
        return [
            TargetMappingFields(
                label="Company Name",
                type=MappingType.STRING,
                value="name",
            )
        ]
