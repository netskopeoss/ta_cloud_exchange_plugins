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

Netskope CFC Helper.
"""

import traceback

from tempfile import gettempdir, mkstemp
from uuid import uuid4

from netskope.common.utils import AlertsHelper, resolve_secret
from netskope.common.utils.exceptions import ForbiddenError
from netskope.integrations.cfc.plugin_base import ValidationResult
from netskope.integrations.cfc.utils import NetskopeClientCFC
from .constants import PLUGIN_NAME


class NetskopeCFCPluginHelper:
    """Helper class for Netskope CFC Plugin."""

    def __init__(self, logger, log_prefix, name):
        """Initialize NetskopeCFCPluginHelper.

        Args:
            logger: Logger object.
            log_prefix (str): Log prefix string.
            name (str): Plugin configuration name.
        """
        self.logger = logger
        self.log_prefix = log_prefix
        self.name = name

    def get_netskope_client(self, tenant=None):
        """
        Get netskope client from the configuration name with validated token.

        Args:
            tenant (Tenant): Tenant object.

        Returns:
            NetskopeClientCFC: NetskopeClientCFC object.
        """
        if tenant:
            self.tenant = tenant
        else:
            helper = AlertsHelper()
            self.tenant = helper.get_tenant_cfc(self.name)

        netskope_client = NetskopeClientCFC(
            tenant_base_url=self.tenant.parameters.get("tenantName"),
            api_token_v2=resolve_secret(self.tenant.parameters.get("v2token")),
            plugin=PLUGIN_NAME,
        )
        return netskope_client

    def validate_configuration_parameters(self, tenant=None):
        """Validate the Plugin configuration parameters.

        Args:
            tenant (Tenant, optional): Tenant object.

        Returns:
            cfc.plugin_base.ValidateResult: ValidateResult object with
            success flag and message.
        """
        self.logger.debug(
            f"{self.log_prefix}: Validating configuration parameters."
        )
        try:
            netskope_client = self.get_netskope_client(tenant)

            # Validating for get custom classifiers api access
            custom_classifiers = netskope_client.all_custom_classifiers(
                customOnly=True, limit=10
            )
            if custom_classifiers.get("customClassifiers"):
                # Validating get custom classifier by id api access
                netskope_client.classifier_by_id(
                    custom_classifiers["customClassifiers"][0]["id"]
                )
                _, temp_file_name = mkstemp(dir=gettempdir(), suffix=".json")
                netskope_client.upload_hash(
                    class_id=custom_classifiers["customClassifiers"][0]["id"],
                    file_path=temp_file_name,
                    ssid=str(uuid4()),
                    sessionend=True,
                )
            else:
                self.logger.info(
                    f"{self.log_prefix}: Validation for the upload hash "
                    "endpoint is skipped as, no custom classifier found "
                    f"on the tenant: '{self.tenant}'."
                )
        except ForbiddenError:
            message = (
                f"{self.log_prefix}: Unable to access classifier endpoints."
                " Add permissions for classifiers to the RBAC V3 token."
            )
            self.logger.error(
                message=message,
                resolution=(
                    "Ensure that the RBAC V3 token has permission to access "
                    "the classifier endpoints."
                )
            )
            return ValidationResult(success=False, message=message)
        except Exception as error:
            message = (
                f"{self.log_prefix}: Error occurred while validating "
                f"configuration parameters. Error: {str(error)}"
            )
            self.logger.error(
                message=message,
                details=traceback.format_exc(),
            )
            return ValidationResult(success=False, message=str(error))

        message = "Successfully validated configuration parameters."
        self.logger.debug(
            f"{self.log_prefix}: {message}"
        )
        return ValidationResult(
            success=True,
            message=message
        )
