"""
BSD 3-Clause License

Copyright (c) 2021, Netskope OSS
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice,
   this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its
   contributors may be used to endorse or promote products derived from
   this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
POSSIBILITY OF SUCH DAMAGE.

Generating Temporary Credentials using IAM Roles Anywhere.
"""

import base64
import datetime
import hashlib
import json
import traceback

import requests
from botocore.exceptions import NoCredentialsError
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

from .databricks_exception import DatabricksException


class DatabricksGenerateTempCreds:
    """Generates temporary AWS credentials via IAM Roles Anywhere."""

    def __init__(
        self,
        configuration,
        logger,
        proxy,
        storage,
        log_prefix,
        user_agent,
    ):
        """Initialize DatabricksGenerateTempCreds.

        Args:
            configuration (dict): Plugin configuration parameters.
            logger: Logger object.
            proxy (dict): Proxy configuration.
            storage (dict): Plugin storage dict.
            log_prefix (str): Log prefix string.
            user_agent (str): User-agent string for HTTP requests.
        """
        self.configuration = configuration
        self.logger = logger
        self.proxy = proxy
        self.storage = storage
        self.log_prefix = log_prefix
        self.user_agent = user_agent

    def parse_response(self, response: requests.models.Response):
        """Parse Response and return JSON from response object.

        Args:
            response (requests.models.Response): Response object.

        Returns:
            dict: Parsed response JSON.

        Raises:
            DatabricksException: On JSON decode or unexpected errors.
        """
        try:
            return response.json()
        except json.JSONDecodeError as err:
            err_msg = f"Invalid JSON response received from API. Error: {err}"
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=f"API response: {response.text}",
            )
            raise DatabricksException(err_msg)
        except Exception as exp:
            err_msg = (
                "Unexpected error occurred while parsing"
                f" JSON response. Error: {exp}"
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=f"API response: {response.text}",
            )
            raise DatabricksException(err_msg)

    def generate_temporary_credentials(self):
        """Generate temporary AWS credentials via IAM Roles Anywhere.

        Returns:
            dict: Credentials response from IAM Roles Anywhere.

        Raises:
            DatabricksException: On authentication or request errors.
        """
        try:
            private_key_file = self.configuration.get(
                "private_key_file", ""
            ).strip()
            pass_phrase = self.configuration.get("pass_phrase")
            public_certificate_file = self.configuration.get(
                "public_certificate_file", ""
            ).strip()
            region = self.configuration.get("region_name", "").strip()
            duration_seconds = "900"
            profile_arn = self.configuration.get("profile_arn", "").strip()
            role_arn = self.configuration.get("role_arn", "").strip()
            session_name = "Session"
            trust_anchor_arn = self.configuration.get(
                "trust_anchor_arn", ""
            ).strip()

            method = "POST"
            service = "rolesanywhere"
            host = f"rolesanywhere.{region}.amazonaws.com"
            endpoint = f"https://rolesanywhere.{region}.amazonaws.com"
            content_type = "application/json"

            if not pass_phrase:
                raise DatabricksException(
                    "Password Phrase is required for"
                    " AWS IAM Roles Anywhere authentication."
                )

            try:
                private_key = serialization.load_pem_private_key(
                    private_key_file.encode("utf-8"), None
                )
            except Exception:
                try:
                    private_key = serialization.load_pem_private_key(
                        private_key_file.encode("utf-8"),
                        password=pass_phrase.encode("utf-8"),
                    )
                except Exception as exp:
                    err_msg = "Unable to load Private Key."
                    self.logger.error(
                        message=f"{self.log_prefix}: {err_msg}",
                        details=f"Error: {exp}",
                    )
                    raise DatabricksException(err_msg)

            cert = x509.load_pem_x509_certificate(
                public_certificate_file.encode()
            )
            amz_x509 = str(
                base64.b64encode(
                    cert.public_bytes(encoding=serialization.Encoding.DER)
                ),
                "utf-8",
            )
            serial_number_dec = cert.serial_number

            request_parameters = (
                "{"
                f'"durationSeconds": {duration_seconds},'
                f'"profileArn": "{profile_arn}",'
                f'"roleArn": "{role_arn}",'
                f'"sessionName": "{session_name}",'
                f'"trustAnchorArn": "{trust_anchor_arn}"'
                "}"
            )

            t = datetime.datetime.utcnow()
            amz_date = t.strftime("%Y%m%dT%H%M%SZ")
            date_stamp = t.strftime("%Y%m%d")

            canonical_uri = "/sessions"
            canonical_querystring = ""
            canonical_headers = (
                f"content-type:{content_type}\n"
                f"host:{host}\n"
                f"x-amz-date:{amz_date}\n"
                f"x-amz-x509:{amz_x509}\n"
            )
            signed_headers = "content-type;host;x-amz-date;x-amz-x509"
            payload_hash = hashlib.sha256(
                request_parameters.encode("utf-8")
            ).hexdigest()
            canonical_request = (
                f"{method}\n"
                f"{canonical_uri}\n"
                f"{canonical_querystring}\n"
                f"{canonical_headers}\n"
                f"{signed_headers}\n"
                f"{payload_hash}"
            )

            algorithm = "AWS4-X509-RSA-SHA256"
            credential_scope = f"{date_stamp}/{region}/{service}/aws4_request"
            string_to_sign = (
                f"{algorithm}\n"
                f"{amz_date}\n"
                f"{credential_scope}\n"
                + hashlib.sha256(canonical_request.encode("utf-8")).hexdigest()
            )

            signature = private_key.sign(
                data=string_to_sign.encode("utf-8"),
                padding=padding.PKCS1v15(),
                algorithm=hashes.SHA256(),
            )
            signature_hex = signature.hex()

            authorization_header = (
                f"{algorithm} "
                f"Credential={serial_number_dec}/{credential_scope}, "
                f"SignedHeaders={signed_headers}, "
                f"Signature={signature_hex}"
            )

            headers = {
                "Content-Type": content_type,
                "X-Amz-Date": amz_date,
                "X-Amz-X509": amz_x509,
                "Authorization": authorization_header,
                "User-Agent": self.user_agent,
            }
            response = requests.post(
                endpoint + canonical_uri,
                data=request_parameters,
                headers=headers,
            )
            if response.status_code in [200, 201]:
                return self.parse_response(response)
            elif response.status_code == 403:
                err_msg = (
                    "Access Denied. Verify the AWS S3 Bucket Region"
                    " Name, Profile ARN, Role ARN, and Trust Anchor"
                    " ARN provided in configuration parameters and"
                    " the policies attached to the role."
                )
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg}",
                    details=f"{self.parse_response(response)}",
                )
                raise DatabricksException(err_msg)
            elif response.status_code == 404:
                err_msg = (
                    "Resource not found. Verify the Profile ARN, Role"
                    " ARN, and Trust Anchor ARN provided in"
                    " configuration parameters."
                )
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg}",
                    details=f"{self.parse_response(response)}",
                )
                raise DatabricksException(err_msg)
            elif 400 <= response.status_code < 500:
                err_msg = (
                    f"Received exit code {response.status_code},"
                    " HTTP client error."
                )
                resp_json = self.parse_response(response)
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg}",
                    details=f"{resp_json}",
                )
                raise DatabricksException(err_msg)
            elif 500 <= response.status_code < 600:
                err_msg = (
                    f"Received exit code {response.status_code},"
                    " HTTP server error."
                )
                resp_json = self.parse_response(response)
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg}",
                    details=f"{resp_json}",
                )
                raise DatabricksException(err_msg)
            else:
                err_msg = (
                    f"Received exit code {response.status_code},"
                    " HTTP error."
                )
                resp_json = self.parse_response(response)
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg}",
                    details=f"{resp_json}",
                )
                raise DatabricksException(err_msg)

        except NoCredentialsError as exp:
            err_msg = (
                "No AWS Credentials were found in the environment."
                " Deploy the plugin into an AWS environment or use"
                " AWS IAM Roles Anywhere authentication."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=f"Error: {exp}",
            )
            raise DatabricksException(err_msg)
        except DatabricksException:
            raise
        except Exception as exp:
            err_msg = (
                "Error occurred while generating Temporary" " Credentials."
            )
            self.logger.error(
                message=(f"{self.log_prefix}: {err_msg} {exp}"),
                details=traceback.format_exc(),
            )
            raise DatabricksException(err_msg)
