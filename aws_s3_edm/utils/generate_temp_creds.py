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

Generating temporary credentials using AWS IAM Roles Anywhere.
"""

import base64
import datetime
import hashlib
import json
import re
from typing import Optional

import requests
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from .constants import (
    CANONICAL_URI,
    CONTENT_TYPE,
    REGION_NAME_REGEX,
    ROLES_ANYWHERE_SESSION_NAME,
    ROLES_ANYWHERE_SESSION_SECONDS,
    ROLES_ANYWHERE_TIMEOUT,
    SIGNED_HEADERS,
    SIGNING_ALGORITHM,
)
from .exception import AWSS3EDMException
from .helper import (
    describe_arn_region_mismatch,
    AWSS3EDMBase,
    get_effective_region,
    get_roles_anywhere_host,
    safe_error_text,
    sanitize_error_text,
)


class MissingPassPhraseError(ValueError):
    """Raised when the private key is encrypted and has no pass phrase."""


class UnsupportedKeyTypeError(ValueError):
    """Raised when the private key is not an RSA key."""


class AWSS3GenerateTemporaryCredentials(AWSS3EDMBase):
    """Generate temporary credentials using IAM Roles Anywhere."""

    default_action = "generating temporary credentials"

    def __init__(
        self,
        configuration: dict,
        logger,
        proxy: dict,
        storage: Optional[dict],
        log_prefix: str,
        user_agent: str,
        verify: bool = True,
    ) -> None:
        """Initialize the temporary credentials generator.

        Args:
            configuration (dict): Step 1 configuration parameters.
            logger: Logger object.
            proxy (dict): Proxy settings for the requests library.
            storage (dict): Plugin storage.
            log_prefix (str): Log prefix.
            user_agent (str): User agent string.
            verify (bool): SSL certificate validation of the request.
        """
        super().__init__(logger, log_prefix)
        self.configuration = configuration
        self.proxy = proxy
        self.storage = storage
        self.user_agent = user_agent
        self.verify = verify

    @staticmethod
    def load_private_key(private_key_pem: str, pass_phrase: Optional[str]):
        """Load a PEM private key, honouring the optional pass phrase.

        The key is first loaded without a password. Only when the key is
        encrypted (cryptography raises ``TypeError``) the pass phrase is
        used, so an unencrypted key works with or without a pass phrase.

        Args:
            private_key_pem (str): PEM encoded private key.
            pass_phrase (Optional[str]): Pass phrase of an encrypted key.

        Raises:
            MissingPassPhraseError: If the key is encrypted and no pass
                phrase is provided.
            ValueError: If the key or pass phrase is invalid.

        Returns:
            The loaded private key object.
        """
        key_bytes = private_key_pem.encode("utf-8")
        try:
            return serialization.load_pem_private_key(
                key_bytes, password=None
            )
        except TypeError as error:
            if not pass_phrase:
                raise MissingPassPhraseError(
                    "Private Key is encrypted and no Password Phrase "
                    "was provided."
                ) from error
        return serialization.load_pem_private_key(
            key_bytes, password=pass_phrase.encode("utf-8")
        )

    @staticmethod
    def ensure_rsa_key(private_key) -> None:
        """Ensure the private key is an RSA key.

        The request is signed with AWS4-X509-RSA-SHA256, so other key
        types (for example EC keys) are not supported.

        Args:
            private_key: The loaded private key object.

        Raises:
            UnsupportedKeyTypeError: If the key is not an RSA key.
        """
        if not isinstance(private_key, rsa.RSAPrivateKey):
            raise UnsupportedKeyTypeError(
                "Only RSA private keys are supported."
            )

    @staticmethod
    def load_certificate(certificate_pem: str):
        """Load a PEM encoded X.509 certificate.

        Args:
            certificate_pem (str): PEM encoded certificate.

        Returns:
            x509.Certificate: The loaded certificate.
        """
        return x509.load_pem_x509_certificate(certificate_pem.encode())

    def _safe_response_text(self, response: requests.Response) -> str:
        """Return the response text without ever raising.

        Args:
            response (requests.Response): Response object.

        Returns:
            str: Response text.
        """
        try:
            return response.text
        except Exception:
            return ""

    def _parse_response(self, response: requests.Response) -> dict:
        """Parse the JSON body of a response.

        Args:
            response (requests.Response): Response object.

        Raises:
            AWSS3EDMException: If the body is not a valid JSON.

        Returns:
            dict: Parsed JSON.
        """
        try:
            return response.json()
        except ValueError as error:
            err_msg = (
                "Invalid JSON response received from AWS IAM Roles "
                "Anywhere."
            )
            raise self._error(
                f"{err_msg} Error: {safe_error_text(error)}",
                "Ensure that the AWS IAM Roles Anywhere endpoint is "
                "reachable directly or through the configured proxy.",
                # The body of a successful response may hold credentials, so
                # it is never logged.
                details=(
                    f"Invalid JSON response (HTTP {response.status_code}, "
                    f"{len(self._safe_response_text(response))} characters)."
                ),
            ) from error

    def _build_request_body(self, configuration: dict) -> str:
        """Build the JSON body of the CreateSession request.

        Args:
            configuration (dict): Step 1 configuration parameters.

        Returns:
            str: JSON string sent as the request body.
        """
        return json.dumps(
            {
                "durationSeconds": ROLES_ANYWHERE_SESSION_SECONDS,
                "profileArn": (configuration.get("profile_arn") or "")
                .strip(),
                "roleArn": (configuration.get("role_arn") or "").strip(),
                "sessionName": ROLES_ANYWHERE_SESSION_NAME,
                "trustAnchorArn": (
                    configuration.get("trust_anchor_arn") or ""
                ).strip(),
            }
        )

    def _sign_request(
        self, configuration: dict, body: str, host: str, region: str
    ) -> dict:
        """Sign the CreateSession request (AWS SigV4 with X.509).

        Args:
            configuration (dict): Step 1 configuration parameters.
            body (str): JSON request body.
            host (str): Roles Anywhere endpoint host.
            region (str): AWS region.

        Raises:
            AWSS3EDMException: If the key or certificate cannot be loaded.

        Returns:
            dict: Request headers including the Authorization header.
        """
        try:
            private_key = self.load_private_key(
                (configuration.get("private_key_file") or "").strip(),
                configuration.get("pass_phrase"),
            )
            self.ensure_rsa_key(private_key)
            cert = self.load_certificate(
                (configuration.get("public_certificate_file") or "").strip()
            )
        except Exception as error:
            err_msg = "Unable to load the Private Key or Certificate Body."
            raise self._error(
                err_msg,
                "Ensure that the Private Key (RSA only) and Certificate "
                "Body are valid PEM values and the Password Phrase matches "
                "an encrypted Private Key.",
            ) from error

        amz_x509 = base64.b64encode(
            cert.public_bytes(encoding=serialization.Encoding.DER)
        ).decode("utf-8")
        now = datetime.datetime.now(datetime.timezone.utc)
        amz_date = now.strftime("%Y%m%dT%H%M%SZ")
        date_stamp = now.strftime("%Y%m%d")

        canonical_headers = (
            f"content-type:{CONTENT_TYPE}\n"
            f"host:{host}\n"
            f"x-amz-date:{amz_date}\n"
            f"x-amz-x509:{amz_x509}\n"
        )
        payload_hash = hashlib.sha256(body.encode("utf-8")).hexdigest()
        canonical_request = (
            f"POST\n{CANONICAL_URI}\n\n{canonical_headers}\n"
            f"{SIGNED_HEADERS}\n{payload_hash}"
        )
        credential_scope = f"{date_stamp}/{region}/rolesanywhere/aws4_request"
        string_to_sign = (
            f"{SIGNING_ALGORITHM}\n{amz_date}\n{credential_scope}\n"
            + hashlib.sha256(canonical_request.encode("utf-8")).hexdigest()
        )
        signature = private_key.sign(
            data=string_to_sign.encode("utf-8"),
            padding=padding.PKCS1v15(),
            algorithm=hashes.SHA256(),
        )
        authorization = (
            f"{SIGNING_ALGORITHM} Credential={cert.serial_number}/"
            f"{credential_scope}, SignedHeaders={SIGNED_HEADERS}, "
            f"Signature={signature.hex()}"
        )
        return {
            "Content-Type": CONTENT_TYPE,
            "X-Amz-Date": amz_date,
            "X-Amz-X509": amz_x509,
            "Authorization": authorization,
            "User-Agent": self.user_agent,
        }

    def _handle_error_response(self, response: requests.Response) -> None:
        """Log and raise an exception for a non successful response.

        Args:
            response (requests.Response): Response object.

        Raises:
            AWSS3EDMException: Always.
        """
        status_code = response.status_code
        resolution = (
            "Ensure that the Profile ARN, Role ARN, Trust Anchor ARN, the "
            "certificate and the policies attached to the role are "
            "correct."
        )
        if status_code == 403:
            err_msg = (
                "Access Denied. The Profile ARN, Role ARN, Trust Anchor "
                "ARN or the policies attached to the role may be wrong."
            )
        elif status_code == 404:
            err_msg = (
                "Resource not found. The Profile ARN, Role ARN or Trust "
                "Anchor ARN may be wrong."
            )
        elif 400 <= status_code < 500:
            err_msg = (
                f"Received exit code {status_code}, HTTP client error "
                "while generating temporary credentials."
            )
        elif 500 <= status_code < 600:
            err_msg = (
                f"Received exit code {status_code}, HTTP server error "
                "while generating temporary credentials."
            )
            resolution = (
                "Ensure that AWS IAM Roles Anywhere is available, as it "
                "returned a server error, and try again after some time."
            )
        else:
            err_msg = (
                f"Received exit code {status_code}. HTTP error while "
                "generating temporary credentials."
            )
        mismatch = describe_arn_region_mismatch(
            self.configuration, get_effective_region(self.configuration)
        )
        if mismatch:
            err_msg = f"{err_msg} {mismatch[0]}"
            resolution = mismatch[1]
        original = self._response_error_text(response)
        if original:
            err_msg = f"{err_msg} Error: {status_code} {original}"
        raise self._error(
            err_msg,
            resolution,
            details=f"API response: {self._safe_response_text(response)}",
        )

    def _response_error_text(self, response: requests.Response) -> str:
        """Get the sanitized AWS error message of an error response.

        Args:
            response (requests.Response): Response object.

        Returns:
            str: The ``message`` of the JSON body, or the body text; empty
                when unavailable.
        """
        try:
            body = response.json()
            text = body.get("message") or body.get("Message")
        except Exception:
            text = None
        if not isinstance(text, str):
            text = self._safe_response_text(response)
        return sanitize_error_text(text) if isinstance(text, str) else ""

    def _extract_credentials(self, response_json: dict) -> dict:
        """Extract the credentials block from a CreateSession response.

        Args:
            response_json (dict): Parsed CreateSession response.

        Raises:
            AWSS3EDMException: If the response has no credentials.

        Returns:
            dict: accessKeyId, secretAccessKey, sessionToken, expiration.
        """
        credential_set = response_json.get("credentialSet") or []
        credentials = (
            credential_set[0].get("credentials") if credential_set else None
        )
        if not credentials:
            err_msg = (
                "Unable to generate temporary credentials. Check the "
                "configuration parameters."
            )
            raise self._error(
                err_msg,
                "Ensure that the Profile ARN, Role ARN and Trust Anchor "
                "ARN provided in the configuration parameters are correct.",
                details="CreateSession response has no credentials.",
            )
        return credentials

    def generate_temporary_credentials(self) -> dict:
        """Generate temporary credentials with IAM Roles Anywhere.

        Raises:
            AWSS3EDMException: On any failure. Credentials, the private key
                and the pass phrase are never logged.

        Returns:
            dict: accessKeyId, secretAccessKey, sessionToken, expiration.
        """
        try:
            region = get_effective_region(self.configuration)
            if not re.fullmatch(REGION_NAME_REGEX, region):
                err_msg = (
                    "Invalid AWS region provided, it cannot be used to "
                    "build the AWS IAM Roles Anywhere endpoint."
                )
                raise self._error(
                    err_msg,
                    "Ensure that the AWS region contains only letters, "
                    "digits and hyphens.",
                    details="The region is not a valid host label.",
                )
            host = get_roles_anywhere_host(region)
            body = self._build_request_body(self.configuration)
            headers = self._sign_request(
                self.configuration, body, host, region
            )
            response = requests.post(
                f"https://{host}{CANONICAL_URI}",
                data=body,
                headers=headers,
                proxies=self.proxy,
                timeout=ROLES_ANYWHERE_TIMEOUT,
                verify=self.verify,
            )
            if response.status_code in (200, 201):
                return self._extract_credentials(
                    self._parse_response(response)
                )
            self._handle_error_response(response)
        except AWSS3EDMException:
            raise
        except requests.exceptions.RequestException as error:
            err_msg = (
                "Unable to connect to the AWS IAM Roles Anywhere endpoint "
                "while generating temporary credentials. Error: "
                f"{safe_error_text(error)}"
            )
            raise self._error(
                err_msg,
                "Ensure that the AWS S3 Bucket Region is correct and the "
                "Cloud Exchange host can reach "
                "rolesanywhere.<region>.amazonaws.com directly or through "
                "the configured proxy.",
            ) from error
        except Exception as error:
            err_msg = "Error occurred while generating temporary credentials."
            raise self._error(
                err_msg,
                "Ensure that the AWS IAM Roles Anywhere configuration "
                "parameters are correct.",
            ) from error
