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

Generate temporary credentials using AWS IAM Roles Anywhere.
"""

import base64
import datetime
import hashlib
import json
import re
from typing import Any, Optional

import requests
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from . import constants as CONST
from .exceptions import AWSS3WebTxException
from .helper import (
    get_effective_region,
    get_roles_anywhere_host,
    log_and_raise,
    safe_error_text,
    sanitize_error_text,
)


class EncryptedKeyError(ValueError):
    """The Private Key is encrypted and cannot be decrypted."""


class MissingPassPhraseError(EncryptedKeyError):
    """The Private Key is encrypted and no Password Phrase is provided."""


class IncorrectPassPhraseError(EncryptedKeyError):
    """The Password Phrase does not decrypt the encrypted Private Key."""


class UnsupportedKeyTypeError(ValueError):
    """The Private Key is not an RSA key."""


def has_required_credentials(credentials: Any) -> bool:
    """Check that temporary credentials hold every required key.

    Args:
        credentials (Any): Credentials from CreateSession or the storage.

    Returns:
        bool: True when ``credentials`` is a dict with a non-empty value
            for accessKeyId, secretAccessKey, sessionToken and expiration.
    """
    return isinstance(credentials, dict) and all(
        credentials.get(key) for key in CONST.REQUIRED_CREDENTIAL_KEYS
    )


class AWSS3GenerateTemporaryCredentials:
    """Generate temporary credentials using IAM Roles Anywhere."""

    def __init__(
        self,
        configuration: dict,
        logger: Any,
        proxy: Optional[dict],
        log_prefix: str,
        user_agent: str,
        verify: bool = True,
    ) -> None:
        """Initialize the temporary credentials generator.

        Args:
            configuration (dict): Plugin configuration parameters.
            logger: CE logger object.
            proxy (Optional[dict]): Proxy settings for requests.
            log_prefix (str): Log prefix.
            user_agent (str): User agent string.
            verify (bool): SSL certificate validation of the request.
        """
        self.configuration = configuration
        self.logger = logger
        self.proxy = proxy or {}
        self.log_prefix = log_prefix
        self.user_agent = user_agent
        self.verify = verify

    @staticmethod
    def load_private_key(
        private_key_pem: str, pass_phrase: Optional[str]
    ) -> Any:
        """Load a PEM private key, using the Password Phrase only if needed.

        The key is first loaded without a password, so an unencrypted key
        works with or without a Password Phrase. Only an encrypted key
        (cryptography raises ``TypeError``) is loaded with the phrase.

        Args:
            private_key_pem (str): PEM encoded private key.
            pass_phrase (Optional[str]): Password Phrase (never stripped).

        Raises:
            MissingPassPhraseError: The key is encrypted and no Password
                Phrase is provided.
            IncorrectPassPhraseError: The Password Phrase does not decrypt
                the key.
            ValueError: The key is not a valid PEM private key.

        Returns:
            The loaded private key object.
        """
        key_bytes = private_key_pem.encode(CONST.TEXT_ENCODING)
        try:
            return serialization.load_pem_private_key(
                key_bytes, password=None
            )
        except TypeError as error:
            if not pass_phrase:
                raise MissingPassPhraseError(
                    CONST.ENCRYPTED_KEY_CAUSE
                ) from error
        try:
            return serialization.load_pem_private_key(
                key_bytes, password=pass_phrase.encode(CONST.TEXT_ENCODING)
            )
        except (TypeError, ValueError) as error:
            raise IncorrectPassPhraseError(
                CONST.ENCRYPTED_KEY_CAUSE
            ) from error

    @staticmethod
    def ensure_rsa_key(private_key: Any) -> None:
        """Ensure that the private key is an RSA key.

        The request is signed with AWS4-X509-RSA-SHA256, so other key types
        cannot be used.

        Args:
            private_key: The loaded private key object.

        Raises:
            UnsupportedKeyTypeError: The key is not an RSA key.
        """
        if not isinstance(private_key, rsa.RSAPrivateKey):
            raise UnsupportedKeyTypeError(
                "Only RSA private keys are supported."
            )

    @staticmethod
    def load_certificate(certificate_pem: str) -> Any:
        """Load a PEM encoded X.509 certificate.

        Args:
            certificate_pem (str): PEM encoded certificate.

        Returns:
            x509.Certificate: The loaded certificate.
        """
        return x509.load_pem_x509_certificate(
            certificate_pem.encode(CONST.TEXT_ENCODING)
        )

    def _raise(
        self,
        cause: str,
        details: Optional[str] = None,
        err: Optional[BaseException] = None,
        resolution: str = CONST.ROLES_ANYWHERE_RESOLUTION,
        action: str = CONST.ROLES_ANYWHERE_ACTION,
    ) -> None:
        """Log an error and raise ``AWSS3WebTxException``.

        Args:
            cause (str): Specific reason.
            details (Optional[str]): Error details.
            err (Optional[BaseException]): Original exception.
            resolution (str): Resolution starting with "Ensure that".
            action (str): What was being done.

        Raises:
            AWSS3WebTxException: Always.
        """
        log_and_raise(
            self.logger,
            self.log_prefix,
            action,
            resolution,
            cause=cause,
            details=details,
            err=err,
        )

    @staticmethod
    def _safe_response_text(response: requests.Response) -> str:
        """Return the response text without ever raising.

        Args:
            response (requests.Response): Response object.

        Returns:
            str: Response text, empty when unavailable.
        """
        try:
            return response.text or ""
        except Exception:
            return ""

    def _parse_response(self, response: requests.Response) -> dict:
        """Parse the JSON body of a successful CreateSession response.

        Args:
            response (requests.Response): Response object.

        Raises:
            AWSS3WebTxException: The body is not a valid JSON object.

        Returns:
            dict: Parsed JSON.
        """
        try:
            response_json = response.json()
        except ValueError as error:
            # The body of a successful response holds credentials, so only
            # its length is logged.
            self._raise(
                "Invalid JSON response received from AWS IAM Roles "
                f"Anywhere. Error: {safe_error_text(error)}",
                details=(
                    f"Invalid JSON response (HTTP {response.status_code}, "
                    f"{len(self._safe_response_text(response))} characters)."
                ),
                err=error,
                resolution=CONST.ENDPOINT_REACHABLE_RESOLUTION,
            )
        if not isinstance(response_json, dict):
            self._raise(
                "Invalid JSON response received from AWS IAM Roles "
                "Anywhere.",
                details=(
                    f"The CreateSession response (HTTP "
                    f"{response.status_code}) is not a JSON object."
                ),
                resolution=CONST.ENDPOINT_REACHABLE_RESOLUTION,
            )
        return response_json

    def _get_value(self, key: str) -> str:
        """Get a trimmed configuration value.

        Args:
            key (str): Configuration parameter key.

        Returns:
            str: The trimmed value, empty when it is missing.
        """
        return (self.configuration.get(key) or "").strip()

    def _build_request_body(self) -> str:
        """Build the JSON body of the CreateSession request.

        Returns:
            str: JSON request body.
        """
        return json.dumps(
            {
                CONST.DURATION_SECONDS_KEY: (
                    CONST.ROLES_ANYWHERE_SESSION_SECONDS
                ),
                CONST.PROFILE_ARN_BODY_KEY: self._get_value(
                    CONST.PROFILE_ARN_KEY
                ),
                CONST.ROLE_ARN_BODY_KEY: self._get_value(CONST.ROLE_ARN_KEY),
                CONST.SESSION_NAME_KEY: CONST.ROLES_ANYWHERE_SESSION_NAME,
                CONST.TRUST_ANCHOR_ARN_BODY_KEY: self._get_value(
                    CONST.TRUST_ANCHOR_ARN_KEY
                ),
            }
        )

    def _load_signing_material(self) -> tuple:
        """Load the private key and the certificate from configuration.

        Raises:
            AWSS3WebTxException: The key or certificate cannot be loaded.

        Returns:
            tuple: (private key, certificate).
        """
        try:
            private_key = self.load_private_key(
                self._get_value(CONST.PRIVATE_KEY_FILE_KEY),
                self.configuration.get(CONST.PASS_PHRASE_KEY),
            )
            self.ensure_rsa_key(private_key)
            certificate = self.load_certificate(
                self._get_value(CONST.PUBLIC_CERTIFICATE_FILE_KEY)
            )
        except Exception as error:
            self._raise(
                "Unable to load the Private Key or Certificate Body.",
                details=type(error).__name__,
                err=error,
                resolution=(
                    "Ensure that the Private Key (RSA only) and Certificate "
                    "Body are valid PEM values and the Password Phrase "
                    "matches an encrypted Private Key."
                ),
            )
        return private_key, certificate

    def _sign_request(self, body: str, host: str, region: str) -> dict:
        """Sign the CreateSession request (AWS SigV4 with X.509).

        Args:
            body (str): JSON request body.
            host (str): Roles Anywhere endpoint host.
            region (str): Effective AWS region.

        Raises:
            AWSS3WebTxException: The key or certificate cannot be loaded.

        Returns:
            dict: Request headers including the Authorization header.
        """
        private_key, certificate = self._load_signing_material()
        amz_x509 = base64.b64encode(
            certificate.public_bytes(encoding=serialization.Encoding.DER)
        ).decode(CONST.TEXT_ENCODING)
        now = datetime.datetime.now(datetime.timezone.utc)
        amz_date = now.strftime(CONST.AMZ_DATE_FORMAT)
        date_stamp = now.strftime(CONST.DATE_STAMP_FORMAT)
        canonical_headers = CONST.CANONICAL_HEADERS_FORMAT.format(
            content_type=CONST.CONTENT_TYPE,
            host=host,
            amz_date=amz_date,
            amz_x509=amz_x509,
        )
        payload_hash = hashlib.sha256(
            body.encode(CONST.TEXT_ENCODING)
        ).hexdigest()
        canonical_request = CONST.CANONICAL_REQUEST_FORMAT.format(
            method=CONST.HTTP_METHOD,
            uri=CONST.CANONICAL_URI,
            canonical_headers=canonical_headers,
            signed_headers=CONST.SIGNED_HEADERS,
            payload_hash=payload_hash,
        )
        credential_scope = CONST.CREDENTIAL_SCOPE_FORMAT.format(
            date_stamp=date_stamp,
            region=region,
            service=CONST.ROLES_ANYWHERE_SERVICE,
            terminator=CONST.SIGNING_TERMINATOR,
        )
        string_to_sign = CONST.STRING_TO_SIGN_FORMAT.format(
            algorithm=CONST.SIGNING_ALGORITHM,
            amz_date=amz_date,
            credential_scope=credential_scope,
            request_hash=hashlib.sha256(
                canonical_request.encode(CONST.TEXT_ENCODING)
            ).hexdigest(),
        )
        signature = private_key.sign(
            data=string_to_sign.encode(CONST.TEXT_ENCODING),
            padding=padding.PKCS1v15(),
            algorithm=hashes.SHA256(),
        )
        authorization = CONST.AUTHORIZATION_FORMAT.format(
            algorithm=CONST.SIGNING_ALGORITHM,
            serial_number=certificate.serial_number,
            credential_scope=credential_scope,
            signed_headers=CONST.SIGNED_HEADERS,
            signature=signature.hex(),
        )
        return {
            CONST.HEADER_CONTENT_TYPE: CONST.CONTENT_TYPE,
            CONST.HEADER_AMZ_DATE: amz_date,
            CONST.HEADER_AMZ_X509: amz_x509,
            CONST.HEADER_AUTHORIZATION: authorization,
            CONST.HEADER_USER_AGENT: self.user_agent,
        }

    def _response_error_text(self, response: requests.Response) -> str:
        """Get the sanitized AWS error message of an error response.

        Args:
            response (requests.Response): Response object.

        Returns:
            str: The ``message`` of the JSON body, else the body text;
                sanitized and truncated.
        """
        try:
            body = response.json()
            text = body.get(CONST.ROLES_ANYWHERE_MESSAGE_KEY) or body.get(
                CONST.ERROR_MESSAGE_KEY
            )
        except Exception:
            text = None
        if not isinstance(text, str):
            text = self._safe_response_text(response)
        return sanitize_error_text(text)

    def _handle_error_response(self, response: requests.Response) -> None:
        """Log and raise for a non successful response.

        Args:
            response (requests.Response): Response object.

        Raises:
            AWSS3WebTxException: Always.
        """
        status_code = response.status_code
        resolution = CONST.ARN_RESOLUTION
        if status_code == 403:
            cause = (
                "Access Denied. The Profile ARN, Role ARN, Trust Anchor "
                "ARN or the policies attached to the role may be wrong."
            )
        elif status_code == 404:
            cause = (
                "Resource not found. The Profile ARN, Role ARN or Trust "
                "Anchor ARN may be wrong."
            )
        elif 400 <= status_code < 500:
            cause = (
                f"Received exit code {status_code}, HTTP client error "
                "while generating temporary credentials."
            )
        elif 500 <= status_code < 600:
            cause = (
                f"Received exit code {status_code}, HTTP server error "
                "while generating temporary credentials."
            )
            resolution = (
                "Ensure that AWS IAM Roles Anywhere is available, as it "
                "returned a server error, and try again after some time."
            )
        else:
            cause = (
                f"Received exit code {status_code}. HTTP error while "
                "generating temporary credentials."
            )
        aws_message = self._response_error_text(response)
        if aws_message:
            cause = f"{cause} Error: {status_code} {aws_message}"
        self._raise(
            cause,
            details=(
                "API response: "
                f"{sanitize_error_text(self._safe_response_text(response))}"
            ),
            resolution=resolution,
        )

    def _extract_credentials(self, response_json: dict) -> dict:
        """Extract the credentials block from a CreateSession response.

        Args:
            response_json (dict): Parsed CreateSession response.

        Raises:
            AWSS3WebTxException: The response has no credentials or one of
                accessKeyId, secretAccessKey, sessionToken and expiration
                is missing.

        Returns:
            dict: accessKeyId, secretAccessKey, sessionToken, expiration.
        """
        credential_set = response_json.get(CONST.CREDENTIAL_SET_KEY) or []
        credentials = None
        if isinstance(credential_set, list) and credential_set:
            first = credential_set[0]
            if isinstance(first, dict):
                credentials = first.get(CONST.CREDENTIALS_KEY)
        if not has_required_credentials(credentials):
            missing = [
                key
                for key in CONST.REQUIRED_CREDENTIAL_KEYS
                if not isinstance(credentials, dict)
                or not credentials.get(key)
            ]
            self._raise(
                "Unable to generate temporary credentials. Check the "
                "configuration parameters.",
                resolution=(
                    "Ensure that the Profile ARN, Role ARN and Trust Anchor "
                    "ARN provided in the configuration parameters are "
                    "correct."
                ),
                details=(
                    "The CreateSession response has no usable credentials. "
                    f"Missing: {', '.join(missing)}."
                ),
            )
        return credentials

    def generate_temporary_credentials(self) -> dict:
        """Generate temporary credentials with IAM Roles Anywhere.

        Credentials, the private key and the Password Phrase are never
        logged.

        Raises:
            AWSS3WebTxException: On any failure (already logged).

        Returns:
            dict: accessKeyId, secretAccessKey, sessionToken, expiration.
        """
        try:
            region = get_effective_region(self.configuration)
            if not re.fullmatch(CONST.REGION_NAME_REGEX, region):
                self._raise(
                    "Invalid AWS region provided, it cannot be used to "
                    "build the AWS IAM Roles Anywhere endpoint.",
                    details="The region is not a valid host label.",
                    resolution=(
                        "Ensure that the AWS S3 Bucket Region (or AWS Custom "
                        "Region) contains only letters, digits and hyphens."
                    ),
                )
            host = get_roles_anywhere_host(region)
            body = self._build_request_body()
            headers = self._sign_request(body, host, region)
            response = requests.post(
                CONST.ROLES_ANYWHERE_URL_FORMAT.format(
                    host=host, uri=CONST.CANONICAL_URI
                ),
                data=body,
                headers=headers,
                proxies=self.proxy,
                verify=self.verify,
                timeout=CONST.ROLES_ANYWHERE_TIMEOUT,
            )
            if response.status_code in CONST.ROLES_ANYWHERE_SUCCESS_CODES:
                return self._extract_credentials(
                    self._parse_response(response)
                )
            self._handle_error_response(response)
        except AWSS3WebTxException:
            raise
        except requests.exceptions.RequestException as error:
            self._raise(
                "Unable to connect to the AWS IAM Roles Anywhere endpoint "
                "while generating temporary credentials. Error: "
                f"{safe_error_text(error)}",
                err=error,
                resolution=(
                    "Ensure that the AWS S3 Bucket Region (or AWS Custom "
                    "Region) is correct and the Cloud Exchange host can "
                    "reach rolesanywhere.<region>.amazonaws.com directly or "
                    "through the configured proxy."
                ),
            )
        except Exception as error:
            self._raise("", details=safe_error_text(error), err=error)
