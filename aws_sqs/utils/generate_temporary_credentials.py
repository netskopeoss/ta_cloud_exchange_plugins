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
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from .exceptions import AWSSQSException


class GenerateTemporaryCredentials:
    """AWS GuardDuty validator class."""

    def __init__(self, configuration, logger, proxy, storage, log_prefix, user_agent):
        """Init method."""
        self.configuration = configuration
        self.logger = logger
        self.proxy = proxy
        self.storage = storage
        self.log_prefix = log_prefix
        self.user_agent = user_agent

    def parse_response(self, response: requests.models.Response):
        """Parse Response will return JSON from response object.

        Args:
            response (response): Response object.

        Returns:
            Any: Response Json.
        """
        try:
            return response.json()
        except json.JSONDecodeError as err:
            err_msg = f"Invalid JSON response received from API. Error: {err}"
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=f"API response: {response.text}",
            )
            raise AWSSQSException(err_msg)
        except Exception as exp:
            err_msg = (
                "Unexpected error occurred while parsing"
                f" json response. Error: {exp}"
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=f"API Response: {response.text}",
            )
            raise AWSSQSException(err_msg)

    def generate_temporary_credentials(self):
        try:
            private_key_file = self.configuration.get("private_key_file", "").strip()
            pass_phrase = self.configuration.get("pass_phrase")
            public_certificate_file = self.configuration.get(
                "public_certificate_file"
            ).strip()
            region = self.configuration.get("region_name", "").strip()
            duration_seconds = "900"
            profile_arn = self.configuration.get("profile_arn", "").strip()
            role_arn = self.configuration.get("role_arn", "").strip()
            session_name = "Session"
            trust_anchor_arn = self.configuration.get("trust_anchor_arn").strip()

            method = "POST"
            service = "rolesanywhere"
            host = "rolesanywhere.{}.amazonaws.com".format(region)
            endpoint = "https://rolesanywhere.{}.amazonaws.com".format(region)
            content_type = "application/json"

            try:
                private_key = serialization.load_pem_private_key(
                    private_key_file.encode("utf-8"), None
                )
            except Exception:
                try:
                    private_key = serialization.load_pem_private_key(
                        private_key_file.encode("utf-8"),
                        password=str.encode(pass_phrase),
                    )
                except Exception as exp:
                    err_msg = "Unable to load Private Key."
                    self.logger.error(
                        message=(f"{self.log_prefix}: {err_msg}"),
                        details=f"Error: {exp}",
                    )
                    raise AWSSQSException(err_msg)

            # Load public certificate
            cert = x509.load_pem_x509_certificate(public_certificate_file.encode())
            amz_x509 = str(
                base64.b64encode(
                    cert.public_bytes(encoding=serialization.Encoding.DER)
                ),
                "utf-8",
            )

            # Public certificate serial number in decimal
            serial_number_dec = cert.serial_number

            # Request parameters for CreateSession--passed in a JSON block.
            request_parameters = "{"
            request_parameters += '"durationSeconds": {},'.format(duration_seconds)
            request_parameters += '"profileArn": "{}",'.format(profile_arn)
            request_parameters += '"roleArn": "{}",'.format(role_arn)
            request_parameters += '"sessionName": "{}",'.format(session_name)
            request_parameters += '"trustAnchorArn": "{}"'.format(trust_anchor_arn)
            request_parameters += "}"

            # Create a date for headers and the credential string
            t = datetime.datetime.utcnow()
            amz_date = t.strftime("%Y%m%dT%H%M%SZ")
            date_stamp = t.strftime("%Y%m%d")

            # ************* TASK 1: CREATE A CANONICAL REQUEST *************
            # http://docs.aws.amazon.com/general/latest/gr/sigv4-create-canonical-request.html

            # Step 2: Create canonical URI--the part of the URI from domain to
            # query
            # string (use '/' if no path)
            canonical_uri = "/sessions"

            # Step 3: Create the canonical query string.
            # In this example, request
            # parameters are passed in the body of the request and the query
            # string is blank.
            canonical_querystring = ""

            # Step 4: Create the canonical headers. Header names must be
            # trimmed and lowercase, and sorted in code point order from
            # low to high.
            # Note that there is a trailing \n.
            canonical_headers = (
                "content-type:"
                + content_type
                + "\n"
                + "host:"
                + host
                + "\n"
                + "x-amz-date:"
                + amz_date
                + "\n"
                + "x-amz-x509:"
                + amz_x509
                + "\n"
            )

            # Step 5: Create the list of signed headers. This lists the headers
            # in the canonical_headers list, delimited with ";" and in alpha.
            # order Note: The request can include any headers;
            #  canonical_headers and
            # signed_headers include those that you want to be included in the
            # hash of the request. "Host" and "x-amz-date" are always required.
            # For Roles Anywhere, content-type and x-amz-x509
            # are also required.
            signed_headers = "content-type;host;x-amz-date;x-amz-x509"

            # Step 6: Create payload hash. In this example,
            # the payload (body of the request) contains the request
            # parameters.
            payload_hash = hashlib.sha256(
                request_parameters.encode("utf-8")
            ).hexdigest()

            # Step 7: Combine elements to create canonical request
            canonical_request = (
                method
                + "\n"
                + canonical_uri
                + "\n"
                + canonical_querystring
                + "\n"
                + canonical_headers
                + "\n"
                + signed_headers
                + "\n"
                + payload_hash
            )

            # ************* TASK 2: CREATE THE STRING TO SIGN*************
            # Match the algorithm to the hashing algorithm you use, SHA-256
            algorithm = "AWS4-X509-RSA-SHA256"
            credential_scope = (
                date_stamp + "/" + region + "/" + service + "/" + "aws4_request"
            )
            string_to_sign = (
                algorithm
                + "\n"
                + amz_date
                + "\n"
                + credential_scope
                + "\n"
                + hashlib.sha256(canonical_request.encode("utf-8")).hexdigest()
            )

            # ************* TASK 3: CALCULATE THE SIGNATURE *************
            # Sign the string_to_sign using the private_key and hex encode
            signature = private_key.sign(
                data=string_to_sign.encode("utf-8"),
                padding=padding.PKCS1v15(),
                algorithm=hashes.SHA256(),
            )
            signature_hex = signature.hex()

            # *** TASK 4: ADD SIGNING INFORMATION TO THE REQUEST ***
            # Put the signature information in a header named Authorization.
            authorization_header = (
                algorithm
                + " "
                + "Credential="
                + str(serial_number_dec)
                + "/"
                + credential_scope
                + ", "
                + "SignedHeaders="
                + signed_headers
                + ", "
                + "Signature="
                + signature_hex
            )

            # For Roles Anywhere, the request  MUST include "host",
            #  "x-amz-date", "x-amz-x509", "content-type", and
            # "Authorization".Except for the authorization
            # header, the headers must be included in the canonical_headers
            #  and signed_headers values, as
            # noted earlier. Order here is not significant.
            # # Python note: The 'host' header is added automatically by the
            #  Python 'requests' library.
            headers = {
                "Content-Type": content_type,
                "X-Amz-Date": amz_date,
                "X-Amz-X509": amz_x509,
                "Authorization": authorization_header,
                "User-Agent": self.user_agent,
            }

            # ************* SEND THE REQUEST *************
            response = requests.post(
                endpoint + canonical_uri,
                data=request_parameters,
                headers=headers,
            )
            if response.status_code in [200, 201]:
                return self.parse_response(response)
            elif response.status_code == 403:
                err_msg = (
                    "Access Denied. Verify the Profile ARN, "
                    "Role ARN, Trust Anchor ARN and Region Name provided in"
                    " configuration parameters and the policies"
                    " attached to the role."
                )
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg}",
                    details=f"{self.parse_response(response)}",
                )
                raise AWSSQSException(err_msg)
            elif response.status_code == 404:
                err_msg = (
                    "Resource not found. Verify the Profile ARN,"
                    "Role ARN and Trust Anchor ARN provided in"
                    " configuration parameters."
                )
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg}.",
                    details=f"{self.parse_response(response)}",
                )
                raise AWSSQSException(err_msg)
            elif response.status_code >= 400 and response.status_code < 500:
                err_msg = (
                    f"Received exit code {response.status_code},"
                    " HTTP client error. Verify the Profile ARN,"
                    " Role ARN, Trust Anchor ARN and Region Name "
                    "provided in configuration parameters."
                )
                resp_json = self.parse_response(response=response)
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg}",
                    details=f"{resp_json}",
                )
                raise AWSSQSException(err_msg)
            elif response.status_code >= 500 and response.status_code < 600:
                err_msg = (
                    f"Received exit code {response.status_code}." " HTTP Server Error."
                )

                resp_json = self.parse_response(response=response)
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg}",
                    details=f"{resp_json}",
                )
                raise AWSSQSException(err_msg)
            else:
                err_msg = f"Received exit code {response.status_code}. HTTP Error."
                resp_json = self.parse_response(response=response)
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg}",
                    details=f"{resp_json}",
                )
                raise AWSSQSException(err_msg)

        except NoCredentialsError as exp:
            err_msg = (
                "No AWS Credentials were found in the environment."
                " Deploy the plugin into AWS environment or use AWS IAM "
                "Roles Anywhere authentication method."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}.",
                details=f"Error: {exp}",
            )
            raise AWSSQSException(err_msg)
        except AWSSQSException:
            raise
        except Exception as exp:
            err_msg = "Error occurred while generating Temporary Credentials."
            self.logger.error(
                message=(f"{self.log_prefix}: {err_msg} Error: {exp}"),
                details=traceback.format_exc(),
            )
            raise AWSSQSException(err_msg)
