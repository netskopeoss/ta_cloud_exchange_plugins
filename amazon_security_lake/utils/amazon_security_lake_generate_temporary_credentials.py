"""Genarating Temporary Credentials using IAM Roles Anywhere"""
import base64
import datetime
import hashlib
import requests
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding


class AmazonSecurityLakeGenerateTemporaryCredentials():
    """Amazon Security Lake validator class."""

    def __init__(self, configuration, logger, proxy):
        """Initialize."""
        self.configuration = configuration
        self.logger = logger
        self.proxy = proxy

    def generate_temporary_credentials(self):

        try:
            private_key_file = self.configuration.get("private_key_file").strip()
            pass_phrase = self.configuration.get("pass_phrase")
            public_certificate_file = self.configuration.get("public_certificate_file").strip()
            region = self.configuration.get("region_name").strip()
            duration_seconds = '900'
            profile_arn = self.configuration.get("profile_arn").strip()
            role_arn = self.configuration.get("role_arn").strip()
            session_name = 'Session'
            trust_anchor_arn = self.configuration.get("trust_anchor_arn").strip()

            method = 'POST'
            service = 'rolesanywhere'
            host = 'rolesanywhere.{}.amazonaws.com'.format(region)
            endpoint = 'https://rolesanywhere.{}.amazonaws.com'.format(region)
            content_type = 'application/json'

            try:
                private_key = serialization.load_pem_private_key(
                    private_key_file.encode("utf-8"),
                    None
                )
            except Exception:
                try:
                    private_key = serialization.load_pem_private_key(
                        private_key_file.encode("utf-8"),
                        password=str.encode(pass_phrase)
                    )
                except Exception as e:
                    raise e

            # Load public certificate
            cert = x509.load_pem_x509_certificate(public_certificate_file.encode())
            amz_x509 = str(base64.b64encode(cert.public_bytes(encoding=serialization.Encoding.DER)), 'utf-8')

            # Public certificate serial number in decimal
            serial_number_dec = cert.serial_number

            # Request parameters for CreateSession--passed in a JSON block.
            request_parameters = '{'
            request_parameters += '"durationSeconds": {},'.format(duration_seconds)
            request_parameters += '"profileArn": "{}",'.format(profile_arn)
            request_parameters += '"roleArn": "{}",'.format(role_arn)
            request_parameters += '"sessionName": "{}",'.format(session_name)
            request_parameters += '"trustAnchorArn": "{}"'.format(trust_anchor_arn)
            request_parameters += '}'

            # Create a date for headers and the credential string
            t = datetime.datetime.utcnow()
            amz_date = t.strftime('%Y%m%dT%H%M%SZ')
            date_stamp = t.strftime('%Y%m%d')

            # ************* TASK 1: CREATE A CANONICAL REQUEST *************
            # http://docs.aws.amazon.com/general/latest/gr/sigv4-create-canonical-request.html

            # Step 2: Create canonical URI--the part of the URI from domain to 
            # query
            # string (use '/' if no path)
            canonical_uri = '/sessions'

            # Step 3: Create the canonical query string. In this example, request
            # parameters are passed in the body of the request and the query string
            # is blank.
            canonical_querystring = ''

            # Step 4: Create the canonical headers. Header names must be trimmed
            # and lowercase, and sorted in code point order from low to high.
            # Note that there is a trailing \n.
            canonical_headers = 'content-type:' + content_type + '\n' + 'host:' + host + '\n' + 'x-amz-date:' + amz_date + '\n' + 'x-amz-x509:' + amz_x509 + '\n'

            # Step 5: Create the list of signed headers. This lists the headers
            # in the canonical_headers list, delimited with ";" and in alpha order.
            # Note: The request can include any headers; canonical_headers and
            # signed_headers include those that you want to be included in the
            # hash of the request. "Host" and "x-amz-date" are always required.
            # For Roles Anywhere, content-type and x-amz-x509 are also required.
            signed_headers = 'content-type;host;x-amz-date;x-amz-x509'

            # Step 6: Create payload hash. In this example, the payload (body of
            # the request) contains the request parameters.
            payload_hash = hashlib.sha256(request_parameters.encode(
                'utf-8'
            )).hexdigest()

            # Step 7: Combine elements to create canonical request
            canonical_request = method + '\n' + canonical_uri + '\n' + canonical_querystring + '\n' + canonical_headers + '\n' + signed_headers + '\n' + payload_hash

            # ************* TASK 2: CREATE THE STRING TO SIGN*************
            # Match the algorithm to the hashing algorithm you use, SHA-256
            algorithm = 'AWS4-X509-RSA-SHA256'
            credential_scope = date_stamp + '/' + region + '/' + service + '/' + 'aws4_request'
            string_to_sign = algorithm + '\n' +  amz_date + '\n' +  credential_scope + '\n' +  hashlib.sha256(canonical_request.encode('utf-8')).hexdigest()

            # ************* TASK 3: CALCULATE THE SIGNATURE *************
            # Sign the string_to_sign using the private_key and hex encode
            signature = private_key.sign(
                data=string_to_sign.encode('utf-8'),
                padding=padding.PKCS1v15(),
                algorithm=hashes.SHA256()
            )
            signature_hex = signature.hex()

            # ************* TASK 4: ADD SIGNING INFORMATION TO THE REQUEST *************
            # Put the signature information in a header named Authorization.
            authorization_header = algorithm + ' ' + 'Credential=' + str(serial_number_dec) + '/' + credential_scope + ', ' +  'SignedHeaders=' + signed_headers + ', ' + 'Signature=' + signature_hex

            # For Roles Anywhere, the request  MUST include "host", "x-amz-date",
            # "x-amz-x509", "content-type", and "Authorization". Except for the authorization
            # header, the headers must be included in the canonical_headers and signed_headers values, as
            # noted earlier. Order here is not significant.
            # # Python note: The 'host' header is added automatically by the Python 'requests' library.
            headers = {
                'Content-Type': content_type,
                'X-Amz-Date': amz_date,
                'X-Amz-X509': amz_x509,
                'Authorization': authorization_header
            }

            # ************* SEND THE REQUEST *************
            r = requests.post(
                endpoint + canonical_uri,
                data=request_parameters,
                headers=headers
            )
            if r.status_code not in [200, 201]:
                error_msg = r.json().get("message", "unexpected error.")
                raise Exception(
                    "Unable to generate Temporary Credentials. "
                    f"Error: {error_msg}"
                )
            return r.json()
        except Exception as err:
            raise err
