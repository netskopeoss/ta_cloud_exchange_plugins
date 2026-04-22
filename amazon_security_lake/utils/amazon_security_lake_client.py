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

Amazon Security Lake Client Class."""


import traceback
import uuid
import time
import json
from copy import deepcopy
import boto3
from botocore.exceptions import (
    NoCredentialsError,
    ClientError,
    ReadTimeoutError,
    EndpointConnectionError,
    ConnectionClosedError,
    ConnectTimeoutError,
)
from datetime import datetime, timedelta, timezone
from botocore.config import Config
from .amazon_security_lake_generate_temporary_credentials import (
    AmazonSecurityLakeGenerateTemporaryCredentials
)
from .amazon_security_lake_exceptions import AmazonSecurityLakeException
from .amazon_security_lake_constants import (
    PLUGIN_NAME,
    DATE_FORMAT,
    VALIDATION_MAX_RETRIES,
    MAX_RETRIES,
    READ_TIMEOUT,
    S3_PARTITION_PATH,
    S3_UPLOAD_RETRY_DELAY_SECONDS,
    USER_AGENT,
    IAM_ROLES_ANYWHERE_TRUST_POLICY_TEMPLATE,
    IAM_ROLES_ANYWHERE_REQUIRED_ACTIONS,
)


ASSUMED_ROLE_DURATION_SECONDS = 3600
ASSUMED_ROLE_EXPIRY_BUFFER_SECONDS = 180  # Refresh 3 minutes early


class AmazonSecurityLakeClient:
    """Amazon Security Lake Client Class."""

    def __init__(
        self, configuration, logger, proxy, storage, log_prefix
    ):
        """Init method."""
        self.configuration = configuration
        self.logger = logger
        self.proxy = proxy
        self.storage = storage
        self.log_prefix = log_prefix
        self.aws_private_key = None
        self.aws_public_key = None
        self.aws_session_token = None

    def set_credentials(self):
        try:
            if (
                self.configuration.get("authentication_method")
                == "aws_iam_roles_anywhere"
            ):
                temp_creds_obj = AmazonSecurityLakeGenerateTemporaryCredentials(  # noqa: E501
                    self.configuration,
                    self.logger,
                    self.proxy,
                    self.storage,
                    self.log_prefix,
                    USER_AGENT,
                )
                if self.storage is None:
                    self.storage = {}
                credentials_in_storage = self.storage.get("credentials")
                if not credentials_in_storage:
                    temporary_credentials = (
                        temp_creds_obj.generate_temporary_credentials()
                    )
                    credentials = temporary_credentials.get("credentialSet")[
                        0
                    ].get("credentials")
                    if credentials:
                        self.storage["credentials"] = credentials
                        credentials_in_storage = credentials
                    else:
                        raise AmazonSecurityLakeException(
                            "Unable to generate Temporary Credentials. "
                            "Check the configuration parameters."
                        )

                elif credentials_in_storage.get("expiration"):
                    expiration = datetime.strptime(
                        credentials_in_storage.get("expiration"),
                        DATE_FORMAT,
                    ).replace(tzinfo=timezone.utc)
                    refresh_deadline = datetime.now(timezone.utc) + timedelta(
                        minutes=3
                    )
                    if expiration <= refresh_deadline:
                        temporary_credentials = (
                            temp_creds_obj.generate_temporary_credentials()
                        )
                        credentials = temporary_credentials.get(
                            "credentialSet"
                        )[0].get("credentials")
                        self.storage["credentials"] = credentials
                        credentials_in_storage = credentials
                credentials_from_storage = credentials_in_storage
                self.aws_public_key = credentials_from_storage.get(
                    "accessKeyId"
                )
                self.aws_private_key = credentials_from_storage.get(
                    "secretAccessKey"
                )
                self.aws_session_token = credentials_from_storage.get(
                    "sessionToken"
                )
            return self.storage
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
            raise AmazonSecurityLakeException(err_msg)
        except AmazonSecurityLakeException:
            raise
        except Exception as err:
            err_msg = "Error occurred while setting credentials."
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {err}",
                details=traceback.format_exc(),
            )
            raise AmazonSecurityLakeException(err_msg)

    def get_aws_s3_client(self, validation_retries=None):
        """To get aws client.
        
        Note: Caller is responsible for setting credentials before calling this method.
        """
        try:
            retries = {
                "max_attempts": (
                    validation_retries
                    if validation_retries is not None
                    else MAX_RETRIES
                ),
                "mode": "standard",
            }
            amazon_security_lake_client = boto3.client(
                "s3",
                aws_access_key_id=self.aws_public_key,
                aws_secret_access_key=self.aws_private_key,
                aws_session_token=self.aws_session_token,
                region_name=self.configuration.get("region_name").strip(),
                config=Config(
                    proxies=self.proxy,
                    user_agent=USER_AGENT,
                    read_timeout=READ_TIMEOUT,
                    retries=retries,
                ),
            )
            return amazon_security_lake_client
        except ReadTimeoutError as exp:
            err_msg = (
                "Read timeout error occurred while creating "
                f"AWS Security Lake client object for {PLUGIN_NAME}."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {exp}",
                details=str(traceback.format_exc()),
            )
            raise AmazonSecurityLakeException(str(exp))
        except ClientError as error:
            if (
                hasattr(error, "response")
                and error.response
                and error.response.get("Error", {}).get("Message")
            ):
                err_msg = error.response["Error"].get("Message")
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg}",
                    details=traceback.format_exc(),
                )
                raise AmazonSecurityLakeException(err_msg)
            else:
                self.logger.error(
                    message=f"{self.log_prefix}: {str(error)}",
                    details=traceback.format_exc(),
                )
                raise AmazonSecurityLakeException(str(error))
        except Exception as exp:
            err_msg = (
                f"Error occurred while creating {PLUGIN_NAME} client object."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {exp}",
                details=str(traceback.format_exc()),
            )
            raise AmazonSecurityLakeException(err_msg)

    def validate_credentials(self):
        """Validate credentials.

        Returns:
            Whether the provided value is valid or not. True in
            case of valid value, False otherwise
        """
        resolution = "Please check if the AWS credentials are valid and the AWS region is correct."
        try:
            self.set_credentials()
            retries = {
                "max_attempts": VALIDATION_MAX_RETRIES,
                "mode": "standard",
            }
            amazon_security_lake_resource = boto3.resource(
                "s3",
                aws_access_key_id=self.aws_public_key,
                aws_secret_access_key=self.aws_private_key,
                aws_session_token=self.aws_session_token,
                region_name=self.configuration.get("region_name").strip(),
                config=Config(
                    proxies=self.proxy,
                    user_agent=USER_AGENT,
                    retries=retries,
                ),
            )

            for _ in amazon_security_lake_resource.buckets.all():
                break
            return True
        except ReadTimeoutError as exp:
            err_msg = (
                "Read timeout error occurred while creating "
                f"AWS Security Lake resource for {PLUGIN_NAME}."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {exp}",
                details=str(traceback.format_exc()),
                resolution=resolution
            )
            raise AmazonSecurityLakeException(err_msg)
        except ClientError as error:
            if (
                hasattr(error, "response")
                and error.response
                and error.response.get("Error", {}).get("Message")
            ):
                err_msg = error.response["Error"].get("Message")
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg} Error: {error}",
                    details=traceback.format_exc(),
                    resolution=resolution
                )
                raise AmazonSecurityLakeException(err_msg)
            else:
                err_msg = "Invalid AWS Credentials provided."
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg} Error: {error}",
                    details=traceback.format_exc(),
                    resolution=resolution
                )
                raise AmazonSecurityLakeException(err_msg)
        except Exception as exp:
            err_msg = "Error occurred while validating credentials."
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {exp}",
                details=str(traceback.format_exc()),
                resolution=resolution
            )
            raise AmazonSecurityLakeException(err_msg)

    def get_iam_client(self, validation_retries=None):
        """Get AWS IAM client.
        
        Returns:
            boto3.client: IAM client object.
        """
        try:
            self.set_credentials()
            retries = {
                "max_attempts": (
                    validation_retries
                    if validation_retries is not None
                    else MAX_RETRIES
                ),
                "mode": "standard",
            }
            iam_client = boto3.client(
                "iam",
                aws_access_key_id=self.aws_public_key,
                aws_secret_access_key=self.aws_private_key,
                aws_session_token=self.aws_session_token,
                region_name=self.configuration.get("region_name").strip(),
                config=Config(
                    proxies=self.proxy,
                    user_agent=USER_AGENT,
                    read_timeout=READ_TIMEOUT,
                    retries=retries,
                ),
            )
            return iam_client
        except ReadTimeoutError as exp:
            err_msg = (
                "Read timeout error occurred while creating "
                f"AWS IAM client object for {PLUGIN_NAME}."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {exp}",
                details=str(traceback.format_exc()),
            )
            raise AmazonSecurityLakeException(str(exp))
        except ClientError as error:
            if (
                hasattr(error, "response")
                and error.response
                and error.response.get("Error", {}).get("Message")
            ):
                err_msg = error.response["Error"].get("Message")
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg}",
                    details=traceback.format_exc(),
                )
                raise AmazonSecurityLakeException(err_msg)
            else:
                self.logger.error(
                    message=f"{self.log_prefix}: {str(error)}",
                    details=traceback.format_exc(),
                )
                raise AmazonSecurityLakeException(str(error))
        except Exception as exp:
            err_msg = (
                f"Error occurred while creating {PLUGIN_NAME} "
                "IAM client object."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {exp}",
                details=str(traceback.format_exc()),
            )
            raise AmazonSecurityLakeException(err_msg)

    def update_provider_role_trust_policy(self, provider_role_arn):
        """Verify/update Provider Role trust policy for IAM Roles Anywhere.
        
        Checks if the trust policy already has the required permissions. If not,
        updates the policy.
        
        Args:
            provider_role_arn (str): ARN of the Provider Role to check/update.
        
        Returns:
            bool: True if trust policy is sufficient or was updated successfully.
                  False if verification/update failed (non-fatal).
        """

        role_name = provider_role_arn.split("/")[-1]
        account_id = provider_role_arn.split(":")[4]
        required_principal = f"arn:aws:iam::{account_id}:root"
        required_actions = {
            action.lower() for action in IAM_ROLES_ANYWHERE_REQUIRED_ACTIONS
        }

        def _policy_has_required_statement(policy_doc):
            statements = policy_doc.get("Statement", [])
            if not isinstance(statements, list):
                statements = [statements]

            for stmt in statements:
                if not isinstance(stmt, dict):
                    continue
                if stmt.get("Effect") != "Allow":
                    continue

                principal = stmt.get("Principal", {})
                principal_aws = None
                if isinstance(principal, dict):
                    principal_aws = principal.get("AWS")

                if isinstance(principal_aws, list):
                    if required_principal not in principal_aws:
                        continue
                elif principal_aws != required_principal:
                    continue

                actions = stmt.get("Action", [])
                if isinstance(actions, str):
                    actions = [actions]
                action_set = {action.lower() for action in actions}
                if required_actions.issubset(action_set):
                    return True
            return False

        try:
            iam_client = self.get_iam_client()
        except AmazonSecurityLakeException as exp:
            self.logger.error(
                f"{self.log_prefix}: Unable to create IAM client for "
                f"trust policy verification: {str(exp)}"
            )
            return False
        except Exception as exp:
            self.logger.error(
                f"{self.log_prefix}: Unexpected error creating IAM client for "
                f"trust policy verification: {str(exp)}"
            )
            return False

        try:
            role = iam_client.get_role(RoleName=role_name)
            assume_role_policy = role.get("Role", {}).get(
                "AssumeRolePolicyDocument", {}
            )
        except ClientError as error:
            error_code = error.response.get("Error", {}).get("Code", "Unknown")
            error_message = error.response.get("Error", {}).get("Message", str(error))
            self.logger.error(
                f"{self.log_prefix}: Failed to read trust policy for "
                f"Provider Role '{role_name}': [{error_code}] {error_message}. "
                "Manual verification may be required."
            )
            return False
        except Exception as exp:
            self.logger.error(
                f"{self.log_prefix}: Unexpected error reading trust policy for "
                f"Provider Role '{role_name}': {str(exp)}"
            )
            return False

        if _policy_has_required_statement(assume_role_policy):
            self.logger.debug(
                f"{self.log_prefix}: Provider Role '{role_name}' trust policy "
                "already permits required actions for IAM Roles Anywhere."
            )
            return True

        try:
            trust_policy = deepcopy(IAM_ROLES_ANYWHERE_TRUST_POLICY_TEMPLATE)
            trust_policy["Statement"][0]["Principal"]["AWS"] = required_principal
            iam_client.update_assume_role_policy(
                RoleName=role_name,
                PolicyDocument=json.dumps(trust_policy),
            )

            self.logger.info(
                f"{self.log_prefix}: Updated trust policy for Provider Role "
                f"'{role_name}' to allow {required_principal} with actions "
                f"{IAM_ROLES_ANYWHERE_REQUIRED_ACTIONS}."
            )
            return True

        except ClientError as error:
            error_code = error.response.get("Error", {}).get("Code", "Unknown")
            error_message = error.response.get("Error", {}).get("Message", str(error))
            self.logger.error(
                f"{self.log_prefix}: Failed to update trust policy for "
                f"Provider Role '{role_name}': [{error_code}] {error_message}. "
                "Manual update may be required."
            )
            return False
        except Exception as exp:
            self.logger.error(
                f"{self.log_prefix}: Unexpected error updating trust policy for "
                f"Provider Role '{role_name}': {str(exp)}. "
                "Manual update may be required."
            )
            return False

    def _ensure_trust_policy_if_applicable(self, provider_role_arn, source_name=None):
        """Wrapper that checks/updates trust policy only when IAM Roles Anywhere is used
        and auto_update_trust_policy is enabled.
        
        Args:
            provider_role_arn (str): ARN of the Provider Role.
            source_name (str, optional): Name of the custom source for logging.
        
        Returns:
            bool: True if trust policy verified/updated.
                  False if
                    not using IAMRA, or
                    auto-update disabled or
                    using IAMRA with auto-update enabled and verification/update failed.
        """
        if not provider_role_arn:
            err_msg = (
                f"Provider role ARN not provided for custom source '{source_name}'; "
                "cannot verify trust policy for IAM Roles Anywhere."
            )
            raise AmazonSecurityLakeException(err_msg)

        if self.configuration.get("authentication_method") != "aws_iam_roles_anywhere":
            return False
        
        if self.configuration.get("auto_update_trust_policy") != "yes":
            self.logger.debug(
                f"{self.log_prefix}: Auto-update trust policy is disabled. "
                "Skipping trust policy verification."
            )
            return False
        
        source_context = f" (custom source: '{source_name}')" if source_name else ""
        self.logger.info(
            f"{self.log_prefix}: Verifying trust policy for provider role "
            f"'{provider_role_arn}'{source_context}..."
        )
        
        return self.update_provider_role_trust_policy(provider_role_arn)

    def get_security_lake_client(self, validation_retries=None):
        """Get AWS Security Lake client.
        
        Returns:
            boto3.client: Security Lake client object.
        """
        try:
            self.set_credentials()
            retries = {
                "max_attempts": (
                    validation_retries
                    if validation_retries is not None
                    else MAX_RETRIES
                ),
                "mode": "standard",
            }
            securitylake_client = boto3.client(
                "securitylake",
                aws_access_key_id=self.aws_public_key,
                aws_secret_access_key=self.aws_private_key,
                aws_session_token=self.aws_session_token,
                region_name=self.configuration.get("region_name").strip(),
                config=Config(
                    proxies=self.proxy,
                    user_agent=USER_AGENT,
                    read_timeout=READ_TIMEOUT,
                    retries=retries,
                ),
            )
            return securitylake_client
        except ReadTimeoutError as exp:
            err_msg = (
                "Read timeout error occurred while creating "
                f"AWS Security Lake client object for {PLUGIN_NAME}."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {exp}",
                details=str(traceback.format_exc()),
            )
            raise AmazonSecurityLakeException(str(exp))
        except ClientError as error:
            if (
                hasattr(error, "response")
                and error.response
                and error.response.get("Error", {}).get("Message")
            ):
                err_msg = error.response["Error"].get("Message")
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg}",
                    details=traceback.format_exc(),
                )
                raise AmazonSecurityLakeException(err_msg)
            else:
                self.logger.error(
                    message=f"{self.log_prefix}: {str(error)}",
                    details=traceback.format_exc(),
                )
                raise AmazonSecurityLakeException(str(error))
        except Exception as exp:
            err_msg = (
                f"Error occurred while creating {PLUGIN_NAME} "
                "Security Lake client object."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {exp}",
                details=str(traceback.format_exc()),
            )
            raise AmazonSecurityLakeException(err_msg)

    def list_custom_log_sources(self, securitylake_client=None):
        """List all custom log sources in Security Lake.
        
        Args:
            securitylake_client: Optional Security Lake client. 
                If not provided, will create a new one.
        
        Returns:
            list: List of custom log sources.
        """
        resolution = (
            "Ensure Security Lake is configured and your configuration "
            "has permission to list its log sources."
        )
        try:            
            all_sources = []
            next_token = None

            # Iterate to handle pagination
            while True:
                request_params = {}
                if next_token:
                    request_params['nextToken'] = next_token
                
                response = securitylake_client.list_log_sources(**request_params)
                
                # Extract and filter sources from response
                for account_sources in response.get("sources", []):
                    for source in account_sources.get("sources", []):
                        if 'customLogSource' in source:
                            all_sources.append(source['customLogSource'])
                
                next_token = response.get('nextToken')
                if not next_token:
                    break

            self.logger.debug(f"{self.log_prefix}: Custom log sources found: {all_sources}")
            return all_sources

        except ClientError as error:
            if (
                hasattr(error, "response")
                and error.response
                and error.response.get("Error", {}).get("Message")
            ):
                err_msg = error.response["Error"].get("Message")
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg}",
                    details=traceback.format_exc(),
                    resolution=resolution
                )
                raise AmazonSecurityLakeException(err_msg)
            else:
                err_msg = f"Error listing custom log sources: {str(error)}"
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg}",
                    details=traceback.format_exc(),
                    resolution=resolution
                )
                raise AmazonSecurityLakeException(err_msg)
        except Exception as exp:
            err_msg = "Error occurred while listing custom log sources."
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {exp}",
                details=str(traceback.format_exc()),
                resolution=resolution
            )
            raise AmazonSecurityLakeException(err_msg)

    def create_custom_log_source(
        self, 
        source_name, 
        event_classes,
        securitylake_client=None
    ):
        """Create a custom log source in AWS Security Lake.
        
        Args:
            source_name (str): Name for the custom source (max 20 characters).
            event_classes (list): List of OCSF event classes.
            securitylake_client: Optional Security Lake client.
        
        Returns:
            dict: Response from create_custom_log_source API.
        """
        resolution = (
            "Ensure the provided configuration is valid and has permission "
            "to create custom log sources in AWS Security Lake."
        )
        try:
            if not securitylake_client:
                securitylake_client = self.get_security_lake_client()
            
            crawler_role_arn = self.configuration.get("crawler_role_arn", "").strip()
            provider_external_id = self.configuration.get("provider_external_id", "").strip()
            provider_principal = self.configuration.get("provider_principal", "").strip()
            
            request_params = {
                "sourceName": source_name,
                "configuration": {
                    "crawlerConfiguration": {
                        "roleArn": crawler_role_arn,
                    },
                    "providerIdentity": {
                        "externalId": provider_external_id,
                        "principal": provider_principal,
                    },
                },
                "eventClasses": event_classes,
            }
            
            self.logger.info(
                f"{self.log_prefix}: Creating custom log source '{source_name}' "
                f"with event classes {event_classes}..."
            )
            
            response = securitylake_client.create_custom_log_source(**request_params)
            
            # Extract S3 location from response
            source = response.get("source", {})
            provider = source.get("provider", {})
            s3_location = provider.get("location", "")
            
            self.logger.info(
                f"{self.log_prefix}: Successfully created custom log source "
                f"'{source_name}'. S3 Location: {s3_location}"
            )
            
            return response
            
        except ClientError as error:
            error_code = error.response.get("Error", {}).get("Code", "Unknown")
            error_message = error.response.get("Error", {}).get("Message", str(error))
            
            # If ConflictException, the source already exists - don't fail
            if error_code == "ConflictException":
                self.logger.info(
                    f"{self.log_prefix}: Custom log source '{source_name}' "
                    "already exists. Continuing..."
                )
                # Return None to indicate it already exists
                return None
            
            err_msg = (
                f"AWS API error occurred while creating custom log source "
                f"'{source_name}': [{error_code}] {error_message}"
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=traceback.format_exc(),
                resolution=resolution
            )
            raise AmazonSecurityLakeException(err_msg)
        except AmazonSecurityLakeException:
            raise
        except Exception as exp:
            err_msg = (
                f"Unexpected error occurred while creating custom log source "
                f"'{source_name}': {str(exp)}"
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=str(traceback.format_exc()),
                resolution=resolution
            )
            raise AmazonSecurityLakeException(err_msg)

    def get_or_create_custom_log_source(
        self, 
        source_name, 
        event_classes,
        max_retries=3
    ):
        """Get or create a custom log source, with retry logic.
        
        This method
            1. first checks if the source exists. 
            2. If not, it attempts to create it with up to max_retries attempts.
        
        Args:
            source_name (str): Name for the custom source.
            event_classes (list): List of OCSF event classes.
            max_retries (int): Maximum number of creation attempts.
        
        Returns:
            dict: {"s3_location": str, "provider_role_arn": str}
        """
        resolution = (
            "Ensure the provided configuration is valid and has permission "
            "to create custom log sources in AWS Security Lake."
            "Check details for detailed error."
        )
        try:
            securitylake_client = self.get_security_lake_client()

            def _extract_provider_details(sources, context):
                """Inner helper that extracts provider metadata for source_name."""
                self.logger.debug(
                    f"{self.log_prefix}: Searching through listed {sources} custom sources "
                    f"for S3 location of '{source_name}' during {context}."
                )

                for idx, source in enumerate(sources, start=1):
                    if source.get("sourceName") != source_name:
                        continue

                    s3_location = source.get("provider", {}).get("location", "")
                    provider_role_arn = source.get("provider", {}).get("roleArn")
                    if s3_location:
                        self.logger.debug(
                            f"{self.log_prefix}: Located existing custom log source "
                            f"'{source_name}' (entry #{idx}) during {context}. "
                            f"S3 Location: {s3_location}"
                        )
                        return {
                            "s3_location": s3_location,
                            "provider_role_arn": provider_role_arn,
                        }

                    self.logger.info(
                        f"{self.log_prefix}: Custom log source '{source_name}' found "
                        f"during {context} but missing provider location."
                    )
                    return None

                self.logger.debug(
                    f"{self.log_prefix}: Custom log source '{source_name}' not found "
                    f"in provided list during {context}."
                )
                return None

            def _attach_trust_check(provider_details):
                """Attach trust_policy_checked flag after verifying/updating trust policy."""
                if not provider_details:
                    return None
                provider_role_arn = provider_details.get("provider_role_arn")
                trust_policy_checked = self._ensure_trust_policy_if_applicable(
                    provider_role_arn, source_name
                )
                provider_details["trust_policy_checked"] = trust_policy_checked
                return provider_details
            
            # First, try to list and find the source
            custom_sources = self.list_custom_log_sources(securitylake_client)
            
            if provider_details := _extract_provider_details(
                sources=custom_sources,
                context="initial lookup"
            ):
                return _attach_trust_check(provider_details)
            
            # Source doesn't exist, try to create it
            self.logger.info(
                f"{self.log_prefix}: Custom log source '{source_name}' not found. "
                "Attempting to create..."
            )
            
            last_exception = None
            for attempt in range(1, max_retries + 1):
                try:
                    response = self.create_custom_log_source(
                        source_name=source_name,
                        event_classes=event_classes,
                        securitylake_client=securitylake_client
                    )
                    
                    # If response is None, source already exists (ConflictException)
                    # Re-fetch from list to get S3 location
                    if response is None:
                        self.logger.info(
                            f"{self.log_prefix}: Source '{source_name}' already exists. "
                            "Fetching S3 location from existing source..."
                        )
                        custom_sources = self.list_custom_log_sources(securitylake_client)
                        if provider_details := _extract_provider_details(
                            sources=custom_sources,
                            context="post-conflict lookup"
                        ):
                            return _attach_trust_check(provider_details)
                        # If we still can't find it, raise error
                        err_msg = (
                            f"Source '{source_name}' exists but could not retrieve "
                            "S3 location from list."
                        )
                        raise AmazonSecurityLakeException(err_msg)
                    
                    # Successfully created - extract S3 location from response
                    source = response.get("source", {})
                    provider = source.get("provider", {})
                    s3_location = provider.get("location", "")
                    provider_role_arn = provider.get("roleArn")

                    if s3_location:
                        provider_details = {
                            "s3_location": s3_location,
                            "provider_role_arn": provider_role_arn,
                        }
                        return _attach_trust_check(provider_details)
                    else:
                        err_msg = (
                            f"Created custom source '{source_name}' but "
                            "S3 location not found in response."
                        )
                        raise AmazonSecurityLakeException(err_msg)
                    
                except AmazonSecurityLakeException as e:
                    last_exception = e
                    if attempt < max_retries:
                        self.logger.info(
                            f"{self.log_prefix}: Attempt {attempt}/{max_retries} "
                            f"to create custom source '{source_name}' failed. "
                            f"Retrying... Error: {str(e)}"
                        )
                    else:
                        self.logger.error(
                            f"{self.log_prefix}: All {max_retries} attempts to "
                            f"create custom source '{source_name}' failed."
                        )
            
            # All retries exhausted
            if last_exception:
                raise last_exception
            else:
                err_msg = (
                    f"Failed to create custom source '{source_name}' "
                    f"after {max_retries} attempts."
                )
                raise AmazonSecurityLakeException(err_msg)
                
        except AmazonSecurityLakeException as exc:
            err_msg = str(exc)
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=str(traceback.format_exc()),
                resolution=resolution,
            )
            raise exc
        except Exception as exp:
            err_msg = (
                f"Error occurred while getting or creating custom log source "
                f"'{source_name}': {str(exp)}"
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=str(traceback.format_exc()),
                resolution=resolution,
            )
            raise AmazonSecurityLakeException(err_msg)

    def assume_provider_role(self, role_arn, external_id, session_context=None):
        """Assume the Security Lake provider role and cache credentials."""
        resolution = (
            "Ensure the provided role ARN and external ID are valid and have permission "
            "to assume the provider role in AWS Security Lake."
            "Check details for detailed error."
        )
        try:
            if not role_arn:
                raise AmazonSecurityLakeException(
                    "Provider role ARN is required to assume role."
                )
            if not external_id:
                raise AmazonSecurityLakeException(
                    "Provider External ID is required to assume provider role."
                )

            assumed_roles_cache = self.storage.setdefault("assumed_roles", {})
            cached_role = assumed_roles_cache.get(role_arn)
            current_epoch = int(time.time())

            if (
                cached_role
                and cached_role.get("expires_at", 0)
                > current_epoch + ASSUMED_ROLE_EXPIRY_BUFFER_SECONDS
            ):
                self.logger.debug(
                    f"{self.log_prefix}: Using cached credentials for provider role '{role_arn}'."
                )
                self.aws_public_key = cached_role.get("access_key_id")
                self.aws_private_key = cached_role.get("secret_access_key")
                self.aws_session_token = cached_role.get("session_token")
                return cached_role

            # Refresh base credentials to ensure AssumeRole succeeds
            self.set_credentials()

            retries = {
                "max_attempts": MAX_RETRIES,
                "mode": "standard",
            }

            sts_client = boto3.client(
                "sts",
                aws_access_key_id=self.aws_public_key,
                aws_secret_access_key=self.aws_private_key,
                aws_session_token=self.aws_session_token,
                region_name=self.configuration.get("region_name").strip(),
                config=Config(
                    proxies=self.proxy,
                    user_agent=USER_AGENT,
                    read_timeout=READ_TIMEOUT,
                    retries=retries,
                ),
            )

            role_session_name = (
                f"NetskopeSecurityLake-{session_context}"
                if session_context
                else f"NetskopeSecurityLake-{uuid.uuid4().hex[:8]}"
            )

            self.logger.info(
                f"{self.log_prefix}: Assuming provider role "
                f"for session '{role_session_name}'."
            )

            response = sts_client.assume_role(
                RoleArn=role_arn,
                RoleSessionName=role_session_name,
                ExternalId=external_id,
                DurationSeconds=ASSUMED_ROLE_DURATION_SECONDS,
            )

            credentials = response.get("Credentials")
            if not credentials:
                err_msg = "AssumeRole response missing credentials."
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg}",
                    details=traceback.format_exc(),
                    resolution=resolution,
                )
                raise AmazonSecurityLakeException(err_msg)
            if not credentials.get("SessionToken"):
                err_msg = "AssumeRole response missing session token."
                self.logger.error(
                    message=f"{self.log_prefix}: {err_msg}",
                    details=traceback.format_exc(),
                    resolution=resolution,
                )
                raise AmazonSecurityLakeException(err_msg)

            assumed_credentials = {
                "access_key_id": credentials.get("AccessKeyId"),
                "secret_access_key": credentials.get("SecretAccessKey"),
                "session_token": credentials.get("SessionToken"),
                "expires_at": int(credentials.get("Expiration").timestamp()),
            }

            assumed_roles_cache[role_arn] = assumed_credentials
            self.storage["assumed_roles"] = assumed_roles_cache
            self.logger.debug(
                f"{self.log_prefix}: Cached provider role credentials for '{role_arn}' "
                f"until {credentials.get('Expiration')}."
            )
            self.aws_public_key = assumed_credentials.get("access_key_id")
            self.aws_private_key = assumed_credentials.get("secret_access_key")
            self.aws_session_token = assumed_credentials.get("session_token")
            return assumed_credentials
        except AmazonSecurityLakeException:
            raise
        except ClientError as error:
            err_msg = (
                f"Failed to assume provider role '{role_arn}'. "
                f"{error.response.get('Error', {}).get('Message', str(error))}"
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=traceback.format_exc(),
                resolution=resolution,
            )
            raise AmazonSecurityLakeException(err_msg)
        except Exception as exp:
            err_msg = (
                f"Unexpected error occurred while assuming provider role '{role_arn}'."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg} Error: {exp}",
                details=str(traceback.format_exc()),
                resolution=resolution,
            )
            raise AmazonSecurityLakeException(err_msg)

    def upload_file_to_s3(
        self,
        file_path,
        s3_location,
        provider_role_arn=None,
        custom_source_name=None,
    ):
        """Upload a local file to the Security Lake S3 bucket with retries.

        Args:
            file_path (str): Path to the local file to upload.
            s3_location (str): Destination S3 location returned by custom source.
            provider_role_arn (str, optional): Provider role to assume for cross-account uploads.
            custom_source_name (str, optional): Name of the custom source for logging.
        """
        resolution = (
            "Ensure the S3 location is valid and the parquet file path is correct."
            "Ensure that AWS configuration has permission to upload files "
            "to S3 bucket and the AWS Region is correct."
        )
        try:
            if not s3_location:
                error_message = (
                    "S3 location is required for upload. "
                    "Each subtype has its own S3 bucket determined by the custom source."
                )
                self.logger.error(f"{self.log_prefix}: {error_message}")
                raise AmazonSecurityLakeException(error_message)

            bucket_name = None
            base_path = None

            # Parse s3_location to extract bucket name and path
            # s3_location can be in format:
            # 1. "s3://bucket-name/path/to/location" (full S3 URI)
            # 2. "path/to/location" (just the path, bucket needs to be determined)
            if s3_location.startswith("s3://"):
                parts = s3_location[5:].split("/", 1)
                bucket_name = parts[0]
                base_path = parts[1] if len(parts) > 1 else ""
            else:
                self.logger.debug(f"{self.log_prefix}: s3_location is not a full S3 URI, using default bucket name.")
                base_path = s3_location
                region_name = self.configuration.get("region_name", "").strip()
                account_id = self.configuration.get("account_id", "").strip()

                if not account_id or not region_name:
                    error_message = (
                        "Cannot determine bucket name from s3_location path. "
                        "Account ID and region name are required in configuration."
                    )
                    self.logger.error(f"{self.log_prefix}: {error_message}")
                    raise AmazonSecurityLakeException(error_message)

                bucket_name = f"aws-security-data-lake-{account_id}-{region_name}"

            if provider_role_arn:
                external_id = self.configuration.get(
                    "provider_external_id", ""
                ).strip()
                self.assume_provider_role(
                    role_arn=provider_role_arn,
                    external_id=external_id,
                    session_context=custom_source_name,
                )
                self.logger.debug(f"{self.log_prefix}: Assumed provider role '{provider_role_arn}' for upload.")
            else:
                self.set_credentials()

            s3_client = self.get_aws_s3_client()

            prefix = self.configuration.get("prefix", "").strip()
            folder_name = "eventDay=" + datetime.now(timezone.utc).strftime("%Y%m%d")
            file_name = (
                str(uuid.uuid1()) + "--" + datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
            )

            if prefix:
                file_name = f"{prefix}_{file_name}"

            region_name = self.configuration.get("region_name", "").strip()
            account_id = self.configuration.get("account_id", "").strip()

            if not region_name or not account_id:
                error_message = (
                    "Cannot construct partitioned path. "
                    "Region name and Account ID are required in configuration."
                )
                self.logger.error(f"{self.log_prefix}: {error_message}")
                raise AmazonSecurityLakeException(error_message)

            if not base_path:
                error_message = (
                    "S3 base path is required but not provided in s3_location. "
                    "The s3_location from AWS Security Lake API should contain a valid base path."
                )
                self.logger.error(
                    message=f"{self.log_prefix}: {error_message}",
                    details=traceback.format_exc(),
                    resolution=(
                        "Ensure the s3_location from AWS Security Lake API contains a valid base path."
                        "Check details for detailed error."
                    ),
                )
                raise AmazonSecurityLakeException(error_message)

            base_path = base_path.rstrip("/")
            s3_key = f"{base_path}/{S3_PARTITION_PATH.format(region_name, account_id, folder_name, file_name)}"

            self.logger.debug(
                f"{self.log_prefix}: Uploading file {file_path} to AWS Security Lake bucket "
                f"{bucket_name}."
            )
            if custom_source_name:
                self.logger.debug(
                    f"{self.log_prefix}: Custom source '{custom_source_name}' upload initiated."
                )

            # Retry mechanism for transient S3 upload errors
            last_exception = None
            for attempt in range(1, MAX_RETRIES + 1):
                try:
                    s3_client.upload_file(file_path, bucket_name, s3_key)
                    self.logger.info(
                        f"{self.log_prefix}: Successfully uploaded file {file_path} "
                        f"to bucket {bucket_name}."
                    )
                    return s3_key
                except (
                    EndpointConnectionError,
                    ConnectionClosedError,
                    ConnectTimeoutError,
                    ReadTimeoutError,
                ) as e:
                    last_exception = e
                    err_msg = (
                        f"S3 upload attempt {attempt}/{MAX_RETRIES} failed "
                        f"due to transient network error: {str(e)}. "
                        f"{'Retrying in ' + str(S3_UPLOAD_RETRY_DELAY_SECONDS) + ' seconds...' if attempt < MAX_RETRIES else 'No more retries left.'}"
                    )
                    self.logger.error(
                        message=f"{self.log_prefix}: {err_msg}",
                        details=traceback.format_exc(),
                        resolution=resolution,
                    )
                    if attempt < MAX_RETRIES:
                        time.sleep(S3_UPLOAD_RETRY_DELAY_SECONDS)
                except ClientError as e:
                    error_code = e.response.get("Error", {}).get("Code", "")
                    retryable_codes = [
                        "RequestTimeout",
                        "Throttling",
                        "ServiceUnavailable",
                        "SlowDown",
                        "InternalError",
                        "ExpiredTokenException",
                        "ExpiredToken"
                    ]
                    if error_code in retryable_codes:
                        last_exception = e
                        err_msg = (
                            f"S3 upload attempt {attempt}/{MAX_RETRIES} failed "
                            f"due to transient AWS error {error_code}: {str(e)}. "
                            f"{'Retrying in ' + str(S3_UPLOAD_RETRY_DELAY_SECONDS) + ' seconds...' if attempt < MAX_RETRIES else 'No more retries left.'}"
                        )
                        self.logger.error(
                            message=f"{self.log_prefix}: {err_msg}",
                            details=traceback.format_exc(),
                            resolution=resolution,
                        )
                        if attempt < MAX_RETRIES:
                            time.sleep(S3_UPLOAD_RETRY_DELAY_SECONDS)
                    else:
                        err_msg = (
                            f"S3 upload failed with non-retryable error {error_code}: {str(e)}. "
                            "Not retrying."
                        )
                        self.logger.error(
                            message=f"{self.log_prefix}: {err_msg}",
                            details=traceback.format_exc(),
                            resolution=resolution,
                        )
                        raise AmazonSecurityLakeException(
                            f"S3 upload failed with error {error_code}: {str(e)}"
                        )
                except Exception as e:
                    err_msg = (
                        f"S3 upload failed with unexpected error: {str(e)}. "
                        "Not retrying."
                    )
                    self.logger.error(
                        message=f"{self.log_prefix}: {err_msg}",
                        details=traceback.format_exc(),
                        resolution=resolution,
                    )
                    raise AmazonSecurityLakeException(err_msg)

            error_message = (
                f"S3 upload failed after {MAX_RETRIES} attempts. "
                f"Last error: {type(last_exception).__name__} - {str(last_exception)}"
            )
            raise AmazonSecurityLakeException(error_message)

        except AmazonSecurityLakeException:
            raise
        except Exception as e:
            error_message = (
                f"An error occurred while uploading file to AWS Security Lake bucket: "
                f"{file_path}."
            )
            self.logger.error(
                message=f"{self.log_prefix}: {error_message} Error: {str(e)}",
                details=str(traceback.format_exc()),
                resolution=resolution,
            )
            raise AmazonSecurityLakeException(error_message)
