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
"""BitSight ARE Plugin."""

import json
import time
from datetime import datetime

import requests
from netskope.common.utils import add_user_agent
from netskope.integrations.grc.models.configuration import (
    MappingType,
    TargetMappingFields,
)
from netskope.integrations.grc.plugin_base import (
    PluginBase,
    PushResult,
    ValidationResult,
)

MAX_RETRY_COUNT = 4
PLUGIN_NAME = "BitSight ARE Plugin"


class BitSightARE(PluginBase):
    """BitSightARE plugin Class."""

    def api_call_helper(self, url, method, data=None):
        """This method help to collect data from BitSight."""
        config = self.configuration
        request_func = getattr(requests, method)
        headers = {"Authorization": f"Token {config['api_key']}"}
        headers = add_user_agent(headers)
        verify = self.ssl_validation
        proxies = self.proxy
        response = {}
        for attempt in range(MAX_RETRY_COUNT):
            resp = request_func(
                url=url,
                headers=headers,
                verify=verify,
                proxies=proxies,
                data=data,
            )
            response_json = self.handle_response(resp)
            if resp.status_code == 200 or resp.status_code == 201:
                response = response_json
                break
            elif resp.status_code == 429 and attempt < (MAX_RETRY_COUNT - 1):
                self.logger.info(
                    f"{PLUGIN_NAME}: Too many requests occurred for {url}, "
                    "retrying to make the API call. "
                    f"Retry count: {attempt + 1}."
                )
                time.sleep(60)
        else:
            raise requests.exceptions.HTTPError("Maximum retry limit reached")
        return response

    def pull_vendors(self):
        """To pull data from BitSight."""
        try:
            config = self.configuration
            url = f"{config['url'].strip('/')}/api/v2/connections.inactives"
            results = self.api_call_helper(url, method="get")
            return results

        except requests.exceptions.ProxyError:
            raise requests.HTTPError("Invalid proxy configuration.")
        except requests.exceptions.ConnectionError:
            raise requests.HTTPError(
                "Unable to establish connection, server is not reachable."
            )
        except requests.exceptions.HTTPError as ex:
            raise requests.HTTPError(
                f"Error occurred while pulling data. {ex}"
            )
        except Exception as ex:
            raise requests.HTTPError(
                f"Error occurred while pulling data. Error: {ex}"
            )

    def add_query_list(self, final_list, mapping_dict):
        """To create final dict for mapping to the destination."""
        query_dict = {}
        query_dict["operator"] = "=="
        operand_dict = mapping_dict["=="]
        query_dict["lhs"] = operand_dict[0].get("var")
        query_dict["rhs"] = operand_dict[1]
        final_list.append(query_dict)

    def get_query_builder_list(self, configuration_mapping_query):
        """To generate dict which contains operaion('and'/'or') and List of dict which contains LHS ,RHS and Operator."""
        configuration_mapping_query = configuration_mapping_query.dict()
        query_builder_dict = {}
        final_list = []
        mapping_query = configuration_mapping_query["jsonQuery"]
        list_query = mapping_query.get("and")
        query_builder_dict["operation"] = "and"
        if not list_query:
            list_query = mapping_query.get("or")
            query_builder_dict["operation"] = "or"
        for mapping_dict in list_query:
            self.add_query_list(final_list, mapping_dict)
        query_builder_dict["query_builder_list"] = final_list
        return query_builder_dict

    def check_result(self, bitsight_record_value, application_value):
        """To check value of the source fields is matching with the value of application field or not."""
        bitsight_record_value = (
            bitsight_record_value.lower()
            if isinstance(bitsight_record_value, str)
            else bitsight_record_value
        )
        if isinstance(application_value, list):
            for app_val in application_value:
                app_val = (
                    app_val.lower() if isinstance(app_val, str) else app_val
                )
                if app_val == bitsight_record_value:
                    return True
            else:
                return False

        application_value = (
            application_value.lower()
            if isinstance(application_value, str)
            else application_value
        )
        return bitsight_record_value == application_value

    def list_of_application(self, final_dict, uuid, app):
        """Final dict created with uuid of each vendor."""
        if uuid in final_dict:
            final_dict[uuid].append(app)
        else:
            final_dict[uuid] = [app]
        return final_dict

    def push(self, applications, mapping):
        """push method to store the data collected from the Netskope tenant into BitSight VRM."""
        self.logger.info(f"{PLUGIN_NAME}: Executing push method.")
        config = self.configuration
        query_builder_dict = self.get_query_builder_list(mapping)
        vendor_results = self.pull_vendors()
        if not vendor_results:
            self.logger.info(
                f"{PLUGIN_NAME}: No monitored vendors found on \
                    BitSight. Hence skipping the sharing."
            )
            return PushResult(
                success=True,
                message="Successfully pushed data to BitSight.",
            )
        final_dict = {}
        operation = query_builder_dict.get("operation")
        skip_count = 0
        for app in applications:
            check_match = False
            app_dict = app.dict()
            for vendor in vendor_results:
                count = 0
                uuid = vendor.get("company", {}).get("uuid")
                if not uuid:
                    continue
                for inner_list in query_builder_dict["query_builder_list"]:
                    count = count + 1
                    bitsight_records = vendor.get("company", {}).get(
                        f"{inner_list['lhs']}"
                    )
                    applications_value = app_dict.get(inner_list["rhs"])
                    res = self.check_result(
                        bitsight_records, applications_value
                    )
                    if res:
                        if operation == "or" or count == len(
                            query_builder_dict["query_builder_list"]
                        ):
                            final_dict = self.list_of_application(
                                final_dict, uuid, app_dict
                            )
                            check_match = True
                            break
                    elif operation == "and":
                        break
            if not check_match:
                skip_count += 1
                self.logger.warn(
                    f"{PLUGIN_NAME}: Application "
                    f"'{app_dict.get('applicationName')}' match is not "
                    "available in BitSight, skipping sharing of "
                    "this application."
                )
        current_time = datetime.now()
        current_time = current_time.strftime("%Y-%m-%d %H:%M:%S")
        shared_count = 0
        for vendor_id in final_dict:
            details = final_dict[vendor_id]
            notes = f"[Netskope CE] Last shared at: {current_time}\n"
            for detail in details:
                notes += f"Application Name: {detail.get('applicationName')}, Cloud Confidence Index: {detail.get('cci')}, CCL: {detail.get('ccl')}, Category Name: {detail.get('categoryName')}, Deep Link: {detail.get('deepLink')}<br>"
            payload = json.dumps({"notes": notes})
            try:
                _ = self.api_call_helper(
                    f"{config['url'].strip('/')}/api/tier/{vendor_id}/note",
                    method="post",
                    data=payload,
                )
                shared_count += len(details)
            except requests.exceptions.ProxyError:
                raise requests.HTTPError("Invalid proxy configuration.")
            except requests.exceptions.ConnectionError:
                raise requests.HTTPError(
                    "Unable to establish connection, server is not reachable."
                )
            except requests.exceptions.HTTPError as ex:
                raise requests.HTTPError(
                    f"Error occurred while pushing data. {ex}"
                )
            except Exception as ex:
                raise requests.HTTPError(
                    f"Error occurred while pushing data. Error: {ex}"
                )
        self.logger.info(
            f"{PLUGIN_NAME}: "
            f"Total {shared_count} applications shared successfully with "
            f"BitSight and {skip_count} applications were skipped."
        )
        return PushResult(
            success=True,
            message="Successfully pushed data to BitSight.",
        )

    def validate(self, data):
        """Validate the Plugin configuration parameters.

        Validation for all the parameters mentioned in the manifest.json for the existence and
        data type. Method returns the grc.plugin_base.ValidationResult object with success = True in the case
        of successful validation and success = False and a error message in the case of failure.
        Args:
            data (dict): Dict object having all the Plugin configuration parameters.
        Returns:
            cte.plugin_base.ValidateResult: ValidateResult object with success flag and message.
        """
        self.logger.info(
            f"{PLUGIN_NAME}: Executing validate method for BitSight plugin."
        )
        if "url" not in data or not data["url"] or type(data["url"]) != str:
            self.logger.error(
                f"{PLUGIN_NAME}: Validation error occured Error:"
                " Invalid BitSight instance URL provided."
            )
            return ValidationResult(
                success=False,
                message="Invalid BitSight Instance URL provided.",
            )

        if (
            "api_key" not in data
            or not data["api_key"]
            or type(data["api_key"]) != str
        ):
            self.logger.error(
                f"{PLUGIN_NAME}: Validation error occured Error:"
                " Invalid api_key provided."
            )
            return ValidationResult(
                success=False,
                message="Invalid api_key provided.",
            )

        try:
            headers = {"Authorization": f"Token {data['api_key']}"}
            response = requests.get(
                f"{data['url'].strip('/')}/api/v2/connections.inactives",
                verify=self.ssl_validation,
                proxies=self.proxy,
                headers=add_user_agent(headers),
            )
            if response.status_code in [401, 403]:
                self.logger.error(
                    f"{PLUGIN_NAME}: HTTP request returned with status "
                    f"code {response.status_code}."
                )
                return ValidationResult(
                    success=False,
                    message="Invalid Authorization Key provided.",
                )
            elif response.status_code != 200:
                self.logger.error(
                    f"{PLUGIN_NAME}: HTTP request returned with "
                    f"status code {response.status_code}."
                )
                return ValidationResult(
                    success=False,
                    message="Could not validate the provided credentials.",
                )
        except Exception as e:
            self.logger.error(
                f"{PLUGIN_NAME}: Error while fetching data from BitSight."
                + repr(e)
            )
            return ValidationResult(
                success=False,
                message="Validation failed. Check the input configuration.",
            )

        return ValidationResult(
            success=True,
            message="Validation successfull for BitSight plugin",
        )

    def handle_response(self, resp):
        """Handle the different HTTP response code.

        Args:
            resp (requests.models.Response): Response object returned
                from API call.
        Returns:
            dict: Returns the dictionary of response JSON when the
                response code is 200.
        Raises:
            HTTPError: When the response code is not 200.
        """
        if resp.status_code == 200 or resp.status_code == 201:
            try:
                return resp.json()
            except ValueError:
                raise requests.exceptions.HTTPError(
                    "Exception occurred while parsing JSON response."
                )
        elif resp.status_code == 429:
            return {}
        elif resp.status_code == 401:
            raise requests.exceptions.HTTPError(
                "Received exit code 401, Authentication Error."
            )
        elif resp.status_code == 403:
            raise requests.exceptions.HTTPError(
                "Received exit code 403, Forbidden User."
            )
        elif resp.status_code >= 400 and resp.status_code < 500:
            raise requests.exceptions.HTTPError(
                f"Received exit code {resp.status_code}, HTTP client Error."
            )
        elif resp.status_code >= 500 and resp.status_code < 600:
            raise requests.exceptions.HTTPError(
                f"Received exit code {resp.status_code}, HTTP server Error."
            )
        else:
            raise requests.exceptions.HTTPError(
                f"Received exit code {resp.status_code}, HTTP Error."
            )

    def get_target_fields(self, plugin_id, plugin_parameters):
        """Get available Target fields."""
        return [
            TargetMappingFields(
                label="Company Name",
                type=MappingType.STRING,
                value="name",
            ),
            TargetMappingFields(
                label="Company Legal Name",
                type=MappingType.STRING,
                value="company_legal_name",
            ),
            TargetMappingFields(
                label="Domain",
                type=MappingType.STRING,
                value="domain",
            ),
            TargetMappingFields(
                label="Website",
                type=MappingType.STRING,
                value="website",
            ),
            TargetMappingFields(
                label="Company Cluster Domain",
                type=MappingType.STRING,
                value="company_cluster_domain",
            ),
        ]
