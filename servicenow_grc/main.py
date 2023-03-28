"""_summary_"""
from datetime import datetime
import json
import requests
import time

from netskope.integrations.grc.plugin_base import (
    PluginBase,
    ValidationResult,
    PushResult,
)
from netskope.common.utils import add_user_agent
from netskope.integrations.grc.models.configuration import (
    TargetMappingFields,
    MappingType,
)

MAX_PER_PAGE = 1000
MAX_RETRY_COUNT = 4


class ServiceNowPlugin(PluginBase):
    """PLugin implementation for ServiceNow"""

    def api_call_helper(self, url, method, params={}, data=None, auth=None, headers={}):
        """This method help to collect data from ServiceNow."""
        request_func = getattr(requests, method)

        headers = add_user_agent(headers)
        verify = self.ssl_validation
        proxies = self.proxy
        response = {}

        for attempt in range(MAX_RETRY_COUNT):
            resp = request_func(
                url=url,
                auth=auth,
                headers=headers,
                verify=verify,
                proxies=proxies,
                params=params,
                data=data,
            )
            response_json = self.handle_response(resp)
            if resp.status_code == 200 or resp.status_code == 201:
                response = response_json
                break
            elif resp.status_code == 429 and attempt < (MAX_RETRY_COUNT - 1):
                self.logger.info(
                    f"Too many requests occurred for {url}, Retrying to make the API call. Retry count:{attempt + 1}"
                )
                time.sleep(60)
        else:
            raise requests.exceptions.HTTPError("Maximum retry limit reached")
        return response

    def map_operator(self, operator):
        """Map the Netskope operator with the ServiceNow operator"""
        mapping = {"==": "="}
        return mapping[operator]

    def apply_query(self, query):
        """Fetches the vendors from ServiceNow that matches the query"""
        config = self.configuration
        try:
            url = f"{config['url'].strip('/')}/api/now/table/core_company"
            auth = (config["username"], config["password"])
            params = {
                "sysparm_limit": MAX_PER_PAGE,
                "sysparm_offset": 0,
                "sysparm_query": query,
            }
            vendor_results = []
            while True:
                results = self.api_call_helper(
                    url, method="get", auth=auth, params=params
                )

                vendors = results.get("result", [])

                for vendor in vendors:
                    vendor_details = {
                        "sys_id": vendor["sys_id"],
                        "notes": vendor.get("notes", ""),
                    }

                    vendor_results.append(vendor_details)
                if len(vendors) < MAX_PER_PAGE:
                    break
                params["sysparm_offset"] += MAX_PER_PAGE

            return vendor_results

        except requests.exceptions.ProxyError:
            raise requests.HTTPError("Invalid proxy configuration.")
        except requests.exceptions.ConnectionError:
            raise requests.HTTPError(
                "Unable to establish connection, server is not reachable."
            )
        except requests.exceptions.HTTPError as ex:
            raise requests.HTTPError(
                f"Error occurred while fetching records from ServiceNow. {ex}"
            )
        except Exception as ex:
            raise requests.HTTPError(
                f"Error occurred while fetching records from ServiceNow. Error: {ex}"
            )

    def add_query_list(self, final_list, mapping_dict):
        """To create final dict for mapping to the destination."""
        query_dict = {}
        query_dict["operator"] = "=="
        operand_dict = mapping_dict["=="]
        query_dict["lhs"] = (
            "parent.name"
            if (operand_dict[0].get("var") == "parent")
            else operand_dict[0].get("var")
        )
        query_dict["rhs"] = operand_dict[1]
        final_list.append(query_dict)

    def get_query_builder_list(self, configuration_mapping_query):
        """To generate dict which contains operation ('and'/'or') and list of dict which contains LHS, RHS, and Operator."""
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

    def get_query_builder(self, app_dict, mapping_list):
        """This method help to build query to fetch only vendors data that matches on ServiceNow."""
        query_list = []
        for query_json in mapping_list:
            mapped_operator = self.map_operator(query_json.get("operator"))
            app_value = app_dict.get(query_json.get("rhs", ""))
            lhs_app_value = query_json.get("lhs")
            if app_value is None:
                app_value = ""
            if isinstance(app_value, list):
                internal_query = ",".join(app_value)
                query = f"{lhs_app_value}IN{internal_query}"
                query_list.append(query)
            else:
                query = f"{lhs_app_value}{mapped_operator}{app_value}"
                query_list.append(query)
        return query_list

    def push(self, applications, query_builder_list):
        """push method to store the data collected from the Netskope tenant into ServiceNow's VRM.
        Args:
            applications (_type_): _description_
        """

        config = self.configuration
        snow_results = {}
        query_builder_dict = self.get_query_builder_list(query_builder_list)
        skip_count = 0
        total_count = 0
        for app in applications:
            total_count += 1
            app_dict = app.dict()
            app_details = {
                "app_id": app_dict.get("applicationId"),
                "app_name": app_dict.get("applicationName"),
                "cci": app_dict.get("cci"),
                "ccl": app_dict.get("ccl"),
                "category_name": app_dict.get("categoryName"),
                "deep_link": app_dict.get("deepLink"),
            }
            mapped_operation = query_builder_dict["operation"]
            mapping_list = query_builder_dict["query_builder_list"]
            if mapped_operation == "and":
                query_list = self.get_query_builder(app_dict, mapping_list)
                final_query = "^".join(query_list)
            else:
                query_list = self.get_query_builder(app_dict, mapping_list)
                final_query = "^OR".join(query_list)
            snow_records = self.apply_query(final_query)

            if not snow_records:
                self.logger.warn(
                    f"Application '{app_dict.get('applicationName')}' match is not available in ServiceNow, skipping sharing of this application."
                )
                skip_count += 1

            self.logger.info(
                f"Found {len(snow_records)} matches for application '{app_dict.get('applicationName')}'."
            )

            for snow_record in snow_records:
                sys_id = snow_record.get("sys_id")
                notes = snow_record.get("notes", "")
                if sys_id in snow_results:
                    snow_results[sys_id]["apps"].append(app_details)
                else:
                    snow_results[sys_id] = {"apps": [app_details], "notes": notes}

        self.logger.info("Pushing the applications to ServiceNow.")
        current_time = datetime.now()
        current_time = current_time.strftime("%Y-%m-%d %H:%M:%S")
        for sys_id, details in snow_results.items():
            apps_list = details.get("apps", [])
            existing_notes = details.get("notes", "")
            current_notes = f"[Netskope CE] Last shared at: {current_time}\n"
            for app in apps_list:
                current_notes += f"Application Name: {app.get('app_name','NA')}, Cloud Confidence Index: {app.get('cci','NA')}, CCL: {app.get('ccl','NA')}, Category Name: {app.get('category_name','NA')}, Deep Link: {app.get('deep_link','NA')}\n"
            if existing_notes:
                notes = current_notes + "\n\n" + existing_notes
            else:
                notes = current_notes
            payload = json.dumps({"notes": notes})

            try:
                _ = self.api_call_helper(
                    f"{config['url'].strip('/')}/api/now/table/core_company/{sys_id}",
                    auth=(config["username"], config["password"]),
                    method="patch",
                    data=payload,
                )
            except requests.exceptions.ProxyError:
                raise requests.HTTPError("Invalid proxy configuration.")
            except requests.exceptions.ConnectionError:
                raise requests.HTTPError(
                    "Unable to establish connection, server is not reachable."
                )
            except requests.exceptions.HTTPError as ex:
                raise requests.HTTPError(f"Error occurred while pushing data. {ex}")
            except Exception as ex:
                raise requests.HTTPError(
                    f"Error occurred while pushing data. Error: {ex}"
                )

        self.logger.info(
            f"Total {total_count - skip_count} applications shared successfully with ServiceNow and "
            f"{skip_count} applications were skipped."
        )
        return PushResult(
            success=True, message="Successfully pushed data to ServiceNow."
        )

    def validate(self, data):
        """Validate the Plugin configuration parameters.

        Validation for all the parameters mentioned in the manifest.json for the existence and
        data type. Method returns the ARE.plugin_base.ValidationResult object with success = True in the case
        of successful validation and success = False and a error message in the case of failure.
        Args:
            data (dict): Dict object having all the Plugin configuration parameters.
        Returns:
            cte.plugin_base.ValidateResult: ValidateResult object with success flag and message.
        """
        self.logger.info(
            "ServiceNow Plugin: Executing validate method for ServiceNow plugin"
        )
        if "url" not in data or not data["url"] or type(data["url"]) != str:
            self.logger.error(
                "ServiceNow Plugin: Validation error occured Error: Invalid ServiceNow instance URL provided."
            )
            return ValidationResult(
                success=False,
                message="Invalid ServiceNow Instance URL provided.",
            )

        if (
            "username" not in data
            or not data["username"]
            or type(data["username"]) != str
        ):
            self.logger.error(
                "ServiceNow Plugin: Validation error occured Error: Invalid Username provided."
            )
            return ValidationResult(
                success=False,
                message="Invalid Username provided.",
            )

        if (
            "password" not in data
            or not data["password"]
            or type(data["password"]) != str
        ):
            self.logger.error(
                "ServiceNow Plugin: Validation error occured Error: Invalid Password provided."
            )
            return ValidationResult(
                success=False,
                message="Invalid Password provided.",
            )

        try:
            response = requests.get(
                f"{data['url'].strip('/')}/api/now/table/core_company",
                params={"sysparm_limit": 1},
                auth=(data["username"], data["password"]),
                verify=self.ssl_validation,
                proxies=self.proxy,
                headers=add_user_agent(),
            )
            if response.status_code in [401, 403]:
                self.logger.error(
                    f"ServiceNow Plugin: HTTP request returned with status code {response.status_code}"
                )
                return ValidationResult(
                    success=False,
                    message="Invalid username/password provided.",
                )
            elif response.status_code != 200:
                self.logger.error(
                    f"ServiceNow Plugin: HTTP request returned with status code {response.status_code}"
                )
                return ValidationResult(
                    success=False,
                    message="Could not validate username/password.",
                )
        except Exception as e:
            self.logger.error(
                "ServiceNow Plugin: Error while fetching data from ServiceNow" + repr(e)
            )
            return ValidationResult(
                success=False,
                message="Validation failed. Check the input configuration.",
            )

        return ValidationResult(
            success=True,
            message="Validation successfull for ServiceNow plugin",
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
                label="Parent Company Name",
                type=MappingType.STRING,
                value="parent",
            ),
        ]

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
