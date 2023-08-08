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

"""Implementation of MISP CTE plugin."""


from typing import Dict, List
from datetime import datetime, timedelta
from netskope.common.utils import add_user_agent
from netskope.integrations.cte.models import Indicator, TagIn
from netskope.integrations.cte.plugin_base import (
    PluginBase,
    ValidationResult,
    PushResult,
)

from .utils.misp_constants import ATTRIBUTE_CATEGORIES, ATTRIBUTE_TYPES, TYPES
from netskope.integrations.cte.utils import TagUtils
from netskope.integrations.cte.models.business_rule import (
    ActionWithoutParams,
    Action,
)
import requests
import json
import os
import traceback

PLATFORM_NAME = "Misp"
MODULE_NAME = "CTE"
PLUGIN_VERSION = "1.2.0"
BATCH_SIZE = 2500


class MISPPlugin(PluginBase):
    """The MISP plugin implementation."""
    def __init__(
        self,
        name,
        *args,
        **kwargs,
    ):
        """Init function.

        Args:
            name (str): Configuration Name.
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
        
    def _add_user_agent(self, headers=None) -> str:
        """Add Client Name to request plugin make.

        Returns:
            str: String containing the Client Name.
        """
        headers = add_user_agent(headers)
        ce_added_agent = headers.get("User-Agent", "netskope-ce")
        user_agent_str = "{}-{}-{}-v{}".format(
            ce_added_agent,
            MODULE_NAME.lower(),
            self.plugin_name.lower(),
            self.plugin_version,
        )

        headers["User-Agent"] = user_agent_str
        return headers

    def _get_plugin_info(self) -> tuple:
        """Get plugin name and version from manifest.

        Returns:
            tuple: Tuple of plugin's name and version fetched from manifest.
        """
        try:
            file_path = os.path.join(
                str(os.path.dirname(os.path.abspath(__file__))),
                "manifest.json",
            )
            with open(file_path, "r") as manifest:
                manifest_json = json.load(manifest)
                plugin_name = manifest_json.get("name", PLATFORM_NAME)
                plugin_version = manifest_json.get("version", PLUGIN_VERSION)
                return (plugin_name, plugin_version)
        except Exception as exp:
            self.logger.info(
                message=(
                    f"{MODULE_NAME} {PLATFORM_NAME}: Error occurred while"
                    " getting plugin details."
                ),
                details=str(exp),
            )
        return (PLATFORM_NAME, PLUGIN_VERSION)
    
    def parse_response(self, response):
        """Parse Response will return JSON from response object.

        Args:
            response (response): Response object.

        Returns:
            json: Response Json.
        """
        try:
            return response.json()
        except json.JSONDecodeError as err:
            err_msg = (
                "Invalid JSON response received. "
                "Error: {}".format(err)
            )
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            raise err
        except Exception as exp:
            err_msg = (
                "Unexpected error occurred while parsing"
                " json response. Error: {}".format(exp)
            )
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}"
            )
            raise err

    def pull(self) -> List[Indicator]:
        """Pull indicators from MISP."""
        existing_tag = f"{self.name} Latest"
        pulling_mechanism = self.configuration.get("pulling_mechanism", "incremental")
        look_back = self.configuration.get("look_back")
        end_time = datetime.now()
        tag_utils = TagUtils()

        if pulling_mechanism == "look_back":
            if not look_back:
                err_msg = "When 'Pulling Mechanism' configuration parameter is set to 'Look Back', please provide a valid non-zero integer value in the 'Look Back' configuration parameter."
                self.logger.error(f"{self.log_prefix}: {err_msg}")
                raise err_msg
            else:
                # Removing the <config_name> Latest tag from the existing indicators
                query = {"sources": {"$elemMatch": {"source": f"{self.name}"}}}
                TagUtils().on_indicators(query).remove(existing_tag)
                start_time = end_time - timedelta(hours=look_back)
                if self.last_run_at and self.last_run_at < start_time:
                    start_time = self.last_run_at
                new_indicator_tag = self._create_marking_tag(tag_utils, existing_tag)
        else:
            start_time = self.last_run_at  # datetime.datetime object.

            if not start_time:
                self.logger.info(
                    f"{self.log_prefix}: This is initial data fetch since "
                    f"checkpoint is empty. Querying indicators for last {self.configuration['days']} days."
                )
                start_time = end_time - timedelta(
                    days=int(self.configuration["days"])
                )
        
        self.logger.info(f"{self.log_prefix}: Start time for this pull cycle: {start_time}")
        # create set of excluded events for
        event_ids = []
        if len(self.configuration["include_event_name"]) != 0:
            for inc_event in (
                self.configuration["include_event_name"].strip().split(",")
            ):
                event_id = self._event_exists(inc_event, self.configuration)[1]
                event_ids.append(event_id)

        # Convert to epoch
        start_time = int(start_time.timestamp())
        end_time = int(end_time.timestamp())

        misp_tags = []

        if self.configuration.get("tags", "").strip():
            misp_tags = self.configuration["tags"].split(",")

        body = {
            "returnFormat": "json",
            "limit": 5000,
            "page": 1,
            "timestamp": [str(start_time), str(end_time)],
            # Filter attributes based on type, category and tags
            "category": self.configuration["attr_category"],
            "type": self.configuration["attr_type"],
            "tags": misp_tags,
        }

        if len(event_ids) != 0:
            body["eventid"] = event_ids

        indicators, skipped_tags = [], []

        while True:
            try:
                response = requests.post(
                    f"{self.configuration['base_url'].strip('/')}/attributes/restSearch",
                    headers=self._add_user_agent(
                        self._get_header(self.configuration["api_key"])
                    ),
                    json=body,
                    verify=self.ssl_validation,
                    proxies=self.proxy,
                )
            except requests.exceptions.ProxyError as err:
                self.logger.error(
                    "{}: Invalid proxy. Error: {}".format(
                        self.log_prefix, err
                    ),
                    details=traceback.format_exc()
                )
                raise err
            except requests.exceptions.ConnectionError as err:
                self.logger.error(
                    "{}: Connection error occurred: {}".format(
                        self.log_prefix, err
                    ),
                    details=traceback.format_exc()
                )
                raise err
            except Exception as err:
                self.logger.error(
                    "{}: Error occurred while fetching the attributes from the Misp server: {}".format(
                        self.log_prefix, err
                    ),
                    details=traceback.format_exc()
                )
                raise err
            response.raise_for_status()
            if response.status_code == 200:
                json_res = self.parse_response(response)
                body["page"] += 1

                for attr in json_res.get("response", {}).get("Attribute", []):
                    if (
                        attr.get("type") in ATTRIBUTE_TYPES
                        # Filter already pushed attributes/indicators
                        and (
                            attr.get("Event", {}).get("info")
                            != self.configuration["event_name"]
                        )
                    ):
                        # Deep link of event corresponding to the attribute
                        event_id, deep_link = attr.get("event_id"), ""
                        tag_list = attr.get("Tag", [])
                        tag_list.append(
                            {
                                "name": attr.get("category", ""),
                                "type": "misp_category",
                            }
                        )
                        if event_id:
                            deep_link = f"{self.configuration['base_url'].strip('/')}/events/view/{event_id}"
                        tags, skipped = self._create_tags(
                            tag_utils,
                            tag_list,
                            self.configuration,
                        )
                        skipped_tags.extend(skipped)
                        if pulling_mechanism == "look_back" and look_back:
                            tags.append(new_indicator_tag)
                        indicators.append(
                            Indicator(
                                value=attr.get("value"),
                                type=TYPES.get(attr.get("type")),
                                firstSeen=attr.get("first_seen", None),
                                comments=attr.get("comment"),
                                tags=tags,
                                extendedInformation=deep_link,
                            )
                        )

                if (
                    len(json_res.get("response", {}).get("Attribute", []))
                    < body["limit"]
                ):
                    break
        if len(skipped_tags) > 0:
            self.logger.warn(
                f"{self.log_prefix}: Skipping following tag(s) because they are too long: {', '.join(skipped_tags)}"
            )
        return indicators

    def _create_marking_tag(self, utils: TagUtils, tag_name: str) -> str:
        """Create new tag in database if required."""
        try:
            if not utils.exists(tag_name):
                utils.create_tag(
                    TagIn(
                        name=tag_name,
                        color="#ED3347",
                    )
                )
                
        except ValueError as err:
            self.logger.error(
                f"{self.log_prefix}: Error occurred while creating an internal tag. Error: {err}",
                details=traceback.format_exc(),
            )
            raise err
        else:
            return tag_name

    def _create_tags(
        self, utils: TagUtils, tags: List[dict], configuration: dict
    ) -> (List[str], List[str]):
        """Create new tag(s) in database if required."""
        if configuration["enable_tagging"] != "yes":
            return [], []

        tag_names, skipped_tags = [], []
        for tag in tags:
            tag_name = (
                f"MISPCATEGORY-{tag.get('name', '').strip()}"
                if tag.get("type") == "misp_category"
                else tag.get("name", "").strip()
            )
            try:
                if not utils.exists(tag_name):
                    utils.create_tag(
                        TagIn(
                            name=tag_name,
                            color=tag.get("colour", "#ED3347"),
                        )
                    )
            except ValueError:
                skipped_tags.append(tag_name)
            else:
                tag_names.append(tag_name)
        return tag_names, skipped_tags

    def _event_exists(self, event_name: str, configuration) -> (bool, str):
        """Check if event exists on MISP instance."""
        try:
            response = requests.post(
                f"{configuration['base_url'].strip('/')}/events/restSearch",
                headers=self._add_user_agent(
                    self._get_header(configuration["api_key"])
                ),
                json={
                    "returnFormat": "json",
                    "limit": 1,
                    "page": 1,
                    "eventinfo": event_name,
                    "metadata": True,  # skips attributes
                },
                verify=self.ssl_validation,
                proxies=self.proxy,
            )
            response.raise_for_status()
            resp_json = self.parse_response(response)
            if (
                response.status_code == 200
                and len(resp_json.get("response", [])) > 0
            ):
                return True, resp_json.get("response")[0].get(
                    "Event", {}
                ).get("id", None)
            return False, None
        except requests.exceptions.ProxyError as err:
            self.logger.error(
                "{}: Invalid proxy. Error: {}".format(
                    self.log_prefix, err
                ),
                details=traceback.format_exc()
            )
            raise err
        except requests.exceptions.ConnectionError as err:
            self.logger.error(
                "{}: Connection error occurred: {}".format(
                    self.log_prefix, err
                ),
                details=traceback.format_exc()
            )
            raise err
        except Exception:
            return False, None

    def _create_event(self, payload: dict) -> PushResult:
        """Create a new event on MISP instance with given name/info and attributes."""
        try:
            response = requests.post(
                f"{self.configuration['base_url'].strip('/')}/events/add",
                headers=self._add_user_agent(
                    self._get_header(self.configuration["api_key"])
                ),
                json=payload,
                verify=self.ssl_validation,
                proxies=self.proxy,
            )
        except requests.exceptions.ProxyError as err:
            self.logger.error(
                "{}: Invalid proxy. Error: {}".format(
                    self.log_prefix, err
                ),
                details=traceback.format_exc()
            )
            raise err
        except requests.exceptions.ConnectionError as err:
            self.logger.error(
                "{}: Connection error occurred: {}".format(
                    self.log_prefix, err
                ),
                details=traceback.format_exc()
            )
            raise err
        except Exception as err:
            self.logger.error(
                "{}: Error occurred while fetching the attributes from the Misp server: {}".format(
                    self.log_prefix, err
                ),
                details=traceback.format_exc()
            )
            raise err
        if response.status_code == 200:
            return PushResult(message="Push Successful.", success=True)
        self.logger.error(
            f"{self.log_prefix}: Skipping the batch. Response code: {response.status_code}",
            details=response.text
        )
        return PushResult(
            message=f"Could not push indicators to MISP. HTTP status code {response.status_code}.",
            success=False,
        )

    def _update_event(self, event_id: str, payload: dict) -> PushResult:
        """Update given event's info and attribute(s)."""
        try:
            response = requests.post(
                f"{self.configuration['base_url'].strip('/')}/events/edit/{event_id}",
                headers=self._add_user_agent(
                    self._get_header(self.configuration["api_key"])
                ),
                json=payload,
                verify=self.ssl_validation,
                proxies=self.proxy,
            )
        except requests.exceptions.ProxyError as err:
            self.logger.error(
                "{}: Invalid proxy. Error: {}".format(
                    self.log_prefix, err
                ),
                details=traceback.format_exc()
            )
            raise err
        except requests.exceptions.ConnectionError as err:
            self.logger.error(
                "{}: Connection error occurred: {}".format(
                    self.log_prefix, err
                ),
                details=traceback.format_exc()
            )
            raise err
        except Exception as err:
            self.logger.error(
                "{}: Error occurred while fetching the attributes from the Misp server: {}".format(
                    self.log_prefix, err
                ),
                details=traceback.format_exc()
            )
            raise err
        if response.status_code == 200:
            return PushResult(message="Push Successful.", success=True)

        self.logger.error(
            f"{self.log_prefix}: Skipping the batch. Response code: {response.status_code}",
            details=response.text
        )
        return PushResult(
            message=f"Could not update the MISP Event with given indicators. HTTP status code {response.status_code}.",
            success=False,
        )

    def push(
        self, indicators: List[Indicator], action_dict: Dict
    ) -> PushResult:
        """Push given indicators to MISP Event."""
        # Map Netskope indicators to MISP attributes
        attributes = []
        action_dict = action_dict.get("parameters")
        for indicator in indicators:
            attributes.append(
                {
                    "type": indicator.type.value,
                    "value": indicator.value,
                    "comment": indicator.comments,
                    "first_seen": indicator.firstSeen.isoformat()
                    if indicator.firstSeen
                    else None,
                    "last_seen": indicator.lastSeen.isoformat()
                    if indicator.lastSeen
                    else None,
                }
            )

        # Check if event already exists
        exists, event_id = self._event_exists(
            action_dict.get("event_name"), self.configuration
        )
        for i in range(0, len(attributes), BATCH_SIZE):
            payload = attributes[i : i + BATCH_SIZE]
            self.logger.info(
                f"{self.log_prefix}: Attempting to push batch {(i / BATCH_SIZE) + 1} of size {len(payload)}"
            )
            if exists:
                # Push attributes/indicators to existing event
                _ = self._update_event(event_id, {"Attribute": payload})
            else:
                # Create new event with all the attributes
                _ = self._create_event(
                    {
                        "info": action_dict.get("event_name"),
                        "Attribute": payload,
                    }
                )
                exists, event_id = self._event_exists(
                    action_dict.get("event_name"), self.configuration
                )
   
        return PushResult(message="Push Successful.", success=True)

    def validate(self, configuration: dict) -> ValidationResult:
        """Validate the configuration."""
        if (
            "base_url" not in configuration
            or not configuration["base_url"].strip()
            or type(configuration["base_url"]) != str
        ):
            self.logger.error(
                f"{self.log_prefix}: Validation error occurred. Error: "
                "Invalid base URL found in the configuration parameters."
            )
            return ValidationResult(
                success=False, message="Invalid base URL provided."
            )

        if (
            "api_key" not in configuration
            or not configuration["api_key"].strip()
            or type(configuration["api_key"]) != str
        ):
            self.logger.error(
                f"{self.log_prefix}: Validation error occurred. Error: Invalid API key found in the configuration parameters."
            )
            return ValidationResult(
                success=False, message="Invalid API key provided."
            )

        if "attr_type" not in configuration or not all(
            x in ATTRIBUTE_TYPES for x in configuration["attr_type"]
        ):
            self.logger.error(
                f"{self.log_prefix}: Validation error occurred. Error: "
                "Invalid attr_type found in the configuration parameters."
            )
            return ValidationResult(
                success=False, message="Invalid attr_type value"
            )

        if "attr_category" not in configuration or not all(
            x in ATTRIBUTE_CATEGORIES for x in configuration["attr_category"]
        ):
            self.logger.error(
                f"{self.log_prefix}: Validation error occurred. Error: "
                "Invalid attr_category found in the configuration parameters."
            )
            return ValidationResult(
                success=False, message="Invalid attr_category value"
            )

        if "tags" not in configuration or type(configuration["tags"]) != str:
            self.logger.error(
                f"{self.log_prefix}: Validation error occurred. Error: "
                "tags not valid in the configuration parameters."
            )
            return ValidationResult(
                success=False, message="Invalid tags value"
            )

        if "include_event_name" not in configuration:
            self.logger.error(
                f"{self.log_prefix}: Validation error occurred. Error: "
                "include_event_name not found in the configuration parameters."
            )
            return ValidationResult(
                success=False, message="Invalid base URL provided."
            )

        if len(configuration["include_event_name"].strip()) != 0:

            events_to_include = (
                configuration["include_event_name"].strip().split(",")
            )

            for event in events_to_include:
                event = event.strip()
                if not event:
                    self.logger.error(
                        f"{self.log_prefix}: Validation error occurred."
                        " Error: Invalid Event name found in the configuration parameters."
                    )
                    return ValidationResult(
                        success=False, message="Invalid Event Name provided."
                    )

                if event == configuration["event_name"].strip():
                    self.logger.error(
                        f"{self.log_prefix}: Validation error occurred. Error: {event} "
                        f"is present in exclude as well as include."
                    )

                    return ValidationResult(
                        success=False,
                        message=f"{event} is present in exclude events as well.",
                    )
                try:
                    exist = self._event_exists(event, configuration)[0]
                except:
                    return ValidationResult(
                        success=False,
                        message=f"Error occurred while fetching the {event} from the MISP Instance.",
                    )
                if not exist:
                    self.logger.error(
                        f"{self.log_prefix}: Validation error occurred. Error: Provided"
                        f" Event name: {event}, doesn't exist on MISP Instance."
                    )
                    return ValidationResult(
                        success=False,
                        message=f"{event} event doesn't exist on MISP Instance.",
                    )

        if "enable_tagging" not in configuration or configuration[
            "enable_tagging"
        ] not in ["yes", "no"]:
            self.logger.error(
                f"{self.log_prefix}: Validation error occurred. Error: Invalid value for 'Enable Tagging' found. "
                "Value of Enable Tagging should be 'yes' or 'no'."
            )
            return ValidationResult(
                success=False,
                message="Invalid value for 'Enable Tagging' provided. Allowed values are 'yes' or 'no'.",
            )
            
        try:
            if "pulling_mechanism" not in configuration or configuration[
                "pulling_mechanism"
            ] not in ["incremental", "look_back"]:
                self.logger.error(
                    f"{self.log_prefix}: Validation error occurred. Error: Invalid value for 'Pulling Mechanism' found. "
                    "Value of Enable Tagging should be 'look_back' or 'incremental'."
                )
                return ValidationResult(
                    success=False,
                    message="Invalid value for 'Pulling Mechanism' provided. Allowed values are 'look_back' or 'incremental'.",
                )
            elif (
                configuration.get("pulling_mechanism", "incremental") == "look_back" and
                (not configuration.get("look_back")
                or int(configuration.get("look_back")) <= 0)
            ):
                err_msg = "When 'Pulling Mechanism' configuration parameter is set to 'Look Back', please provide a valid non-zero integer value in the 'Look Back' configuration parameter."
                self.logger.error(
                    f"{self.log_prefix}: {err_msg}"
                )
                return ValidationResult(
                    success=False,
                    message=err_msg,
                )
        except ValueError:
            return ValidationResult(
                success=False,
                message="Invalid Look Back provided.",
            )

        try:
            if (
                "days" not in configuration
                or not configuration["days"]
                or int(configuration["days"]) <= 0
            ):
                self.logger.error(
                    f"{self.log_prefix}: Validation error occurred. Error: Invalid days provided."
                )
                return ValidationResult(
                    success=False,
                    message="Invalid Number of days provided.",
                )
        except ValueError:
            return ValidationResult(
                success=False,
                message="Invalid Number of days provided.",
            )

        return self._validate_auth(configuration)

    def _get_header(self, api_key: str) -> dict:
        return {
            "Authorization": api_key,
            "Accept": "application/json",
            "Content-Type": "application/json",
        }

    def _validate_auth(self, configuration: dict) -> ValidationResult:
        """Validate API key by making REST API call."""
        try:
            response = requests.get(
                f"{configuration['base_url'].strip('/')}/servers/getVersion.json",
                headers=self._add_user_agent(
                    self._get_header(configuration["api_key"])
                ),
                verify=self.ssl_validation,
                proxies=self.proxy,
            )
            response.raise_for_status()
            resp_json = self.parse_response(response)
            if response.status_code == 200 and resp_json.get("version"):
                return ValidationResult(
                    success=True, message="Validation successful."
                )
            else:
                self.logger.error(
                    f"{self.log_prefix}: Error occurred while validating the credentials."
                )

        except Exception as ex:
            self.logger.error(
                f"{self.log_prefix}: Could not validate authentication credentials. Exception: {ex}",
                details=traceback.format_exc(),
            )
        return ValidationResult(
            success=False,
            message="Error occurred while validating account credentials.",
        )

    def get_actions(self):
        """Get available actions."""
        return [
            ActionWithoutParams(label="Add to event", value="event"),
        ]

    def validate_action(self, action: Action):
        """Validate Misp configuration."""
        if action.value not in ["event"]:
            return ValidationResult(
                success=False, message="Unsupported action provided."
            )
        if action.parameters.get("event_name", "") is None:
            return ValidationResult(
                success=False, message="Invalid Event Name Provided."
            )
        return ValidationResult(success=True, message="Validation successful.")

    def get_action_fields(self, action: Action):
        """Get fields required for an action."""
        if action.value == "event":
            return [
                {
                    "label": "Event Name",
                    "key": "event_name",
                    "type": "text",
                    "mandatory": True,
                    "default": "",
                    "description": "Name of the MISP Event in which the attributes/indicators are to be pushed",
                }
            ]
