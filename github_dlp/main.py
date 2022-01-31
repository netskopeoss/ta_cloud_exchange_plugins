"""Github DLP implementation to pull the data."""
import base64
import datetime
import hashlib
import time
from typing import List, Dict
import requests
from requests.exceptions import MissingSchema, InvalidSchema, InvalidURL
from netskope.integrations.cte.models import TagIn
from netskope.integrations.cte.utils import TagUtils
from netskope.integrations.cte.models import IndicatorType
from netskope.integrations.cte.models import Indicator
from netskope.integrations.cte.plugin_base import (
    PluginBase,
    ValidationResult,
)
from netskope.integrations.cte.models.business_rule import Action
from netskope.common.utils import add_user_agent
URL_SUFFIX: Dict[str, str] = {
    "VALIDATE": "/user",
    "LIST_REPO": "/user/repos",
    "REPO_DETAILS": "/repos/{}",
    "GET_TREE_HASH": "/repos/{}/branches/{}",
    "GET_TREE": "/repos/{}/git/trees/{}",
    "GET_FILE_CONTENT": "/repos/{}/git/blobs/{}",
    "CHECK_RATE_LIMIT": "/rate_limit",
    "GET_LIST_COMMIT": "/repos/{}/commits",
    "GET_FILE_LIST_USING_DIFF_OF_TWO_COMMIT": "/repos/{}/compare/{}...{}",
}
USER_AGENT = "Netskope CTE"
DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
SUPPORTED_STATUS_OF_FILE = ["modified", "added"]
API_QUOTA_LIMIT = 5000


class GitHubDLPPlugin(PluginBase):
    """GithubDLPPlugin class having concrete implementation for pulling threat information."""

    per_pull_quota = 2500
    recovery_storage = {}

    def set_quota_limit(self):
        """Set manual quota limit using configuration parameter."""
        percentage_of_quota = int(self.configuration["quota_limit"])
        self.per_pull_quota = int(
            (API_QUOTA_LIMIT * percentage_of_quota) / 100
        )

    def validate_repo(self, repository_name):
        """Validate repository name and return space removed name.

        Args:
            repository_name (str) : Name of repository.
        Return:
            (str) : Return correct and space removed repository name.
        Raise:
            Valuerror: if any error occur then throw error.
        """
        # strip before and after spaces
        repository_name = repository_name.strip()
        repo_temp = repository_name.split("/")
        if len(repo_temp) != 2:
            self.logger.error(
                "Plugin: GitHub DLP - "
                f"Invalid Repository '{repository_name}'."
            )
            raise ValueError(f"Invalid Repository '{repository_name}'.")
        repo_temp2 = []
        for repo in repo_temp:
            repo_temp2.append(repo.strip())
        return "/".join(repo_temp2)

    def check_repository_list(self, data, remaining_rate_limit):
        """Check each repository is available or not.

        Args:
            data (dict): Dict object having all the Plugin configuration parameters.
            remaining_rate_limit (int): Remaining rate limit of Github APIs.
        Returns:
            Will raise exception if error comes.
        """
        if data["repository"].strip():
            repository_list = data["repository"].split(",")
            repository_list = list(dict.fromkeys(repository_list))
            if len(repository_list) > remaining_rate_limit:
                self.logger.info(
                    "Plugin: GitHub DLP - "
                    "The API rate limit is not sufficient to verify the repository."
                )
                raise ValueError(
                    "The API rate limit is not sufficient to verify the repository."
                )
            for repository_name in repository_list:
                repository_name = self.validate_repo(repository_name)
                repo_detail_endpoint = "{}{}".format(
                    data["base_url"].strip("/"),
                    URL_SUFFIX["REPO_DETAILS"].format(repository_name),
                )
                headers = {
                    "User-Agent": USER_AGENT,
                    "Authorization": f"Token {data['api_token']}",
                }
                try:
                    resp = requests.get(
                        repo_detail_endpoint,
                        headers=add_user_agent(headers),
                        verify=self.ssl_validation,
                        proxies=self.proxy,
                    )
                except (
                    requests.exceptions.ConnectionError,
                    requests.exceptions.ProxyError,
                    requests.exceptions.RequestException,
                ) as e:
                    self.logger.error(
                        "Plugin: GitHub DLP - Exception occurred while making an API call to GitHub."
                    )
                    raise e

                if resp.status_code != 200:
                    if resp.status_code == 403:
                        try:
                            resp_json = resp.json()
                            msg = resp_json["message"]
                        except (ValueError, KeyError):
                            self.logger.error(
                                "Plugin: GitHub DLP - "
                                f"Received status code {resp.status_code}. "
                                f"An unexpected error occurred while validating the branch from GitHub."
                            )
                            raise requests.HTTPError(
                                "Plugin: GitHub DLP - "
                                f"Received status code {resp.status_code}. "
                                f"An unexpected error occurred while validating the branch from GitHub."
                            )
                        if "API rate limit exceeded" in msg:
                            self.logger.error(
                                "Plugin: GitHub DLP - "
                                "API rate limit exceeded."
                            )
                            raise ValueError("API rate limit exceeded.")
                    self.logger.error(
                        "Plugin: GitHub DLP - "
                        f"Invalid Repository '{repository_name}'."
                    )
                    raise ValueError(
                        f"Invalid Repository '{repository_name}'."
                    )
                resp_json = resp.json()
                if not resp_json.get("default_branch"):
                    self.logger.error(
                        f"Plugin: GitHub DLP - "
                        f"Repository '{repository_name}' has no default branch."
                    )
                    raise ValueError(
                        f"Repository '{repository_name}' has no default branch."
                    )

    @staticmethod
    def strip_args(data):
        """Strip arguments from left and right directions.

        Args:
            data (dict): Dict object having all the Plugin configuration parameters.
        """
        keys = data.keys()
        for key in keys:
            if isinstance(data[key], str):
                data[key] = data[key].strip()

    def return_error(self, resp, data):
        """Handle the different HTTP response code and return error.

        Args:
            resp (requests.models.Response): Response object returned from API call.
            data (dict): Dict object having all the Plugin configuration parameters.
        Returns:
            dict: Returns the dictionary of response JSON when the response code not 200.
        """
        try:
            resp_json = resp.json()
        except Exception:
            self.logger.error(
                "Plugin: GitHub DLP - Invalid Base URL/API token."
            )
            raise ValueError("Invalid Base URL/API token.")

        message = resp_json.get("message")
        if message and message == "Bad credentials":
            self.logger.error("Plugin: GitHub DLP - Invalid API token.")
            raise ValueError("Invalid API token provided.")
        if message and "API rate limit exceeded" in message:
            self.logger.error(
                "Plugin: GitHub DLP - API rate limit exceeded while validating credentials."
            )
            raise ValueError("API rate limit exceeded.")
        elif message:
            self.logger.error(f"Plugin: GitHub DLP - '{message}'.")
            raise ValueError(f"{message}")
        if resp.status_code == 401:
            self.logger.error(
                "Plugin: GitHub DLP - Invalid Base URL/API token provided."
            )
            raise ValueError("Invalid Base URL/API token provided.")
        elif 400 <= resp.status_code < 500:
            self.logger.error(
                f"Plugin: GitHub DLP - "
                f"Received status code {resp.status_code}, HTTP client Error."
            )
            raise ValueError("Invalid Base URL/API token provided.")
        elif 500 <= resp.status_code < 600:
            self.logger.error(
                f"Plugin: GitHub DLP - "
                f"Received status code {resp.status_code}, HTTP server Error."
            )
            raise ValueError(
                f"Received status code {resp.status_code}, HTTP server Error."
            )
        else:
            self.logger.error(
                f"Plugin: GitHub DLP - "
                f"Received status code {resp.status_code}, HTTP Error."
            )
            raise ValueError(
                f"Received status code {resp.status_code}, HTTP Error."
            )

    def handle_error(self, resp, data):
        """Handle the different HTTP response code.

        Args:
            resp (requests.models.Response): Response object returned from API call.
            data (dict): Dict object having all the Plugin configuration parameters.
        Returns:
            ValidationResult: ValidationResult object having validation results after making
            an API call or Will raise exception.
        """
        if resp.status_code == 200:
            try:
                json_resp = resp.json()
            except ValueError:
                self.logger.error(
                    "Plugin: GitHub DLP - Invalid Base URL/API Token."
                )
                raise ValueError("Invalid Base URL/API Token.")
            if not json_resp.get("login") or not json_resp.get("id"):
                self.logger.error(
                    "Plugin: GitHub DLP - "
                    "An unexpected error occurred while validating from GitHub."
                )
                raise requests.HTTPError(
                    "An unexpected error occurred while validating from GitHub."
                )
            if data["repository"]:
                try:
                    remaining_rate_limit = int(
                        resp.headers.get("X-RateLimit-Remaining")
                    )
                    rate_limit_reset_time = int(
                        resp.headers.get("X-RateLimit-Reset")
                    )
                except Exception:
                    self.logger.error(
                        "Plugin: GitHub DLP - "
                        "An unexpected error occurred while validating from GitHub."
                    )
                    raise requests.HTTPError(
                        "An unexpected error occurred while validating from GitHub."
                    )
                if remaining_rate_limit and rate_limit_reset_time:
                    self.check_repository_list(data, remaining_rate_limit)

            self.logger.info(
                "Plugin: GitHub DLP - Validation successful for GitHub DLP plugin."
            )
            return ValidationResult(
                success=True,
                message="Validation successful for GitHub DLP plugin.",
            )
        else:
            self.return_error(resp, data)

    def validate_auth_params(self, data):
        """Validate the authentication params with GitHub APIs.

        Args:
            data (dict): Dict object having all the Plugin configuration parameters.
        Returns:
            ValidationResult: ValidationResult object having validation results after making
            an API call or Will raise exception.
        """
        auth_endpoint = "{}{}".format(
            data["base_url"].strip("/"), URL_SUFFIX["VALIDATE"]
        )
        headers = {
            "User-Agent": USER_AGENT,
            "Authorization": f"Token {data['api_token']}",
        }
        try:
            resp = requests.get(
                auth_endpoint,
                headers=add_user_agent(headers),
                verify=self.ssl_validation,
                proxies=self.proxy,
            )
        except requests.exceptions.ProxyError:
            self.logger.error(
                "Plugin: GitHub DLP - Invalid proxy configuration."
            )
            raise requests.exceptions.ProxyError(
                "Invalid proxy configuration."
            )
        except (requests.exceptions.ConnectionError, requests.HTTPError):
            self.logger.error(
                "Plugin: GitHub DLP - "
                "Invalid Base URL/API Token/proxy server provided."
            )
            raise requests.exceptions.ConnectionError(
                "Invalid Base URL/API Token/proxy server provided."
            )
        except (
            MissingSchema,
            InvalidSchema,
            InvalidURL,
        ):
            self.logger.error(
                "Plugin: GitHub DLP - Invalid Base URL provided."
            )
            raise InvalidURL("Invalid Base URL provided.")
        return self.handle_error(resp, data=data)

    def validate(self, data):
        """Validate the Plugin configuration parameters.

        Args:
            data (dict): Dict object having all the Plugin configuration parameters.
        Returns:
            cte.plugin_base.ValidateResult: ValidateResult object with success flag and message.
        """
        self.logger.info(
            "Plugin: GitHub DLP - Executing validate method for GitHub DLP plugin."
        )
        if (
            ("base_url" not in data)
            or (not data["base_url"])
            or (type(data["base_url"]) != str)
            or (data["base_url"].strip() == "")
        ):
            self.logger.error(
                "Plugin: GitHub DLP - Validation error occurred for GitHub DLP plugin. "
                "Error: Invalid Base URL provided."
            )
            return ValidationResult(
                success=False, message="Invalid Base URL provided.",
            )

        if (
            ("api_token" not in data)
            or (not data["api_token"])
            or (type(data["api_token"]) != str)
            or (data["api_token"].strip() == "")
        ):
            self.logger.error(
                "Plugin: GitHub DLP - Validation error occurred for GitHub DLP plugin. "
                "Error: Invalid API Token provided."
            )
            return ValidationResult(
                success=False, message="Invalid API Token provided.",
            )
        if (
            ("quota_limit" not in data)
            or (not data["quota_limit"])
            or (not (100 >= int(data["quota_limit"]) >= 1))
        ):
            self.logger.error(
                "Plugin: GitHub DLP - Validation error occurred for GitHub DLP plugin. "
                "Error: Invalid Quota Limit provided."
            )
            return ValidationResult(
                success=False, message="Invalid Quota Limit provided.",
            )

        try:
            self.strip_args(data)
            return self.validate_auth_params(data)
        except Exception as e:
            return ValidationResult(success=False, message=f"{str(e)}",)

    def get_tree_hash_based_on_branch_name(
        self, repository_name, default_branch
    ):
        """Get tree hash based on repository and branch name.

        Args:
            repository_name (str) : Name of repository.
            default_branch (str) : Name of default branch name of repository.

         Returns:
            Tuple(str,str) : Contain tree hash and commit hash of repo. Use while fetching data using this hash.
        """
        branch_tree_hash_endpoint = "{}{}".format(
            self.configuration["base_url"].strip("/"),
            URL_SUFFIX["GET_TREE_HASH"].format(
                repository_name, default_branch
            ),
        )
        resp = self.verify_response_errors(branch_tree_hash_endpoint)
        if resp.status_code != 200:
            if resp.status_code == 403:
                try:
                    resp_json = resp.json()
                    msg = resp_json["message"]
                except (ValueError, KeyError):
                    self.logger.error(
                        "Plugin: GitHub DLP - "
                        f"An unexpected error occurred for configuration '{self._name}' "
                        f"while fetching data from GitHub."
                    )
                    self.notifier.error(
                        "Plugin: GitHub DLP - "
                        f"An unexpected error occurred for configuration '{self._name}' "
                        f"while fetching data from GitHub."
                    )
                    raise ValueError(
                        "Plugin: GitHub DLP - "
                        f"An unexpected error occurred for configuration '{self._name}' "
                        f"while fetching data from GitHub."
                    )
                if "API rate limit exceeded" in msg:
                    self.logger.info(
                        "Plugin: GitHub DLP - API rate limit exceeded for "
                        f"configuration '{self._name}' while pulling data from GitHub."
                    )
                    raise ValueError(
                        "Plugin: GitHub DLP - API rate limit exceeded for "
                        f"configuration '{self._name}' while pulling data from GitHub."
                    )
            if resp.status_code == 401:
                self.logger.info(
                    "Plugin: GitHub DLP - An unauthenticated error occurred for configuration "
                    f"'{self._name}' while pulling data. The current user's account might be deleted."
                )
                self.notifier.error(
                    "Plugin: GitHub DLP - An unauthenticated error occurred for configuration "
                    f"'{self._name}' while pulling data. The current user's account might be deleted."
                )
                raise requests.HTTPError(
                    "Plugin: GitHub DLP - An unauthenticated error occurred for configuration "
                    f"'{self._name}' while pulling data. The current user's account might be deleted."
                )

            self.logger.info(
                f"Plugin: GitHub DLP - No content found for repository '{repository_name}'."
            )
            return False, False
        tree_hash = (
            resp.json()
            .get("commit", {})
            .get("commit", {})
            .get("tree", {})
            .get("sha")
        )
        commit_hash = resp.json().get("commit", {}).get("sha", "")
        return tree_hash, commit_hash

    def get_default_branch_names_based_on_repo(self, repository_list):
        """Get default branch name of each repository.

        Args:
            repository_list (list): Repository names.
        Returns:
            list: Contain list of repository details. Use to store into storage
            and help when need to processing via chunk.
        """
        repo_branch_list = []
        if repository_list:
            for repository_name in repository_list:
                repo_detail_endpoint = "{}{}".format(
                    self.configuration["base_url"].strip("/"),
                    URL_SUFFIX["REPO_DETAILS"].format(repository_name),
                )
                resp = self.verify_response_errors(repo_detail_endpoint)
                if resp.status_code != 200:
                    if resp.status_code == 403:
                        try:
                            resp_json = resp.json()
                            msg = resp_json["message"]
                        except (ValueError, KeyError):
                            self.logger.error(
                                "Plugin: GitHub DLP - "
                                f"An unexpected error occurred for configuration '{self._name}' "
                                f"while fetching data from GitHub."
                            )
                            self.notifier.error(
                                "Plugin: GitHub DLP - "
                                f"An unexpected error occurred for configuration '{self._name}' "
                                f"while fetching data from GitHub."
                            )
                            raise ValueError(
                                "Plugin: GitHub DLP - "
                                f"An unexpected error occurred for configuration '{self._name}' "
                                f"while fetching data from GitHub."
                            )
                        if "API rate limit exceeded" in msg:
                            self.logger.info(
                                "Plugin: GitHub DLP - API rate limit exceeded for "
                                f"configuration '{self._name}' while pulling data from GitHub."
                            )
                            raise ValueError(
                                "Plugin: GitHub DLP - "
                                "API rate limit exceeded while getting branch information."
                            )
                    if resp.status_code == 404:
                        self.logger.info(
                            "Plugin: GitHub DLP - "
                            f"An unexpected error for repository '{repository_name}'. "
                            "The requested repository or account might be deleted."
                        )
                        self.notifier.error(
                            "Plugin: GitHub DLP - "
                            f"An unexpected error for repository '{repository_name}'. "
                            "The requested repository or account might be deleted."
                        )
                        raise requests.HTTPError(
                            "Plugin: GitHub DLP - "
                            f"An unexpected error for repository '{repository_name}'. "
                            "The requested repository or account might be deleted."
                        )
                    if resp.status_code == 401:
                        self.logger.info(
                            "Plugin: GitHub DLP - An unauthenticated error occurred for configuration "
                            f"'{self._name}' while pulling data. The current user's account might be deleted."
                        )
                        self.notifier.error(
                            "Plugin: GitHub DLP - An unauthenticated error occurred for configuration "
                            f"'{self._name}' while pulling data. The current user's account might be deleted."
                        )
                        raise requests.HTTPError(
                            "Plugin: GitHub DLP - An unauthenticated error occurred for configuration "
                            f"'{self._name}' while pulling data. The current user's account might be deleted."
                        )
                    self.notifier.error(
                        "Plugin: GitHub DLP - "
                        f"Received status code {resp.status_code} for configuration '{self._name}' while pulling data."
                    )
                    self.logger.info(
                        "Plugin: GitHub DLP - "
                        f"Received status code {resp.status_code} for configuration '{self._name}' while pulling data."
                    )
                    raise requests.HTTPError(
                        "Plugin: GitHub DLP - "
                        f"Received status code {resp.status_code} for configuration '{self._name}' while pulling data."
                    )

                resp_json = resp.json()
                if resp_json.get("default_branch"):
                    (
                        tree_hash,
                        commit_hash,
                    ) = self.get_tree_hash_based_on_branch_name(
                        repository_name, resp_json.get("default_branch")
                    )
                    if tree_hash:
                        details = {
                            "id": resp_json.get("id"),
                            "repo_name": repository_name,
                            "default_branch": resp_json.get("default_branch"),
                            "repo_processing_detail": {},
                            "start_time": time.time(),
                            "commit_start": True,
                            "commit_processing_detail": [],
                            "tree_hash": tree_hash,
                            "commit_hash": commit_hash,
                            "repo_processed": False,
                        }
                        repo_branch_list.append(details)
        else:
            list_repo_endpoint = "{}{}".format(
                self.configuration["base_url"].strip("/"),
                URL_SUFFIX["LIST_REPO"],
            )
            resp = self.verify_response_errors(list_repo_endpoint)
            if resp.status_code != 200:
                if resp.status_code == 403:
                    try:
                        resp_json = resp.json()
                        msg = resp_json["message"]
                    except ValueError:
                        self.notifier.error(
                            "Plugin: GitHub DLP - "
                            f"Received status code {resp.status_code} for configuration "
                            f"'{self._name}' while pulling data."
                        )
                        self.logger.info(
                            "Plugin: GitHub DLP - "
                            f"Received status code {resp.status_code} for configuration "
                            f"'{self._name}' while pulling data."
                        )
                        raise requests.HTTPError(
                            "Plugin: GitHub DLP - "
                            f"Received status code {resp.status_code} for configuration "
                            f"'{self._name}' while pulling data."
                        )
                    if "API rate limit exceeded" in msg:
                        self.logger.info(
                            "Plugin: GitHub DLP - API rate limit exceeded for "
                            f"configuration '{self._name}' while pulling data from GitHub."
                        )
                        raise ValueError(
                            "Plugin: GitHub DLP - API rate limit exceeded for "
                            f"configuration '{self._name}' while pulling data from GitHub."
                        )
                if resp.status_code == 404:
                    self.logger.info(
                        "Plugin: GitHub DLP - "
                        f"Received status code {resp.status_code} for configuration "
                        f"'{self._name}' while getting repository list. "
                        "The requested repository or account might be deleted."
                    )
                    self.notifier.error(
                        "Plugin: GitHub DLP - "
                        f"Received status code {resp.status_code} for configuration "
                        f"'{self._name}' while getting repository list. "
                        "The requested repository or account might be deleted."
                    )
                    raise requests.HTTPError(
                        "Plugin: GitHub DLP - "
                        f"Received status code {resp.status_code} for configuration "
                        f"'{self._name}' while getting repository list. "
                        "The requested repository or account might be deleted."
                    )
                if resp.status_code == 401:
                    self.logger.info(
                        "Plugin: GitHub DLP - An unauthenticated error occurred for configuration "
                        f"'{self._name}' while pulling data. The current user's account might be deleted."
                    )
                    self.notifier.error(
                        "Plugin: GitHub DLP - An unauthenticated error occurred for configuration "
                        f"'{self._name}' while pulling data. The current user's account might be deleted."
                    )
                    raise requests.HTTPError(
                        "Plugin: GitHub DLP - An unauthenticated error occurred for configuration "
                        f"'{self._name}' while pulling data. The current user's account might be deleted."
                    )

                self.notifier.error(
                    "Plugin: GitHub DLP - "
                    f"Received status code {resp.status_code} for configuration "
                    f"'{self._name}' while pulling data."
                )
                self.logger.info(
                    "Plugin: GitHub DLP - "
                    f"Received status code {resp.status_code} for configuration "
                    f"'{self._name}' while pulling data."
                )
                raise requests.HTTPError(
                    "Plugin: GitHub DLP - "
                    f"Received status code {resp.status_code} for configuration "
                    f"'{self._name}' while pulling data."
                )
            resp_list = resp.json()

            if not resp_list:
                self.notifier.error(
                    f"Plugin: GitHub DLP - No repository found for configuration '{self._name}'."
                )
                self.logger.info(
                    f"Plugin: GitHub DLP - No repository found for configuration '{self._name}'."
                )
                raise ValueError(
                    f"Plugin: GitHub DLP - No repository found for configuration '{self._name}'."
                )

            for resp_dict in resp_list:
                if resp_dict.get("default_branch") and resp_dict.get(
                    "full_name"
                ):
                    (
                        tree_hash,
                        commit_hash,
                    ) = self.get_tree_hash_based_on_branch_name(
                        resp_dict.get("full_name"),
                        resp_dict.get("default_branch"),
                    )
                    if tree_hash:
                        details = {
                            "id": resp_dict.get("id"),
                            "repo_name": resp_dict.get("full_name"),
                            "default_branch": resp_dict.get("default_branch"),
                            "repo_processing_detail": {},
                            "start_time": time.time(),
                            "commit_start": True,
                            "commit_processing_detail": [],
                            "tree_hash": tree_hash,
                            "commit_hash": commit_hash,
                            "repo_processed": False,
                        }
                        repo_branch_list.append(details)

        return repo_branch_list

    def update_storage(self, repo_branch_list):
        """Update storage if new repository comes store into storage. Use while processing multiple repository in chunk.

        Args:
             repo_branch_list: Contain list of repository details help to identify file content and tree hash.
        """
        updated_storage1 = []
        # store repo details which is new comes.
        for input_details in repo_branch_list:
            flag = False
            for stored_details in self.storage["github_dlp"]:
                if input_details["id"] == stored_details["id"]:
                    flag = True
                    stored_details["commit_start"] = True
                    updated_storage1.append(stored_details)
                    break
            if not flag:
                updated_storage1.append(input_details)

        # check storage which is already proceed store into storage
        updated_storage2 = updated_storage1.copy()
        for stored_details in self.storage["github_dlp"]:
            flag = False
            for updated_details in updated_storage1:
                if stored_details["id"] == updated_details["id"]:
                    flag = True
                    break
            if not flag and stored_details["repo_processed"]:
                stored_details["commit_start"] = False
                updated_storage2.append(stored_details)

        self.storage["github_dlp"] = updated_storage2.copy()

    @staticmethod
    def _create_tags(utils, tag_name):
        """Create custom tag if it not already available.

        Args: utils (TagUtils obj): Object of class TagUtils. Contains all
        """
        if not utils.exists(tag_name):
            utils.create_tag(TagIn(name=tag_name, color="#ED3347"))

    def get_indicators_without_recursion(self, repo_index, resp):
        """Return indicators without recursion logic as data is limited.

        Args:
            repo_index (int): repository index value to identify repository name using storage.
            resp (request.Response): Response object of get tree github API.
        Returns:
            List[cte.models.Indicator]: List indicators fetched from Github.
        Raises:
            requests.HTTPError: When HTTP response code is not 200 or some error occurred in the API call.
        """
        self.storage["github_dlp"][repo_index]["repo_processing_detail"] = {
            "truncated": "false",
            "remaining_process_file_list": [],
        }
        resp_json = resp.json()
        for detail in resp_json.get("tree", []):
            if detail.get("type", "") == "blob":
                self.storage["github_dlp"][repo_index][
                    "repo_processing_detail"
                ]["remaining_process_file_list"].append(
                    {
                        "file_path": detail.get("path"),
                        "file_hash": detail.get("sha"),
                        "type": "blob",
                    }
                )

        remaining_rate_limit = int(resp.headers.get("X-RateLimit-Remaining"))
        if remaining_rate_limit == 0:
            self.logger.info(
                "Plugin: GitHub DLP - API rate limit exceeded for "
                f"configuration '{self._name}' while pulling data from GitHub."
            )
            return []
        return self.get_pending_indicators(repo_index)

    def get_pending_indicators_with_recursion(self, repo_index):
        """Return indicators without recursion logic as data is limited.

        Args:
            repo_index (int): repository index value to identify repository name using storage.
        Returns:
            List[cte.models.Indicator]: List indicators fetched from Github.
        Raises:
            requests.HTTPError: When HTTP response code is not 200 or some error occurred in the API call.
        """
        indicators = []
        while 1:
            flag = self.check_quota(0)
            # if quota limit exceeded then lets return indicators
            if not flag:
                return indicators

            self.per_pull_quota = self.per_pull_quota - 1
            if self.per_pull_quota <= 0:
                self.logger.info(
                    "Plugin: GitHub DLP - Per pull quota limit exceeded for "
                    f"configuration '{self._name}'. Please wait till the next pull."
                )
                return indicators

            remaining_file_list_temp = self.storage["github_dlp"][repo_index][
                "repo_processing_detail"
            ]["remaining_process_file_list"].copy()
            if len(remaining_file_list_temp) == 0:
                self.storage["github_dlp"][repo_index]["repo_processed"] = True
                return indicators

            if remaining_file_list_temp[0]["type"] == "blob":
                get_file_content_endpoint = "{}{}".format(
                    self.configuration["base_url"].strip("/"),
                    URL_SUFFIX["GET_FILE_CONTENT"].format(
                        self.storage["github_dlp"][repo_index]["repo_name"],
                        remaining_file_list_temp[0]["file_hash"],
                    ),
                )
                resp = self.verify_response_errors(get_file_content_endpoint)
                if resp.status_code != 200:
                    temp = self.handle_status_code(
                        resp, indicators, repo_index
                    )
                    if type(temp) == list:
                        return temp
                else:
                    resp_json = resp.json()
                    content = base64.b64decode(resp_json.get("content"))
                    md5_hash = hashlib.md5(content).hexdigest()
                    comment_str = (
                        f"File Path is {self.storage['github_dlp'][repo_index]['repo_name']}"
                        f"/{remaining_file_list_temp[0].get('file_path')}"
                    )
                    if self.configuration["tag"]:
                        tag_name = " ".join(self.configuration["tag"].split())
                        tag_name = tag_name.replace(
                            "$REPO",
                            self.storage["github_dlp"][repo_index][
                                "repo_name"
                            ],
                        )
                        utils = TagUtils()
                        self._create_tags(utils, tag_name[0:50])
                        indicators.append(
                            Indicator(
                                value=md5_hash,
                                type=IndicatorType.MD5,
                                comments=comment_str,
                                safe=True,
                                tags=[tag_name[0:50]],
                            )
                        )
                    else:
                        indicators.append(
                            Indicator(
                                value=md5_hash,
                                type=IndicatorType.MD5,
                                safe=True,
                                comments=comment_str,
                            )
                        )

                    self.storage["github_dlp"][repo_index][
                        "repo_processing_detail"
                    ]["remaining_process_file_list"].remove(
                        remaining_file_list_temp[0]
                    )

                    remaining_rate_limit = int(
                        resp.headers.get("X-RateLimit-Remaining")
                    )
                    if remaining_rate_limit == 0:
                        self.logger.info(
                            "Plugin: GitHub DLP - API rate limit exceeded for "
                            f"configuration '{self._name}' while pulling data from GitHub. "
                            f"Please wait till the next pull."
                        )
                        return indicators
            elif remaining_file_list_temp[0]["type"] == "tree":
                get_tree_endpoint = "{}{}".format(
                    self.configuration["base_url"].strip("/"),
                    URL_SUFFIX["GET_TREE"].format(
                        self.storage["github_dlp"][repo_index]["repo_name"],
                        remaining_file_list_temp[0]["file_hash"],
                    ),
                )
                resp = self.verify_response_errors(get_tree_endpoint)
                if resp.status_code != 200:
                    temp = self.handle_status_code(
                        resp, indicators, repo_index
                    )
                    if type(temp) == list:
                        return temp
                else:
                    resp_json = resp.json()
                    temp_list = []
                    root_folder_path = remaining_file_list_temp[0].get(
                        "file_path"
                    )
                    for detail in resp_json.get("tree", []):
                        temp_list.append(
                            {
                                "file_path": f"{root_folder_path}/{detail.get('path')}",
                                "file_hash": detail.get("sha"),
                                "type": detail.get("type"),
                            }
                        )

                    self.storage["github_dlp"][repo_index][
                        "repo_processing_detail"
                    ]["remaining_process_file_list"].remove(
                        remaining_file_list_temp[0]
                    )
                    # if new files comes add in front of list
                    if temp_list:
                        temp_list.extend(
                            self.storage["github_dlp"][repo_index][
                                "repo_processing_detail"
                            ]["remaining_process_file_list"]
                        )
                        self.storage["github_dlp"][repo_index][
                            "repo_processing_detail"
                        ]["remaining_process_file_list"] = temp_list.copy()

                    remaining_rate_limit = int(
                        resp.headers.get("X-RateLimit-Remaining")
                    )
                    if remaining_rate_limit == 0:
                        self.logger.info(
                            "Plugin: GitHub DLP - API rate limit exceeded for "
                            f"configuration '{self._name}' while pulling data from GitHub. "
                            f"Please wait till the next pull."
                        )
                        return indicators

    def get_indicators_with_recursion(self, repo_index):
        """Return indicators without recursion logic as data is limited.

        Args:
            repo_index (int): repository index value to identify repository name using storage.
        Returns:
            List[cte.models.Indicator]: List indicators fetched from Github.
        Raises:
            requests.HTTPError: When HTTP response code is not 200 or some error occurred in the API call.
        """
        flag = self.check_quota(0)
        # if quota limit exceeded then lets return indicators
        if not flag:
            return []
        # calling get tree api using recursive mode
        get_tree_endpoint = "{}{}".format(
            self.configuration["base_url"].strip("/"),
            URL_SUFFIX["GET_TREE"].format(
                self.storage["github_dlp"][repo_index]["repo_name"],
                self.storage["github_dlp"][repo_index]["tree_hash"],
            ),
        )
        resp = self.verify_response_errors(get_tree_endpoint)

        if resp.status_code != 200:
            temp = self.handle_status_code(resp, ["dummy"], repo_index)
            if temp:
                return []

        resp_json = resp.json()
        self.storage["github_dlp"][repo_index]["repo_processing_detail"] = {
            "truncated": "true",
            "remaining_process_file_list": [],
        }

        for detail in resp_json.get("tree", []):
            self.storage["github_dlp"][repo_index]["repo_processing_detail"][
                "remaining_process_file_list"
            ].append(
                {
                    "file_path": detail.get("path"),
                    "file_hash": detail.get("sha"),
                    "type": detail.get("type"),
                }
            )

        flag = self.check_quota(0)
        # if quota limit exceeded then lets return indicators
        if not flag:
            return []

        indicators = self.get_pending_indicators_with_recursion(repo_index)
        return indicators

    def get_indicators_direct(self, repo_index):
        """Get indicators using repo name name and tree hash.

        Args:
            repo_index (int): repository index value to identify repository name using storage.
        Returns:
            List[cte.models.Indicator]: List indicators fetched from Github.
        Raises:
            requests.HTTPError: When HTTP response code is not 200 or some error occurred in the API call.
        """
        flag = self.check_quota(0)
        # if quota limit exceeded then lets return indicators
        if not flag:
            self.logger.info(
                "Plugin: GitHub DLP - API rate limit exceeded for "
                f"configuration '{self._name}' while pulling data from GitHub. "
                f"Please wait till the next pull."
            )
            return []

        self.per_pull_quota = self.per_pull_quota - 1

        get_tree_endpoint = "{}{}?recursive=true".format(
            self.configuration["base_url"].strip("/"),
            URL_SUFFIX["GET_TREE"].format(
                self.storage["github_dlp"][repo_index]["repo_name"],
                self.storage["github_dlp"][repo_index]["tree_hash"],
            ),
        )
        resp = self.verify_response_errors(get_tree_endpoint)
        if resp.status_code != 200:
            # when repository have no content then API return 404 status code
            if resp.status_code == 404:
                self.storage["github_dlp"][repo_index]["repo_processed"] = True
                return []

            temp = self.handle_status_code(resp, ["dummy"], repo_index)
            if temp:
                return []

        resp_json = resp.json()
        if resp_json.get("truncated"):
            indicators = self.get_indicators_with_recursion(repo_index)
            return indicators
        else:
            indicators = self.get_indicators_without_recursion(
                repo_index, resp
            )
            return indicators

    def verify_response_errors(self, api_endpoint, params={}):
        """Verify connection error and return response object.

        Args:
             api_endpoint (str): API endpoint url when we need to hit.
             params (Dict): The parameters that will pass to api.
        Returns:
            (requests.models.Response) : Return API response object.
        """
        headers = {
            "User-Agent": USER_AGENT,
            "Authorization": f"Token {self.configuration['api_token']}",
        }
        try:
            if not params:
                resp = requests.get(
                    api_endpoint,
                    headers=add_user_agent(headers),
                    verify=self.ssl_validation,
                    proxies=self.proxy,
                )
            else:
                resp = requests.get(
                    api_endpoint,
                    params=params,
                    headers=add_user_agent(headers),
                    verify=self.ssl_validation,
                    proxies=self.proxy,
                )
        except (
            requests.exceptions.ProxyError,
            requests.exceptions.ConnectionError,
            requests.exceptions.RequestException,
        ) as e:
            self.notifier.error(
                "Plugin: GitHub DLP - Exception occurred while making an API call "
                f"to GitHub for configuration '{self._name}'."
            )
            self.logger.error(
                "Plugin: GitHub DLP - Exception occurred while making an API call "
                f"to GitHub for configuration '{self._name}'."
            )
            if self.recovery_storage:
                self.storage["github_dlp"] = self.recovery_storage[
                    "github_dlp"
                ]
            raise e

        return resp

    def handle_status_code(self, resp, indicators, repo_index):
        """Handle error status code and throw error based on status code.

        Args:
            resp (requests.models.Response) : API endpoint url when we need to hit.
            indicators (list) : Contain list of indicator.
            repo_index (int) : index of storage help to get repository detail.

        Returns:
            (indicators) : list of indicators.
        """
        if resp.status_code == 403:
            try:
                resp_json = resp.json()
                msg = resp_json["message"]
            except (ValueError, KeyError):
                self.notifier.error(
                    "Plugin: GitHub DLP - "
                    f"Received status code {resp.status_code} for configuration "
                    f"'{self._name}' while pulling data."
                )
                self.logger.info(
                    "Plugin: GitHub DLP - "
                    f"Received status code {resp.status_code} for configuration "
                    f"'{self._name}' while pulling data."
                )
                raise requests.HTTPError(
                    "Plugin: GitHub DLP - "
                    f"Received status code {resp.status_code} for configuration "
                    f"'{self._name}' while pulling data."
                )
            if "API rate limit exceeded" in msg:
                self.logger.info(
                    "Plugin: GitHub DLP - API rate limit exceeded for "
                    f"configuration '{self._name}' while pulling data from GitHub."
                )
                return indicators
            self.notifier.error(
                "Plugin: GitHub DLP - "
                f"Received status code {resp.status_code} while pulling data for "
                f"configuration '{self._name}', Forbidden error."
            )
            self.logger.info(
                "Plugin: GitHub DLP - "
                f"Received status code {resp.status_code} while pulling data for "
                f"configuration '{self._name}', Forbidden error."
            )
            raise requests.HTTPError(
                "Plugin: GitHub DLP - "
                f"Received status code {resp.status_code} while pulling data for "
                f"configuration '{self._name}', Forbidden error."
            )
        elif resp.status_code == 401:
            self.logger.info(
                "Plugin: GitHub DLP - An unauthenticated error occurred for configuration "
                f"'{self._name}' while pulling data. The current user's account might be deleted."
            )
            self.notifier.error(
                "Plugin: GitHub DLP - An unauthenticated error occurred for configuration "
                f"'{self._name}' while pulling data. The current user's account might be deleted."
            )
            raise requests.HTTPError(
                "Plugin: GitHub DLP - An unauthenticated error occurred for configuration "
                f"'{self._name}' while pulling data. The current user's account might be deleted."
            )
        elif resp.status_code == 404:
            self.logger.error(
                "Plugin: GitHub DLP - "
                f"An unexpected error for repository '{self.storage['github_dlp'][repo_index]['repo_name']}'. "
                f"The requested repository or account might be deleted."
            )
            self.notifier.error(
                "Plugin: GitHub DLP - "
                f"An unexpected error for repository '{self.storage['github_dlp'][repo_index]['repo_name']}'. "
                f"The requested repository or account might be deleted."
            )
            raise requests.HTTPError(
                "Plugin: GitHub DLP - "
                f"An unexpected error for repository '{self.storage['github_dlp'][repo_index]['repo_name']}'. "
                f"The requested repository or account might be deleted."
            )
        else:
            self.notifier.error(
                "Plugin: GitHub DLP - "
                f"Received status code {resp.status_code} for configuration "
                f"'{self._name}' while pulling data."
            )
            self.logger.info(
                "Plugin: GitHub DLP - "
                f"Received status code {resp.status_code} for configuration "
                f"'{self._name}' while pulling data."
            )
            raise requests.HTTPError(
                "Plugin: GitHub DLP - "
                f"Received status code {resp.status_code} for configuration "
                f"'{self._name}' while pulling data."
            )

    def get_pending_indicators(self, repo_index):
        """Get indicators storage dict.

        Args:
            repo_index (int): repository index value to identify repository name using storage.
        Returns:
            List[cte.models.Indicator]: List indicators fetched from Github.
        Raises:
            requests.HTTPError: When HTTP response code is not 200 or some error occurred in the API call.
        """
        remaining_file_list_temp = self.storage["github_dlp"][repo_index][
            "repo_processing_detail"
        ]["remaining_process_file_list"].copy()
        indicators = []
        for detail in remaining_file_list_temp:
            self.per_pull_quota = self.per_pull_quota - 1
            if self.per_pull_quota <= 0:
                self.logger.info(
                    "Plugin: GitHub DLP - Per pull quota limit exceeded for "
                    f"configuration '{self._name}'. Please wait till the next pull."
                )
                return indicators
            get_file_content_endpoint = "{}{}".format(
                self.configuration["base_url"].strip("/"),
                URL_SUFFIX["GET_FILE_CONTENT"].format(
                    self.storage["github_dlp"][repo_index]["repo_name"],
                    detail.get("file_hash"),
                ),
            )
            resp = self.verify_response_errors(get_file_content_endpoint)

            if resp.status_code != 200:
                indicators_temp = self.handle_status_code(
                    resp, indicators, repo_index
                )
                if type(indicators_temp) == list:
                    return indicators_temp
            else:
                resp_json = resp.json()
                content = base64.b64decode(resp_json.get("content"))
                md5_hash = hashlib.md5(content).hexdigest()
                comment_str = (
                    f"File Path is {self.storage['github_dlp'][repo_index]['repo_name']}"
                    f"/{detail.get('file_path')}"
                )
                if self.configuration["tag"]:
                    tag_name = " ".join(self.configuration["tag"].split())
                    tag_name = tag_name.replace(
                        "$REPO",
                        self.storage["github_dlp"][repo_index]["repo_name"],
                    )
                    utils = TagUtils()
                    self._create_tags(utils, tag_name[0:50])
                    indicators.append(
                        Indicator(
                            value=md5_hash,
                            type=IndicatorType.MD5,
                            comments=comment_str,
                            safe=True,
                            tags=[tag_name[0:50]],
                        )
                    )
                else:
                    indicators.append(
                        Indicator(
                            value=md5_hash,
                            type=IndicatorType.MD5,
                            safe=True,
                            comments=comment_str,
                        )
                    )
                self.storage["github_dlp"][repo_index][
                    "repo_processing_detail"
                ]["remaining_process_file_list"].remove(detail)
                if (
                    len(
                        self.storage["github_dlp"][repo_index][
                            "repo_processing_detail"
                        ]["remaining_process_file_list"]
                    )
                    == 0
                ):
                    self.storage["github_dlp"][repo_index][
                        "repo_processed"
                    ] = True
                    return indicators

                remaining_rate_limit = int(
                    resp.headers.get("X-RateLimit-Remaining")
                )
                if remaining_rate_limit == 0:
                    self.logger.info(
                        "Plugin: GitHub DLP - API rate limit exceeded for "
                        f"configuration '{self._name}' while pulling data from GitHub."
                    )
                    return indicators
        return indicators

    def check_quota(self, count):
        """Return flag indicating whether remaining rate limit is less then count or not.

        Args:
            count (int) : describe value of remaining rate limit.
        Returns:
            List[cte.models.Indicator]: List indicators fetched from Github.
        Raises:
            requests.HTTPError: When HTTP response code is not 200 or some error occurred in the API call.
        """
        check_api_rate_limit_endpoint = "{}{}".format(
            self.configuration["base_url"].strip("/"),
            URL_SUFFIX["CHECK_RATE_LIMIT"],
        )
        resp = self.verify_response_errors(check_api_rate_limit_endpoint)
        if resp.status_code == 401:
            self.logger.info(
                "Plugin: GitHub DLP - An unauthenticated error occurred for configuration "
                f"'{self._name}' while pulling data. The current user's account might be deleted."
            )
            self.notifier.error(
                "Plugin: GitHub DLP - An unauthenticated error occurred for configuration "
                f"'{self._name}' while pulling data. The current user's account might be deleted."
            )
            raise requests.HTTPError(
                "Plugin: GitHub DLP - An unauthenticated error occurred for configuration "
                f"'{self._name}' while pulling data. The current user's account might be deleted."
            )

        resp.raise_for_status()
        try:
            remaining_rate_limit = int(
                resp.headers.get("X-RateLimit-Remaining")
            )
        except (ValueError, TypeError):
            return False
        if remaining_rate_limit > count:
            return True
        return False

    def store_commit_changes_files_into_storage(self, repo_index, resp_json):
        """Store commit file changes into storage and return flag if successful or not.

        Args:
             repo_index (int) : index of repository while accessing into storage.
             resp_json (list): Response json of files changes API.
        Returns:
            bool : Flag indicating storing file successful or not.
        """
        file_process_list = []
        old_commit_hash = self.storage["github_dlp"][repo_index]["commit_hash"]
        for details in resp_json:
            self.per_pull_quota -= 1
            # call get all file based on commit difference
            get_all_file_based_on_diff_endpoint = "{}{}".format(
                self.configuration["base_url"].strip("/"),
                URL_SUFFIX["GET_FILE_LIST_USING_DIFF_OF_TWO_COMMIT"].format(
                    self.storage["github_dlp"][repo_index]["repo_name"],
                    old_commit_hash,
                    details.get("sha"),
                ),
            )
            resp = self.verify_response_errors(
                get_all_file_based_on_diff_endpoint
            )

            if resp.status_code != 200:
                # pass dummy text as temporary so it work for common method
                result = self.handle_status_code(resp, "dummy", repo_index)
                if result:
                    return False

            resp_json = resp.json()
            if (
                resp_json.get("files", [])
                and type(resp_json.get("files", [])) == list
            ):
                for file_details in resp_json.get("files", []):
                    if file_details.get("status") in SUPPORTED_STATUS_OF_FILE:
                        file_process_list.append(
                            {
                                "file_path": file_details.get("filename", ""),
                                "file_hash": file_details.get("sha", ""),
                            }
                        )
            old_commit_hash = details.get("sha")
        self.storage["github_dlp"][repo_index][
            "commit_processing_detail"
        ] = file_process_list
        self.storage["github_dlp"][repo_index]["commit_hash"] = old_commit_hash
        return True

    def get_indicators_from_pending_commits(self, repo_index):
        """Get indicators storage dict.

        Args:
            repo_index (int): repository index value to identify repository name using storage.

        Returns:
            List[cte.models.Indicator]: List indicators fetched from Github.
        Raises:
            requests.HTTPError: When HTTP response code is not 200 or some error occurred in the API call.
        """
        remaining_file_list_temp = self.storage["github_dlp"][repo_index][
            "commit_processing_detail"
        ].copy()
        indicators = []
        for detail in remaining_file_list_temp:
            self.per_pull_quota = self.per_pull_quota - 1
            if self.per_pull_quota <= 0:
                self.logger.info(
                    "Plugin: GitHub DLP - Per pull quota limit exceeded for "
                    f"configuration '{self._name}'. Please wait till the next pull."
                )
                return indicators

            # check quota for safety while parallel processing
            flag = self.check_quota(0)
            if not flag:
                self.logger.info(
                    "Plugin: GitHub DLP - API rate limit exceeded for "
                    f"configuration '{self._name}' while pulling data from GitHub."
                )
                return indicators
            get_file_content_endpoint = "{}{}".format(
                self.configuration["base_url"].strip("/"),
                URL_SUFFIX["GET_FILE_CONTENT"].format(
                    self.storage["github_dlp"][repo_index]["repo_name"],
                    detail.get("file_hash"),
                ),
            )
            resp = self.verify_response_errors(get_file_content_endpoint)

            if resp.status_code != 200:
                indicators_temp = self.handle_status_code(
                    resp, indicators, repo_index
                )
                if type(indicators_temp) == list:
                    return indicators_temp
            else:
                resp_json = resp.json()
                content = base64.b64decode(resp_json.get("content"))
                md5_hash = hashlib.md5(content).hexdigest()
                comment_str = (
                    f"File Path is {self.storage['github_dlp'][repo_index]['repo_name']}"
                    f"/{detail.get('file_path')}"
                )
                if self.configuration["tag"]:
                    tag_name = " ".join(self.configuration["tag"].split())
                    tag_name = tag_name.replace(
                        "$REPO",
                        self.storage["github_dlp"][repo_index]["repo_name"],
                    )
                    utils = TagUtils()
                    self._create_tags(utils, tag_name[0:50])
                    indicators.append(
                        Indicator(
                            value=md5_hash,
                            type=IndicatorType.MD5,
                            comments=comment_str,
                            safe=True,
                            tags=[tag_name[0:50]],
                        )
                    )
                else:
                    indicators.append(
                        Indicator(
                            value=md5_hash,
                            type=IndicatorType.MD5,
                            safe=True,
                            comments=comment_str,
                        )
                    )
                self.storage["github_dlp"][repo_index][
                    "commit_processing_detail"
                ].remove(detail)
                remaining_rate_limit = int(
                    resp.headers.get("X-RateLimit-Remaining")
                )
                if remaining_rate_limit == 0:
                    self.logger.info(
                        "Plugin: GitHub DLP - API rate limit exceeded for "
                        f"configuration '{self._name}' while pulling data from GitHub."
                    )
                    return indicators
        return indicators

    def get_indicators_from_commits(self, repo_index):
        """Get indicators from commit API whose file are added or modified.

        Args:
            repo_index (int): index of repository help to access storage.

        Returns:
            List[cte.models.Indicator]: List indicators fetched from Github.
        Raises:
            requests.HTTPError: When HTTP response code is not 200 or some error occurred in the API call.
        """
        # check quota for safety while parallel processing
        flag = self.check_quota(0)
        if not flag:
            self.logger.info(
                "Plugin: GitHub DLP - API rate limit exceeded for "
                f"configuration '{self._name}' while pulling data from GitHub."
            )
            return []

        # call get all commit api based on time stamp
        get_list_commit_endpoint = "{}{}".format(
            self.configuration["base_url"].strip("/"),
            URL_SUFFIX["GET_LIST_COMMIT"].format(
                self.storage["github_dlp"][repo_index]["repo_name"]
            ),
        )

        params = {
            "since": datetime.datetime.utcfromtimestamp(
                self.storage["github_dlp"][repo_index]["start_time"]
            ).strftime(DATE_FORMAT),
            "until": datetime.datetime.utcfromtimestamp(time.time()).strftime(
                DATE_FORMAT
            ),
            "per_page": 100,
        }

        new_start_time = time.time()
        commit_responses = []
        page_no = 0
        while 1:
            self.per_pull_quota -= 1
            page_no = page_no + 1
            params["page"] = page_no
            resp = self.verify_response_errors(
                get_list_commit_endpoint, params
            )
            if resp.status_code != 200:
                # when repo has no branch or no content then API returns 409 as conflict error
                # we ignore this status code and return empty list.
                if resp.status_code == 409:
                    return []
                temp = self.handle_status_code(resp, ["dummy"], repo_index)
                if temp:
                    return []

            resp_json = resp.json()
            if len(resp_json) != 0:
                commit_responses.extend(resp_json)
            else:
                break

        if int(resp.headers.get("X-RateLimit-Remaining")) < len(
            commit_responses
        ):
            # limit is less so lets return it
            self.logger.info(
                "Plugin: GitHub DLP - API rate limit exceeded for "
                f"configuration '{self._name}' while pulling data from GitHub."
            )
            return []

        commit_responses.reverse()
        flag = self.store_commit_changes_files_into_storage(
            repo_index=repo_index, resp_json=commit_responses
        )
        if not flag:
            return []

        self.storage["github_dlp"][repo_index]["start_time"] = new_start_time

        flag = self.check_quota(0)
        # if quota limit exceeded then lets return indicators
        if not flag:
            return []

        # check user quota limit
        if self.per_pull_quota <= 0:
            self.logger.info(
                "Plugin: GitHub DLP - Per pull quota limit exceeded for "
                f"configuration '{self._name}'. Please wait till the next pull."
            )
            return []

        # check if files present or not
        if self.storage["github_dlp"][repo_index]["commit_processing_detail"]:
            return self.get_indicators_from_pending_commits(repo_index)
        else:
            return []

    def fetch_indicators(self):
        """Fetch threat data using github API.

        Returns:
            List[cte.models.Indicator]: List indicators fetched from Github.
        Raises:
            requests.HTTPError: When HTTP response code is not 200 or some error occurred in the API call.
        """
        indicators = []

        flag = self.check_quota(0)
        # if quota limit exceeded then lets return indicators
        if not flag:
            return []

        # processing repo whose repo is not processed
        for repo_index in range(0, len(self.storage["github_dlp"])):
            if not self.storage["github_dlp"][repo_index]["repo_processed"]:
                if (
                    not self.storage["github_dlp"][repo_index]
                    .get("repo_processing_detail", {})
                    .get("truncated")
                ):
                    indicators.extend(self.get_indicators_direct(repo_index))
                elif (
                    self.storage["github_dlp"][repo_index]
                    .get("repo_processing_detail", {})
                    .get("truncated")
                    == "false"
                ):
                    indicators.extend(self.get_pending_indicators(repo_index))
                elif (
                    self.storage["github_dlp"][repo_index]
                    .get("repo_processing_detail", {})
                    .get("truncated")
                    == "true"
                ):
                    indicators.extend(
                        self.get_pending_indicators_with_recursion(repo_index)
                    )

            flag = self.check_quota(0)
            # if quota limit exceeded then lets return indicators
            if not flag:
                return indicators

            # if rate limit is 0 lets returns indicators
            if self.per_pull_quota == 0:
                return indicators

        # processing repo whose currently running and new commit is available.
        for repo_index in range(0, len(self.storage["github_dlp"])):
            if self.storage["github_dlp"][repo_index]["commit_start"]:
                # check if commit processing is pending of this repo
                if (
                    len(
                        self.storage["github_dlp"][repo_index][
                            "commit_processing_detail"
                        ]
                    )
                    != 0
                ):
                    indicators.extend(
                        self.get_indicators_from_pending_commits(repo_index)
                    )

                    flag = self.check_quota(0)
                    # if quota limit exceeded then lets return indicators
                    if not flag:
                        return indicators

                    # if per pull limit is 0 then lets returns indicators
                    if self.per_pull_quota == 0:
                        return indicators

                if (
                    len(
                        self.storage["github_dlp"][repo_index][
                            "commit_processing_detail"
                        ]
                    )
                    == 0
                ):
                    # get commit of this repo
                    indicators.extend(
                        self.get_indicators_from_commits(repo_index)
                    )

                    flag = self.check_quota(0)
                    # if quota limit exceeded then lets return indicators
                    if not flag:
                        return indicators

                    # if per pull limit is 0 then lets returns indicators
                    if self.per_pull_quota == 0:
                        return indicators

        return indicators

    def get_repository_names(self, repository):
        """Convert comma separated string to list.

        Args:
            repository (str): comma separated repository string.

        Returns:
            List: contain repository list.
        """
        if repository.strip():
            repository_list = repository.split(",")
            repository_list = list(dict.fromkeys(repository_list))
            result_repo_list = []
            for repository_name in repository_list:
                result_repo_list.append(self.validate_repo(repository_name))
            return result_repo_list
        return []

    def pull(self) -> List[Indicator]:
        """Pull method of Github DLP."""
        self.set_quota_limit()

        self.strip_args(self.configuration)

        config = self.configuration

        repository_list = self.get_repository_names(config["repository"])
        if repository_list:
            # check quota should be larger then repository names * 2 to get default hash of repo to proceed farther
            flag = self.check_quota(len(repository_list) * 2)
            # if quota limit exceeded then lets return indicators
            if not flag:
                self.logger.info(
                    "Plugin: GitHub DLP - API rate limit exceeded for "
                    f"configuration '{self._name}' while pulling data from GitHub."
                )
                return []

        repo_branch_list = self.get_default_branch_names_based_on_repo(
            repository_list
        )

        # store details into storage.
        if not self.storage:
            self.storage["github_dlp"] = repo_branch_list
        else:
            # if storage is already there then update repo list into storage
            self.update_storage(repo_branch_list)

        self.recovery_storage = self.storage.copy()
        indicators = self.fetch_indicators()
        return indicators

    def get_actions(self):
        """Get available actions."""
        return []

    def validate_action(self, action: Action):
        """Validate GitHubDLP configuration."""
        return ValidationResult(success=True, message="Validation successful.")

    def get_action_fields(self, action: Action):
        """Get fields required for an action."""
        return []
