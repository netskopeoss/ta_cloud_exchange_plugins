""" SecurityScorecard Plugin """

import requests
import datetime
import re
import string
import time
from typing import Dict, List
from netskope.integrations.cte.plugin_base import (
    PluginBase,
    ValidationResult,
    PushResult,
)
from netskope.integrations.cte.models.business_rule import (
    ActionWithoutParams,
    Action,
)
from netskope.integrations.cte.models import (
    Indicator,
    IndicatorType,
    SeverityType,
    TagIn,
)
from netskope.common.utils import add_user_agent
from netskope.integrations.cte.utils import TagUtils

HIGH_SEVERITY_ISSUES = {
    "web_vuln_host_high",
    "redirect_to_insecure_website",
    "web_vuln_host_low",
    "web_vuln_host_medium",
    "local_file_path_exposed_via_url_scheme",
    "communication_with_server_certificate_issued_by_blacklisted_country",
    "communication_server_with_expired_cert",
    "domain_missing_https_v2",
    "links_to_insecure_website",
    "uses_log4j",
    "website_defacement",
    "ransomware_association",
    "alleged_breach_incident",
    "ransomware_victim",
    "adware_installation",
    "adware_installation_trail",
    "anonymous_proxy",
    "attack_detected",
    "malware_controller",
    "malware_infection",
    "malware_infection_trail",
    "phishing",
    "pva_installation",
    "pva_installation_trail",
    "exploited_product",
    "ransomware_infection",
    "ransomware_infection_trail",
    "suspicious_traffic",
    "threat_actor_hosting_infrastructure",
    "tlscert_expired",
    "tlscert_revoked",
    "tlscert_self_signed",
    "tlscert_excessive_expiration",
    "tlscert_weak_signature",
    "tlscert_no_revocation",
    "product_uses_vulnerable_log4j",
    "ssh_weak_protocol",
    "ssh_weak_cipher",
    "ssh_weak_mac",
    "tls_weak_protocol",
    "tls_weak_cipher",
    "patching_cadence_high",
    "service_vuln_host_high",
    "patching_analysis_high",
    "patching_cadence_low",
    "service_vuln_host_low",
    "patching_analysis_low",
    "patching_cadence_medium",
    "service_vuln_host_medium",
    "patching_analysis_medium",
    "patching_cadence_info",
    "service_vuln_host_info",
}

class SecurityScorecardPlugin(PluginBase):
    """SecurityScorecardPlugin class having concrete implementation for pulling threat information."""

    def _get_headers(self, config):
        headers = {
            "Accept": "application/json; charset=utf-8",
            "X-SSC-Application-Name": "Netskope CTE",
            "Authorization": f"Token {config.get('api_token')}"
        }
        return headers
    
    def _validate_portfolio_names(self, portfolios, config):
        portfolio_names = set(
            val for val in config.get("portfolio_names").split(",")
        )
        for portfolio in portfolios:
            if portfolio["name"] in portfolio_names:
                portfolio_names.remove(portfolio["name"])
        if len(portfolio_names) == 0:
            return True
        else:
            return False
    
    def _get_portfolios(self, config, retry_count=1):
        try:
            headers = self._get_headers(config)
            url = "https://api.securityscorecard.io/portfolios"
            response = requests.get(
                url=url,
                headers=headers
            )
            if response.status_code == 200:
                self.logger.info("Plugin SecurityScorecard: Successfully Pulled All the portfolios you have access to.")
                return {"json": response.json(), "status_code": response.status_code}
            elif response.status_code in [429, 503, 301]:
                retry_val = response.headers.get("retry-after", "60")
                if retry_count <= 3 and retry_val.isdigit() and int(retry_val) <= 300:
                    self.logger.error(f"Plugin SecurityScorecard: Retrying to Pull the portfolios after {retry_val} seconds")
                    time.sleep(int(retry_val))
                    return self._get_portfolios(config, retry_count+1)
            self.logger.error(f"Plugin SecurityScorecard: Failed to Pull the portfolios. Response code : {response}, Reason : {response.reason}")
            return {"json": {"entries": [], "total": 0}, "status_code": response.status_code}
        except Exception as e:
            self.logger.error(f"Plugin SecurityScorecard: Error occurred while fetching the Portfolios : {e}")
    
    def _get_portfolio_ids(self, portfolios, config):
        portfolio_names = set(
            val for val in config.get("portfolio_names").split(",")
        )
        portfolio_ids = set()
        for portfolio in portfolios:
            if portfolio["name"] in portfolio_names:
                portfolio_ids.add(portfolio["id"])
        return portfolio_ids
    
    def _get_companies(self, portfolio_id, config, retry_count=1):
        try:
            params = {
                "grade": config.get("grade")
            }
            headers = self._get_headers(config)
            url = f"https://api.securityscorecard.io/portfolios/{portfolio_id}/companies"
            response = requests.get(
                url=url,
                headers=headers,
                params=params
            )
            if response.status_code == 200:
                return {"json": response.json(), "status_code": response.status_code}
            elif response.status_code in [429, 503, 301]:
                retry_val = response.headers.get("retry-after", "60")
                if retry_count <= 3 and retry_val.isdigit() and int(retry_val) <= 300:
                    self.logger.error(f"Plugin SecurityScorecard: Retrying to Pull the companies of portfolio - {portfolio_id} after {retry_val} seconds")
                    time.sleep(int(retry_val))
                    return self._get_companies(portfolio_id, config, retry_count+1)
            self.logger.error(f"Plugin SecurityScorecard: Failed to Pull the companies of portfolio - {portfolio_id}. Response code : {response}, Reason : {response.reason}")
            return {"json": {"entries": [], "total": 0}, "status_code": response.status_code}
        except Exception as e:
            self.logger.error(f"Plugin SecurityScorecard: Error occurred while fething the companies of portfolio - {portfolio_id} : {e}")

    def _get_company_details(self, company_domain, config, retry_count=1):
        try:
            headers = self._get_headers(config)
            url = f"https://api.securityscorecard.io/companies/{company_domain}/factors"
            response = requests.get(
                url=url,
                headers=headers
            )
            if response.status_code == 200:
                return {"json": response.json(), "status_code": response.status_code}
            elif response.status_code in [429, 503, 301]:
                retry_val = response.headers.get("retry-after", "60")
                if retry_count <= 3 and retry_val.isdigit() and int(retry_val) <= 300:
                    self.logger.error(f"Plugin SecurityScorecard: Retrying to Pull the company details of - {company_domain} after {retry_val} seconds")
                    time.sleep(int(retry_val))
                    return self._get_company_details(company_domain, config, retry_count+1)
            self.logger.error(f"Plugin SecurityScorecard: Failed to Pull the company details of - {company_domain}. Response code : {response}, Reason : {response.reason}")
            return {"json": {"entries": [], "total": 0}, "status_code": response.status_code}
        except Exception as e:
            self.logger.error(f"Plugin SecurityScorecard: Error occurred while fetching the company details of - {company_domain} : {e}") 

    def _get_tags_issues_severity(self, company_details, config):
        colours = {
            "positive": "#19ad70",
            "info": "#258bde",
            "low": "#eebc00",
            "medium": "#f78432",
            "high": "#ce2229"
        }
        severity_provided = set(config.get("tag_severity", []))
        tags = []
        issues = set()
        issue_severity = set()
        company_severity = SeverityType.UNKNOWN
        for factor in company_details:
            issue_summary = factor.get("issue_summary")
            for val in issue_summary:
                issue_severity.add(val.get("severity"))
                issues.add(val.get("type"))
                if val.get("severity") in severity_provided:
                    tag = {
                        "name": string.capwords(" ".join(map(str, val.get("type").split("_")))),
                        "colour": colours.get(val.get("severity"))
                    }
                    tags.append(tag)
                    
        if "high" in issue_severity:
            company_severity = SeverityType.HIGH
        elif "medium" in issue_severity:
            company_severity = SeverityType.MEDIUM
        elif "low" in issue_severity:
            company_severity = SeverityType.LOW
        
        return tags, issues, company_severity

    def _create_tags(self, tags: List[dict]) -> (List[str], List[str]):
        """Create new tag(s) in database if required."""
        utils = TagUtils()
        tag_names, skipped_tags = [], []
        for tag in tags:
            try:
                if not utils.exists(tag.get("name").strip()):
                    utils.create_tag(
                        TagIn(
                            name=tag.get("name").strip(),
                            color=tag.get("colour"),
                        )
                    )
            except ValueError:
                skipped_tags.append(tag.get("name").strip())
            else:
                tag_names.append(tag.get("name").strip())
        return tag_names, skipped_tags

    def _get_indicators(self, companies, config) -> List[Indicator]:
        indicators = []
        for company in companies:
            company_details = self._get_company_details(
                company.get("domain"), 
                config
            )["json"]["entries"]
            tags, issues, severity = self._get_tags_issues_severity(company_details, config)
            if len(issues.intersection(HIGH_SEVERITY_ISSUES)) != 0:
                tag_names, skipped_tag_names = self._create_tags(tags)
                extended_information = f"https://platform.securityscorecard.io/#/scorecard/{company.get('domain')}/factors"
                indicators.append(
                    Indicator(
                        value=company.get("domain"),
                        type=IndicatorType.URL,
                        tags=tag_names,
                        severity=severity,
                        extendedInformation=extended_information
                    )
                )
        return indicators

    def pull(self) -> List[Indicator]:
        """Pull the Threat information from SecurityScorecard platform.

        Returns:
            List[cte.models.Indicators]: List of indicator objects received from the SecurityScorecard platform.
        """
        config = self.configuration
        self.logger.info("Plugin SecurityScorecard: excuting pull method")
        try:
            portfolios = self._get_portfolios(config)["json"]["entries"]
            portfolio_ids = self._get_portfolio_ids(portfolios, config)
            indicators = []
            for portfolio_id in portfolio_ids:
                companies = self._get_companies(portfolio_id, config)["json"]["entries"]
                indicators_pulled = self._get_indicators(companies, config)
                self.logger.info(f"Plugin SecurityScorecard: {len(indicators_pulled)} Companies pulled for portfolio {portfolio_id}")
                indicators.extend(indicators_pulled)
            self.logger.info(f"Plugin SecurityScorecard: Total {len(indicators)} Companies pulled from SecurityScorecard")
            return indicators
        except Exception as e:
            self.logger.error(f"Plugin SecurityScorecard: Error occurred while executing Pull method : {e}")

    def validate(self, configuration: dict) -> ValidationResult:
        """Validate the Plugin configuration parameters.

        Validation for all the parameters mentioned in the manifest.json for the existence and
        data type. Method returns the netskope.integrations.cte.plugin_base.ValidationResult object with success = True in the case
        of successful validation and success = False and a error message in the case of failure.
        Args:
            configuration (dict): Dict object having all the Plugin configuration parameters.
        Returns:
            netskope.integrations.cte.plugin_base.ValidateResult: ValidateResult object with success flag and message.
        """
        
        if ("api_token" not in configuration
            or not configuration["api_token"]
            or type(configuration["api_token"]) != str
        ):
            self.logger.error("Plugin SecurityScorecard: Validation error occurred. Field - API Token")
            return ValidationResult(
                success=False, message="Invalid API Token provided.",
            )
        if ("portfolio_names" not in configuration
            or not configuration["portfolio_names"]
            or type(configuration["portfolio_names"]) != str
        ):
            self.logger.error("Plugin SecurityScorecard: Validation error occurred. Field - Portfolios")
            return ValidationResult(
                success=False, message="Invalid Portfolios provided.",
            )
        if ("grade" not in configuration
            or not configuration["grade"]
            or type(configuration["grade"]) != str
        ):
            self.logger.error("Plugin SecurityScorecard: Validation error occurred. Field - Company Grade Threshold")
            return ValidationResult(
                success=False, message="Invalid Company Grade Threshold provided.",
            )
        if ("tag_severity" not in configuration
            or type(configuration["tag_severity"]) != list
        ):
            self.logger.error("Plugin SecurityScorecard: Validation error occurred. Field - Tag Severity")
            return ValidationResult(
                success=False, message="Invalid Tag Severity provided.",
            )
        
        response = self._get_portfolios(configuration)
        if (response["status_code"] != 200):
            self.logger.error("Plugin SecurityScorecard: Validation error occurred. Field - API Token")
            return ValidationResult(
                success=False, message="Invalid API Token provided.",
            )
        
        portfolios = response["json"]["entries"]
        if (self._validate_portfolio_names(portfolios, configuration) == False):
            self.logger.error("Plugin SecurityScorecard: Validation error occurred. Field - Portfolios")
            return ValidationResult(
                success=False, message="Invalid Portfolios provided.",
            )
        return ValidationResult(
            success=True, message="Validation Successful for Secure Scorecard plugin."
        )

    def get_actions(self): 
        """Get available actions.
        Returns:
            List[ActionWithoutParams]: List of ActionWithoutParams objects that are supported by the plugin.
        """
        return []

    def get_action_fields(self, action: Action):
        """Get fields required for an action.
        
        Args: 
            action (Action): Action object which is selected as Target.
        Return:
            List[Dict]: List of configurable fields based on selected action.
        """
        return []

    def validate_action(self, action: Action):
        """Validate Action Parameters.
        
        Args: 
            action (Action): Action object having all the configurable parameters.
        Return:
            netskope.integrations.cte.plugin_base.ValidateResult: ValidateResult object with success flag and message.
        """
        return ValidationResult(success=True, message="Validation successful.")
