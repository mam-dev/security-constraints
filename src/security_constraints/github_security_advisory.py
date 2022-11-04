"""Module for fetching vulnerabilities from the GitHub Security Advisory."""
import logging
import os
import string
from typing import Any, Dict, List, Optional

import requests

from security_constraints.common import (
    FailedPrerequisitesError,
    FetchVulnerabilitiesError,
    SecurityVulnerability,
    SecurityVulnerabilityDatabaseAPI,
)

LOGGER = logging.getLogger(__name__)


QUERY_TEMPLATE = string.Template(
    "{"
    "securityVulnerabilities("
    " first: $first"
    " ecosystem:PIP"
    " severities:$severities"
    " $additional"
    ") {"
    "    totalCount"
    "    pageInfo { endCursor startCursor hasNextPage }"
    "    nodes {"
    "        advisory {"
    "            ghsaId"
    "            identifiers { value type }"
    "        }"
    "        vulnerableVersionRange"
    "        package { name }"
    "    }"
    "}"
    "}"
)


class GithubSecurityAdvisoryAPI(SecurityVulnerabilityDatabaseAPI):
    """API toward the GitHub Security Advisory database.

    Instantiation requires that the environment variable SC_GITHUB_TOKEN
    has been set to a valid token with permissions to read from public
    GitHub repositories.

    """

    URL = "https://api.github.com/graphql"

    def __init__(self):
        self._session = requests.Session()
        self._current_cursor: Optional[str] = None
        try:
            self._token: str = os.environ["SC_GITHUB_TOKEN"]
        except KeyError as missing_key:
            raise FailedPrerequisitesError(f"Missing from environment: {missing_key}")

    def get_database_name(self) -> str:
        return "Github Security Advisory"

    def get_vulnerabilities(self) -> List[SecurityVulnerability]:
        """Fetch all CRITICAL vulnerabilities from GitHub Security Advisory."""
        after: Optional[str] = None
        vulnerabilities: List[SecurityVulnerability] = []
        more_data_exists = True
        while more_data_exists:
            json_response: Dict = self._do_graphql_request(
                severities=["CRITICAL"], after=after
            )
            try:
                json_data: Dict = json_response["data"]
                vulnerabilities.extend(
                    [
                        SecurityVulnerability(
                            name=",".join(
                                identifier["value"]
                                for identifier in node["advisory"]["identifiers"]
                                if identifier["type"] != "GHSA"
                            )
                            or node["advisory"]["ghsaId"],
                            identifier=node["advisory"]["ghsaId"],
                            package=node["package"]["name"],
                            vulnerable_range=node["vulnerableVersionRange"],
                        )
                        for node in json_data["securityVulnerabilities"]["nodes"]
                    ]
                )
                more_data_exists = json_data["securityVulnerabilities"]["pageInfo"][
                    "hasNextPage"
                ]
                after = json_data["securityVulnerabilities"]["pageInfo"]["endCursor"]
            except KeyError as missing_key:
                error_msg = f"Key {missing_key} not found in: {json_response}"
                LOGGER.error(error_msg)
                raise FetchVulnerabilitiesError(error_msg)

        return vulnerabilities

    def _do_graphql_request(
        self, severities: List[str], after: Optional[str] = None
    ) -> Any:
        query = QUERY_TEMPLATE.substitute(
            first=100,
            severities=",".join(severities),
            additional=f'after:"{after}"' if after is not None else "",
        )
        response: requests.Response = self._session.post(
            url=self.URL,
            headers={"Authorization": f"bearer {self._token}"},
            json={"query": query},
        )
        try:
            response.raise_for_status()
            return response.json()
        except requests.HTTPError as error:
            LOGGER.error(
                "HTTP error (status %s) received from URL %s: %s",
                response.status_code,
                self.URL,
                error,
            )
            raise FetchVulnerabilitiesError from error
        except requests.JSONDecodeError as error:
            LOGGER.error("Could not decode json data in response: %s", response.text)
            raise FetchVulnerabilitiesError from error
