"""Module for fetching vulnerabilities from the GitHub Security Advisory."""
import logging
import os
import string
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Set, cast

import requests

from security_constraints.common import (
    FailedPrerequisitesError,
    FetchVulnerabilitiesError,
    SecurityVulnerability,
    SecurityVulnerabilityDatabaseAPI,
    SeverityLevel,
)

if TYPE_CHECKING:  # pragma: no cover
    import sys

    if sys.version_info >= (3, 8):
        from typing import TypedDict
    else:
        from typing_extensions import TypedDict

    class _GraphQlResponseJson(TypedDict, total=False):
        data: Dict[Any, Any]


LOGGER = logging.getLogger(__name__)

QUERY_TEMPLATE = string.Template(
    "{"
    "securityVulnerabilities("
    " first: $first"
    " ecosystem:PIP"
    " severities:[$severities]"
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

    def __init__(self) -> None:
        self._session = requests.Session()
        self._current_cursor: Optional[str] = None
        try:
            self._token: str = os.environ["SC_GITHUB_TOKEN"]
        except KeyError as missing_key:
            raise FailedPrerequisitesError(
                f"Missing from environment: {missing_key}"
            ) from None

    def get_database_name(self) -> str:
        return "Github Security Advisory"

    def get_vulnerabilities(
        self, severities: Set[SeverityLevel]
    ) -> List[SecurityVulnerability]:
        """Fetch all CRITICAL vulnerabilities from GitHub Security Advisory.

        The SeverityLevels map trivially to GitHub's SecurityAdvisorySeverity.

        """
        after: Optional[str] = None
        vulnerabilities: List[SecurityVulnerability] = []
        more_data_exists = True
        while more_data_exists:
            json_response: "_GraphQlResponseJson" = self._do_graphql_request(
                severities=severities, after=after
            )
            try:
                json_data: Dict[str, Any] = json_response["data"]
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
                raise FetchVulnerabilitiesError(error_msg) from None

        return vulnerabilities

    @staticmethod
    def _verify_graphql_json(response_json: Any) -> "_GraphQlResponseJson":
        if (
            not isinstance(response_json, dict)
            or "data" not in response_json
            or not isinstance(response_json["data"], dict)
            or any(not isinstance(key, str) for key in response_json["data"])
        ):
            raise FetchVulnerabilitiesError(
                f"Unexpected json data format in response: {response_json}"
            )
        return cast("_GraphQlResponseJson", response_json)

    def _do_graphql_request(
        self, severities: Set[SeverityLevel], after: Optional[str] = None
    ) -> "_GraphQlResponseJson":
        query = QUERY_TEMPLATE.substitute(
            first=100,
            severities=",".join(sorted([str(severity) for severity in severities])),
            additional=f'after:"{after}"' if after is not None else "",
        )
        response: requests.Response = self._session.post(
            url=self.URL,
            headers={"Authorization": f"bearer {self._token}"},
            json={"query": query},
        )
        try:
            response.raise_for_status()
            json_content: Any = response.json()
            return self._verify_graphql_json(response_json=json_content)
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
