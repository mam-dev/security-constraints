from typing import TYPE_CHECKING, Any, Dict, List, Set

import pytest

from security_constraints.common import (
    FailedPrerequisitesError,
    FetchVulnerabilitiesError,
    SecurityVulnerability,
    SeverityLevel,
)
from security_constraints.github_security_advisory import GithubSecurityAdvisoryAPI

if TYPE_CHECKING:
    from requests_mock import Mocker as RequestsMock


def test_instantiate_without_token_in_env() -> None:
    with pytest.raises(FailedPrerequisitesError):
        _ = GithubSecurityAdvisoryAPI()


def test_get_database_name(github_token: str) -> None:
    assert GithubSecurityAdvisoryAPI().get_database_name() == "Github Security Advisory"


@pytest.mark.parametrize(
    "severities, expected_graphql_severities",
    [
        ({SeverityLevel.CRITICAL}, "[CRITICAL]"),
        ({SeverityLevel.HIGH, SeverityLevel.CRITICAL}, "[CRITICAL,HIGH]"),
        (
            {SeverityLevel.MODERATE, SeverityLevel.HIGH, SeverityLevel.CRITICAL},
            "[CRITICAL,HIGH,MODERATE]",
        ),
    ],
)
def test_get_vulnerabilities(
    github_token: str,
    requests_mock: "RequestsMock",
    severities: Set[SeverityLevel],
    expected_graphql_severities: str,
) -> None:
    cursors = (
        "Y3Vyc29yOnYyOpK5MjAyMi0wMy0yM1QyMDo1NDoyNSswMTowMM0X4Q==",
        "Y3Vyc29yOnYyOpK5MjAyMC0wOS0yNVQxOTo0MjowMCswMjowMM0UeQ==",
        "Y3Vyc29yOnYyOpK5MjAyMC0wOS0yNVQxOTo0MjowMCswMXowMM0DeQ==",
        "Y3Vyc29yOnYyOpK5MjAyMC0wOS0yNVQxOTo0MjowMCswMHowMM0LeQ==",
    )
    expected_vulnerabilities: List[SecurityVulnerability] = []
    vulnerability_nodes: List[Dict[str, Any]] = []
    for request_index in range(3):
        for i in range(100 if request_index < 2 else 41):
            ghsa = f"GHSA-{request_index}-{i}"
            package = f"package_{request_index}_{i}"
            expected_vulnerabilities.append(
                SecurityVulnerability(
                    name="CVE-2020-12345",
                    identifier=ghsa,
                    package=package,
                    vulnerable_range="< 1.2.3",
                )
            )
            vulnerability_nodes.append(
                {
                    "advisory": {
                        "ghsaId": ghsa,
                        "identifiers": [
                            {
                                "value": ghsa,
                                "type": "GHSA",
                            },
                            {"value": "CVE-2020-12345", "type": "CVE"},
                        ],
                    },
                    "vulnerableVersionRange": "< 1.2.3",
                    "package": {"name": package},
                }
            )

    requests_mock.post(
        "https://api.github.com/graphql",
        [
            {
                "json": {
                    "data": {
                        "securityVulnerabilities": {
                            "totalCount": 241,
                            "pageInfo": {
                                "endCursor": cursors[request_index + 1],
                                "startCursor": cursors[request_index],
                                "hasNextPage": request_index < 2,
                            },
                            "nodes": vulnerability_nodes[
                                request_index
                                * 100 : min(request_index * 100 + 100, 241)
                            ],
                        }
                    }
                }
            }
            for request_index in range(3)
        ],
        request_headers={"Authorization": f"bearer {github_token}"},
    )

    api = GithubSecurityAdvisoryAPI()
    vulnerabilities = api.get_vulnerabilities(severities=severities)

    assert vulnerabilities == expected_vulnerabilities
    assert requests_mock.call_count == 3
    assert [req.json()["query"] for req in requests_mock.request_history] == [
        (
            "{"
            "securityVulnerabilities("
            " first: 100"
            " ecosystem:PIP"
            f" severities:{expected_graphql_severities}"
            f" {additional}"
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
        for additional in [""] + [f'after:"{cursor}"' for cursor in cursors[1:3]]
    ]


def test_get_vulnerabilities__http_error(
    github_token: str, requests_mock: "RequestsMock"
) -> None:
    requests_mock.post(
        "https://api.github.com/graphql",
        status_code=500,
    )
    api = GithubSecurityAdvisoryAPI()
    with pytest.raises(FetchVulnerabilitiesError):
        _ = api.get_vulnerabilities(severities={SeverityLevel.CRITICAL})


@pytest.mark.parametrize(
    "json_content", [{"data": {"error": "something went wrong"}}, {}, "xyz"]
)
def test_get_vulnerabilities__malformed_data(
    github_token: str, requests_mock: "RequestsMock", json_content: Any
) -> None:
    requests_mock.post(
        "https://api.github.com/graphql",
        json=json_content,
        request_headers={"Authorization": f"bearer {github_token}"},
    )

    api = GithubSecurityAdvisoryAPI()
    with pytest.raises(FetchVulnerabilitiesError):
        _ = api.get_vulnerabilities(severities={SeverityLevel.CRITICAL})


def test_get_vulnerabilities__json_decode_error(
    github_token: str, requests_mock: "RequestsMock"
) -> None:
    requests_mock.post(
        "https://api.github.com/graphql",
        text="",
        request_headers={"Authorization": f"bearer {github_token}"},
    )

    api = GithubSecurityAdvisoryAPI()
    with pytest.raises(FetchVulnerabilitiesError):
        _ = api.get_vulnerabilities(severities={SeverityLevel.CRITICAL})
