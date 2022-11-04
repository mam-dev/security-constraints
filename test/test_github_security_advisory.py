from typing import Dict, List

import pytest

from security_constraints.github_security_advisory import (
    FailedPrerequisitesError,
    FetchVulnerabilitiesError,
    GithubSecurityAdvisoryAPI,
    SecurityVulnerability,
)


@pytest.fixture(name="github_token")
def fixture_token_in_env(monkeypatch) -> str:
    """Set SC_GITHUB_TOKEN environment variable and return it."""
    token = "3e00409b-f017-4ecc-b7bf-f11f6e2a5693"
    monkeypatch.setenv("SC_GITHUB_TOKEN", token)
    return token


def test_instantiate_without_token_in_env() -> None:
    with pytest.raises(FailedPrerequisitesError):
        _ = GithubSecurityAdvisoryAPI()


def test_get_database_name(github_token) -> None:
    assert GithubSecurityAdvisoryAPI().get_database_name() == "Github Security Advisory"


def test_get_vulnerabilities(github_token, requests_mock) -> None:
    cursors = (
        "Y3Vyc29yOnYyOpK5MjAyMi0wMy0yM1QyMDo1NDoyNSswMTowMM0X4Q==",
        "Y3Vyc29yOnYyOpK5MjAyMC0wOS0yNVQxOTo0MjowMCswMjowMM0UeQ==",
        "Y3Vyc29yOnYyOpK5MjAyMC0wOS0yNVQxOTo0MjowMCswMXowMM0DeQ==",
        "Y3Vyc29yOnYyOpK5MjAyMC0wOS0yNVQxOTo0MjowMCswMHowMM0LeQ==",
    )
    expected_vulnerabilities: List[SecurityVulnerability] = []
    vulnerability_nodes: List[Dict] = []
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
    vulnerabilities = api.get_vulnerabilities()

    assert vulnerabilities == expected_vulnerabilities
    assert requests_mock.call_count == 3


def test_get_vulnerabilities__http_error(github_token, requests_mock) -> None:
    requests_mock.post(
        "https://api.github.com/graphql",
        status_code=500,
    )
    with pytest.raises(FetchVulnerabilitiesError):
        api = GithubSecurityAdvisoryAPI()
        _ = api.get_vulnerabilities()


def test_get_vulnerabilities__malformed_data(github_token, requests_mock) -> None:
    requests_mock.post(
        "https://api.github.com/graphql",
        json={"data": {"error": "something went wrong"}},
        request_headers={"Authorization": f"bearer {github_token}"},
    )

    with pytest.raises(FetchVulnerabilitiesError):
        api = GithubSecurityAdvisoryAPI()
        _ = api.get_vulnerabilities()


def test_get_vulnerabilities__json_decode_error(github_token, requests_mock) -> None:
    requests_mock.post(
        "https://api.github.com/graphql",
        body=r"",
        request_headers={"Authorization": f"bearer {github_token}"},
    )

    with pytest.raises(FetchVulnerabilitiesError):
        api = GithubSecurityAdvisoryAPI()
        _ = api.get_vulnerabilities()
