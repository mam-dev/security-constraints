import pytest

from security_constraints.common import ArgumentNamespace, SeverityLevel


@pytest.fixture(name="arg_namespace")
def fixture_arg_namespace() -> ArgumentNamespace:
    return ArgumentNamespace(
        dump_config=False,
        debug=False,
        version=False,
        output=None,
        ignore_ids=[],
        config=None,
        min_severity=SeverityLevel.CRITICAL,
    )


@pytest.fixture(name="github_token")
def fixture_token_in_env(monkeypatch) -> str:
    """Set SC_GITHUB_TOKEN environment variable and return it."""
    token = "3e00409b-f017-4ecc-b7bf-f11f6e2a5693"
    monkeypatch.setenv("SC_GITHUB_TOKEN", token)
    return token
