import datetime
from typing import TYPE_CHECKING, Generator
from unittest.mock import Mock

import freezegun
import pytest

if TYPE_CHECKING:
    from _pytest.monkeypatch import MonkeyPatch

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
def fixture_token_in_env(monkeypatch: "MonkeyPatch") -> str:
    """Set SC_GITHUB_TOKEN environment variable and return it."""
    token = "3e00409b-f017-4ecc-b7bf-f11f6e2a5693"
    monkeypatch.setenv("SC_GITHUB_TOKEN", token)
    return token


@pytest.fixture(name="mock_version")
def fixture_mock_version(monkeypatch: "MonkeyPatch") -> Mock:
    """Mock main.version with a mock that returns 'x.y.z'."""
    mock_version: Mock = Mock(return_value="x.y.z")
    monkeypatch.setattr("security_constraints.main.version", mock_version)
    return mock_version


@pytest.fixture(name="frozen_time")
def _fixture_frozen_time() -> Generator[None, None, None]:
    """Freeze time during the test.

    The UTC timestamp will be '1986-04-09T12:11:10.000009Z'.

    """
    time_to_freeze = datetime.datetime(
        1986, 4, 9, 12, 11, 10, 9, tzinfo=datetime.timezone.utc
    )
    with freezegun.freeze_time(time_to_freeze=time_to_freeze):
        yield
