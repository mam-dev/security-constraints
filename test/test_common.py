from typing import Any, List, Set
from unittest.mock import Mock

import pytest

from security_constraints.common import (
    ArgumentNamespace,
    Configuration,
    PackageConstraints,
    SecurityVulnerability,
    SeverityLevel,
)

IGNORE_IDS = {"A-1", "B-2"}


@pytest.mark.parametrize("raw_severity", SeverityLevel.supported_values())
def test_severity_level_case_insensitive(raw_severity: SeverityLevel) -> None:
    assert (
        SeverityLevel(raw_severity)
        == SeverityLevel(raw_severity.lower())
        == SeverityLevel(raw_severity.upper())
        == SeverityLevel(raw_severity.title())
    )


@pytest.mark.parametrize("input_value", ["fake", 13])
def test_severity_level_bad_value(input_value: Any) -> None:
    with pytest.raises(ValueError, match=str(input_value)):
        _ = SeverityLevel(input_value)


def test_severity_level_supported_values() -> None:
    assert SeverityLevel.supported_values() == ["CRITICAL", "HIGH", "MODERATE", "LOW"]


def test_severity_level_compare_with_other_type() -> None:
    with pytest.raises(TypeError):
        _ = SeverityLevel.CRITICAL > 5


@pytest.mark.parametrize(
    "severities, expected",
    [
        ([SeverityLevel.CRITICAL], [SeverityLevel.CRITICAL]),
        (
            [SeverityLevel.LOW, SeverityLevel.CRITICAL, SeverityLevel.HIGH],
            [SeverityLevel.LOW, SeverityLevel.HIGH, SeverityLevel.CRITICAL],
        ),
    ],
)
def test_sort_severity_levels(
    severities: List[SeverityLevel], expected: List[SeverityLevel]
) -> None:
    assert sorted(severities) == expected


@pytest.mark.parametrize(
    "severity, expected",
    [
        (SeverityLevel.CRITICAL, {SeverityLevel.CRITICAL}),
        (SeverityLevel.HIGH, {SeverityLevel.HIGH, SeverityLevel.CRITICAL}),
        (
            SeverityLevel.MODERATE,
            {SeverityLevel.MODERATE, SeverityLevel.HIGH, SeverityLevel.CRITICAL},
        ),
        (
            SeverityLevel.LOW,
            {
                SeverityLevel.LOW,
                SeverityLevel.MODERATE,
                SeverityLevel.HIGH,
                SeverityLevel.CRITICAL,
            },
        ),
    ],
)
def test_get_higher_or_equal_severities(
    severity: SeverityLevel, expected: Set[SeverityLevel]
) -> None:
    assert severity.get_higher_or_equal_severities() == expected


@pytest.mark.parametrize(
    "first, second, expected",
    [
        (SeverityLevel.CRITICAL, SeverityLevel.CRITICAL, True),
        (SeverityLevel.CRITICAL, SeverityLevel.MODERATE, False),
        (SeverityLevel.LOW, SeverityLevel.MODERATE, True),
    ],
)
def test_severity_level_le(
    first: SeverityLevel, second: SeverityLevel, expected: bool
) -> None:
    assert (first <= second) == expected


@pytest.mark.parametrize(
    "first, second, expected",
    [
        (SeverityLevel.CRITICAL, SeverityLevel.CRITICAL, True),
        (SeverityLevel.CRITICAL, SeverityLevel.MODERATE, True),
        (SeverityLevel.LOW, SeverityLevel.MODERATE, False),
    ],
)
def test_severity_level_ge(
    first: SeverityLevel, second: SeverityLevel, expected: bool
) -> None:
    assert (first >= second) == expected


def test_argument_namespace_can_be_modified(arg_namespace: ArgumentNamespace) -> None:
    arg_namespace.dump_config = True
    assert arg_namespace.dump_config
    arg_namespace.debug = True
    assert arg_namespace.debug
    arg_namespace.version = True
    assert arg_namespace.version
    mock_output = Mock()
    arg_namespace.output = mock_output
    assert arg_namespace.output is mock_output
    arg_namespace.ignore_ids = ["GHSA-X1"]
    assert arg_namespace.ignore_ids == ["GHSA-X1"]
    arg_namespace.config = "sc-conf.yaml"
    assert arg_namespace.config == "sc-conf.yaml"
    arg_namespace.min_severity = SeverityLevel.HIGH
    assert arg_namespace.min_severity == SeverityLevel.HIGH


def test_argument_namespace_cannot_be_extended(
    arg_namespace: ArgumentNamespace,
) -> None:
    with pytest.raises(AttributeError):
        arg_namespace.does_not_exist = True


def test_configuration_to_dict() -> None:
    actual_dict = Configuration(ignore_ids=IGNORE_IDS).to_dict()
    assert actual_dict == {"ignore_ids": sorted(IGNORE_IDS), "min_severity": "CRITICAL"}


def test_configuration_from_dict() -> None:
    created_from_dict = Configuration.from_dict(
        {"ignore_ids": list(IGNORE_IDS), "min_severity": "HIGH"}
    )
    assert created_from_dict == Configuration(
        ignore_ids=IGNORE_IDS, min_severity=SeverityLevel.HIGH
    )
    assert isinstance(created_from_dict.ignore_ids, set)
    assert isinstance(created_from_dict.min_severity, SeverityLevel)


def test_configuration_from_dict__no_min_severity_in_config() -> None:
    created_from_dict = Configuration.from_dict({"ignore_ids": list(IGNORE_IDS)})
    assert created_from_dict == Configuration(
        ignore_ids=IGNORE_IDS, min_severity=SeverityLevel.CRITICAL
    )
    assert isinstance(created_from_dict.min_severity, SeverityLevel)


def test_configuration_from_dict__empty() -> None:
    created_from_dict = Configuration.from_dict({})
    assert created_from_dict == Configuration()
    assert isinstance(created_from_dict.ignore_ids, set)
    assert isinstance(created_from_dict.min_severity, SeverityLevel)


def test_configuration_from_args() -> None:
    created_from_args = Configuration.from_args(
        ArgumentNamespace(
            dump_config=False,
            debug=False,
            version=False,
            output=Mock(),
            ignore_ids=["GHSA-1", "GHSA-3"],
            config=None,
            min_severity=SeverityLevel.HIGH,
        )
    )
    assert created_from_args == Configuration(
        ignore_ids={"GHSA-1", "GHSA-3"},
        min_severity=SeverityLevel.HIGH,
    )


@pytest.mark.parametrize(
    "configs, expected",
    [
        ([Configuration()], Configuration()),
        (
            [
                Configuration(min_severity=SeverityLevel.LOW),
                Configuration(ignore_ids={"GHSA-3"}),
            ],
            Configuration(ignore_ids={"GHSA-3"}, min_severity=SeverityLevel.LOW),
        ),
        (
            [
                Configuration(ignore_ids={"GHSA-2"}),
                Configuration(ignore_ids={"GHSA-3"}),
            ],
            Configuration(ignore_ids={"GHSA-3", "GHSA-2"}),
        ),
        (
            [
                Configuration(
                    ignore_ids={"GHSA-1", "GHSA-6", "GHSA-2"},
                    min_severity=SeverityLevel.CRITICAL,
                ),
                Configuration(
                    ignore_ids={"GHSA-2", "GHSA-4"}, min_severity=SeverityLevel.CRITICAL
                ),
                Configuration(
                    ignore_ids={"GHSA-3", "GHSA-4"}, min_severity=SeverityLevel.HIGH
                ),
                Configuration(
                    ignore_ids={"GHSA-5", "GHSA-1"}, min_severity=SeverityLevel.MODERATE
                ),
            ],
            Configuration(
                ignore_ids={"GHSA-1", "GHSA-2", "GHSA-3", "GHSA-4", "GHSA-5", "GHSA-6"},
                min_severity=SeverityLevel.MODERATE,
            ),
        ),
    ],
)
def test_configuration_merge(
    configs: List[Configuration], expected: Configuration
) -> None:
    assert Configuration.merge(*configs) == expected


def test_configuration_supported_keys() -> None:
    assert Configuration.supported_keys() == ["ignore_ids", "min_severity"]


@pytest.mark.parametrize(
    "package, specifiers, expected",
    [
        ("pystuff", [">=2.0"], "pystuff>=2.0"),
        ("vectorflow", [">=2.0"], "vectorflow>=2.0"),
        ("pystuff", [">=2.0", "<5"], "pystuff>=2.0,<5"),
        ("pystuff", [">=2.0", "<5", "!=3.2.1"], "pystuff>=2.0,<5,!=3.2.1"),
    ],
)
def test_package_constraints_str(
    package: str, specifiers: List[str], expected: str
) -> None:
    assert str(PackageConstraints(package=package, specifiers=specifiers)) == expected


def test_security_vulnerability_str() -> None:
    vulnerability = SecurityVulnerability(
        name="vulnerability-name",
        identifier="MY-ID",
        package="pystuff",
        vulnerable_range="<3.2.1",
    )
    assert str(vulnerability) == "vulnerability-name"
