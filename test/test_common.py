from typing import List, Set

import pytest

from security_constraints.common import (
    Configuration,
    PackageConstraints,
    SecurityVulnerability,
    SeverityLevel,
)

IGNORE_IDS = ["A-1", "B-2"]


@pytest.mark.parametrize("raw_severity", SeverityLevel.supported_values())
def test_severity_level_case_insensitive(raw_severity: SeverityLevel) -> None:
    assert (
        SeverityLevel(raw_severity)
        == SeverityLevel(raw_severity.lower())
        == SeverityLevel(raw_severity.upper())
        == SeverityLevel(raw_severity.title())
    )


def test_severity_level_supported_values() -> None:
    assert SeverityLevel.supported_values() == ["CRITICAL", "HIGH", "MODERATE", "LOW"]


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


def test_configuration_to_dict() -> None:
    actual_dict = Configuration(ignore_ids=IGNORE_IDS).to_dict()
    assert actual_dict == {"ignore_ids": IGNORE_IDS, "min_severity": "CRITICAL"}


def test_configuration_from_dict() -> None:
    created_from_dict = Configuration.from_dict(
        {"ignore_ids": IGNORE_IDS, "min_severity": "HIGH"}
    )
    assert created_from_dict == Configuration(
        ignore_ids=IGNORE_IDS, min_severity=SeverityLevel.HIGH
    )
    assert isinstance(created_from_dict.min_severity, SeverityLevel)


def test_configuration_from_dict__no_min_severity_in_config() -> None:
    created_from_dict = Configuration.from_dict({"ignore_ids": IGNORE_IDS})
    assert created_from_dict == Configuration(
        ignore_ids=IGNORE_IDS, min_severity=SeverityLevel.CRITICAL
    )
    assert isinstance(created_from_dict.min_severity, SeverityLevel)


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
