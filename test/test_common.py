from typing import List

import pytest

from security_constraints.common import (
    Configuration,
    PackageConstraints,
    SecurityVulnerability,
)

IGNORE_IDS = ["A-1", "B-2"]


def test_configuration_to_dict() -> None:
    actual_dict = Configuration(ignore_ids=IGNORE_IDS).to_dict()
    assert actual_dict == {"ignore_ids": IGNORE_IDS}


def test_configuration_from_dict() -> None:
    created_from_dict = Configuration.from_dict({"ignore_ids": IGNORE_IDS})
    assert created_from_dict == Configuration(ignore_ids=IGNORE_IDS)


def test_configuration_supported_keys() -> None:
    assert Configuration.supported_keys() == ["ignore_ids"]


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
