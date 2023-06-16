import argparse
import logging
import sys
from typing import TYPE_CHECKING, List, Set, Type
from unittest.mock import Mock, call, create_autospec

import pytest
import yaml

from security_constraints.common import (
    ArgumentNamespace,
    Configuration,
    PackageConstraints,
    SecurityConstraintsError,
    SecurityVulnerability,
    SecurityVulnerabilityDatabaseAPI,
    SeverityLevel,
)
from security_constraints.main import (
    are_constraints_pip_friendly,
    create_header,
    fetch_vulnerabilities,
    filter_vulnerabilities,
    format_constraints_file_line,
    get_args,
    get_config,
    get_safe_version_constraints,
    get_security_vulnerability_database_apis,
    main,
    setup_logging,
    sort_vulnerabilities,
)

if TYPE_CHECKING:
    from pathlib import Path

    from _pytest.capture import CaptureFixture
    from _pytest.monkeypatch import MonkeyPatch


def test_get_security_vulnerability_database_apis(monkeypatch: "MonkeyPatch") -> None:
    mock = Mock()
    monkeypatch.setattr("security_constraints.main.GithubSecurityAdvisoryAPI", mock)
    assert get_security_vulnerability_database_apis() == [mock.return_value]


@pytest.mark.parametrize(
    "vulnerability, expected",
    [
        (
            SecurityVulnerability(
                name="CVE-2020-123",
                identifier="GHSA-1-2-3",
                package="pystuff",
                vulnerable_range="= 0.2.0",
            ),
            PackageConstraints(package="pystuff", specifiers=["!=0.2.0"]),
        ),
        (
            SecurityVulnerability(
                name="CVE-2020-123",
                identifier="GHSA-1-2-3",
                package="pystuff",
                vulnerable_range="<= 1.0.8",
            ),
            PackageConstraints(package="pystuff", specifiers=[">1.0.8"]),
        ),
        (
            SecurityVulnerability(
                name="CVE-2020-123",
                identifier="GHSA-1-2-3",
                package="pystuff",
                vulnerable_range="< 0.1.11",
            ),
            PackageConstraints(package="pystuff", specifiers=[">=0.1.11"]),
        ),
        (
            SecurityVulnerability(
                name="CVE-2020-123",
                identifier="GHSA-1-2-3",
                package="pystuff",
                vulnerable_range=">= 4.3.0, < 4.3.5",
            ),
            PackageConstraints(package="pystuff", specifiers=[">=4.3.5"]),
        ),
        (
            SecurityVulnerability(
                name="CVE-2020-123",
                identifier="GHSA-1-2-3",
                package="pystuff",
                vulnerable_range=">= 0.0.1",
            ),
            PackageConstraints(package="pystuff", specifiers=["<0.0.1"]),
        ),
        (
            SecurityVulnerability(
                name="CVE-2020-123",
                identifier="GHSA-1-2-3",
                package="pystuff",
                vulnerable_range="",  # strange, but function should handle it
            ),
            PackageConstraints(package="pystuff", specifiers=[]),
        ),
    ],
)
def test_get_safe_version_constraints(
    vulnerability: SecurityVulnerability, expected: PackageConstraints
) -> None:
    assert get_safe_version_constraints(vulnerability) == expected


@pytest.mark.parametrize(
    "constraints, expected",
    [
        (PackageConstraints(package="pystuff", specifiers=[">1.2"]), True),
        (PackageConstraints(package="pystuff", specifiers=["!=1.2.4"]), True),
        (PackageConstraints(package="pystuff", specifiers=["<2"]), True),
        (
            PackageConstraints(package="pystuff", specifiers=[">1.2", "<2", "!=1.2.4"]),
            True,
        ),
        (PackageConstraints(package="pystuff", specifiers=[">1.2dev0"]), False),
        (PackageConstraints(package="pystuff", specifiers=["<1.0.1b1"]), False),
        (PackageConstraints(package="pystuff", specifiers=["<=1.0.2b1deb1"]), False),
        (PackageConstraints(package="pystuff", specifiers=[">banana-peel"]), False),
        (PackageConstraints(package="pystuff", specifiers=["==1.2dev0"]), True),
    ],
)
def test_are_constraints_pip_friendly(
    constraints: PackageConstraints, expected: bool
) -> None:
    assert are_constraints_pip_friendly(constraints) == expected


def test_get_args(monkeypatch: "MonkeyPatch") -> None:
    mock = create_autospec(argparse.ArgumentParser)
    monkeypatch.setattr("argparse.ArgumentParser", mock)
    args = get_args()
    mock.return_value.add_argument.assert_called()
    assert args is mock.return_value.parse_args.return_value


def test_get_config__no_file(
    monkeypatch: "MonkeyPatch", arg_namespace: ArgumentNamespace
) -> None:
    mock_configuration_cls = create_autospec(Configuration, instance=False)
    monkeypatch.setattr(
        "security_constraints.main.Configuration", mock_configuration_cls
    )
    arg_namespace.config = None
    assert (
        get_config(args=arg_namespace) is mock_configuration_cls.from_args.return_value
    )
    mock_configuration_cls.from_args.assert_called_once_with(arg_namespace)


def test_get_config__config_file(
    tmp_path: "Path", monkeypatch: "MonkeyPatch", arg_namespace: ArgumentNamespace
) -> None:
    mock_configuration_cls = create_autospec(Configuration, instance=False)
    monkeypatch.setattr(
        "security_constraints.main.Configuration", mock_configuration_cls
    )
    mock_config_file: Path = tmp_path / "sc_conf.yaml"
    mock_config_file_content = {
        "ignore_ids": ["GHSA-1", "GHSA-3"],
        "min_severity": "HIGH",
    }
    arg_namespace.config = str(mock_config_file)
    with open(mock_config_file, mode="w") as fh:
        yaml.safe_dump(mock_config_file_content, fh)
    assert get_config(args=arg_namespace) is mock_configuration_cls.merge.return_value
    mock_configuration_cls.from_args.assert_called_once_with(arg_namespace)
    mock_configuration_cls.from_dict.assert_called_once_with(mock_config_file_content)
    mock_configuration_cls.merge.assert_called_once_with(
        mock_configuration_cls.from_dict.return_value,
        mock_configuration_cls.from_args.return_value,
    )


@pytest.mark.parametrize("debug", [False, True])
def test_setup_logging(monkeypatch: "MonkeyPatch", debug: bool) -> None:
    mock = Mock()
    monkeypatch.setattr("logging.getLogger", mock)
    setup_logging(debug=debug)
    mock.return_value.setLevel.assert_called_once_with(
        logging.DEBUG if debug else logging.INFO
    )


@pytest.mark.parametrize(
    "severities",
    [{SeverityLevel.CRITICAL}, {SeverityLevel.CRITICAL, SeverityLevel.HIGH}],
)
def test_fetch_vulnerabilities(severities: Set[SeverityLevel]) -> None:
    mock_vulnerabilities = [create_autospec(SecurityVulnerability) for _ in range(3)]
    mock_apis = [
        Mock(
            spec=SecurityVulnerabilityDatabaseAPI,
            get_vulnerabilities=Mock(return_value=mock_vulnerabilities[:2]),
        ),
        Mock(
            spec=SecurityVulnerabilityDatabaseAPI,
            get_vulnerabilities=Mock(return_value=[mock_vulnerabilities[2]]),
        ),
    ]
    assert (
        fetch_vulnerabilities(mock_apis, severities=severities) == mock_vulnerabilities
    )
    for mock_api in mock_apis:
        mock_api.get_vulnerabilities.assert_called_once_with(severities=severities)


@pytest.mark.parametrize(
    "vulnerabilities, config, expected",
    [
        (
            [
                SecurityVulnerability(
                    name="CVE-1",
                    identifier="GHSA-1",
                    package="pystuff",
                    vulnerable_range="= 1.0",
                ),
                SecurityVulnerability(
                    name="CVE-X1",
                    identifier="GHSA-X1",
                    package="nonsense",
                    vulnerable_range="= 1.0",
                ),
                SecurityVulnerability(
                    name="CVE-2",
                    identifier="GHSA-2",
                    package="pybanana",
                    vulnerable_range="= 2.0",
                ),
                SecurityVulnerability(
                    name="CVE-X2",
                    identifier="GHSA-X1",
                    package="some-package",
                    vulnerable_range="= 1.0",
                ),
                SecurityVulnerability(
                    name="CVE-3U",
                    identifier="GHSA-3",
                    package="pypeel",
                    vulnerable_range="< 3.0dev1",
                ),
            ],
            Configuration(ignore_ids={"GHSA-X1", "GHSA-X2"}),
            [
                SecurityVulnerability(
                    name="CVE-1",
                    identifier="GHSA-1",
                    package="pystuff",
                    vulnerable_range="= 1.0",
                ),
                SecurityVulnerability(
                    name="CVE-2",
                    identifier="GHSA-2",
                    package="pybanana",
                    vulnerable_range="= 2.0",
                ),
                SecurityVulnerability(
                    name="CVE-3U",
                    identifier="GHSA-3",
                    package="pypeel",
                    vulnerable_range="< 3.0dev1",
                ),
            ],
        ),
        ([], Configuration(), []),
    ],
)
def test_filter_vulnerabilities(
    vulnerabilities: List[SecurityVulnerability],
    config: Configuration,
    expected: List[SecurityVulnerability],
) -> None:
    assert (
        filter_vulnerabilities(config=config, vulnerabilities=vulnerabilities)
        == expected
    )


@pytest.mark.parametrize(
    "vulnerabilities, expected",
    [
        (
            [
                SecurityVulnerability(
                    name="CVE-1",
                    identifier="GHSA-1",
                    package="pystuff",
                    vulnerable_range="= 1.0",
                ),
                SecurityVulnerability(
                    name="CVE-2",
                    identifier="GHSA-2",
                    package="pybanana",
                    vulnerable_range="= 2.0",
                ),
                SecurityVulnerability(
                    name="CVE-3U",
                    identifier="GHSA-3",
                    package="pypeel",
                    vulnerable_range="< 3.0dev1",
                ),
            ],
            [
                SecurityVulnerability(
                    name="CVE-2",
                    identifier="GHSA-2",
                    package="pybanana",
                    vulnerable_range="= 2.0",
                ),
                SecurityVulnerability(
                    name="CVE-3U",
                    identifier="GHSA-3",
                    package="pypeel",
                    vulnerable_range="< 3.0dev1",
                ),
                SecurityVulnerability(
                    name="CVE-1",
                    identifier="GHSA-1",
                    package="pystuff",
                    vulnerable_range="= 1.0",
                ),
            ],
        ),
        ([], []),
    ],
)
def test_sort_vulnerabilities(
    vulnerabilities: List[SecurityVulnerability], expected: List[SecurityVulnerability]
) -> None:
    assert sort_vulnerabilities(vulnerabilities=vulnerabilities) == expected


@pytest.mark.parametrize(
    "db_names, config, expected",
    [
        (
            ["FakeDB"],
            Configuration(),
            (
                "# Generated by security-constraints x.y.z"
                " on 1986-04-09T12:11:10.000009Z\n"
                "# Data sources: FakeDB\n"
                r"# Configuration: {'ignore_ids': [], 'min_severity': 'CRITICAL'}"
            ),
        ),
        (
            ["FakeDB", "Another DB"],
            Configuration(ignore_ids={"GHSA-1", "GHSA-2"}),
            (
                "# Generated by security-constraints x.y.z"
                " on 1986-04-09T12:11:10.000009Z\n"
                "# Data sources: FakeDB, Another DB\n"
                r"# Configuration: "
                "{'ignore_ids': ['GHSA-1', 'GHSA-2'], 'min_severity': 'CRITICAL'}"
            ),
        ),
        (
            [],
            Configuration(),
            (
                "# Generated by security-constraints x.y.z"
                " on 1986-04-09T12:11:10.000009Z\n"
                "# Data sources: \n"
                r"# Configuration: {'ignore_ids': [], 'min_severity': 'CRITICAL'}"
            ),
        ),
    ],
)
def test_create_header(
    monkeypatch: "MonkeyPatch",
    frozen_time: None,
    db_names: List[str],
    config: Configuration,
    expected: str,
) -> None:
    mock_version = Mock(return_value="x.y.z")
    monkeypatch.setattr("security_constraints.main.version", mock_version)
    assert (
        create_header(
            [
                Mock(
                    spec=SecurityVulnerabilityDatabaseAPI,
                    get_database_name=Mock(return_value=db_name),
                )
                for db_name in db_names
            ],
            config,
        )
        == expected
    )
    mock_version.assert_called_once_with("security-constraints")


@pytest.mark.parametrize(
    "constraints, vulnerability, expected",
    [
        (
            PackageConstraints(package="pystuff", specifiers=[">=5.2"]),
            SecurityVulnerability(
                name="CVE-1",
                identifier="GHSA-1",
                package="pystuff",
                vulnerable_range="< 5.2",
            ),
            "pystuff>=5.2  # CVE-1 (ID: GHSA-1)",
        ),
        (
            PackageConstraints(package="pystuff", specifiers=[">=5", "!=6.0.0"]),
            SecurityVulnerability(
                name="CVE-1",
                identifier="GHSA-1",
                package="pystuff",
                vulnerable_range="< 5,= 6.0.0",
            ),
            "pystuff>=5,!=6.0.0  # CVE-1 (ID: GHSA-1)",
        ),
    ],
)
def test_format_constraints_file_line(
    constraints: PackageConstraints, vulnerability: SecurityVulnerability, expected: str
) -> None:
    assert format_constraints_file_line(constraints, vulnerability) == expected


def test_format_constraints_file_line__package_mismatch() -> None:
    with pytest.raises(AssertionError):
        _ = format_constraints_file_line(
            PackageConstraints(package="a-package", specifiers=[]),
            SecurityVulnerability(
                name="CVE-1",
                identifier="GHSA-1",
                package="another-package",
                vulnerable_range="< 1",
            ),
        )


@pytest.fixture(name="mock_are_constraints_pip_friendly")
def fixture_mock_are_constraints_pip_friendly(monkeypatch: "MonkeyPatch") -> Mock:
    mock_are_constraints_pip_friendly: Mock = create_autospec(
        are_constraints_pip_friendly
    )
    monkeypatch.setattr(
        "security_constraints.main.are_constraints_pip_friendly",
        mock_are_constraints_pip_friendly,
    )
    return mock_are_constraints_pip_friendly


@pytest.fixture(name="mock_yaml_dump")
def fixture_mock_yaml_dump(monkeypatch: "MonkeyPatch") -> Mock:
    mock_yaml_dump: Mock = create_autospec(yaml.safe_dump)
    monkeypatch.setattr("security_constraints.main.yaml.safe_dump", mock_yaml_dump)
    return mock_yaml_dump


@pytest.fixture(name="mock_fetch_vulnerabilities")
def fixture_mock_fetch_vulnerabilities(monkeypatch: "MonkeyPatch") -> Mock:
    mock_fetch_vulnerabilities: Mock = create_autospec(fetch_vulnerabilities)
    monkeypatch.setattr(
        "security_constraints.main.fetch_vulnerabilities", mock_fetch_vulnerabilities
    )
    return mock_fetch_vulnerabilities


@pytest.fixture(name="mock_get_args")
def fixture_mock_get_args(monkeypatch: "MonkeyPatch") -> Mock:
    mock_get_args: Mock = create_autospec(get_args)
    monkeypatch.setattr("security_constraints.main.get_args", mock_get_args)
    return mock_get_args


@pytest.fixture(name="mock_setup_logging")
def fixture_mock_setup_logging(monkeypatch: "MonkeyPatch") -> Mock:
    mock_setup_logging: Mock = create_autospec(setup_logging)
    monkeypatch.setattr("security_constraints.main.setup_logging", mock_setup_logging)
    return mock_setup_logging


@pytest.fixture(name="mock_get_config")
def fixture_mock_get_config(monkeypatch: "MonkeyPatch") -> Mock:
    mock_get_config: Mock = create_autospec(get_config)
    monkeypatch.setattr("security_constraints.main.get_config", mock_get_config)
    return mock_get_config


@pytest.fixture(name="mock_filter_vulnerabilities")
def fixture_mock_filter_vulnerabilities(monkeypatch: "MonkeyPatch") -> Mock:
    mock_filter_vulnerabilities: Mock = create_autospec(filter_vulnerabilities)
    monkeypatch.setattr(
        "security_constraints.main.filter_vulnerabilities", mock_filter_vulnerabilities
    )
    return mock_filter_vulnerabilities


@pytest.fixture(name="mock_create_header")
def fixture_mock_create_header(monkeypatch: "MonkeyPatch") -> Mock:
    mock_create_header: Mock = create_autospec(create_header)
    mock_create_header.return_value = "# Fake header"
    monkeypatch.setattr("security_constraints.main.create_header", mock_create_header)
    return mock_create_header


@pytest.fixture(name="mock_get_apis")
def fixture_mock_get_apis(monkeypatch: "MonkeyPatch") -> Mock:
    mock_get_apis: Mock = create_autospec(get_security_vulnerability_database_apis)
    monkeypatch.setattr(
        "security_constraints.main.get_security_vulnerability_database_apis",
        mock_get_apis,
    )
    return mock_get_apis


@pytest.fixture(name="mock_sort_vulnerabilities")
def fixture_mock_sort_vulnerabilities(monkeypatch: "MonkeyPatch") -> Mock:
    mock_sort_vulnerabilities: Mock = create_autospec(sort_vulnerabilities)
    monkeypatch.setattr(
        "security_constraints.main.sort_vulnerabilities", mock_sort_vulnerabilities
    )
    return mock_sort_vulnerabilities


@pytest.fixture(name="mock_format_constraints_file_line")
def fixture_mock_format_constraints_file_line(monkeypatch: "MonkeyPatch") -> Mock:
    mock_format_constraints_file_line: Mock = create_autospec(
        format_constraints_file_line
    )
    monkeypatch.setattr(
        "security_constraints.main.format_constraints_file_line",
        mock_format_constraints_file_line,
    )
    return mock_format_constraints_file_line


@pytest.fixture(name="mock_get_safe_constraints")
def fixture_mock_get_safe_constraints(monkeypatch: "MonkeyPatch") -> Mock:
    mock_get_safe_constraints: Mock = create_autospec(get_safe_version_constraints)
    monkeypatch.setattr(
        "security_constraints.main.get_safe_version_constraints",
        mock_get_safe_constraints,
    )
    return mock_get_safe_constraints


@pytest.mark.parametrize("to_stdout", [True, False])
def test_main(
    mock_are_constraints_pip_friendly: Mock,
    mock_yaml_dump: Mock,
    mock_fetch_vulnerabilities: Mock,
    mock_get_args: Mock,
    mock_setup_logging: Mock,
    mock_get_config: Mock,
    mock_filter_vulnerabilities: Mock,
    mock_create_header: Mock,
    mock_get_apis: Mock,
    mock_sort_vulnerabilities: Mock,
    mock_format_constraints_file_line: Mock,
    mock_get_safe_constraints: Mock,
    arg_namespace: ArgumentNamespace,
    to_stdout: bool,
) -> None:
    mock_stream = Mock(isatty=Mock(return_value=to_stdout))
    mock_vulnerabilities = [create_autospec(SecurityVulnerability) for _ in range(3)]
    mock_sorted_vulnerabilities = [
        mock_vulnerabilities[2],
        mock_vulnerabilities[0],
        mock_vulnerabilities[1],
    ]
    mock_constraints = [create_autospec(PackageConstraints) for _ in range(3)]
    mock_api = Mock(get_database_name=Mock(return_value="fake database"))
    mock_get_args.return_value = arg_namespace
    arg_namespace.output = mock_stream
    arg_namespace.ignore_ids = ["GHSA-X1"]
    arg_namespace.min_severity = SeverityLevel.CRITICAL
    mock_get_config.return_value = Configuration(
        ignore_ids={"GHSA-X1", "GHSA-X2"}, min_severity=SeverityLevel.CRITICAL
    )
    mock_get_apis.return_value = [mock_api]
    mock_fetch_vulnerabilities.return_value = mock_vulnerabilities
    mock_sort_vulnerabilities.return_value = mock_sorted_vulnerabilities
    mock_get_safe_constraints.side_effect = mock_constraints
    mock_are_constraints_pip_friendly.side_effect = [True, False, True]
    mock_format_constraints_file_line.side_effect = [
        "constraints-line-1",
        "constraints-line-2",
    ]

    exit_code = main()

    assert exit_code == 0
    mock_yaml_dump.assert_not_called()
    mock_get_args.assert_called_once_with()
    mock_setup_logging.assert_called_once_with(debug=arg_namespace.debug)
    mock_get_config.assert_called_once_with(args=arg_namespace)
    mock_get_apis.assert_called_once_with()
    mock_fetch_vulnerabilities.assert_called_once_with(
        [mock_api], severities={SeverityLevel.CRITICAL}
    )
    mock_filter_vulnerabilities.assert_called_once_with(
        config=Configuration(
            ignore_ids={"GHSA-X2", "GHSA-X1"}, min_severity=SeverityLevel.CRITICAL
        ),
        vulnerabilities=mock_vulnerabilities,
    )
    mock_sort_vulnerabilities.assert_called_once_with(
        mock_filter_vulnerabilities.return_value
    )
    mock_get_safe_constraints.assert_has_calls(
        [call(v) for v in mock_sorted_vulnerabilities],
        any_order=False,
    )
    mock_format_constraints_file_line.assert_has_calls(
        [
            call(mock_constraints[0], mock_sorted_vulnerabilities[0]),
            call(mock_constraints[2], mock_sorted_vulnerabilities[2]),
        ]
    )
    mock_stream.write.assert_has_calls(
        [
            call("# Fake header\n"),
            call("constraints-line-1\n"),
            call("constraints-line-2\n"),
        ],
        any_order=False,
    )
    mock_stream.isatty.assert_called_once_with()
    if to_stdout:
        mock_stream.close.assert_not_called()
    else:
        mock_stream.close.assert_called_once_with()


@pytest.mark.parametrize("to_stdout", [True, False])
def test_main__dump_config(
    mock_get_args: Mock,
    mock_setup_logging: Mock,
    mock_get_config: Mock,
    mock_yaml_dump: Mock,
    mock_get_apis: Mock,
    arg_namespace: ArgumentNamespace,
    monkeypatch: "MonkeyPatch",
    to_stdout: bool,
) -> None:
    mock_stream = Mock(isatty=Mock(return_value=to_stdout))
    mock_get_args.return_value = arg_namespace
    arg_namespace.output = mock_stream
    arg_namespace.dump_config = True
    arg_namespace.ignore_ids = ["GHSA-X1"]
    arg_namespace.min_severity = SeverityLevel.CRITICAL
    mock_get_config.return_value = Configuration(
        ignore_ids={"GHSA-X1", "GHSA-X2"}, min_severity=SeverityLevel.CRITICAL
    )

    exit_code = main()

    assert exit_code == 0
    mock_yaml_dump.assert_called_once_with(
        {"ignore_ids": ["GHSA-X1", "GHSA-X2"], "min_severity": "CRITICAL"},
        stream=sys.stdout,
    )
    mock_get_args.assert_called_once_with()
    mock_setup_logging.assert_called_once_with(debug=mock_get_args.return_value.debug)
    mock_get_config.assert_called_once_with(args=mock_get_args.return_value)
    mock_get_apis.assert_not_called()
    mock_stream.write.assert_not_called()
    mock_stream.isatty.assert_called_once_with()
    if to_stdout:
        mock_stream.close.assert_not_called()
    else:
        mock_stream.close.assert_called_once_with()


def test_main__version(
    mock_version: Mock,
    mock_get_args: Mock,
    mock_setup_logging: Mock,
    mock_get_config: Mock,
    mock_yaml_dump: Mock,
    mock_get_apis: Mock,
    arg_namespace: ArgumentNamespace,
    capsys: "CaptureFixture[str]",
) -> None:
    mock_stream = Mock()
    mock_get_args.return_value = arg_namespace
    arg_namespace.version = True
    arg_namespace.output = mock_stream
    arg_namespace.dump_config = True
    arg_namespace.ignore_ids = ["GHSA-X1"]

    exit_code = main()

    assert exit_code == 0
    out, err = capsys.readouterr()
    mock_version.assert_called_once_with("security-constraints")
    assert "x.y.z" in out
    assert not err
    mock_yaml_dump.assert_not_called()
    mock_get_args.assert_called_once_with()
    mock_setup_logging.assert_not_called()
    mock_get_config.assert_not_called()
    mock_get_apis.assert_not_called()
    mock_stream.write.assert_not_called()


@pytest.mark.parametrize(
    "exception_type, expected_exit_code",
    [(SecurityConstraintsError, 1), (Exception, 2)],
)
def test_main__exception(
    monkeypatch: "MonkeyPatch",
    mock_get_args: Mock,
    mock_setup_logging: Mock,
    mock_get_config: Mock,
    mock_yaml_dump: Mock,
    mock_get_apis: Mock,
    mock_filter_vulnerabilities: Mock,
    arg_namespace: ArgumentNamespace,
    exception_type: Type[Exception],
    expected_exit_code: int,
) -> None:
    mock_stream = Mock(isatty=Mock(return_value=True))
    mock_get_apis.side_effect = exception_type("intentional")
    mock_get_args.return_value = arg_namespace
    arg_namespace.output = mock_stream
    arg_namespace.ignore_ids = ["GHSA-X1"]
    mock_get_config.return_value = Configuration(ignore_ids={"GHSA-X1", "GHSA-X2"})

    exit_code = main()

    assert exit_code == expected_exit_code
    mock_yaml_dump.assert_not_called()
    mock_get_args.assert_called_once_with()
    mock_setup_logging.assert_called_once_with(debug=mock_get_args.return_value.debug)
    mock_get_config.assert_called_once_with(args=arg_namespace)
    mock_get_apis.assert_called_once_with()
    mock_filter_vulnerabilities.assert_not_called()
    mock_stream.write.assert_not_called()
    mock_stream.isatty.assert_called_once_with()


def test_main__output_none_exception(
    mock_get_args: Mock,
    mock_setup_logging: Mock,
    mock_get_config: Mock,
    arg_namespace: ArgumentNamespace,
) -> None:
    mock_get_args.return_value = arg_namespace
    arg_namespace.output = None

    exit_code = main()

    assert exit_code == 2
    mock_get_config.assert_not_called()
