"""This module contains common definitions for use in any other module."""
import abc
import argparse
import dataclasses
import enum
from typing import IO, Any, Dict, List, Optional, Set


class SeverityLevel(str, enum.Enum):
    """The severity of a security vulnerability."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MODERATE = "MODERATE"
    LOW = "LOW"

    @classmethod
    def _missing_(cls, value: object) -> Optional["SeverityLevel"]:
        # Makes instantiation case-insensitive
        if isinstance(value, str):
            for member in cls:
                if member.value == value.upper():
                    return member
        return None

    def get_higher_or_equal_severities(self) -> Set["SeverityLevel"]:
        """Get a set containing this SeverityLevel and all higher ones."""
        return {
            SeverityLevel(value)
            for value in type(self).__members__.values()
            if self.severity_score <= SeverityLevel(value).severity_score
        }

    @classmethod
    def supported_values(cls) -> List[str]:
        """Return a list of the supported severity values."""
        return list(str(v) for v in cls)

    @property
    def severity_score(self) -> int:
        """Get a numerical value for the severity.

        Higher value means more severe.

        """
        return {
            self.LOW.value: 10,  # type: ignore[attr-defined]
            self.MODERATE.value: 25,  # type: ignore[attr-defined]
            self.HIGH.value: 50,  # type: ignore[attr-defined]
            self.CRITICAL.value: 100,  # type: ignore[attr-defined]
        }[self.value]

    def _compare_as_int(self, method_name: str, other: Any) -> bool:
        if not isinstance(other, type(self)):
            raise TypeError(f"Cannot compare {type(self)} and {type(other)}")
        comparison_method = getattr(self.severity_score, method_name)
        return comparison_method(other.severity_score)  # type: ignore[no-any-return]

    def __gt__(self, other) -> bool:
        return self._compare_as_int("__gt__", other)

    def __lt__(self, other) -> bool:
        return self._compare_as_int("__lt__", other)

    def __ge__(self, other) -> bool:
        return self._compare_as_int("__ge__", other)

    def __le__(self, other) -> bool:
        return self._compare_as_int("__le__", other)

    def __str__(self) -> str:
        return self.value


class ArgumentNamespace(argparse.Namespace):
    """Namespace for arguments."""

    dump_config: bool
    debug: bool
    version: bool
    output: Optional[IO]
    ignore_ids: List[str]
    config: Optional[str]
    min_severity: SeverityLevel


class SecurityConstraintsError(Exception):
    """Base class for all exceptions in this application."""


class FailedPrerequisitesError(SecurityConstraintsError):
    """Error raised when something is missing in order to run the application."""


class FetchVulnerabilitiesError(SecurityConstraintsError):
    """Error which occurred when fetching vulnerabilities."""


@dataclasses.dataclass
class Configuration:
    """The application configuration.

    Corresponds to the contents of a configuration file.

    """

    ignore_ids: List[str] = dataclasses.field(default_factory=list)
    min_severity: SeverityLevel = dataclasses.field(default=SeverityLevel.CRITICAL)

    def __post_init__(self) -> None:
        # Type coerce the severity
        self.min_severity = SeverityLevel(self.min_severity)

    def to_dict(self) -> Dict:
        def _dict_factory(data):
            def convert(obj):
                if isinstance(obj, enum.Enum):
                    # Use values for Enums
                    return obj.value
                return obj

            return dict((key, convert(value)) for key, value in data)

        return dataclasses.asdict(self, dict_factory=_dict_factory)

    @classmethod
    def from_dict(cls, json: Dict) -> "Configuration":
        return cls(**json)

    @classmethod
    def supported_keys(cls) -> List[str]:
        """Return a list of keys which are supported in the config file."""
        return list(cls().to_dict().keys())


@dataclasses.dataclass
class PackageConstraints:
    """Version constraints for a single python package.

    Attributes:
        package: The name of the package.
        specifies: A list of version specifiers, e.g. ">3.0".

    """

    package: str
    specifiers: List[str] = dataclasses.field(default_factory=list)

    def __str__(self) -> str:
        return f"{self.package}{','.join(self.specifiers)}"


@dataclasses.dataclass
class SecurityVulnerability:
    """A security vulnerability in a Python package.

    Attributes:
        name: Human-readable name of the vulnerability.
        identifier: Used to uniquely identify this vulnerability,
            e.g. when ignoring it.
        package: The name of the affected Python package.
        vulnerable_range: String specifying which versions are vulnerable.
            Syntax:
            = 0.2.0 denotes a single vulnerable version.
            <= 1.0.8 denotes a version range up to and including the specified version
            < 0.1.11 denotes a version range up to, but excluding, the specified version
            >= 4.3.0, < 4.3.5 denotes a version range with a known min and max version.
            >= 0.0.1 denotes a version range with a known minimum, but no known maximum.

    """

    name: str
    identifier: str
    package: str
    vulnerable_range: str

    def __str__(self) -> str:
        return self.name


class SecurityVulnerabilityDatabaseAPI(abc.ABC):
    """An API toward a database of security vulnerabilities in Python packages."""

    @abc.abstractmethod
    def get_database_name(self) -> str:
        """Return the name of the vulnerability database in human-readable text."""

    @abc.abstractmethod
    def get_vulnerabilities(
        self, severities: Set[SeverityLevel]
    ) -> List[SecurityVulnerability]:
        """Fetch and return all relevant security vulnerabilities from the database."""
