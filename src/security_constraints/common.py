"""This module contains common definitions for use in any other module."""
from __future__ import annotations

import abc
import argparse
import dataclasses
import enum
from typing import (
    IO,
    TYPE_CHECKING,
    Any,
)

if TYPE_CHECKING:  # pragma: no cover
    import sys
    from typing import TypedDict

    if sys.version_info >= (3, 11):
        from typing import Self  # pragma: no cover (<py311)
    else:
        from typing_extensions import Self  # pragma: no cover (>=py311)

    class _ConfigurationKwargs(TypedDict, total=False):
        ignore_ids: set[str]
        min_severity: SeverityLevel


class SeverityLevel(str, enum.Enum):
    """The severity of a security vulnerability."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MODERATE = "MODERATE"
    LOW = "LOW"

    @classmethod
    def _missing_(cls, value: object) -> Self | None:
        # Makes instantiation case-insensitive
        if isinstance(value, str):
            for member in cls:
                if member.value == value.upper():
                    return member
        return None

    def get_higher_or_equal_severities(self) -> set[Self]:
        """Get a set containing this SeverityLevel and all higher ones."""
        return {
            type(self)(value)
            for value in type(self).__members__.values()
            if self.severity_score <= SeverityLevel(value).severity_score
        }

    @classmethod
    def supported_values(cls) -> list[str]:
        """Return a list of the supported severity values."""
        return [str(v) for v in cls]

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

    def __gt__(self, other: Any) -> bool:
        return self._compare_as_int("__gt__", other)

    def __lt__(self, other: Any) -> bool:
        return self._compare_as_int("__lt__", other)

    def __ge__(self, other: Any) -> bool:
        return self._compare_as_int("__ge__", other)

    def __le__(self, other: Any) -> bool:
        return self._compare_as_int("__le__", other)

    def __str__(self) -> str:
        return self.value


class ArgumentNamespace(argparse.Namespace):
    """Namespace for arguments."""

    dump_config: bool
    debug: bool
    version: bool
    output: IO[str] | None
    ignore_ids: list[str]
    config: str | None
    min_severity: SeverityLevel

    def __setattr__(self, key: str, value: Any) -> None:
        # Makes it so that no attributes except those type hinted above can be set.
        if key not in self.__annotations__:  # get_type_hints(self):
            raise AttributeError(f"No attribute named '{key}'")
        super().__setattr__(key, value)


class SecurityConstraintsError(Exception):
    """Base class for all exceptions in this application."""


class FailedPrerequisitesError(SecurityConstraintsError):
    """Error raised when something is missing in order to run the application."""


class FetchVulnerabilitiesError(SecurityConstraintsError):
    """Error which occurred when fetching vulnerabilities."""


@dataclasses.dataclass(frozen=True)
class Configuration:
    """The application configuration.

    Corresponds to the contents of a configuration file,
    or to (some of) the arguments given in a CLI execution.

    """

    ignore_ids: set[str] = dataclasses.field(default_factory=set)
    min_severity: SeverityLevel = dataclasses.field(default=SeverityLevel.CRITICAL)

    def to_dict(self) -> dict[str, Any]:
        def _dict_factory(data: list[tuple[str, Any]]) -> dict[str, Any]:
            def convert(obj: Any) -> Any:
                if isinstance(obj, enum.Enum):
                    # Use values for Enums
                    return obj.value
                if isinstance(obj, set):
                    # Use ordered list for sets
                    return sorted(obj)
                return obj  # pragma: no cover

            return {key: convert(value) for key, value in data}

        return dataclasses.asdict(self, dict_factory=_dict_factory)

    @classmethod
    def from_dict(cls, in_dict: dict[str, Any]) -> Self:
        kwargs: _ConfigurationKwargs = {}
        if "ignore_ids" in in_dict:
            kwargs["ignore_ids"] = set(in_dict["ignore_ids"])
        if "min_severity" in in_dict:
            kwargs["min_severity"] = SeverityLevel(in_dict["min_severity"])
        return cls(**kwargs)

    @classmethod
    def from_args(cls, args: ArgumentNamespace) -> Self:
        return cls(
            ignore_ids=set(args.ignore_ids),
            min_severity=args.min_severity,
        )

    @classmethod
    def merge(cls, *config: Self) -> Self:
        """Merge multiple Configurations into a new one."""
        all_ignore_ids_entries = (c.ignore_ids for c in config)
        all_min_severity_entries = (c.min_severity for c in config)
        return cls(
            ignore_ids=set.union(*all_ignore_ids_entries),
            min_severity=min(all_min_severity_entries),
        )

    @classmethod
    def supported_keys(cls) -> list[str]:
        """Return a list of keys which are supported in the config file."""
        return list(cls().to_dict().keys())


@dataclasses.dataclass
class PackageConstraints:
    """Version constraints for a single python package.

    Attributes:
        package: The name of the package.
        specifiers: A list of version specifiers, e.g. ">3.0".

    """

    package: str
    specifiers: list[str] = dataclasses.field(default_factory=list)

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
        self, severities: set[SeverityLevel]
    ) -> list[SecurityVulnerability]:
        """Fetch and return all relevant security vulnerabilities from the database."""
