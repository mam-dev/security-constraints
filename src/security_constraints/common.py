"""This module contains common definitions for use in any other module."""
import abc
import dataclasses
from typing import Dict, List


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

    def to_dict(self) -> Dict:
        return dataclasses.asdict(self)

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
    def get_vulnerabilities(self) -> List[SecurityVulnerability]:
        """Fetch and return all relevant security vulnerabilities from the database."""
