# security-constraints

Security-constraints is a command-line application used
to fetch security vulnerabilities in Python packages from
external sources and from them generate version constraints
for the packages.

The constraints can then be given to `pip install` with the `-c` option,
either on the command line or in a requirements file.

## Installation

Just install it with `pip`:
```bash
pip install security-constraints
```

## Usage

The environment variable `SC_GITHUB_TOKEN` needs to be set
to a valid GitHub token which provides read access to public
repositories. This is needed in order to access GitHub Security
Advisory. Once this is set, you can simply run the program to
output safe pip constraints to stdout.

```bash
>security-constraints
# Generated by security-constraints 1.0.0 on 2022-11-04T08:33:54.523625
# Data sources: Github Security Advisory
# Configuration: {'ignore_ids': []}
...
vncauthproxy>=1.2.0  # CVE-2022-36436 (ID: GHSA-237r-mx84-7x8c)
waitress!=1.4.2  # CVE-2020-5236 (ID: GHSA-73m2-3pwg-5fgc)
waitress>=1.4.0  # GHSA-4ppp-gpcr-7qf6 (ID: GHSA-4ppp-gpcr-7qf6)
ymlref>0.1.1  # CVE-2018-20133 (ID: GHSA-8r8j-xvfj-36f9)
>
```

You can use `--output` to instead output to a file.

```bash
>security-constraints --output constraints.txt
>cat constraints.txt
# Generated by security-constraints 1.0.0 on 2022-11-04T08:33:54.523625
# Data sources: Github Security Advisory
# Configuration: {'ignore_ids': []}
...
vncauthproxy>=1.2.0  # CVE-2022-36436 (ID: GHSA-237r-mx84-7x8c)
waitress!=1.4.2  # CVE-2020-5236 (ID: GHSA-73m2-3pwg-5fgc)
waitress>=1.4.0  # GHSA-4ppp-gpcr-7qf6 (ID: GHSA-4ppp-gpcr-7qf6)
ymlref>0.1.1  # CVE-2018-20133 (ID: GHSA-8r8j-xvfj-36f9)
>
```

You can provide a space-separated list of IDs of vulnerabilities that
should be ignored. The IDs in question are those that appear in after
`ID:` in the comments in the output.

```bash
>security-constraints --ignore-ids GHSA-4ppp-gpcr-7qf6 GHSA-8r8j-xvfj-36f9
# Generated by security-constraints 1.0.0 on 2022-11-04T08:33:54.523625
# Data sources: Github Security Advisory
# Configuration: {'ignore_ids': ['GHSA-4ppp-gpcr-7qf6', 'GHSA-8r8j-xvfj-36f9']}
...
vncauthproxy>=1.2.0  # CVE-2022-36436 (ID: GHSA-237r-mx84-7x8c)
waitress!=1.4.2  # CVE-2020-5236 (ID: GHSA-73m2-3pwg-5fgc)
>
```

The IDs to ignore can also be given in a configuration file using `--config`.
To create an initial configuration file, you can use `--dump-config`. This
will dump the current configuration (including any `--ignore-ids` passed) to
stdout and then exit. You can redirect this into a file to create an
initial configuration file. The configuration file is in yaml format.

```bash
>security-constraints --ignore-ids GHSA-4ppp-gpcr-7qf6 GHSA-8r8j-xvfj-36f9 --dump-config > sc_config.yaml
>cat sc_config.yaml
ignore_ids:
- GHSA-4ppp-gpcr-7qf6
- GHSA-8r8j-xvfj-36f9
>security-constraints --config sc_config.yaml
# Generated by security-constraints 1.0.0 on 2022-11-04T08:33:54.523625
# Data sources: Github Security Advisory
# Configuration: {'ignore_ids': ['GHSA-4ppp-gpcr-7qf6', 'GHSA-8r8j-xvfj-36f9']}
...
vncauthproxy>=1.2.0  # CVE-2022-36436 (ID: GHSA-237r-mx84-7x8c)
waitress!=1.4.2  # CVE-2020-5236 (ID: GHSA-73m2-3pwg-5fgc)
>
```

By default, security-constraints fetches all security vulnerabilities with
severity "CRITICAL" or higher (as understood by Github Security Advisory).
The minimum severity can be configured using the option `--min-severity` or
by setting `min_severity` in the config file (if both are set, their common
minimum will be used).

```bash
>security-constraints --min-severity high
```

## Contributing
Pull requests as well as new issues are welcome.

[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)
[![CI](https://github.com/mam-dev/security-constraints/actions/workflows/ci.yaml/badge.svg?branch=main)](https://github.com/mam-dev/security-constraints/actions/workflows/ci.yaml)
