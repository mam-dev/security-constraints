#!/usr/bin/env bash

echo "Preparing system test..."
THIS_DIR="$(dirname "$0")"
pushd "${THIS_DIR}" &> /dev/null || exit 1
VENV=$(mktemp --directory)
python -m venv "${VENV}"
. "${VENV}/bin/activate"
"${VENV}/bin/python3" -m pip install --quiet --upgrade pip
"${VENV}/bin/python3" -m pip install --quiet --editable "$(git rev-parse --show-toplevel)" || exit 1
OUTPUT_FILE=$(mktemp)

echo "Executing system test..."
security-constraints --config="sc-conf.yaml" --output="${OUTPUT_FILE}"  || exit 1

echo "Verifying that ID from config was ignored..."
test -z "$(grep --files-with-match "(ID: GHSA-8r8j-xvfj-3fff6f9)" "${OUTPUT_FILE}" )" || exit 1
echo "Verifying that pip install works with the output file..."
"${VENV}/bin/python3" -m pip install --quiet --dry-run ymlref --constraint="${OUTPUT_FILE}" || exit 1

popd &> /dev/null || exit 1

echo "System test passed!"
