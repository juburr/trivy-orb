#!/bin/bash
#
# Logs in to a registry for the login command, with trivy registry login,
# which checks the credentials with the registry and stores them where Docker
# does (~/.docker/config.json, or $DOCKER_CONFIG/config.json), so later scans
# of the registry's images, and docker, crane or oras, use them too.

set -euo pipefail
# A job can turn xtrace on for every step (SHELLOPTS, or set -x in $BASH_ENV), and it would print the password.
set +o xtrace

if [[ -z "${SCRIPT_TRIVY_LIB:-}" ]]; then
    echo "ERROR: SCRIPT_TRIVY_LIB is not set; run this script through the orb's login command." >&2
    exit 1
fi
eval "${SCRIPT_TRIVY_LIB}"

REGISTRY=$(tv_subst "${PARAM_REGISTRY}")
tv_env_var_name username "${PARAM_USERNAME}"
tv_env_var_name password "${PARAM_PASSWORD}"
USERNAME=${!PARAM_USERNAME:-}
PASSWORD=${!PARAM_PASSWORD:-}

# Removes the credentials from this shell when the step ends, whatever its
# outcome.
cleanup_secrets() {
    unset PASSWORD USERNAME
}
trap cleanup_secrets EXIT

if [[ -z "${REGISTRY}" ]]; then
    echo "ERROR: registry is required, such as ghcr.io or localhost:5000." >&2
    exit 1
fi
if ! tv_match "${REGISTRY}" '^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?(:[0-9]{1,5})?$'; then
    echo "ERROR: registry must be a host with an optional port, such as ghcr.io or localhost:5000, not '${REGISTRY}'." >&2
    exit 1
fi
if [[ -z "${USERNAME}" ]]; then
    echo "ERROR: The ${PARAM_USERNAME} environment variable, which username names, is empty or unset." >&2
    echo "  Set it from a secret (a CircleCI context or project variable, or a GitHub Actions secret in the step's env)," >&2
    echo "  or pass the name of another variable as username." >&2
    exit 1
fi
if [[ -z "${PASSWORD}" ]]; then
    echo "ERROR: The ${PARAM_PASSWORD} environment variable, which password names, is empty or unset." >&2
    echo "  Set it from a secret (a CircleCI context or project variable, or a GitHub Actions secret in the step's env)," >&2
    echo "  or pass the name of another variable as password." >&2
    exit 1
fi
# Trivy reads --username as a CSV record, so a comma or a double quote would
# split it or change it.
if [[ "${USERNAME}" == *[,\"]* || "${USERNAME}" == *$'\n'* ]]; then
    echo "ERROR: The username in ${PARAM_USERNAME} holds a comma, a double quote or a newline, which trivy can't take." >&2
    exit 1
fi
tv_trivy

echo "Logging in to ${REGISTRY} with trivy..."
echo "  Username: from ${PARAM_USERNAME}"
echo "  Password: from ${PARAM_PASSWORD}"

# The password goes on stdin, never on the command line. printf, not echo:
# echo would take a password of -n or -e as its own option. Trivy reads a
# TRIVY_PASSWORD in the job's environment as --password, which it refuses
# alongside --password-stdin, so the job's credentials variables are left out.
if ! printf '%s\n' "${PASSWORD}" | env -u TRIVY_USERNAME -u TRIVY_PASSWORD -u TRIVY_PASSWORD_STDIN -u TRIVY_REGISTRY_TOKEN \
    "${TV_TRIVY}" registry login --username "${USERNAME}" --password-stdin -- "${REGISTRY}"; then
    echo "ERROR: trivy could not log in to ${REGISTRY}. Its error is above: check the credentials, and that the registry is reachable." >&2
    exit 1
fi
