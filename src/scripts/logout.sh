#!/bin/bash
#
# Logs out of a registry for the logout command, with trivy registry logout,
# which removes the credentials login stored. It doesn't contact the
# registry.

set -euo pipefail

if [[ -z "${SCRIPT_TRIVY_LIB:-}" ]]; then
    echo "ERROR: SCRIPT_TRIVY_LIB is not set; run this script through the orb's logout command." >&2
    exit 1
fi
eval "${SCRIPT_TRIVY_LIB}"

REGISTRY=$(tv_subst "${PARAM_REGISTRY}")

if [[ -z "${REGISTRY}" ]]; then
    echo "ERROR: registry is required. Pass the same host that login took." >&2
    exit 1
fi
if ! tv_match "${REGISTRY}" '^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?(:[0-9]{1,5})?$'; then
    echo "ERROR: registry must be a host with an optional port, such as ghcr.io or localhost:5000, not '${REGISTRY}'." >&2
    exit 1
fi
tv_trivy

echo "Removing the credentials for ${REGISTRY} with trivy..."
if ! "${TV_TRIVY}" registry logout -- "${REGISTRY}"; then
    echo "ERROR: trivy registry logout failed. Its error is above." >&2
    exit 1
fi
