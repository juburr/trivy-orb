#!/bin/bash
#
# Fetches Trivy's databases into cache_dir for the fetch_db command: the
# vulnerability database, and on request the Java database (for JARs in
# images) and the misconfiguration checks bundle. Trivy downloads each one
# only when the copy there is due for an update, so a cache that fetch_db
# restored is used as it is while it is current.
#
# Exports TRIVY_CACHE_DIR, which every later trivy reads, and TRIVY_ORB_*_DIR,
# which tell scan to skip updating what was fetched here, so scans that run
# in parallel never download over each other. Repositories given here are
# exported too (TRIVY_DB_REPOSITORY, ...), so later scans that do update use
# the same mirror.

set -euo pipefail

if [[ -z "${SCRIPT_TRIVY_LIB:-}" ]]; then
    echo "ERROR: SCRIPT_TRIVY_LIB is not set; run this script through the orb's fetch_db command." >&2
    exit 1
fi
eval "${SCRIPT_TRIVY_LIB}"

JAVA_DB=$(tv_bool java_db "${PARAM_JAVA_DB}")
CHECKS_BUNDLE=$(tv_bool checks_bundle "${PARAM_CHECKS_BUNDLE}")
DB_REPOSITORY=$(tv_subst "${PARAM_DB_REPOSITORY}")
JAVA_DB_REPOSITORY=$(tv_subst "${PARAM_JAVA_DB_REPOSITORY}")
CHECKS_BUNDLE_REPOSITORY=$(tv_subst "${PARAM_CHECKS_BUNDLE_REPOSITORY}")
MAX_DB_AGE_DAYS=$(tv_subst "${PARAM_MAX_DB_AGE_DAYS}")
TIMEOUT=$(tv_subst "${PARAM_TIMEOUT}")

for setting in "db_repository=${DB_REPOSITORY}" "java_db_repository=${JAVA_DB_REPOSITORY}" \
    "checks_bundle_repository=${CHECKS_BUNDLE_REPOSITORY}"; do
    value=${setting#*=}
    # OCI references, such as mirror.example.com/aquasec/trivy-db:2, and for
    # the databases a comma-separated list of them, tried in order.
    if [[ -n "${value}" ]] && ! tv_match "${value}" '^[A-Za-z0-9][A-Za-z0-9._:/@-]*(,[A-Za-z0-9][A-Za-z0-9._:/@-]*)*$'; then
        echo "ERROR: ${setting%%=*} must be OCI references such as mirror.example.com/aquasec/trivy-db:2, separated by commas, not '${value}'." >&2
        exit 2
    fi
done
if [[ "${CHECKS_BUNDLE_REPOSITORY}" == *,* ]]; then
    echo "ERROR: checks_bundle_repository takes one repository: Trivy tries no other for the checks bundle." >&2
    exit 2
fi
tv_uint max_db_age_days "${MAX_DB_AGE_DAYS}"
if [[ -n "${TIMEOUT}" ]] && ! tv_match "${TIMEOUT}" '^([0-9]+(\.[0-9]+)?(ns|us|ms|s|m|h))+$'; then
    echo "ERROR: timeout must be a duration such as 10m or 1h30m, not '${TIMEOUT}'." >&2
    exit 2
fi
tv_require_jq
tv_trivy
tv_cache_dir "${PARAM_CACHE_DIR}"
if ! mkdir -p "${TV_CACHE_DIR}"; then
    echo "ERROR: Could not create cache_dir ${TV_CACHE_DIR}." >&2
    exit 1
fi

TV_WORK=$(mktemp -d)
trap 'rm -rf "${TV_WORK}"' EXIT

TIMEOUT_ARGS=()
if [[ -n "${TIMEOUT}" ]]; then
    TIMEOUT_ARGS=("--timeout=${TIMEOUT}")
fi

# fetch WHAT ARG...: runs trivy ARG... until it succeeds, three times at
# most: a registry that limits the rate of pulls, or fails for a moment,
# often works a little later. A run whose log shows it fell back to the
# checks built into trivy failed to fetch the checks bundle.
fetch() {
    local what=$1 attempt status
    shift
    for attempt in 1 2 3; do
        echo "Fetching the ${what} into ${TV_CACHE_DIR}..."
        printf 'Running: trivy'
        printf ' %q' "$@"
        printf '\n'
        status=0
        "${TV_TRIVY}" "$@" 2>&1 | tee "${TV_WORK}/fetch.log" || status=$?
        if [[ "${status}" -eq 0 ]] && ! grep -q 'Falling back to embedded checks' "${TV_WORK}/fetch.log"; then
            return 0
        fi
        if [[ "${attempt}" -lt 3 ]]; then
            echo "WARN: Fetching the ${what} failed (exit code ${status}). Trying again in $((attempt * 15)) seconds." >&2
            sleep $((attempt * 15))
        fi
    done
    echo "ERROR: Could not fetch the ${what} after 3 attempts. The log of the last one is above." >&2
    return 1
}

DB_ARGS=(--cache-dir "${TV_CACHE_DIR}" --no-progress --scanners vuln ${TIMEOUT_ARGS[@]+"${TIMEOUT_ARGS[@]}"})
if [[ -n "${DB_REPOSITORY}" ]]; then
    DB_ARGS+=("--db-repository=${DB_REPOSITORY}")
fi
fetch "vulnerability database" image --download-db-only "${DB_ARGS[@]}"
if [[ "${JAVA_DB}" == true ]]; then
    DB_ARGS=(--cache-dir "${TV_CACHE_DIR}" --no-progress --scanners vuln ${TIMEOUT_ARGS[@]+"${TIMEOUT_ARGS[@]}"})
    if [[ -n "${JAVA_DB_REPOSITORY}" ]]; then
        DB_ARGS+=("--java-db-repository=${JAVA_DB_REPOSITORY}")
    fi
    fetch "Java database" image --download-java-db-only "${DB_ARGS[@]}"
fi
if [[ "${CHECKS_BUNDLE}" == true ]]; then
    # Trivy has no option to fetch only the checks bundle: a configuration
    # scan of an empty directory fetches it, and checks nothing.
    mkdir "${TV_WORK}/empty"
    CHECKS_ARGS=(--cache-dir "${TV_CACHE_DIR}" --skip-version-check --disable-telemetry --exit-code 0 --format json
        --output "${TV_WORK}/checks.json" ${TIMEOUT_ARGS[@]+"${TIMEOUT_ARGS[@]}"})
    if [[ -n "${CHECKS_BUNDLE_REPOSITORY}" ]]; then
        CHECKS_ARGS+=("--checks-bundle-repository=${CHECKS_BUNDLE_REPOSITORY}")
    fi
    fetch "misconfiguration checks bundle" config "${CHECKS_ARGS[@]}" -- "${TV_WORK}/empty"
fi

tv_db_metadata
if ! tv_db_fresh "${MAX_DB_AGE_DAYS}"; then
    echo "ERROR: The vulnerability database Trivy fetched is too old to use. Check db_repository, or the mirror it names." >&2
    exit 1
fi
if [[ "${JAVA_DB}" == true ]]; then
    if ! tv_json_is /dev/stdin '(.JavaDB.UpdatedAt // "") != ""' <<< "${TV_DB_JSON}"; then
        echo "ERROR: Trivy reported no Java database in ${TV_CACHE_DIR} after fetching it." >&2
        exit 1
    fi
    echo "Java database: built $(jq -r '.JavaDB.UpdatedAt' <<< "${TV_DB_JSON}")."
fi
if [[ "${CHECKS_BUNDLE}" == true ]]; then
    if ! tv_json_is /dev/stdin '(.CheckBundle.Digest // "") != ""' <<< "${TV_DB_JSON}"; then
        echo "ERROR: Trivy reported no checks bundle in ${TV_CACHE_DIR} after fetching it." >&2
        exit 1
    fi
    echo "Checks bundle: $(jq -r '.CheckBundle.Digest' <<< "${TV_DB_JSON}"), fetched $(jq -r '.CheckBundle.DownloadedAt // "unknown"' <<< "${TV_DB_JSON}")."
fi

tv_export TRIVY_CACHE_DIR "${TV_CACHE_DIR}"
tv_export TRIVY_ORB_DB_DIR "${TV_CACHE_DIR}"
if [[ "${JAVA_DB}" == true ]]; then
    tv_export TRIVY_ORB_JAVA_DB_DIR "${TV_CACHE_DIR}"
fi
if [[ "${CHECKS_BUNDLE}" == true ]]; then
    tv_export TRIVY_ORB_CHECKS_DIR "${TV_CACHE_DIR}"
fi
if [[ -n "${DB_REPOSITORY}" ]]; then
    tv_export TRIVY_DB_REPOSITORY "${DB_REPOSITORY}"
fi
if [[ -n "${JAVA_DB_REPOSITORY}" ]]; then
    tv_export TRIVY_JAVA_DB_REPOSITORY "${JAVA_DB_REPOSITORY}"
fi
if [[ -n "${CHECKS_BUNDLE_REPOSITORY}" ]]; then
    tv_export TRIVY_CHECKS_BUNDLE_REPOSITORY "${CHECKS_BUNDLE_REPOSITORY}"
fi
echo "Later steps scan with the databases in ${TV_CACHE_DIR} (TRIVY_CACHE_DIR)."
