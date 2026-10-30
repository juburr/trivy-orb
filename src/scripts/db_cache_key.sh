#!/bin/bash
#
# Writes the files fetch_db's cache keys are computed from, named
# ${ORB_DB_CACHE_KEY_PREFIX}-<name>. CircleCI never replaces a saved cache,
# so the databases are saved under a key naming the databases themselves:
#
#   location, before the restore: HOME and cache_dir as given, since a cache
#     is restored to the absolute path it was saved from, the working
#     directory when cache_dir is relative to it, the databases fetched and
#     the repositories they come from, so jobs with different databases
#     never trade them;
#   day0, day1 and day2, before the restore: today's date in UTC and the two
#     days before;
#   built and database, after the fetch: the build date of the vulnerability
#     database now in cache_dir, and the build times of both databases and
#     the checks bundle's digest, from trivy version.
#
# The save key is location, built and database, and the restore tries
# today's build date first, then the two days before, then any. CircleCI
# restores the newest cache saved under a prefix, so a job that saves an
# older database late can never outrank a newer one saved earlier. A job
# whose restored databases were current saves nothing, since its key exists.
#
# Parameters arrive as ORB_DB_CACHE_KEY_PART (location or database),
# ORB_DB_CACHE_KEY_PREFIX, and fetch_db's PARAM_ variables.

set -euo pipefail

if [[ -z "${SCRIPT_TRIVY_LIB:-}" ]]; then
    echo "ERROR: SCRIPT_TRIVY_LIB is not set; run this script through the orb's fetch_db command." >&2
    exit 1
fi
eval "${SCRIPT_TRIVY_LIB}"

prefix=${ORB_DB_CACHE_KEY_PREFIX}
tmps=()
trap 'rm -f ${tmps[@]+"${tmps[@]}"}' EXIT

# write_key NAME CONTENT: writes CONTENT and a newline to ${prefix}-NAME. The
# file is written under a new name and renamed into place, so a file or
# symlink someone else left at its name in a shared /tmp is never written
# through. mv would move it into a directory, so that is refused.
write_key() {
    local file="${prefix}-$1" tmp
    tmp=$(mktemp "${file}.XXXXXX")
    tmps+=("${tmp}")
    printf '%s\n' "$2" > "${tmp}"
    if [[ -d "${file}" ]] || ! mv -f "${tmp}" "${file}"; then
        echo "ERROR: Could not write ${file}." >&2
        exit 1
    fi
}

case "${ORB_DB_CACHE_KEY_PART}" in
    location)
        # cache_dir as given: the cache steps expand ~ but not environment
        # variables, so the raw value names the directory they save. A
        # relative one is saved from the working directory.
        dir=${PARAM_CACHE_DIR:-}
        workdir=""
        if [[ -n "${dir}" && "${dir}" != /* && "${dir}" != \~ && "${dir}" != \~/* ]]; then
            workdir=${PWD}
        fi
        java=$(tv_bool java_db "${PARAM_JAVA_DB:-false}")
        checks=$(tv_bool checks_bundle "${PARAM_CHECKS_BUNDLE:-false}")
        write_key location "$(printf '%s\n' "${HOME:-}" "${dir}" "${workdir}" "trivy-db:2 java:${java} checks:${checks}" \
            "$(tv_subst "${PARAM_DB_REPOSITORY:-}")" "$(tv_subst "${PARAM_JAVA_DB_REPOSITORY:-}")" \
            "$(tv_subst "${PARAM_CHECKS_BUNDLE_REPOSITORY:-}")")"
        now=$(date -u +%s)
        for day in 0 1 2; do
            write_key "day${day}" "$(date -u -d "@$((now - day * 86400))" +%Y-%m-%d)"
        done
        echo "Database cache location: ${dir}${workdir:+ in ${workdir}} (Java database: ${java}, checks bundle: ${checks})."
        ;;
    database)
        identity=""
        if command -v trivy > /dev/null 2>&1 && command -v jq > /dev/null 2>&1; then
            tv_trivy
            tv_cache_dir "${PARAM_CACHE_DIR:-}"
            if metadata=$(tv_bare "${TV_TRIVY}" version --format json --cache-dir "${TV_CACHE_DIR}" 2> /dev/null); then
                # shellcheck disable=SC2016 # jq program, not shell
                identity=$(jq -r 'select(.VulnerabilityDB.UpdatedAt) | "vulnerability database \(.VulnerabilityDB.UpdatedAt)",
                    "Java database \(.JavaDB.UpdatedAt // "none")", "checks bundle \(.CheckBundle.Digest // "none")"' \
                    <<< "${metadata}" 2> /dev/null || true)
            fi
        fi
        built=$(printf '%s\n' "${identity}" | awk '/^vulnerability database / { print substr($3, 1, 10); exit }')
        if [[ -z "${identity}" ]]; then
            identity="date $(date -u +%Y-%m-%d)"
            echo "WARN: trivy version named no vulnerability database; keying the cache by today's date instead." >&2
        fi
        if [[ ! "${built}" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}$ ]]; then
            built=$(date -u +%Y-%m-%d)
        fi
        write_key built "${built}"
        write_key database "${identity}"
        echo "Database cache key names the databases built on ${built}:"
        printf '%s\n' "${identity}" | sed 's/^/  /'
        ;;
    *)
        echo "ERROR: ORB_DB_CACHE_KEY_PART must be location or database, got '${ORB_DB_CACHE_KEY_PART}'." >&2
        exit 1
        ;;
esac
