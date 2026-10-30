#!/bin/bash
#
# Scans with Trivy for the scan command: an image, a directory, a root
# filesystem, a repository, infrastructure as code or an SBOM. Trivy writes
# one JSON report; the gate, the JUnit file and the run record are read from
# it, and the other formats are rendered from it with trivy convert, so every
# report describes the same scan.
#
# Findings at or above fail_on fail the step unless report_only is true. A
# scan that can't complete, a stale vulnerability database, and a scan that
# found nothing to check fail it either way.

set -euo pipefail

if [[ -z "${SCRIPT_TRIVY_LIB:-}" ]]; then
    echo "ERROR: SCRIPT_TRIVY_LIB is not set; run this script through the orb's scan command." >&2
    exit 1
fi
eval "${SCRIPT_TRIVY_LIB}"

STARTED=$(date -u +%Y-%m-%dT%H:%M:%SZ)
TARGET_TYPE=$(tv_subst "${PARAM_TARGET_TYPE}")
TARGET=$(tv_subst "${PARAM_TARGET}")
INPUT=$(tv_subst "${PARAM_INPUT}")
SEVERITY=$(tv_subst "${PARAM_SEVERITY}")
FAIL_ON=$(tv_subst "${PARAM_FAIL_ON}")
FAIL_ON_EOL=$(tv_bool fail_on_eol "${PARAM_FAIL_ON_EOL}")
IGNORE_UNFIXED=$(tv_bool ignore_unfixed "${PARAM_IGNORE_UNFIXED}")
IGNORE_FILE=$(tv_subst "${PARAM_IGNORE_FILE}")
PKG_TYPES=$(tv_subst "${PARAM_PKG_TYPES}")
IMAGE_SRC=$(tv_subst "${PARAM_IMAGE_SRC}")
PLATFORM=$(tv_subst "${PARAM_PLATFORM}")
OFFLINE=$(tv_bool offline "${PARAM_OFFLINE}")
ALLOW_EMPTY=$(tv_bool allow_empty "${PARAM_ALLOW_EMPTY}")
TIMEOUT=$(tv_subst "${PARAM_TIMEOUT}")
MAX_DB_AGE_DAYS=$(tv_subst "${PARAM_MAX_DB_AGE_DAYS}")
REPORT_NAME=$(tv_subst "${PARAM_REPORT_NAME}")
JUNIT=$(tv_bool junit "${PARAM_JUNIT}")
RUN_RECORD=$(tv_bool run_record "${PARAM_RUN_RECORD}")
REPORT_ONLY=$(tv_bool report_only "${PARAM_REPORT_ONLY}")
tv_list scanners "${PARAM_SCANNERS}"
SCANNERS=(${TV_LIST[@]+"${TV_LIST[@]}"})
tv_list vex "${PARAM_VEX}"
VEX=(${TV_LIST[@]+"${TV_LIST[@]}"})
tv_list skip_dirs "${PARAM_SKIP_DIRS}"
SKIP_DIRS=(${TV_LIST[@]+"${TV_LIST[@]}"})
tv_list skip_files "${PARAM_SKIP_FILES}"
SKIP_FILES=(${TV_LIST[@]+"${TV_LIST[@]}"})
tv_list formats "${PARAM_FORMATS}"
FORMATS=(${TV_LIST[@]+"${TV_LIST[@]}"})
tv_words extra_args "$(tv_subst "${PARAM_EXTRA_ARGS}")"
EXTRA_ARGS=(${TV_WORDS[@]+"${TV_WORDS[@]}"})

# usage MESSAGE...: stops the step on a parameter that can't work, before
# anything runs.
usage() {
    printf 'ERROR: %s\n' "$1" >&2
    if [[ $# -gt 1 ]]; then
        printf '  %s\n' "${@:2}" >&2
    fi
    exit 2
}

# --- What to scan ---
# A leading ~ in a path is the home directory, as in the shell. An image
# reference never starts with one.
for name in TARGET INPUT; do
    if [[ "${!name}" == \~ || "${!name}" == \~/* ]] && [[ "${name}" == INPUT || "${TARGET_TYPE}" != image ]]; then
        printf -v "${name}" '%s' "${HOME:-}${!name:1}"
    fi
done
case "${TARGET_TYPE}" in
    image | filesystem | rootfs | repository | config | sbom) ;;
    *) usage "target_type must be image, filesystem, rootfs, repository, config or sbom, not '${TARGET_TYPE}'." ;;
esac
if [[ "${TARGET}" == *$'\n'* || "${INPUT}" == *$'\n'* ]]; then
    usage "target and input must be one line."
fi
if [[ -n "${INPUT}" ]]; then
    if [[ "${TARGET_TYPE}" != image ]]; then
        usage "input is an image archive or OCI layout to scan, so it needs target_type: image."
    fi
    if [[ -n "${TARGET}" ]]; then
        usage "Give target (an image reference) or input (an image archive or OCI layout), not both."
    fi
    if [[ ! -e "${INPUT%[:@]*}" && ! -e "${INPUT}" ]]; then
        usage "input names no file or directory: '${INPUT}'."
    fi
elif [[ -z "${TARGET}" ]]; then
    case "${TARGET_TYPE}" in
        image) usage "target is required: the image to scan, such as ghcr.io/org/app:1.0, or set input to an image archive." ;;
        repository) usage "target is required: the repository to scan, a directory or a URL." ;;
        sbom) usage "target is required: the SBOM file to scan." ;;
        *) usage "target is required: the directory to scan, such as \".\"." ;;
    esac
fi
if [[ "${TARGET_TYPE}" == image ]]; then
    if [[ -n "${IMAGE_SRC}" ]] && ! tv_match "${IMAGE_SRC}" '^(docker|containerd|podman|remote)(,(docker|containerd|podman|remote))*$'; then
        usage "image_src must be a comma-separated list of docker, containerd, podman and remote, not '${IMAGE_SRC}'."
    fi
elif [[ -n "${IMAGE_SRC}" || -n "${PLATFORM}" ]]; then
    usage "image_src and platform apply to images, so they need target_type: image."
fi

# --- What to look for ---
VALID_SCANNERS="vuln misconfig secret license"
if [[ "${TARGET_TYPE}" == sbom ]]; then
    VALID_SCANNERS="vuln license"
fi
if [[ "${TARGET_TYPE}" == config ]]; then
    for name in scanners:"${SCANNERS[*]-}" vex:"${VEX[*]-}" pkg_types:"${PKG_TYPES}"; do
        if [[ -n "${name#*:}" ]]; then
            usage "${name%%:*} doesn't apply to target_type: config, which checks infrastructure as code for misconfigurations only."
        fi
    done
    if [[ "${IGNORE_UNFIXED}" == true ]]; then
        usage "ignore_unfixed doesn't apply to target_type: config, which checks for misconfigurations only."
    fi
fi
for scanner in ${SCANNERS[@]+"${SCANNERS[@]}"}; do
    if [[ " ${VALID_SCANNERS} " != *" ${scanner} "* ]]; then
        usage "scanners can be ${VALID_SCANNERS// /, } for target_type: ${TARGET_TYPE}, not '${scanner}'."
    fi
done
# Trivy scans for vulnerabilities and secrets by default, but config for
# misconfigurations only, and sbom for vulnerabilities only.
if [[ "${#SCANNERS[@]}" -gt 0 ]]; then
    ENABLED=" ${SCANNERS[*]} "
else
    case "${TARGET_TYPE}" in
        config) ENABLED=" misconfig " ;;
        sbom) ENABLED=" vuln " ;;
        *) ENABLED=" vuln secret " ;;
    esac
fi
if [[ -n "${PKG_TYPES}" ]] && ! tv_match "${PKG_TYPES}" '^(os|library)(,(os|library))?$'; then
    usage "pkg_types must be os, library, or both separated by a comma, not '${PKG_TYPES}'."
fi
if [[ "${TARGET_TYPE}" == sbom && $((${#SKIP_DIRS[@]} + ${#SKIP_FILES[@]})) -gt 0 ]]; then
    usage "skip_dirs and skip_files don't apply to target_type: sbom."
fi

# --- What counts ---
FAIL_ON=$(printf '%s' "${FAIL_ON}" | tr '[:upper:]' '[:lower:]')
case "${FAIL_ON}" in
    critical | high | medium | low | unknown) ;;
    *) usage "fail_on must be critical, high, medium, low or unknown, not '${FAIL_ON}'." ;;
esac
FAIL_RANK=$(tv_rank "${FAIL_ON}")
FAIL_LABEL=$(printf '%s' "${FAIL_ON}" | tr '[:lower:]' '[:upper:]')
if [[ -n "${SEVERITY}" ]]; then
    SEVERITY=$(printf '%s' "${SEVERITY}" | tr '[:lower:]' '[:upper:]' | tr -d ' ')
    if ! tv_match "${SEVERITY}" '^(UNKNOWN|LOW|MEDIUM|HIGH|CRITICAL)(,(UNKNOWN|LOW|MEDIUM|HIGH|CRITICAL))*$'; then
        usage "severity must be a comma-separated list of UNKNOWN, LOW, MEDIUM, HIGH and CRITICAL, not '${SEVERITY}'."
    fi
fi
tv_uint max_db_age_days "${MAX_DB_AGE_DAYS}"
if [[ -n "${TIMEOUT}" ]] && ! tv_match "${TIMEOUT}" '^([0-9]+(\.[0-9]+)?(ns|us|ms|s|m|h))+$'; then
    usage "timeout must be a duration such as 10m or 1h30m, not '${TIMEOUT}'."
fi
if [[ -z "${IGNORE_FILE}" && -z "${TRIVY_IGNOREFILE:-}" && ! -e .trivyignore && -f .trivyignore.yaml ]]; then
    # Trivy reads .trivyignore by default, but never .trivyignore.yaml.
    IGNORE_FILE=.trivyignore.yaml
    echo "Using the ignore file .trivyignore.yaml, since there is no .trivyignore."
fi
if [[ -n "${IGNORE_FILE}" && ! -f "${IGNORE_FILE}" ]]; then
    usage "ignore_file names no file: '${IGNORE_FILE}'."
fi
for document in ${VEX[@]+"${VEX[@]}"}; do
    case "${document}" in
        repo | repository | oci | sbom-ref) ;;
        *)
            if [[ ! -f "${document}" ]]; then
                usage "vex names no file: '${document}'. Give VEX documents, or repo, oci or sbom-ref."
            fi
            ;;
    esac
done

# --- Reports ---
for format in ${FORMATS[@]+"${FORMATS[@]}"}; do
    case "${format}" in
        json | sarif | table | cyclonedx | spdx-json | github) ;;
        *) usage "formats can be json, sarif, table, cyclonedx, spdx-json and github, not '${format}'." ;;
    esac
done
has_format() {
    [[ " ${FORMATS[*]-} " == *" $1 "* ]]
}
# Options the command sets itself, and those that would change how the
# reports are written.
for word in ${EXTRA_ARGS[@]+"${EXTRA_ARGS[@]}"}; do
    name=${word%%=*}
    case "${name}" in
        --format | --output | --exit-code | --exit-on-eol | --cache-dir | --list-all-pkgs | --template | --report \
            | --download-db-only | --download-java-db-only | --output-plugin-arg | --show-suppressed | --)
            usage "extra_args can't hold ${name}: the scan command sets it, or it would change the reports it reads." ;;
        -f* | -o* | -t*)
            if [[ "${name}" != --* ]]; then
                usage "extra_args can't hold ${word}: the scan command sets the format, output and template itself."
            fi
            ;;
    esac
done
tv_require_jq
tv_output "${PARAM_OUTPUT_DIR}" "${REPORT_NAME}"
tv_trivy
tv_cache_dir "${PARAM_CACHE_DIR}"

TV_WORK=$(mktemp -d)
trap 'rm -rf "${TV_WORK}"' EXIT

# An earlier scan's reports, which would otherwise be stored with this one's.
rm -f "${TV_BASE}.json" "${TV_BASE}.sarif" "${TV_BASE}.txt" "${TV_BASE}.cdx.json" "${TV_BASE}.spdx.json" \
    "${TV_BASE}.github.json" "${TV_BASE}.run-record.json" "${TV_OUT}/junit/${REPORT_NAME}.xml"

# --- The command line ---
# TV_ARGS holds what decides what is scanned, for the log and the run record;
# the reporting options follow it.
TV_ARGS=("${TARGET_TYPE}")
NOT_CONFIG=false
if [[ "${TARGET_TYPE}" != config ]]; then
    NOT_CONFIG=true
fi
if [[ "${#SCANNERS[@]}" -gt 0 ]]; then
    TV_ARGS+=("--scanners=$(IFS=,; printf '%s' "${SCANNERS[*]}")")
fi
if [[ -n "${SEVERITY}" ]]; then
    TV_ARGS+=("--severity=${SEVERITY}")
fi
if [[ "${IGNORE_UNFIXED}" == true ]]; then
    TV_ARGS+=(--ignore-unfixed)
fi
if [[ -n "${IGNORE_FILE}" ]]; then
    TV_ARGS+=("--ignorefile=${IGNORE_FILE}")
fi
for document in ${VEX[@]+"${VEX[@]}"}; do
    TV_ARGS+=("--vex=${document}")
done
if [[ -n "${PKG_TYPES}" ]]; then
    TV_ARGS+=("--pkg-types=${PKG_TYPES}")
fi
for dir in ${SKIP_DIRS[@]+"${SKIP_DIRS[@]}"}; do
    TV_ARGS+=("--skip-dirs=${dir}")
done
for file in ${SKIP_FILES[@]+"${SKIP_FILES[@]}"}; do
    TV_ARGS+=("--skip-files=${file}")
done
if [[ -n "${IMAGE_SRC}" ]]; then
    TV_ARGS+=("--image-src=${IMAGE_SRC}")
fi
if [[ -n "${PLATFORM}" ]]; then
    TV_ARGS+=("--platform=${PLATFORM}")
fi
if [[ -n "${INPUT}" ]]; then
    TV_ARGS+=("--input=${INPUT}")
fi
if [[ -n "${TIMEOUT}" ]]; then
    TV_ARGS+=("--timeout=${TIMEOUT}")
fi
# Updates are skipped for what fetch_db fetched into this cache directory in
# this job, so parallel scans never download over each other, and for
# everything when offline.
SKIP_DB=false
SKIP_JAVA_DB=false
SKIP_CHECKS=false
if [[ "${OFFLINE}" == true ]]; then
    SKIP_DB=true
    SKIP_JAVA_DB=true
    SKIP_CHECKS=true
else
    [[ "${TRIVY_ORB_DB_DIR:-}" == "${TV_CACHE_DIR}" ]] && SKIP_DB=true
    [[ "${TRIVY_ORB_JAVA_DB_DIR:-}" == "${TV_CACHE_DIR}" ]] && SKIP_JAVA_DB=true
    [[ "${TRIVY_ORB_CHECKS_DIR:-}" == "${TV_CACHE_DIR}" ]] && SKIP_CHECKS=true
fi
if [[ "${NOT_CONFIG}" == true ]]; then
    [[ "${SKIP_DB}" == true ]] && TV_ARGS+=(--skip-db-update)
    [[ "${SKIP_JAVA_DB}" == true ]] && TV_ARGS+=(--skip-java-db-update)
    [[ "${OFFLINE}" == true ]] && TV_ARGS+=(--offline-scan)
fi
if [[ "${TARGET_TYPE}" != sbom && "${SKIP_CHECKS}" == true ]]; then
    TV_ARGS+=(--skip-check-update)
fi
TV_ARGS+=(${EXTRA_ARGS[@]+"${EXTRA_ARGS[@]}"})

REPORT="${TV_WORK}/report.json"
COMMAND=("${TV_TRIVY}" "${TV_ARGS[@]}" --cache-dir "${TV_CACHE_DIR}" --format json --output "${REPORT}" --exit-code 0
    --skip-version-check --disable-telemetry)
if [[ "${NOT_CONFIG}" == true ]]; then
    COMMAND+=(--list-all-pkgs --show-suppressed --no-progress)
fi
if [[ -n "${TARGET}" ]]; then
    COMMAND+=(-- "${TARGET}")
fi

# TV_TARGET_JSON: what was asked for, then what Trivy says it scanned.
TV_TARGET_JSON=$(jq -cn --arg type "${TARGET_TYPE}" --arg target "${TARGET}" --arg input "${INPUT}" \
    '{type: $type, target: (if $target == "" then null else $target end), input: (if $input == "" then null else $input end)}')
# shellcheck disable=SC2034 # read by tv_run_record
TV_GATE_JSON=$(jq -cn --arg fail_on "${FAIL_LABEL}" --argjson report_only "${REPORT_ONLY}" --argjson eol "${FAIL_ON_EOL}" \
    --argjson allow_empty "${ALLOW_EMPTY}" --argjson max_age "${MAX_DB_AGE_DAYS}" \
    '{fail_on: $fail_on, fail_on_eol: $eol, report_only: $report_only, allow_empty: $allow_empty, max_db_age_days: $max_age}')
TV_REPORTS=()
TV_COUNTS=null
# shellcheck disable=SC2034 # read by tv_run_record, until tv_db_metadata sets it
TV_DB_JSON=null

# error MESSAGE...: the scan has no verdict. Writes the run record, then
# fails the step.
error() {
    printf 'ERROR: %s\n' "$1" >&2
    if [[ $# -gt 1 ]]; then
        printf '  %s\n' "${@:2}" >&2
    fi
    if [[ "${RUN_RECORD}" == true ]]; then
        TV_REPORTS+=("${TV_BASE}.run-record.json")
        tv_run_record "${TV_BASE}.run-record.json" scan error 1 "${STARTED}"
    fi
    exit 1
}

printf 'Running: trivy'
printf ' %q' "${COMMAND[@]:1}"
printf '\n'
STATUS=0
"${COMMAND[@]}" 2>&1 | tee "${TV_WORK}/trivy.log" || STATUS=$?
if [[ "${STATUS}" -ne 0 ]]; then
    error "Trivy could not complete the scan (exit code ${STATUS}), so there is no verdict. Its log is above."
fi
if ! tv_json_is "${REPORT}" '.SchemaVersion == 2'; then
    error "Trivy wrote no JSON report this command can read (SchemaVersion 2)."
fi
TV_TARGET_JSON=$(jq -c --slurpfile r "${REPORT}" '. + {
        artifact_name: ($r[0].ArtifactName // null), artifact_type: ($r[0].ArtifactType // null),
        artifact_id: (if ($r[0].ArtifactID // "") == "" then null else $r[0].ArtifactID end),
        repo_digests: ($r[0].Metadata.RepoDigests // []), os: ($r[0].Metadata.OS // null)}' <<< "${TV_TARGET_JSON}")
ARTIFACT=$(jq -r '.ArtifactName // ""' "${REPORT}")
ARTIFACT=${ARTIFACT:-${TARGET:-${INPUT}}}

# --- The databases it used ---
tv_db_metadata
if [[ "${ENABLED}" == *" vuln "* ]] && ! tv_db_fresh "${MAX_DB_AGE_DAYS}"; then
    error "The vulnerability database Trivy scanned with is not fresh enough to trust its result."
fi
if [[ "${ENABLED}" == *" misconfig "* ]] && grep -q 'Falling back to embedded checks' "${TV_WORK}/trivy.log"; then
    echo "WARN: Trivy couldn't use its checks bundle and checked misconfigurations with the checks built into trivy ${TV_TRIVY_VERSION}." >&2
fi

# --- The verdict ---
FINDINGS=$(jq -c "${TV_FINDINGS_JQ}" "${REPORT}")
TV_COUNTS=$(tv_counts "${FINDINGS}" "${FAIL_RANK}" "${REPORT}")
count() {
    jq -r "$1" <<< "${TV_COUNTS}"
}
if [[ "${ALLOW_EMPTY}" != true ]]; then
    if [[ "${ENABLED}" == *" vuln "* && "$(count '.packages')" -eq 0 && "$(count '.os == null')" == true ]]; then
        error "Trivy found no packages to check for vulnerabilities in ${ARTIFACT}, so the scan checked nothing." \
            "An image scan reads OS packages and installed artifacts; a filesystem or repository scan reads lockfiles" \
            "such as package-lock.json or go.mod. Check target and target_type, or set allow_empty to true."
    fi
    if [[ "${ENABLED}" == " misconfig " && "$(count '.misconfiguration_checks')" -eq 0 && "$(count '.findings')" -eq 0 ]]; then
        error "Trivy found no infrastructure as code to check for misconfigurations in ${ARTIFACT}, so the scan checked nothing." \
            "Check target, or set allow_empty to true."
    fi
fi
EOL=false
if [[ "$(count '.os.EOSL == true')" == true ]]; then
    EOL=true
    OS_NAME=$(count '"\(.os.Family) \(.os.Name)"')
    if [[ "${FAIL_ON_EOL}" == true ]]; then
        echo "ERROR: ${OS_NAME} is end of life, and gets no more security fixes (fail_on_eol is true)." >&2
    else
        echo "WARN: ${OS_NAME} is end of life, and gets no more security fixes, so new vulnerabilities in it go unreported." >&2
    fi
fi

# --- Reports ---
cp "${REPORT}" "${TV_BASE}.json"
TV_REPORTS+=("${TV_BASE}.json")
for format in ${FORMATS[@]+"${FORMATS[@]}"}; do
    case "${format}" in
        json) continue ;;
        sarif) file="${TV_BASE}.sarif" ;;
        table) file="${TV_BASE}.txt" ;;
        cyclonedx) file="${TV_BASE}.cdx.json" ;;
        spdx-json) file="${TV_BASE}.spdx.json" ;;
        github) file="${TV_BASE}.github.json" ;;
    esac
    if ! tv_convert "${REPORT}" "${format}" "${file}"; then
        tv_tail "${TV_WORK}/convert.log" 20
        error "trivy convert could not write the ${format} report."
    fi
    TV_REPORTS+=("${file}")
    if [[ "${format}" == sarif ]]; then
        ARTIFACT_TYPE=$(jq -r '.ArtifactType // ""' "${REPORT}")
        if [[ ("${ARTIFACT_TYPE}" == filesystem || "${ARTIFACT_TYPE}" == repository) && -d "${TARGET}" ]]; then
            tv_sarif_root "${file}" "file://$(cd "${TARGET}" && pwd)/"
        fi
    fi
done
if [[ "${JUNIT}" == true ]]; then
    tv_findings_junit "${TV_OUT}/junit/${REPORT_NAME}.xml" "trivy ${TARGET_TYPE} ${ARTIFACT}" "${FINDINGS}" "${FAIL_RANK}"
    TV_REPORTS+=("${TV_OUT}/junit/${REPORT_NAME}.xml")
fi
if has_format table; then
    cat "${TV_BASE}.txt"
fi

# --- Summary and gate ---
FAILING=$(count '.failing')
SUMMARY=$(jq -r --arg label "${FAIL_LABEL}" '
    def n($c): ([.[$c][]?] | add // 0);
    "\(.findings) finding(s): \(n("vulnerabilities")) vulnerabilities, \(n("misconfigurations")) misconfigurations,"
    + " \(n("secrets")) secrets and \(n("licenses")) licenses; \(.failing) at or above \($label)"
    + (if .suppressed > 0 then "; \(.suppressed) suppressed by ignore files or VEX" else "" end)
    + "; \(.packages) packages checked"' <<< "${TV_COUNTS}")
echo "Trivy scanned ${ARTIFACT} (${TARGET_TYPE}): ${SUMMARY}."
if [[ "${FAILING}" -gt 0 ]]; then
    echo "Findings at or above ${FAIL_LABEL}:"
    tv_print_findings "${FINDINGS}" "${FAIL_RANK}"
    if [[ "${FAILING}" -gt 50 ]]; then
        echo "  ... and $((FAILING - 50)) more, in the reports."
    fi
fi
GATE=false
if [[ "${FAILING}" -gt 0 ]] || [[ "${EOL}" == true && "${FAIL_ON_EOL}" == true ]]; then
    GATE=true
fi
if [[ "${RUN_RECORD}" == true ]]; then
    OUTCOME=passed
    if [[ "${GATE}" == true && "${REPORT_ONLY}" == true ]]; then
        OUTCOME=findings-reported
    elif [[ "${GATE}" == true ]]; then
        OUTCOME=findings
    fi
    TV_REPORTS+=("${TV_BASE}.run-record.json")
    tv_run_record "${TV_BASE}.run-record.json" scan "${OUTCOME}" 0 "${STARTED}"
fi
if [[ "${GATE}" == true ]]; then
    REASON="$(tv_plural "${FAILING}" finding findings) at or above ${FAIL_LABEL} in ${ARTIFACT}"
    if [[ "${EOL}" == true && "${FAIL_ON_EOL}" == true ]]; then
        REASON+=", and an end-of-life OS"
    fi
    tv_gate true "${REPORT_ONLY}" "Trivy found ${REASON}."
fi
tv_gate false "${REPORT_ONLY}" "Trivy found nothing at or above ${FAIL_LABEL} in ${ARTIFACT}."
