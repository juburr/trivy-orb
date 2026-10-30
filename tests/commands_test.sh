#!/usr/bin/env bash
#
# Tests the command scripts offline, each run by tests/run_command.sh with its
# parameters' defaults from the command's YAML, against a stand-in trivy that
# records every call (arguments, working directory and TRIVY_* variables),
# writes a fixture report from tests/fixtures/reports for a scan, database
# metadata for a fetch, and minimal SARIF, table and SBOM files for convert:
#
#   scan
#     - the arguments for every target type, with only the flags each Trivy
#       command takes, the reporting options last and the target after --
#     - the gate: findings at or above fail_on fail the step, report_only
#       reports them, findings below are skipped JUnit cases
#     - a scan that can't complete, a stale or missing vulnerability database,
#       and one that checked nothing fail it whatever report_only says
#     - updates are skipped for what fetch_db fetched, and offline skips all
#     - every format is rendered by trivy convert in an empty directory
#       without the job's TRIVY_* variables, and SARIF's ROOTPATH names the
#       scanned directory
#     - the run record, an end-of-life OS, ignore files, and every input
#       check failing before trivy runs
#   fetch_db: the downloads, retries, staleness, and the exports
#   db_cache_key.sh: the cache key files
#   login and logout: the password only on stdin, and the job's TRIVY_*
#     credentials kept from trivy
#
# The scripts run with the bash first on the PATH, so putting an older bash
# there checks it. A stand-in circleci CLI expands $ORB_TEST_VAR.
#
# Run from a checkout:
#   bash <this file>

set -uo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
until [[ -f "${ROOT}/src/@orb.yml" ]]; do
    if [[ "${ROOT}" == "/" ]]; then
        echo "FAIL: no src/@orb.yml above ${BASH_SOURCE[0]}"
        exit 1
    fi
    ROOT=$(dirname "${ROOT}")
done
FIXTURES="${ROOT}/tests/fixtures/reports"

WORK=$(mktemp -d)
trap 'rm -rf "${WORK}"' EXIT
STUB="${WORK}/stub"
HOME_DIR="${WORK}/home"
JOB="${WORK}/job"
OUT="${WORK}/reports"
mkdir -p "${WORK}/bin" "${STUB}/calls" "${HOME_DIR}" "${JOB}"

# Like `circleci env subst`, expands $NAME and ${NAME} references, from stdin.
cat > "${WORK}/bin/circleci" << 'EOF'
#!/usr/bin/env bash
if [[ "$*" != "env subst" ]]; then
    echo "circleci stub: expected 'env subst' with the value on stdin, got: $*" >&2
    exit 1
fi
input=$(cat)
output=""
re='^([^$]*)\$(\{([A-Za-z_][A-Za-z0-9_]*)\}|([A-Za-z_][A-Za-z0-9_]*))(.*)$'
while [[ "${input}" =~ ${re} ]]; do
    name=${BASH_REMATCH[3]:-${BASH_REMATCH[4]}}
    output+="${BASH_REMATCH[1]}${!name-}"
    input=${BASH_REMATCH[5]}
done
printf '%s' "${output}${input}"
EOF
# Retries wait without delaying the tests.
printf '#!/bin/sh\nexit 0\n' > "${WORK}/bin/sleep"

# The stand-in trivy. Settings:
#   STUB_REPORT        the report a scan writes (default clean.json)
#   STUB_SCAN_EXIT     a scan's exit code, after a FATAL line
#   STUB_LOG_LINE      a line a scan or a fetch logs
#   STUB_DB_AGE_DAYS   how old a fetched vulnerability database is
#   STUB_FETCH_FAILS   how many fetches fail before one works
#   STUB_CONVERT_EXIT  convert's exit code
#   STUB_LOGIN_EXIT    registry login's exit code
cat > "${WORK}/bin/trivy" << 'EOF'
#!/usr/bin/env bash
# A job's SHELLOPTS reaches this script, as the real trivy isn't one.
set +o errexit +o nounset +o pipefail +o xtrace
calls="${STUB_DIR}/calls"
n=$(($(find "${calls}" -name '*.args' | wc -l) + 1))
printf '%s\n' "$@" > "${calls}/${n}.args"
{ printf 'cwd=%s\n' "${PWD}"; env | grep '^TRIVY_' | sort; } > "${calls}/${n}.meta"
args=("$@")
# opt NAME: the value of --NAME VALUE or --NAME=VALUE.
opt() {
    local i
    for ((i = 0; i < ${#args[@]}; i++)); do
        case "${args[i]}" in
            "--$1") printf '%s\n' "${args[i + 1]}"; return 0 ;;
            "--$1="*) printf '%s\n' "${args[i]#*=}"; return 0 ;;
        esac
    done
    return 1
}
has() { [[ " ${args[*]} " == *" $1 "* ]]; }
# The positional arguments after --.
positional() {
    local i seen=false
    for ((i = 0; i < ${#args[@]}; i++)); do
        if [[ "${seen}" == true ]]; then printf '%s\n' "${args[i]}"; fi
        [[ "${args[i]}" == -- ]] && seen=true
    done
}
stamp() { date -u -d "@$(($(date -u +%s) - $1))" +%Y-%m-%dT%H:%M:%S.123456789Z; }
cache=$(opt cache-dir || true)
case "$1" in
    --version)
        echo "Version: ${STUB_VERSION:-0.76.1}"
        exit 0
        ;;
    version)
        jq -cn --arg v "${STUB_VERSION:-0.76.1}" \
            --slurpfile db <(cat "${cache}/db/metadata.json" 2> /dev/null || echo null) \
            --slurpfile java <(cat "${cache}/java-db/metadata.json" 2> /dev/null || echo null) \
            --slurpfile checks <(cat "${cache}/policy/metadata.json" 2> /dev/null || echo null) \
            '{Version: $v} + (if $db[0] then {VulnerabilityDB: $db[0]} else {} end)
             + (if $java[0] then {JavaDB: $java[0]} else {} end) + (if $checks[0] then {CheckBundle: $checks[0]} else {} end)'
        exit 0
        ;;
    convert)
        [[ -n "${STUB_CONVERT_EXIT:-}" ]] && { echo "FATAL convert failed" >&2; exit "${STUB_CONVERT_EXIT}"; }
        report=$(positional | tail -n 1)
        out=$(opt output)
        case "$(opt format)" in
            sarif) jq -n --arg r "${report}" '{version: "2.1.0", runs: [{tool: {driver: {name: "Trivy"}}, results: [],
                originalUriBaseIds: {ROOTPATH: {uri: ("file://" + $r + "/")}}}]}' > "${out}" ;;
            table) printf 'Report Summary (table of %s)\n' "$(jq -r .ArtifactName "${report}")" > "${out}" ;;
            cyclonedx) echo '{"bomFormat": "CycloneDX"}' > "${out}" ;;
            spdx-json) echo '{"spdxVersion": "SPDX-2.3"}' > "${out}" ;;
            github) echo '{"version": 0}' > "${out}" ;;
            *) echo "FATAL unknown format" >&2; exit 1 ;;
        esac
        exit 0
        ;;
    registry)
        if [[ "$2" == login ]]; then
            password=$(cat)
            printf 'user=%s password=%s registry=%s\n' "$(opt username)" "${password}" "$(positional)" > "${STUB_DIR}/login"
            exit "${STUB_LOGIN_EXIT:-0}"
        fi
        printf 'logout %s\n' "$(positional)" > "${STUB_DIR}/logout"
        exit 0
        ;;
esac
# A fetch.
if has --download-db-only || has --download-java-db-only; then
    attempts=$(($(cat "${STUB_DIR}/attempts" 2> /dev/null || echo 0) + 1))
    echo "${attempts}" > "${STUB_DIR}/attempts"
    if [[ "${attempts}" -le "${STUB_FETCH_FAILS:-0}" ]]; then
        echo "FATAL Fatal error: TOOMANYREQUESTS: retry later" >&2
        exit 1
    fi
    dir=db
    has --download-java-db-only && dir=java-db
    mkdir -p "${cache}/${dir}"
    age=$((${STUB_DB_AGE_DAYS:-0} * 86400 + 3600))
    jq -n --arg u "$(stamp "${age}")" --arg n "$(stamp $((age - 86400)))" --arg d "$(stamp 60)" \
        '{Version: 2, NextUpdate: $n, UpdatedAt: $u, DownloadedAt: $d}' > "${cache}/${dir}/metadata.json"
    exit 0
fi
# A scan.
if [[ -n "${STUB_SCAN_EXIT:-}" ]]; then
    echo "FATAL Fatal error: unable to find the specified image" >&2
    exit "${STUB_SCAN_EXIT}"
fi
echo "INFO [vuln] Vulnerability scanning is enabled" >&2
if [[ -n "${STUB_LOG_LINE:-}" ]]; then
    echo "${STUB_LOG_LINE}" >&2
fi
if [[ "$1" == config && -n "${cache}" && -z "${STUB_LOG_LINE:-}" ]]; then
    mkdir -p "${cache}/policy"
    jq -n --arg d "$(stamp 60)" '{Digest: "sha256:c0ffee", DownloadedAt: $d}' > "${cache}/policy/metadata.json"
fi
cp "${STUB_REPORT:-${STUB_FIXTURES}/clean.json}" "$(opt output)"
EOF
chmod +x "${WORK}/bin/"*

FAILURES=0
RC=0
OUTPUT=""

# run COMMAND [NAME=VALUE ...] [-- VAR=value ...]: runs COMMAND's script in
# the job directory through tests/run_command.sh, with the parameters given
# and the environment settings after --. Recorded calls, BASH_ENV and the
# stand-in's state start empty.
run() {
    local command=$1 params=() envs=()
    shift
    while [[ $# -gt 0 && "$1" != -- ]]; do
        params+=("$1")
        shift
    done
    if [[ $# -gt 0 ]]; then
        shift
        envs=("$@")
    fi
    rm -rf "${STUB}/calls" "${STUB}/attempts" "${STUB}/login" "${STUB}/logout"
    mkdir -p "${STUB}/calls"
    : > "${WORK}/bash_env"
    OUTPUT=$(cd "${JOB}" && env HOME="${HOME_DIR}" PATH="${WORK}/bin:${PATH}" BASH_ENV="${WORK}/bash_env" \
        STUB_DIR="${STUB}" STUB_FIXTURES="${FIXTURES}" ${envs[@]+"${envs[@]}"} \
        bash "${ROOT}/tests/run_command.sh" "${command}" ${params[@]+"${params[@]}"} 2>&1)
    RC=$?
}

# scan [NAME=VALUE ...] [-- VAR=value ...]: run scan with output_dir in OUT.
# Every run record it writes is kept, to check against the schema at the end.
RECORDS=0
mkdir -p "${WORK}/records"
scan() {
    local params=() envs=() record
    while [[ $# -gt 0 && "$1" != -- ]]; do
        params+=("$1")
        shift
    done
    [[ $# -gt 0 ]] && envs=("$@")
    run scan "output_dir=${OUT}" ${params[@]+"${params[@]}"} ${envs[@]+"${envs[@]}"}
    for record in "${OUT}"/*.run-record.json; do
        [[ -f "${record}" ]] || continue
        RECORDS=$((RECORDS + 1))
        cp "${record}" "${WORK}/records/${RECORDS}.json"
    done
}

check() {
    local description=$1 call
    shift
    if "$@"; then
        printf 'ok: %s\n' "${description}"
    else
        printf 'FAIL: %s\n' "${description}"
        while IFS= read -r line; do
            printf '    | %s\n' "${line}"
        done <<< "${OUTPUT}"
        for call in "${STUB}/calls/"*.args; do
            [[ -f "${call}" ]] || continue
            printf '    trivy call %s: %s\n' "$(basename "${call}" .args)" "$(tr '\n' ' ' < "${call}")"
        done
        FAILURES=$((FAILURES + 1))
    fi
}
rc_is() { [[ "${RC}" -eq "$1" ]]; }
failed() { [[ "${RC}" -ne 0 ]]; }
said() { grep -qF -- "$1" <<< "${OUTPUT}"; }
not_said() { ! said "$1"; }
# script_lacks TEXT: the script's output lacks TEXT; run_command.sh's own
# first line, which echoes the parameters, is left out.
script_lacks() { ! grep -v '^Running scripts/' <<< "${OUTPUT}" | grep -qF -- "$1"; }
trivy_not_run() { [[ -z "$(find "${STUB}/calls" -name '*.args')" ]]; }
# the_scan: the arguments of the scan call (the one with --format json and
# --output, not a version or convert call).
scan_call() {
    local call
    for call in "${STUB}/calls/"*.args; do
        if grep -qx -- --output "${call}" && ! grep -qx convert "${call}"; then
            printf '%s\n' "${call}"
            return 0
        fi
    done
    return 1
}
# scan_has ARG...: the scan call got each of these arguments, in this order,
# next to each other.
scan_has() {
    local call
    call=$(scan_call) || return 1
    grep -qzF -- "$(printf '%s\n' "$@")" "${call}"
}
scan_lacks() { local call; call=$(scan_call) || return 1; ! grep -qxF -- "$1" "${call}"; }
scan_ends_with() { local call; call=$(scan_call) || return 1; [[ "$(tail -n 2 "${call}")" == "$(printf -- '--\n%s' "$1")" ]]; }
scan_first() { local call; call=$(scan_call) || return 1; [[ "$(head -n 1 "${call}")" == "$1" ]]; }
# call_having ARG: the recorded arguments file of the first call with ARG.
call_having() {
    local call
    for call in "${STUB}/calls/"*.args; do
        if grep -qxF -- "$1" "${call}"; then
            printf '%s\n' "${call}"
            return 0
        fi
    done
    return 1
}
call_count() { [[ "$(find "${STUB}/calls" -name '*.args' | wc -l)" -eq "$1" ]]; }
# convert_meta FORMAT: the recorded working directory and TRIVY_* variables
# of the convert call for FORMAT.
convert_meta() {
    local call
    for call in "${STUB}/calls/"*.args; do
        if grep -qx convert "${call}" && grep -qx -- "$1" "${call}"; then
            cat "${call%.args}.meta"
            return 0
        fi
    done
    return 1
}
report() { [[ -s "${OUT}/$1" ]]; }
differs() { ! cmp -s "$1" "$2"; }
lacks() { ! grep -qF -- "$1" "$2"; }
lacks_line() { ! grep -q -- "$1" "$2"; }
no_report() { [[ ! -e "${OUT}/$1" ]]; }
json_is() { [[ "$(jq -c "$2" "${OUT}/$1" 2> /dev/null)" == "$3" ]]; }
exported() {
    # shellcheck disable=SC2016 # expanded by the clean shell, not here
    [[ "$(env -i bash -c 'source "$1"; printf "%s" "${!2}"' _ "${WORK}/bash_env" "$1")" == "$2" ]]
}
not_exported() { ! grep -q "^export $1=" "${WORK}/bash_env"; }

# make_db DIR [AGE_DAYS]: a vulnerability database's metadata in DIR, built
# AGE_DAYS (default 0) days and an hour ago.
make_db() {
    local age=$(((${2:-0}) * 86400 + 3600))
    stamp() { date -u -d "@$(($(date -u +%s) - $1))" +%Y-%m-%dT%H:%M:%S.5Z; }
    mkdir -p "$1/db"
    jq -n --arg u "$(stamp "${age}")" --arg n "$(stamp $((age - 86400)))" --arg d "$(stamp 60)" \
        '{Version: 2, NextUpdate: $n, UpdatedAt: $u, DownloadedAt: $d}' > "$1/db/metadata.json"
}
CACHE="${HOME_DIR}/.cache/trivy"
make_db "${CACHE}"

echo "=== scan: arguments"
scan target=registry.example/app:1.0 -- STUB_REPORT="${FIXTURES}/clean.json"
check "an image scan with nothing found passes" rc_is 0
check "runs trivy image" scan_first image
check "with the cache directory, and a JSON report trivy exits 0 for" \
    scan_has --cache-dir "${CACHE}" --format json --output
check "without telemetry or the version check" scan_has --exit-code 0 --skip-version-check --disable-telemetry
check "listing every package and the suppressed findings, without progress bars" \
    scan_has --list-all-pkgs --show-suppressed --no-progress
check "and the image last, after --" scan_ends_with registry.example/app:1.0
check "never failing on an end-of-life OS itself" scan_has --exit-on-eol 0
check "updates the databases by default" scan_lacks --skip-db-update
check "passes no severity, so every one is reported" scan_lacks --severity
check "and Trivy's default scanners, explicitly" scan_has image --scanners=vuln,secret
check "says it passed" said "Passed: Trivy found nothing at or above HIGH in registry.example/clean:1.0."
check "writes the JSON report" report trivy.json
check "the JSON report is Trivy's" json_is trivy.json .ArtifactName '"registry.example/clean:1.0"'
check "writes SARIF" report trivy.sarif
check "and the table" report trivy.txt
check "prints the table" said "Report Summary (table of registry.example/clean:1.0)"
check "writes JUnit" report junit/trivy.xml
check "with one passing case when nothing was found" grep -q 'name="no findings"' "${OUT}/junit/trivy.xml"
check "writes no run record by default" no_report trivy.run-record.json
check "summarizes what it checked" said "0 finding(s): 0 vulnerabilities, 0 misconfigurations, 0 secrets and 0 licenses; 0 at or above HIGH; 2 packages checked"

scan target=registry.example/app:1.0 scanners=vuln,secret,license severity=high,critical ignore_unfixed=true \
    ignore_file=.trivyignore vex="vex.json repo" pkg_types=os skip_dirs="vendor,node_modules" skip_files=a.txt \
    image_src=remote platform=linux/arm64 timeout=15m extra_args="--detection-priority comprehensive" \
    -- STUB_REPORT="${FIXTURES}/clean.json"
check "every option fails before trivy runs when its files are missing" failed
check "naming the ignore file" said "ignore_file names no file: '.trivyignore'."
check "before trivy runs" trivy_not_run
touch "${JOB}/.trivyignore" "${JOB}/vex.json"
scan target=registry.example/app:1.0 scanners=vuln,secret,license severity=high,critical ignore_unfixed=true \
    ignore_file=.trivyignore vex="vex.json repo" pkg_types=os skip_dirs="vendor,node_modules" skip_files=a.txt \
    image_src=remote platform=linux/arm64 timeout=15m extra_args="--detection-priority comprehensive" \
    -- STUB_REPORT="${FIXTURES}/clean.json"
check "an image scan with every option passes" rc_is 0
check "passes each option as Trivy's flag" scan_has image --scanners=vuln,secret,license --severity=HIGH,CRITICAL \
    --ignore-unfixed --ignorefile=.trivyignore --vex=vex.json --vex=repo --pkg-types=os --skip-dirs=vendor \
    --skip-dirs=node_modules --skip-files=a.txt --image-src=remote --platform=linux/arm64 --timeout=15m \
    --detection-priority comprehensive --cache-dir
rm -f "${JOB}/.trivyignore" "${JOB}/vex.json"

mkdir -p "${JOB}/app"
scan target_type=filesystem target=app -- STUB_REPORT="${FIXTURES}/filesystem.json"
check "a filesystem scan runs trivy filesystem on the directory" scan_first filesystem
check "after --" scan_ends_with app
check "fails on its HIGH vulnerability" rc_is 1
check "SARIF's ROOTPATH names the scanned directory" \
    json_is trivy.sarif '.runs[0].originalUriBaseIds.ROOTPATH.uri' "\"file://${JOB}/app/\""

scan target_type=config target=app -- STUB_REPORT="${FIXTURES}/config-clean.json"
check "a config scan passes when every check passed" rc_is 0
check "runs trivy config" scan_first config
for flag in --list-all-pkgs --show-suppressed --no-progress --skip-db-update --scanners; do
    check "without ${flag}, which trivy config doesn't take" scan_lacks "${flag}"
done
check "needs no vulnerability database" not_said "Vulnerability database: built"
check "and passes no --exit-on-eol, which trivy config doesn't take" scan_lacks --exit-on-eol

scan target_type=sbom target=bom.json -- STUB_REPORT="${FIXTURES}/clean.json"
check "an sbom scan runs trivy sbom" scan_first sbom
check "for vulnerabilities, its default" scan_has sbom --scanners=vuln
check "with the SBOM after --" scan_ends_with bom.json
scan target_type=sbom target=bom.json -- STUB_REPORT="${FIXTURES}/clean.json" TRIVY_ORB_CHECKS_DIR="${CACHE}"
check "without --skip-check-update, which trivy sbom doesn't take" scan_lacks --skip-check-update

touch "${JOB}/image.tar"
scan input=image.tar -- STUB_REPORT="${FIXTURES}/clean.json"
check "an image archive is passed as --input" scan_has --input=image.tar
check "with no target after it" scan_lacks --
rm -f "${JOB}/image.tar"

scan target=-oops -- STUB_REPORT="${FIXTURES}/clean.json"
check "a target that starts with - stays after --" scan_ends_with -oops

mkdir -p "${HOME_DIR}/project"
scan target_type=filesystem 'target=~/project' -- STUB_REPORT="${FIXTURES}/filesystem.json"
check "a leading ~ in a path is the home directory" scan_ends_with "${HOME_DIR}/project"
scan 'target=~registry/app:1.0' -- STUB_REPORT="${FIXTURES}/clean.json"
check "but not in an image reference" scan_ends_with '~registry/app:1.0'

# shellcheck disable=SC2016 # expanded by the stand-in circleci
scan 'target=registry.example/${ORB_TEST_VAR}:1.0' -- STUB_REPORT="${FIXTURES}/clean.json" ORB_TEST_VAR=expanded
check "expands environment variables in target" scan_ends_with registry.example/expanded:1.0

echo "=== scan: the gate"
scan target=registry.example/app:1.0 run_record=true -- STUB_REPORT="${FIXTURES}/vulnerable.json"
check "findings at or above HIGH fail the step" rc_is 1
check "saying how many" said "ERROR: Trivy found 3 findings at or above HIGH in registry.example/app:1.0."
check "counting each kind" said "6 finding(s): 4 vulnerabilities, 0 misconfigurations, 1 secrets and 1 licenses; 3 at or above HIGH; 1 suppressed by ignore files or VEX; 2 packages checked"
check "listing the findings, most severe first" said "  CRITICAL	secret	aws-access-key-id	/app/config.env"
check "with the package and its fix" said "  HIGH	vulnerability	CVE-2026-0002	registry.example/app:1.0 (alpine 3.20.3)	libssl3 3.3.2-r0 (fixed in 3.3.3-r0)"
check "still writes every report" report trivy.sarif
check "JUnit has a failed case per finding at or above HIGH" \
    test "$(grep -c '<failure ' "${OUT}/junit/trivy.xml")" -eq 3
check "and a skipped case per finding below it" test "$(grep -c '<skipped ' "${OUT}/junit/trivy.xml")" -eq 3
check "the run record says findings" json_is trivy.run-record.json .outcome '"findings"'
check "names the trivy that ran" json_is trivy.run-record.json '.tool | [.name, .version]' '["trivy","0.76.1"]'
check "with its SHA-512" json_is trivy.run-record.json '.tool.sha512 | length' 128
check "and what it scanned" json_is trivy.run-record.json '.target | [.type, .target, .artifact_type, .os.Family]' \
    '["image","registry.example/app:1.0","container_image","alpine"]'
check "the database it scanned with" json_is trivy.run-record.json '.databases.VulnerabilityDB.Version' 2
check "the gate" json_is trivy.run-record.json '.gate | [.fail_on, .report_only]' '["HIGH",false]'
check "the counts" json_is trivy.run-record.json '.counts | [.findings, .failing, .vulnerabilities.CRITICAL, .suppressed]' '[6,3,1,1]'
check "the arguments, without the reporting options" json_is trivy.run-record.json .arguments '["image","--scanners=vuln,secret"]'
check "and each report with its SHA-256" json_is trivy.run-record.json '[.reports[].path | split("/") | last]' \
    '["trivy.json","trivy.sarif","trivy.txt","trivy.xml"]'

scan target=registry.example/app:1.0 report_only=true run_record=true -- STUB_REPORT="${FIXTURES}/vulnerable.json"
check "report_only reports the findings without failing" rc_is 0
check "with a warning" said "WARN: Trivy found 3 findings at or above HIGH"
check "the run record says findings-reported" json_is trivy.run-record.json .outcome '"findings-reported"'

scan target=registry.example/app:1.0 fail_on=critical -- STUB_REPORT="${FIXTURES}/vulnerable.json"
check "fail_on critical counts only CRITICAL findings" said "ERROR: Trivy found 2 findings at or above CRITICAL"
scan target=registry.example/app:1.0 fail_on=critical -- STUB_REPORT="${FIXTURES}/medium.json"
check "and passes with a MEDIUM one" rc_is 0
scan target=registry.example/app:1.0 fail_on=medium -- STUB_REPORT="${FIXTURES}/medium.json"
check "which fail_on medium fails" rc_is 1
scan target=registry.example/app:1.0 fail_on=unknown -- STUB_REPORT="${FIXTURES}/vulnerable.json"
check "fail_on unknown counts every finding" said "Trivy found 6 findings at or above UNKNOWN"

scan target_type=config target=. -- STUB_REPORT="${FIXTURES}/config.json"
check "a failed misconfiguration check fails the step" rc_is 1
check "naming it" said "  HIGH	misconfiguration	DS-0002	Dockerfile"

scan target=registry.example/old:1.0 -- STUB_REPORT="${FIXTURES}/eol.json"
check "an end-of-life OS passes by default" rc_is 0
check "with a warning" said "WARN: alpine 3.10.9 is end of life"
scan target=registry.example/old:1.0 fail_on_eol=true -- STUB_REPORT="${FIXTURES}/eol.json"
check "and fails with fail_on_eol" rc_is 1
check "saying so" said "and an end-of-life OS."

echo "=== scan: no verdict"
scan target=registry.example/app:1.0 run_record=true report_only=true -- STUB_SCAN_EXIT=1
check "a scan trivy can't complete fails the step, whatever report_only says" rc_is 1
check "saying there is no verdict" said "ERROR: Trivy could not complete the scan (exit code 1)"
check "with trivy's own error" said "unable to find the specified image"
check "the run record says error" json_is trivy.run-record.json .outcome '"error"'
check "and writes no other report" no_report trivy.json

scan target_type=filesystem target=. report_only=true -- STUB_REPORT="${FIXTURES}/empty.json"
check "a vulnerability scan that found no packages fails" rc_is 1
check "saying it checked nothing" said "Trivy found no packages to check for vulnerabilities in empty-dir"
scan target_type=filesystem target=. allow_empty=true -- STUB_REPORT="${FIXTURES}/empty.json"
check "unless allow_empty is true" rc_is 0
scan target_type=filesystem target=. scanners=secret -- STUB_REPORT="${FIXTURES}/empty.json"
check "a secret scan that found nothing passes" rc_is 0
scan target_type=filesystem target=. -- STUB_REPORT="${FIXTURES}/config-clean.json" TRIVY_SCANNERS=misconfig
check "a job's TRIVY_SCANNERS doesn't change what the checks expect" scan_has filesystem --scanners=vuln,secret
scan target_type=config target=. -- STUB_REPORT="${FIXTURES}/config-empty.json"
check "a config scan that found nothing to check fails" rc_is 1
check "saying so" said "Trivy found no infrastructure as code to check"
scan target_type=config target=. severity=CRITICAL -- STUB_REPORT="${FIXTURES}/config-filtered.json"
check "but not one whose checks severity left out of the report" rc_is 0

make_db "${CACHE}" 10
scan target=registry.example/app:1.0 report_only=true -- STUB_REPORT="${FIXTURES}/clean.json"
check "a vulnerability database older than max_db_age_days fails the scan" rc_is 1
check "saying how old it is" said "was built 10 days ago"
scan target=registry.example/app:1.0 max_db_age_days=0 -- STUB_REPORT="${FIXTURES}/clean.json"
check "max_db_age_days 0 accepts it" rc_is 0
scan target=registry.example/app:1.0 max_db_age_days=30 -- STUB_REPORT="${FIXTURES}/clean.json"
check "and a larger limit" rc_is 0
scan target=registry.example/app:1.0 max_db_age_days=011 run_record=true -- STUB_REPORT="${FIXTURES}/clean.json"
check "a limit with a leading zero is read as decimal, not octal" rc_is 0
check "in the run record too" json_is trivy.run-record.json .gate.max_db_age_days 11
make_db "${CACHE}"
scan target=registry.example/app:1.0 cache_dir="${WORK}/empty-cache" -- STUB_REPORT="${FIXTURES}/clean.json"
check "a cache_dir without a vulnerability database fails a vulnerability scan" rc_is 1
check "saying there is none" said "There is no vulnerability database in ${WORK}/empty-cache"

scan target_type=config target=. scanners="" -- STUB_REPORT="${FIXTURES}/config.json" STUB_LOG_LINE="ERROR Falling back to embedded checks"
check "a fallback to the checks built into trivy is a warning" said "WARN: Trivy couldn't use its checks bundle"

scan target_type=repository target=https://robot:s3cret@git.example/org/app.git run_record=true \
    -- STUB_REPORT="${FIXTURES}/filesystem.json"
check "a remote repository is scanned from its URL" scan_ends_with https://robot:s3cret@git.example/org/app.git
check "whose credentials stay out of the log" script_lacks "s3cret"
check "and out of the run record" json_is trivy.run-record.json '.target.target' '"https://git.example/org/app.git"'
check "and SARIF has no ROOTPATH, as there is no local directory" \
    json_is trivy.sarif '.runs[0].originalUriBaseIds.ROOTPATH' null

echo "=== scan: databases and offline"
scan target=registry.example/app:1.0 -- STUB_REPORT="${FIXTURES}/clean.json" TRIVY_ORB_DB_DIR="${CACHE}"
check "skips updating the database fetch_db fetched here" scan_has --skip-db-update
check "but not the Java database it didn't" scan_lacks --skip-java-db-update
scan target=registry.example/app:1.0 -- STUB_REPORT="${FIXTURES}/clean.json" TRIVY_ORB_DB_DIR="${WORK}/elsewhere"
check "updates a database fetch_db fetched into another directory" scan_lacks --skip-db-update
scan target=registry.example/app:1.0 -- STUB_REPORT="${FIXTURES}/clean.json" TRIVY_ORB_DB_DIR="${CACHE}" \
    TRIVY_ORB_JAVA_DB_DIR="${CACHE}" TRIVY_ORB_CHECKS_DIR="${CACHE}"
check "skips every update fetch_db covered" scan_has --skip-db-update --skip-java-db-update --skip-check-update
scan target=registry.example/app:1.0 offline=true -- STUB_REPORT="${FIXTURES}/clean.json"
check "offline skips every update and the Maven lookups" \
    scan_has --skip-db-update --skip-java-db-update --offline-scan --skip-check-update
scan target_type=config target=. offline=true -- STUB_REPORT="${FIXTURES}/config-clean.json"
check "a config scan offline skips only the checks update" scan_has config --skip-check-update
check "since trivy config takes no database flags" scan_lacks --skip-db-update
scan target=registry.example/app:1.0 -- STUB_REPORT="${FIXTURES}/clean.json" TRIVY_CACHE_DIR="${WORK}/exported"
check "uses the cache directory fetch_db exported" scan_has --cache-dir "${WORK}/exported"
scan target=registry.example/app:1.0 cache_dir="~/other" max_db_age_days=0 -- STUB_REPORT="${FIXTURES}/clean.json" TRIVY_CACHE_DIR="${WORK}/exported"
check "and cache_dir over it, with ~ expanded" scan_has --cache-dir "${HOME_DIR}/other"

echo "=== scan: reports"
scan target=registry.example/app:1.0 formats="sarif table cyclonedx spdx-json github json" -- STUB_REPORT="${FIXTURES}/clean.json" \
    TRIVY_SEVERITY=CRITICAL TRIVY_IGNOREFILE=missing.yaml
check "every format is written" rc_is 0
for file in trivy.json trivy.sarif trivy.txt trivy.cdx.json trivy.spdx.json trivy.github.json; do
    check "writes ${file}" report "${file}"
done
check "the job's TRIVY_* variables reach the scan" grep -q '^TRIVY_SEVERITY=CRITICAL$' "$(scan_call | sed 's/args$/meta/')"
check "but not trivy convert" eval '! convert_meta cyclonedx | grep -q "^TRIVY_"'
check "which runs in an empty directory" eval 'convert_meta cyclonedx | grep -q "^cwd=.*/convert$"'
check "SARIF of an image has no ROOTPATH of its own" \
    json_is trivy.sarif '.runs[0].originalUriBaseIds.ROOTPATH.uri | test("report.json/$")' true
scan target=registry.example/app:1.0 formats="" -- STUB_REPORT="${FIXTURES}/clean.json"
check "formats can be empty" rc_is 0
check "which writes the JSON report alone" no_report trivy.sarif
check "and an earlier scan's reports are removed" no_report trivy.cdx.json
check "the JSON report stays" report trivy.json
check "the findings are printed without the table" said "0 finding(s)"
scan target=registry.example/app:1.0 -- STUB_REPORT="${FIXTURES}/clean.json" STUB_CONVERT_EXIT=1
check "a convert that fails fails the step" rc_is 1
check "naming the format" said "trivy convert could not write the sarif report."
scan target=registry.example/app:1.0 report_name=api junit=false -- STUB_REPORT="${FIXTURES}/clean.json"
check "report_name names the reports" report api.json
check "junit false writes no JUnit" no_report junit/api.xml

printf 'vulnerabilities:\n  - id: CVE-2026-0001\n' > "${JOB}/.trivyignore.yaml"
scan target=registry.example/app:1.0 -- STUB_REPORT="${FIXTURES}/clean.json"
check "a .trivyignore.yaml is used when there is no .trivyignore" scan_has --ignorefile=.trivyignore.yaml
check "saying so" said "Using the ignore file .trivyignore.yaml"
touch "${JOB}/.trivyignore"
scan target=registry.example/app:1.0 -- STUB_REPORT="${FIXTURES}/clean.json"
check "but not when there is a .trivyignore, which trivy reads itself" scan_lacks --ignorefile=.trivyignore.yaml
rm -f "${JOB}/.trivyignore" "${JOB}/.trivyignore.yaml"

echo "=== scan: input checks"
# expect_usage MESSAGE NAME=VALUE...: the scan stops with MESSAGE, exit code
# 2, before trivy runs.
expect_usage() {
    local message=$1
    shift
    scan "$@" -- STUB_REPORT="${FIXTURES}/clean.json"
    check "refuses $*" rc_is 2
    check "saying: ${message}" said "${message}"
    check "before trivy runs" trivy_not_run
}
expect_usage "target_type must be image, filesystem, rootfs, repository, config or sbom, not 'vm'." target_type=vm target=x
expect_usage "target is required: the image to scan" target=
expect_usage "target is required: the directory to scan" target_type=filesystem
expect_usage "input is an image archive or OCI layout to scan, so it needs target_type: image." target_type=filesystem target=. input=a.tar
expect_usage "Give target (an image reference) or input (an image archive or OCI layout), not both." target=x input=a.tar
expect_usage "input names no file or directory: 'missing.tar'." input=missing.tar
expect_usage "image_src and platform apply to images" target_type=filesystem target=. platform=linux/amd64
expect_usage "image_src must be a comma-separated list" target=x image_src=daemon
expect_usage "scanners can be vuln, misconfig, secret, license for target_type: image, not 'vulns'." target=x scanners=vulns
expect_usage "scanners can be vuln, license for target_type: sbom, not 'secret'." target_type=sbom target=x scanners=secret
expect_usage "scanners doesn't apply to target_type: config" target_type=config target=. scanners=vuln
expect_usage "ignore_unfixed doesn't apply to target_type: config" target_type=config target=. ignore_unfixed=true
expect_usage "skip_dirs and skip_files don't apply to target_type: sbom." target_type=sbom target=x skip_dirs=a
expect_usage "pkg_types must be os, library, or both" target=x pkg_types=apk
expect_usage "fail_on must be critical, high, medium, low or unknown, not 'severe'." target=x fail_on=severe
expect_usage "severity must be a comma-separated list" target=x severity=HIGH,URGENT
expect_usage "timeout must be a duration such as 10m or 1h30m, not '10 minutes'." target=x "timeout=10 minutes"
expect_usage "formats can be json, sarif, table, cyclonedx, spdx-json and github, not 'html'." target=x formats=html
expect_usage "vex names no file: 'missing.json'." target=x vex=missing.json
for refused in --format=table "--output x" --exit-code=1 "--cache-dir /tmp" -fjson "-o x" --list-all-pkgs=false --; do
    expect_usage "extra_args can't hold" target=x "extra_args=${refused}"
done
scan target=x "extra_args=--debug \$(touch ${WORK}/pwned)" -- STUB_REPORT="${FIXTURES}/clean.json"
check "a \$(...) in extra_args fails the step" failed
check "and runs nothing" test ! -e "${WORK}/pwned"
scan target=x max_db_age_days=-1 -- STUB_REPORT="${FIXTURES}/clean.json"
check "a negative max_db_age_days is refused" failed
check "before trivy scans" eval '! scan_call'
scan target=x output_dir=relative -- STUB_REPORT="${FIXTURES}/clean.json"
check "a relative output_dir is refused" said "output_dir must be an absolute path"
scan target=x report_name=../x -- STUB_REPORT="${FIXTURES}/clean.json"
check "a report_name with a path is refused" said "report_name must be letters, digits"

echo "=== fetch_db"
rm -rf "${CACHE}"
run fetch_db
check "fetches the vulnerability database" rc_is 0
check "with trivy image --download-db-only into the default cache directory" \
    grep -qzF -- "$(printf '%s\n' image --download-db-only --cache-dir "${CACHE}" --no-progress --scanners vuln)" "$(call_having --download-db-only)"
check "says how old it is" said "Vulnerability database: built"
check "exports TRIVY_CACHE_DIR" exported TRIVY_CACHE_DIR "${CACHE}"
check "and that it fetched the database there" exported TRIVY_ORB_DB_DIR "${CACHE}"
check "but not the Java database" not_exported TRIVY_ORB_JAVA_DB_DIR
check "exports no repository it didn't use" not_exported TRIVY_DB_REPOSITORY

run fetch_db java_db=true checks_bundle=true db_repository=mirror.example/aquasec/trivy-db:2,ghcr.io/aquasecurity/trivy-db:2 \
    java_db_repository=mirror.example/aquasec/trivy-java-db:1 checks_bundle_repository=mirror.example/aquasec/trivy-checks:2 timeout=20m
check "fetches all three" rc_is 0
check "the database from the repositories given" grep -qx -- '--db-repository=mirror.example/aquasec/trivy-db:2,ghcr.io/aquasecurity/trivy-db:2' "$(call_having --download-db-only)"
check "with the timeout" grep -qx -- '--timeout=20m' "$(call_having --download-db-only)"
check "the Java database with trivy image --download-java-db-only" call_having --download-java-db-only
check "from its repository" grep -qx -- '--java-db-repository=mirror.example/aquasec/trivy-java-db:1' "$(call_having --download-java-db-only)"
check "the checks bundle with a config scan of an empty directory" call_having config
check "from its repository" grep -qx -- '--checks-bundle-repository=mirror.example/aquasec/trivy-checks:2' "$(call_having config)"
check "reports the Java database" said "Java database: built"
check "and the checks bundle" said "Checks bundle: sha256:c0ffee"
check "exports what it fetched" exported TRIVY_ORB_JAVA_DB_DIR "${CACHE}"
check "all of it" exported TRIVY_ORB_CHECKS_DIR "${CACHE}"
check "and the repositories, for later scans" exported TRIVY_DB_REPOSITORY "mirror.example/aquasec/trivy-db:2,ghcr.io/aquasecurity/trivy-db:2"
check "every one" exported TRIVY_CHECKS_BUNDLE_REPOSITORY "mirror.example/aquasec/trivy-checks:2"

run fetch_db -- STUB_FETCH_FAILS=2
check "a fetch that fails twice is tried again" rc_is 0
check "with a warning each time" said "WARN: Fetching the vulnerability database failed (exit code 1). Trying again in 30 seconds."
run fetch_db -- STUB_FETCH_FAILS=3
check "three failures fail the step" rc_is 1
check "saying so" said "ERROR: Could not fetch the vulnerability database after 3 attempts."
check "and exports nothing" not_exported TRIVY_CACHE_DIR
run fetch_db checks_bundle=true -- STUB_LOG_LINE="ERROR Falling back to embedded checks"
check "a checks bundle trivy fell back from counts as a failed fetch" rc_is 1
run fetch_db -- STUB_DB_AGE_DAYS=10
check "a fetched database older than max_db_age_days fails the step" rc_is 1
check "saying it is too old" said "The vulnerability database Trivy fetched is too old to use."
run fetch_db cache_dir=relative/cache
check "a relative cache_dir is made absolute" exported TRIVY_CACHE_DIR "${JOB}/relative/cache"
run fetch_db db_repository="mirror.example/trivy-db:2 --insecure"
check "a repository with spaces is refused" rc_is 2
check "before trivy runs" trivy_not_run
run fetch_db checks_bundle_repository=a.example/checks:2,b.example/checks:2
check "a second checks bundle repository is refused" said "checks_bundle_repository takes one repository"

echo "=== db_cache_key.sh"
# key PART [VAR=value ...]: runs db_cache_key.sh for PART, writing the key files
# under WORK/key.
key() {
    local part=$1 extra=()
    shift
    # Bash 4.0 takes an empty "$@" for an unbound variable.
    if [[ $# -gt 0 ]]; then
        extra=("$@")
    fi
    OUTPUT=$(cd "${JOB}" && env HOME="${HOME_DIR}" PATH="${WORK}/bin:${PATH}" STUB_DIR="${STUB}" \
        ORB_DB_CACHE_KEY_PART="${part}" ORB_DB_CACHE_KEY_PREFIX="${WORK}/key" SCRIPT_TRIVY_LIB="$(cat "${ROOT}/src/scripts/lib/trivy.sh")" \
        PARAM_CACHE_DIR="~/.cache/trivy" PARAM_JAVA_DB=0 PARAM_CHECKS_BUNDLE=0 PARAM_DB_REPOSITORY="" PARAM_JAVA_DB_REPOSITORY="" \
        PARAM_CHECKS_BUNDLE_REPOSITORY="" ${extra[@]+"${extra[@]}"} bash "${ROOT}/src/scripts/db_cache_key.sh" 2>&1)
    RC=$?
}
key location
check "the location key is written" rc_is 0
# shellcheck disable=SC2088 # the literal ~, as the key file holds it
check "naming HOME and cache_dir as given" grep -qxF "~/.cache/trivy" "${WORK}/key-location"
check "and what is fetched" grep -qxF "trivy-db:2 java:false checks:false" "${WORK}/key-location"
check "with today's date" grep -qxF "$(date -u +%Y-%m-%d)" "${WORK}/key-day0"
check "and the two days before" grep -qxF "$(date -u -d '2 days ago' +%Y-%m-%d)" "${WORK}/key-day2"
cp "${WORK}/key-location" "${WORK}/location-default"
key location PARAM_JAVA_DB=1
check "the Java database changes the location" differs "${WORK}/key-location" "${WORK}/location-default"
key location PARAM_CACHE_DIR=relative
check "a relative cache_dir adds the working directory" grep -qxF "${JOB}" "${WORK}/key-location"
key database
check "the database key is written" rc_is 0
check "naming the database's build date" grep -qxF "$(jq -r '.UpdatedAt[:10]' "${CACHE}/db/metadata.json")" "${WORK}/key-built"
check "and its build time" grep -qF "vulnerability database $(jq -r .UpdatedAt "${CACHE}/db/metadata.json")" "${WORK}/key-database"
key database PARAM_CACHE_DIR="${WORK}/no-database"
check "without a database, the key is today's date" grep -qxF "date $(date -u +%Y-%m-%d)" "${WORK}/key-database"
check "with a warning" said "WARN: trivy version named no vulnerability database"

echo "=== login and logout"
run login registry=registry.example:5000 -- REGISTRY_USERNAME=robot 'REGISTRY_PASSWORD=-n s3cret, "x"' \
    TRIVY_PASSWORD=wrong TRIVY_USERNAME=wrong SHELLOPTS=xtrace
check "login succeeds" rc_is 0
check "with the username, the password from stdin, and the registry" \
    grep -qxF 'user=robot password=-n s3cret, "x" registry=registry.example:5000' "${STUB}/login"
check "never putting the password on the command line" lacks s3cret "$(call_having login)"
check "nor in the log, with xtrace on" not_said "s3cret"
check "and keeping the job's TRIVY_PASSWORD and TRIVY_USERNAME from trivy" \
    lacks_line '^TRIVY_\(PASSWORD\|USERNAME\)=' "$(call_having login | sed 's/args$/meta/')"
run login registry=ghcr.io username=GH_USER password=GH_TOKEN -- GH_USER=octocat GH_TOKEN=ghp_token
check "reads the variables username and password name" grep -qxF 'user=octocat password=ghp_token registry=ghcr.io' "${STUB}/login"
run login registry=ghcr.io -- REGISTRY_USERNAME=robot
check "an empty password fails before trivy runs" rc_is 1
check "naming the variable" said "The REGISTRY_PASSWORD environment variable, which password names, is empty or unset."
check "before trivy runs" trivy_not_run
run login registry=ghcr.io -- REGISTRY_PASSWORD=x
check "so does an empty username" said "The REGISTRY_USERNAME environment variable"
run login registry=ghcr.io -- REGISTRY_USERNAME=a,b REGISTRY_PASSWORD=x
check "a username with a comma is refused" said "holds a comma, a double quote or a newline"
run login registry=https://ghcr.io -- REGISTRY_USERNAME=a REGISTRY_PASSWORD=x
check "a registry URL is refused" said "registry must be a host with an optional port"
run login registry=ghcr.io -- REGISTRY_USERNAME=a REGISTRY_PASSWORD=x STUB_LOGIN_EXIT=1
check "a login trivy refuses fails the step" rc_is 1
check "saying so" said "ERROR: trivy could not log in to ghcr.io."
run logout registry=registry.example:5000
check "logout succeeds" rc_is 0
check "logging out of the registry" grep -qxF 'logout registry.example:5000' "${STUB}/logout"
run logout registry="ghcr.io/org"
check "logout refuses a path" said "registry must be a host with an optional port"

echo "=== run records"
check "the scans wrote run records" test "${RECORDS}" -gt 0
problems=""
for record in "${WORK}/records/"*.json; do
    # shellcheck disable=SC2016 # jq program, not shell
    problem=$(jq -r --slurpfile schema "${ROOT}/schemas/run-record.v1.json" '$schema[0] as $schema
        | ($schema.required - keys | map("missing \(.)")[]),
          (select(.schema != $schema.properties.schema.const) | "schema is \(.schema)"),
          (select(.outcome as $o | $schema.properties.outcome.enum | index($o) | not) | "outcome \(.outcome)")' "${record}" 2>&1)
    [[ -n "${problem}" ]] && problems+="${record##*/}: ${problem}"$'\n'
done
OUTPUT=${problems}
check "every record has the fields the schema requires" test -z "${problems}"
if command -v python3 > /dev/null 2>&1 && python3 -c 'import jsonschema' 2> /dev/null; then
    OUTPUT=$(python3 - "${ROOT}/schemas/run-record.v1.json" "${WORK}/records/"*.json 2>&1 << 'EOF'
import json, sys, jsonschema
schema = json.load(open(sys.argv[1]))
validator = jsonschema.Draft202012Validator(schema)
bad = 0
for path in sys.argv[2:]:
    for error in validator.iter_errors(json.load(open(path))):
        print(f"{path}: {'/'.join(map(str, error.path))}: {error.message}")
        bad += 1
sys.exit(1 if bad else 0)
EOF
    )
    RC=$?
    check "and validates against it with jsonschema" rc_is 0
else
    echo "  skip: Python's jsonschema is not installed, so only the checks above ran"
fi

echo
if [[ "${FAILURES}" -gt 0 ]]; then
    echo "${FAILURES} command check(s) failed."
    exit 1
fi
echo "All command checks passed."
