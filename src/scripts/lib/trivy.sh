#!/bin/bash

# Shared helpers for the trivy-orb commands. Each command passes this file to
# its step as SCRIPT_TRIVY_LIB, and its script evals it after
# set -euo pipefail, so it only defines functions and variables.
#
# Trivy reads every TRIVY_<FLAG> environment variable as that flag, so the
# helpers keep their own state in TV_ variables.

# tv_subst VALUE: prints VALUE with environment variables expanded. The value
# is piped in on stdin: passed as an argument, a value starting with "-" would
# be parsed as a flag. Without the CircleCI CLI (GitHub Actions and local
# runs), the value is used as is.
tv_subst() {
    if command -v circleci > /dev/null 2>&1; then
        printf '%s' "$1" | circleci env subst
    else
        printf '%s\n' "$1"
    fi
}

# tv_bool NAME VALUE: prints true or false. CircleCI passes boolean parameters
# as 1 or 0; GitHub Actions and local callers use true or false.
tv_bool() {
    case "$2" in
        1 | true) echo true ;;
        0 | false) echo false ;;
        *)
            echo "ERROR: ${1} must be true or false, not '${2}'." >&2
            exit 1
            ;;
    esac
}

# split_shell_words STRING: splits STRING into the SHELL_WORDS array the way
# the shell splits a command line into words, but expands and executes
# nothing. Single quotes keep everything literal. Inside double quotes a
# backslash escapes only ", \, $, ` and newline, as in bash. Outside quotes a
# backslash escapes the next character, and a backslash-newline joins lines.
# A # that starts a word starts a comment, which runs to the end of the line.
# Spaces, tabs and newlines separate words, and '' is an empty word. Returns 1
# if a quote is never closed, 2 if the input ends in a backslash outside
# quotes (which escapes nothing), 3 for bash's $'...' or $"..." quoting, which
# it does not implement, 4 for a $(...) or backtick outside quotes, which it
# would not run, and 5 for a shell operator (| & ; < > ( )) outside quotes,
# such as a redirection or a <(...) process substitution.
split_shell_words() {
    local input=$1 word="" in_word=false quote="" char next i
    SHELL_WORDS=()
    for ((i = 0; i < ${#input}; i++)); do
        char=${input:i:1}
        if [[ "${quote}" == "'" ]]; then
            if [[ "${char}" == "'" ]]; then quote=""; else word+=${char}; fi
        elif [[ "${quote}" == '"' ]]; then
            if [[ "${char}" == '"' ]]; then
                quote=""
            elif [[ "${char}" == "\\" ]] && ((i + 1 < ${#input})); then
                next=${input:i+1:1}
                case "${next}" in
                    '"' | "\\" | '$' | '`') word+=${next}; i=$((i + 1)) ;;
                    $'\n') i=$((i + 1)) ;;
                    *) word+=${char} ;;
                esac
            else
                word+=${char}
            fi
        else
            case "${char}" in
                ' ' | $'\t' | $'\n')
                    if [[ "${in_word}" == true ]]; then
                        SHELL_WORDS+=("${word}")
                        word=""
                        in_word=false
                    fi
                    ;;
                "'" | '"') quote=${char}; in_word=true ;;
                "#")
                    if [[ "${in_word}" == true ]]; then
                        word+=${char}
                    else
                        while ((i + 1 < ${#input})) && [[ "${input:i+1:1}" != $'\n' ]]; do
                            i=$((i + 1))
                        done
                    fi
                    ;;
                "\\")
                    ((i + 1 < ${#input})) || return 2
                    i=$((i + 1))
                    if [[ "${input:i:1}" != $'\n' ]]; then
                        word+=${input:i:1}
                        in_word=true
                    fi
                    ;;
                '$')
                    case "${input:i+1:1}" in
                        "'" | '"') return 3 ;;
                        "(") return 4 ;;
                    esac
                    word+=${char}
                    in_word=true
                    ;;
                '`') return 4 ;;
                '|' | '&' | ';' | '<' | '>' | '(' | ')') return 5 ;;
                *) word+=${char}; in_word=true ;;
            esac
        fi
    done
    [[ -z "${quote}" ]] || return 1
    if [[ "${in_word}" == true ]]; then
        SHELL_WORDS+=("${word}")
    fi
}

# tv_words PARAMETER VALUE: sets TV_WORDS to VALUE split like shell words
# (see split_shell_words), naming PARAMETER in any error. Nothing in it is
# expanded or executed: a $(...) or backtick that reached a parameter through
# an environment variable (a branch name, a commit message) reaches the tool as
# text inside quotes, and fails the step outside them.
tv_words() {
    local status=0
    split_shell_words "$2" || status=$?
    case "${status}" in
        0) ;;
        1)
            echo "ERROR: ${1} could not be split into arguments: it has a quote that is never closed." >&2
            echo "  A literal ' or \" needs a backslash before it, or quotes of the other kind around it." >&2
            exit 1
            ;;
        2)
            echo "ERROR: ${1} could not be split into arguments: it ends in a backslash." >&2
            echo "  A literal \\ at the end needs another \\ before it." >&2
            exit 1
            ;;
        3)
            echo "ERROR: ${1} could not be split into arguments: \$'...' and \$\"...\" quoting is not supported." >&2
            echo "  Use '...' or \"...\" instead." >&2
            exit 1
            ;;
        4)
            echo "ERROR: ${1} could not be split into arguments: it has a \$(...) or backtick outside quotes." >&2
            echo "  ${1} is not run as shell code, so the command would not run. Quote it to pass it to the tool as text." >&2
            exit 1
            ;;
        *)
            echo "ERROR: ${1} could not be split into arguments: it has one of | & ; < > ( ) outside quotes." >&2
            echo "  ${1} is not run as shell code, so pipes, redirections and <(...) would not work. Quote it to pass it to the tool as text." >&2
            exit 1
            ;;
    esac
    # shellcheck disable=SC2034 # read by the script that evals this file
    TV_WORDS=(${SHELL_WORDS[@]+"${SHELL_WORDS[@]}"})
}

# tv_match VALUE REGEX: [[ VALUE =~ REGEX ]] in the C locale, setting
# BASH_REMATCH. In other locales a range such as [a-z] can match letters such
# as é (cimg images set LC_ALL=en_US.UTF-8), so checks with ranges use this.
tv_match() {
    local LC_ALL=C
    [[ "$1" =~ $2 ]]
}

# tv_require_jq: stops the step unless jq, which the reports are built with,
# is on the PATH.
tv_require_jq() {
    if ! command -v jq > /dev/null 2>&1; then
        echo "ERROR: jq is not on the PATH, and this command needs it to write its reports." >&2
        echo "  CircleCI's cimg images and GitHub's hosted runners have it; elsewhere, install jq in an earlier step." >&2
        exit 1
    fi
}

# tv_output DIR NAME: checks output_dir and report_name, creates DIR, and sets
# TV_OUT to DIR and TV_BASE to the path every report of this run starts with.
tv_output() {
    if [[ "$1" != /* || "$1" == *$'\n'* ]]; then
        echo "ERROR: output_dir must be an absolute path, not '$1'." >&2
        exit 1
    fi
    if ! tv_match "$2" '^[A-Za-z0-9][A-Za-z0-9._-]*$'; then
        echo "ERROR: report_name must be letters, digits, '.', '_' and '-', not '$2'." >&2
        exit 1
    fi
    if ! mkdir -p "$1"; then
        echo "ERROR: Could not create output_dir $1." >&2
        exit 1
    fi
    TV_OUT=${1%/}
    TV_OUT=${TV_OUT:-/}
    # shellcheck disable=SC2034 # read by the script that evals this file
    TV_BASE="${TV_OUT%/}/$2"
}

# tv_uint PARAMETER VALUE [MIN]: stops the step unless VALUE is a whole number
# of at least MIN (default 0).
tv_uint() {
    if ! tv_match "$2" '^[0-9]{1,9}$' || ((10#$2 < ${3:-0})); then
        echo "ERROR: ${1} must be a whole number of at least ${3:-0}, not '$2'." >&2
        exit 1
    fi
}

# tv_junit FILE SUITE CASES: writes JUnit XML to FILE, for CircleCI's Tests
# tab or any other JUnit reader, from CASES, a JSON array of test cases:
#   {"classname": ..., "name": ..., "status": "failed" | "skipped" | "passed",
#    "message": ..., "detail": ...}
# A run with no cases gets one passing case, so the tab shows it ran.
tv_junit() {
    local dir=${1%/*}
    mkdir -p "${dir}"
    # shellcheck disable=SC2016 # jq program, not shell
    jq -r --arg suite "$2" '
        (if length == 0 then [{classname: $suite, name: "no findings", status: "passed"}] else . end) as $cases
        | "<?xml version=\"1.0\" encoding=\"UTF-8\"?>",
          "<testsuites>",
          "  <testsuite name=\"\($suite | @html)\" tests=\"\($cases | length)\" failures=\"\([$cases[] | select(.status == "failed")] | length)\" skipped=\"\([$cases[] | select(.status == "skipped")] | length)\">",
          ($cases[] |
            "    <testcase classname=\"\(.classname | @html)\" name=\"\(.name | @html)\">"
            + (if .status == "failed" then "<failure message=\"\((.message // "") | @html)\">\((.detail // "") | @html)</failure>"
               elif .status == "skipped" then "<skipped message=\"\((.message // "") | @html)\"/>"
               else "" end)
            + "</testcase>"),
          "  </testsuite>",
          "</testsuites>"
    ' <<< "$3" > "$1"
}

# tv_gate FINDINGS REPORT_ONLY SUMMARY: ends a check. Without findings it
# succeeds. With findings it fails with SUMMARY, unless REPORT_ONLY is true,
# when it only warns: the reports are written either way.
tv_gate() {
    if [[ "$1" == false ]]; then
        echo "Passed: $3"
        exit 0
    fi
    if [[ "$2" == true ]]; then
        echo "WARN: $3" >&2
        echo "WARN: report_only is true, so this step passes. The reports are in ${TV_OUT}." >&2
        exit 0
    fi
    echo "ERROR: $3" >&2
    echo "  The reports are in ${TV_OUT}. Set report_only to true to report findings without failing." >&2
    exit 1
}

# tv_plural COUNT SINGULAR PLURAL: prints COUNT and the word that goes with
# it, such as "1 file" or "2 files".
tv_plural() {
    if [[ "$1" -eq 1 ]]; then
        printf '%s %s\n' "$1" "$2"
    else
        printf '%s %s\n' "$1" "$3"
    fi
}

# tv_tail FILE [LINES]: prints the last LINES (default 40) lines of FILE to
# stderr, indented, to show why a tool failed.
tv_tail() {
    local lines=${2:-40} total first
    # A Go panic prints its message first, then the stack of every
    # goroutine, so the message is printed too when the tail leaves it out.
    total=$(wc -l < "$1")
    first=$(awk '/^(panic|fatal error): / { print NR; exit }' "$1")
    if [[ -n "${first}" ]] && ((first <= total - lines)); then
        awk -v n="${first}" 'NR >= n && NR < n + 8' "$1" | sed 's/^/  /' >&2
        echo "  ..." >&2
    fi
    tail -n "${lines}" "$1" | sed 's/^/  /' >&2
}

# tv_export NAME VALUE: exports NAME=VALUE, shell-quoted, to later steps
# through BASH_ENV (on GitHub Actions, the action passes it on through
# GITHUB_ENV).
tv_export() {
    if [[ -z "${BASH_ENV:-}" ]]; then
        echo "WARN: BASH_ENV is not set, so ${1} is not exported to later steps." >&2
        return 0
    fi
    printf 'export %s=%q\n' "$1" "$2" >> "${BASH_ENV}"
}

# tv_env_var_name PARAMETER VALUE: stops the step unless VALUE can name an
# environment variable.
tv_env_var_name() {
    if ! tv_match "$2" '^[A-Za-z_][A-Za-z0-9_]*$'; then
        echo "ERROR: ${1} must name an environment variable, not '${2}'." >&2
        exit 1
    fi
}

# tv_json_is FILE FILTER [JQ_OPTION...]: whether FILE holds one JSON value for
# which FILTER is true. It compares jq's output instead of using -e, since jq
# 1.6 (as on Ubuntu 22.04 and some cimg images) exits 0 with -e when the file
# is empty, as a tool that failed before writing its report leaves it.
tv_json_is() {
    local file=$1 filter=$2 options=()
    if [[ $# -gt 2 ]]; then
        options=("${@:3}")
    fi
    [[ "$(jq -c ${options[@]+"${options[@]}"} "(${filter}) | if . then true else false end" "${file}" 2> /dev/null)" == true ]]
}

# tv_sha256 FILE: prints FILE's SHA-256.
tv_sha256() {
    sha256sum -- "$1" | awk '{ print $1 }'
}

# tv_url_public URL: prints URL without the userinfo, query and fragment,
# which can hold credentials, so it can go in a log or an artifact.
tv_url_public() {
    local url=$1
    if [[ "${url}" =~ ^([A-Za-z][A-Za-z0-9+.-]*://)([^/?#]*@)?([^?#]*) ]]; then
        printf '%s%s\n' "${BASH_REMATCH[1]}" "${BASH_REMATCH[3]}"
    else
        printf '%s\n' "${url%%[?#]*}"
    fi
}

# tv_ci_json: describes the CI job this runs in, for run records: a CircleCI
# job or a GitHub Actions run, or null elsewhere.
tv_ci_json() {
    if [[ -n "${CIRCLE_BUILD_URL:-}" ]]; then
        jq -cn --arg url "${CIRCLE_BUILD_URL}" --arg sha "${CIRCLE_SHA1:-}" --arg job "${CIRCLE_JOB:-}" \
            --arg repo "${CIRCLE_PROJECT_USERNAME:-}${CIRCLE_PROJECT_REPONAME:+/${CIRCLE_PROJECT_REPONAME}}" \
            '{provider: "circleci", build_url: $url, sha1: $sha, job: $job, repository: $repo}'
    elif [[ "${GITHUB_ACTIONS:-}" == true ]]; then
        jq -cn --arg url "${GITHUB_SERVER_URL:-https://github.com}/${GITHUB_REPOSITORY:-}/actions/runs/${GITHUB_RUN_ID:-}/attempts/${GITHUB_RUN_ATTEMPT:-1}" \
            --arg sha "${GITHUB_SHA:-}" --arg job "${GITHUB_JOB:-}" --arg repo "${GITHUB_REPOSITORY:-}" \
            '{provider: "github-actions", build_url: $url, sha1: $sha, job: $job, repository: $repo}'
    else
        echo null
    fi
}

# tv_args_json ARG...: the arguments as a JSON array. They pass through jq
# NUL-separated, so arguments that start with "-" never reach jq's own option
# parsing, and a URL among them loses its userinfo, query and fragment.
tv_args_json() {
    if [[ $# -eq 0 ]]; then
        echo '[]'
        return 0
    fi
    # Ended by a word rather than a NUL, which jq 1.6 drops from the end of
    # raw input.
    { printf '%s\0' "$@"; printf 'end'; } | jq -Rsc 'split("\u0000") | .[:-1]
        | map(gsub("(?<scheme>[A-Za-z][A-Za-z0-9+.-]*://)[^/?#\\s]*@"; "\(.scheme)")
            | gsub("(?<url>[A-Za-z][A-Za-z0-9+.-]*://[^?#\\s]*)[?#]\\S*"; "\(.url)"))'
}

# tv_list PARAMETER VALUE: sets TV_LIST to VALUE, with environment variables
# expanded, split on commas, spaces and newlines.
tv_list() {
    local value
    TV_LIST=()
    value=$(tv_subst "$2")
    value=${value//,/ }
    # shellcheck disable=SC2034 # read by the script that evals this file
    read -r -d '' -a TV_LIST <<< "${value//$'\n'/ }" || true
}

# tv_bare COMMAND...: runs COMMAND with the job's TRIVY_* environment
# variables unset. Trivy reads each one as a flag, so a TRIVY_SEVERITY or
# TRIVY_EXIT_CODE set for the job would change how trivy convert renders a
# report the scan already filtered, or make it fail.
tv_bare() {
    local name unset=()
    while IFS= read -r name; do
        unset+=(-u "${name}")
    done < <(compgen -e | grep '^TRIVY_' || true)
    env ${unset[@]+"${unset[@]}"} "$@"
}

# tv_trivy: sets TV_TRIVY to the trivy on the PATH and TV_TRIVY_VERSION to
# the version it reports, or stops the step saying how to install it.
tv_trivy() {
    if ! TV_TRIVY=$(command -v trivy); then
        echo "ERROR: trivy is not on the PATH. Install it in an earlier step with this orb's install command." >&2
        exit 1
    fi
    TV_TRIVY_VERSION=$(tv_bare "${TV_TRIVY}" --version 2> /dev/null | awk '$1 == "Version:" { print $2; exit }') || TV_TRIVY_VERSION=""
    if [[ -z "${TV_TRIVY_VERSION}" ]]; then
        echo "ERROR: ${TV_TRIVY} --version reports no version. Is it Trivy?" >&2
        exit 1
    fi
}

# tv_cache_dir VALUE: sets TV_CACHE_DIR to the cache directory Trivy keeps its
# databases in: VALUE with environment variables and a leading ~ expanded,
# made absolute; or, when VALUE is empty, TRIVY_CACHE_DIR (which fetch_db
# exports), then Trivy's own default, $XDG_CACHE_HOME/trivy or
# $HOME/.cache/trivy.
tv_cache_dir() {
    local dir
    dir=$(tv_subst "$1")
    if [[ -z "${dir}" ]]; then
        dir=${TRIVY_CACHE_DIR:-}
    fi
    if [[ -z "${dir}" ]]; then
        if [[ -n "${XDG_CACHE_HOME:-}" ]]; then
            dir="${XDG_CACHE_HOME}/trivy"
        elif [[ -n "${HOME:-}" ]]; then
            dir="${HOME}/.cache/trivy"
        else
            echo "ERROR: HOME is not set, so cache_dir has no default. Set cache_dir to an absolute path." >&2
            exit 1
        fi
    fi
    if [[ "${dir}" == \~ || "${dir}" == \~/* ]]; then
        if [[ -z "${HOME:-}" ]]; then
            echo "ERROR: HOME is not set, so cache_dir can't start with ~." >&2
            exit 1
        fi
        dir="${HOME}${dir:1}"
    fi
    if [[ "${dir}" != /* ]]; then
        dir="${PWD}/${dir}"
    fi
    if [[ "${dir}" == *$'\n'* ]]; then
        echo "ERROR: cache_dir must be one line." >&2
        exit 1
    fi
    while [[ "${dir}" == */ && "${dir}" != / ]]; do
        dir=${dir%/}
    done
    TV_CACHE_DIR=${dir}
}

# tv_db_metadata: sets TV_DB_JSON to what Trivy reports about the databases in
# TV_CACHE_DIR: {"Version": ..., "VulnerabilityDB": {...}, "JavaDB": {...},
# "CheckBundle": {...}}, each database only when it is there. trivy version
# reads them from disk, without the network. TV_WORK is the script's work
# directory, as for tv_convert.
# shellcheck disable=SC2153 # TV_WORK is set by the script that evals this file
tv_db_metadata() {
    if ! TV_DB_JSON=$(tv_bare "${TV_TRIVY}" version --format json --cache-dir "${TV_CACHE_DIR}" 2> "${TV_WORK}/version.log") \
        || ! tv_json_is /dev/stdin 'type == "object"' <<< "${TV_DB_JSON}"; then
        echo "ERROR: trivy version could not read the databases in ${TV_CACHE_DIR}:" >&2
        tv_tail "${TV_WORK}/version.log" 10
        exit 1
    fi
    TV_DB_JSON=$(jq -c . <<< "${TV_DB_JSON}")
}

# tv_epoch TIMESTAMP: prints an RFC 3339 TIMESTAMP as seconds since the epoch.
tv_epoch() {
    date -u -d "$1" +%s 2> /dev/null
}

# tv_db_fresh MAX_DAYS: checks the vulnerability database in TV_DB_JSON. It
# fails when there is none, or when it was built more than MAX_DAYS days ago
# (0: no limit): Trivy uses a stale database without a word when it is told
# not to update it.
tv_db_fresh() {
    local updated next epoch age
    updated=$(jq -r '.VulnerabilityDB.UpdatedAt // ""' <<< "${TV_DB_JSON}")
    next=$(jq -r '.VulnerabilityDB.NextUpdate // ""' <<< "${TV_DB_JSON}")
    if [[ -z "${updated}" ]] || ! epoch=$(tv_epoch "${updated}"); then
        echo "ERROR: There is no vulnerability database in ${TV_CACHE_DIR}, or it has no build date." >&2
        return 1
    fi
    age=$((($(date -u +%s) - epoch) / 86400))
    echo "Vulnerability database: built ${updated} (${age} days ago), next update ${next:-unknown}."
    if (($1 > 0 && age > $1)); then
        echo "ERROR: The vulnerability database in ${TV_CACHE_DIR} was built $(tv_plural "${age}" day days) ago," >&2
        echo "  more than max_db_age_days ($1). A stale database misses recent vulnerabilities. Fetch a new one" >&2
        echo "  (fetch_db, or a scan without offline), or raise max_db_age_days." >&2
        return 1
    fi
}

# TV_FINDINGS_JQ: turns a Trivy JSON report into one array of the findings
# that count: every vulnerability, misconfiguration with status FAIL, secret
# and license left after Trivy's filters, with its severity's rank.
# shellcheck disable=SC2016,SC2034 # a jq program, read by the script that evals this file
TV_FINDINGS_JQ='
def rank: {"UNKNOWN": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}[.] // 0;
[(.Results // [])[] as $r
    | (($r.Vulnerabilities // [])[]
        | {class: "vulnerability", target: $r.Target, id: .VulnerabilityID, severity: (.Severity // "UNKNOWN"),
           title: (.Title // ""), url: (.PrimaryURL // ""), pkg: (.PkgName // ""), installed: (.InstalledVersion // ""),
           fixed: (.FixedVersion // ""), status: (.Status // "")}),
      (($r.Misconfigurations // [])[] | select(.Status == "FAIL")
        | {class: "misconfiguration", target: $r.Target, id: (.ID // .AVDID // ""), severity: (.Severity // "UNKNOWN"),
           title: (.Title // ""), url: (.PrimaryURL // ""), message: (.Message // ""), line: (.CauseMetadata.StartLine // null)}),
      (($r.Secrets // [])[]
        | {class: "secret", target: $r.Target, id: (.RuleID // ""), severity: (.Severity // "UNKNOWN"),
           title: (.Title // ""), line: (.StartLine // null)}),
      (($r.Licenses // [])[]
        | {class: "license", target: $r.Target, id: (.Name // ""), severity: (.Severity // "UNKNOWN"),
           title: "\(.Category // "unknown") license \(.Name // "")", pkg: (.PkgName // ""), file: (.FilePath // "")})
  ]
| map(. + {rank: (.severity | rank)})
'

# tv_rank SEVERITY: prints the rank of a severity name, as TV_FINDINGS_JQ
# ranks them: UNKNOWN 0 to CRITICAL 4.
tv_rank() {
    case "$1" in
        CRITICAL | critical) echo 4 ;;
        HIGH | high) echo 3 ;;
        MEDIUM | medium) echo 2 ;;
        LOW | low) echo 1 ;;
        *) echo 0 ;;
    esac
}

# tv_counts FINDINGS RANK REPORT: prints the counts for the summary and the
# run record: findings by class and severity, how many rank at or above
# RANK, the packages Trivy found, the suppressed findings, and the OS.
tv_counts() {
    # shellcheck disable=SC2016 # jq program, not shell
    jq -c --argjson rank "$2" --slurpfile report "$3" '
        def bysev: reduce .[] as $f ({}; .[$f.severity] += 1);
        ($report[0]) as $r
        | {
            findings: length,
            failing: (map(select(.rank >= $rank)) | length),
            vulnerabilities: (map(select(.class == "vulnerability")) | bysev),
            misconfigurations: (map(select(.class == "misconfiguration")) | bysev),
            secrets: (map(select(.class == "secret")) | bysev),
            licenses: (map(select(.class == "license")) | bysev),
            packages: ([($r.Results // [])[] | (.Packages // [])[]] | length),
            misconfiguration_checks: ([($r.Results // [])[] | (.MisconfSummary // {}) | (.Successes // 0) + (.Failures // 0)] | add // 0),
            suppressed: ([($r.Results // [])[] | (.ExperimentalModifiedFindings // [])[]] | length),
            os: ($r.Metadata.OS // null)
          }' <<< "$1"
}

# tv_findings_junit FILE SUITE FINDINGS RANK: writes the findings as JUnit:
# one test case per finding, failed at or above RANK and skipped below it.
tv_findings_junit() {
    local cases
    # shellcheck disable=SC2016 # jq program, not shell
    cases=$(jq -c --argjson rank "$4" '
        map({
            classname: "\(.class): \(.target)",
            name: (.id + (if (.pkg // "") != "" then " in \(.pkg) \(.installed // "")" else "" end)),
            status: (if .rank >= $rank then "failed" else "skipped" end),
            message: (if .rank >= $rank then "\(.severity): \(.title)" else "below fail_on: \(.severity): \(.title)" end),
            detail: ([(.title // empty), (.url // empty),
                      (if (.fixed // "") != "" then "Fixed in \(.fixed)" else empty end),
                      (.message // empty), (if .line then "Line \(.line)" else empty end)]
                     | map(select(. != "")) | join("\n"))
        })' <<< "$3")
    tv_junit "$1" "$2" "${cases}"
}

# tv_print_findings FINDINGS RANK [LIMIT]: prints the findings at or above
# RANK, most severe first, at most LIMIT (default 50) of them.
tv_print_findings() {
    # shellcheck disable=SC2016 # jq program, not shell
    jq -r --argjson rank "$2" --argjson limit "${3:-50}" '
        map(select(.rank >= $rank)) | sort_by(-.rank, .class, .target, .id) | .[:$limit][]
        | "  \(.severity)\t\(.class)\t\(.id)\t\(.target)"
          + (if (.pkg // "") != "" then "\t\(.pkg) \(.installed // "")" else "" end)
          + (if (.fixed // "") != "" then " (fixed in \(.fixed))" else "" end)' <<< "$1"
}

# tv_convert REPORT FORMAT OUTPUT: renders the JSON REPORT in another of
# Trivy's formats with trivy convert. It runs in an empty directory without
# the job's TRIVY_* variables, so no trivy.yaml, .trivyignore or variable
# filters again what the scan already filtered; and with every severity and
# exit code 0, which are also convert's defaults.
tv_convert() {
    local dir="${TV_WORK}/convert"
    rm -rf "${dir}"
    mkdir -p "${dir}"
    (cd "${dir}" && tv_bare "${TV_TRIVY}" convert --format "$2" --output "$3" --exit-code 0 \
        --severity UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL -- "$1") > "${TV_WORK}/convert.log" 2>&1
}

# tv_sarif_root FILE ROOT: sets ROOTPATH, the base the SARIF report's file
# locations are relative to, to ROOT. trivy convert sets it from the JSON
# report's path for a filesystem or repository scan, where the scan itself
# would have set the scanned directory.
tv_sarif_root() {
    local tmp="${TV_WORK}/sarif.tmp"
    # shellcheck disable=SC2016 # jq program, not shell
    jq --arg root "$2" '.runs |= map(.originalUriBaseIds.ROOTPATH = {uri: $root})' "$1" > "${tmp}" && mv -f "${tmp}" "$1"
}

# tv_tool_json PATH VERSION: describes the trivy that ran, for the run record.
tv_tool_json() {
    local sha=""
    sha=$(sha512sum -- "$1" 2> /dev/null | awk '{ print $1 }') || sha=""
    jq -cn --arg path "$1" --arg version "$2" --arg sha "${sha}" \
        '{name: "trivy", path: $path, version: $version, sha512: (if $sha == "" then null else $sha end)}'
}

# tv_run_record FILE COMMAND OUTCOME EXIT_CODE STARTED: writes a run record,
# the JSON document schemas/run-record.v1.json describes, saying what exactly
# this command scanned, with which Trivy and databases, so a reviewer can tell
# without running it again. It reads what the command set:
#   TV_TRIVY, TV_TRIVY_VERSION  the trivy that ran, and its version
#   TV_ARGS                     the arguments it ran with, as an array
#   TV_TARGET_JSON              what it scanned, as JSON
#   TV_DB_JSON                  trivy version's account of the databases
#   TV_REPORTS                  the report files written
#   TV_COUNTS                   the counts from tv_counts
#   TV_GATE_JSON                the gate's settings
# OUTCOME is passed, findings, findings-reported (findings with report_only)
# or error.
tv_run_record() {
    local file=$1 path reports="[]" args
    for path in ${TV_REPORTS[@]+"${TV_REPORTS[@]}"}; do
        if [[ -f "${path}" ]]; then
            reports=$(jq -c --arg path "${path}" --arg sha "$(tv_sha256 "${path}")" '. + [{path: $path, sha256: $sha}]' <<< "${reports}")
        fi
    done
    args=$(tv_args_json ${TV_ARGS[@]+"${TV_ARGS[@]}"})
    if ! jq -n --arg command "$2" --arg outcome "$3" --argjson code "$4" --arg started "$5" \
        --arg finished "$(date -u +%Y-%m-%dT%H:%M:%SZ)" --arg cwd "$(pwd)" --argjson ci "$(tv_ci_json)" \
        --argjson tool "$(if [[ -n "${TV_TRIVY:-}" ]]; then tv_tool_json "${TV_TRIVY}" "${TV_TRIVY_VERSION:-}"; else echo null; fi)" \
        --argjson target "${TV_TARGET_JSON:-null}" --argjson databases "${TV_DB_JSON:-null}" \
        --argjson reports "${reports}" --argjson counts "${TV_COUNTS:-null}" --argjson gate "${TV_GATE_JSON:-null}" \
        --argjson args "${args}" '{
            schema: "https://github.com/juburr/trivy-orb/blob/main/schemas/run-record.v1.json",
            command: $command, outcome: $outcome, exit_code: $code,
            started_at: $started, finished_at: $finished, ci: $ci, working_directory: $cwd,
            tool: $tool, arguments: $args, target: $target, databases: $databases,
            gate: $gate, counts: $counts, reports: $reports
        }' > "${file}"; then
        echo "WARN: Could not write the run record ${file}." >&2
        return 0
    fi
    echo "Run record: ${file}"
}
