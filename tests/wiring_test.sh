#!/usr/bin/env bash
#
# Checks how the command YAML and the scripts fit together, offline:
#
#   - every PARAM_ variable a script reads is set by each command that runs
#     it, from the parameter of the same name, and every parameter a command
#     declares is passed on to its script (or used in its steps);
#   - every script that evals SCRIPT_TRIVY_LIB gets it;
#   - a command that writes into output_dir stores it as artifacts under
#     trivy-reports/ with when: always;
#   - the variables fetch_db exports are the ones scan reads;
#   - install defaults to the newest release in its checksum table;
#   - the README documents every command and names its GitHub Action;
#   - every run step has a name, as orb-tools review's RC008 asks;
#   - tests/run_command.sh runs each command's own script, with each PARAM_
#     variable once.
#
# Run from a checkout:
#   bash tests/wiring_test.sh

set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "${ROOT}"
FAILURES=0
fail() {
    printf 'FAIL: %s\n' "$*"
    FAILURES=$((FAILURES + 1))
}

# param_vars SCRIPT: the PARAM_ variables SCRIPT reads.
param_vars() {
    grep -oE '\$\{PARAM_[A-Z0-9_]+' "$1" | sed 's/^\${//' || true
}

# unnamed_runs FILE: "<line>: <problem>" for each run step in FILE without a
# name: a "- run:" mapping whose own keys have no name, or an empty one, and
# a "- run: <command>" string, which can't have one.
unnamed_runs() {
    awk '
        function close_step() {
            if (open && !named) { print start ": this run step has no name" }
            open = 0
        }
        {
            match($0, /^ */)
            indent = RLENGTH
            if (open && NF && indent <= dash) { close_step() }
            if ($0 ~ /^ *- run:/) {
                close_step()
                dash = indent
                rest = $0
                sub(/^ *- run:[ ]*/, "", rest)
                if (rest != "") { print FNR ": this run step is a string, which has no name" }
                else { open = 1; named = 0; keys = -1; start = FNR }
                next
            }
            if (open && NF) {
                if (keys < 0) { keys = indent }
                if (indent == keys && $0 ~ /^ *name:/) {
                    value = $0
                    sub(/^ *name:[ ]*/, "", value)
                    gsub(/["\047 ]/, "", value)
                    if (value != "") { named = 1 }
                }
            }
        }
        END { close_step() }
    ' "$1"
}

# params FILE: the parameters a command declares.
params() {
    awk '/^parameters:/ { p = 1; next } /^[^ ]/ { p = 0 } p && /^  [a-z_0-9]+:$/ { sub(/:$/, ""); print $1 }' "$1"
}

# default FILE PARAMETER: the default of PARAMETER in FILE, without quotes.
default() {
    awk -v name="  $2:" '$0 == name { p = 1; next } p && /^  [^ ]/ { exit } p && /^    default:/ { sub(/^    default: */, ""); gsub(/"/, ""); print; exit }' "$1"
}

for yml in src/commands/*.yml; do
    command=${yml##*/}
    command=${command%.yml}
    mapfile -t declared < <(params "${yml}")
    mapfile -t scripts < <(grep -oE 'command: << include\(scripts/[^)]+\.sh\) >>' "${yml}" \
        | sed -E 's/command: << include\(([^)]+)\) >>/\1/' | sort -u)
    passed=$(grep -oE 'PARAM_[A-Z0-9_]+: << parameters\.[a-z0-9_]+ >>' "${yml}" || true)
    while IFS= read -r line; do
        [[ -z "${line}" ]] && continue
        var=${line%%:*}
        name=${line##*parameters.}
        name=${name% >>}
        if [[ "${var}" != "PARAM_${name^^}" ]]; then
            fail "${command}: ${var} is set from parameters.${name}"
        fi
    done <<< "${passed}"
    for script in ${scripts[@]+"${scripts[@]}"}; do
        mapfile -t read_vars < <(param_vars "src/${script}" | sort -u)
        for var in ${read_vars[@]+"${read_vars[@]}"}; do
            if ! grep -qE "^ +${var}: << parameters\.[a-z0-9_]+ >>$" "${yml}"; then
                fail "${command}: src/${script} reads ${var}, which ${command}.yml doesn't set"
            fi
        done
        if grep -q 'SCRIPT_TRIVY_LIB' "src/${script}" \
            && ! grep -q 'SCRIPT_TRIVY_LIB: << include(scripts/lib/trivy.sh) >>' "${yml}"; then
            fail "${command}: src/${script} needs SCRIPT_TRIVY_LIB, which ${command}.yml doesn't pass"
        fi
    done
    for name in ${declared[@]+"${declared[@]}"}; do
        if ! grep -qE "<< parameters\.${name} >>" "${yml}"; then
            fail "${command}: the parameter ${name} is never used"
        fi
    done
    if grep -q 'parameters.output_dir' "${yml}"; then
        if ! grep -qE '^ +destination: trivy-reports$' "${yml}" || ! grep -qE '^ +path: << parameters\.output_dir >>$' "${yml}"; then
            fail "${command}: doesn't store output_dir as artifacts under trivy-reports/"
        fi
        if [[ "$(grep -c 'when: always' "${yml}")" -lt "$(grep -cE '^ +- store_(artifacts|test_results):' "${yml}")" ]]; then
            fail "${command}: a store step doesn't run when the step fails (when: always)"
        fi
    fi
    if ! grep -q "### \`trivy/${command}\`" README.md 2> /dev/null; then
        fail "${command}: the README has no section for it"
    fi
    if ! grep -q "juburr/trivy-orb/actions/${command}@" README.md 2> /dev/null; then
        fail "${command}: the README doesn't name its GitHub Action, juburr/trivy-orb/actions/${command}"
    fi
    while IFS= read -r problem; do
        [[ -n "${problem}" ]] && fail "${yml}:${problem}"
    done < <(unnamed_runs "${yml}")
done

# What fetch_db exports, scan reads: the cache directory, and what fetch_db
# fetched there, so scan skips updating it.
for var in TRIVY_CACHE_DIR TRIVY_ORB_DB_DIR TRIVY_ORB_JAVA_DB_DIR TRIVY_ORB_CHECKS_DIR; do
    grep -q "tv_export ${var} " src/scripts/fetch_db.sh || fail "fetch_db doesn't export ${var}"
done
grep -q 'TRIVY_CACHE_DIR:-' src/scripts/lib/trivy.sh || fail "scan doesn't read TRIVY_CACHE_DIR"
for var in TRIVY_ORB_DB_DIR TRIVY_ORB_JAVA_DB_DIR TRIVY_ORB_CHECKS_DIR; do
    grep -q "${var}:-" src/scripts/scan.sh || fail "scan doesn't read ${var}"
done
# run_command.sh runs the script named after the command, such as
# fetch_db.sh between fetch_db's two cache key steps.
grep -q 'command: << include(scripts/fetch_db.sh) >>' src/commands/fetch_db.yml \
    || fail "fetch_db.yml doesn't run scripts/fetch_db.sh, which run_command.sh picks for it"

# install defaults to the newest release it can verify.
newest=$(sed -n '/^declare -A sha512sums=($/,/^)$/p' src/scripts/install.sh | grep -oE '^    \["[0-9.]+/' \
    | tr -d ' ["/' | sort -uV | tail -n 1)
if [[ "$(default src/commands/install.yml version)" != "${newest}" ]]; then
    fail "install defaults to version $(default src/commands/install.yml version), not ${newest}, the newest in the checksum table"
fi

# tests/run_command.sh, which test-deploy.yml runs the steps that must fail
# with, picks each command's own script. /dev/null/none can't be a
# directory, so the script stops at cd, after naming what it would run.
for yml in src/commands/*.yml; do
    grep -q '^  working_dir:$' "${yml}" || continue
    command=${yml##*/}
    command=${command%.yml}
    running=$(bash tests/run_command.sh "${command}" working_dir=/dev/null/none 2> /dev/null | awk 'NR == 1' || true)
    if [[ "${running}" != "Running scripts/${command}.sh in /dev/null/none with "* ]]; then
        fail "run_command.sh ${command} doesn't run scripts/${command}.sh: ${running:-it printed nothing}"
    fi
    repeated=$(tr ' ' '\n' <<< "${running#* with }" | grep -oE '^PARAM_[A-Z0-9_]+=' | sort | uniq -d | tr -d '=' | tr '\n' ' ' || true)
    if [[ -n "${repeated}" ]]; then
        fail "run_command.sh ${command} sets ${repeated% } more than once"
    fi
done

if [[ "${FAILURES}" -gt 0 ]]; then
    echo "${FAILURES} failure(s)"
    exit 1
fi
echo "ok: every command passes every parameter its scripts read, uses every parameter it declares, stores its reports, names its run steps, and hands the next command what it reads"
