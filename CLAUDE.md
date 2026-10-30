# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is an unofficial CircleCI orb, and set of GitHub Actions, for Trivy, Aqua Security's scanner for vulnerabilities, misconfigurations, secrets and licenses in container images, filesystems, repositories, infrastructure as code and SBOMs. The orb installs a checksum-verified Trivy, caches its databases, and wraps the scan with a severity gate and reports: `install`, `fetch_db`, `scan`, `login` and `logout`.

## Development Commands

```bash
# Pack the orb from source into a single file, and validate it
circleci orb pack src/ > orb.yml
circleci orb validate orb.yml

# Lint
yamllint .
shellcheck src/scripts/*.sh src/scripts/lib/*.sh actions/*.sh tests/*.sh

# Tests (offline; jq, and python3 with jsonschema for the run record schema)
for t in tests/*_test.sh; do bash "$t" || break; done

# Run one command's script with its YAML defaults (what test-deploy.yml uses for steps that must fail)
bash tests/run_command.sh scan target_type=filesystem target=tests/fixtures/vulnerable

# Print checksum table entries for a new Trivy release (needs cosign and jq)
./src/scripts/install_hash.sh -v <version>
```

## Architecture

### Orb Structure (`src/`)

- `@orb.yml` - Orb metadata (version 2.1)
- `commands/` - `install`, `fetch_db`, `scan`, `login`, `logout`, one script each in `scripts/`
- `scripts/lib/trivy.sh` - Helpers shared by the command scripts, passed to each step as `SCRIPT_TRIVY_LIB: << include(scripts/lib/trivy.sh) >>` and `eval`ed after a check that it is set. Only defines functions and variables; no `set` line. Its state lives in `TV_` variables: Trivy reads every `TRIVY_<FLAG>` environment variable as that flag.
- `scripts/db_cache_key.sh` - Writes the files `fetch_db`'s cache keys are computed from
- `examples/` - Usage examples, pinned to the orb's current version
- `../schemas/run-record.v1.json` - The run record's JSON Schema. Its URL is in every run record, so fields are only ever added within v1.
- `../actions/<command>/action.yml` - The GitHub Action for each command (see below)

### Install (`scripts/install.sh`, `install_hash.sh`)

`install.sh` follows the layout every juburr orb's install.sh shares: a tool definition, the shared install logic (byte-identical across the orbs; never edit it here alone), and the `sha512sums` table keyed `"<version>/<arch>"`, holding the SHA-512 of the `trivy` binary inside `trivy_<version>_Linux-64bit.tar.gz` or `_Linux-ARM64.tar.gz`. `tests/install_test.sh` is the shared install contract; its tool fixture section adds Trivy's own checks. `scripts/cache_key.sh` is shared too. The tool definition:

- **Compromised releases.** `TRIVY_COMPROMISED_VERSIONS` (0.69.4, 0.69.5, 0.69.6; GHSA-69fq-xp46-6x23) is checked against `PARAM_VERSION`, expanded as the shared logic expands it, before the shared logic reads it, so every `verify_checksums` mode refuses them before downloading. 0.69.4 was published on 2026-03-19 with stolen credentials, through GitHub Releases, deb/rpm and get.trivy.dev; 0.69.5 and 0.69.6 were Docker Hub images only.
- **Mirror.** `tool_install` reads `download_base_url` (`trivy_download_base_url`), an https mirror that replaces `https://github.com` in the release URL, refusing credentials, a query or a fragment, then runs the shared single-binary install.
- **Smoke test.** `tool_version` runs `trivy --version` with a cache directory that doesn't exist, so a job's restored databases (or a broken one) never decide whether the binary works. It makes no network call.

The table starts at 0.69.2: the GitHub releases before it have no assets left. `install_hash.sh`'s `verify_upstream` requires, for each release:

1. cosign verifying `trivy_<version>_checksums.txt.sigstore.json` for the exact identity `https://github.com/<repository>/.github/workflows/reusable-release.yaml@refs/tags/v<version>` and issuer `https://token.actions.githubusercontent.com`. The repository is `aquasecurity/trivy`, except 0.69.2's, `aquasecurity/private-trivy` (`trivy_release_repository`).
2. The list's transparency log time at least `TRIVY_MIN_RELEASE_AGE_DAYS` (default 7) days ago: 0.69.4 was signed by the real release workflow, and was online about three hours.
3. The archive's SHA-256 in that list.

It refuses the compromised releases. To add a release: run `install_hash.sh -v <version>` once it is 7 days old, paste the entries into the table, newest first, and move the default in `install.yml` and `actions/install/action.yml` (and the README's pins) when it is the newest. The `install-hash` job in `.github/workflows/actions.yml` runs it for the default and checks it prints the table's entries.

### Command scripts (`src/scripts/`)

- **`scan.sh`** checks every parameter before trivy runs (exit 2), then runs `trivy <target_type> [options] --cache-dir D --format json --output <work>/report.json --exit-code 0 --skip-version-check --disable-telemetry [--list-all-pkgs --show-suppressed --no-progress] -- <target>`.
  - **Flags per command.** `trivy config` takes no `--scanners`, `--list-all-pkgs`, `--show-suppressed`, `--no-progress`, `--ignore-unfixed`, `--vex`, `--pkg-types` or database flags, and `trivy sbom` no `--skip-dirs`, `--skip-files` or `--skip-check-update`; an unknown flag is fatal. Parameters that don't apply are refused.
  - **Exit codes.** Trivy exits 1 for every fatal error, the same as `--exit-code 1` for findings, so the scan always runs with `--exit-code 0`, and the verdict comes from the JSON report. A non-zero exit is an error.
  - **Findings** (`TV_FINDINGS_JQ`): every vulnerability, misconfiguration with status FAIL, secret and license left after Trivy's filters, ranked UNKNOWN 0 to CRITICAL 4; those at or above `fail_on` fail the step unless `report_only`. Licenses count too, which Trivy grades by category.
  - **No verdict** fails the step whatever `report_only` says: trivy failing, a report without SchemaVersion 2, a vulnerability database missing or older than `max_db_age_days` (Trivy uses a stale one silently under `--skip-db-update`), and a scan that checked nothing (no packages and no OS for a vulnerability scan; no infrastructure as code for a misconfiguration-only scan) unless `allow_empty`. A fallback to the checks built into trivy (`Falling back to embedded checks` in its log) is a warning.
  - **Databases.** Updates are skipped for what `fetch_db` fetched into the same cache directory in this job (`TRIVY_ORB_DB_DIR`, `TRIVY_ORB_JAVA_DB_DIR`, `TRIVY_ORB_CHECKS_DIR`), so parallel scans never download over each other (Trivy removes the database directory before extracting a new one); `offline` skips all three and adds `--offline-scan`.
  - **Reports.** The JSON report is `<report_name>.json`; `formats` renders the others with `trivy convert` (`tv_convert`), in an empty directory and with the job's `TRIVY_*` variables unset (`tv_bare`), so no `trivy.yaml`, `.trivyignore` or `TRIVY_SEVERITY` filters again what the scan already filtered. convert sets SARIF's `ROOTPATH` from the JSON file's path for filesystem and repository reports, so `tv_sarif_root` sets it to the scanned directory. JUnit (`tv_findings_junit`) has a failed case per finding at or above `fail_on` and a skipped one below. An earlier run's reports with the same `report_name` are removed first.
  - **Ignore files.** Trivy reads `.trivyignore` from the working directory, but never `.trivyignore.yaml`, so the script passes that one when there is no `.trivyignore`.
  - **Ambient configuration.** A `trivy.yaml` in the working directory and the job's `TRIVY_*` variables still set the flags the script doesn't pass. It passes `--severity` only when `severity` is set: an empty `--severity` filters out everything.
  - A leading `~` in a path target or `input` is the home directory.
- **`fetch_db.sh`** runs `trivy image --download-db-only --scanners vuln` (and `--download-java-db-only` with `java_db`; and a `trivy config` scan of an empty directory with `checks_bundle`, since Trivy has no option to fetch the bundle alone), each up to three times, 15 and 30 seconds apart: a registry limiting pulls often works a moment later. Trivy downloads only when the copy there is due. Then it checks the vulnerability database's age, and exports `TRIVY_CACHE_DIR`, the `TRIVY_ORB_*_DIR` markers and the repositories given (`TRIVY_DB_REPOSITORY`, ...).
- **`db_cache_key.sh`** ports grype-orb's database cache key design. CircleCI never replaces a saved cache, so the restore keys try `location` + today's date, then the two days before, then `location` alone, and the save key is `location` + the vulnerability database's build date + its, the Java database's and the checks bundle's identity from `trivy version --format json`. `location` holds HOME, `cache_dir` as given (the cache steps expand `~` but not environment variables), the working directory when it is relative, and what is fetched from where.
- **`login.sh`** pipes the password to `trivy registry login --username U --password-stdin -- REGISTRY` with xtrace off, and without the job's `TRIVY_USERNAME`, `TRIVY_PASSWORD` and `TRIVY_REGISTRY_TOKEN` (a `TRIVY_PASSWORD` conflicts with `--password-stdin`). Trivy reads `--username` as a CSV record, so a username with a comma or double quote is refused. Login checks the credentials with the registry. **`logout.sh`** runs `trivy registry logout`.

### Shared helpers (`scripts/lib/trivy.sh`)

- Ported from go-security-orb's: `tv_subst`, `tv_bool`, `split_shell_words`/`tv_words`, `tv_match` (C locale), `tv_require_jq`, `tv_output`, `tv_uint`, `tv_junit`, `tv_gate`, `tv_plural`, `tv_tail`, `tv_export`, `tv_env_var_name`, `tv_json_is` (never `jq -e` on a tool's output: jq 1.6 exits 0 on an empty file), `tv_sha256`, `tv_url_public`, `tv_ci_json`, `tv_args_json`.
- Trivy's own: `tv_list`, `tv_bare`, `tv_trivy`, `tv_cache_dir` (the parameter, then `TRIVY_CACHE_DIR`, then `$XDG_CACHE_HOME/trivy` or `~/.cache/trivy`), `tv_db_metadata` (`trivy version --format json`, which reads local metadata only), `tv_epoch`, `tv_db_fresh`, `TV_FINDINGS_JQ`, `tv_rank`, `tv_counts`, `tv_findings_junit`, `tv_print_findings`, `tv_convert`, `tv_sarif_root`, `tv_tool_json`, `tv_run_record`.
- Keep `schemas/run-record.v1.json` in step with `tv_run_record`; `tests/commands_test.sh` checks every run record it writes against it.

### GitHub Actions (`actions/`)

Every command has a composite action of the same name in `actions/<command>/action.yml`, with inputs identical to the command's parameters (names and defaults). Each step passes inputs to the orb's script as `PARAM_*` environment variables, as the command does, and runs it with `bash "${GITHUB_ACTION_PATH}/../run_script.sh" SCRIPT SCRIPT_TRIVY_LIB=<lib>`. Inputs never appear inside a `run:` script. `install` restores and saves `actions/cache` with the command's key ingredients; `fetch_db` computes its keys with `db_cache_key.sh`, as grype-orb's `update_database` action does. `scan` names its artifact `trivy-reports-<report_name>-<random>` and uploads `output_dir` with `actions/upload-artifact` under `if: always()` and `store_artifacts`; `no_output_timeout` is CircleCI's. Every `uses:` is pinned to a commit SHA with its version in a comment.

`actions/run_script.sh` and `tests/actions_test.sh` are identical in every juburr orb that ships actions; never edit them here alone. The action inputs were generated from the command YAML; keep them in sync by hand or with an equivalent generator, and quote any default a YAML 1.1 reader would take for a boolean or number. The action descriptions leave out "Environment variables are expanded", since there is no CircleCI CLI on GitHub's runners. `tests/actions_test.sh` checks all of this.

### Tests

- `tests/install_test.sh`: the shared install contract, then the refusal of compromised releases in every mode and `download_base_url`.
- `tests/commands_test.sh`: every command script through `tests/run_command.sh` (so with its YAML defaults), against a stand-in trivy that records each call's arguments, working directory and `TRIVY_*` variables, copies a fixture report from `tests/fixtures/reports`, writes database metadata, and renders minimal convert output. It checks the arguments per target type, the gate, every way a scan has no verdict, the database flags, the reports, the input checks, `fetch_db`'s retries and exports, the cache key files and login's password handling, and validates the run records against the schema. It passes with bash 4.0, 4.3 and 5 first on the `PATH`.
- `tests/wiring_test.sh`: every `PARAM_` a script reads is passed, every parameter is used, reports are stored, run steps are named, the README documents every command and action, `fetch_db` exports what `scan` reads, and install defaults to the newest table entry.
- `tests/fixtures/vulnerable` (lodash 4.17.15, a Dockerfile running as root, a privileged pod) and `tests/fixtures/clean` are what CI scans with the real Trivy. CI copies them out of `tests/`, since Trivy skips secrets under paths starting with "test", and writes a random GitHub token into the vulnerable one at run time, so the repository holds no secret.

### CI Pipeline

- `.circleci/config.yml` - Setup workflow: `test-install`, `test-env-subst` (env subst and shell conventions), `test-commands` (command and wiring tests), `test-actions`, orb-tools lint, pack and review (`orb_name: trivy`), shellcheck.
- `.circleci/test-deploy.yml` - `install-test` (the default, its table entry, the cache, 0.69.2), `checksum-test` (unlisted and compromised releases refused before downloading; a local HTTPS mirror serving the real release, then one with a changed binary), `arm64-test`, `fetch-db-test` (databases, exports, a second fetch that downloads nothing; persisted to the workspace), `scan-test` (the fixtures, every report, an SBOM scan, a config scan, and alpine 3.19.0 by digest, end of life), `offline-test` (the workspace's databases with mirror.gcr.io, ghcr.io and check.trivy.dev blocked), `login-test` (a private image in a `registry:2` with htpasswd, refused after logout). Publishing runs on `v*` tags.
- `.github/workflows/actions.yml` - The same with the actions on GitHub's runners: `offline-tests`, `install` (amd64 and arm64), `install-from-cache`, `install-hash` (install_hash.sh with cosign from cosign-orb's action), `scan` (also an image archive from `docker save`), `offline`, `login`.

## Linting

YAML linting uses `.yamllint` config (extends "relaxed", 200-char line limit). Shell scripts are linted with shellcheck via the CI pipeline.

Scripts pass parameter values to `circleci env subst` on stdin, as `tv_subst` does. Passed as an argument, a value starting with `-` is parsed as a CLI flag. `tests/env_subst_test.sh` enforces this.

## Shell conventions

Every script in `src/scripts/` except the shared install code follows the conventions all juburr orbs share. `tests/shell_conventions_test.sh` checks the mechanical ones; it is identical in every orb, so never edit it.

- Line 1 is `#!/bin/bash` and the first command is `set -euo pipefail` (the library in `lib/` has no `set` line). No `set +o history`, never xtrace; `login.sh` runs `set +o xtrace` with a one-line comment.
- Under `-u`, use `${VAR:-}` for variables that may be unset. `PARAM_*` values the command YAML always sets are read directly, so tests that run a script directly must set every one of them (`tests/run_command.sh` sets them from the YAML).
- Expand an array that can be empty as `${arr[@]+"${arr[@]}"}`, not `"${arr[@]}"`: under `-u`, bash before 4.4 treats an empty array as unset and aborts with "unbound variable", and the orb supports bash 4.0+. Bash 4.0 also treats an empty `"$@"` as unbound, so copy `"$@"` into an array only when `$#` is non-zero.
- `ERROR: ` and `WARN: ` messages go to stderr (`>&2` on every line of the message); everything else goes to stdout. Every non-zero exit prints an `ERROR:` line first, unless the failing tool already explained itself. Input checks exit 2.
- `$BASH_ENV` exports use `printf 'export %s=%q\n'`; `eval` only runs orb code (`"${SCRIPT_TRIVY_LIB}"`). Secrets never go on a command line: the registry password reaches trivy on stdin.
- Temporary files and directories come from `mktemp` and are removed by one EXIT trap per script.
- The scripts must work with jq 1.6: never `jq -e` on a tool's output.

## Naming

Command names say what they do (`install`, `fetch_db`, `scan`, `login`, `logout`). Parameters that map onto one Trivy flag take its long name in snake_case (`scanners`, `severity`, `ignore_unfixed`, `ignore_file` for `--ignorefile`, `vex`, `pkg_types`, `skip_dirs`, `skip_files`, `image_src`, `platform`, `input`, `cache_dir`, `timeout`, `db_repository`, `java_db_repository`, `checks_bundle_repository`); `target_type` is the Trivy command and `target` its argument. Plumbing matches the other juburr orbs: `working_dir`, `extra_args`, `output_dir`, `report_name`, `formats`, `junit`, `run_record`, `report_only`, `store_artifacts`, `max_db_age_days`; `fail_on` as in grype-orb and stig-scanner-orb; credentials are `env_var_name` parameters named `username` and `password` (defaults `REGISTRY_USERNAME`/`REGISTRY_PASSWORD`).

## Verification

Before committing changes, verify work locally if tools are available on the system:
- Run `shellcheck src/scripts/*.sh src/scripts/lib/*.sh actions/*.sh tests/*.sh` and `yamllint .`
- Run every `tests/*_test.sh`, also with bash 4.0 and 4.3 first on the `PATH`
- Run `circleci orb pack src/ > orb.yml && circleci orb validate orb.yml`, and validate `.circleci/test-deploy.yml` with the packed orb spliced in under `orbs.trivy-orb`
- For changes to a command, also run it with the real Trivy against `tests/fixtures`, as `test-deploy.yml` does
