#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
usage: scripts/native-lab-validation.sh <riftmap-bin> <config.toml> <output-dir>

Runs repeatable validation evidence collection for an authorized native Linux
lab. By default it performs offline checks and scan --dry-run only. Set
RIFTMAP_LAB_RUN_LIVE=1 to run a live scan, resume, export, and validation-report.

Optional environment:
  RIFTMAP_LAB_EXPECT_ENDPOINTS=<n>  require validate-config target_count == n
  RIFTMAP_LAB_RUN_LIVE=1           run the live scan path
  RIFTMAP_LAB_SKIP_DOCTOR=1        skip doctor for offline dry-run evidence
EOF
}

if [[ $# -ne 3 ]]; then
  usage
  exit 2
fi

BIN="$1"
CONFIG="$2"
OUT="$3"

if [[ ! -x "${BIN}" ]]; then
  echo "riftmap binary not found or not executable: ${BIN}" >&2
  exit 2
fi
if [[ ! -f "${CONFIG}" ]]; then
  echo "config not found: ${CONFIG}" >&2
  exit 2
fi

mkdir -p "${OUT}"

run_capture() {
  local name="$1"
  shift
  printf 'running %s\n' "${name}" >&2
  {
    printf '$'
    printf ' %q' "$@"
    printf '\n'
    "$@"
  } >"${OUT}/${name}.txt" 2>&1
}

run_time_capture() {
  local name="$1"
  shift
  printf 'running %s\n' "${name}" >&2
  {
    printf '$ /usr/bin/time -v'
    printf ' %q' "$@"
    printf '\n'
    /usr/bin/time -v "$@"
  } >"${OUT}/${name}.txt" 2>&1
}

command_json() {
  local name="$1"
  shift
  if command -v "$1" >/dev/null 2>&1; then
    "$@" >"${OUT}/${name}.txt" 2>&1 || true
  else
    printf 'missing command: %s\n' "$1" >"${OUT}/${name}.txt"
  fi
}

cp "${CONFIG}" "${OUT}/config.toml"
uname -a >"${OUT}/uname.txt"
cat /proc/meminfo >"${OUT}/meminfo.txt"
cat /proc/cpuinfo >"${OUT}/cpuinfo.txt"
command_json libpcap-version pkg-config --modversion libpcap

run_capture validate-config "${BIN}" validate-config -c "${CONFIG}"
run_capture estimate "${BIN}" estimate -c "${CONFIG}"
run_capture tc-template "${BIN}" tc-template -c "${CONFIG}"

TARGET_COUNT="$(awk -F': ' '/^target_count: / {print $2}' "${OUT}/validate-config.txt" | tail -n1)"
if [[ -n "${RIFTMAP_LAB_EXPECT_ENDPOINTS:-}" && "${TARGET_COUNT}" != "${RIFTMAP_LAB_EXPECT_ENDPOINTS}" ]]; then
  echo "expected ${RIFTMAP_LAB_EXPECT_ENDPOINTS} endpoints, validate-config reported ${TARGET_COUNT}" >&2
  exit 1
fi

INTERFACE="$(awk -F' = ' '/^interface = / {gsub(/"/, "", $2); print $2; exit}' "${CONFIG}")"
if [[ -n "${INTERFACE}" ]]; then
  ip -s link show dev "${INTERFACE}" >"${OUT}/ip-link-before.txt" 2>&1 || true
  tc -s -j qdisc show dev "${INTERFACE}" >"${OUT}/tc-before.json" 2>&1 || true
  if command -v ethtool >/dev/null 2>&1; then
    ethtool "${INTERFACE}" >"${OUT}/ethtool.txt" 2>&1 || true
    ethtool -k "${INTERFACE}" >"${OUT}/ethtool-offloads.txt" 2>&1 || true
    ethtool -i "${INTERFACE}" >"${OUT}/ethtool-driver.txt" 2>&1 || true
  fi
fi

if [[ "${RIFTMAP_LAB_SKIP_DOCTOR:-0}" == "1" && "${RIFTMAP_LAB_RUN_LIVE:-0}" != "1" ]]; then
  printf 'skipped by RIFTMAP_LAB_SKIP_DOCTOR=1\n' >"${OUT}/doctor.txt"
else
  run_capture doctor "${BIN}" doctor -c "${CONFIG}"
fi
run_time_capture dry-run "${BIN}" scan -c "${CONFIG}" --dry-run

DRY_JOB="$(awk '/^job: / {print $2}' "${OUT}/dry-run.txt" | tail -n1)"
if [[ -n "${DRY_JOB}" && -d "${DRY_JOB}" ]]; then
  du -sb "${DRY_JOB}" >"${OUT}/dry-run-job-size.txt" 2>&1 || true
fi

if [[ "${RIFTMAP_LAB_RUN_LIVE:-0}" == "1" ]]; then
  run_time_capture scan "${BIN}" scan -c "${CONFIG}"
  JOB_DIR="$(awk '/^job: / {print $2}' "${OUT}/scan.txt" | tail -n1)"
  if [[ -z "${JOB_DIR}" || ! -d "${JOB_DIR}" ]]; then
    echo "scan did not report a valid job directory" >&2
    exit 1
  fi
  run_capture status-json "${BIN}" job status --job "${JOB_DIR}" --json
  run_time_capture resume "${BIN}" resume --job "${JOB_DIR}"
  run_capture report-json "${BIN}" report --job "${JOB_DIR}" --json
  run_capture export "${BIN}" export --job "${JOB_DIR}"
  run_capture validation-report "${BIN}" validation-report -c "${CONFIG}" --job "${JOB_DIR}"
  du -sb "${JOB_DIR}" >"${OUT}/job-size.txt" 2>&1 || true
  if [[ -n "${INTERFACE}" ]]; then
    ip -s link show dev "${INTERFACE}" >"${OUT}/ip-link-after.txt" 2>&1 || true
    tc -s -j qdisc show dev "${INTERFACE}" >"${OUT}/tc-after.json" 2>&1 || true
  fi
fi

cat >"${OUT}/README.txt" <<EOF
RiftMap native lab validation artifact

Config: ${CONFIG}
Endpoint count: ${TARGET_COUNT:-unknown}
Live scan run: ${RIFTMAP_LAB_RUN_LIVE:-0}

Review:
- validate-config.txt
- estimate.txt
- doctor.txt
- dry-run.txt and dry-run-job-size.txt for materialization/RSS evidence
- tc-before.json and tc-after.json for qdisc counters when live scan is enabled
- scan.txt, status-json.txt, report-json.txt, export.txt, validation-report.txt when live scan is enabled
EOF

printf 'validation artifacts written to %s\n' "${OUT}"
