#!/usr/bin/env bash
set -euo pipefail

BIN="${1:-target/debug/riftmap}"
NS="riftmap-smoke-$$"
HOST_IF="rmh$$"
PEER_IF="rmp$$"
ROOT="$(mktemp -d)"
SERVER_PID=""

cleanup() {
  if [[ -n "${SERVER_PID}" ]]; then
    kill "${SERVER_PID}" 2>/dev/null || true
  fi
  ip link del "${HOST_IF}" 2>/dev/null || true
  ip netns del "${NS}" 2>/dev/null || true
  rm -rf "${ROOT}"
}
trap cleanup EXIT

if [[ "${EUID}" -ne 0 ]]; then
  echo "netns smoke test requires root or sudo" >&2
  exit 77
fi

if [[ ! -x "${BIN}" ]]; then
  echo "riftmap binary not found or not executable: ${BIN}" >&2
  exit 2
fi

ip netns add "${NS}"
ip link add "${HOST_IF}" type veth peer name "${PEER_IF}"
ip link set "${PEER_IF}" netns "${NS}"
ip addr add 10.255.0.1/30 dev "${HOST_IF}"
ip link set "${HOST_IF}" up
ip netns exec "${NS}" ip addr add 10.255.0.2/30 dev "${PEER_IF}"
ip netns exec "${NS}" ip link set lo up
ip netns exec "${NS}" ip link set "${PEER_IF}" up

tc qdisc replace dev "${HOST_IF}" root tbf rate 10mbit burst 64kb latency 50ms

ip netns exec "${NS}" python3 -u -c '
import socket

listener = socket.socket()
listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
listener.bind(("10.255.0.2", 2222))
listener.listen(8)
while True:
    conn, _ = listener.accept()
    with conn:
        conn.sendall(b"SSH-2.0-RiftMapSmoke\r\n")
' &
SERVER_PID="$!"

for _ in $(seq 1 50); do
  if ip netns exec "${NS}" python3 -c 'import socket; s=socket.create_connection(("10.255.0.2", 2222), 0.1); s.close()' 2>/dev/null; then
    break
  fi
  sleep 0.1
done

cat >"${ROOT}/targets.txt" <<'TARGETS'
10.255.0.2
TARGETS

cat >"${ROOT}/config.toml" <<EOF
[scan]
port = 2222
protocol = "ssh"
services = [
  { port = 2222, protocol = "ssh" },
  { port = 2223, protocol = "ssh" },
]
syn_attempts = 1
source_port = 61000
connect_timeout_ms = 1000
banner_timeout_ms = 1000
banner_max_bytes = 1024
banner_attempts = 1
banner_concurrency = 4
banner_connects_per_second = 10

[targets]
include = ["${ROOT}/targets.txt"]
exclude = []
allow_private = true
max_targets = 4

[network]
interface = "${HOST_IF}"
source_ip = "10.255.0.1"
provider_egress_mbps = 10
application_ratio = 0.80
tc_ratio = 1.0
require_tc = true
accounting = "estimated-wire"

[output]
job_root = "${ROOT}/jobs"
output_all = true
EOF

"${BIN}" estimate -c "${ROOT}/config.toml"
"${BIN}" doctor -c "${ROOT}/config.toml"
"${BIN}" scan -c "${ROOT}/config.toml" --dry-run
SCAN_OUTPUT="$("${BIN}" scan -c "${ROOT}/config.toml")"
echo "${SCAN_OUTPUT}"
JOB_DIR="$(printf '%s\n' "${SCAN_OUTPUT}" | awk '/^job: / {print $2}')"

"${BIN}" job status --job "${JOB_DIR}"
"${BIN}" job status --job "${JOB_DIR}" --json
"${BIN}" resume --job "${JOB_DIR}"
"${BIN}" report --job "${JOB_DIR}"
"${BIN}" report --job "${JOB_DIR}" --json
"${BIN}" validation-report -c "${ROOT}/config.toml" --job "${JOB_DIR}"
"${BIN}" export --job "${JOB_DIR}"
"${BIN}" export --job "${JOB_DIR}"

RESULTS="${JOB_DIR}/results.ndjson"
test -s "${RESULTS}"
grep -q '"state":"open"' "${RESULTS}"
grep -q '"state":"no_response"' "${RESULTS}"
grep -q '"banner_status":"ok"' "${RESULTS}"
grep -q '"banner_text":"SSH-2.0-RiftMapSmoke"' "${RESULTS}"
grep -q '"syn_mss":' "${JOB_DIR}/summary.json"
grep -q '"interface_tx_packets":' "${JOB_DIR}/summary.json"
grep -q '"completed": true' "${JOB_DIR}/summary.json"
grep -q '"pcap_drops": 0' "${JOB_DIR}/summary.json"
