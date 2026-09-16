#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Native routed LAN over real TUN devices (Linux, root).
# Usage: sudo bash scripts/ci_e2e/run_native_routes_test.sh /path/to/mqvpn
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
MQVPN="$(realpath "${1:-$SCRIPT_DIR/../../build/mqvpn}")"
source "$SCRIPT_DIR/sanitizer_check.sh"
[[ $EUID == 0 && -x "$MQVPN" && -c /dev/net/tun ]] || {
    echo "Requires root, a built mqvpn and /dev/net/tun" >&2
    exit 1
}
WORK="$(mktemp -d /tmp/mqvpn-native.XXXXXX)"
NS_S="mqr-s-$$"
NS_C="mqr-c-$$"
NS_L="mqr-l-$$"
SERVER_PID=""
CLIENT_PID=""
created=()

cleanup() {
    local rc=$?
    trap - EXIT
    stop_and_check_sanitizer "$CLIENT_PID" client "$WORK/client.log" || rc=1
    stop_and_check_sanitizer "$SERVER_PID" server "$WORK/server.log" || rc=1
    for ns in "${created[@]}"; do ip netns del "$ns" 2>/dev/null || true; done
    if [[ $rc != 0 ]]; then
        tail -n 50 "$WORK/server.log" "$WORK/client.log" 2>/dev/null || true
        echo "Failure logs retained in $WORK" >&2
    else
        rm -rf -- "$WORK"
    fi
    exit "$rc"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

for ns in "$NS_S" "$NS_C" "$NS_L"; do
    ip netns add "$ns"
    created+=("$ns")
    ip -n "$ns" link set lo up
done
# Create each pair inside its namespace; no host interfaces or routes change.
ip -n "$NS_S" link add transport type veth peer name transport netns "$NS_C"
ip -n "$NS_C" link add lan type veth peer name lan netns "$NS_L"
ip -n "$NS_S" addr add 10.255.0.1/24 dev transport
ip -n "$NS_C" addr add 10.255.0.2/24 dev transport
ip -n "$NS_S" link set transport up
ip -n "$NS_C" link set transport up
ip -n "$NS_C" addr add 10.50.1.1/24 dev lan
ip -n "$NS_L" addr add 10.50.1.10/24 dev lan
ip -n "$NS_C" -6 addr add fd50:1::1/64 dev lan nodad
ip -n "$NS_L" -6 addr add fd50:1::10/64 dev lan nodad
ip -n "$NS_C" link set lan up
ip -n "$NS_L" link set lan up
ip -n "$NS_L" route add default via 10.50.1.1
ip -n "$NS_L" -6 route add default via fd50:1::1
ip -n "$NS_S" addr add 10.60.0.1/32 dev lo
ip -n "$NS_S" -6 addr add fd60::1/128 dev lo nodad
# Forwarding applies only to the client-router namespace. No NAT is configured.
ip netns exec "$NS_C" sysctl -qw net.ipv4.ip_forward=1 net.ipv6.conf.all.forwarding=1
ip netns exec "$NS_C" sysctl -qw net.ipv4.conf.all.rp_filter=0 net.ipv4.conf.default.rp_filter=0
ip netns exec "$NS_S" sysctl -qw net.ipv4.conf.all.rp_filter=0 net.ipv4.conf.default.rp_filter=0

cat >"$WORK/server.conf" <<EOF
[Interface]
Listen = 10.255.0.1:4443
Subnet = 10.0.0.0/24
Subnet6 = fd00::/112
[TLS]
Cert = $SCRIPT_DIR/../../tests/certs/test.crt
Key = $SCRIPT_DIR/../../tests/certs/test.key
[Auth]
User = router:native-route-test-key
[Route]
User = router
Prefix = 10.50.1.0/24
[Route]
User = router
Prefix = fd50:1::/64
EOF
cat >"$WORK/client.conf" <<EOF
[Interface]
NoRoutes = true
Reconnect = false
[Server]
Address = 10.255.0.1:4443
Insecure = true
[Auth]
Key = native-route-test-key
User = router
[Hybrid]
Tcp = raw
EOF

wait_tun() {
    local ns=$1 pid=$2
    for ((i=0; i<100; i++)); do
        kill -0 "$pid" 2>/dev/null || return 1
        if ip -n "$ns" -4 addr show dev mqvpn0 2>/dev/null | grep -q 'inet ' &&
           ip -n "$ns" -6 addr show dev mqvpn0 2>/dev/null | grep -q 'fd00:'; then
            return 0
        fi
        sleep 0.1
    done
    echo "TUN did not become ready in $ns" >&2
    return 1
}
start_client() {
    ip netns exec "$NS_C" "$MQVPN" --config "$WORK/client.conf" >>"$WORK/client.log" 2>&1 &
    CLIENT_PID=$!
    wait_tun "$NS_C" "$CLIENT_PID"
    ip -n "$NS_C" route replace 10.60.0.1/32 dev mqvpn0
    ip -n "$NS_C" -6 route replace fd60::1/128 dev mqvpn0
}
check_connectivity() {
    ip netns exec "$NS_S" ping -n -I 10.60.0.1 -c 2 -W 2 10.50.1.10
    ip netns exec "$NS_S" ping -n -6 -I fd60::1 -c 2 -W 2 fd50:1::10
    ip netns exec "$NS_L" ping -n -I 10.50.1.10 -c 2 -W 2 10.60.0.1
    ip netns exec "$NS_L" ping -n -6 -I fd50:1::10 -c 2 -W 2 fd60::1
}

ip netns exec "$NS_S" "$MQVPN" --config "$WORK/server.conf" >"$WORK/server.log" 2>&1 &
SERVER_PID=$!
wait_tun "$NS_S" "$SERVER_PID"
ip -n "$NS_S" route add 10.50.1.0/24 dev mqvpn0
ip -n "$NS_S" -6 route add fd50:1::/64 dev mqvpn0
start_client
check_connectivity

stop_and_check_sanitizer "$CLIENT_PID" client "$WORK/client.log"
CLIENT_PID=""
# Wait for request/connection teardown before claiming the routed principal again.
sleep 1
start_client
check_connectivity
echo "PASS: native LAN routing, IPv4/IPv6 both directions and reconnect"
