#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Real H3 STREAM, original 4-tuple and selective return routing. Linux/root.
# SOCKET_MATCH=iptables permits equivalent xt_socket testing on kernels without
# CONFIG_NFT_SOCKET; the default exercises the documented production nft rules.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
MQVPN="$(realpath "${1:-$SCRIPT_DIR/../../build/mqvpn}")"
source "$SCRIPT_DIR/sanitizer_check.sh"
[[ $EUID == 0 && -x "$MQVPN" && -c /dev/net/tun ]]
WORK="$(mktemp -d /tmp/mqvpn-transparent.XXXXXX)"
NS_S="mqt-s-$$"; NS_C="mqt-c-$$"; NS_L="mqt-l-$$"; NS_P="mqt-p-$$"
SERVER_PID=""; CLIENT_PID=""; PEER_PID=""; LAN_PID=""; FLOW_PID=""; BLOCK_PID=""
created=()
cleanup() {
    local rc=$?
    trap - EXIT
    for pid in "$PEER_PID" "$LAN_PID" "$FLOW_PID" "$BLOCK_PID"; do
        [[ -z $pid ]] || { kill "$pid" 2>/dev/null || true; wait "$pid" 2>/dev/null || true; }
    done
    stop_and_check_sanitizer "$CLIENT_PID" client "$WORK/client.log" || rc=1
    stop_and_check_sanitizer "$SERVER_PID" server "$WORK/server.log" || rc=1
    for ns in "${created[@]}"; do ip netns del "$ns" 2>/dev/null || true; done
    if [[ $rc != 0 ]]; then
        tail -n 35 "$WORK/server.log" "$WORK/client.log" "$WORK/peer.log" 2>/dev/null || true
        echo "Failure logs: $WORK" >&2
    else
        rm -rf -- "$WORK"
    fi
    exit "$rc"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
for ns in "$NS_S" "$NS_C" "$NS_L" "$NS_P"; do
    ip netns add "$ns"; created+=("$ns"); ip -n "$ns" link set lo up
    ip netns exec "$ns" sysctl -qw net.ipv4.conf.all.rp_filter=0 net.ipv4.conf.default.rp_filter=0
done
ip -n "$NS_S" link add transport type veth peer name transport netns "$NS_C"
ip -n "$NS_C" link add lan type veth peer name lan netns "$NS_L"
ip -n "$NS_S" link add egress type veth peer name egress netns "$NS_P"
ip -n "$NS_S" addr add 10.255.0.1/24 dev transport
ip -n "$NS_C" addr add 10.255.0.2/24 dev transport
ip -n "$NS_C" addr add 10.111.252.1/22 dev lan
ip -n "$NS_L" addr add 10.111.252.25/22 dev lan
ip -n "$NS_S" addr add 192.168.100.1/24 dev egress
ip -n "$NS_P" addr add 192.168.100.50/24 dev egress
for ns in "$NS_S" "$NS_C"; do ip -n "$ns" link set transport up; done
for ns in "$NS_C" "$NS_L"; do ip -n "$ns" link set lan up; done
for ns in "$NS_S" "$NS_P"; do ip -n "$ns" link set egress up; done
ip -n "$NS_L" route add default via 10.111.252.1
ip -n "$NS_P" route add 10.111.252.0/22 via 192.168.100.1
for ns in "$NS_S" "$NS_C"; do ip netns exec "$ns" sysctl -qw net.ipv4.ip_forward=1; done

ip -n "$NS_S" rule add pref 100 fwmark 0x100/0x100 lookup 100
ip -n "$NS_S" route add local 0.0.0.0/0 dev lo table 100
if [[ ${SOCKET_MATCH:-nft} == iptables ]]; then
    ip netns exec "$NS_S" iptables -t mangle -A PREROUTING -i egress -p tcp \
        -m socket --transparent -j MARK --set-xmark 0x100/0x100
else
    ip netns exec "$NS_S" nft -f - <<'EOF'
table ip mqvpn_transparent {
    chain prerouting {
        type filter hook prerouting priority -150; policy accept;
        iifname "egress" meta l4proto tcp socket transparent 1 counter meta mark set meta mark | 0x100
    }
}
EOF
fi

cat >"$WORK/server.conf" <<EOF
[Interface]
Listen = 10.255.0.1:4443
Subnet = 10.0.0.0/24
[TLS]
Cert = $SCRIPT_DIR/../../tests/certs/test.crt
Key = $SCRIPT_DIR/../../tests/certs/test.key
[Auth]
User = test002:transparent-test-key
[Route]
User = test002
Prefix = 10.111.252.0/22
[Hybrid]
Enabled = true
Tcp = stream
Transparent = true
EgressAllow = 192.168.100.0/24
EOF
cat >"$WORK/client.conf" <<EOF
[Interface]
NoRoutes = true
Reconnect = false
[Server]
Address = 10.255.0.1:4443
Insecure = true
[Auth]
Key = transparent-test-key
User = test002
[Hybrid]
Enabled = true
Tcp = stream
Transparent = true
EOF
wait_tun() {
    local ns=$1 pid=$2
    for ((i=0; i<100; i++)); do
        kill -0 "$pid" 2>/dev/null || return 1
        if ip -n "$ns" -4 addr show dev mqvpn0 2>/dev/null | grep -q 'inet '; then return 0; fi
        sleep 0.1
    done
    return 1
}
ip netns exec "$NS_S" "$MQVPN" --config "$WORK/server.conf" >"$WORK/server.log" 2>&1 &
SERVER_PID=$!
wait_tun "$NS_S" "$SERVER_PID"
ip -n "$NS_S" route add 10.111.252.0/22 dev mqvpn0
ip netns exec "$NS_C" "$MQVPN" --config "$WORK/client.conf" >"$WORK/client.log" 2>&1 &
CLIENT_PID=$!
wait_tun "$NS_C" "$CLIENT_PID"
ip -n "$NS_C" route add 192.168.100.0/24 dev mqvpn0

# The peer reports getpeername(), not a proxy header. Keep all eight sockets
# open concurrently; compare both source IP and exact port at the LAN client.
cat >"$WORK/echo.py" <<'PY'
import socket, sys, threading
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind((sys.argv[1], int(sys.argv[2])))
s.listen(32)
open(sys.argv[3], 'w').close()
def serve(c, addr):
    try:
        with c:
            c.sendall(('%s:%d\n' % addr).encode())
            while data := c.recv(65536):
                c.sendall(data)
    finally:
        print('closed %s:%d' % addr, flush=True)
while True:
    c, addr = s.accept()
    threading.Thread(target=serve, args=(c, addr), daemon=True).start()
PY
ip netns exec "$NS_P" python3 "$WORK/echo.py" 192.168.100.50 443 "$WORK/peer.ready" >"$WORK/peer.log" 2>&1 &
PEER_PID=$!
ip netns exec "$NS_L" python3 "$WORK/echo.py" 10.111.252.25 8443 "$WORK/lan.ready" >"$WORK/lan.log" 2>&1 &
LAN_PID=$!
for ((i=0; i<50; i++)); do
    [[ -f $WORK/peer.ready && -f $WORK/lan.ready ]] && break
    sleep 0.1
done
ip netns exec "$NS_L" python3 - "$WORK" <<'PY' &
import socket, sys, pathlib, time
work = pathlib.Path(sys.argv[1])
flows = []
for port in range(53000, 53008):
    c = socket.socket()
    c.settimeout(10)
    c.bind(('10.111.252.25', port))
    c.connect(('192.168.100.50', 443))
    f = c.makefile('rb')
    observed = f.readline().decode().strip()
    assert observed == '10.111.252.25:%d' % port, observed
    payload = bytes(range(256)) * 256
    c.sendall(payload)
    assert f.read(len(payload)) == payload
    flows.append((c, f))
(work / 'flows.ready').touch()
deadline = time.monotonic() + 15
while not (work / 'flows.close').exists():
    assert time.monotonic() < deadline
    time.sleep(.05)
for c, f in flows:
    c.shutdown(socket.SHUT_WR)
    assert f.read() == b''
    f.close(); c.close()
print('PASS: eight simultaneous H3 flows preserve source IP and ports 53000..53007')
PY
FLOW_PID=$!
for ((i=0; i<100; i++)); do
    [[ -f $WORK/flows.ready ]] && break
    kill -0 "$FLOW_PID" 2>/dev/null || { wait "$FLOW_PID"; exit 1; }
    sleep 0.1
done
[[ -f $WORK/flows.ready ]]
check_raw_return() {
    ip netns exec "$NS_P" ping -n -c 2 -W 2 10.111.252.25
    ip netns exec "$NS_P" python3 - <<'PY'
import socket
with socket.create_connection(('10.111.252.25', 8443), timeout=5) as c:
    with c.makefile('rb') as f:
        assert f.readline().startswith(b'192.168.100.50:')
        c.sendall(b'central-to-LAN\n')
        assert f.readline() == b'central-to-LAN\n'
PY
}
check_raw_return
touch "$WORK/flows.close"
wait "$FLOW_PID"
FLOW_PID=""
check_raw_return
grep -q 'connect-tcp: transparent flow user=test002 src=10.111.252.25:53000' "$WORK/server.log"

# Occupy an original source tuple on the server: the flow must fail, never
# reach the peer under a substituted source, and leave the H3 tunnel usable.
ip netns exec "$NS_S" python3 - "$WORK/block.ready" <<'PY' &
import socket, sys, time
s = socket.socket()
s.setsockopt(socket.SOL_IP, socket.IP_TRANSPARENT, 1)
s.bind(('10.111.252.25', 53020))
open(sys.argv[1], 'w').close()
time.sleep(30)
PY
BLOCK_PID=$!
for ((i=0; i<50; i++)); do [[ -f $WORK/block.ready ]] && break; sleep 0.1; done
[[ -f $WORK/block.ready ]]
ip netns exec "$NS_L" python3 - <<'PY'
import socket
with socket.socket() as c:
    c.settimeout(5)
    c.bind(('10.111.252.25', 53020))
    try:
        c.connect(('192.168.100.50', 443))
        assert c.recv(100) == b'', 'collision silently fell back to another source'
    except (ConnectionResetError, ConnectionRefusedError):
        pass
PY
grep -q 'transparent bind failed src=10.111.252.25:53020' "$WORK/server.log"
kill "$BLOCK_PID"; wait "$BLOCK_PID" 2>/dev/null || true; BLOCK_PID=""
check_raw_return

# Keep two flows alive across session teardown and verify the peer sees closure.
ip netns exec "$NS_L" python3 - "$WORK/teardown.ready" <<'PY' &
import socket, sys, time
flows = []
for port in (53030, 53031):
    c = socket.socket()
    c.settimeout(5)
    c.bind(('10.111.252.25', port))
    c.connect(('192.168.100.50', 443))
    f = c.makefile('rb')
    assert f.readline() == ('10.111.252.25:%d\n' % port).encode()
    flows.append((c, f))
open(sys.argv[1], 'w').close()
time.sleep(30)
PY
FLOW_PID=$!
for ((i=0; i<50; i++)); do [[ -f $WORK/teardown.ready ]] && break; sleep 0.1; done
[[ -f $WORK/teardown.ready ]]
# Restart the authenticated session, then establish another transparent flow.
stop_and_check_sanitizer "$CLIENT_PID" client "$WORK/client.log"
CLIENT_PID=""
for ((i=0; i<50; i++)); do
    [[ $(grep -c 'closed 10.111.252.25:5303[01]' "$WORK/peer.log") == 2 ]] && break
    sleep 0.1
done
[[ $(grep -c 'closed 10.111.252.25:5303[01]' "$WORK/peer.log") == 2 ]]
kill "$FLOW_PID"; wait "$FLOW_PID" 2>/dev/null || true; FLOW_PID=""
ip netns exec "$NS_C" "$MQVPN" --config "$WORK/client.conf" >>"$WORK/client.log" 2>&1 &
CLIENT_PID=$!
wait_tun "$NS_C" "$CLIENT_PID"
ip -n "$NS_C" route replace 192.168.100.0/24 dev mqvpn0
ip netns exec "$NS_L" python3 - <<'PY'
import socket
with socket.socket() as c:
    c.settimeout(5)
    c.bind(('10.111.252.25', 53100))
    c.connect(('192.168.100.50', 443))
    with c.makefile('rb') as f:
        assert f.readline() == b'10.111.252.25:53100\n'
        c.sendall(b'after-reconnect\n')
        assert f.readline() == b'after-reconnect\n'
PY
check_raw_return
echo 'PASS: bind collision fails closed, session teardown closes sockets, reconnect preserves source'
echo "PASS: matching TCP replies reach local sockets; unmatched TCP/ICMP use mqvpn0 during and after Hybrid flows (${SOCKET_MATCH:-nft})"
