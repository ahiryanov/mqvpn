#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Real H3 STREAM, original 4-tuple and selective return routing. Linux/root.
# SOCKET_MATCH=iptables permits equivalent xt_socket testing on kernels without
# CONFIG_NFT_SOCKET; the default exercises the documented production nft rules.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
MQVPN="$(realpath "${1:-$SCRIPT_DIR/../../build/mqvpn}")"
MQVPN_SERVER="$(realpath "${MQVPN_SERVER:-$MQVPN}")"
source "$SCRIPT_DIR/sanitizer_check.sh"
[[ $EUID == 0 && -x "$MQVPN" && -c /dev/net/tun ]]
WORK="$(mktemp -d /tmp/mqvpn-stream-credit.XXXXXX)"
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
TcpMaxFlows = 1024
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
TcpMaxFlows = 1024
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
ip netns exec "$NS_S" "$MQVPN_SERVER" --config "$WORK/server.conf" >"$WORK/server.log" 2>&1 &
SERVER_PID=$!
wait_tun "$NS_S" "$SERVER_PID"
ip -n "$NS_S" route add 10.111.252.0/22 dev mqvpn0
ip netns exec "$NS_C" "$MQVPN" --config "$WORK/client.conf" --control-port 9091 >"$WORK/client.log" 2>&1 &
CLIENT_PID=$!
wait_tun "$NS_C" "$CLIENT_PID"
ip -n "$NS_C" route add 192.168.100.0/24 dev mqvpn0


# A real peer behind the server sends far more than the advertised H3 window.
cat >"$WORK/peer.py" <<'PY'
import socket, threading, pathlib, sys
work = pathlib.Path(sys.argv[1])
block = bytes(range(256)) * 256
def serve(c):
    try:
        with c:
            command = c.recv(1)
            if command == b'D':
                for _ in range(1024):
                    c.sendall(block)
            else:
                c.sendall(command)
    except (BrokenPipeError, ConnectionResetError):
        pass
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('192.168.100.50', 443)); s.listen(256)
(work / 'peer.ready').touch()
while True:
    c, _ = s.accept()
    threading.Thread(target=serve, args=(c,), daemon=True).start()
PY
ip netns exec "$NS_P" python3 "$WORK/peer.py" "$WORK" >"$WORK/peer.log" 2>&1 &
PEER_PID=$!
for ((i=0; i<50; i++)); do
    [[ -f $WORK/peer.ready ]] && break
    sleep 0.1
done
[[ -f $WORK/peer.ready ]]
ip netns exec "$NS_L" python3 - "$WORK" "$CLIENT_PID" "$NS_C" <<'PY'
import socket, sys, pathlib, time, subprocess, json, threading
work, pid, router = pathlib.Path(sys.argv[1]), int(sys.argv[2]), sys.argv[3]
def rss():
    text = pathlib.Path('/proc/%d/status' % pid).read_text()
    return int(next(s for s in text.splitlines() if s.startswith('VmRSS:')).split()[1]) * 1024
def transport_rx():
    return int(subprocess.check_output(['ip', 'netns', 'exec', router, 'cat',
        '/sys/class/net/transport/statistics/rx_bytes']))
def diag():
    code = r"""import socket,json
s=socket.create_connection(('127.0.0.1',9091),timeout=3)
s.sendall(b'{"cmd":"get_stats"}\n')
data=b''
while True:
    x=s.recv(8192)
    if not x: break
    data+=x
print(data.decode())
"""
    st = json.loads(subprocess.check_output(
        ['ip', 'netns', 'exec', router, 'python3', '-c', code]))
    d = st['stream_diag']; assert d['available'] == 1
    assert d['recv_credit'] == max(0, d['recv_limit'] - d['recv_used'])
    assert d['send_credit'] == max(0, d['send_limit'] - d['send_used'])
    return d

def quick_probe():
    with socket.create_connection(('192.168.100.50', 443), timeout=5) as q:
        q.sendall(b'Q'); assert q.recv(1) == b'Q'
block = bytes(range(256)) * 256
def receive_exact(c, size):
    got = 0
    while got < size:
        data = c.recv(min(65536, size - got))
        assert data, ('unexpected EOF', got, size)
        expected = (block * 2)[got % len(block):got % len(block) + len(data)]
        assert data == expected, ('corrupt data', got)
        got += len(data)
    return got
# One stalled LAN receiver: the H3 queue must plateau and another flow works.
c = socket.socket(); c.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 32768)
c.settimeout(40); c.connect(('192.168.100.50', 443))
base_rx = transport_rx(); c.sendall(b'D')
receive_exact(c, 65536)
samples = []
for _ in range(40):
    samples.append((transport_rx() - base_rx, rss()))
    time.sleep(.1)
quick_probe()
d = diag()
assert 128 * 1024 < d['h3_pending'] < 512 * 1024, ('unread H3 not visible', d)
assert d['tcp_downlink_paused'] >= 1, ('paused TCP not visible', d)
assert d['tcp_downlink_queue_blocks'] > 0, ('quota pause not visible', d)
assert d['tcp_downlink_queued_pbufs'] > 0, ('TCP queue not visible', d)
assert d['tcp_downlink_pause_max_ms'] > 0, ('pause age not visible', d)
peak_rx = max(v[0] for v in samples); peak_rss = max(v[1] for v in samples)
tail_rx = samples[-1][0] - samples[-10][0]
print('paused: transport_rx=%d peak_rss=%d last_second_rx=%d' %
    (peak_rx, peak_rss, tail_rx), flush=True)
assert peak_rx < 24 * 1024**2, ('unbounded transport download', peak_rx)
assert tail_rx < 1024**2, ('transport did not plateau', tail_rx)
assert peak_rss < 160 * 1024**2, ('unbounded client RSS', peak_rss)
receive_exact(c, 64 * 1024**2 - 65536)
assert c.recv(1) == b''; c.close()
quick_probe()
d = diag()
assert d['h3_pending'] == 0 and d['tcp_downlink_paused'] == 0, d
assert d['tcp_downlink_h3_bytes'] >= 64 * 1024**2, d
assert d['tcp_downlink_tcp_bytes'] >= 64 * 1024**2, d
print('PASS: 64 MiB byte-exact download resumes; another flow works while paused')
# Several stalled flows exercise the aggregate credit. Abort them and check
# that the same VPN connection accepts another byte-exact transfer.
flows = []
base_rx = transport_rx()
for _ in range(4):
    q = socket.socket(); q.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 32768)
    q.settimeout(10); q.connect(('192.168.100.50', 443)); q.sendall(b'D')
    flows.append(q)
time.sleep(4)
aggregate_rx = transport_rx() - base_rx
aggregate_rss = rss()
print('four paused: transport_rx=%d rss=%d' % (aggregate_rx, aggregate_rss), flush=True)
assert aggregate_rx < 44 * 1024**2, ('aggregate credit unbounded', aggregate_rx)
assert aggregate_rss < 200 * 1024**2, ('aggregate RSS unbounded', aggregate_rss)
for q in flows: q.close()
time.sleep(.5)
quick_probe()
with socket.create_connection(('192.168.100.50', 443), timeout=40) as q:
    q.sendall(b'D'); receive_exact(q, 64 * 1024**2); assert q.recv(1) == b''
d = diag()
assert d['h3_pending'] == 0 and d['tcp_downlink_paused'] == 0, d
assert d['tcp_downlink_resume_events'] > 0, d
print('PASS: aggregate bounded; cancelled downloads release credit without reconnect')

# The office reproducer: many receivers retain data while independent fast
# transfers and short probes must keep working. Run BEFORE cancelling any
# slow receiver, so a reset/idle eviction cannot masquerade as recovery.
paused, slow, threads = [], [], []
stop = threading.Event()
errors = []
fast_bytes = [0]
slow_bytes = [0]

def open_download():
    q = socket.socket()
    q.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
    q.settimeout(5)
    q.connect(('192.168.100.50', 443)); q.sendall(b'D')
    return q

def slow_reader(q):
    got = 0
    try:
        while not stop.is_set():
            data = q.recv(2048)
            if not data: break
            expected = (block * 2)[got % len(block):got % len(block) + len(data)]
            assert data == expected, ('slow data corruption', got)
            got += len(data); slow_bytes[0] += len(data)
            stop.wait(1)
    except OSError as e:
        if not stop.is_set(): errors.append(('slow', str(e)))

def fast_reader():
    try:
        while not stop.is_set():
            with socket.create_connection(('192.168.100.50', 443), timeout=5) as q:
                q.sendall(b'D')
                got = 0
                while not stop.is_set():
                    data = q.recv(65536)
                    if not data: break
                    expected = (block * 2)[got % len(block):got % len(block) + len(data)]
                    assert data == expected, ('fast data corruption', got)
                    got += len(data); fast_bytes[0] += len(data)
    except Exception as e:
        if not stop.is_set(): errors.append(('fast', str(e)))

before = diag()
try:
    for _ in range(64):
        q = open_download(); paused.append(q); receive_exact(q, 4096)
    for _ in range(32):
        q = open_download(); slow.append(q)
        t = threading.Thread(target=slow_reader, args=(q,), daemon=True)
        t.start(); threads.append(t)
    for _ in range(4):
        t = threading.Thread(target=fast_reader, daemon=True)
        t.start(); threads.append(t)
    samples = []
    successes = 0
    for _ in range(30):
        quick_probe(); successes += 1
        d = diag(); samples.append(d)
        assert d['h3_pending'] <= 32 * 1024**2, ('H3 budget escaped', d)
        assert rss() < 220 * 1024**2, ('client RSS escaped', rss())
        assert not errors, errors
        time.sleep(1)
    assert successes == 30
    assert max(d['tcp_pressure_evicted'] for d in samples) == before['tcp_pressure_evicted'], ('unexpected pressure reset', samples[-1])
    assert fast_bytes[0] >= 16 * 1024**2, ('no fast progress', fast_bytes)
    assert slow_bytes[0] > 0
    assert max(d['tcp_downlink_paused'] for d in samples) >= 64
    assert max(d['tcp_downlink_queued_pbufs'] for d in samples) < 8192
    assert max(d['tcp_downlink_queue_blocks'] for d in samples) > before['tcp_downlink_queue_blocks']
    print('PASS: 64 paused + 32 slow readers coexist with fast byte-exact downloads; '
          '30/30 independent probes; fast_bytes=%d peak_h3=%d peak_tcp_pbufs=%d' %
          (fast_bytes[0], max(d['h3_pending'] for d in samples),
           max(d['tcp_downlink_queued_pbufs'] for d in samples)), flush=True)
finally:
    stop.set()
    for q in paused + slow:
        try: q.shutdown(socket.SHUT_RDWR)
        except OSError: pass
        q.close()
    for t in threads: t.join(6)
time.sleep(1)
quick_probe()
assert not errors, errors
print('PASS: mixed-load connections cleaned up without VPN restart')

# With the historical 32 MiB profile, 144 stopped readers exhaust aggregate
# credit and exercise pressure recovery. The adaptive 256 MiB profile leaves
# credit available: require bounded buffers and uninterrupted probes there,
# without claiming this fixture exercised aggregate exhaustion.
holders = []
before = diag()
try:
    for _ in range(144):
        q = open_download(); holders.append(q)
    deadline = time.monotonic() + 60
    exhausted = False
    restored = False
    peak_pending = 0
    failed_probes = 0
    while time.monotonic() < deadline:
        d = diag()
        peak_pending = max(peak_pending, d['h3_pending'])
        exhausted |= d['recv_credit'] < 16384 and d['h3_pending'] >= 16 * 1024**2
        assert rss() < 220 * 1024**2, ('saturated client RSS escaped', rss())
        try:
            quick_probe()
            if exhausted and d['tcp_pressure_evicted'] > before['tcp_pressure_evicted']:
                restored = True
                break
        except (OSError, AssertionError):
            failed_probes += 1
        time.sleep(1)
    d = diag()
    if exhausted:
        assert restored, ('no bounded pressure recovery', d)
        assert d['tcp_pressure_evicted'] > before['tcp_pressure_evicted'], d
        print('PASS: aggregate saturation recovers without reconnect; '
              'pressure_evicted=%d failed_probes=%d peak_h3=%d' %
              (d['tcp_pressure_evicted'] - before['tcp_pressure_evicted'],
               failed_probes, peak_pending), flush=True)
    else:
        assert d['recv_window'] > 32 * 1024**2, d
        assert failed_probes == 0, ('probes stalled without exhaustion', d)
        assert peak_pending < d['recv_window'], d
        print('PASS: 144 stopped readers remain bounded with available '
              'aggregate credit; saturation not reached; peak_h3=%d' %
              peak_pending, flush=True)
finally:
    for q in holders:
        try: q.shutdown(socket.SHUT_RDWR)
        except OSError: pass
        q.close()
time.sleep(1)
quick_probe()

PY
