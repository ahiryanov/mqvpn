# Transparent Hybrid TCP (Linux, IPv4)

Transparent Hybrid keeps client lwIP and H3 STREAM over MPQUIC, and binds the
server's egress socket to the original LAN source IP **and port**. For example,
the peer sees `10.111.252.25:53000 -> 192.168.100.50:443`.

Enable on **both** client and server:

```ini
[Hybrid]
Enabled = true
Tcp = stream
Transparent = true
```

`Transparent` defaults to `false`; ordinary Hybrid retains its existing wire
format and server-source sockets. JSON: `"hybrid":{"enabled":true,"tcp":"stream",
"transparent":true}`. Library: `mqvpn_config_set_hybrid_transparent(cfg, 1)`.
RAW / CONNECT-IP traffic and its routing remain unchanged. `Transparent` applies
only to flows selected for the STREAM lane; it does not change lane selection.

Server example (in addition to the existing Interface/TLS configuration):

```ini
[Auth]
User = test002:REPLACE_WITH_PERSONAL_KEY
[Route]
User = test002
Prefix = 10.111.252.0/22
[Hybrid]
Enabled = true
Tcp = stream
Transparent = true
EgressAllow = 192.168.100.0/24
```

Client `[Auth]` uses `User = test002` and the matching `Key`. The peer/router must
route `10.111.252.0/22` back through the mqvpn server. Do not SNAT/masquerade these
egress connections if the peer must see the original source. Existing forwarding
and firewall permissions for routed LAN traffic are still required.

## Selective Linux return routing

Run these commands as root **in the server's network namespace**. This example
reserves mark bit `0x100`, routing table `100`, and rule priority `100`; choose
unused values if these are already allocated. Replace `eth1` with the actual
interface receiving replies from the peer/MikroTik. Repeat the socket rule for
other return interfaces if routing is asymmetric.

```bash
ip -4 rule add pref 100 fwmark 0x100/0x100 lookup 100
ip -4 route add local 0.0.0.0/0 dev lo table 100

nft -f - <<'EOF'
table ip mqvpn_transparent {
    chain prerouting {
        type filter hook prerouting priority -150; policy accept;
        iifname "eth1" meta l4proto tcp socket transparent 1 counter meta mark set meta mark | 0x100
    }
}
EOF

# Keep the ordinary route for traffic with no matching transparent socket:
ip -4 route replace 10.111.252.0/22 dev mqvpn0
```

The socket match selects only packets belonging to transparent sockets. Matching
replies receive the reserved mark bit and route locally; other traffic continues
through the normal routing table to `mqvpn0`. There is no prefix-wide TPROXY rule,
no connection-mark restore, and no mark on the outgoing socket. Other mark bits
are preserved. Do not add a general fwmark restoration rule that sends unrelated
packets into table 100.

Priority `-150` is the Linux-documented mangle PREROUTING socket-divert placement,
before the route decision. Requires `CONFIG_NFT_SOCKET`, `CONFIG_NF_SOCKET_IPV4`
and policy routing support. See the [Linux kernel transparent proxy guide](https://cdn.kernel.org/doc/html/latest/networking/tproxy.html).

Integrate this with the site's firewall: transparent replies traverse **INPUT**,
and egress TCP traverses **OUTPUT**. Unmatched routed traffic still traverses
**FORWARD**. If INPUT defaults to drop, allow marked TCP replies on the trusted
return interface in your existing INPUT chain, for example:

```nft
iifname "eth1" meta l4proto tcp meta mark & 0x100 == 0x100 accept
```

An accept in this separate PREROUTING chain would not override another chain's
INPUT drop. Ensure later rules do not overwrite the mark. For asymmetric paths,
use loose reverse-path validation (`rp_filter=2`) on the return interface and
check the site's existing `all` setting; strict reverse-path validation can
reject otherwise valid replies. No sysctls or shell commands are executed by
libmqvpn.

Remove only this setup with:

```bash
nft delete table ip mqvpn_transparent
ip -4 rule del pref 100 fwmark 0x100/0x100 lookup 100
ip -4 route del local 0.0.0.0/0 dev lo table 100
```

Persist the rules using the distribution's network/firewall configuration.

## Permissions and failure behavior

`IP_TRANSPARENT` requires `CAP_NET_ADMIN` **or** `CAP_NET_RAW` in the network
namespace governing the socket. TUN, routes, rules and nftables setup normally
already require `CAP_NET_ADMIN`. Preserving source ports below the namespace's
`net.ipv4.ip_unprivileged_port_start` additionally requires
`CAP_NET_BIND_SERVICE`. Do not remove these capabilities before egress sockets
are opened. See [IP_TRANSPARENT](https://man7.org/linux/man-pages/man2/IP_TRANSPARENT.2const.html)
and [ip(7)](https://www.man7.org/linux/man-pages/man7/ip.7.html).

The server sets `IP_TRANSPARENT` before `bind(original_src)` and retains the
existing nonblocking connect, timeouts, relay and accounting. `IP_FREEBIND` is
unnecessary. No `SO_REUSEADDR`/`SO_REUSEPORT` is set: an occupied source tuple or
TIME_WAIT may produce `EADDRINUSE`. Only that flow fails (HTTP 502), with the
operation, source and errno logged. A second destination using the same source
IP:port can therefore also be refused. There is **no** retry with an ephemeral
port or server IP. Non-Linux egress is unavailable/returns 501.

## Wire and authorization

Transparent v1 uses `:protocol = mqvpn-tcp-transparent-v1`, the unchanged
`/.well-known/mqvpn/tcp/<destination>/<port>/` path, and headers
`x-mqvpn-src-ip` / `x-mqvpn-src-port`. Old servers reject the unknown protocol
with 501 without damaging the H3 connection. A new server with Transparent=false
also refuses this protocol. A Transparent=true server refuses legacy TCP
requests lacking the explicit protocol/source metadata. Upgrade/configure both
ends together. IPv6 transparent flows are explicitly rejected; TODO: add IPv6
source parsing, `IPV6_TRANSPARENT` and corresponding return-routing tests.
Ordinary IPv6 Hybrid is unchanged.

Before socket creation the server verifies the request's Bearer key, its match
to the live CONNECT-IP session's authenticated principal, and source ownership.
Allowed sources are that session's assigned tunnel IP or a prefix whose global
longest-prefix-match owner is that principal. A more-specific route belonging
to another user wins even if that user is offline. Other tunnel-pool addresses
are always denied. A global-key session may use its assigned IP only; display
`x-user` cannot grant route ownership. `EgressAllow` controls destinations only.

Missing, malformed, duplicate source headers, embedded NULs, zero/out-of-range
ports and duplicate routing/auth headers are rejected. Failures affect one H3
request. Closing a session closes its transparent egress sockets before its
address/routes are released; reconnect needs a fresh authenticated session.

## Tests

`test_config`, `test_api`, and `test_tcp_egress` cover defaults, parsing, protocol
compatibility, real H3 source rejection/acceptance, nested route ownership,
credential mismatch and requests after session teardown. Existing relay tests
continue exercising Transparent=false.

```bash
ctest --test-dir build --output-on-failure
sudo bash scripts/ci_e2e/run_transparent_tcp_test.sh ./build/mqvpn
```

The namespace test creates LAN, client, server and peer namespaces, opens eight
simultaneous flows from `10.111.252.25:53000..53007`, verifies the peer's actual
`getpeername()` and echoed payload/FIN, and checks peer-initiated TCP and ICMP to
the LAN both during and after those flows. It also checks bind collisions, closure
of active egress sockets on session teardown, and a new flow after reconnect.
For kernels lacking NFT_SOCKET but
providing `xt_socket`, explicitly run `sudo env SOCKET_MATCH=iptables bash ...`;
that tests the equivalent socket-divert behavior, not the native nft expression.
