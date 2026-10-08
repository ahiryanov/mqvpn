# Hybrid TCP STREAM progress and diagnostics

The office mixed-receiver reproducer exhausted the shared lwIP TCP segment
pool and retained almost all of the 32 MiB QUIC receive window. New flows
then stalled even below TcpMaxFlows and with bounded process memory.

This fix limits each LAN TCP queue to its share of half the segment pool
(maximum 128 queued pbufs when few flows are active). DATA stays in H3 until
the queue can accept it; partial stash retries preserve bytes and FIN.
The aggregate QUIC receive window is bounded at 256 MiB per tunnel and
direction. Each stream starts at 256 KiB and can grow to the original 16 MiB ceiling when half its current window is
consumed within two RTTs and unread DATA is low. The sampler is independent
of frequent credit refills, so a fast reader is not fixed at 256 KiB.
Growth stops while aggregate unread DATA occupies at least 192 MiB.
Unread bodies and repeated BLOCKED frames cannot trigger adaptive growth.
xquic reissues sub-half-window consumed credit when the peer is short of
credit, without crediting unread DATA. TCP scheduling and flow caps are unchanged.

The client reclaims headroom before complete exhaustion: less than 64 MiB
credit together with at least 192 MiB unread H3 DATA. The exhaustion
fallback (less than 16 KiB credit with at least 128 MiB unread H3 DATA) also
remains, covering receive credit held in transport reassembly. An explicitly zero-window
LAN receiver must be continuously paused and without positive downlink ACK
progress for 5 seconds; a positive TCP window retains the 30-second grace
for temporary loss. Progressing slow readers and ordinary idle connections
are preserved. Each check cancels at most one oldest qualifying TCP/H3 flow;
checks are at most eight per second, with engine progress and fresh receive
counters between victims. This avoids cancelling a batch after one large
autotuned flow has already freed enough credit. Cancellation resets that
TCP connection and its H3 request, never the VPN; the application must retry.
This remains a pressure fallback, not a guarantee for unlimited stalled peers.

The 256 KiB / 16 MiB / 256 MiB profile is on
`perf/stream-window-256m-20261008`, based on the accepted STREAM fix without
the experimental BBR2 probe-wait change. Use the exact xquic gitlink pinned
by the mqvpn commit. The larger receive budget is not preallocated and is
not a process RSS limit; retained payload can be 224 MiB higher per tunnel
and direction than the earlier 32 MiB profile, plus metadata and other queues.
Rebuild both client and server, including their matching xquic headers and
libraries. The xquic connection-settings/stats ABI grew; mixing new mqvpn
with an old xquic shared library is unsafe. The public libmqvpn stats ABI and
wire protocol are unchanged. A separate Yocto xquic recipe needs the new
xquic SRCREV as well as the mqvpn SRCREV.

The former fixed 256 KiB window can limit a single flow to about 21 Mbit/s
at 100 ms RTT or 10.5 Mbit/s at 200 ms, before other overhead. The restored 16 MiB
ceiling is about 134 Mbit/s at one second RTT; initial growth and real LTE performance
still need hardware validation. Small initial credit is not a permanent
rate limit. The local TCP queue ceiling is also raised within the unchanged
half-pool budget so a lightly loaded LAN does not unnecessarily throttle LTE.
The fallback is client-side downlink protection; server upload pressure is
bounded by receive credit and existing server idle/socket logic.

The 8 October office run of the preceding fixed-window revision showed
recovery without restart, but six sequential 5-second probe timeouts under
144 non-readers and ten probe timeouts under mixed load. Those measurements
do not validate the adaptive-window revision. At the user's request no
additional tests were run for this update; only compilation and source review.

No new user configuration keys are required. Existing emergency service
memory limits and stream guard may remain during hardware validation.
`tcp_pressure_evicted` records the targeted fallback; queue and byte counters
distinguish expected slow-receiver pauses from actual relay progress.

The client's existing control API returns an additive `stream_diag` object
in `get_stats`. Field definitions are in [control-api.md](control-api.md).
The previously installed passive collector already records the whole reply
every ten seconds. On that router a manual sample is:

```sh
python3 /usr/local/sbin/mqvpn-stream-diag.py --once
```

Use the same mixed paused/slow/fast-receiver reproducer, use the updated server, and retain samples before, during and after a failed short probe.
Record connection/reconnect events and process PID alongside the metrics:
QUIC offsets and TCP lane totals restart with their respective lifetimes.
Retrieve `snapshots.jsonl` and rotations before a power reset; `/var/log`
on the current router is volatile. The collector's compact journal summary
does not yet include this new nested object; the full JSON file does.

Compare three observations:

1. `h3_pending`, `recv_credit`, `recv_limit` and window-update age. Large
   retained DATA with exhausted receive credit supports a shared-credit
   starvation hypothesis; it does not by itself prove the defect.
2. `tcp_downlink_paused`, maximum pause age, stash and upload queue gauges.
   Failed retries must not reset pause age. A pause is expected for a LAN
   client that intentionally stops reading and is not automatically dead.
3. Changes in H3-consumed, TCP-written and TCP-ACKed bytes. These distinguish
   transport buffering, stalled relay writes, and an unresponsive receiver.
   Retry attempts and H3 AGAIN returns alone are not successful progress.

Remove paused receivers, then slow receivers, without restarting mqvpn.
Compare recovered short probes and credit/queue counters at each stage.
Increasing `TcpMaxFlows` does not repair a shared-credit stall below the flow cap.
