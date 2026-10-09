# Hybrid TCP STREAM progress and diagnostics

The office mixed-receiver reproducer exhausted the shared lwIP TCP segment
pool and retained almost all of the 32 MiB QUIC receive window. New flows
then stalled even below TcpMaxFlows and with bounded process memory.

This fix limits each LAN TCP queue to its share of half the segment pool
(maximum 128 queued pbufs when few flows are active). DATA stays in H3 until
the queue can accept it; partial stash retries preserve bytes and FIN.
The aggregate QUIC receive window is bounded at 256 MiB per tunnel and
direction. Each stream starts at its fixed 16 MiB ceiling; adaptive window
growth is not used by this mqvpn profile. Unread DATA still retains credit,
and bounded lwIP queues and consumption-based H3 credit remain in force.

Independently of aggregate pressure, the client's existing 1 Hz flow sweep
tracks queued, paused downloads observed with a zero TCP receive window.
After 10 seconds without positive downlink ACK progress it cancels the
individual TCP/H3 flow. Positive ACKs, an observed positive window or a relay
resume reset this deadline. Clock regression restarts observation. This is
an application policy, not a TCP protocol requirement: an intentionally
paused application may need to reconnect. Ordinary idle connections are
not affected, including when TcpIdleTimeoutSec is zero.

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
flow has already freed enough credit. Cancellation resets that
TCP connection and its H3 request, never the VPN; the application must retry.
This remains a pressure fallback, not a guarantee for unlimited stalled peers.

The fixed 16 MiB / 256 MiB profile is on
`perf/stream-fixed-16m-20261008`, based on the earlier adaptive profile.
The pinned xquic revision is unchanged. Rebuild mqvpn on client and server
to use the fixed initial window in both directions; there is no new xquic
change. Headers and libraries must still match the pinned xquic ABI.
The budget is not preallocated and is not a process RSS limit. No LTE rate
cap is added. Removing window growth does not guarantee higher throughput
or remove congestion-control startup time.

As few as 16 completely buffered streams can occupy the aggregate window.
Many slow but progressing readers can still fill it: the 10-second policy
does not cancel them, and short requests may temporarily wait. Unlimited
slow readers cannot all retain large windows within a bounded shared budget.
The fallback is client-side downlink protection; server upload pressure is
bounded by receive credit and existing server idle/socket logic.

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
