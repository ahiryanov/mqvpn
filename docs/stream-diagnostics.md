# Diagnosing hybrid TCP STREAM stalls

This branch adds observation of the reproduced slow-receiver stall. It does
not change receive-window allocation, scheduling, flow caps or restart rules.
The existing backpressure protection and reduced logging remain in place.
No new configuration keys or per-flow production logs are added.

Build mqvpn from `fix/stream-diagnostics-20261007` and xquic from the exact
gitlink pinned by that commit (`dev/stream-diagnostics-20261007`). Rebuild
libmqvpn and the client against that xquic header/library pair. xquic's
connection-stats ABI grew; using an old xquic shared library with the new
mqvpn library/executable is unsafe. The public libmqvpn stats ABI is unchanged.
The on-wire protocol is unchanged, so the deployed server can remain at its
current version while testing the instrumented client. If a separate Yocto
recipe supplies xquic, update its revision as well as mqvpn's revision.

The client's existing control API returns an additive `stream_diag` object
in `get_stats`. Field definitions are in [control-api.md](control-api.md).
The previously installed passive collector already records the whole reply
every ten seconds. On that router a manual sample is:

```sh
python3 /usr/local/sbin/mqvpn-stream-diag.py --once
```

Use the same mixed paused/slow/fast-receiver reproducer, keep the server
unchanged, and retain samples before, during and after a failed short probe.
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
Use those measurements to choose a flow-control or relay fix. Increasing
`TcpMaxFlows` does not repair a shared-credit stall below the flow cap.
