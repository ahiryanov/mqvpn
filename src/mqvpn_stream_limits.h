// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

#ifndef MQVPN_STREAM_LIMITS_H
#define MQVPN_STREAM_LIMITS_H

/* Receive credit per QUIC connection/direction, not process RSS.
 * Share the budget with the stalled LAN receiver pressure fallback. */
#define MQVPN_H3_STREAM_INITIAL_WINDOW MQVPN_H3_STREAM_RECV_WINDOW
#define MQVPN_H3_STREAM_RECV_WINDOW    (16u * 1024u * 1024u)
#define MQVPN_H3_CONN_RECV_WINDOW      (256u * 1024u * 1024u)

#endif
