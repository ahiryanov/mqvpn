// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mqvpn contributors

/* Real QUIC loopback tests of routed ownership. The source-policy hook is used
 * only to simulate a malicious client: traffic still crosses QUIC and the
 * production server's source gate. No TUN device or root privileges needed. */
#include "libmqvpn.h"
#include <arpa/inet.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

extern int mqvpn_client_test_apply_address_assign_capsule(mqvpn_client_t *,
                                                          const uint8_t *, size_t);
extern int mqvpn_client_test_allowed_src_prefix_count(const mqvpn_client_t *);

#define CHECK(expr)                                                    \
    do {                                                               \
        if (!(expr)) {                                                 \
            fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #expr); \
            exit(1);                                                   \
        }                                                              \
    } while (0)

typedef struct {
    mqvpn_client_t *client;
    int fd;
    mqvpn_path_handle_t path;
    mqvpn_tunnel_info_t info;
    int ready;
    int packets;
    uint8_t last[128];
    size_t last_len;
} peer_t;

static peer_t peers[4];
static mqvpn_server_t *server;
static int server_fd;
static struct sockaddr_in server_addr;
static int uplinks, unreachables;
static uint8_t last_uplink[128];

static uint64_t
clock_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static int
udp_socket(struct sockaddr_in *addr)
{
    int fd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0);
    CHECK(fd >= 0);
    memset(addr, 0, sizeof(*addr));
    addr->sin_family = AF_INET;
    addr->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    CHECK(bind(fd, (struct sockaddr *)addr, sizeof(*addr)) == 0);
    socklen_t len = sizeof(*addr);
    CHECK(getsockname(fd, (struct sockaddr *)addr, &len) == 0);
    return fd;
}

static void
server_ready(const mqvpn_tunnel_info_t *info, void *ctx)
{
    (void)info;
    (void)ctx;
}

static void
server_output(const uint8_t *pkt, size_t len, void *ctx)
{
    (void)ctx;
    if (len >= 20 && ((pkt[0] >> 4) == 4 ? pkt[9] == 17 : len >= 40 && pkt[6] == 17)) {
        uplinks++;
        memcpy(last_uplink, pkt, len < sizeof(last_uplink) ? len : sizeof(last_uplink));
    } else if ((len >= 28 && pkt[0] >> 4 == 4 && pkt[9] == 1 && pkt[20] == 3) ||
               (len >= 48 && pkt[0] >> 4 == 6 && pkt[6] == 58 && pkt[40] == 1)) {
        unreachables++;
    }
}

static void
peer_ready(const mqvpn_tunnel_info_t *info, void *ctx)
{
    peer_t *p = ctx;
    p->info = *info;
    p->ready++;
}

static void
peer_output(const uint8_t *pkt, size_t len, void *ctx)
{
    peer_t *p = ctx;
    p->packets++;
    p->last_len = len;
    memcpy(p->last, pkt, len < sizeof(p->last) ? len : sizeof(p->last));
}

static void
pump(void)
{
    uint8_t buf[65536];
    struct sockaddr_storage from;
    socklen_t from_len;
    ssize_t n;
    for (int i = 0; i < 4; i++)
        if (peers[i].client) mqvpn_client_tick(peers[i].client);
    for (;;) {
        from_len = sizeof(from);
        n = recvfrom(server_fd, buf, sizeof(buf), MSG_DONTWAIT, (struct sockaddr *)&from,
                     &from_len);
        if (n <= 0) break;
        CHECK(mqvpn_server_on_socket_recv(server, buf, (size_t)n,
                                          (struct sockaddr *)&from,
                                          from_len) == MQVPN_OK);
    }
    mqvpn_server_tick(server);
    struct pollfd fds[5] = {{.fd = server_fd, .events = POLLIN}};
    for (int i = 0; i < 4; i++) {
        peer_t *p = &peers[i];
        fds[i + 1] = (struct pollfd){.fd = p->client ? p->fd : -1, .events = POLLIN};
        if (!p->client) continue;
        for (;;) {
            from_len = sizeof(from);
            n = recvfrom(p->fd, buf, sizeof(buf), MSG_DONTWAIT, (struct sockaddr *)&from,
                         &from_len);
            if (n <= 0) break;
            mqvpn_client_on_socket_recv(p->client, p->path, buf, (size_t)n,
                                        (struct sockaddr *)&from, from_len);
        }
    }
    poll(fds, 5, 1);
}

static void
settle(void)
{
    uint64_t end = clock_ms() + 100;
    do {
        pump();
    } while (clock_ms() < end);
}

static void
wait_sessions(int expected)
{
    uint64_t end = clock_ms() + 5000;
    while (mqvpn_server_get_n_clients(server) != expected && clock_ms() < end)
        pump();
    CHECK(mqvpn_server_get_n_clients(server) == expected);
    settle();
}

static void
open_peer(int index, const char *key, const char *name, int accepted)
{
    peer_t *p = &peers[index];
    CHECK(!p->client);
    memset(p, 0, sizeof(*p));
    struct sockaddr_in addr;
    p->fd = udp_socket(&addr);
    mqvpn_config_t *cfg = mqvpn_config_new();
    CHECK(cfg);
    CHECK(mqvpn_config_set_server(cfg, "127.0.0.1", ntohs(server_addr.sin_port)) ==
          MQVPN_OK);
    CHECK(mqvpn_config_set_insecure(cfg, 1) == MQVPN_OK);
    CHECK(mqvpn_config_set_auth_key(cfg, key) == MQVPN_OK);
    CHECK(mqvpn_config_set_auth_username(cfg, name) == MQVPN_OK);
    CHECK(mqvpn_config_set_reconnect(cfg, 0, 1) == MQVPN_OK);
    mqvpn_config_set_log_level(cfg, MQVPN_LOG_ERROR);
    mqvpn_client_callbacks_t cbs = MQVPN_CLIENT_CALLBACKS_INIT;
    cbs.tunnel_config_ready = peer_ready;
    cbs.tun_output = peer_output;
    p->client = mqvpn_client_new(cfg, &cbs, p);
    mqvpn_config_free(cfg);
    CHECK(p->client);
    mqvpn_path_desc_t desc = {.struct_size = sizeof(desc)};
    memcpy(desc.local_addr, &addr, sizeof(addr));
    desc.local_addr_len = sizeof(addr);
    p->path = mqvpn_client_add_path_fd(p->client, p->fd, &desc);
    CHECK(p->path != (mqvpn_path_handle_t)-1);
    CHECK(mqvpn_client_set_server_addr(p->client, (struct sockaddr *)&server_addr,
                                       sizeof(server_addr)) == MQVPN_OK);
    CHECK(mqvpn_client_connect(p->client) == MQVPN_OK);
    uint64_t end = clock_ms() + 5000;
    while (!p->ready && clock_ms() < end) {
        pump();
        mqvpn_client_state_t state = mqvpn_client_get_state(p->client);
        if (state == MQVPN_STATE_CLOSED) break;
    }
    CHECK(!!p->ready == !!accepted);
    if (accepted) {
        CHECK(p->info.has_v6);
        CHECK(mqvpn_client_set_tun_active(p->client, 1, -1) == MQVPN_OK);
    }
}

static void
close_peer(int index)
{
    peer_t *p = &peers[index];
    if (!p->client) return;
    mqvpn_client_disconnect(p->client);
    settle();
    mqvpn_client_destroy(p->client);
    p->client = NULL;
    close(p->fd);
}

/* A small UDP datagram; payload contents identify preservation through the
 * tunnel. The tests check the unchanged addresses and the decremented TTL. */
static size_t
packet(uint8_t *buf, int family, const char *src, const char *dst)
{
    memset(buf, 0, 64);
    size_t hlen = family == 4 ? 20 : 40;
    int af = family == 4 ? AF_INET : AF_INET6;
    buf[0] = family == 4 ? 0x45 : 0x60;
    buf[family == 4 ? 3 : 5] = family == 4 ? 32 : 12;
    buf[family == 4 ? 8 : 7] = 64;
    buf[family == 4 ? 9 : 6] = 17;
    CHECK(inet_pton(af, src, buf + (family == 4 ? 12 : 8)) == 1);
    CHECK(inet_pton(af, dst, buf + (family == 4 ? 16 : 24)) == 1);
    buf[hlen] = 0x12;
    buf[hlen + 2] = 0x34;
    buf[hlen + 5] = 12;
    memcpy(buf + hlen + 8, "LAN!", 4);
    if (family == 4) {
        unsigned sum = 0;
        for (int i = 0; i < 20; i += 2)
            sum += ((unsigned)buf[i] << 8) | buf[i + 1];
        while (sum >> 16)
            sum = (sum & 0xffff) + (sum >> 16);
        buf[10] = (uint8_t)(~sum >> 8);
        buf[11] = (uint8_t)~sum;
    }
    return hlen + 12;
}

static void
uplink(int index, int family, const char *src, int allowed)
{
    uint8_t buf[64];
    size_t len = packet(buf, family, src, family == 4 ? "192.0.2.1" : "2001:db8::1");
    int before = uplinks;
    CHECK(mqvpn_client_on_tun_packet(peers[index].client, buf, len) == MQVPN_OK);
    settle();
    CHECK(uplinks == before + allowed);
    if (allowed) {
        CHECK(memcmp(last_uplink + (family == 4 ? 12 : 8), buf + (family == 4 ? 12 : 8),
                     family == 4 ? 8 : 32) == 0);
        CHECK(last_uplink[family == 4 ? 8 : 7] == 63);
    }
}

static void
downlink(int index, int family, const char *dst)
{
    uint8_t buf[64];
    size_t len = packet(buf, family, family == 4 ? "192.0.2.1" : "2001:db8::1", dst);
    int before[4];
    for (int i = 0; i < 4; i++)
        before[i] = peers[i].packets;
    int unreachable_before = unreachables;
    CHECK(mqvpn_server_on_tun_packet(server, buf, len) == MQVPN_OK);
    settle();
    for (int i = 0; i < 4; i++)
        CHECK(peers[i].packets == before[i] + (i == index));
    if (index >= 0) {
        CHECK(peers[index].last_len == len);
        CHECK(memcmp(peers[index].last + (family == 4 ? 12 : 8),
                     buf + (family == 4 ? 12 : 8), family == 4 ? 8 : 32) == 0);
    } else {
        CHECK(unreachables == unreachable_before + 1);
    }
}

static void
allow_spoofed_sources(peer_t *p)
{
    /* Keep the real primaries, add 0/0 and ::/0 locally. This deliberately
     * bypasses ONLY the honest client's source gate to test server enforcement. */
    uint8_t policy[64];
    size_t n = 0;
    policy[n++] = 0;
    policy[n++] = 4;
    memcpy(policy + n, p->info.assigned_ip, 4);
    n += 4;
    policy[n++] = 32;
    policy[n++] = 0;
    policy[n++] = 6;
    memcpy(policy + n, p->info.assigned_ip6, 16);
    n += 16;
    policy[n++] = 112;
    policy[n++] = 0;
    policy[n++] = 4;
    memset(policy + n, 0, 4);
    n += 4;
    policy[n++] = 0;
    policy[n++] = 0;
    policy[n++] = 6;
    memset(policy + n, 0, 16);
    n += 16;
    policy[n++] = 0;
    CHECK(mqvpn_client_test_apply_address_assign_capsule(p->client, policy, n) == 0);
}

int
main(void)
{
    server_fd = udp_socket(&server_addr);
    mqvpn_config_t *cfg = mqvpn_config_new();
    CHECK(cfg);
    CHECK(mqvpn_config_set_listen(cfg, "127.0.0.1", ntohs(server_addr.sin_port)) ==
          MQVPN_OK);
    CHECK(mqvpn_config_set_subnet(cfg, "10.0.0.0/24") == MQVPN_OK);
    CHECK(mqvpn_config_set_subnet6(cfg, "fd00::/112") == MQVPN_OK);
    CHECK(mqvpn_config_set_tls_cert(cfg, TEST_CERT_FILE, TEST_KEY_FILE) == MQVPN_OK);
    CHECK(mqvpn_config_set_auth_key(cfg, "global-key") == MQVPN_OK);
    CHECK(mqvpn_config_add_user(cfg, "alice", "alice-key") == MQVPN_OK);
    CHECK(mqvpn_config_add_user(cfg, "bob", "bob-key") == MQVPN_OK);
    CHECK(mqvpn_config_set_user_fixed_ip(cfg, "alice", "10.0.0.10") == MQVPN_OK);
    CHECK(mqvpn_config_add_route(cfg, "alice", "10.50.0.0/16") == MQVPN_OK);
    CHECK(mqvpn_config_add_route(cfg, "alice", "fd50:1::/48") == MQVPN_OK);
    CHECK(mqvpn_config_add_route(cfg, "bob", "10.50.8.0/24") == MQVPN_OK);
    CHECK(mqvpn_config_add_route(cfg, "bob", "fd50:1:0:8::/64") == MQVPN_OK);
    mqvpn_config_set_log_level(cfg, MQVPN_LOG_ERROR);
    mqvpn_server_callbacks_t cbs = MQVPN_SERVER_CALLBACKS_INIT;
    cbs.tunnel_config_ready = server_ready;
    cbs.tun_output = server_output;
    server = mqvpn_server_new(cfg, &cbs, NULL);
    mqvpn_config_free(cfg);
    CHECK(server);
    CHECK(mqvpn_server_set_socket_fd(server, server_fd, (struct sockaddr *)&server_addr,
                                     sizeof(server_addr)) == MQVPN_OK);
    CHECK(mqvpn_server_start(server) == MQVPN_OK);

    /* A global-key holder cannot take the named user's pin or routes. */
    open_peer(0, "global-key", "alice", 1);
    CHECK(peers[0].info.assigned_ip[3] != 10);
    CHECK(mqvpn_client_test_allowed_src_prefix_count(peers[0].client) == 0);
    downlink(-1, 4, "10.50.9.1");
    open_peer(1, "alice-key", "ignored-display-name", 1);
    CHECK(peers[1].info.assigned_ip[3] == 10);
    CHECK(mqvpn_client_test_allowed_src_prefix_count(peers[1].client) == 2);
    open_peer(3, "alice-key", "alice", 0);
    wait_sessions(2);
    close_peer(3);

    /* LPM must select an offline narrower owner instead of the live parent. */
    downlink(1, 4, "10.50.9.1");
    downlink(1, 6, "fd50:1:0:9::1");
    downlink(-1, 4, "10.50.8.1");
    downlink(-1, 6, "fd50:1:0:8::1");
    open_peer(2, "bob-key", "bob", 1);
    wait_sessions(3);
    CHECK(mqvpn_client_test_allowed_src_prefix_count(peers[2].client) == 2);
    downlink(2, 4, "10.50.8.1");
    downlink(2, 6, "fd50:1:0:8::1");
    uplink(1, 4, "10.50.9.1", 1);
    uplink(1, 6, "fd50:1:0:9::1", 1);
    uplink(2, 4, "10.50.8.1", 1);
    uplink(2, 6, "fd50:1:0:8::1", 1);

    allow_spoofed_sources(&peers[0]);
    allow_spoofed_sources(&peers[1]);
    uplink(0, 4, "10.50.9.1", 0);
    uplink(0, 6, "fd50:1:0:9::1", 0);
    uplink(1, 4, "10.50.8.1", 0);
    uplink(1, 6, "fd50:1:0:8::1", 0);
    uplink(1, 4, "10.0.0.1", 0);
    uplink(1, 6, "fd00::1", 0);
    uplink(1, 4, "198.51.100.1", 0);

    close_peer(2);
    wait_sessions(2);
    downlink(-1, 4, "10.50.8.1");
    downlink(-1, 6, "fd50:1:0:8::1");
    uplink(1, 4, "10.50.8.1", 0);
    open_peer(2, "bob-key", "bob", 1);
    downlink(2, 4, "10.50.8.1");
    downlink(2, 6, "fd50:1:0:8::1");

    /* Removing alice disconnects her credential-derived session, not the
     * global-key session with an identical untrusted display name. Bob's
     * nested routes survive compaction of the ownership table. */
    CHECK(mqvpn_server_remove_user(server, "alice") == MQVPN_OK);
    wait_sessions(2);
    CHECK(mqvpn_client_get_state(peers[0].client) == MQVPN_STATE_ESTABLISHED);
    downlink(2, 4, "10.50.8.1");
    downlink(2, 6, "fd50:1:0:8::1");
    for (int i = 0; i < 4; i++)
        close_peer(i);
    wait_sessions(0);
    downlink(-1, 4, "10.50.8.1");
    mqvpn_server_destroy(server);
    close(server_fd);
    puts("native route loopback: IPv4/IPv6, LPM, spoofing, reconnect and removal PASS");
    return 0;
}
