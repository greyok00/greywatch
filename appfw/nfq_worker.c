/* nfq_worker.c — the native NFQUEUE verdict worker (task #13).

Replaces python3-netfilterqueue as queue 111's client: verdicts for TCP
new-conn traffic do not land through that binding on this stack
(queue_total builds while "allow" decisions stream). This worker owns
the netlink transport in C and delegates every
DECISION to the greywatch daemon over two local datagram sockets:

  /run/greywatch/nfq_events.sock  ← worker SENDS "PKT <id> <proto> <src> <sport> <dst> <dport>"
  /run/greywatch/nfq_worker.sock  ← worker RECEIVES "ALLOW <id>" / "DROP <id>"

Protocol (owner-approved): the worker HOLDS each packet id for at most
PEND_MS (250); the daemon's decision arrives within that window or the
worker ACCEPTS it (fail-open — the machine can never be locked out, even
if the daemon dies mid-flight). Signals accept everything pending and
exit. IPv4 only (the nft ruleset queues ipv4; anything else = accept).
*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <time.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <arpa/inet.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <linux/netfilter.h>

#define QNUM          111
#define PEND_MS       250
#define COPY_RANGE    256
#define MAX_PENDING   2048
#define EVENTS_PATH   "/run/greywatch/nfq_events.sock"
#define CONTROL_PATH  "/run/greywatch/nfq_worker.sock"

static volatile sig_atomic_t g_stop = 0;
/* socket paths overridable for tests/sandboxed runs (defaults: /run) */
static const char *control_path(void) {
    const char *e = getenv("NFQ_CONTROL_PATH");
    return e ? e : CONTROL_PATH;
}
static const char *events_path(void) {
    const char *e = getenv("NFQ_EVENTS_PATH");
    return e ? e : EVENTS_PATH;
}
static int g_ctl = -1;                 /* worker's own control socket */
static struct sockaddr_un g_daemon;    /* daemon's events socket */

struct pend {
    uint32_t id;
    uint64_t deadline_ms;
    struct nfq_q_handle *qh;
};

static struct pend pend[MAX_PENDING];
static size_t pend_n = 0;

static uint64_t now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static void on_signal(int sig) { (void)sig; g_stop = 1; }

/* apply verdict to a pending entry (accept = 1, drop = 0) */
static void settle(struct nfq_handle *h, size_t i, int accept) {
    nfq_set_verdict(pend[i].qh, pend[i].id,
                    accept ? NF_ACCEPT : NF_DROP, 0, NULL);
    pend[i] = pend[pend_n - 1];
    pend_n--;
    (void)h;
}

static void sweep(struct nfq_handle *h) {
    uint64_t now = now_ms();
    for (size_t i = 0; i < pend_n; ) {
        if (now > pend[i].deadline_ms) {    /* decision never came: ACCEPT */
            settle(h, i, 1);
            continue;
        }
        i++;
    }
}

static int find_pending(uint32_t id) {
    for (size_t i = 0; i < pend_n; i++)
        if (pend[i].id == id)
            return (int)i;
    return -1;
}

static void send_events(const char *line) {
    /* Non-blocking: the event is a LOG, never enforcement. A full daemon
       socket must never freeze the verdict path (2026-10-25 deadlock:
       worker blocked here while the daemon blocked sending decisions
       back on a full control socket). Lost events are acceptable. */
    (void)sendto(g_ctl, line, strlen(line), MSG_DONTWAIT,
                 (struct sockaddr *)&g_daemon, sizeof(g_daemon));
}

static int queue_cb(struct nfq_q_handle *qh, struct nfgenmsg *nfg,
                    struct nfq_data *nfa, void *data) {
    (void)nfg; (void)data;
    struct nfqnl_msg_packet_hdr *ph = nfq_get_msg_packet_hdr(nfa);
    if (!ph)
        return 0;              /* no id ⇒ no verdict possible in C; relies on
                                  fail_open `bypass` in the nft rule, and the
                                  queue-total watchdog (audit #3/#9) */
    uint32_t id = ntohl(ph->packet_id);

    unsigned char *payload = NULL;
    int plen = nfq_get_payload(nfa, &payload);
    unsigned char *b = (unsigned char *)payload;
    if (plen < 20 || !b) {
        nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
        return 0;
    }
    if ((b[0] >> 4) != 4) {                  /* not IPv4 → accept */
        nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
        return 0;
    }
    int ihl = (b[0] & 0x0F) * 4;
    if (plen < ihl + 4) {
        nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
        return 0;
    }
    int proto = b[9];
    char src[INET_ADDRSTRLEN] = "?", dst[INET_ADDRSTRLEN] = "?";
    char line[256];
    uint16_t sport = 0, dport = 0;
    if (proto == 6 || proto == 17) {
        sport = (b[ihl] << 8) | b[ihl + 1];
        dport = (b[ihl + 2] << 8) | b[ihl + 3];
        snprintf(line, sizeof(line),
                 "PKT %u %s %s %u %s %u", id,
                 proto == 6 ? "tcp" : "udp", src, sport, dst, dport);
    } else {
        nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
        return 0;                            /* non-TCP/UDP → accept */
    }
    inet_ntop(AF_INET, b + 12, src, sizeof(src));
    inet_ntop(AF_INET, b + 16, dst, sizeof(dst));
    snprintf(line, sizeof(line), "PKT %u %s %s %u %s %u", id,
             proto == 6 ? "tcp" : "udp", src, sport, dst, dport);
    send_events(line);

    if (pend_n >= MAX_PENDING) {             /* policy overflow → fail-open */
        nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
        return 0;
    }
    pend[pend_n].id = id;
    pend[pend_n].qh = (struct nfq_q_handle *)qh;
    pend[pend_n].deadline_ms = now_ms() + PEND_MS;
    pend_n++;
    return 0;
}

int main(void) {
    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);

    /* control socket: the daemon answers here */
    g_ctl = socket(AF_UNIX, SOCK_DGRAM, 0);
    struct sockaddr_un self;
    memset(&self, 0, sizeof(self));
    self.sun_family = AF_UNIX;
    strncpy(self.sun_path, control_path(), sizeof(self.sun_path) - 1);
    unlink(control_path());
    if (bind(g_ctl, (struct sockaddr *)&self, sizeof(self)) < 0) {
        perror("bind control"); return 1;
    }
    /* Both directions non-blocking. A full peer socket must degrade to a
       dropped event / a late ALLOW (250 ms sweep), never a frozen worker. */
    int fl = fcntl(g_ctl, F_GETFL, 0);
    if (fl >= 0)
        fcntl(g_ctl, F_SETFL, fl | O_NONBLOCK);
    memset(&g_daemon, 0, sizeof(g_daemon));
    g_daemon.sun_family = AF_UNIX;
    strncpy(g_daemon.sun_path, events_path(), sizeof(g_daemon.sun_path) - 1);

    struct nfq_handle *h = nfq_open();
    if (!h) { perror("nfq_open"); return 1; }
    struct nfq_q_handle *qh = nfq_create_queue(h, QNUM, queue_cb, NULL);
    if (!qh) { perror("nfq_create_queue"); return 1; }
    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, COPY_RANGE) < 0) {
        perror("nfq_set_mode"); return 1;
    }
    /* Kernel-side headroom: default queue length (1024) overflows during a
       burst and silently destroys packets. Raise it and let the in-worker
       >512 sweep fail packets open long before this bound is reached. */
    if (nfq_set_queue_maxlen(qh, 8192) < 0)
        perror("nfq_set_queue_maxlen (continuing with default)");
    int nfd = nfq_fd(h);

    /* audit #1: netlink overflow silently destroys queued packets. Give the
       netlink fd the biggest receive buffer permitted, then drain fully. */
    int rcvbuf = 4 * 1024 * 1024;
    if (setsockopt(nfd, SOL_SOCKET, SO_RCVBUFFORCE,
                   &rcvbuf, sizeof(rcvbuf)) < 0)
        setsockopt(nfd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));

    /* 50 ms control-socket poll cadence: verdicts + fail-open sweeps */
    struct timeval tv = {0, 50000};
    setsockopt(g_ctl, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    char ctl[128];
    char buf[8192] __attribute__((aligned));
    while (!g_stop) {
        fd_set r;
        FD_ZERO(&r);
        FD_SET(nfd, &r);
        FD_SET(g_ctl, &r);
        int maxfd = (nfd > g_ctl ? nfd : g_ctl) + 1;
        struct timeval t = {0, 50000};
        int rv = select(maxfd, &r, NULL, NULL, &t);
        if (rv < 0 && errno != EINTR) break;
        sweep(NULL);
        /* queue-pressure watchdog (audit #4): when held packets pile up
           past 512, fail them open — the daemon decides under headroom,
           never against a backlog this machine waits on. */
        while (pend_n > 512)
            settle(NULL, pend_n - 1, 1);
        if (FD_ISSET(g_ctl, &r)) {
            /* Drain EVERY queued decision, not one per 50 ms tick. The old
               single-recv loop capped the worker at 20 decisions/s; a burst
               left 200 KB+ on the control socket and the daemon blocked
               writing it (2026-10-25 outage). */
            for (;;) {
                ssize_t n = recv(g_ctl, ctl, sizeof(ctl) - 1, MSG_DONTWAIT);
                if (n <= 0) break;               /* EAGAIN/empty: done */
                ctl[n] = 0;
                uint32_t id = 0;
                int act = -1;
                if (sscanf(ctl, "ALLOW %u", &id) == 1) act = 1;
                else if (sscanf(ctl, "DROP %u", &id) == 1) act = 0;
                if (act < 0 || !qh) continue;
                int i = find_pending(id);
                if (i >= 0) {
                    nfq_set_verdict(qh, id,
                                    act ? NF_ACCEPT : NF_DROP, 0, NULL);
                    pend[i] = pend[pend_n - 1];
                    pend_n--;
                }
            }
        }
        /* audit #1/#2: drain netlink until EAGAIN; guard every recv() and
           every packet length before libnetfilter_queue parses the buffer */
        if (FD_ISSET(nfd, &r)) {
            for (;;) {
                ssize_t n = recv(nfd, buf, sizeof(buf), MSG_DONTWAIT);
                if (n <= 0) break;               /* 0 or -1: nothing to parse */
                nfq_handle_packet(h, buf, n);
            }
        }
    }
    /* orderly exit: ACCEPT everything pending — never a lockout */
    sweep(NULL);
    nfq_destroy_queue(qh);
    nfq_close(h);
    close(g_ctl);
    unlink(control_path());
    return 0;
}