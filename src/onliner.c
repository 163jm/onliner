/*
 * onliner.c - LuCI online device tracker
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * 改动：
 *  - 用 netlink RTNLGRP_NEIGH 事件驱动替换 /proc/net/arp 轮询
 *  - 每设备支持多个地址（IPv4 + 公网 IPv6，过滤 fe80::）
 *  - 实时数据纯内存，通过 Unix socket 对外提供
 *  - 仅每 10 分钟持久化写一次 /etc/onliner/devices.json
 *  - onliner-ctl 工具通过 socket 发 SET_NAME / CLEAR_OFFLINE 写回内存
 */

#define _POSIX_C_SOURCE 200809L


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdarg.h>
#include <time.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/epoll.h>
#include <sys/timerfd.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/neighbour.h>
#include <ctype.h>

#define PERSIST_FILE      "/etc/onliner/devices.json"
#define RUN_DIR           "/tmp/onliner"
#define LOG_FILE          RUN_DIR "/onliner.log"
#define LOCK_FILE         RUN_DIR "/onliner.lock"
#define SOCK_PATH         RUN_DIR "/onliner.sock"
#define DHCP_LEASES       "/tmp/dhcp.leases"
#define PERSIST_INTERVAL  600
#define DUMP_INTERVAL     60
#define MAX_DEVICES       512
#define MAX_ADDRS         8
#define MAC_LEN           18
#define IP_LEN            46
#define NAME_LEN          64
#define IFACE_LEN         16
#define SOCK_BUF_SIZE     (MAX_DEVICES * 640 + 256)
#define EPOLL_MAX         16
#define NUD_ONLINE_MASK   (NUD_REACHABLE | NUD_STALE | NUD_DELAY | NUD_PROBE)
#define NUD_IGNORE_MASK   (NUD_INCOMPLETE | NUD_NOARP | NUD_PERMANENT)

typedef struct {
    char addr[IP_LEN];
    bool is_v6;
} AddrEntry;

typedef struct {
    char      mac[MAC_LEN];
    AddrEntry addrs[MAX_ADDRS];
    int       n_addrs;
    char      name[NAME_LEN];
    char      custom_name[NAME_LEN];
    char      interface[IFACE_LEN];
    bool      online;
    time_t    first_seen;
    time_t    last_online;
    time_t    last_offline;
    time_t    uptime;
    bool      used;
} Device;

static Device   g_devs[MAX_DEVICES];
static int      g_ndev    = 0;
static volatile sig_atomic_t g_running = 1;
static FILE    *g_log     = NULL;
static int      g_epoll   = -1;
static int      g_nlfd    = -1;
static int      g_sockfd  = -1;
static int      g_timerfd = -1;
static int      g_dumpfd  = -1;

/* ── 工具 ──────────────────────────────────────────────────── */

static void log_msg(const char *msg) {
    time_t t = time(NULL);
    struct tm *tm_info = localtime(&t);
    char ts[32];
    strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", tm_info);
    if (g_log) { fprintf(g_log, "%s %s\n", ts, msg); fflush(g_log); }
    printf("%s %s\n", ts, msg);
}

static void log_fmt(const char *fmt, ...) {
    char buf[512];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    log_msg(buf);
}

static void mkdir_p(const char *path) {
    char tmp[256];
    snprintf(tmp, sizeof(tmp), "%s", path);
    for (char *p = tmp + 1; *p; p++) {
        if (*p == '/') { *p = '\0'; mkdir(tmp, 0755); *p = '/'; }
    }
    mkdir(tmp, 0755);
}

static void write_all(int fd, const char *buf, size_t len) {
    size_t sent = 0;
    while (sent < len) {
        ssize_t r = write(fd, buf + sent, len - sent);
        if (r < 0) { if (errno == EINTR) continue; break; }
        sent += (size_t)r;
    }
}

static void sock_reply(int fd, const char *msg) {
    write_all(fd, msg, strlen(msg));
}

/* ── 设备表 ─────────────────────────────────────────────────── */

static Device *find_device(const char *mac) {
    for (int i = 0; i < g_ndev; i++)
        if (g_devs[i].used && strcasecmp(g_devs[i].mac, mac) == 0)
            return &g_devs[i];
    return NULL;
}

static Device *alloc_device(void) {
    if (g_ndev >= MAX_DEVICES) return NULL;
    Device *d = &g_devs[g_ndev++];
    memset(d, 0, sizeof(*d));
    d->used = true;
    return d;
}

static void addr_upsert(Device *d, const char *addr, bool is_v6) {
    for (int i = 0; i < d->n_addrs; i++)
        if (strcmp(d->addrs[i].addr, addr) == 0) return;
    for (int i = 0; i < d->n_addrs; i++) {
        if (d->addrs[i].is_v6 == is_v6) {
            snprintf(d->addrs[i].addr, IP_LEN, "%s", addr);
            return;
        }
    }
    if (d->n_addrs >= MAX_ADDRS) return;
    snprintf(d->addrs[d->n_addrs].addr, IP_LEN, "%s", addr);
    d->addrs[d->n_addrs].is_v6 = is_v6;
    d->n_addrs++;
}

/* ── DHCP 主机名 ────────────────────────────────────────────── */

static void get_hostname(const char *ip, const char *mac,
                          char *out, int outsz) {
    FILE *f = fopen(DHCP_LEASES, "r");
    if (!f) { snprintf(out, outsz, "?"); return; }
    char line[256], l_exp[32], l_mac[64], l_ip[64], l_name[NAME_LEN];
    out[0] = '\0';
    while (fgets(line, sizeof(line), f)) {
        if (sscanf(line, "%31s %63s %63s %63s",
                   l_exp, l_mac, l_ip, l_name) < 4) continue;
        if (strcasecmp(l_mac, mac) == 0 || strcmp(l_ip, ip) == 0) {
            if (strcmp(l_name, "*") != 0) {
                snprintf(out, outsz, "%s", l_name);
                break;
            }
        }
    }
    fclose(f);
    if (out[0] == '\0') snprintf(out, outsz, "?");
}

/* ── Netlink 邻居事件 ───────────────────────────────────────── */

/* 前置声明（定义在 nl_dump_neigh 之后）*/
static void sync_mark(Device *d);

static void handle_neigh(const struct nlmsghdr *nlh) {
    const struct ndmsg *ndm = (const struct ndmsg *)NLMSG_DATA(nlh);
    bool is_del = (nlh->nlmsg_type == RTM_DELNEIGH);

    if (ndm->ndm_family != AF_INET && ndm->ndm_family != AF_INET6) return;
    if (!is_del && (ndm->ndm_state & NUD_IGNORE_MASK)) return;

    char    ip_str[IP_LEN] = "";
    uint8_t mac_raw[6]     = {0};
    bool    has_mac        = false;
    bool    is_v6          = (ndm->ndm_family == AF_INET6);

    int rta_len = (int)RTM_PAYLOAD(nlh);
    const struct rtattr *rta =
        (const struct rtattr *)((const char *)ndm +
                                NLMSG_ALIGN(sizeof(struct ndmsg)));

    for (; RTA_OK(rta, rta_len); rta = RTA_NEXT(rta, rta_len)) {
        if (rta->rta_type == NDA_DST) {
            inet_ntop(ndm->ndm_family, RTA_DATA(rta), ip_str, IP_LEN);
        } else if (rta->rta_type == NDA_LLADDR) {
            if (RTA_PAYLOAD(rta) == 6) {
                memcpy(mac_raw, RTA_DATA(rta), 6);
                has_mac = true;
            }
        }
    }

    if (!has_mac || ip_str[0] == '\0') return;
    if (is_v6 && strncasecmp(ip_str, "fe80", 4) == 0) return;

    bool zero_mac = true;
    for (int i = 0; i < 6; i++) if (mac_raw[i]) { zero_mac = false; break; }
    if (zero_mac) return;

    char mac_str[MAC_LEN];
    snprintf(mac_str, MAC_LEN, "%02x:%02x:%02x:%02x:%02x:%02x",
             mac_raw[0], mac_raw[1], mac_raw[2],
             mac_raw[3], mac_raw[4], mac_raw[5]);

    char iface[IFACE_LEN] = "br-lan";
    if (ndm->ndm_ifindex > 0)
        if_indextoname(ndm->ndm_ifindex, iface);

    bool going_online  = !is_del && (ndm->ndm_state & NUD_ONLINE_MASK);
    bool going_offline =  is_del || (ndm->ndm_state & NUD_FAILED);

    time_t  now = time(NULL);
    Device *d   = find_device(mac_str);

    if (d) {
        if (going_online) {
            addr_upsert(d, ip_str, is_v6);
            if (!d->online) {
                d->online      = true;
                d->uptime      = now;
                d->last_online = now;
                snprintf(d->interface, IFACE_LEN, "%s", iface);
                if (d->name[0] == '\0' || strcmp(d->name, "?") == 0)
                    get_hostname(ip_str, mac_str, d->name, NAME_LEN);
            }
            sync_mark(d);
        } else if (going_offline && d->online) {
            d->online       = false;
            d->last_offline = now;
        }
    } else if (going_online) {
        d = alloc_device();
        if (!d) return;
        snprintf(d->mac,       MAC_LEN,   "%s", mac_str);
        snprintf(d->interface, IFACE_LEN, "%s", iface);
        addr_upsert(d, ip_str, is_v6);
        get_hostname(ip_str, mac_str, d->name, NAME_LEN);
        d->custom_name[0] = '\0';
        d->first_seen  = now;
        d->online      = true;
        d->last_online = now;
        d->uptime      = now;
        sync_mark(d);
    }
}

/* ── JSON 序列化 ────────────────────────────────────────────── */

static void json_escape(FILE *f, const char *in) {
    for (; *in; in++) {
        if (*in == '"' || *in == '\\') { fputc('\\', f); fputc(*in, f); }
        else if ((unsigned char)*in >= 0x20) fputc(*in, f);
    }
}

static void serialize_json(FILE *f) {
    fprintf(f, "{\"devices\":[\n");
    bool first = true;

    for (int i = 0; i < g_ndev; i++) {
        Device *d = &g_devs[i];
        if (!d->used) continue;
        if (!first) fprintf(f, ",\n");
        first = false;

        /* 地址：v4 在前，v6 在后，换行分隔 */
        char ip_combined[IP_LEN * MAX_ADDRS + MAX_ADDRS];
        int  pos = 0;
        ip_combined[0] = '\0';
        for (int pass = 0; pass < 2; pass++) {
            for (int j = 0; j < d->n_addrs; j++) {
                if ((bool)pass != d->addrs[j].is_v6) continue;
                if (pos > 0) ip_combined[pos++] = '\n';
                int r = snprintf(ip_combined + pos,
                                 sizeof(ip_combined) - (size_t)pos,
                                 "%s", d->addrs[j].addr);
                if (r > 0) pos += r;
            }
        }

        fprintf(f, "  {\"mac\":\"%s\",\"ip\":\"", d->mac);
        json_escape(f, ip_combined);
        fprintf(f, "\",\"name\":\"");
        json_escape(f, d->name);
        fprintf(f, "\",\"custom_name\":\"");
        json_escape(f, d->custom_name);
        fprintf(f, "\","
            "\"interface\":\"%s\","
            "\"status\":\"%s\","
            "\"first_seen\":%ld,"
            "\"last_online\":%ld,"
            "\"last_offline\":%ld,"
            "\"uptime\":%ld}",
            d->interface,
            d->online ? "online" : "offline",
            (long)d->first_seen,
            (long)d->last_online,
            (long)d->last_offline,
            (long)d->uptime);
    }
    fprintf(f, "\n]}\n");
}

/* ── 持久化 ─────────────────────────────────────────────────── */

static void persist(void) {
    char tmp[256];
    snprintf(tmp, sizeof(tmp), "%s.tmp", PERSIST_FILE);
    FILE *f = fopen(tmp, "w");
    if (!f) { log_fmt("ERROR: cannot write %s: %s", tmp, strerror(errno)); return; }
    serialize_json(f);
    fclose(f);
    if (rename(tmp, PERSIST_FILE) != 0)
        log_fmt("ERROR: rename %s -> %s: %s", tmp, PERSIST_FILE, strerror(errno));
    else
        log_msg("persisted to " PERSIST_FILE);
}

/* ── JSON 解析（启动加载）───────────────────────────────────── */

static const char *json_find_key(const char *s, const char *key) {
    char needle[NAME_LEN + 4];
    snprintf(needle, sizeof(needle), "\"%s\":", key);
    return strstr(s, needle);
}

static bool json_get_str(const char *p, const char *key,
                          char *out, int outsz) {
    const char *kp = json_find_key(p, key);
    if (!kp) return false;
    kp += strlen(key) + 3;
    while (*kp == ' ') kp++;
    if (*kp != '"') return false;
    kp++;
    int n = 0;
    while (*kp && *kp != '"' && n < outsz - 1) {
        if (*kp == '\\' && *(kp + 1)) kp++;
        out[n++] = *kp++;
    }
    out[n] = '\0';
    return true;
}

static bool json_get_long(const char *p, const char *key, long *out) {
    const char *kp = json_find_key(p, key);
    if (!kp) return false;
    kp += strlen(key) + 3;
    while (*kp == ' ') kp++;
    char *end;
    *out = strtol(kp, &end, 10);
    return end != kp;
}

static void load_json(const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) return;
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    rewind(f);
    if (sz <= 0 || sz > 1024 * 1024) { fclose(f); return; }
    char *buf = malloc((size_t)sz + 1);
    if (!buf) { fclose(f); return; }
    if ((long)fread(buf, 1, (size_t)sz, f) != sz) { free(buf); fclose(f); return; }
    buf[sz] = '\0';
    fclose(f);

    time_t now = time(NULL);
    const char *p = buf;

    while ((p = strchr(p, '{')) != NULL) {
        if (*(p + 1) != '"' && *(p + 1) != '\n') { p++; continue; }
        const char *end = strchr(p, '}');
        if (!end) break;

        int   objlen = (int)(end - p + 1);
        char *obj    = malloc((size_t)objlen + 1);
        if (!obj) { p = end + 1; continue; }
        memcpy(obj, p, (size_t)objlen);
        obj[objlen] = '\0';

        char mac[MAC_LEN]    = "", name[NAME_LEN]  = "";
        char cname[NAME_LEN] = "", iface[IFACE_LEN] = "";
        char status[16]      = "";
        char ip_raw[IP_LEN * MAX_ADDRS + MAX_ADDRS] = "";
        long first_seen = 0, last_online = 0, last_offline = 0, uptime = 0;

        json_get_str(obj, "mac",         mac,    MAC_LEN);
        json_get_str(obj, "ip",          ip_raw, (int)sizeof(ip_raw));
        json_get_str(obj, "name",        name,   NAME_LEN);
        json_get_str(obj, "custom_name", cname,  NAME_LEN);
        json_get_str(obj, "interface",   iface,  IFACE_LEN);
        json_get_str(obj, "status",      status, (int)sizeof(status));
        json_get_long(obj, "first_seen",   &first_seen);
        json_get_long(obj, "last_online",  &last_online);
        json_get_long(obj, "last_offline", &last_offline);
        json_get_long(obj, "uptime",       &uptime);
        free(obj);

        if (mac[0] == '\0') { p = end + 1; continue; }

        Device *d = alloc_device();
        if (!d) break;
        snprintf(d->mac,         MAC_LEN,   "%s", mac);
        snprintf(d->name,        NAME_LEN,  "%s", name);
        snprintf(d->custom_name, NAME_LEN,  "%s", cname);
        snprintf(d->interface,   IFACE_LEN, "%s", iface);

        char *tok = ip_raw, *nl;
        while (*tok) {
            nl = strchr(tok, '\n');
            if (nl) *nl = '\0';
            if (*tok) addr_upsert(d, tok, strchr(tok, ':') != NULL);
            if (!nl) break;
            tok = nl + 1;
        }

        d->online       = false;
        d->first_seen   = (time_t)first_seen;
        d->last_online  = (time_t)last_online;
        d->last_offline = (strcmp(status, "online") == 0)
                          ? now : (time_t)last_offline;
        d->uptime       = (time_t)uptime;
        p = end + 1;
    }
    free(buf);
}

/* ── Netlink helpers ────────────────────────────────────────── */

/* 同步用的 generation 计数器：每次全量 dump 自增，
 * handle_neigh 收到 REACHABLE/STALE 等在线状态时更新设备的 gen，
 * dump 完成后（NLMSG_DONE）将 gen 落后的在线设备标记离线 */
static uint32_t g_sync_gen     = 0;
static bool     g_syncing      = false;
static uint32_t g_dev_gen[MAX_DEVICES]; /* 与 g_devs[] 一一对应 */

static void nl_dump_neigh(int nlfd, uint8_t family) {
    struct {
        struct nlmsghdr nlh;
        struct ndmsg    ndm;
    } req;
    memset(&req, 0, sizeof(req));
    req.nlh.nlmsg_len   = NLMSG_LENGTH(sizeof(struct ndmsg));
    req.nlh.nlmsg_type  = RTM_GETNEIGH;
    req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    req.nlh.nlmsg_seq   = (uint32_t)time(NULL);
    req.ndm.ndm_family  = family;
    if (send(nlfd, &req, req.nlh.nlmsg_len, 0) < 0)
        log_fmt("nl_dump_neigh family=%d: %s", (int)family, strerror(errno));
}

/* 开始一轮同步：自增 generation */
static void sync_begin(void) {
    g_sync_gen++;
    g_syncing = true;
}

/* handle_neigh 中设备被确认在线时调用 */
static void sync_mark(Device *d) {
    if (g_syncing)
        g_dev_gen[d - g_devs] = g_sync_gen;
}

/* dump 的两个 family 都完成后调用：将未被确认的在线设备标记离线 */
static void sync_end(void) {
    time_t now = time(NULL);
    for (int i = 0; i < g_ndev; i++) {
        if (g_devs[i].used && g_devs[i].online &&
            g_dev_gen[i] != g_sync_gen) {
            g_devs[i].online       = false;
            g_devs[i].last_offline = now;
        }
    }
    g_syncing = false;
}

static void nl_read(int nlfd) {
    char buf[65536];
    ssize_t n;
    /* 记录本次 recv 循环里是否遇到 NLMSG_DONE（dump 结束标志） */
    bool got_done = false;
    while ((n = recv(nlfd, buf, sizeof(buf), MSG_DONTWAIT)) > 0) {
        struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
        for (; NLMSG_OK(nlh, (uint32_t)n); nlh = NLMSG_NEXT(nlh, n)) {
            if (nlh->nlmsg_type == NLMSG_DONE)  { got_done = true; break; }
            if (nlh->nlmsg_type == NLMSG_ERROR) continue;
            if (nlh->nlmsg_type == RTM_NEWNEIGH ||
                nlh->nlmsg_type == RTM_DELNEIGH)
                handle_neigh(nlh);
        }
    }
    /* 如果正在同步且收到 DONE，完成清扫
     * 注意：IPv4 和 IPv6 各有一个 DONE，等第二个才真正结束
     * 用一个简单计数器处理 */
    if (got_done && g_syncing) {
        static int done_count = 0;
        done_count++;
        if (done_count >= 2) {   /* 两个 family 都 DONE */
            done_count = 0;
            sync_end();
        }
    }
}

/* ── Unix socket ────────────────────────────────────────────── */

static void sock_send_json(int fd) {
    char *buf = malloc(SOCK_BUF_SIZE);
    if (!buf) { close(fd); return; }
    FILE *mf = fmemopen(buf, SOCK_BUF_SIZE, "w");
    if (!mf) { free(buf); close(fd); return; }
    serialize_json(mf);
    fflush(mf);
    long sz = ftell(mf);
    fclose(mf);
    if (sz > 0) write_all(fd, buf, (size_t)sz);
    free(buf);
    close(fd);
}

static void sock_handle_client(int fd) {
    char line[512];
    memset(line, 0, sizeof(line));
    ssize_t n = recv(fd, line, sizeof(line) - 1, 0);
    if (n <= 0) { close(fd); return; }
    line[n] = '\0';

    char *ep = line + strlen(line) - 1;
    while (ep >= line && (*ep == '\r' || *ep == '\n')) *ep-- = '\0';

    if (strcmp(line, "GET") == 0) {
        sock_send_json(fd);
        return;
    }

    if (strncmp(line, "SET_NAME ", 9) == 0) {
        char *rest = line + 9;
        char *sp   = strchr(rest, ' ');
        char mac[MAC_LEN]      = "";
        char newname[NAME_LEN] = "";
        if (sp) {
            int mlen = (int)(sp - rest);
            if (mlen >= MAC_LEN) mlen = MAC_LEN - 1;
            memcpy(mac, rest, (size_t)mlen);
            mac[mlen] = '\0';
            snprintf(newname, NAME_LEN, "%s", sp + 1);
        } else {
            snprintf(mac, MAC_LEN, "%.*s", MAC_LEN - 1, rest);
            mac[MAC_LEN - 1] = '\0';
        }
        Device *d = find_device(mac);
        if (!d) sock_reply(fd, "ERR not found\n");
        else {
            snprintf(d->custom_name, NAME_LEN, "%s", newname);
            sock_reply(fd, "OK\n");
        }
        close(fd);
        return;
    }

    if (strcmp(line, "CLEAR_OFFLINE") == 0) {
        int w = 0;
        for (int i = 0; i < g_ndev; i++) {
            if (g_devs[i].used && g_devs[i].online) {
                if (i != w) g_devs[w] = g_devs[i];
                w++;
            }
        }
        g_ndev = w;
        sock_reply(fd, "OK\n");
        close(fd);
        return;
    }

    sock_reply(fd, "ERR unknown command\n");
    close(fd);
}

/* ── 信号 & 锁 ──────────────────────────────────────────────── */

static void handle_signal(int sig) { (void)sig; g_running = 0; }

static bool acquire_lock(void) {
    FILE *f = fopen(LOCK_FILE, "r");
    if (f) {
        pid_t old_pid = 0;
        if (fscanf(f, "%d", &old_pid) != 1) old_pid = 0;
        fclose(f);
        if (old_pid > 0 && kill(old_pid, 0) == 0) {
            log_fmt("Already running (pid=%d), exiting.", old_pid);
            return false;
        }
        remove(LOCK_FILE);
    }
    f = fopen(LOCK_FILE, "w");
    if (!f) return false;
    fprintf(f, "%d\n", (int)getpid());
    fclose(f);
    return true;
}

/* ── main ───────────────────────────────────────────────────── */

int main(void) {
    mkdir_p(RUN_DIR);
    mkdir_p("/etc/onliner");

    g_log = fopen(LOG_FILE, "a");
    if (!acquire_lock()) return 1;

    signal(SIGTERM, handle_signal);
    signal(SIGINT,  handle_signal);
    signal(SIGPIPE, SIG_IGN);

    load_json(PERSIST_FILE);

    /* netlink */
    g_nlfd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
    if (g_nlfd < 0) { perror("netlink socket"); return 1; }
    struct sockaddr_nl sa;
    memset(&sa, 0, sizeof(sa));
    sa.nl_family = AF_NETLINK;
    sa.nl_groups = RTMGRP_NEIGH;
    if (bind(g_nlfd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        perror("netlink bind"); return 1;
    }

    /* unix socket */
    unlink(SOCK_PATH);
    g_sockfd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (g_sockfd < 0) { perror("unix socket"); return 1; }
    struct sockaddr_un sun;
    memset(&sun, 0, sizeof(sun));
    sun.sun_family = AF_UNIX;
    snprintf(sun.sun_path, sizeof(sun.sun_path), "%s", SOCK_PATH);
    if (bind(g_sockfd, (struct sockaddr *)&sun, sizeof(sun)) < 0) {
        perror("unix bind"); return 1;
    }
    chmod(SOCK_PATH, 0600);
    if (listen(g_sockfd, 8) < 0) { perror("listen"); return 1; }

    /* timerfd */
    g_timerfd = timerfd_create(CLOCK_MONOTONIC, TFD_CLOEXEC);
    if (g_timerfd < 0) { perror("timerfd"); return 1; }
    struct itimerspec its;
    memset(&its, 0, sizeof(its));
    its.it_value.tv_sec    = PERSIST_INTERVAL;
    its.it_interval.tv_sec = PERSIST_INTERVAL;
    timerfd_settime(g_timerfd, 0, &its, NULL);

    /* dumpfd: 60s 全量 dump 兜底 */
    g_dumpfd = timerfd_create(CLOCK_MONOTONIC, TFD_CLOEXEC);
    if (g_dumpfd < 0) { perror("dumpfd"); return 1; }
    struct itimerspec dts;
    memset(&dts, 0, sizeof(dts));
    dts.it_value.tv_sec    = DUMP_INTERVAL;
    dts.it_interval.tv_sec = DUMP_INTERVAL;
    timerfd_settime(g_dumpfd, 0, &dts, NULL);

    /* epoll */
    g_epoll = epoll_create1(EPOLL_CLOEXEC);
    if (g_epoll < 0) { perror("epoll"); return 1; }
    struct epoll_event ev;
    memset(&ev, 0, sizeof(ev));
    ev.events = EPOLLIN;
    ev.data.fd = g_nlfd;    epoll_ctl(g_epoll, EPOLL_CTL_ADD, g_nlfd,    &ev);
    ev.data.fd = g_sockfd;  epoll_ctl(g_epoll, EPOLL_CTL_ADD, g_sockfd,  &ev);
    ev.data.fd = g_timerfd; epoll_ctl(g_epoll, EPOLL_CTL_ADD, g_timerfd, &ev);
    ev.data.fd = g_dumpfd;  epoll_ctl(g_epoll, EPOLL_CTL_ADD, g_dumpfd,  &ev);

    sync_begin();
    nl_dump_neigh(g_nlfd, AF_INET);
    nl_dump_neigh(g_nlfd, AF_INET6);

    log_fmt("onliner started (pid=%d, netlink+socket mode)", (int)getpid());

    struct epoll_event events[EPOLL_MAX];
    while (g_running) {
        int nr = epoll_wait(g_epoll, events, EPOLL_MAX, -1);
        if (nr < 0) { if (errno == EINTR) continue; break; }
        for (int i = 0; i < nr; i++) {
            int efd = events[i].data.fd;
            if (efd == g_nlfd) {
                nl_read(g_nlfd);
            } else if (efd == g_sockfd) {
                int cfd = accept4(g_sockfd, NULL, NULL, SOCK_CLOEXEC);
                if (cfd >= 0) sock_handle_client(cfd);
            } else if (efd == g_timerfd) {
                uint64_t exp;
                if (read(g_timerfd, &exp, sizeof(exp)) > 0)
                    persist();
            } else if (efd == g_dumpfd) {
                uint64_t exp;
                if (read(g_dumpfd, &exp, sizeof(exp)) > 0) {
                    sync_begin();
                    nl_dump_neigh(g_nlfd, AF_INET);
                    nl_dump_neigh(g_nlfd, AF_INET6);
                }
            }
        }
    }

    log_fmt("onliner stopping (pid=%d)", (int)getpid());
    persist();
    close(g_epoll);
    close(g_nlfd);
    close(g_sockfd);
    close(g_timerfd);
    close(g_dumpfd);
    unlink(SOCK_PATH);
    remove(LOCK_FILE);
    if (g_log) fclose(g_log);
    return 0;
}
