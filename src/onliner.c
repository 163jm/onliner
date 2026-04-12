/*
 * onliner.c - LuCI online device tracker
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * 架构：
 *  - netlink RTMGRP_NEIGH 事件驱动，内核邻居表变化时立即响应
 *  - Unix socket 对外提供 JSON RPC，供 ucode 查询/修改
 *  - 所有数据只在内存中，无任何运行时文件 IO
 *  - select() 主循环同时监听 netlink + socket，无事件时 CPU 占用为零
 *
 * RPC 协议（每次请求/响应均为一行 JSON + '\n'）：
 *  请求：{"method":"get_devices"}
 *        {"method":"set_custom_name","mac":"xx:xx","name":"mypc"}
 *        {"method":"clear_offline"}
 *  响应：{"devices":[...]}   /   {"result":true}   /   {"error":"..."}
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdbool.h>
#include <ctype.h>
#include <time.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/un.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/neighbour.h>
#include <arpa/inet.h>
#include <net/if.h>

/* ── 常量 ────────────────────────────────────────────────────── */
#define SOCKET_PATH  "/tmp/onliner/onliner.sock"
#define LOCK_FILE    "/tmp/onliner/onliner.lock"
#define LOG_FILE     "/tmp/onliner/onliner.log"
#define PERSIST_FILE "/etc/onliner/devices.json"
#define RUN_DIR      "/tmp/onliner"
#define MAX_DEVICES  256
#define MAX_CLIENTS  8
#define MAC_LEN      18
#define IP4_LEN      16
#define IP6_LEN      46
#define NAME_LEN     64
#define IFACE_LEN    16

/* ── 设备结构体 ──────────────────────────────────────────────── */
typedef struct {
    bool   used;
    char   mac[MAC_LEN];
    char   ip4[IP4_LEN];
    char   ip6[IP6_LEN];         /* 全局 IPv6，可为空 */
    char   name[NAME_LEN];
    char   custom_name[NAME_LEN];
    char   interface[IFACE_LEN];
    bool   online;
    time_t first_seen;
    time_t last_online;
    time_t last_offline;
    time_t uptime;
} Device;

/* ── 全局状态 ─────────────────────────────────────────────────── */
static Device                g_devs[MAX_DEVICES];
static int                   g_ndev    = 0;
static volatile sig_atomic_t g_running = 1;
static FILE                 *g_log     = NULL;
static int                   g_srv_fd  = -1;
static int                   g_cli_fd[MAX_CLIENTS];
static int                   g_cli_n   = 0;

/* ══════════════════════════════════════════════════════════════
 * 工具函数
 * ══════════════════════════════════════════════════════════════ */

static void log_msg(const char *fmt, ...) {
    time_t t = time(NULL);
    struct tm *tm = localtime(&t);
    char ts[32];
    strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", tm);
    va_list ap; va_start(ap, fmt);
    char body[512]; vsnprintf(body, sizeof(body), fmt, ap);
    va_end(ap);
    if (g_log) { fprintf(g_log, "%s %s\n", ts, body); fflush(g_log); }
    printf("%s %s\n", ts, body);
}

static void mkdir_p(const char *path) {
    char tmp[256];
    snprintf(tmp, sizeof(tmp), "%s", path);
    for (char *p = tmp + 1; *p; p++) {
        if (*p != '/') continue;
        *p = '\0'; mkdir(tmp, 0755); *p = '/';
    }
    mkdir(tmp, 0755);
}

/* ── 设备表 ──────────────────────────────────────────────────── */
static Device *find_by_mac(const char *mac) {
    for (int i = 0; i < g_ndev; i++)
        if (g_devs[i].used && strcasecmp(g_devs[i].mac, mac) == 0)
            return &g_devs[i];
    return NULL;
}

static Device *alloc_dev(void) {
    if (g_ndev >= MAX_DEVICES) return NULL;
    Device *d = &g_devs[g_ndev++];
    memset(d, 0, sizeof(*d));
    d->used = true;
    return d;
}

/* ── DHCP leases 查主机名 ────────────────────────────────────── */
static void lookup_hostname(const char *ip4, const char *mac,
                             char *out, int outsz) {
    FILE *f = fopen("/tmp/dhcp.leases", "r");
    if (!f) { snprintf(out, outsz, "?"); return; }
    char line[256], le[32], lm[64], li[64], ln[NAME_LEN];
    out[0] = '\0';
    while (fgets(line, sizeof(line), f)) {
        if (sscanf(line, "%31s %63s %63s %63s", le, lm, li, ln) < 4) continue;
        if ((strcasecmp(lm, mac) == 0 || strcmp(li, ip4) == 0)
             && strcmp(ln, "*") != 0) {
            snprintf(out, outsz, "%s", ln); break;
        }
    }
    fclose(f);
    if (out[0] == '\0') snprintf(out, outsz, "?");
}

/* ── IPv6：过滤链路本地和组播，只保留全局单播 ───────────────── */
static bool is_global_ipv6(const char *addr) {
    if (strncasecmp(addr, "fe80", 4) == 0) return false;
    if (strncasecmp(addr, "ff",   2) == 0) return false;
    return true;
}

/* ══════════════════════════════════════════════════════════════
 * 设备状态更新
 * ══════════════════════════════════════════════════════════════ */

static void upsert_device(const char *ip, int af, const char *mac,
                           bool online, const char *iface) {
    time_t now = time(NULL);
    bool is_v6 = (af == AF_INET6);
    Device *d = find_by_mac(mac);

    if (!d) {
        d = alloc_dev();
        if (!d) { log_msg("WARN: device table full"); return; }
        snprintf(d->mac,       MAC_LEN,   "%s", mac);
        snprintf(d->interface, IFACE_LEN, "%s", iface);
        if (is_v6) snprintf(d->ip6, IP6_LEN, "%s", ip);
        else       snprintf(d->ip4, IP4_LEN, "%s", ip);
        lookup_hostname(d->ip4, mac, d->name, NAME_LEN);
        d->first_seen = now;
        d->online     = online;
        if (online) { d->last_online = now; d->uptime = now; }
        log_msg("NEW  %s  %s  %s", mac, ip, online ? "online" : "offline");
        return;
    }

    /* 更新 IP（IPv4 / 全局 IPv6 分别存放） */
    if (is_v6) {
        if (is_global_ipv6(ip)) snprintf(d->ip6, IP6_LEN, "%s", ip);
        else return;
    } else {
        snprintf(d->ip4, IP4_LEN, "%s", ip);
    }

    /* 状态迁移 */
    if (online && !d->online) {
        d->online      = true;
        d->uptime      = now;
        d->last_online = now;
        snprintf(d->interface, IFACE_LEN, "%s", iface);
        if (d->name[0] == '\0' || strcmp(d->name, "?") == 0)
            lookup_hostname(d->ip4, mac, d->name, NAME_LEN);
        log_msg("UP   %s  %s", mac, ip);
    } else if (!online && d->online) {
        d->online       = false;
        d->last_offline = now;
        log_msg("DOWN %s  %s", mac, ip);
    }
}

/* ══════════════════════════════════════════════════════════════
 * Netlink
 * ══════════════════════════════════════════════════════════════ */

static int nl_open(void) {
    int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
    if (fd < 0) { log_msg("ERROR: netlink socket: %s", strerror(errno)); return -1; }

    struct sockaddr_nl sa = {
        .nl_family = AF_NETLINK,
        .nl_groups = RTMGRP_NEIGH,
    };
    if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        log_msg("ERROR: netlink bind: %s", strerror(errno));
        close(fd); return -1;
    }
    return fd;
}

static void nl_dump(int fd) {
    struct {
        struct nlmsghdr nlh;
        struct ndmsg    ndm;
    } req = {
        .nlh = {
            .nlmsg_len   = NLMSG_LENGTH(sizeof(struct ndmsg)),
            .nlmsg_type  = RTM_GETNEIGH,
            .nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP,
            .nlmsg_seq   = 1,
        },
        .ndm = { .ndm_family = AF_UNSPEC },
    };
    if (send(fd, &req, req.nlh.nlmsg_len, 0) < 0)
        log_msg("ERROR: netlink dump: %s", strerror(errno));
}

static void nl_parse_neigh(struct nlmsghdr *nlh) {
    struct ndmsg *ndm = NLMSG_DATA(nlh);

    bool online = (ndm->ndm_state &
                   (NUD_REACHABLE | NUD_STALE | NUD_DELAY | NUD_PROBE)) != 0;

    /* 跳过纯 INCOMPLETE/FAILED（还没获取到 MAC 的条目）
     * NUD_NOARP 是静态条目（如路由器自身），也跳过               */
    if (!online && (ndm->ndm_state & (NUD_NOARP | NUD_PERMANENT))) return;

    char ip[IP6_LEN]      = "";
    char mac[MAC_LEN]     = "";
    char iface[IFACE_LEN] = "";

    if (ndm->ndm_ifindex > 0)
        if_indextoname(ndm->ndm_ifindex, iface);
    if (iface[0] == '\0')
        snprintf(iface, IFACE_LEN, "if%d", ndm->ndm_ifindex);

    /* NDM_RTA/NDM_PAYLOAD 在部分内核头未定义，手动计算 */
    struct rtattr *rta = (struct rtattr *)((char *)ndm + NLMSG_ALIGN(sizeof(struct ndmsg)));
    int len = (int)(nlh->nlmsg_len - NLMSG_SPACE(sizeof(struct ndmsg)));
    for (; RTA_OK(rta, len); rta = RTA_NEXT(rta, len)) {
        if (rta->rta_type == NDA_DST) {
            if (ndm->ndm_family == AF_INET)
                inet_ntop(AF_INET,  RTA_DATA(rta), ip, sizeof(ip));
            else if (ndm->ndm_family == AF_INET6)
                inet_ntop(AF_INET6, RTA_DATA(rta), ip, sizeof(ip));
        } else if (rta->rta_type == NDA_LLADDR) {
            unsigned char *hw = RTA_DATA(rta);
            snprintf(mac, MAC_LEN, "%02x:%02x:%02x:%02x:%02x:%02x",
                     hw[0], hw[1], hw[2], hw[3], hw[4], hw[5]);
        }
    }

    if (ip[0] == '\0' || mac[0] == '\0') return;
    if (strcmp(mac, "00:00:00:00:00:00") == 0) return;
    if (ndm->ndm_family == AF_INET6 && !is_global_ipv6(ip)) return;

    if (nlh->nlmsg_type == RTM_DELNEIGH) online = false;

    upsert_device(ip, ndm->ndm_family, mac, online, iface);
}

static void nl_recv(int fd) {
    char buf[8192];
    ssize_t n;
    while ((n = recv(fd, buf, sizeof(buf), MSG_DONTWAIT)) > 0) {
        struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
        for (; NLMSG_OK(nlh, (unsigned int)n); nlh = NLMSG_NEXT(nlh, n)) {
            if (nlh->nlmsg_type == NLMSG_DONE)  break;
            if (nlh->nlmsg_type == NLMSG_ERROR) break;
            if (nlh->nlmsg_type == RTM_NEWNEIGH ||
                nlh->nlmsg_type == RTM_DELNEIGH)
                nl_parse_neigh(nlh);
        }
    }
}

/* ══════════════════════════════════════════════════════════════
 * JSON 生成
 * ══════════════════════════════════════════════════════════════ */

static void json_write_str(FILE *f, const char *s) {
    fputc('"', f);
    for (; *s; s++) {
        switch (*s) {
            case '"':  fputs("\\\"", f); break;
            case '\\': fputs("\\\\", f); break;
            case '\n': fputs("\\n",  f); break;
            case '\r': fputs("\\r",  f); break;
            case '\t': fputs("\\t",  f); break;
            default:
                if ((unsigned char)*s >= 0x20) fputc(*s, f);
        }
    }
    fputc('"', f);
}

static void serialize_devices(FILE *f) {
    fprintf(f, "{\"devices\":[");
    bool first = true;
    for (int i = 0; i < g_ndev; i++) {
        Device *d = &g_devs[i];
        if (!d->used) continue;
        if (!first) fputc(',', f);
        first = false;
        fprintf(f, "{\"mac\":");          json_write_str(f, d->mac);
        fprintf(f, ",\"ip\":");           json_write_str(f, d->ip4);
        fprintf(f, ",\"ip6\":");          json_write_str(f, d->ip6);
        fprintf(f, ",\"name\":");         json_write_str(f, d->name);
        fprintf(f, ",\"custom_name\":"); json_write_str(f, d->custom_name);
        fprintf(f, ",\"interface\":");   json_write_str(f, d->interface);
        fprintf(f, ",\"status\":");      json_write_str(f,
                                             d->online ? "online" : "offline");
        fprintf(f, ",\"first_seen\":%ld",   (long)d->first_seen);
        fprintf(f, ",\"last_online\":%ld",  (long)d->last_online);
        fprintf(f, ",\"last_offline\":%ld", (long)d->last_offline);
        fprintf(f, ",\"uptime\":%ld",       (long)d->uptime);
        fputc('}', f);
    }
    fprintf(f, "]}");
}

/* ══════════════════════════════════════════════════════════════
 * 递归下降 JSON 解析器（用于读取持久化文件）
 * ══════════════════════════════════════════════════════════════ */

typedef struct { const char *p; const char *end; } JP;

static void jp_ws(JP *j) {
    while (j->p < j->end && isspace((unsigned char)*j->p)) j->p++;
}

static bool jp_str(JP *j, char *out, int outsz) {
    jp_ws(j);
    if (j->p >= j->end || *j->p != '"') return false;
    j->p++;
    int n = 0;
    while (j->p < j->end && *j->p != '"') {
        char c = *j->p++;
        if (c == '\\' && j->p < j->end) {
            c = *j->p++;
            if (c == 'n') c = '\n';
            else if (c == 'r') c = '\r';
            else if (c == 't') c = '\t';
        }
        if (n < outsz - 1) out[n++] = c;
    }
    out[n] = '\0';
    if (j->p < j->end) j->p++;
    return true;
}

static bool jp_long(JP *j, long *out) {
    jp_ws(j);
    if (j->p >= j->end) return false;
    char *end;
    *out = strtol(j->p, &end, 10);
    if (end == j->p) return false;
    j->p = end;
    return true;
}

static void jp_skip(JP *j) {
    jp_ws(j);
    if (j->p >= j->end) return;
    if (*j->p == '"') { char t[256]; jp_str(j, t, sizeof(t)); return; }
    if (*j->p == '{' || *j->p == '[') {
        char open = *j->p++, close = open == '{' ? '}' : ']';
        jp_ws(j);
        while (j->p < j->end && *j->p != close) {
            jp_skip(j); jp_ws(j);
            if (j->p < j->end && *j->p == ':') { j->p++; jp_skip(j); jp_ws(j); }
            if (j->p < j->end && *j->p == ',') { j->p++; jp_ws(j); }
        }
        if (j->p < j->end) j->p++;
        return;
    }
    while (j->p < j->end && !isspace((unsigned char)*j->p)
           && *j->p != ',' && *j->p != '}' && *j->p != ']') j->p++;
}

static void jp_parse_device(JP *j) {
    jp_ws(j);
    if (j->p >= j->end || *j->p != '{') return;
    j->p++;

    char mac[MAC_LEN]="", ip4[IP4_LEN]="", ip6[IP6_LEN]="";
    char name[NAME_LEN]="", cname[NAME_LEN]="";
    char iface[IFACE_LEN]="", status[16]="";
    long first_seen=0, last_online=0, last_offline=0, uptime=0;

    jp_ws(j);
    while (j->p < j->end && *j->p != '}') {
        char key[64] = "";
        jp_str(j, key, sizeof(key));
        jp_ws(j);
        if (j->p < j->end && *j->p == ':') j->p++;

        if      (!strcmp(key,"mac"))          jp_str(j, mac,    sizeof(mac));
        else if (!strcmp(key,"ip"))           jp_str(j, ip4,    sizeof(ip4));
        else if (!strcmp(key,"ip6"))          jp_str(j, ip6,    sizeof(ip6));
        else if (!strcmp(key,"name"))         jp_str(j, name,   sizeof(name));
        else if (!strcmp(key,"custom_name"))  jp_str(j, cname,  sizeof(cname));
        else if (!strcmp(key,"interface"))    jp_str(j, iface,  sizeof(iface));
        else if (!strcmp(key,"status"))       jp_str(j, status, sizeof(status));
        else if (!strcmp(key,"first_seen"))   jp_long(j, &first_seen);
        else if (!strcmp(key,"last_online"))  jp_long(j, &last_online);
        else if (!strcmp(key,"last_offline")) jp_long(j, &last_offline);
        else if (!strcmp(key,"uptime"))       jp_long(j, &uptime);
        else jp_skip(j);

        jp_ws(j);
        if (j->p < j->end && *j->p == ',') j->p++;
        jp_ws(j);
    }
    if (j->p < j->end) j->p++;

    if (mac[0] == '\0') return;
    Device *d = alloc_dev();
    if (!d) return;
    snprintf(d->mac,         MAC_LEN,   "%s", mac);
    snprintf(d->ip4,         IP4_LEN,   "%s", ip4);
    snprintf(d->ip6,         IP6_LEN,   "%s", ip6);
    snprintf(d->name,        NAME_LEN,  "%s", name);
    snprintf(d->custom_name, NAME_LEN,  "%s", cname);
    snprintf(d->interface,   IFACE_LEN, "%s", iface);
    d->online       = false;   /* 重启后统一标记离线 */
    d->first_seen   = (time_t)first_seen;
    d->last_online  = (time_t)last_online;
    d->last_offline = (time_t)last_offline;
    d->uptime       = (time_t)uptime;
}

static void load_persist(void) {
    FILE *f = fopen(PERSIST_FILE, "r");
    if (!f) return;
    fseek(f, 0, SEEK_END); long sz = ftell(f); rewind(f);
    if (sz <= 0 || sz > 512*1024) { fclose(f); return; }
    char *buf = malloc(sz + 1);
    if (!buf) { fclose(f); return; }
    if (fread(buf, 1, sz, f) != (size_t)sz) { free(buf); fclose(f); return; }
    buf[sz] = '\0'; fclose(f);

    JP j = { buf, buf + sz };
    while (j.p < j.end && *j.p != '[') j.p++;
    if (j.p >= j.end) { free(buf); return; }
    j.p++;
    jp_ws(&j);
    while (j.p < j.end && *j.p != ']') {
        jp_parse_device(&j);
        jp_ws(&j);
        if (j.p < j.end && *j.p == ',') j.p++;
        jp_ws(&j);
    }
    free(buf);
    log_msg("INFO: loaded %d devices from %s", g_ndev, PERSIST_FILE);
}

/* ══════════════════════════════════════════════════════════════
 * Unix Socket RPC
 * ══════════════════════════════════════════════════════════════ */

static int sock_open(void) {
    unlink(SOCKET_PATH);
    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) { log_msg("ERROR: socket: %s", strerror(errno)); return -1; }
    struct sockaddr_un sa = { .sun_family = AF_UNIX };
    snprintf(sa.sun_path, sizeof(sa.sun_path), "%s", SOCKET_PATH);
    if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        log_msg("ERROR: bind %s: %s", SOCKET_PATH, strerror(errno));
        close(fd); return -1;
    }
    chmod(SOCKET_PATH, 0660);
    listen(fd, MAX_CLIENTS);
    return fd;
}

/* 从请求 JSON 中提取指定 key 的字符串值 */
static bool rpc_get_str(const char *req, const char *key,
                         char *out, int outsz) {
    char needle[64];
    snprintf(needle, sizeof(needle), "\"%s\"", key);
    const char *p = strstr(req, needle);
    if (!p) return false;
    JP j = { p + strlen(needle), req + strlen(req) };
    jp_ws(&j);
    if (j.p >= j.end || *j.p != ':') return false;
    j.p++;
    return jp_str(&j, out, outsz);
}

static void handle_request(const char *req, FILE *out) {
    char method[32] = "";
    rpc_get_str(req, "method", method, sizeof(method));

    if (!strcmp(method, "get_devices")) {
        serialize_devices(out);
        fputc('\n', out);
        fflush(out);
        return;
    }

    if (!strcmp(method, "set_custom_name")) {
        char mac[MAC_LEN] = "", name[NAME_LEN] = "";
        rpc_get_str(req, "mac",  mac,  sizeof(mac));
        rpc_get_str(req, "name", name, sizeof(name));
        if (!mac[0]) {
            fprintf(out, "{\"error\":\"mac required\"}\n");
            fflush(out); return;
        }
        Device *d = find_by_mac(mac);
        if (!d) {
            fprintf(out, "{\"error\":\"device not found\"}\n");
            fflush(out); return;
        }
        snprintf(d->custom_name, NAME_LEN, "%s", name);
        fprintf(out, "{\"result\":true}\n");
        fflush(out);
        return;
    }

    if (!strcmp(method, "clear_offline")) {
        int w = 0;
        for (int i = 0; i < g_ndev; i++)
            if (g_devs[i].used && g_devs[i].online)
                g_devs[w++] = g_devs[i];
        g_ndev = w;
        fprintf(out, "{\"result\":true}\n");
        fflush(out);
        return;
    }

    fprintf(out, "{\"error\":\"unknown method\"}\n");
    fflush(out);
}

static void sock_accept(void) {
    if (g_cli_n >= MAX_CLIENTS) return;
    int fd = accept(g_srv_fd, NULL, NULL);
    if (fd < 0) return;
    struct timeval tv = { .tv_sec = 5 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    g_cli_fd[g_cli_n++] = fd;
}

static void sock_serve(int idx) {
    int fd = g_cli_fd[idx];
    char buf[1024];
    ssize_t n = recv(fd, buf, sizeof(buf) - 1, 0);
    if (n > 0) {
        buf[n] = '\0';
        char *nl = strchr(buf, '\n');
        if (nl) *nl = '\0';
        int out_fd = dup(fd);
        if (out_fd >= 0) {
            FILE *out = fdopen(out_fd, "w");
            if (out) { handle_request(buf, out); fclose(out); }
            else close(out_fd);
        }
    }
    close(fd);
    g_cli_fd[idx] = g_cli_fd[--g_cli_n];
}

/* ══════════════════════════════════════════════════════════════
 * 启动 / 主循环
 * ══════════════════════════════════════════════════════════════ */

static void handle_sig(int sig) { (void)sig; g_running = 0; }

static bool acquire_lock(void) {
    FILE *f = fopen(LOCK_FILE, "r");
    if (f) {
        pid_t pid = 0;
        if (fscanf(f, "%d", &pid) == 1 && pid > 0 && kill(pid, 0) == 0) {
            fclose(f);
            log_msg("Already running (pid=%d)", pid);
            return false;
        }
        fclose(f); remove(LOCK_FILE);
    }
    f = fopen(LOCK_FILE, "w");
    if (!f) return false;
    fprintf(f, "%d\n", (int)getpid());
    fclose(f);
    return true;
}

int main(void) {
    mkdir_p(RUN_DIR);
    g_log = fopen(LOG_FILE, "a");

    if (!acquire_lock()) return 1;

    signal(SIGTERM, handle_sig);
    signal(SIGINT,  handle_sig);

    /* 启动时加载历史（文件不存在时静默跳过） */
    load_persist();

    int nl_fd = nl_open();
    if (nl_fd < 0) return 1;

    g_srv_fd = sock_open();
    if (g_srv_fd < 0) { close(nl_fd); return 1; }

    /* 请求当前邻居表的全量快照 */
    nl_dump(nl_fd);

    log_msg("INFO: onliner started (pid=%d)", (int)getpid());

    while (g_running) {
        fd_set rset;
        FD_ZERO(&rset);
        FD_SET(nl_fd,    &rset);
        FD_SET(g_srv_fd, &rset);
        int maxfd = nl_fd > g_srv_fd ? nl_fd : g_srv_fd;
        for (int i = 0; i < g_cli_n; i++) {
            FD_SET(g_cli_fd[i], &rset);
            if (g_cli_fd[i] > maxfd) maxfd = g_cli_fd[i];
        }

        /* 60 秒超时用于心跳日志，正常有事件时立即返回 */
        struct timeval tv = { .tv_sec = 60 };
        int r = select(maxfd + 1, &rset, NULL, NULL, &tv);
        if (r < 0) {
            if (errno == EINTR) continue;
            log_msg("ERROR: select: %s", strerror(errno));
            break;
        }
        if (r == 0) {
            int online = 0;
            for (int i = 0; i < g_ndev; i++)
                if (g_devs[i].used && g_devs[i].online) online++;
            log_msg("TICK: %d devices, %d online", g_ndev, online);
            continue;
        }

        if (FD_ISSET(nl_fd,    &rset)) nl_recv(nl_fd);
        if (FD_ISSET(g_srv_fd, &rset)) sock_accept();
        for (int i = g_cli_n - 1; i >= 0; i--)
            if (FD_ISSET(g_cli_fd[i], &rset)) sock_serve(i);
    }

    log_msg("INFO: onliner stopping (pid=%d)", (int)getpid());
    close(nl_fd);
    close(g_srv_fd);
    for (int i = 0; i < g_cli_n; i++) close(g_cli_fd[i]);
    unlink(SOCKET_PATH);
    remove(LOCK_FILE);
    if (g_log) fclose(g_log);
    return 0;
}
