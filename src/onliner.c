/*
 * onliner.c - LuCI online device tracker (C rewrite of onliner.sh)
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * 对比 Shell 版本的改进：
 *  - 直接读 /proc/net/arp，无需 fork `ip neigh`
 *  - 所有设备操作在内存哈希表完成，无需调用 jq
 *  - JSON 解析/生成为内置轻量实现，无外部依赖
 *  - 整个扫描周期零额外进程，内存占用 < 200KB
 *  - DHCP leases 解析也在进程内完成
 *
 * /etc/onliner/devices.json 仅保存 mac/name/custom_name 映射，
 * 仅在发现新设备时写入，避免频繁写 flash。
 * 运行时完整数据仍保存在 /tmp/onliner/devices.json（内存 fs）。
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
#include <strings.h>
#include <ctype.h>

/* ── 常量 ────────────────────────────────────────────────────── */
#define PERSIST_FILE   "/etc/onliner/devices.json"
#define RUN_DIR        "/tmp/onliner"
#define DEVICES_JSON   RUN_DIR "/devices.json"
#define LOG_FILE       RUN_DIR "/onliner.log"
#define LOCK_FILE      RUN_DIR "/onliner.lock"
#define DHCP_LEASES    "/tmp/dhcp.leases"
#define ARP_FILE       "/proc/net/arp"
#define SCAN_INTERVAL  30          /* 秒 */
#define MAX_DEVICES    512
#define MAC_LEN        18          /* "xx:xx:xx:xx:xx:xx\0" */
#define IP_LEN         46          /* IPv6 max */
#define NAME_LEN       64
#define IFACE_LEN      16
#define JSON_BUF_SIZE  (MAX_DEVICES * 512 + 256)

/* ── 设备结构体 ──────────────────────────────────────────────── */
typedef struct {
    char     mac[MAC_LEN];
    char     ip[IP_LEN];
    char     name[NAME_LEN];
    char     custom_name[NAME_LEN];
    char     interface[IFACE_LEN];
    bool     online;
    time_t   first_seen;
    time_t   last_online;
    time_t   last_offline;
    time_t   uptime;             /* 本次上线时刻 */
    bool     used;
} Device;

/* ── 全局状态 ─────────────────────────────────────────────────── */
static Device  g_devs[MAX_DEVICES];
static int     g_ndev = 0;
static volatile sig_atomic_t g_running = 1;
static FILE   *g_log = NULL;

/* ── 工具函数 ─────────────────────────────────────────────────── */
static void str_tolower(char *s) {
    for (; *s; s++) *s = (char)tolower((unsigned char)*s);
}

static void log_msg(const char *msg) {
    time_t t = time(NULL);
    struct tm *tm = localtime(&t);
    char ts[32];
    strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", tm);
    if (g_log) {
        fprintf(g_log, "%s %s\n", ts, msg);
        fflush(g_log);
    }
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

/* mkdir -p 简化版（只支持单层） */
static void mkdir_p(const char *path) {
    char tmp[256];
    snprintf(tmp, sizeof(tmp), "%s", path);
    for (char *p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            mkdir(tmp, 0755);
            *p = '/';
        }
    }
    mkdir(tmp, 0755);
}

/* ── 设备查找（线性，MAX_DEVICES=512 完全够用） ──────────────── */
static Device *find_device(const char *mac) {
    for (int i = 0; i < g_ndev; i++) {
        if (g_devs[i].used &&
            strcasecmp(g_devs[i].mac, mac) == 0)
            return &g_devs[i];
    }
    return NULL;
}

static Device *alloc_device(void) {
    if (g_ndev >= MAX_DEVICES) return NULL;
    Device *d = &g_devs[g_ndev++];
    memset(d, 0, sizeof(*d));
    d->used = true;
    return d;
}

/* ── DHCP leases 解析：查 MAC 或 IP 对应的主机名 ────────────── */
static void get_hostname(const char *ip, const char *mac, char *out, int outsz) {
    FILE *f = fopen(DHCP_LEASES, "r");
    if (!f) { snprintf(out, outsz, "?"); return; }

    char line[256], l_exp[32], l_mac[64], l_ip[64], l_name[NAME_LEN];
    out[0] = '\0';

    while (fgets(line, sizeof(line), f)) {
        /* 格式: expiry mac ip hostname client-id */
        if (sscanf(line, "%31s %63s %63s %63s",
                   l_exp, l_mac, l_ip, l_name) < 4) continue;
        if (strcasecmp(l_mac, mac) == 0 ||
            strcmp(l_ip, ip) == 0) {
            if (strcmp(l_name, "*") != 0) {
                snprintf(out, outsz, "%s", l_name);
                break;
            }
        }
    }
    fclose(f);
    if (out[0] == '\0') snprintf(out, outsz, "?");
}

/* ── 设备更新逻辑（对应 shell 的 upsert_device） ────────────── */
static void upsert_device(const char *ip, const char *mac,
                           bool online, const char *iface) {
    time_t now = time(NULL);
    Device *d = find_device(mac);

    if (d) {
        /* 已知设备 */
        if (online && !d->online) {
            /* offline → online */
            d->online      = true;
            d->uptime      = now;
            d->last_online = now;
            snprintf(d->ip, IP_LEN, "%s", ip);
            snprintf(d->interface, IFACE_LEN, "%s", iface);
            /* 仅在名称未知时更新 */
            if (d->name[0] == '\0' || strcmp(d->name, "?") == 0) {
                get_hostname(ip, mac, d->name, NAME_LEN);
            }
        } else if (!online && d->online) {
            /* online → offline */
            d->online       = false;
            d->last_offline = now;
        } else {
            /* 状态未变，更新 IP 即可 */
            snprintf(d->ip, IP_LEN, "%s", ip);
        }
    } else {
        /* 新设备 */
        d = alloc_device();
        if (!d) return;
        snprintf(d->mac, MAC_LEN, "%s", mac);
        str_tolower(d->mac);
        snprintf(d->ip,        IP_LEN,   "%s", ip);
        snprintf(d->interface, IFACE_LEN,"%s", iface);
        get_hostname(ip, mac, d->name, NAME_LEN);
        d->custom_name[0] = '\0';
        d->first_seen  = now;
        d->online      = online;
        if (online) {
            d->last_online = now;
            d->uptime      = now;
        }
        /* 新设备入表，立即持久化主机名映射 */
        save_names();
    }
}

/* ── /proc/net/arp 扫描 ──────────────────────────────────────── */
/*
 * /proc/net/arp 格式：
 * IP address       HW type  Flags  HW address          Mask  Device
 * 192.168.1.1      0x1      0x2    aa:bb:cc:dd:ee:ff   *     br-lan
 *
 * Flags: 0x2 = ATF_COM (完整条目，在线)
 *        0x0 / 0x4 = 不完整或静态
 */
static void scan(void) {
    FILE *f = fopen(ARP_FILE, "r");
    if (!f) { log_msg("ERROR: cannot open /proc/net/arp"); return; }

    /* 标记所有当前在线设备为"待核实" */
    bool seen[MAX_DEVICES];
    memset(seen, 0, sizeof(seen));

    char line[256];
    { char *_r = fgets(line, sizeof(line), f); (void)_r; } /* 跳过表头 */

    while (fgets(line, sizeof(line), f)) {
        char l_ip[IP_LEN], l_hwtype[16], l_flags[16];
        char l_mac[MAC_LEN], l_mask[16], l_dev[IFACE_LEN];

        if (sscanf(line, "%45s %15s %15s %17s %15s %15s",
                   l_ip, l_hwtype, l_flags, l_mac, l_mask, l_dev) < 6)
            continue;

        /* 跳过无效 MAC */
        if (strcmp(l_mac, "00:00:00:00:00:00") == 0) continue;
        /* 跳过 IPv6 链路本地（/proc/net/arp 通常只有 IPv4，但以防万一） */
        if (strncmp(l_ip, "fe80", 4) == 0) continue;

        /* flags 0x2 = REACHABLE/STALE 有效，0x0 = INCOMPLETE */
        long flags = strtol(l_flags, NULL, 16);
        bool is_online = (flags & 0x2) != 0;

        str_tolower(l_mac);
        upsert_device(l_ip, l_mac, is_online, l_dev[0] ? l_dev : "br-lan");

        /* 标记本次扫描中见过此设备 */
        Device *d = find_device(l_mac);
        if (d) seen[d - g_devs] = true;
    }
    fclose(f);

    /* 已知在线但本次 ARP 表中完全消失 → 离线 */
    time_t now = time(NULL);
    for (int i = 0; i < g_ndev; i++) {
        if (g_devs[i].used && g_devs[i].online && !seen[i]) {
            g_devs[i].online       = false;
            g_devs[i].last_offline = now;
        }
    }
}

/* ── 轻量 JSON 转义 ──────────────────────────────────────────── */
static int json_escape(char *out, int outsz, const char *in) {
    int n = 0;
    for (; *in && n < outsz - 2; in++) {
        if (*in == '"' || *in == '\\') {
            if (n + 2 >= outsz) break;
            out[n++] = '\\'; out[n++] = *in;
        } else if ((unsigned char)*in < 0x20) {
            /* 跳过控制字符 */
        } else {
            out[n++] = *in;
        }
    }
    out[n] = '\0';
    return n;
}

/* ── JSON 生成 ────────────────────────────────────────────────── */
static void write_json(const char *path) {
    /* 先写临时文件再原子替换 */
    char tmp[256];
    snprintf(tmp, sizeof(tmp), "%s.tmp", path);

    FILE *f = fopen(tmp, "w");
    if (!f) { log_fmt("ERROR: cannot write %s: %s", tmp, strerror(errno)); return; }

    fprintf(f, "{\"devices\":[\n");
    bool first = true;
    char esc[NAME_LEN * 2];

    for (int i = 0; i < g_ndev; i++) {
        Device *d = &g_devs[i];
        if (!d->used) continue;
        if (!first) fprintf(f, ",\n");
        first = false;

        json_escape(esc, sizeof(esc), d->name);
        fprintf(f,
            "  {\"mac\":\"%s\",\"ip\":\"%s\",\"name\":\"%s\",",
            d->mac, d->ip, esc);

        json_escape(esc, sizeof(esc), d->custom_name);
        fprintf(f,
            "\"custom_name\":\"%s\","
            "\"interface\":\"%s\","
            "\"status\":\"%s\","
            "\"first_seen\":%ld,"
            "\"last_online\":%ld,"
            "\"last_offline\":%ld,"
            "\"uptime\":%ld}",
            esc,
            d->interface,
            d->online ? "online" : "offline",
            (long)d->first_seen,
            (long)d->last_online,
            (long)d->last_offline,
            (long)d->uptime);
    }
    fprintf(f, "\n]}\n");
    fclose(f);

    if (rename(tmp, path) != 0)
        log_fmt("ERROR: rename %s -> %s: %s", tmp, path, strerror(errno));
}

/* ── 轻量 JSON 解析（只解析我们自己写的格式） ───────────────── */
/* 简单的 key 查找，找到 "key": 之后的字符串或数字值 */
static const char *json_find_key(const char *json, const char *key) {
    char needle[NAME_LEN + 4];
    snprintf(needle, sizeof(needle), "\"%s\":", key);
    return strstr(json, needle);
}

static bool json_get_str(const char *p, const char *key, char *out, int outsz) {
    const char *kp = json_find_key(p, key);
    if (!kp) return false;
    kp += strlen(key) + 3;  /* skip "key": */
    while (*kp == ' ') kp++;
    if (*kp != '"') return false;
    kp++;
    int n = 0;
    while (*kp && *kp != '"' && n < outsz - 1) {
        if (*kp == '\\' && *(kp+1)) { kp++; }
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

/* ── 持久化：只保存 mac/name/custom_name 映射 ───────────────── */
/*
 * 格式：
 * {"names":[
 *   {"mac":"aa:bb:cc:dd:ee:ff","name":"iPhone","custom_name":"老爸的手机"},
 *   ...
 * ]}
 *
 * 仅在发现新 MAC 或 custom_name 变更时写入，避免频繁写 flash。
 * 运行时完整状态保存在 /tmp/onliner/devices.json（tmpfs，不受影响）。
 */
static void save_names(void) {
    char tmp[256];
    snprintf(tmp, sizeof(tmp), "%s.tmp", PERSIST_FILE);

    FILE *f = fopen(tmp, "w");
    if (!f) { log_fmt("ERROR: cannot write %s: %s", tmp, strerror(errno)); return; }

    fprintf(f, "{\"names\":[\n");
    bool first = true;
    char esc_name[NAME_LEN * 2], esc_cname[NAME_LEN * 2];

    for (int i = 0; i < g_ndev; i++) {
        Device *d = &g_devs[i];
        if (!d->used) continue;
        if (!first) fprintf(f, ",\n");
        first = false;
        json_escape(esc_name,  sizeof(esc_name),  d->name);
        json_escape(esc_cname, sizeof(esc_cname), d->custom_name);
        fprintf(f, "  {\"mac\":\"%s\",\"name\":\"%s\",\"custom_name\":\"%s\"}",
                d->mac, esc_name, esc_cname);
    }
    fprintf(f, "\n]}\n");
    fclose(f);

    if (rename(tmp, PERSIST_FILE) != 0)
        log_fmt("ERROR: rename %s -> %s: %s", tmp, PERSIST_FILE, strerror(errno));
    else
        log_fmt("names saved (%d devices)", g_ndev);
}

/* ── 启动时加载主机名映射，恢复 name/custom_name ────────────── */
static void load_json(const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) return;

    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    rewind(f);

    if (sz <= 0 || sz > 256 * 1024) { fclose(f); return; }

    char *buf = malloc(sz + 1);
    if (!buf) { fclose(f); return; }
    if (fread(buf, 1, sz, f) != (size_t)sz) { free(buf); fclose(f); return; }
    buf[sz] = '\0';
    fclose(f);

    /* 逐个 {} 块解析，只取 mac / name / custom_name */
    const char *p = buf;
    while ((p = strchr(p, '{')) != NULL) {
        if (*(p+1) == '"' || *(p+1) == '\n') {
            const char *end = strchr(p, '}');
            if (!end) break;

            int objlen = (int)(end - p + 1);
            char *obj = malloc(objlen + 1);
            if (!obj) { p = end + 1; continue; }
            memcpy(obj, p, objlen);
            obj[objlen] = '\0';

            char mac[MAC_LEN] = "", name[NAME_LEN] = "", cname[NAME_LEN] = "";
            json_get_str(obj, "mac",         mac,   MAC_LEN);
            json_get_str(obj, "name",        name,  NAME_LEN);
            json_get_str(obj, "custom_name", cname, NAME_LEN);
            free(obj);

            if (mac[0] == '\0') { p = end + 1; continue; }

            /* 预填到设备表，等 scan() 时再补齐 IP/接口/状态等 */
            Device *d = alloc_device();
            if (!d) break;
            snprintf(d->mac,         MAC_LEN,  "%s", mac);
            snprintf(d->name,        NAME_LEN, "%s", name);
            snprintf(d->custom_name, NAME_LEN, "%s", cname);
            d->online = false;   /* 重启后一律离线，等 scan 重新判断 */

            p = end + 1;
        } else {
            p++;
        }
    }
    free(buf);
    log_fmt("loaded %d name mappings from %s", g_ndev, path);
}

/* ── 信号处理 ────────────────────────────────────────────────── */
static void handle_signal(int sig) {
    (void)sig;
    g_running = 0;
}

/* ── Lock 文件 ───────────────────────────────────────────────── */
static bool acquire_lock(void) {
    /* 检查旧 lock */
    FILE *f = fopen(LOCK_FILE, "r");
    if (f) {
        pid_t old_pid = 0;
        if (fscanf(f, "%d", &old_pid) != 1) old_pid = 0;
        fclose(f);
        if (old_pid > 0 && kill(old_pid, 0) == 0) {
            log_fmt("Already running (pid=%d), exiting.", old_pid);
            return false;
        }
        /* 死进程遗留的 lock，清除 */
        remove(LOCK_FILE);
    }

    f = fopen(LOCK_FILE, "w");
    if (!f) return false;
    fprintf(f, "%d\n", (int)getpid());
    fclose(f);
    return true;
}

/* ── main ────────────────────────────────────────────────────── */
int main(void) {
    /* 初始化目录 */
    mkdir_p(RUN_DIR);
    mkdir_p("/etc/onliner");

    /* 打开日志 */
    g_log = fopen(LOG_FILE, "a");

    /* Lock */
    if (!acquire_lock()) return 1;

    /* 信号 */
    signal(SIGTERM, handle_signal);
    signal(SIGINT,  handle_signal);

    /* 加载历史数据 */
    load_json(PERSIST_FILE);

    log_fmt("onliner started (pid=%d, /proc/net/arp mode)", (int)getpid());

    while (g_running) {
        scan();
        /* 只写 tmpfs，持久化仅在新设备出现时由 save_names() 触发 */
        write_json(DEVICES_JSON);

        /* 分段 sleep，每秒检查一次 g_running，使 SIGTERM 快速响应 */
        for (int i = 0; i < SCAN_INTERVAL && g_running; i++)
            sleep(1);
    }

    log_fmt("onliner stopping (pid=%d)", (int)getpid());
    remove(LOCK_FILE);
    if (g_log) fclose(g_log);
    return 0;
}
