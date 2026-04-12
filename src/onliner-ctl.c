/*
 * onliner-ctl.c - 与 onliner 守护进程通信的极简工具
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * 用法：
 *   onliner-ctl get
 *   onliner-ctl set-name <mac> [<name>]
 *   onliner-ctl clear-offline
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>

#define SOCK_PATH "/tmp/onliner/onliner.sock"
#define BUF_SIZE  65536

static int connect_sock(void) {
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) { perror("socket"); return -1; }
    struct sockaddr_un sun = { .sun_family = AF_UNIX };
    snprintf(sun.sun_path, sizeof(sun.sun_path), "%s", SOCK_PATH);
    if (connect(fd, (struct sockaddr *)&sun, sizeof(sun)) < 0) {
        perror("connect"); close(fd); return -1;
    }
    return fd;
}

static void do_cmd(const char *cmd) {
    int fd = connect_sock();
    if (fd < 0) { fprintf(stderr, "onliner not running?\n"); exit(1); }

    /* 发命令 */
    size_t len = strlen(cmd);
    if (write(fd, cmd, len) != (ssize_t)len ||
        write(fd, "\n", 1) != 1) {
        perror("write"); close(fd); exit(1);
    }
    /* 关写端，让服务端知道请求结束（对 GET 有用） */
    shutdown(fd, SHUT_WR);

    /* 读回全部响应输出到 stdout */
    char buf[BUF_SIZE];
    ssize_t n;
    while ((n = read(fd, buf, sizeof(buf))) > 0)
        fwrite(buf, 1, n, stdout);

    close(fd);
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr,
            "Usage:\n"
            "  onliner-ctl get\n"
            "  onliner-ctl set-name <mac> [<name>]\n"
            "  onliner-ctl clear-offline\n");
        return 1;
    }

    if (strcmp(argv[1], "get") == 0) {
        do_cmd("GET");

    } else if (strcmp(argv[1], "set-name") == 0) {
        if (argc < 3) { fprintf(stderr, "set-name requires <mac>\n"); return 1; }
        char cmd[256];
        /* name 可以为空（清除自定义名） */
        if (argc >= 4)
            snprintf(cmd, sizeof(cmd), "SET_NAME %s %s", argv[2], argv[3]);
        else
            snprintf(cmd, sizeof(cmd), "SET_NAME %s ", argv[2]);
        do_cmd(cmd);

    } else if (strcmp(argv[1], "clear-offline") == 0) {
        do_cmd("CLEAR_OFFLINE");

    } else {
        fprintf(stderr, "Unknown command: %s\n", argv[1]);
        return 1;
    }

    return 0;
}
