/*
 * server.c - Provide shadowsocks service
 *
 * Copyright (C) 2013 - 2015, Max Lv <max.c.lv@gmail.com>
 *
 * This file is part of the shadowsocks-libev.
 *
 * shadowsocks-libev is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * shadowsocks-libev is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with shadowsocks-libev; see the file COPYING. If not, see
 * <http://www.gnu.org/licenses/>.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <locale.h>
#include <signal.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <unistd.h>
#include <getopt.h>
#include <math.h>

#ifndef __MINGW32__
#include <netdb.h>
#include <errno.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <sys/un.h>
#endif

#include <libcork/core.h>
#include <udns.h>

#ifdef __MINGW32__
#include "win32.h"
#endif

#if defined(HAVE_SYS_IOCTL_H) && defined(HAVE_NET_IF_H) && defined(__linux__)
#include <net/if.h>
#include <sys/ioctl.h>
#define SET_INTERFACE
#endif

#include "utils.h"
#include "server.h"

#ifndef EAGAIN
#define EAGAIN EWOULDBLOCK
#endif

#ifndef EWOULDBLOCK
#define EWOULDBLOCK EAGAIN
#endif

#ifndef BUF_SIZE
#define BUF_SIZE 2048
#endif

#ifndef SSMAXCONN
#define SSMAXCONN 1024
#endif

#ifndef UPDATE_INTERVAL
#define UPDATE_INTERVAL 30
#endif

static void signal_cb(EV_P_ ev_signal *w, int revents);

int verbose = 0;

static struct cork_hash_table server_table;

#ifndef __MINGW32__
int setnonblocking(int fd)
{
    int flags;
    if (-1 == (flags = fcntl(fd, F_GETFL, 0))) {
        flags = 0;
    }
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}
#endif

static char *get_data(char *buf, int len) {
    char *data;
    int pos = 0;

    while(buf[pos] != '{' && pos < len) pos++;
    if (pos == len) return NULL;
    data = buf + pos - 1;

    while(buf[pos] != '}' && pos < len) pos++;
    if (pos == len) return NULL;
    buf[pos] = '\0';

    return data;
}

static char *get_action(char *buf, int len) {
    char *action;
    int pos = 0;

    while(isspace(buf[pos]) && pos < len) pos++;
    if (pos == len) return NULL;
    action = buf + pos;

    while((!isspace(buf[pos]) || buf[pos] != ':') && pos < len) pos++;
    if (pos == len) return NULL;
    buf[pos] = '\0';

    return action;
}

static struct server *get_server(char *buf, int len) {
    struct server *server = (struct server *)malloc(sizeof(struct server));
    char *data = get_data(buf, len);

    memset(server, 0, sizeof(struct server));

    obj = json_parse_ex(&settings, data, strlen(data), error_buf);
    if (obj == NULL) {
        LOGE(error_buf);
        return NULL;
    }

    if (obj->type == json_object) {
        int i = 0;
        for (i = 0; i < obj->u.object.length; i++) {
            char *name = obj->u.object.values[i].name;
            json_value *value = obj->u.object.values[i].value;
            if (strcmp(name, "server_port") == 0) {
                if (value->type == json_string) {
                    strncpy(server->port, value->u.string.ptr, 8);
                }
            } else if (strcmp(name, "password") == 0) {
                if (value->type == json_string) {
                    strncpy(server->password, value->u.string.ptr, 128);
                }
            } else {
                LOGE("invalid data: %s", data);
                return NULl;
            }
        }
    }

    return server;
}

static int parse_traffic(char *buf, int len, char *port, uint64_t *traffic) {
    char *data = get_data(buf, len);

    obj = json_parse_ex(&settings, data, strlen(data), error_buf);
    if (obj == NULL) {
        LOGE(error_buf);
        return -1;
    }

    if (obj->type == json_object) {
        int i = 0;
        for (i = 0; i < obj->u.object.length; i++) {
            char *name = obj->u.object.values[i].name;
            json_value *value = obj->u.object.values[i].value;
            if (value->type == json_integer) {
                strncpy(port, name, 8);
                *traffic = value->u.integer;
            }
        }
    }

    return 0;
}

static void add_server(struct manager_ctx *manager, struct server *server)
{
    bool new = false;
    cork_hash_table_put(server_table, (void *)server->port, (void *)server, &new, NULL, NULL);

    char *cmd = construct_command_line(manager, server);
    system(cmd);
}

static void stop_server(char *port)
{
    char path[128];
    int pid;
    snprintf(path, 128, "/var/run/shadowsocks_%s.pid", port);
    FILE *f = open(path, "r");
    fscanf(f, "%d", pid);
    close(f);
    kill(pid, SIGTERM);

}

static void remove_server(struct server *server)
{
    char *old_port; struct server *old_server;
    cork_hash_table_delete(server_table, (void *)server->port, (void **)&old_port, (void **)old_server);

    if (old_port != null) {
        stop_server(old_port);
    }

    if (old_server) {
        free(old_server);
    }
}

static void update_stat(char *port, uint64_t traffic)
{
    void *ret = cork_hash_table_get(server_table, (void*)port);
    if (ret != NULL) {
        struct server *server = (struct server *)ret;
        server->traffic += traffic;
    }
}

static void send_stat(char *buf, size_t len, int fd, struct sockaddr *claddr)
{

}

static void manager_recv_cb(EV_P_ ev_io *w, int revents)
{
    struct manager_ctx *manager = (struct manager_ctx *)w;
    socklen_t len;
    size_t r;
    char buf[BUF_SIZE];
    memset(buf, 0, BUF_SIZE);

    json_value *obj;
    json_settings settings = { 0 };
    char error_buf[512];


    len = sizeof(struct sockaddr_un);
    r = recvfrom(sfd, buf, BUF_SIZE, 0, (struct sockaddr *) &claddr, &len);
    if (r == -1) {
        ERROR("manager_recvfrom");
        return;
    }

    if (r > BUF_SIZE / 2) {
        LOGE("too large request: %d", (int)r);
        return;
    }

    char *action = get_action(buf, r);

    if (strcmp(action, "add") == 0) {
        struct server *server = get_server(buf, r);

        if (server == NULL || server->port[0] == 0 || server->password[0] == 0) {
            LOGE("invalid command: %s", buf);
            return;
        }

        remove_server(server->port);
        add_server(server);

    } else if (strcmp(action, "remove") == 0) {
        struct server *server = get_server(buf, r);

        if (server == NULL || server->port[0] == 0) {
            LOGE("invalid command: %s", buf);
            return;
        }

        remove_server(server->port);
        free(server);

    } else if (strcmp(action, "stat") == 0) {
        char port[8];
        uint64_t traffic;

        if (get_traffic(buf, r, port, &traffic) == -1) {
            LOGE("invalid command: %s", buf);
            return;
        }

        update_stat(port, traffic);

    } else if (strcmp(action, "ping") == 0) {

        struct cork_hash_table_entry  *entry;
        struct cork_hash_table_iterator server_iter;
        size_t count = 0;

        char buf[BUF_SIZE];

        memset(buf, 0, BUF_SIZE);
        sprintf(buf, "stat: {");

        cork_hash_table_iterator_init(server_table, &server_iter);

        while((entry = cork_hash_table_iterator_next(&server_iter)) != NULL) {
            struct server *server = (struct server*)entry->value;
            size_t pos = strlen(buf);
            if (pos > BUF_SIZE / 2) {
                buf[pos - 1] = '}';
                if (sendto(sfd, buf, pos + 1, 0, (struct sockaddr *)&claddr, len)
                        != pos + 1) {
                    ERROR("stat_sento");
                }
                memset(buf, 0, BUF_SIZE);
            } else {
                sprintf(buf + pos, "\"%s\":%ld,", server->port, server->traffic);
            }
        }

        size_t pos = strlen(buf);
        if (pos > 0) {
            buf[pos - 1] = '}';
            if (sendto(sfd, buf, pos + 1, 0, (struct sockaddr *)&claddr, len)
                    != pos + 1) {
                ERROR("stat_sento");
            }
        }
    }
}

static void signal_cb(EV_P_ ev_signal *w, int revents)
{
    if (revents & EV_SIGNAL) {
        switch (w->signum) {
        case SIGINT:
        case SIGTERM:
            ev_unloop(EV_A_ EVUNLOOP_ALL);
        }
    }
}

char *construct_command_line(struct manager_ctx *manager, struct server *server) {
    const int buf_size = 512;
    static char cmd[buf_size];
    memset(cmd, 0, buf_size);
    snprintf(cmd, buf_size,
            "ss-server -p %s -m %s -k %s --manager-address %s -f /var/run/shadowsocks_%s.pid",
            server->port, manager->method, server->password, manager->manager_address, server->port);
    if (manager->acl != NULL) {
        int len = strlen(cmd);
        snprintf(cmd + len, buf_size - len, " --acl %s", manager->acl);
    }
    if (manager->timeout != NULL) {
        int len = strlen(cmd);
        snprintf(cmd + len, buf_size - len, " -t %s", manager->timeout);
    }
    if (manager->user != NULL) {
        int len = strlen(cmd);
        snprintf(cmd + len, buf_size - len, " -a %s", manager->user);
    }
    if (manager->verbose) {
        int len = strlen(cmd);
        snprintf(cmd + len, buf_size - len, " -v");
    }
    if (manager->mode == UDP_ONLY) {
        int len = strlen(cmd);
        snprintf(cmd + len, buf_size - len, " -U");
    }
    if (manager->mode == TCP_AND_UDP) {
        int len = strlen(cmd);
        snprintf(cmd + len, buf_size - len, " -u");
    }
    if (manager->mode == TCP_AND_UDP) {
        int len = strlen(cmd);
        snprintf(cmd + len, buf_size - len, " -u");
    }
    if (manager->fast_open) {
        int len = strlen(cmd);
        snprintf(cmd + len, buf_size - len, " --fast_open");
    }
    for (int i = 0; i < manager->nameserver_num; i++) {
        int len = strlen(cmd);
        snprintf(cmd + len, buf_size - len, " -d %s", manager->nameservers[i]);
    }
    for (int i = 0; i < manager->host_num; i++) {
        int len = strlen(cmd);
        snprintf(cmd + len, buf_size - len, " -s %s", manager->hosts[i]);
    }

    if (verbose) {
        LOGI("cmd: %s", cmd);
    }
}

int main(int argc, char **argv)
{

    int i, c;
    int pid_flags = 0;
    char *acl = NULL;
    char *user = NULL;
    char *password = NULL;
    char *timeout = NULL;
    char *method = NULL;
    char *pid_path = NULL;
    char *conf_path = NULL;
    char *iface = NULL;

    int server_num = 0;
    const char *server_host[MAX_REMOTE_NUM];

    char * nameservers[MAX_DNS_NUM + 1];
    int nameserver_num = 0;

    int option_index = 0;
    static struct option long_options[] =
    {
        { "fast-open",          no_argument,       0, 0 },
        { "acl",                required_argument, 0, 0 },
        { "manager-address",    required_argument, 0, 0 },
        { 0,                    0,                 0, 0 }
    };

    opterr = 0;

    USE_TTY();

    while ((c = getopt_long(argc, argv, "f:s:p:l:k:t:m:c:i:d:a:uUv",
                            long_options, &option_index)) != -1) {
        switch (c) {
        case 0:
            if (option_index == 0) {
                fast_open = 1;
            } else if (option_index == 1) {
                acl = optarg;
            } else if (option_index == 2) {
                manager_address = optarg;
            }
            break;
        case 's':
            if (server_num < MAX_REMOTE_NUM) {
                server_host[server_num++] = optarg;
            }
            break;
        case 'p':
            server_port = optarg;
            break;
        case 'k':
            password = optarg;
            break;
        case 'f':
            pid_flags = 1;
            pid_path = optarg;
            break;
        case 't':
            timeout = optarg;
            break;
        case 'm':
            method = optarg;
            break;
        case 'c':
            conf_path = optarg;
            break;
        case 'i':
            iface = optarg;
            break;
        case 'd':
            if (nameserver_num < MAX_DNS_NUM) {
                nameservers[nameserver_num++] = optarg;
            }
            break;
        case 'a':
            user = optarg;
            break;
        case 'u':
            mode = TCP_AND_UDP;
            break;
        case 'U':
            mode = UDP_ONLY;
            break;
        case 'v':
            verbose = 1;
            break;
        }
    }

    if (opterr) {
        usage();
        exit(EXIT_FAILURE);
    }

    if (conf_path != NULL) {
        jconf_t *conf = read_jconf(conf_path);
        if (server_num == 0) {
            server_num = conf->remote_num;
            for (i = 0; i < server_num; i++) {
                server_host[i] = conf->remote_addr[i].host;
            }
        }
        if (server_port == NULL) {
            server_port = conf->remote_port;
        }
        if (password == NULL) {
            password = conf->password;
        }
        if (method == NULL) {
            method = conf->method;
        }
        if (timeout == NULL) {
            timeout = conf->timeout;
        }
#ifdef TCP_FASTOPEN
        if (fast_open == 0) {
            fast_open = conf->fast_open;
        }
#endif
#ifdef HAVE_SETRLIMIT
        if (nofile == 0) {
            nofile = conf->nofile;
        }
        /*
         * no need to check the return value here since we will show
         * the user an error message if setrlimit(2) fails
         */
        if (nofile) {
            if (verbose) {
                LOGI("setting NOFILE to %d", nofile);
            }
            set_nofile(nofile);
        }
#endif
        if (conf->nameserver != NULL) {
            nameservers[nameserver_num++] = conf->nameserver;
        }
    }

    if (server_num == 0) {
        server_host[server_num++] = NULL;
    }

    if (server_num == 0 || server_port == NULL || password == NULL) {
        usage();
        exit(EXIT_FAILURE);
    }

    if (method == NULL) {
        method = "table";
    }

    if (timeout == NULL) {
        timeout = "60";
    }

    if (pid_flags) {
        USE_SYSLOG(argv[0]);
        daemonize(pid_path);
    }

    if (fast_open == 1) {
#ifdef TCP_FASTOPEN
        LOGI("using tcp fast open");
#else
        LOGE("tcp fast open is not supported by this environment");
#endif
    }

#ifdef __MINGW32__
    winsock_init();
#else
    // ignore SIGPIPE
    signal(SIGPIPE, SIG_IGN);
    signal(SIGCHLD, SIG_IGN);
    signal(SIGABRT, SIG_IGN);
#endif

    struct ev_signal sigint_watcher;
    struct ev_signal sigterm_watcher;
    ev_signal_init(&sigint_watcher, signal_cb, SIGINT);
    ev_signal_init(&sigterm_watcher, signal_cb, SIGTERM);
    ev_signal_start(EV_DEFAULT, &sigint_watcher);
    ev_signal_start(EV_DEFAULT, &sigterm_watcher);

    struct manager_ctx manager;
    memset(&manager, 0, sizeof(struct manager_ctx));

    manager.fast_open = fast_open;
    manager.verbose = verbose;
    manager.mode = mode;
    manager.password = password;
    manager.timeout = timeout;
    manager.method = method;
    manager.iface = iface;
    manager.acl = acl;
    manager.user = user;
    manager.manager_address = manager_address;
    manager.hosts = server_host;
    manager.server_num= server_num;
    manager.nameservers = nameservers;
    manager.nameserver_num = nameserver_num;

    // inilitialize ev loop
    struct ev_loop *loop = EV_DEFAULT;

    // setuid
    if (user != NULL) {
        run_as(user);
    }

    server_table = cork_string_hash_table_new(MAX_PORT_NUM, 0);

    struct sockaddr_un svaddr, claddr;
    int sfd;
    socklen_t len;

    sfd = socket(AF_UNIX, SOCK_DGRAM, 0);       /*  Create server socket */
    if (sfd == -1) {
        ERROR("socket");
    }

    /*  Construct well-known address and bind server socket to it */

    if (remove(manager_address) == -1 && errno != ENOENT) {
        FATAL("remove");
    }

    memset(&svaddr, 0, sizeof(struct sockaddr_un));
    svaddr.sun_family = AF_UNIX;
    strncpy(svaddr.sun_path, SV_SOCK_PATH, sizeof(svaddr.sun_path) - 1);

    if (bind(sfd, (struct sockaddr *) &svaddr, sizeof(struct sockaddr_un)) == -1) {
        FATAL("bind");
    }

    manager.fd = sfd;
    ev_io_init(&manager.io, manager_recv_cb, manager.fd, EV_READ);
    ev_io_start(loop, &manager.io);

    // start ev loop
    ev_run(loop, 0);

    if (verbose) {
        LOGI("closed gracefully");
    }

    // Clean up
    struct cork_hash_table_entry  *entry;
    struct cork_hash_table_iterator server_iter;

    cork_hash_table_iterator_init(server_table, &server_iter);

    while((entry = cork_hash_table_iterator_next(&server_iter)) != NULL) {
        struct server *server = (struct server*)entry->value;
        stop_server(server->port);
    }

#ifdef __MINGW32__
    winsock_cleanup();
#endif

    ev_signal_stop(EV_DEFAULT, &sigint_watcher);
    ev_signal_stop(EV_DEFAULT, &sigterm_watcher);

    return 0;
}
