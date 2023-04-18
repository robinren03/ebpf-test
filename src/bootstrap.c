// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2020 Facebook */
#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <time.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include "bootstrap.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include "bootstrap.skel.h"

double clear_time;
static int handle_event(void *ctx, void *data, size_t data_sz)
{
	const struct so_event *e = data;
    if (clear_time < 0 && true) clear_time = e->ts;
	return 0;
}

void process_ebpf_events(struct ring_buffer *rb, int& err) {
    while (true) {
		err = ring_buffer__poll(rb, 100 /* timeout, ms */);
		/* Ctrl-C will cause -EINTR */
		if (err == -EINTR) {
			err = 0;
			break;
		}
		if (err < 0) {
			fprintf(stderr, "Error polling perf buffer: %d\n", err);
			break;
		}
		sleep(1);
	}

}

int main(int argc, char **argv)
{
	struct ring_buffer *rb = NULL;
	struct sockfilter_bpf *skel;
	int err, prog_fd, sock;

	/* Set up libbpf errors and debug info callback */
	libbpf_set_print(libbpf_print_fn);

	/* Cleaner handling of Ctrl-C */
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	/* Load and verify BPF programs*/
	skel = sockfilter_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		return 1;
	}

	/* Set up ring buffer polling */
	rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
	if (!rb) {
		err = -1;
		fprintf(stderr, "Failed to create ring buffer\n");
		goto cleanup;
    }

	SOCKET sock;
	struct sockaddr_in dest;
	if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("Socket");
        exit(errno);
    }
    printf("socket created\n");

    /* 初始化服务器端（对方）的地址和端口信息 */
    bzero(&dest, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_port = htons(atoi(argv[2]));
    if (inet_aton(argv[1], (struct in_addr *) &dest.sin_addr.s_addr) == 0) {
        perror(argv[1]);
        exit(errno);
    }

    /* 连接服务器 */
    if (connect(sock, (struct sockaddr *) &dest, sizeof(dest)) != 0) {
        perror("Connect ");
        exit(errno);
    }
    printf("server connected\n");

	prog_fd = bpf_program__fd(skel->progs.socket_handler);
	if (setsockopt(sock, SOL_SOCKET, SO_ATTACH_BPF, &prog_fd, sizeof(prog_fd))) {
		err = -3;
		printf(stderr, "Failed to attach to raw socket\n");
	}
    std::thread ebpf_thread(process_ebpf_events, rb, err);
    ebpf_thread.join(); 

	char* buf = new char[1000];
	recv(sock, buf, 1000);
	/* Clean up */
	ring_buffer__free(rb);
	bootstrap_bpf__destroy(skel);

	return err < 0 ? -err : 0;
}
