// SPDX-License-Identifier: GPL-2.0
#include <stdio.h>
#include <assert.h>
#include <linux/bpf.h>
#include <bpf/bpf.h>
#include "libbpf.h"
#include "sock_example.h"
#include <unistd.h>
#include <arpa/inet.h>
#include <string.h>
int main(int ac, char **argv)
{

	struct bpf_object *obj;
	int map_fd, prog_fd, map_fd2, map_fd3, map_fd4, map_fd5, map_fd6, map_fd7;
	char filename[256];
	int i, sock;
	FILE *f;

	snprintf(filename, sizeof(filename), "%s_kern.o", argv[0]);
	if (bpf_prog_load(filename, BPF_PROG_TYPE_SOCKET_FILTER,
			  &obj, &prog_fd))
		return 1;
	return 0;	
}
