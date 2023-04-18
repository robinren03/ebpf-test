/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2020 Facebook */
#ifndef __BOOTSTRAP_H
#define __BOOTSTRAP_H

#define TASK_COMM_LEN 16
#define MAX_FILENAME_LEN 127

struct so_event {
	__be32 src_addr;
	__u32 ip_proto;
	__u32 ts;
};

#endif /* __BOOTSTRAP_H */
