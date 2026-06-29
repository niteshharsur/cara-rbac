// SPDX-License-Identifier: GPL-2.0
// cara_connect.bpf.c
//
// eBPF kprobe/tracepoint program that intercepts outgoing TCP connect()
// calls from containers and filters those targeting the Kubernetes API server
// (default port 6443). Matched events are pushed to a BPF perf event ring
// buffer for the Go userspace agent to consume.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#define TASK_COMM_LEN 16
#define AF_INET       2
#define AF_INET6      10

// Target port for Kubernetes API server (configurable via map)
#define DEFAULT_APISERVER_PORT 6443

struct event {
    __u32 pid;
    __u32 tid;
    __u32 uid;
    __u32 gid;
    __u64 cgroup_id;
    __u32 daddr;     // destination IPv4 address (network byte order)
    __u16 dport;     // destination port (host byte order)
    __u8  comm[TASK_COMM_LEN];
};

// Perf event output map
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} events SEC(".maps");

// Configurable target port map (index 0 = apiserver port)
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u16);
} target_port SEC(".maps");

SEC("kprobe/tcp_connect")
int BPF_KPROBE(trace_tcp_connect, struct sock *sk) {
    struct event evt = {};

    // Read destination address and port
    __u16 dport = 0;
    BPF_CORE_READ_INTO(&dport, sk, __sk_common.skc_dport);
    dport = __builtin_bswap16(dport); // network to host byte order

    // Check target port — default 6443, or read from map
    __u32 key = 0;
    __u16 *configured_port = bpf_map_lookup_elem(&target_port, &key);
    __u16 api_port = configured_port ? *configured_port : DEFAULT_APISERVER_PORT;

    if (dport != api_port) {
        return 0; // Not API server traffic
    }

    // Read destination IPv4 address
    __u16 family = 0;
    BPF_CORE_READ_INTO(&family, sk, __sk_common.skc_family);
    if (family != AF_INET) {
        return 0; // Only handle IPv4 for now
    }

    BPF_CORE_READ_INTO(&evt.daddr, sk, __sk_common.skc_daddr);
    evt.dport = dport;

    // Process metadata
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    evt.pid = pid_tgid >> 32;
    evt.tid = (__u32)pid_tgid;

    __u64 uid_gid = bpf_get_current_uid_gid();
    evt.uid = (__u32)uid_gid;
    evt.gid = uid_gid >> 32;

    evt.cgroup_id = bpf_get_current_cgroup_id();

    bpf_get_current_comm(&evt.comm, sizeof(evt.comm));

    // Submit event
    bpf_perf_event_output(bpf_get_current_task(), &events, BPF_F_CURRENT_CPU,
                          &evt, sizeof(evt));
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
