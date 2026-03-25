# bpf-tracing

This is a tracing facility for eBPF that integrates neatly into the [tracing](https://crates.io/crates/tracing) crate. 

## Usage

Include the [bpf_tracing.h](include/bpf_tracing.h) header.

```c
#include "bpf-tracing.h"

SEC("sockops")
int monitor_sockets(struct bpf_sock_ops *ops) {
    if (ops->op == BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB || ops->op == BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB) {
        bpf_start_info_span("sockops");

        bpf_info("Established socket %d", skey.local.port);

        bpf_end_span("sockops");
    }

    return SK_PASS;
}
```

Consult [monitor.bpf.c](bpf-tracing/examples/monitor.bpf.c) for a more complete example.
