# bpf-tracing: Rich diagnostics for eBPF

[![Crates.io][crates-badge]][crates-url]
[![GPL v3 licensed][gpl-badge]][gpl-url]
[![Build Status][actions-badge]][actions-url]

[crates-badge]: https://img.shields.io/crates/v/bpf-tracing.svg
[crates-url]: https://crates.io/crates/bpf-tracing
[gpl-badge]: https://img.shields.io/badge/License-GPL%20v3-blue.svg
[gpl-url]: LICENSE
[actions-badge]: https://github.com/lbrndnr/bpf-tracing-rs/actions/workflows/CI.yml/badge.svg
[actions-url]: https://github.com/lbrndnr/bpf-tracing-rs/actions/workflows/CI.yml

This is a tracing facility for eBPF that produces rich, event-based diagnostic information. Similar to [bpftool](https://github.com/libbpf/bpftool), it reads the kernel's tracefs file system, parses the logs and emits them conveniently using the [tracing](https://crates.io/crates/tracing) crate. 

## Usage

To use `bpf-tracing`, add the following to your `Cargo.toml`:
```toml
[dependencies]
bpf-tracing = "0.0.1"

[build-dependencies]
bpf-tracing-include = "0.0.2"
```

Next, in your `build.rs` script, provide the `bpf_tracing_include` arguments to clang as follows:
```rust
let mut args = vec![OsString::from("-I"), OsString::from("../include")];
args.extend(bpf_tracing_include::clang_args_from_env(true));

SkeletonBuilder::new()
    .source(&src)
    .clang_args(args)
    .build_and_generate(&out)
    .unwrap();
```
`clang_args_from_env` reads the `BPF_LOG` environment variable, and falls back to `RUST_LOG` if it's not set. Note that `bpf-tracing` disables tracing at compile time, since logging is expensive in eBPF. Note that this example uses [libbpf-rs](https://github.com/libbpf/libbpf-rs), but other libraries work just as well.

In your eBPF program, you can now include the [bpf_tracing.h](include/bpf_tracing.h) header and call tracing functions.
```c
#include "bpf_tracing.h"

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

Finally, in your Rust program, you'll have to enable `bpf-tracing`. It then starts reading the tracefs file system and continuously emits the tracing events.
```rust
bpf_tracing::try_init()?;
```

## License
This project is licensed under the [GPL-3.0 license](LICENSE).
