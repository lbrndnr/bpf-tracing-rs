# bpf-tracing: Rich diagnostics for eBPF

[![Crates.io][crates-badge]][crates-url]
[![MIT licensed][mit-badge]][mit-url]
[![Build Status][actions-badge]][actions-url]

[crates-badge]: https://img.shields.io/crates/v/bpf-tracing.svg
[crates-url]: https://crates.io/crates/bpf-tracing
[mit-badge]: https://img.shields.io/badge/License-MIT-blue.svg
[mit-url]: LICENSE
[actions-badge]: https://github.com/lbrndnr/bpf-tracing-rs/actions/workflows/CI.yml/badge.svg
[actions-url]: https://github.com/lbrndnr/bpf-tracing-rs/actions/workflows/CI.yml

This is a tracing facility for eBPF that produces rich, event-based diagnostic information. Similar to [bpftool](https://github.com/libbpf/bpftool), it reads the kernel's tracefs file system, parses the logs and emits them conveniently using the [tracing](https://crates.io/crates/tracing) crate. 

## Usage

You can run the example using `RUST_LOG=trace cargo r --bin example` 

To use `bpf-tracing`, add the following to your `Cargo.toml`:
```toml
[dependencies]
bpf-tracing = "0.0.4"

[build-dependencies]
bpf-tracing-include = "0.0.4"
```

Next, in your `build.rs` script, provide the `bpf_tracing_include` arguments to clang as follows:
```rust
let mut args = vec![OsString::from("-I"), OsString::from("../include")];
args.extend(bpf_tracing_include::clang_args_from_default_env(true).unwrap());

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

This will yield the following trace:
```
2026-04-20T13:23:27.545062Z  INFO bpf: example/src/monitor.bpf.c:34: sockops
2026-04-20T13:23:27.545166Z  INFO bpf: example/src/monitor.bpf.c:50: Established socket [127.0.0.1:34812->127.0.0.1:9999]
2026-04-20T13:23:27.545239Z  INFO bpf: example/src/monitor.bpf.c:60: Add socket [127.0.0.1:34812->127.0.0.1:9999]
2026-04-20T13:23:27.545345Z  INFO bpf: example/src/monitor.bpf.c:34: sockops
2026-04-20T13:23:27.545450Z  INFO bpf: example/src/monitor.bpf.c:50: Established socket [127.0.0.1:9999->127.0.0.1:34812]
```

## License
This project is licensed under the [MIT license](LICENSE).
