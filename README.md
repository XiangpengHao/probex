# snitch

`snitch` is an eBPF-based Linux process tracer.
It runs a command, traces kernel events for that command (and forked children), writes a Parquet file, and can launch a web viewer for exploration.

## What It Traces

`snitch` currently attaches these tracepoints:

1. `sched:sched_switch`
2. `sched:sched_process_fork`
3. `sched:sched_process_exit`
4. `exceptions:page_fault_user`
5. `syscalls:sys_enter_read`
6. `syscalls:sys_exit_read`
7. `syscalls:sys_enter_write`
8. `syscalls:sys_exit_write`

9. `perf_event` CPU clock sampler (perf-style frequency sampling, default `999` Hz)

Events are filtered by a kernel-side PID map (`TRACED_PIDS`):

1. The target child PID is inserted before the command starts executing.
2. On fork, children are automatically added.
3. On process exit, that PID is removed.

## How It Works (Runtime Flow)

1. `snitch` loads embedded eBPF bytecode.
2. It forks a child and pauses it with `SIGSTOP` before `exec`.
3. It inserts the child PID into `TRACED_PIDS`.
4. It attaches all tracepoints.
5. It sends `SIGCONT`, so the child starts running the target command.
6. eBPF programs emit typed events into a ring buffer.
7. Userspace reads events, flattens them, and writes batched Parquet output.
8. When tracing ends, it optionally launches `snitch-viewer`.

## Quick Start (Linux)

### 1. Prerequisites

1. Stable Rust: `rustup toolchain install stable`
2. Nightly + `rust-src` (needed for eBPF build): `rustup toolchain install nightly --component rust-src`
3. `bpf-linker`: `cargo install bpf-linker` (`--no-default-features` on macOS)

You need Linux with eBPF tracepoint support and sufficient privileges (typically root).

### 2. Trace a command

First build the snitch-viewer app:
```shell
dx bundle --release --fullstack -p snitch-viewer
```

Then run the snitch to collect events.
```shell
sudo -E cargo run --release -p snitch -- -- sleep 1
```

Nix one-command flow (builds missing artifacts, traces, then opens viewer):
```shell
nix run .#snitch -- sleep 1
```

Default behavior:

1. Writes `trace.parquet`
2. If events were captured, launches `snitch-viewer` on port `8080`
3. If `snitch-viewer` is missing (or not bundled correctly), tracing still succeeds and `snitch` logs a warning instead of launching the viewer

### 3. Common CLI examples

Custom output path:

```shell
sudo -E cargo run --release -p snitch -- -o /tmp/my-trace.parquet -- sleep 2
```

Do not auto-launch viewer:

```shell
sudo -E cargo run --release -p snitch -- --no-viewer -- sleep 2
```

Enable perf-style CPU sampling at 99 Hz:

```shell
sudo -E cargo run --release -p snitch -- --sample-freq 99 -- sleep 5
```

For deep user-space call stacks, build traced binaries with frame pointers
enabled (for Rust: `RUSTFLAGS="-C force-frame-pointers=yes"`), otherwise
sampling stacks can look shallow or noisy.

Change viewer port used by auto-launch:

```shell
sudo -E cargo run --release -p snitch -- --port 9000 -- sleep 2
```

## Viewer Guide

For local fullstack development in this repo, use the Dioxus dev server:

```shell
dx serve -p snitch-viewer
```

The server reads `SNITCH_FILE` (default: `trace.parquet`), so set `SNITCH_FILE=/path/to/trace.parquet` when needed.

Then open `http://localhost:8080`.

For production/distribution of the fullstack app, build a Dioxus bundle:

```shell
dx bundle --release --platform server --fullstack -p snitch-viewer
```

The bundled server binary is typically produced under:

```shell
target/dx/snitch-viewer/release/web/snitch-viewer
```

You can also control output location:

```shell
dx bundle --release --platform server --fullstack -p snitch-viewer --out-dir ./dist
```

Then run the bundled executable and pass runtime args:

```shell
./dist/web/snitch-viewer --file trace.parquet --port 8080 --address 0.0.0.0
```

Viewer features:

1. Event table with pagination
2. Filter by event type
3. Filter by PID
4. Summary stats: total events, distinct event types/PIDs, trace duration

## Current Limitations

1. Linux-only (tracepoint/eBPF based).
2. `process_exit.exit_code` is currently `0` because that tracepoint does not provide exit status directly in this implementation.
3. `sched_switch` does not include real TGIDs for prev/next tasks (stored as `0`).
4. Only read/write syscalls are traced right now.

## Development

Regular checks:

```shell
cargo check
```

Integration tests that require root + eBPF support:

```shell
sudo -E cargo test --package snitch --test integration_test
```

## License

With the exception of eBPF code, snitch is distributed under the terms
of either the [MIT license] or the [Apache License] (version 2.0), at your
option.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in this crate by you, as defined in the Apache-2.0 license, shall
be dual licensed as above, without any additional terms or conditions.

### eBPF

All eBPF code is distributed under either the terms of the
[GNU General Public License, Version 2] or the [MIT license], at your
option.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in this project by you, as defined in the GPL-2 license, shall be
dual licensed as above, without any additional terms or conditions.

[Apache license]: LICENSE-APACHE
[MIT license]: LICENSE-MIT
[GNU General Public License, Version 2]: LICENSE-GPL2
