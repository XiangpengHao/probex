# probex 

`probex` is the missing Linux profiler you've been waiting for.
It is low-friction, easy to use, and works out of the box.

## Usage

### Nix
```
nix run github:XiangpengHao/probex -- sleep 1
```

### Cargo

You need to have the `bpf-linker` tool installed.

```shell
cargo install bpf-linker
cargo install probex
probex -- sleep 1
```

Or build from source:
```shell
cargo build --release -p probex --locked
target/release/probex -- sleep 1
```

### Launch modes

`probex` supports three user-facing modes:

```shell
# Launch backend + frontend only (no initial trace loaded)
probex

# Open an existing trace file
probex --view trace.parquet

# Trace a command, then open the result in the viewer
probex -- sleep 1
```

### Download binary

```shell
wget -O probex.tar.gz $(curl -s https://api.github.com/repos/XiangpengHao/probex/releases/latest | grep "browser_download_url.*linux-x86_64.*tar.gz" | cut -d : -f 2,3 | tr -d \")
tar -xzf probex.tar.gz
sudo ./probex -- sleep 1
```
## Demo 
<video src="https://github.com/user-attachments/assets/5d66ac40-fefc-4cbb-9edc-2fa31e358ae7" controls="controls"></video>

#### Frame pointers

`probex` works best with frame pointers enabled on the target binary.
Without them, stack traces may be shallow or incomplete.
[Why you should enable them](https://www.brendangregg.com/blog/2024-03-17/the-return-of-the-frame-pointers.html).

Rust — add to `.cargo/config.toml`:
```toml
[build]
rustflags = ["-C", "force-frame-pointers=yes"]
```

C / C++ — compile with `-fno-omit-frame-pointer`.


## License

With the exception of eBPF code, probex is distributed under the terms
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
