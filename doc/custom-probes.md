# Runtime Custom Probes

The viewer can generate runtime custom probes for:

- `tracepoint`
- `fentry`
- `fexit`

Current constraints:

- Only a subset of argument/return field types is supported.
- Field/record/filter support depends on probe schema details from the running kernel.

Build/cache location:

- `~/.cache/probex/generated`
