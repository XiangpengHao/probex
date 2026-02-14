# Engineering principles

1. Think about minimal changes to complete the task.
2. Always cargo check after coding.
3. Consider refactoring when a function needs more than 3 args.
4. When fixing a bug, think from first principles: why it happened, what is the root cause, what is the best place to fix it.
5. Whenever you want to use web-sys, js-sys, and wasm-bindgen, consider what dioxus already provides. try not to use low level APIs unless necessary.

# Agent guides

1. Ask if you think one instruction is ambiguous.
2. Ask if you're unsure which alternative is better.
3. Always run cargo check after coding.

# Session learnings

- Prefer builder-style APIs over request structs for ergonomics.
- Split modules by cognitive boundary; keep types with their implementations.
- Do not add new dependency.
- Prefer compact, information-dense summaries over tall cards; colocate related controls/stats and remove redundant panels.
- We never care about compatibility. Focus on new code/feature/format only.
- Prefer strict contracts over best-effort behavior: missing required schema/data is a hard failure.
- Use types and parser invariants to make invalid states unrepresentable; avoid runtime “ignore/fallback” branches.
