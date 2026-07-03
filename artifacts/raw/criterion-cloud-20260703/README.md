# Criterion re-run — cloud container, 2026-07-03

Re-measurement of the `nexus_validation` benchmark suite for the Nexus-IQ
white paper (see `WHITEPAPER.md` in the `adaptiveliquidity/Nexus-IQ`
repository, §8.2). `summary.json` carries mean/median/std-dev point estimates
plus p50/p95/p99 computed from the raw per-iteration sample distributions.

Environment: 4-vCPU Intel Xeon @ 2.80 GHz shared-tenancy cloud container,
15 GiB RAM, Linux 6.18.5, rustc 1.94.1, Nexus `85780b8a`, features
`bench-cold-start,bench-snapshot-create,bench-snapshot-rollback,
bench-execute-tool,bench-execute-real-memory,bench-integrated`.
No CPU-governor control (documented limitation, same caveat as the
2026-06-07 WSL2 validation report).

Headline observations (details in the white paper):

1. Rollback ≪ snapshot-create: 202 µs vs 5.81 ms at 1 MiB (~29×);
   87.7 ms vs 708 ms at 100 MiB.
2. Warm path is microseconds: cached-precompiled execute 172 µs;
   full integrated snapshot+execute+validate cycle 235 µs;
   module compilation dominates the cold path (~9.4× win from caching).
3. Execution cost is flat in guest memory size (1.7–2.1 ms across
   1–100 MiB); snapshot cost is linear in size.
4. Cross-environment deltas vs the published WSL2/Ryzen run are
   operation-class-dependent: cold-start ≈ identical, compression-bound
   snapshot ops 2.3–4.3× slower here, execute path 3–6× faster here
   (WSL2 thread-scheduling overhead hypothesis). Within-class ratios are
   the portable claims; absolute numbers are environment-indexed.
