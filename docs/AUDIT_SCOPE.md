# External Audit Scope — Nexus-IQ v1.0-rc

Single entry point for the external security audit planned before v1.1.0
(AUDIT.md defines contact and process; this document defines scope).

## Systems under audit

| Component | Repo / revision | Surface |
|---|---|---|
| Nexus hypervisor | `adaptiveliquidity/Nexus` @ v1.0-rc branch | WASM sandbox + WASI preopens, capability tokens, snapshot engine, proof capsules, daemon protocol, MCP stdio |
| AEON-IQ kernel | `adaptiveliquidity/AEON-IQ` @ v1.0-rc branch | OpenAI-compatible proxy, management REST API, pgvector retrieval, background workers |
| Bridge | `Nexus/crates/aeon_nexus_bridge` | evidence wire types, canonicalization, HMAC helpers |
| Self-host kit | `adaptiveliquidity/Nexus-IQ` | compose topology, secret generation, install/doctor scripts |

## Existing threat-model inputs (read in this order)

1. `docs/AEON_NEXUS_THREAT_MODEL.md` — full boundary table for the memory integration.
2. `docs/NEXUSIQ_THREAT_MODEL.md` — kit-level summary (top-5 trust boundaries).
3. `docs/security_threat_model_phase_b.md` — phase-B hardening decisions.
4. `docs/AEON_NEXUS_KEY_PROVISIONING.md` — key material separation and rotation.
5. `docs/NEXUSIQ_PROOF_LIMITATIONS.md` — what proof capsules do NOT claim.

## Findings pre-closed since the threat models were written

- **C2 (evidence trust)**: AEON-IQ now Ed25519 counter-signs served hit sets
  (`aeon-evidence-sig-v1`); Nexus verifies against a pinned key before
  `Attested*`; the verified flag is not settable via the daemon wire protocol.
- **Sensitivity egress**: archival/conflict candidates exclude
  `private`/`secret`; PATCH re-embed uses a scoped local lane
  (`LOCAL_EMBEDDING_BASE_URL`) or refuses. Residual: first-pass extraction
  relies on post-hoc-labeling timing — flag if insert-time labeling appears.
- **Registry integrity**: published images are cosign-signed keyless
  (GitHub OIDC) in all three publish workflows; DSSE capsule export exists.

## Priority questions for the auditor

1. Capability lexical path containment (symlink trust boundary) — is the
   documented `WasiToolConfig` escape hatch sufficient, and is the default
   safe for the kit's actual mount set?
2. Evidence counter-signature scheme: canonicalization byte-compatibility
   between AEON-IQ `attestation.rs` and `aeon_nexus_bridge` (independent
   implementations of the same key-sort algorithm — check for drift cases:
   non-BMP strings, float formatting, duplicate keys).
3. Fail-open surfaces: memory recall and timeline delivery fail open by
   design — validate the blast radius when AEON-IQ is compromised (advisory
   memory reaching denial negotiation, capped at 2 rounds/strict subset).
4. Daemon protocol authentication (`NEXUS_AGENTD_AUTH_TOKEN`) and the
   absence of per-request HMAC on the Nexus↔AEON link (documented
   non-feature; isolated network assumption).
5. The `AEON_ALLOW_INSECURE_PROVIDER_URLS` global flag vs the scoped local
   lane — confirm the global flag can be deprecated for kit deployments.

## Reproduction

`AUDIT.md` §Benchmark reproduction is current; the kit's
`./verify-live-stack.sh` is the end-to-end no-mocks check. The AEON-IQ
benchmark suite gates on `proof_status: pass` and includes an EXPLAIN-plan
regression test for the retrieval hot path.
