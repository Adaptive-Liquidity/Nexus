# AEON-IQ x Nexus Key Provisioning

**Status:** Phase 10 release hardening

Nexus uses three AEON-IQ integration key materials:

- `NEXUS_AEON_MANAGEMENT_KEY` (secret): authorizes calls to AEON-IQ management endpoints.
- `NEXUS_AEON_HMAC_KEY` (secret): binds AEON-IQ memory evidence into Nexus proof capsules.
- `NEXUS_AEON_VERIFYING_KEY` (public): AEON-IQ's Ed25519 evidence verifying key.
  When set, Nexus verifies the counter-signature AEON-IQ attaches to every
  memory-search response and only reports `Attested*` memory modes on success;
  a missing or invalid signature drops the hits and degrades the outcome.

They are separate key materials. Do not reuse one value for another.

## Generate Keys

Generate high-entropy hex strings outside source control. Use one 32-byte hex value for the management API key and a different 32-byte hex value for the HMAC key:

```bash
openssl rand -hex 32
```

The HMAC key is hex-decoded by Nexus; a 32-byte value is 64 hex characters.

## Distribute Keys

Provision the management key to both systems:

```bash
export MANAGEMENT_API_KEY="<64-hex-chars>"
export NEXUS_AEON_MANAGEMENT_KEY="$MANAGEMENT_API_KEY"
```

Provision the HMAC key to both systems:

```bash
export AEON_NEXUS_HMAC_KEY_HEX="<64-hex-chars>"
export NEXUS_AEON_HMAC_KEY="$AEON_NEXUS_HMAC_KEY_HEX"
```

AEON-IQ's exact HMAC environment variable name is deployment-owned, but it must receive the same HMAC key used by Nexus so AEON-IQ timeline/evidence rows can be verified against Nexus proof evidence.

Provision the evidence-signature key pair:

```bash
# On the AEON-IQ side: a private Ed25519 seed (secret)
export AEON_EVIDENCE_SIGNING_KEY="$(openssl rand -hex 32)"
```

Then read the corresponding public verifying key from AEON-IQ and pin it in
Nexus (it is public material — safe to store in config management):

```bash
curl -s -H "X-Management-Key: $MANAGEMENT_API_KEY" \
  "$AEON_BASE_URL/api/v1/evidence/verifying-key"
# → {"version":"aeon-evidence-sig-v1","key_id":"<64-hex>","persistent":true}
export NEXUS_AEON_VERIFYING_KEY="<key_id from the response>"
```

Do not pin a key reported with `"persistent": false` — that is an ephemeral
key that changes on every AEON-IQ restart (AEON_EVIDENCE_SIGNING_KEY unset).

Rotation: generate a new seed, restart AEON-IQ, re-read the verifying key,
update `NEXUS_AEON_VERIFYING_KEY`, restart Nexus consumers. During the window
between AEON-IQ and Nexus restarts, verification fails closed (hits dropped,
`Degraded` attestation) — schedule both restarts together.

Keys must be injected through the process environment or the deployment secret manager. Never commit keys, hardcode them in Rust, include them in examples with real values, or log them above debug. Debug logs should still avoid printing key material.

## Rotation Procedure

1. Generate a new management key and a new HMAC key.
2. Configure AEON-IQ to accept the new management key and use the new HMAC key for new evidence.
3. Roll Nexus with the matching `NEXUS_AEON_MANAGEMENT_KEY` and `NEXUS_AEON_HMAC_KEY`.
4. Run an `aeon-memory` smoke test and confirm new proof capsules report `memory_mode = Attested` when memory evidence is available.
5. Retire the old management key after all Nexus instances have moved.
6. Retain old HMAC keys in the audit-verifier environment for historical proof verification if historical capsules must be recomputed.

During rotation, in-flight proof capsules may reference evidence produced with the old key. Do not delete old verification material until the retention window for those proofs has passed.

## Absent Or Misconfigured Keys

If `NEXUS_AEON_MANAGEMENT_KEY` is absent, Nexus does not call AEON-IQ memory management endpoints. The memory client returns empty/no-op values and execution continues.

If `NEXUS_AEON_HMAC_KEY` is absent or empty, Nexus records `MemoryAttestationMode::Absent` and does not embed a `MemoryEvidenceRef`. Execution remains fail-open, but the proof is not memory-attested.

If the HMAC key is invalid hex, Nexus treats configuration loading as invalid instead of silently using a fallback key.

## Logging Rules

Keys are read only from environment variables. They must not be hardcoded or logged above debug. Operational logs may mention that a key is missing or invalid, but must not include key material. If debugging requires comparing evidence, compare digests or key ids in a controlled audit environment rather than printing secret values.
