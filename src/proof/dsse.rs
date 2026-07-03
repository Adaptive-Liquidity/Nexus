//! DSSE (Dead Simple Signing Envelope) export for Proof Capsules.
//!
//! Wraps a capsule's canonical JSON as a DSSE envelope so standard
//! supply-chain tooling (in-toto verifiers, `cosign verify-blob` with DSSE
//! support) can consume runtime attestations without understanding Nexus's
//! native `SignatureEnvelope`.  The DSSE signature is computed over the
//! spec's Pre-Authentication Encoding (PAE) with the same dedicated proof
//! key used for native capsule signing — provisioned via
//! `NEXUS_PROOF_SIGNING_KEY`, since an ephemeral per-process key cannot be
//! recovered by an offline export command.
//!
//! Scope note (GA): this is an *optional output format*, not a redesign —
//! full Sigstore/Rekor transparency-log integration remains post-GA.

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::error::{NexusError, Result};
use crate::proof::canonical::canonical_bytes;
use crate::proof::schema::ProofCapsule;

/// DSSE payloadType for a Nexus proof capsule.  The payload is the capsule's
/// canonical (recursively key-sorted) JSON, so the capsule's own
/// `limitations[]` honesty array travels inside every envelope.
pub const CAPSULE_PAYLOAD_TYPE: &str = "application/vnd.nexus.proof-capsule+json";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DsseSignature {
    /// Hex-encoded Ed25519 verifying key (matches the capsule's native
    /// `signature.key_id` convention).
    pub keyid: String,
    /// Base64 (standard) of the raw 64-byte Ed25519 signature over the PAE.
    pub sig: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DsseEnvelope {
    #[serde(rename = "payloadType")]
    pub payload_type: String,
    /// Base64 (standard) of the canonical capsule JSON.
    pub payload: String,
    pub signatures: Vec<DsseSignature>,
}

/// DSSE v1 Pre-Authentication Encoding:
/// `"DSSEv1" SP LEN(type) SP type SP LEN(payload) SP payload`.
pub fn pae(payload_type: &str, payload: &[u8]) -> Vec<u8> {
    let mut out = format!(
        "DSSEv1 {} {} {} ",
        payload_type.len(),
        payload_type,
        payload.len()
    )
    .into_bytes();
    out.extend_from_slice(payload);
    out
}

/// Wrap a capsule in a signed DSSE envelope.
pub fn wrap_capsule(capsule: &ProofCapsule, key: &SigningKey) -> Result<DsseEnvelope> {
    let payload = canonical_bytes(capsule).map_err(|e| {
        NexusError::ConfigError(format!("failed to canonicalize capsule for DSSE: {e}"))
    })?;
    let signature = key.sign(&pae(CAPSULE_PAYLOAD_TYPE, &payload));
    Ok(DsseEnvelope {
        payload_type: CAPSULE_PAYLOAD_TYPE.to_string(),
        payload: STANDARD.encode(&payload),
        signatures: vec![DsseSignature {
            keyid: hex_lower(&key.verifying_key().to_bytes()),
            sig: STANDARD.encode(signature.to_bytes()),
        }],
    })
}

/// Verify a DSSE envelope against a verifying key.  Checks payload type,
/// keyid match, and the Ed25519 signature over the PAE.
pub fn verify_envelope(
    envelope: &DsseEnvelope,
    vk: &VerifyingKey,
) -> std::result::Result<(), String> {
    if envelope.payload_type != CAPSULE_PAYLOAD_TYPE {
        return Err(format!(
            "unexpected payloadType {:?} (expected {CAPSULE_PAYLOAD_TYPE:?})",
            envelope.payload_type
        ));
    }
    let payload = STANDARD
        .decode(&envelope.payload)
        .map_err(|e| format!("payload is not valid base64: {e}"))?;
    let expected_keyid = hex_lower(&vk.to_bytes());
    let matching = envelope
        .signatures
        .iter()
        .find(|s| s.keyid.eq_ignore_ascii_case(&expected_keyid))
        .ok_or_else(|| format!("no signature with keyid {expected_keyid}"))?;
    let sig_bytes = STANDARD
        .decode(&matching.sig)
        .map_err(|e| format!("signature is not valid base64: {e}"))?;
    let sig_bytes: [u8; 64] = sig_bytes
        .as_slice()
        .try_into()
        .map_err(|_| "signature is not 64 bytes".to_string())?;
    let signature = Signature::from_bytes(&sig_bytes);
    vk.verify(&pae(&envelope.payload_type, &payload), &signature)
        .map_err(|e| format!("DSSE signature verification failed: {e}"))
}

fn hex_lower(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proof::schema::ProofCapsuleBuilder;

    fn test_capsule() -> ProofCapsule {
        use crate::proof::schema::TypedDigest;
        ProofCapsuleBuilder::new(
            "dsse_test_tool",
            TypedDigest::sha256_public(b"module-bytes"),
            TypedDigest::sha256_public(b"input-bytes"),
        )
        .build()
    }

    /// PAE follows the DSSE v1 spec byte-for-byte.
    #[test]
    fn pae_matches_spec_encoding() {
        let encoded = pae("t", b"pp");
        assert_eq!(encoded, b"DSSEv1 1 t 2 pp".to_vec());
    }

    /// Wrap → verify round-trips with the signing key's verifying key.
    #[test]
    fn wrap_and_verify_round_trip() {
        let key = SigningKey::from_bytes(&[3u8; 32]);
        let envelope = wrap_capsule(&test_capsule(), &key).unwrap();
        assert_eq!(envelope.payload_type, CAPSULE_PAYLOAD_TYPE);
        assert_eq!(envelope.signatures.len(), 1);
        verify_envelope(&envelope, &key.verifying_key()).expect("round trip must verify");
    }

    /// Any payload tamper (even one byte) fails verification.
    #[test]
    fn tampered_payload_fails() {
        let key = SigningKey::from_bytes(&[3u8; 32]);
        let mut envelope = wrap_capsule(&test_capsule(), &key).unwrap();
        let mut payload = STANDARD.decode(&envelope.payload).unwrap();
        let last = payload.len() - 1;
        payload[last] ^= 0x01;
        envelope.payload = STANDARD.encode(&payload);
        assert!(verify_envelope(&envelope, &key.verifying_key()).is_err());
    }

    /// A signature from a different key is rejected by keyid mismatch.
    #[test]
    fn wrong_key_fails() {
        let key = SigningKey::from_bytes(&[3u8; 32]);
        let other = SigningKey::from_bytes(&[4u8; 32]);
        let envelope = wrap_capsule(&test_capsule(), &key).unwrap();
        assert!(verify_envelope(&envelope, &other.verifying_key()).is_err());
    }
}
