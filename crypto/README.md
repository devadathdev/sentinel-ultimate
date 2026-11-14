# SENTINEL Cryptographic Vault — v1.0

This module adds the post-7-layer cryptographic envelope requested for SENTINEL.

## Protection model

1. Application plaintext is authenticated and encrypted with **AES-256-GCM / inner key**.
2. The complete inner envelope is independently authenticated and encrypted with **AES-256-GCM / outer key**.
3. Network transport is protected separately by **TLS 1.3** at the hardened reverse proxy/load balancer.

The two AES keys are required to be different. Keys are represented by key IDs and must come from a KMS/HSM or equivalent secret manager in production.

## Key handling

Never commit generated keys. Generate 32-byte random keys and store them in a KMS/HSM. Rotate keys using versioned key IDs and retain old decrypt keys only for the documented ciphertext-retention window.

## Replay / freshness

Every envelope contains a UUID event ID and creation timestamp. The reference decryptor rejects future-dated envelopes and envelopes older than the configured maximum age. For high-assurance distributed deployments, add a durable event-ID replay store (Redis/database/KMS-backed service) before accepting repeated event IDs.

## TLS

TLS 1.3 is transport protection, not a replacement for the two application encryption layers. Terminate TLS at a hardened reverse proxy and keep TLS private keys separate from AES key material.

This is a cryptographic component, not a claim that the complete SENTINEL system is unbreakable.

## Adaptive Crypto Shield

`crypto/adaptive/` adds automatic key-epoch rotation around the two AES-256-GCM
layers. AES-256-GCM remains stable; independent inner/outer keys change by epoch.
Rotation can be triggered by age, message count, byte volume, security events,
administrative action, or emergency lockdown. Retired epochs have bounded grace
and can be explicitly revoked.

Production key material must be managed by a KMS/HSM. The reference adaptive
manager generates ephemeral test keys only and must not be used as a production
key store.
