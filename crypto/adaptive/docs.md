# Adaptive Crypto Operations

## Normal rotation

A rotation occurs automatically when the active epoch reaches its configured
age, message count, or byte threshold. The old epoch remains decryptable only
for the configured grace period so retained ciphertext can be migrated or read.

## Emergency rotation

When SENTINEL enters an emergency cryptographic state, `emergency_rotate()`
creates a fresh epoch and immediately revokes the previous epoch. This is an
availability/security trade-off: ciphertext under the revoked epoch will no
longer decrypt through the active service. Recovery requires the protected KMS/
HSM backup and an explicit incident-response decision.

## Operational rule

Do not rotate keys merely to make the algorithm "random." Keep a small,
reviewed algorithm suite and rotate key material. Record every rotation and
revocation event in the immutable security audit pipeline.
