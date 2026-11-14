# SENTINEL Adaptive Crypto Shield

This is the automatic key-changing layer that sits above the existing double
AES-256-GCM envelope and below TLS 1.3 transport.

## What changes automatically

SENTINEL keeps AES-256-GCM as the approved algorithm and automatically changes
**independent encryption keys by cryptographic epoch**. It does not randomly
switch algorithms, because uncontrolled algorithm changes can create downgrade,
interoperability, and recovery problems.

Rotation can be triggered by:

- key age
- message count
- encrypted byte volume
- security event
- administrative action
- emergency lockdown

Each epoch has independent inner and outer 256-bit keys. New ciphertext always
uses the active epoch. Retired epochs are accepted only during a bounded grace
period and can be revoked immediately.

## Production key storage

The reference implementation generates random test keys in memory. Production
keys MUST be generated/imported and retained by a KMS/HSM or equivalent managed
secret system. The application should receive only the minimum key operations it
needs.

Never persist these generated test keys in source control.
