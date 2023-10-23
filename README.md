# ARC52 reference implementation

This implementation is not meant to be used in production. It is a reference implementation for the ARC52 specification.

## Run

```shell
$ yarn
$ yarn tests
```

## Output

```shell
 PASS  ./contextual.api.crypto.spec.ts
  Contextual Derivation & Signing
    (Derivations) Context
      ✓ (OK) Sign Arbitrary Message (19 ms)
      ✓ (OK) ECDH (33 ms)
      ✓ (OK) ECDH, Encrypt and Decrypt (30 ms)
      ✓ Libsodium example ECDH (4 ms)
      Addresses
        Soft Derivations
          ✓ (OK) Derive m'/44'/283'/0'/0/0 Algorand Address Key (30 ms)
          ✓ (OK) Derive m'/44'/283'/0'/0/1 Algorand Address Key (8 ms)
          ✓ (OK) Derive m'/44'/283'/0'/0/2 Algorand Address Key (8 ms)
        Hard Derivations
          ✓ (OK) Derive m'/44'/283'/1'/0/0 Algorand Address Key (8 ms)
          ✓ (OK) Derive m'/44'/283'/2'/0/1 Algorand Address Key (7 ms)
      Identities
        Soft Derivations
          ✓ (OK) Derive m'/44'/0'/0'/0/0 Identity Key (26 ms)
          ✓ (OK) Derive m'/44'/0'/0'/0/1 Identity Key (18 ms)
          ✓ (OK) Derive m'/44'/0'/0'/0/2 Identity Key (9 ms)
        Hard Derivations
          ✓ (OK) Derive m'/44'/0'/1'/0/0 Identity Key (15 ms)
          ✓ (OK) Derive m'/44'/0'/2'/0/1 Identity Key (9 ms)

Test Suites: 1 passed, 1 total
Tests:       14 passed, 14 total
Snapshots:   0 total
Time:        1.882 s, estimated 3 s
Ran all test suites.
Done in 2.40s.

```