# TPM-bound mixed-curve identities

Status: implementation design

## Goals

Nebula nodes may hold X25519, NIST P-256, and NIST P-384 static ECDH
keys. A node advertises its usable keys in local preference order and two
forked nodes choose the first local preference also supported by the peer.
P-256 and P-384 private operations may be performed by a TPM without exporting
the private scalar. Existing Nebula nodes remain reachable through the current
X25519 IX handshake.

This design deliberately does not pretend that unlike curves can perform ECDH:
both operands of every DH operation use the selected curve.

## Existing constraints

The current wire protocol chooses the Noise DH function before parsing any
handshake payload. `flynn/noise` also uses `DHLen` to parse static public keys,
so a responder cannot infer the suite after beginning IX. The current
certificate `Curve` field conflates the host public-key algorithm with the CA
signature algorithm. `CertState` stores one private key shared by its v1 and v2
certificates. P-256 PKCS#11 ECDH already exists, but there is no TPM backend,
P-384 suite, or multi-key identity.

An unauthenticated pre-handshake capability packet would permit stripping and
reordering. A timeout followed automatically by X25519 would permit an active
attacker to force that fallback. Neither is acceptable as negotiation.

## Protocol

### Authenticated bootstrap

Every identity that enables compatibility mode has a CA-signed X25519
bootstrap certificate and key. Forked and stock nodes first complete the
existing `HandshakeIXPSK0` exchange unchanged. Stock peers therefore require
no new parser or wire behavior.

Forked nodes append an optional, backwards-compatible protobuf field to the
encrypted handshake payload:

```protobuf
message KeyCapability {
  uint32 curve = 1;
  bytes certificate = 2;
}

repeated KeyCapability key_capabilities = 9; // preference order
bytes capability_nonce = 10;                 // 32 random bytes
```

Each certificate binds the same Nebula network identity and groups to one
public key and is independently validated by the configured CA pool. Because
legacy Nebula certificates conflate host and CA curves, deployments currently
use one trusted CA root per curve with equivalent constraints; exact issuer
fingerprints and validity timestamps need not match. The existing X25519 certificate is
included conceptually as the bootstrap capability but need not be duplicated.
Unknown fields remain ignored by stock Nebula's narrow parser.

The capability list is covered by Noise transport authentication because it is
inside the encrypted IX payload. Each advertised certificate is independently
verified against the CA pool before selection. Duplicate curves, unknown
curves, malformed public points, inconsistent network identities, invalid
certificates, and preference lists above the configured limit fail closed.

### Selection and upgrade

After bootstrap, each forked endpoint computes the selected curve from the
initiator's ordered list intersected with the responder's available list. The
initiator's order is authoritative for that connection. The responder sends a
selection record over the authenticated bootstrap tunnel. Both sides hash the
canonical capability lists, both nonces, selected curve, both bootstrap
certificate fingerprints, and role labels into a negotiation transcript.

A new handshake subtype performs IX with the selected P-256 or P-384 suite.
The transcript hash is supplied as the Noise prologue, binding the upgrade to
the authenticated negotiation and preventing list stripping, reordering,
selection substitution, and cross-connection replay. On completion, Nebula
atomically replaces the bootstrap tunnel's cipher states. The bootstrap tunnel
is retained only until upgrade success or failure is decided.

The new subtype encodes the curve unambiguously:

- `HandshakeIXP256Upgrade`
- `HandshakeIXP384Upgrade`

Separate subtypes avoid parsing attacker-controlled key lengths before suite
selection. Future algorithms require new explicit subtype assignments.

### Downgrade policy

A stock peer sends no capability extension and continues on X25519. A forked
peer that advertises an upgrade but fails or suppresses it is not silently
accepted as stock. The connection fails unless an administrator explicitly
sets the global `handshakes.allow_authenticated_x25519_fallback` policy. It
defaults to false and applies only after the peer's bootstrap identity has been
authenticated.

To prevent a previously observed capable peer from being impersonated as a
stock peer through extension stripping, capability state is cached by
certificate fingerprint for at least the certificate lifetime in the mode-0600
file configured by `handshakes.capability_cache_path`. This writable path is
required whenever mixed-curve credentials are configured, so daemon restart
does not erase downgrade history. Administrators may clear this cache during
an intentional downgrade. Because the initial list
is already Noise-authenticated, an on-path attacker cannot alter it; the cache
covers denial/replay behavior across separate connection attempts.

Compatibility has an unavoidable boundary: first contact with a genuinely
stock peer cannot prove that the peer did not once support an extension. Sites
requiring strict P-curve operation configure an expected minimum curve for
that peer and reject stock-only bootstrap.

## Certificate model

Add independent fields for:

- host key-agreement curve: X25519, P-256, or P-384;
- CA signature algorithm/curve;
- host public key.

Legacy v1/v2 certificates retain their existing encoding and interpretation.
A new certificate encoding carries the separated fields. CA constraints are
applied identically to every key certificate. All certificates in one local
identity must agree on VPN networks, groups, issuer, and validity policy.

`CertState` becomes an immutable credential set keyed by certificate version
and key-agreement curve. A credential owns a `StaticDHKey` rather than a raw
private byte slice:

```go
type StaticDHKey interface {
    Curve() Curve
    PublicKey() []byte
    DH(peerPublic []byte) ([]byte, error)
    Close() error
}
```

Software, PKCS#11, and TPM implementations satisfy this interface. Public-key
parsing and point validation happen before backend dispatch. The Noise adapter
uses opaque handles internally; callers never receive a TPM private scalar.

## Configuration

Mixed-curve daemon operation keeps the stock v2 X25519 credential in
`pki.cert`/`pki.key` and accepts optional `pki.p256_cert`, `pki.p256_key`,
`pki.p384_cert`, and `pki.p384_key` pairs. `pki.curve_preferences` orders the
configured upgrades, for example `[P384, P256]`. Every curve-specific CA must
be present in `pki.ca`. `handshakes.capability_cache_path` names the persistent
downgrade-state file; `handshakes.allow_authenticated_x25519_fallback` is the
explicit global compatibility override and defaults to false. Fork peers first establish the stock-compatible tunnel,
then automatically negotiate and replace it with the selected explicit upgrade.
Upgrade-over-relay is currently rejected rather than silently falling back;
direct peer endpoints are required for mixed-curve upgrade.

## TPM behavior

P-256 and P-384 keys are created beneath a configured storage parent with
fixed-TPM, fixed-parent, sensitive-data-origin, user-with-auth, and ECDH usage
attributes. The public area is checked against the certificate and expected
curve at load. ECDH uses `TPM2_ECDH_ZGen`; only the derived point leaves the
TPM. The adapter serializes access per TPM context, bounds operation time, and
fails the handshake closed after transport, authorization, policy, or point
validation errors.

Tests use isolated `swtpm` state and never address persistent handles on the
physical development TPM.

## Software X25519 protection

When a TPM lacks X25519, its private key is stored as a sealed TPM object. A
systemd `ExecStartPre` helper unseals it and installs it in a service-owned
kernel keyring. The main process reads it directly into locked memory and
revokes the keyring entry after acquisition. No plaintext key file is created.
DynamicUser, keyring permissions, `NoNewPrivileges`, ptrace restrictions,
`LimitCORE=0`, `PR_SET_DUMPABLE=0`, `PR_SET_PTRACER=0`, `MADV_DONTDUMP`, and
CRIU denial through the non-dumpable/ptrace boundary reduce exposure.

Without a TPM, fresh random wrapping material is mixed with Linux machine-id
and boot-id to create an ephemeral host-bound wrapping key that protects idle
in-memory key material. The process decrypts into a locked scratch buffer only for the
software X25519 operation, then wipes it. Loss or change of wrapping material
makes the stored value unrecoverable.

These are best-effort controls, not an HSM guarantee. Software X25519 plaintext
necessarily exists briefly in process memory. Root, kernel compromise, hostile
code in the Nebula process, and sufficiently timed memory inspection remain
outside the protection boundary. Linux keyrings also do not perform X25519;
they only narrow provisioning exposure.

## Failure and recovery

- Unsupported or malformed capability: reject the upgrade; do not reinterpret.
- No mutually supported curve: retain X25519 only for authenticated stock or
  explicitly allowed fallback; otherwise close.
- TPM unavailable, policy mismatch, or object lost: fail the affected
  credential closed and report actionable diagnostics.
- Sealed X25519 PCR/host policy invalidated: do not regenerate silently;
  re-enroll or restore through an administrator-approved recovery flow.
- Upgrade interrupted: discard partial Noise state and bootstrap tunnel unless
  explicit fallback policy permits it.
- Hot reload: construct and verify a complete immutable credential set before
  replacing the active set.

## Test matrix

| Initiator | Responder | Expected result |
| --- | --- | --- |
| fork X/P-256/P-384 | fork X/P-256/P-384 | highest initiator preference selected and transcript-bound upgrade succeeds |
| fork P-384/P-256/X | fork P-256/P-384/X | P-384 selected |
| fork P-384/X | fork P-256/X | authenticated X fallback only when policy allows |
| fork X/P-256 | stock X | unchanged stock IX succeeds |
| stock X | fork X/P-256 | unchanged stock IX succeeds |
| fork TPM P-256 | fork TPM P-256 | `swtpm` ECDH succeeds and private material is non-exportable |
| fork TPM P-384 | fork TPM P-384 | `swtpm` ECDH succeeds and private material is non-exportable |
| reordered/stripped list | fork | transcript or capability cache rejects downgrade |
| substituted selection | fork | transcript mismatch rejects upgrade |
| malformed/off-curve P key | fork | rejected before TPM/backend operation |
| duplicate/oversized list | fork | rejected before selection |
| invalidated sealed X key | service restart | service fails closed with no plaintext file |
| no TPM fallback | fork X | connection succeeds with documented memory protections active |

Unit tests cover canonical encoding, deterministic selection, point validation,
legacy unknown-field parsing, transcript construction, and policy decisions.
Integration tests cover every row above. The NixOS VM test proves service and
`swtpm` lifecycle, keyring isolation, restart/invalidation behavior, and stock
binary interoperability.
