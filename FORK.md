# ShirabeNetwork/rustls — Kirika fork

This branch (`kirika/0.23.46`) is a fork of [rustls](https://github.com/rustls/rustls)
with a small linear series of client-side patches that let a caller reshape the
ClientHello (browser-like TLS fingerprint) while rustls keeps the TLS security
layer: handshake state machine, key schedule, key exchange secrets, certificate
and signature verification.

It exists for Kirika's opt-in "compatible TLS (security downgrade)" switch only.
Upstream rustls is the default everywhere else. Upstream declined GREASE /
fingerprinting features (rustls/rustls#357, #1501), so none of this is intended
for upstream, and it has had no review beyond its own tests.

## Provenance and license

- Base: upstream tag `v/0.23.46`, commit `f04804fa13341a9b1dc02b5d1dd8a746f2c4b7fb`.
- Only the `rustls` crate is patched (plus this file). Other workspace crates are
  upstream as of the base commit.
- rustls is licensed Apache-2.0 OR ISC OR MIT (`LICENSE`, `LICENSE-APACHE`,
  `LICENSE-ISC`, `LICENSE-MIT`, unchanged). The patches are under the same terms.
- No code was taken from other projects. The client EncryptedExtensions for ALPS
  follows the behaviour of BoringSSL / Chrome and uTLS
  (refraction-networking/utls, BSD-3-Clause), reimplemented from the wire format.
  cfal/rustls (a REALITY fork of 0.23.46, MIT / Apache-2.0) was not used for these
  patches; its client hook design is the reference for a later REALITY patch.

## Patches

One commit each, in this order; each is a self-contained change on top of the
previous ones. Fork code is marked with `Kirika fork` comments; new files are
`rustls/src/client/{customize,alps,fork_test}.rs` and
`rustls/tests/client_hello_customizer.rs`.

### P1 `ClientHelloCustomizer`

`rustls::client::danger::{ClientHelloCustomizer, ClientHelloContext,
HelloRetryContext, CustomClientHelloError}`, installed with
`ClientConfig::dangerous().set_client_hello_customizer(Arc<dyn ClientHelloCustomizer>)`.
rustls builds its ClientHello as usual (first hello and the second hello after a
HelloRetryRequest) and passes the encoded handshake message, header included, to
`customize(&context, hello, &mut out)`. The context says whether this is a retry
(with the HelloRetryRequest message and the first ClientHello as sent), and
whether the hello is a real ECH outer hello or carries GREASE ECH. rustls
re-parses `out` and uses it only if the invariants below hold; otherwise the
connection fails with `Error::InvalidCustomClientHello(CustomClientHelloError)`.
The customizer's bytes are what is sent and what enters the transcript hash.
Everything later checked against "what we offered" is recomputed from the bytes
actually sent: extension types (only types rustls can parse count as offered),
cipher suites, supported groups, key share groups, certificate compression
algorithms. The ServerHello, HelloRetryRequest and CompressedCertificate checks
use them. Session resumption is **force-disabled**: the setter replaces
`resumption` with `Resumption::disabled()` and turns early data off, and while a
customizer is set the client never reads a stored session or key exchange hint,
even if `resumption` is changed afterwards. QUIC with a customizer is refused.
ECH (real config): the customizer gets the outer hello with an all-zero ECH
payload; rustls then seals the inner hello with the customized outer hello
(without the handshake header, payload still zero) as AAD and writes the payload
in place. Because the customized outer hello no longer carries rustls' extension
bodies in rustls' order, the inner hello does not use `ech_outer_extensions`
compression when a customizer is set (larger, still padded, inner hello). The
inner hello stays rustls-shaped. ECH GREASE: the customizer must keep rustls'
GREASE ECH extension byte-identical.

### P2 Independent component key share

`ClientHelloCustomizer::independent_hybrid_component_share() -> bool` (default
`false`). When `true` and the first key share is a hybrid group
(`X25519MLKEM768`) whose classical component (`X25519`) is enabled separately,
rustls generates a separate X25519 key pair with the provider for the second key
share instead of reusing the hybrid's component key (as browsers do), keeps it
across a HelloRetryRequest that does not name a group, and uses it if the server
selects X25519.

### P3 ALPS

If the ClientHello as sent offered `application_settings` (0x44cd, or the old
0x4469), exactly one ALPS extension of an offered codepoint is accepted in the
server's EncryptedExtensions when the negotiated ALPN protocol is in that
offer's protocol list; anything else stays an unsolicited extension. The
server's settings are ignored. After the server Finished and before the client
Certificate / Finished, the client sends an EncryptedExtensions message
(type 8) with the same codepoint and **empty** settings, under the handshake
traffic keys and in the transcript.

### P4 Responses to offered extensions rustls does not know

If offered in the ClientHello as sent: `trust_anchors` (0xca34) in
EncryptedExtensions, and `signed_certificate_timestamp` (0x0012) and
`trust_anchors` in TLS 1.3 CertificateEntry extensions are accepted and ignored.
Not offered: `UnsolicitedEncryptedExtension` / `UnsolicitedCertExtension`. Other
unknown CertificateEntry extensions still fail to decode. The rustls server keeps
refusing any client CertificateEntry extension (for these two types now as
`UnsolicitedCertExtension` instead of a decode error).

## P1 invariants

The customized hello is accepted only if:

1. it is exactly one well-formed ClientHello handshake message that rustls parses
   (no trailing bytes, no duplicate extensions, `pre_shared_key` last if present);
2. `random` and `legacy_session_id` are unchanged;
3. every key share whose group is not a GREASE value (RFC 8701, `0x?a?a`) is
   byte-identical (group and key) to a share rustls generated, and no non-GREASE
   group appears twice — the customizer cannot add shares rustls has no private
   key for; it may drop shares;
4. there is no `pre_shared_key` and no `early_data` extension;
5. `server_name`, `application_layer_protocol_negotiation`, `cookie`,
   `encrypted_client_hello`, `ech_outer_extensions` and the QUIC transport
   parameter extensions are present exactly when rustls sent them, with
   byte-identical bodies;
6. `supported_versions` offers TLS 1.3.

GREASE values in cipher suites, groups, key shares, versions, signature
algorithms and extension types are tolerated, as are unknown extensions,
reordering and padding. The server's choices are checked against the offer as
sent: a cipher suite, group or version rustls does not implement or did not
enable still fails, e.g. a TLS 1.2 ServerHello with a TLS 1.3-only config fails
with `PeerIncompatible::ServerTlsVersionIsDisabledByOurConfig`; a TLS 1.2 suite in
a TLS 1.3 ServerHello with `PeerMisbehaved::SelectedUnusableCipherSuiteForVersion`;
an unimplemented or GREASE suite with `SelectedUnofferedCipherSuite`; a key share
for a group no share was sent for with `WrongGroupForKeyShare`.

Known limits: with real ECH *accepted*, the server answered the rustls-shaped
inner hello while offered suites / groups are recorded from the customized outer
hello, so a customizer should not drop suites, groups or key shares rustls
offered when ECH is enabled. TLS 1.2 with a customizer is not tested (Kirika
uses TLS 1.3-only configs).

## Rebasing onto a newer upstream 0.23.x tag

```sh
git fetch upstream --tags
git switch kirika/0.23.46
git switch -c kirika/0.23.NN
git rebase --onto v/0.23.NN v/0.23.46     # replays P1..P4 and FORK.md
# resolve conflicts patch by patch (grep "Kirika fork"), then:
cargo fmt -p rustls
cargo clippy -j 4 -p rustls --all-targets -- -D warnings -A clippy::nonminimal_bool
cargo test -j 4 -p rustls
cargo test -j 4 -p rustls --no-default-features --features aws_lc_rs,std
git push origin kirika/0.23.NN
```

Update the base tag and commit in this file, then run Kirika's own interop
tests against the new head before pinning it. Upstream 0.23.x security releases
must be followed. A move to 0.24 is a separate project.

## Tests

- `rustls/tests/client_hello_customizer.rs` (integration, `aws_lc_rs`): a test
  customizer adds GREASE everywhere, unknown extensions (ALPS, SCT,
  trust_anchors, compress_certificate, padding) and reverses the extension order;
  handshakes for each TLS 1.3 suite × {X25519MLKEM768, X25519} with data round
  trips; HelloRetryRequest (server limited to secp256r1) with the customizer
  invoked twice; invariant violations; resumption disabled; certificate
  compression following the sent hello; scripted ServerHellos choosing a TLS 1.2
  version, a TLS 1.2 / unimplemented / GREASE suite, or a group without a share;
  independent X25519 share (P2); ECH GREASE with HRR; real ECH (the payload
  opens with HPKE using the customized outer hello as AAD; the outer handshake
  verifies up to the expected ECH rejection); QUIC refused.
- `rustls/src/client/fork_test.rs` (unit, `aws_lc_rs`): scripted TLS 1.3 server
  (secrets from the client's key log) for ALPS (client EncryptedExtensions bytes,
  server and client Finished over the transcript including both, unsolicited
  cases) and P4 (tolerated / refused trust_anchors and SCT).

```sh
cargo test -j 4 -p rustls                                                     # default features
cargo test -j 4 -p rustls --no-default-features --features aws_lc_rs,std       # Kirika's features
cargo test -j 4 -p rustls --test client_hello_customizer
cargo test -j 4 -p rustls --lib fork_test
```

`cargo clippy -p rustls --all-targets -- -D warnings` with Rust 1.95 reports two
`clippy::nonminimal_bool` findings in upstream `server/hs.rs` and
`server/tls13.rs` that exist at the base commit; they are left untouched to keep
the patch set small (`-A clippy::nonminimal_bool`).
