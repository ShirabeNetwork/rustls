//! Kirika fork: tests for `ClientHelloCustomizer` and the patches built on it.
//!
//! See `FORK.md` at the repository root.

#![cfg(feature = "aws_lc_rs")]
#![allow(clippy::disallowed_types)]

use std::io::{Read, Write};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use pki_types::{DnsName, EchConfigListBytes, ServerName};
use rustls::client::danger::{ClientHelloContext, ClientHelloCustomizer, CustomClientHelloError};
use rustls::client::{EchConfig, EchGreaseConfig, EchMode, EchStatus};
use rustls::compress::{
    CertCompressor, CertDecompressor, CompressionFailed, CompressionLevel, DecompressionFailed,
};
use rustls::crypto::aws_lc_rs as provider;
use rustls::crypto::aws_lc_rs::hpke::ALL_SUPPORTED_SUITES;
use rustls::crypto::hpke::EncapsulatedSecret;
use rustls::crypto::{CryptoProvider, SupportedKxGroup};
use rustls::internal::msgs::base::PayloadU16;
use rustls::internal::msgs::codec::Codec;
use rustls::internal::msgs::handshake::{
    EchConfigContents, EchConfigPayload, HpkeKeyConfig, HpkeSymmetricCipherSuite,
};
use rustls::version::TLS13;
use rustls::{
    CertificateCompressionAlgorithm, ClientConfig, ClientConnection, Error, NamedGroup,
    PeerIncompatible, ServerConfig, ServerConnection, SupportedCipherSuite,
};
use rustls_test::{
    ErrorFromPeer, KeyType, do_handshake, do_handshake_until_error, finish_client_config,
    finish_server_config, server_name, transfer,
};

// --- a minimal ClientHello editor ---

const EXT_SUPPORTED_GROUPS: u16 = 0x000a;
const EXT_SIGNATURE_ALGORITHMS: u16 = 0x000d;
const EXT_SERVER_NAME: u16 = 0x0000;
const EXT_SCT: u16 = 0x0012;
const EXT_PADDING: u16 = 0x0015;
const EXT_COMPRESS_CERTIFICATE: u16 = 0x001b;
const EXT_EARLY_DATA: u16 = 0x002a;
const EXT_PRE_SHARED_KEY: u16 = 0x0029;
const EXT_SUPPORTED_VERSIONS: u16 = 0x002b;
const EXT_KEY_SHARE: u16 = 0x0033;
const EXT_ALPS: u16 = 0x44cd;
const EXT_TRUST_ANCHORS: u16 = 0xca34;
const EXT_ECH: u16 = 0xfe0d;

#[derive(Clone, Debug, PartialEq)]
struct Hello {
    version: [u8; 2],
    random: Vec<u8>,
    session_id: Vec<u8>,
    suites: Vec<u16>,
    compression: Vec<u8>,
    exts: Vec<(u16, Vec<u8>)>,
}

impl Hello {
    fn parse(msg: &[u8]) -> Self {
        assert_eq!(msg[0], 1);
        let len = (usize::from(msg[1]) << 16) | (usize::from(msg[2]) << 8) | usize::from(msg[3]);
        assert_eq!(len, msg.len() - 4);
        let b = &msg[4..];
        let mut p = 0;
        let version = [b[0], b[1]];
        p += 2;
        let random = b[p..p + 32].to_vec();
        p += 32;
        let sid_len = usize::from(b[p]);
        p += 1;
        let session_id = b[p..p + sid_len].to_vec();
        p += sid_len;
        let cs_len = usize::from(u16::from_be_bytes([b[p], b[p + 1]]));
        p += 2;
        let suites = b[p..p + cs_len]
            .chunks(2)
            .map(|c| u16::from_be_bytes([c[0], c[1]]))
            .collect();
        p += cs_len;
        let cm_len = usize::from(b[p]);
        p += 1;
        let compression = b[p..p + cm_len].to_vec();
        p += cm_len;
        let mut exts = Vec::new();
        if p < b.len() {
            p += 2;
            while p < b.len() {
                let typ = u16::from_be_bytes([b[p], b[p + 1]]);
                let l = usize::from(u16::from_be_bytes([b[p + 2], b[p + 3]]));
                exts.push((typ, b[p + 4..p + 4 + l].to_vec()));
                p += 4 + l;
            }
        }
        Self {
            version,
            random,
            session_id,
            suites,
            compression,
            exts,
        }
    }

    fn encode(&self) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(&self.version);
        b.extend_from_slice(&self.random);
        b.push(self.session_id.len() as u8);
        b.extend_from_slice(&self.session_id);
        b.extend_from_slice(&((self.suites.len() * 2) as u16).to_be_bytes());
        for s in &self.suites {
            b.extend_from_slice(&s.to_be_bytes());
        }
        b.push(self.compression.len() as u8);
        b.extend_from_slice(&self.compression);
        let mut e = Vec::new();
        for (typ, body) in &self.exts {
            e.extend_from_slice(&typ.to_be_bytes());
            e.extend_from_slice(&(body.len() as u16).to_be_bytes());
            e.extend_from_slice(body);
        }
        b.extend_from_slice(&(e.len() as u16).to_be_bytes());
        b.extend_from_slice(&e);
        let mut msg = vec![
            1,
            (b.len() >> 16) as u8,
            (b.len() >> 8) as u8,
            b.len() as u8,
        ];
        msg.extend_from_slice(&b);
        msg
    }

    fn ext(&self, typ: u16) -> Option<&Vec<u8>> {
        self.exts
            .iter()
            .find(|(t, _)| *t == typ)
            .map(|(_, b)| b)
    }

    fn ext_mut(&mut self, typ: u16) -> Option<&mut Vec<u8>> {
        self.exts
            .iter_mut()
            .find(|(t, _)| *t == typ)
            .map(|(_, b)| b)
    }

    fn key_shares(&self) -> Vec<(u16, Vec<u8>)> {
        let body = self.ext(EXT_KEY_SHARE).unwrap();
        let mut out = Vec::new();
        let mut p = 2;
        while p < body.len() {
            let g = u16::from_be_bytes([body[p], body[p + 1]]);
            let l = usize::from(u16::from_be_bytes([body[p + 2], body[p + 3]]));
            out.push((g, body[p + 4..p + 4 + l].to_vec()));
            p += 4 + l;
        }
        out
    }

    fn set_key_shares(&mut self, shares: &[(u16, Vec<u8>)]) {
        let mut list = Vec::new();
        for (g, k) in shares {
            list.extend_from_slice(&g.to_be_bytes());
            list.extend_from_slice(&(k.len() as u16).to_be_bytes());
            list.extend_from_slice(k);
        }
        let mut body = (list.len() as u16)
            .to_be_bytes()
            .to_vec();
        body.extend_from_slice(&list);
        *self.ext_mut(EXT_KEY_SHARE).unwrap() = body;
    }
}

/// Prepend `item` to a list with a `len_bytes`-byte length prefix.
fn prepend(body: &mut Vec<u8>, len_bytes: usize, item: &[u8]) {
    let mut list = body[len_bytes..].to_vec();
    list.splice(0..0, item.iter().copied());
    let len = list.len().to_be_bytes();
    *body = len[len.len() - len_bytes..].to_vec();
    body.extend_from_slice(&list);
}

fn append(body: &mut Vec<u8>, len_bytes: usize, item: &[u8]) {
    let mut list = body[len_bytes..].to_vec();
    list.extend_from_slice(item);
    let len = list.len().to_be_bytes();
    *body = len[len.len() - len_bytes..].to_vec();
    body.extend_from_slice(&list);
}

/// The ALPN-shaped ALPS body offering `h2`.
fn alps_body() -> Vec<u8> {
    vec![0x00, 0x03, 0x02, b'h', b'2']
}

/// GREASE everywhere, unknown extensions, reversed extension order.
fn greased(mut h: Hello, add_compress_certificate: bool) -> Hello {
    h.suites.insert(0, 0x0a0a);
    h.suites.push(0xc02f); // a TLS 1.2 suite rustls (TLS 1.3 only) did not enable
    h.suites.push(0x1304); // TLS_AES_128_CCM_SHA256, not implemented
    if let Some(b) = h.ext_mut(EXT_SUPPORTED_GROUPS) {
        prepend(b, 2, &[0x1a, 0x1a]);
    }
    if let Some(b) = h.ext_mut(EXT_SIGNATURE_ALGORITHMS) {
        prepend(b, 2, &[0x3a, 0x3a]);
    }
    if let Some(b) = h.ext_mut(EXT_SUPPORTED_VERSIONS) {
        prepend(b, 1, &[0x2a, 0x2a]);
        append(b, 1, &[0x03, 0x03]);
    }
    if h.ext(EXT_KEY_SHARE).is_some() {
        let mut shares = h.key_shares();
        shares.insert(0, (0x1a1a, vec![0]));
        h.set_key_shares(&shares);
    }
    h.exts.reverse();
    h.exts.insert(0, (0x4a4a, vec![]));
    h.exts.push((EXT_ALPS, alps_body()));
    h.exts.push((EXT_SCT, vec![]));
    h.exts
        .push((EXT_TRUST_ANCHORS, vec![0x00, 0x00]));
    if add_compress_certificate
        && h.ext(EXT_COMPRESS_CERTIFICATE)
            .is_none()
    {
        h.exts
            .push((EXT_COMPRESS_CERTIFICATE, vec![0x02, 0x00, 0x02]));
    }
    h.exts.push((EXT_PADDING, vec![0; 17]));
    h.exts.push((0x5a5a, vec![0]));
    h
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum Mode {
    Greased,
    GreasedWithCompressCertificate,
    StripCompressCertificate,
    ChangeRandom,
    ForeignKeyShare,
    DuplicateKeyShare,
    AddEarlyData,
    AddPsk,
    ChangeSni,
    DropSupportedVersions13,
    Truncate,
}

/// One customizer call.
#[derive(Clone, Debug)]
struct Seen {
    /// The hello rustls built.
    ours: Vec<u8>,
    /// The hello the customizer returned.
    sent: Vec<u8>,
    /// (HelloRetryRequest, first hello) for a retry.
    retry: Option<(Vec<u8>, Vec<u8>)>,
    ech_outer: bool,
    ech_grease: bool,
}

#[derive(Debug)]
struct TestCustomizer {
    mode: Mode,
    independent: bool,
    calls: AtomicUsize,
    /// (rustls' hello, sent hello, retry context: (hrr, first hello)) per call.
    seen: Mutex<Vec<Seen>>,
}

impl TestCustomizer {
    fn new(mode: Mode) -> Arc<Self> {
        Arc::new(Self {
            mode,
            independent: false,
            calls: AtomicUsize::new(0),
            seen: Mutex::new(Vec::new()),
        })
    }
}

impl ClientHelloCustomizer for TestCustomizer {
    fn independent_hybrid_component_share(&self) -> bool {
        self.independent
    }

    fn customize(
        &self,
        context: &ClientHelloContext<'_>,
        hello: &[u8],
        out: &mut Vec<u8>,
    ) -> Result<(), Error> {
        self.calls
            .fetch_add(1, Ordering::SeqCst);
        let ours = Hello::parse(hello);
        let mut h = match self.mode {
            Mode::GreasedWithCompressCertificate => greased(ours, true),
            Mode::StripCompressCertificate => {
                let mut h = greased(ours, false);
                h.exts
                    .retain(|(t, _)| *t != EXT_COMPRESS_CERTIFICATE);
                h
            }
            _ => greased(ours, false),
        };
        match self.mode {
            Mode::ChangeRandom => h.random[0] ^= 1,
            Mode::ForeignKeyShare => {
                let mut shares = h.key_shares();
                let last = shares.last_mut().unwrap();
                last.1[0] ^= 1;
                h.set_key_shares(&shares);
            }
            Mode::DuplicateKeyShare => {
                let mut shares = h.key_shares();
                shares.push(shares.last().unwrap().clone());
                h.set_key_shares(&shares);
            }
            Mode::AddEarlyData => h.exts.push((EXT_EARLY_DATA, vec![])),
            Mode::AddPsk => {
                let mut psk = vec![0x00, 0x07, 0x00, 0x01, b'a', 0, 0, 0, 0];
                psk.extend_from_slice(&[0x00, 0x21, 0x20]);
                psk.extend_from_slice(&[0; 32]);
                h.exts.push((EXT_PRE_SHARED_KEY, psk));
            }
            Mode::ChangeSni => {
                let sni = h.ext_mut(EXT_SERVER_NAME).unwrap();
                *sni.last_mut().unwrap() ^= 0x01;
            }
            Mode::DropSupportedVersions13 => {
                *h.ext_mut(EXT_SUPPORTED_VERSIONS)
                    .unwrap() = vec![0x02, 0x03, 0x03];
            }
            _ => {}
        }
        let mut encoded = h.encode();
        if self.mode == Mode::Truncate {
            encoded.pop();
        }
        out.extend_from_slice(&encoded);
        self.seen.lock().unwrap().push(Seen {
            ours: hello.to_vec(),
            sent: encoded,
            retry: context.retry.as_ref().map(|r| {
                (
                    r.hello_retry_request.to_vec(),
                    r.first_client_hello.to_vec(),
                )
            }),
            ech_outer: context.ech_outer,
            ech_grease: context.ech_grease,
        });
        Ok(())
    }
}

// --- configs ---

fn kx_provider(kx_groups: Vec<&'static dyn SupportedKxGroup>) -> CryptoProvider {
    CryptoProvider {
        kx_groups,
        ..provider::default_provider()
    }
}

fn client_config(kx_groups: Vec<&'static dyn SupportedKxGroup>) -> ClientConfig {
    let builder = ClientConfig::builder_with_provider(kx_provider(kx_groups).into())
        .with_protocol_versions(&[&TLS13])
        .unwrap();
    let mut config = finish_client_config(KeyType::EcdsaP256, builder);
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    config
}

fn default_client_kx() -> Vec<&'static dyn SupportedKxGroup> {
    vec![
        provider::kx_group::X25519MLKEM768,
        provider::kx_group::X25519,
        provider::kx_group::SECP256R1,
        provider::kx_group::SECP384R1,
    ]
}

fn customized_client(mode: Mode) -> (ClientConfig, Arc<TestCustomizer>) {
    let mut config = client_config(default_client_kx());
    let customizer = TestCustomizer::new(mode);
    config
        .dangerous()
        .set_client_hello_customizer(customizer.clone());
    (config, customizer)
}

fn server_config(
    suites: Vec<SupportedCipherSuite>,
    kx_groups: Vec<&'static dyn SupportedKxGroup>,
) -> ServerConfig {
    let provider = CryptoProvider {
        cipher_suites: suites,
        kx_groups,
        ..provider::default_provider()
    };
    let mut config = finish_server_config(
        KeyType::EcdsaP256,
        ServerConfig::builder_with_provider(provider.into())
            .with_protocol_versions(&[&TLS13])
            .unwrap(),
    );
    config.alpn_protocols = vec![b"h2".to_vec()];
    config
}

fn all_tls13_suites() -> Vec<SupportedCipherSuite> {
    vec![
        provider::cipher_suite::TLS13_AES_128_GCM_SHA256,
        provider::cipher_suite::TLS13_AES_256_GCM_SHA384,
        provider::cipher_suite::TLS13_CHACHA20_POLY1305_SHA256,
    ]
}

fn round_trip(client: &mut ClientConnection, server: &mut ServerConnection) {
    client
        .writer()
        .write_all(b"hello from client")
        .unwrap();
    transfer(client, server);
    server.process_new_packets().unwrap();
    let mut buf = [0u8; 17];
    server
        .reader()
        .read_exact(&mut buf)
        .unwrap();
    assert_eq!(&buf, b"hello from client");

    server
        .writer()
        .write_all(b"hello from server")
        .unwrap();
    transfer(server, client);
    client.process_new_packets().unwrap();
    client
        .reader()
        .read_exact(&mut buf)
        .unwrap();
    assert_eq!(&buf, b"hello from server");
}

fn first_flight(client: &mut ClientConnection) -> Vec<u8> {
    let mut wire = Vec::new();
    client.write_tls(&mut wire).unwrap();
    // one handshake record carrying the ClientHello
    assert_eq!(wire[0], 0x16);
    let len = usize::from(u16::from_be_bytes([wire[3], wire[4]]));
    wire[5..5 + len].to_vec()
}

// --- P1 tests ---

#[test]
fn customized_hello_is_sent_and_handshakes_for_each_suite_and_group() {
    for suite in all_tls13_suites() {
        for group in [
            provider::kx_group::X25519MLKEM768,
            provider::kx_group::X25519,
        ] {
            let (config, customizer) = customized_client(Mode::Greased);
            let mut client =
                ClientConnection::new(Arc::new(config), server_name("localhost")).unwrap();
            let mut wire = Vec::new();
            client.write_tls(&mut wire).unwrap();

            let seen = customizer.seen.lock().unwrap().clone();
            assert_eq!(seen.len(), 1);
            assert_eq!(
                wire[5..],
                seen[0].sent[..],
                "wire bytes are the customizer's"
            );
            assert!(seen[0].retry.is_none());

            let mut server =
                ServerConnection::new(Arc::new(server_config(vec![suite], vec![group]))).unwrap();
            server
                .read_tls(&mut wire.as_slice())
                .unwrap();
            server.process_new_packets().unwrap();
            do_handshake(&mut client, &mut server);

            assert_eq!(client.negotiated_cipher_suite(), Some(suite));
            assert_eq!(
                client
                    .negotiated_key_exchange_group()
                    .unwrap()
                    .name(),
                group.name()
            );
            assert_eq!(client.alpn_protocol(), Some(&b"h2"[..]));
            round_trip(&mut client, &mut server);
            assert_eq!(customizer.calls.load(Ordering::SeqCst), 1);
        }
    }
}

#[test]
fn hello_retry_request_invokes_customizer_twice() {
    let (config, customizer) = customized_client(Mode::Greased);
    let mut client = ClientConnection::new(Arc::new(config), server_name("localhost")).unwrap();
    let mut server = ServerConnection::new(Arc::new(server_config(
        all_tls13_suites(),
        vec![provider::kx_group::SECP256R1],
    )))
    .unwrap();
    do_handshake(&mut client, &mut server);
    round_trip(&mut client, &mut server);

    assert_eq!(customizer.calls.load(Ordering::SeqCst), 2);
    assert_eq!(
        client.handshake_kind(),
        Some(rustls::HandshakeKind::FullWithHelloRetryRequest)
    );
    assert_eq!(
        client
            .negotiated_key_exchange_group()
            .unwrap()
            .name(),
        NamedGroup::secp256r1
    );
    let seen = customizer.seen.lock().unwrap().clone();
    let (hrr, first) = seen[1]
        .retry
        .clone()
        .expect("retry context");
    assert_eq!(first, seen[0].sent, "first hello as sent");
    assert_eq!(hrr[0], 2, "HelloRetryRequest is a ServerHello message");

    // The second hello carries only rustls' new P-256 share (plus GREASE).
    let second = Hello::parse(&seen[1].sent);
    let shares = second.key_shares();
    assert_eq!(shares.len(), 2);
    assert_eq!(shares[0].0, 0x1a1a);
    assert_eq!(shares[1].0, u16::from(NamedGroup::secp256r1));
    assert_eq!(second.random, Hello::parse(&seen[0].sent).random);
}

fn expect_refused(mode: Mode, err: CustomClientHelloError) {
    let (config, _) = customized_client(mode);
    assert_eq!(
        ClientConnection::new(Arc::new(config), server_name("localhost")).unwrap_err(),
        Error::InvalidCustomClientHello(err),
        "{mode:?}"
    );
}

#[test]
fn invariant_violations_are_refused() {
    use rustls::internal::msgs::enums::ExtensionType;
    expect_refused(Mode::ChangeRandom, CustomClientHelloError::RandomChanged);
    expect_refused(
        Mode::ForeignKeyShare,
        CustomClientHelloError::ForeignKeyShare,
    );
    expect_refused(
        Mode::DuplicateKeyShare,
        CustomClientHelloError::DuplicateKeyShare,
    );
    expect_refused(Mode::AddEarlyData, CustomClientHelloError::PskOrEarlyData);
    expect_refused(Mode::AddPsk, CustomClientHelloError::PskOrEarlyData);
    expect_refused(
        Mode::ChangeSni,
        CustomClientHelloError::ExtensionMismatch(ExtensionType::ServerName),
    );
    expect_refused(
        Mode::DropSupportedVersions13,
        CustomClientHelloError::Tls13NotOffered,
    );
    expect_refused(Mode::Truncate, CustomClientHelloError::Malformed);
}

#[test]
fn customizer_disables_resumption() {
    let (mut config, customizer) = customized_client(Mode::Greased);
    // Even if resumption is turned back on, no session is offered.
    config.resumption = rustls::client::Resumption::in_memory_sessions(8);
    let config = Arc::new(config);
    let server = Arc::new(server_config(
        all_tls13_suites(),
        vec![provider::kx_group::X25519],
    ));
    for _ in 0..2 {
        let mut client = ClientConnection::new(config.clone(), server_name("localhost")).unwrap();
        let mut server = ServerConnection::new(server.clone()).unwrap();
        do_handshake(&mut client, &mut server);
        round_trip(&mut client, &mut server);
        assert_eq!(client.handshake_kind(), Some(rustls::HandshakeKind::Full));
    }
    for seen in customizer.seen.lock().unwrap().iter() {
        assert!(
            Hello::parse(&seen.ours)
                .ext(EXT_PRE_SHARED_KEY)
                .is_none()
        );
    }
}

// --- certificate compression ---

#[derive(Debug)]
struct IdentityCompression(CertificateCompressionAlgorithm, AtomicBool);

impl CertDecompressor for IdentityCompression {
    fn decompress(&self, input: &[u8], output: &mut [u8]) -> Result<(), DecompressionFailed> {
        if input.len() != output.len() {
            return Err(DecompressionFailed);
        }
        output.copy_from_slice(input);
        self.1.store(true, Ordering::SeqCst);
        Ok(())
    }

    fn algorithm(&self) -> CertificateCompressionAlgorithm {
        self.0
    }
}

impl CertCompressor for IdentityCompression {
    fn compress(
        &self,
        input: Vec<u8>,
        _level: CompressionLevel,
    ) -> Result<Vec<u8>, CompressionFailed> {
        Ok(input)
    }

    fn algorithm(&self) -> CertificateCompressionAlgorithm {
        self.0
    }
}

static CLIENT_BROTLI: IdentityCompression = IdentityCompression(
    CertificateCompressionAlgorithm::Brotli,
    AtomicBool::new(false),
);
static SERVER_BROTLI: IdentityCompression = IdentityCompression(
    CertificateCompressionAlgorithm::Brotli,
    AtomicBool::new(false),
);

#[test]
fn certificate_compression_follows_the_sent_hello() {
    // Advertised by rustls and kept by the customizer: the certificate arrives compressed.
    for (mode, expect_compressed) in [
        (Mode::Greased, true),
        (Mode::StripCompressCertificate, false),
    ] {
        CLIENT_BROTLI
            .1
            .store(false, Ordering::SeqCst);
        let (mut config, _) = customized_client(mode);
        config.cert_decompressors = vec![&CLIENT_BROTLI];
        let mut server_config = server_config(all_tls13_suites(), vec![provider::kx_group::X25519]);
        server_config.cert_compressors = vec![&SERVER_BROTLI];
        let mut client = ClientConnection::new(Arc::new(config), server_name("localhost")).unwrap();
        let mut server = ServerConnection::new(Arc::new(server_config)).unwrap();
        do_handshake(&mut client, &mut server);
        round_trip(&mut client, &mut server);
        assert_eq!(
            CLIENT_BROTLI.1.load(Ordering::SeqCst),
            expect_compressed,
            "{mode:?}"
        );
    }
}

#[test]
fn certificate_compression_offered_only_by_the_customizer() {
    // rustls has no decompressor, the customizer offers brotli anyway: the server
    // compresses, and rustls refuses the algorithm it cannot decompress.
    let (mut config, _) = customized_client(Mode::GreasedWithCompressCertificate);
    config.cert_decompressors = vec![];
    let mut server_config = server_config(all_tls13_suites(), vec![provider::kx_group::X25519]);
    server_config.cert_compressors = vec![&SERVER_BROTLI];
    let mut client = ClientConnection::new(Arc::new(config), server_name("localhost")).unwrap();
    let mut server = ServerConnection::new(Arc::new(server_config)).unwrap();
    let err = do_handshake_until_error(&mut client, &mut server).unwrap_err();
    assert_eq!(
        err,
        ErrorFromPeer::Client(Error::PeerMisbehaved(
            rustls::PeerMisbehaved::SelectedUnofferedCertCompression
        ))
    );
}

// --- ECH ---

#[test]
fn ech_grease_with_customizer() {
    let suite = ALL_SUPPORTED_SUITES[0];
    let (public_key, _) = suite.generate_key_pair().unwrap();
    let builder = ClientConfig::builder_with_provider(kx_provider(default_client_kx()).into())
        .with_ech(EchMode::Grease(EchGreaseConfig::new(suite, public_key)))
        .unwrap();
    let mut config = finish_client_config(KeyType::EcdsaP256, builder);
    config.alpn_protocols = vec![b"h2".to_vec()];
    let customizer = TestCustomizer::new(Mode::Greased);
    config
        .dangerous()
        .set_client_hello_customizer(customizer.clone());

    let mut client = ClientConnection::new(Arc::new(config), server_name("localhost")).unwrap();
    let mut server = ServerConnection::new(Arc::new(server_config(
        all_tls13_suites(),
        vec![provider::kx_group::SECP256R1],
    )))
    .unwrap();
    do_handshake(&mut client, &mut server);
    round_trip(&mut client, &mut server);
    assert_eq!(client.ech_status(), EchStatus::Grease);

    // HRR: both hellos carry the same GREASE ECH extension.
    let seen = customizer.seen.lock().unwrap().clone();
    assert_eq!(seen.len(), 2);
    assert!(
        seen.iter()
            .all(|s| s.ech_grease && !s.ech_outer)
    );
    let ech: Vec<_> = seen
        .iter()
        .map(|s| {
            Hello::parse(&s.sent)
                .ext(EXT_ECH)
                .cloned()
                .unwrap()
        })
        .collect();
    assert_eq!(ech[0], ech[1]);
}

fn real_ech_config() -> (EchConfig, Vec<u8>, rustls::crypto::hpke::HpkePrivateKey) {
    let suite = ALL_SUPPORTED_SUITES[0];
    let (public_key, private_key) = suite.generate_key_pair().unwrap();
    let suite_id = suite.suite();
    let config = EchConfigPayload::V18(EchConfigContents {
        key_config: HpkeKeyConfig {
            config_id: 7,
            kem_id: suite_id.kem,
            public_key: PayloadU16::new(public_key.0.clone()),
            symmetric_cipher_suites: vec![HpkeSymmetricCipherSuite {
                kdf_id: suite_id.sym.kdf_id,
                aead_id: suite_id.sym.aead_id,
            }],
        },
        maximum_name_length: 0,
        public_name: DnsName::try_from("testserver.com").unwrap(),
        extensions: vec![],
    });
    let mut info = b"tls ech\x00".to_vec();
    config.encode(&mut info);
    let mut list = Vec::new();
    vec![config].encode(&mut list);
    (
        EchConfig::new(EchConfigListBytes::from(list), &[suite]).unwrap(),
        info,
        private_key,
    )
}

fn real_ech_client() -> (
    ClientConfig,
    Arc<TestCustomizer>,
    Vec<u8>,
    rustls::crypto::hpke::HpkePrivateKey,
) {
    let (ech_config, info, private_key) = real_ech_config();
    let builder = ClientConfig::builder_with_provider(kx_provider(default_client_kx()).into())
        .with_ech(EchMode::Enable(ech_config))
        .unwrap();
    let mut config = finish_client_config(KeyType::Rsa2048, builder);
    config.alpn_protocols = vec![b"h2".to_vec()];
    let customizer = TestCustomizer::new(Mode::Greased);
    config
        .dangerous()
        .set_client_hello_customizer(customizer.clone());
    (config, customizer, info, private_key)
}

#[test]
fn real_ech_outer_aad_is_the_customized_hello() {
    let (config, customizer, info, private_key) = real_ech_client();
    let mut client =
        ClientConnection::new(Arc::new(config), server_name("private.example")).unwrap();
    let sent = first_flight(&mut client);
    let seen = customizer.seen.lock().unwrap().clone();
    assert!(seen[0].ech_outer, "ech_outer");

    // The hook saw an all-zero payload; the wire carries the sealed one.
    let hooked = Hello::parse(&seen[0].sent);
    let wire = Hello::parse(&sent);
    let hooked_ech = hooked.ext(EXT_ECH).unwrap();
    let wire_ech = wire.ext(EXT_ECH).unwrap().clone();
    assert_eq!(hooked_ech.len(), wire_ech.len());
    assert_ne!(hooked_ech, &wire_ech);
    assert_eq!(hooked.exts.len(), wire.exts.len());
    for ((t1, b1), (t2, b2)) in hooked.exts.iter().zip(wire.exts.iter()) {
        assert_eq!(t1, t2);
        if *t1 != EXT_ECH {
            assert_eq!(b1, b2);
        }
    }

    // Open the payload as the server would: AAD = outer hello without the
    // handshake header, payload zeroed.
    // ECH body: type(1) cipher_suite(4) config_id(1) enc(2+n) payload(2+m)
    let enc_len = usize::from(u16::from_be_bytes([wire_ech[6], wire_ech[7]]));
    let enc = wire_ech[8..8 + enc_len].to_vec();
    let payload_len = usize::from(u16::from_be_bytes([
        wire_ech[8 + enc_len],
        wire_ech[9 + enc_len],
    ]));
    let payload = wire_ech[10 + enc_len..10 + enc_len + payload_len].to_vec();
    let mut aad = sent[4..].to_vec();
    let pos = aad
        .windows(payload.len())
        .position(|w| w == payload)
        .unwrap();
    aad[pos..pos + payload.len()].fill(0);

    let suite = ALL_SUPPORTED_SUITES[0];
    let mut opener = suite
        .setup_opener(&EncapsulatedSecret(enc), &info, &private_key)
        .unwrap();
    let inner = opener.open(&aad, &payload).unwrap();
    // The inner hello is rustls-shaped, carries the private name, and does not
    // reference outer extensions.
    assert!(
        inner
            .windows(b"private.example".len())
            .any(|w| w == b"private.example")
    );
    assert!(
        !inner
            .windows(2)
            .any(|w| w == [0xfd, 0x00])
    );
}

#[test]
fn real_ech_customized_outer_handshake_completes_until_rejection() {
    // The rustls server cannot do ECH, so it completes the outer handshake for the
    // public name: the transcript over the customized outer hello must verify.
    let (config, _customizer, _, _) = real_ech_client();
    let mut client =
        ClientConnection::new(Arc::new(config), server_name("private.example")).unwrap();
    let mut server = ServerConnection::new(Arc::new({
        let provider = provider::default_provider();
        let mut c = finish_server_config(
            KeyType::Rsa2048,
            ServerConfig::builder_with_provider(provider.into())
                .with_protocol_versions(&[&TLS13])
                .unwrap(),
        );
        c.alpn_protocols = vec![b"h2".to_vec()];
        c
    }))
    .unwrap();
    let err = do_handshake_until_error(&mut client, &mut server).unwrap_err();
    assert!(matches!(
        err,
        ErrorFromPeer::Client(Error::PeerIncompatible(
            PeerIncompatible::ServerRejectedEncryptedClientHello(_)
        ))
    ));
    assert_eq!(client.ech_status(), EchStatus::Rejected);
}

#[test]
fn customizer_is_not_used_for_quic() {
    let (config, _) = customized_client(Mode::Greased);
    let err = rustls::quic::ClientConnection::new(
        Arc::new(config),
        rustls::quic::Version::V1,
        ServerName::try_from("localhost").unwrap(),
        vec![1, 2, 3],
    )
    .unwrap_err();
    assert_eq!(
        err,
        Error::InvalidCustomClientHello(CustomClientHelloError::QuicNotSupported)
    );
}

// --- server choices rustls cannot or did not offer ---

fn client_after_server_hello(
    cipher_suite: rustls::CipherSuite,
    legacy_version: rustls::ProtocolVersion,
    extensions: Vec<rustls_test::encoding::Extension>,
) -> Error {
    use rustls_test::encoding::{message_framing, server_hello};
    let (config, _) = customized_client(Mode::Greased);
    let mut client = ClientConnection::new(Arc::new(config), server_name("localhost")).unwrap();
    let mut wire = Vec::new();
    client.write_tls(&mut wire).unwrap();
    let ch = Hello::parse(&wire[5..]);
    let mut sid = vec![ch.session_id.len() as u8];
    sid.extend_from_slice(&ch.session_id);

    let sh = server_hello(legacy_version, &[7; 32], &sid, cipher_suite, extensions);
    let record = message_framing(
        rustls::ContentType::Handshake,
        rustls::ProtocolVersion::TLSv1_2,
        sh,
    );
    client
        .read_tls(&mut record.as_slice())
        .unwrap();
    client
        .process_new_packets()
        .unwrap_err()
}

fn tls13_server_exts(group: NamedGroup, share_len: usize) -> Vec<rustls_test::encoding::Extension> {
    use rustls::internal::msgs::enums::ExtensionType;
    use rustls_test::encoding::{Extension, len_u16};
    let mut share = group.to_array().to_vec();
    share.extend(len_u16(vec![9; share_len]));
    vec![
        Extension::new_versions_server_tls13(),
        Extension {
            typ: ExtensionType::KeyShare,
            body: share,
        },
    ]
}

#[test]
fn tls12_server_hello_is_refused_cleanly() {
    assert_eq!(
        client_after_server_hello(
            rustls::CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            rustls::ProtocolVersion::TLSv1_2,
            vec![],
        ),
        Error::PeerIncompatible(PeerIncompatible::ServerTlsVersionIsDisabledByOurConfig)
    );
}

#[test]
fn unimplemented_suite_offered_by_customizer_is_refused_cleanly() {
    // 0xc02f is in the customized hello, but is a TLS 1.2 suite.
    assert_eq!(
        client_after_server_hello(
            rustls::CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            rustls::ProtocolVersion::TLSv1_2,
            tls13_server_exts(NamedGroup::X25519, 32),
        ),
        Error::PeerMisbehaved(rustls::PeerMisbehaved::SelectedUnusableCipherSuiteForVersion)
    );
    // 0x1304 (TLS_AES_128_CCM_SHA256) is not implemented by the provider.
    assert_eq!(
        client_after_server_hello(
            rustls::CipherSuite::TLS13_AES_128_CCM_SHA256,
            rustls::ProtocolVersion::TLSv1_2,
            tls13_server_exts(NamedGroup::X25519, 32),
        ),
        Error::PeerMisbehaved(rustls::PeerMisbehaved::SelectedUnofferedCipherSuite)
    );
    // GREASE suite
    assert_eq!(
        client_after_server_hello(
            rustls::CipherSuite::from(0x0a0a),
            rustls::ProtocolVersion::TLSv1_2,
            tls13_server_exts(NamedGroup::X25519, 32),
        ),
        Error::PeerMisbehaved(rustls::PeerMisbehaved::SelectedUnofferedCipherSuite)
    );
}

#[test]
fn server_key_share_for_a_group_not_sent_is_refused() {
    // secp256r1 is in supported_groups but no share was sent; GREASE share group too.
    for group in [NamedGroup::secp256r1, NamedGroup::from(0x1a1a)] {
        assert_eq!(
            client_after_server_hello(
                rustls::CipherSuite::TLS13_AES_128_GCM_SHA256,
                rustls::ProtocolVersion::TLSv1_2,
                tls13_server_exts(group, 65),
            ),
            Error::PeerMisbehaved(rustls::PeerMisbehaved::WrongGroupForKeyShare)
        );
    }
}

// --- P2: independent X25519 share ---

#[test]
fn independent_x25519_share() {
    for independent in [false, true] {
        for group in [
            provider::kx_group::X25519,
            provider::kx_group::X25519MLKEM768,
        ] {
            let mut config = client_config(default_client_kx());
            let customizer = Arc::new(TestCustomizer {
                mode: Mode::Greased,
                independent,
                calls: AtomicUsize::new(0),
                seen: Mutex::new(Vec::new()),
            });
            config
                .dangerous()
                .set_client_hello_customizer(customizer.clone());
            let mut client =
                ClientConnection::new(Arc::new(config), server_name("localhost")).unwrap();
            let mut server =
                ServerConnection::new(Arc::new(server_config(all_tls13_suites(), vec![group])))
                    .unwrap();
            do_handshake(&mut client, &mut server);
            round_trip(&mut client, &mut server);
            assert_eq!(
                client
                    .negotiated_key_exchange_group()
                    .unwrap()
                    .name(),
                group.name()
            );

            // rustls' own shares: X25519MLKEM768 = ML-KEM-768 key (1184) || X25519 key (32)
            let ours = Hello::parse(&customizer.seen.lock().unwrap()[0].ours).key_shares();
            assert_eq!(ours.len(), 2);
            assert_eq!(ours[0].0, u16::from(NamedGroup::X25519MLKEM768));
            assert_eq!(ours[1].0, u16::from(NamedGroup::X25519));
            assert_eq!(ours[1].1.len(), 32);
            let component = &ours[0].1[1184..];
            assert_eq!(component == ours[1].1.as_slice(), !independent);
        }
    }
}

#[test]
fn independent_share_is_replaced_after_hello_retry_request() {
    let mut config = client_config(default_client_kx());
    let customizer = Arc::new(TestCustomizer {
        mode: Mode::Greased,
        independent: true,
        calls: AtomicUsize::new(0),
        seen: Mutex::new(Vec::new()),
    });
    config
        .dangerous()
        .set_client_hello_customizer(customizer.clone());
    let mut client = ClientConnection::new(Arc::new(config), server_name("localhost")).unwrap();
    let mut server = ServerConnection::new(Arc::new(server_config(
        all_tls13_suites(),
        vec![provider::kx_group::SECP256R1],
    )))
    .unwrap();
    do_handshake(&mut client, &mut server);
    round_trip(&mut client, &mut server);
    let seen = customizer.seen.lock().unwrap();
    let second = Hello::parse(&seen[1].ours).key_shares();
    assert_eq!(second.len(), 1);
    assert_eq!(second[0].0, u16::from(NamedGroup::secp256r1));
}
