//! Kirika fork: scripted-server tests for responses rustls' own server never
//! sends (ALPS, P3).  See `FORK.md`.
#![cfg(feature = "aws_lc_rs")]

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use std::sync::Mutex;

use pki_types::{CertificateDer, ServerName, UnixTime};

use super::customize::{ClientHelloContext, ClientHelloCustomizer, RawClientHello};
use crate::client::{ClientConfig, ClientConnection};
use crate::crypto::aws_lc_rs as provider;
use crate::crypto::cipher::{MessageDecrypter, MessageEncrypter};
use crate::crypto::hash::Context;
use crate::crypto::tls13::OkmBlock;
use crate::crypto::{CryptoProvider, hash};
use crate::enums::{CipherSuite, ContentType, ProtocolVersion, SignatureScheme};
use crate::error::{Error, PeerMisbehaved};
use crate::msgs::base::{Payload, PayloadU16};
use crate::msgs::codec::Codec;
use crate::msgs::enums::{Compression, NamedGroup};
use crate::msgs::handshake::{
    HandshakeMessagePayload, HandshakePayload, KeyShareEntry, Random, ServerExtensions,
    ServerHelloPayload, SessionId,
};
use crate::msgs::message::{InboundOpaqueMessage, Message, MessagePayload, PlainMessage};
use crate::sync::Arc;
use crate::tls13::Tls13CipherSuite;
use crate::tls13::key_schedule::{derive_traffic_iv, derive_traffic_key, hkdf_expand_label_block};
use crate::verify::{
    DigitallySignedStruct, HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
};
use crate::{KeyLog, version};

const ALPS: u16 = 0x44cd;

fn suite() -> &'static Tls13CipherSuite {
    provider::cipher_suite::TLS13_AES_128_GCM_SHA256
        .tls13()
        .unwrap()
}

/// Appends extensions to rustls' hello.
#[derive(Debug)]
struct AppendExtensions(Vec<(u16, Vec<u8>)>);

impl ClientHelloCustomizer for AppendExtensions {
    fn customize(
        &self,
        _context: &ClientHelloContext<'_>,
        hello: &[u8],
        out: &mut Vec<u8>,
    ) -> Result<(), Error> {
        let raw = RawClientHello::parse(hello).unwrap();
        let ext_start = raw.extensions[0].1.start - 4;
        let mut exts = hello[ext_start..].to_vec();
        for (typ, body) in &self.0 {
            exts.extend_from_slice(&typ.to_be_bytes());
            exts.extend_from_slice(&(body.len() as u16).to_be_bytes());
            exts.extend_from_slice(body);
        }
        let mut body = hello[4..ext_start - 2].to_vec();
        body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
        body.extend_from_slice(&exts);
        out.push(1);
        out.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
        out.extend_from_slice(&body);
        Ok(())
    }
}

#[derive(Debug)]
struct AcceptAnything;

impl ServerCertVerifier for AcceptAnything {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![SignatureScheme::ECDSA_NISTP256_SHA256]
    }
}

/// Captures the handshake traffic secrets the client logs.
#[derive(Debug, Default)]
struct Secrets(Mutex<Vec<(String, Vec<u8>)>>);

impl Secrets {
    fn get(&self, label: &str) -> Vec<u8> {
        self.0
            .lock()
            .unwrap()
            .iter()
            .find(|(l, _)| l == label)
            .unwrap()
            .1
            .clone()
    }
}

impl KeyLog for Secrets {
    fn will_log(&self, _label: &str) -> bool {
        true
    }

    fn log(&self, label: &str, _client_random: &[u8], secret: &[u8]) {
        self.0
            .lock()
            .unwrap()
            .push((label.into(), secret.to_vec()));
    }
}

fn traffic_keys(secret: &[u8]) -> (Box<dyn MessageEncrypter>, Box<dyn MessageDecrypter>) {
    let s = suite();
    let expander = s
        .hkdf_provider
        .expander_for_okm(&OkmBlock::new(secret));
    let key = derive_traffic_key(expander.as_ref(), s.aead_alg);
    let iv = derive_traffic_iv(expander.as_ref());
    let enc = s.aead_alg.encrypter(key, iv);
    let key = derive_traffic_key(expander.as_ref(), s.aead_alg);
    let iv = derive_traffic_iv(expander.as_ref());
    (enc, s.aead_alg.decrypter(key, iv))
}

fn finished(secret: &[u8], transcript: &hash::Output) -> Vec<u8> {
    let s = suite();
    let expander = s
        .hkdf_provider
        .expander_for_okm(&OkmBlock::new(secret));
    let key = hkdf_expand_label_block(expander.as_ref(), b"finished", &[]);
    s.hkdf_provider
        .hmac_sign(&key, transcript.as_ref())
        .as_ref()
        .to_vec()
}

fn handshake_msg(typ: u8, body: &[u8]) -> Vec<u8> {
    let mut m = vec![typ];
    m.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
    m.extend_from_slice(body);
    m
}

fn ext(typ: u16, body: &[u8]) -> Vec<u8> {
    let mut e = typ.to_be_bytes().to_vec();
    e.extend_from_slice(&(body.len() as u16).to_be_bytes());
    e.extend_from_slice(body);
    e
}

fn alpn_list(protocols: &[&[u8]]) -> Vec<u8> {
    let mut list = Vec::new();
    for p in protocols {
        list.push(p.len() as u8);
        list.extend_from_slice(p);
    }
    let mut body = (list.len() as u16)
        .to_be_bytes()
        .to_vec();
    body.extend_from_slice(&list);
    body
}

struct Scripted {
    client: ClientConnection,
    secrets: Arc<Secrets>,
    transcript: Box<dyn Context>,
    server_enc: Box<dyn MessageEncrypter>,
    seq: u64,
}

/// Client with an X25519-only TLS 1.3 config whose hello gets `extra` appended;
/// the scripted server answers with a ServerHello.
fn scripted(extra: Vec<(u16, Vec<u8>)>) -> Scripted {
    let secrets = Arc::new(Secrets::default());
    let provider = CryptoProvider {
        kx_groups: vec![provider::kx_group::X25519],
        ..provider::default_provider()
    };
    let mut config = ClientConfig::builder_with_provider(provider.into())
        .with_protocol_versions(&[&version::TLS13])
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAnything))
        .with_no_client_auth();
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    config.key_log = secrets.clone();
    if !extra.is_empty() {
        config
            .dangerous()
            .set_client_hello_customizer(Arc::new(AppendExtensions(extra)));
    }
    let mut client =
        ClientConnection::new(config.into(), ServerName::try_from("localhost").unwrap()).unwrap();

    let mut wire = Vec::new();
    client.write_tls(&mut wire).unwrap();
    let mut transcript = suite().common.hash_provider.start();
    transcript.update(&wire[5..]);

    let sh = HandshakeMessagePayload(HandshakePayload::ServerHello(ServerHelloPayload {
        random: Random([0; 32]),
        compression_method: Compression::Null,
        cipher_suite: CipherSuite::TLS13_AES_128_GCM_SHA256,
        legacy_version: ProtocolVersion::TLSv1_3,
        session_id: SessionId::empty(),
        extensions: Box::new(ServerExtensions {
            key_share: Some(KeyShareEntry {
                group: NamedGroup::X25519,
                payload: PayloadU16::new(vec![0xaa; 32]),
            }),
            ..ServerExtensions::default()
        }),
    }));
    transcript.update(&sh.get_encoding());
    let sh = Message {
        version: ProtocolVersion::TLSv1_3,
        payload: MessagePayload::handshake(sh),
    };
    client
        .read_tls(&mut sh.into_wire_bytes().as_slice())
        .unwrap();
    client.process_new_packets().unwrap();

    let (server_enc, _) = traffic_keys(&secrets.get("SERVER_HANDSHAKE_TRAFFIC_SECRET"));
    Scripted {
        client,
        secrets,
        transcript,
        server_enc,
        seq: 0,
    }
}

impl Scripted {
    /// Send one encrypted handshake message from the server.
    fn send(&mut self, msg: &[u8]) -> Result<(), Error> {
        self.transcript.update(msg);
        let plain = PlainMessage {
            typ: ContentType::Handshake,
            version: ProtocolVersion::TLSv1_3,
            payload: Payload::new(msg.to_vec()),
        };
        let record = self
            .server_enc
            .encrypt(plain.borrow_outbound(), self.seq)
            .unwrap()
            .encode();
        self.seq += 1;
        self.client
            .read_tls(&mut record.as_slice())
            .unwrap();
        self.client
            .process_new_packets()
            .map(|_| ())
    }

    /// EncryptedExtensions with `exts`, then Certificate, CertificateVerify, Finished.
    fn server_flight(&mut self, exts: &[u8]) -> Result<(), Error> {
        let mut ee = (exts.len() as u16)
            .to_be_bytes()
            .to_vec();
        ee.extend_from_slice(exts);
        self.send(&handshake_msg(8, &ee))?;

        // context(0) + list(u24): one entry, cert "x", no extensions
        let cert = [0, 0, 0, 6, 0, 0, 1, b'x', 0, 0];
        self.send(&handshake_msg(11, &cert))?;
        let mut cv = SignatureScheme::ECDSA_NISTP256_SHA256
            .to_array()
            .to_vec();
        cv.extend_from_slice(&[0, 1, 0]);
        self.send(&handshake_msg(15, &cv))?;

        let verify_data = finished(
            &self
                .secrets
                .get("SERVER_HANDSHAKE_TRAFFIC_SECRET"),
            &self.transcript.fork_finish(),
        );
        self.send(&handshake_msg(20, &verify_data))
    }

    /// Decrypt the client's handshake flight (after its fake CCS).
    fn client_flight(&mut self) -> Vec<u8> {
        let mut wire = Vec::new();
        self.client
            .write_tls(&mut wire)
            .unwrap();
        // skip the middlebox-compatibility ChangeCipherSpec record
        assert_eq!(&wire[..6], &[0x14, 0x03, 0x03, 0x00, 0x01, 0x01]);
        let mut record = wire[6..].to_vec();
        assert_eq!(record[0], 0x17);
        let len = usize::from(u16::from_be_bytes([record[3], record[4]]));
        assert_eq!(record.len(), 5 + len);
        let (_, mut dec) = traffic_keys(
            &self
                .secrets
                .get("CLIENT_HANDSHAKE_TRAFFIC_SECRET"),
        );
        let msg = InboundOpaqueMessage::new(
            ContentType::ApplicationData,
            ProtocolVersion::TLSv1_2,
            &mut record[5..],
        );
        let plain = dec.decrypt(msg, 0).unwrap();
        assert_eq!(plain.typ, ContentType::Handshake);
        plain.payload.to_vec()
    }
}

#[test]
fn alps_is_answered_with_empty_client_encrypted_extensions() {
    for codepoint in [ALPS, 0x4469] {
        let mut s = scripted(vec![(codepoint, alpn_list(&[b"h2"]))]);
        let mut exts = ext(0x0010, &alpn_list(&[b"h2"]));
        exts.extend(ext(codepoint, b"\x00\x03server-settings"));
        s.server_flight(&exts).unwrap();
        assert!(!s.client.is_handshaking());

        let flight = s.client_flight();
        let client_ee = [
            0x08,
            0x00,
            0x00,
            0x06,
            0x00,
            0x04,
            (codepoint >> 8) as u8,
            codepoint as u8,
            0x00,
            0x00,
        ];
        assert_eq!(&flight[..10], &client_ee);

        // client Finished covers the transcript including its EncryptedExtensions
        s.transcript.update(&client_ee);
        let expected = finished(
            &s.secrets
                .get("CLIENT_HANDSHAKE_TRAFFIC_SECRET"),
            &s.transcript.fork_finish(),
        );
        assert_eq!(&flight[10..], &handshake_msg(20, &expected)[..]);
    }
}

#[test]
fn alps_without_offer_is_unsolicited() {
    let mut s = scripted(vec![]);
    let mut exts = ext(0x0010, &alpn_list(&[b"h2"]));
    exts.extend(ext(ALPS, b""));
    assert_eq!(
        s.server_flight(&exts),
        Err(PeerMisbehaved::UnsolicitedEncryptedExtension.into())
    );
}

#[test]
fn alps_for_other_protocol_or_codepoint_is_unsolicited() {
    // ALPS offered for h2 only, but http/1.1 negotiated.
    let mut s = scripted(vec![(ALPS, alpn_list(&[b"h2"]))]);
    let mut exts = ext(0x0010, &alpn_list(&[b"http/1.1"]));
    exts.extend(ext(ALPS, b""));
    assert_eq!(
        s.server_flight(&exts),
        Err(PeerMisbehaved::UnsolicitedEncryptedExtension.into())
    );

    // ALPS without ALPN.
    let mut s = scripted(vec![(ALPS, alpn_list(&[b"h2"]))]);
    assert_eq!(
        s.server_flight(&ext(ALPS, b"")),
        Err(PeerMisbehaved::UnsolicitedEncryptedExtension.into())
    );

    // The old codepoint answered to an offer of the new one.
    let mut s = scripted(vec![(ALPS, alpn_list(&[b"h2"]))]);
    let mut exts = ext(0x0010, &alpn_list(&[b"h2"]));
    exts.extend(ext(0x4469, b""));
    assert_eq!(
        s.server_flight(&exts),
        Err(PeerMisbehaved::UnsolicitedEncryptedExtension.into())
    );
}

#[test]
fn no_client_encrypted_extensions_without_alps() {
    let mut s = scripted(vec![(ALPS, alpn_list(&[b"h2"]))]);
    s.server_flight(&ext(0x0010, &alpn_list(&[b"h2"])))
        .unwrap();
    let flight = s.client_flight();
    assert_eq!(flight[0], 20, "Finished only");
    let expected = finished(
        &s.secrets
            .get("CLIENT_HANDSHAKE_TRAFFIC_SECRET"),
        &s.transcript.fork_finish(),
    );
    assert_eq!(flight, handshake_msg(20, &expected));
}
