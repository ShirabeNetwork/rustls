//! Kirika fork: ClientHello customization hook (fork patch P1).
//!
//! rustls builds its ClientHello as usual (random, legacy_session_id and every
//! key share are rustls' own), then hands the encoded handshake message to a
//! [`ClientHelloCustomizer`].  The customizer returns the bytes to send; rustls
//! re-parses them and only uses them if the invariants checked in [`apply`]
//! hold.  The returned bytes are what goes on the wire and into the transcript.
//!
//! This is not part of upstream rustls.  See `FORK.md` at the repository root.

use alloc::vec::Vec;
use core::fmt;
use core::ops::Range;

use crate::client::ech::EchState;
use crate::enums::{ContentType, HandshakeType, ProtocolVersion};
use crate::error::Error;
use crate::msgs::base::Payload;
use crate::msgs::enums::ExtensionType;
use crate::msgs::handshake::{ClientHelloPayload, EncryptedClientHello, HandshakePayload};
use crate::msgs::message::{Message, MessagePayload};

/// Reshapes the ClientHello that rustls is about to send.
///
/// Set with [`DangerousClientConfig::set_client_hello_customizer`].  Setting a
/// customizer disables session resumption and early data for that config.
///
/// The customizer may change the *shape* of the hello (extension order,
/// GREASE values, additional extensions, cipher suite / group / signature
/// algorithm lists, padding), but rustls rejects the result with
/// [`Error::InvalidCustomClientHello`] unless:
///
/// - it is exactly one well-formed ClientHello handshake message
///   (4-byte header included) that rustls can parse;
/// - `random` and `legacy_session_id` are unchanged;
/// - every key share entry whose group is not a GREASE value (RFC 8701) is
///   byte-identical to one rustls generated, and no group appears twice;
/// - there is no `pre_shared_key` or `early_data` extension;
/// - `server_name`, `application_layer_protocol_negotiation`, `cookie`,
///   `encrypted_client_hello`, `ech_outer_extensions` and the QUIC transport
///   parameter extensions are present exactly when rustls sent them, with
///   byte-identical bodies;
/// - `supported_versions` offers TLS 1.3.
///
/// Everything rustls later checks the server's responses against (offered
/// cipher suites, groups, key share groups, extension types, certificate
/// compression algorithms) is recomputed from the bytes actually sent.
/// Extensions rustls cannot parse are not treated as offered.
///
/// [`DangerousClientConfig::set_client_hello_customizer`]: crate::client::danger::DangerousClientConfig::set_client_hello_customizer
pub trait ClientHelloCustomizer: fmt::Debug + Send + Sync {
    /// Produce the ClientHello to send.
    ///
    /// `hello` is the handshake message rustls built (handshake header
    /// included).  Write the message to send, also with its handshake header,
    /// into `out`, which is empty on entry.  Returning an error aborts the
    /// handshake with that error.
    fn customize(
        &self,
        context: &ClientHelloContext<'_>,
        hello: &[u8],
        out: &mut Vec<u8>,
    ) -> Result<(), Error>;

    /// Send an independent key share for the classical component of a hybrid
    /// group (fork patch P2).
    ///
    /// When the first key share is a hybrid group (e.g. `X25519MLKEM768`) whose
    /// classical component group (e.g. `X25519`) is enabled separately, rustls
    /// by default sends the hybrid's own component key as the second share.
    /// When this returns `true`, rustls instead generates a separate key pair for
    /// the component group with the provider (as browsers do) and uses it if the
    /// server selects that group.  Defaults to `false`.
    fn independent_hybrid_component_share(&self) -> bool {
        false
    }
}

/// Context passed to [`ClientHelloCustomizer::customize`].
#[non_exhaustive]
#[derive(Debug)]
pub struct ClientHelloContext<'a> {
    /// `Some` when this is the second ClientHello, sent in response to a
    /// HelloRetryRequest.
    pub retry: Option<HelloRetryContext<'a>>,
    /// The hello is the outer ClientHello of a real ECH offer.
    ///
    /// The `encrypted_client_hello` extension must be kept byte-identical.
    /// For a fresh offer its payload is all zeroes at this point: rustls
    /// encrypts the inner hello with the customized outer hello as AAD and
    /// then fills in the payload.
    pub ech_outer: bool,
    /// The hello carries a GREASE `encrypted_client_hello` extension, which
    /// must be kept byte-identical.
    pub ech_grease: bool,
}

/// HelloRetryRequest context for the second ClientHello.
#[non_exhaustive]
#[derive(Debug)]
pub struct HelloRetryContext<'a> {
    /// The HelloRetryRequest handshake message as received (header included).
    pub hello_retry_request: &'a [u8],
    /// The first ClientHello handshake message as sent (header included).
    pub first_client_hello: &'a [u8],
}

/// Why rustls refused a customized ClientHello.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CustomClientHelloError {
    /// The output is not exactly one well-formed ClientHello message.
    Malformed,
    /// `random` differs from the one rustls generated.
    RandomChanged,
    /// `legacy_session_id` differs from the one rustls generated.
    SessionIdChanged,
    /// A non-GREASE key share is not one rustls generated.
    ForeignKeyShare,
    /// A non-GREASE key share group appears more than once.
    DuplicateKeyShare,
    /// `pre_shared_key` or `early_data` is present.
    PskOrEarlyData,
    /// An extension that must match rustls' own was changed, added or removed.
    ExtensionMismatch(ExtensionType),
    /// `supported_versions` does not offer TLS 1.3.
    Tls13NotOffered,
    /// A customizer cannot be used for QUIC connections.
    QuicNotSupported,
}

impl fmt::Display for CustomClientHelloError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Malformed => write!(f, "not a well-formed ClientHello"),
            Self::RandomChanged => write!(f, "random changed"),
            Self::SessionIdChanged => write!(f, "legacy_session_id changed"),
            Self::ForeignKeyShare => write!(f, "key share not generated by rustls"),
            Self::DuplicateKeyShare => write!(f, "duplicate key share group"),
            Self::PskOrEarlyData => write!(f, "pre_shared_key or early_data present"),
            Self::ExtensionMismatch(typ) => write!(f, "extension {typ:?} does not match"),
            Self::Tls13NotOffered => write!(f, "supported_versions lacks TLS 1.3"),
            Self::QuicNotSupported => write!(f, "not supported for QUIC"),
        }
    }
}

impl From<CustomClientHelloError> for Error {
    fn from(e: CustomClientHelloError) -> Self {
        Self::InvalidCustomClientHello(e)
    }
}

/// RFC 8701 GREASE value (`0x?a?a` with equal bytes).
pub(crate) fn is_grease(v: u16) -> bool {
    v & 0x0f0f == 0x0a0a && (v >> 8) == (v & 0xff)
}

/// Extensions whose presence and body must be exactly what rustls sent.
const MUST_MATCH: &[ExtensionType] = &[
    ExtensionType::ServerName,
    ExtensionType::ALProtocolNegotiation,
    ExtensionType::Cookie,
    ExtensionType::EncryptedClientHello,
    ExtensionType::EncryptedClientHelloOuterExtensions,
    ExtensionType::TransportParameters,
    ExtensionType::TransportParametersDraft,
];

/// Byte offsets into an encoded ClientHello handshake message.
pub(crate) struct RawClientHello {
    random: Range<usize>,
    session_id: Range<usize>,
    /// Extension type and body range, in wire order.
    pub(crate) extensions: Vec<(u16, Range<usize>)>,
}

impl RawClientHello {
    /// Walk an encoded ClientHello handshake message (header included).
    ///
    /// Returns `None` unless `msg` is exactly one ClientHello message whose
    /// framing is consistent.
    pub(crate) fn parse(msg: &[u8]) -> Option<Self> {
        let mut c = Cursor { buf: msg, pos: 0 };
        if c.u8()? != u8::from(HandshakeType::ClientHello) {
            return None;
        }
        let len = c.u24()?;
        if len != msg.len() - 4 {
            return None;
        }
        c.take(2)?; // legacy_version
        let random = c.take(32)?;
        let sid_len = usize::from(c.u8()?);
        let session_id = c.take(sid_len)?;
        let cs_len = usize::from(c.u16()?);
        c.take(cs_len)?;
        let cm_len = usize::from(c.u8()?);
        c.take(cm_len)?;

        let mut extensions = Vec::new();
        if c.pos != msg.len() {
            let ext_len = usize::from(c.u16()?);
            if c.pos + ext_len != msg.len() {
                return None;
            }
            while c.pos < msg.len() {
                let typ = c.u16()?;
                let body_len = usize::from(c.u16()?);
                extensions.push((typ, c.take(body_len)?));
            }
        }

        Some(Self {
            random,
            session_id,
            extensions,
        })
    }

    /// The body of the first extension of type `typ`.
    pub(crate) fn find<'a>(&self, msg: &'a [u8], typ: ExtensionType) -> Option<&'a [u8]> {
        let typ = u16::from(typ);
        self.extensions
            .iter()
            .find(|(t, _)| *t == typ)
            .map(|(_, body)| &msg[body.clone()])
    }
}

struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl Cursor<'_> {
    fn take(&mut self, n: usize) -> Option<Range<usize>> {
        let end = self.pos.checked_add(n)?;
        if end > self.buf.len() {
            return None;
        }
        let r = self.pos..end;
        self.pos = end;
        Some(r)
    }

    fn u8(&mut self) -> Option<u8> {
        let r = self.take(1)?;
        Some(self.buf[r.start])
    }

    fn u16(&mut self) -> Option<u16> {
        let r = self.take(2)?;
        Some(u16::from_be_bytes([
            self.buf[r.start],
            self.buf[r.start + 1],
        ]))
    }

    fn u24(&mut self) -> Option<usize> {
        let r = self.take(3)?;
        let b = &self.buf[r];
        Some(usize::from(b[0]) << 16 | usize::from(b[1]) << 8 | usize::from(b[2]))
    }
}

/// A real ECH offer whose payload is sealed after customization.
pub(crate) struct PendingEchSeal<'a> {
    pub(crate) state: &'a mut EchState,
    pub(crate) encoded_inner_hello: Vec<u8>,
}

/// Run `customizer` over `ours` and return the checked message to send.
pub(crate) fn apply(
    customizer: &dyn ClientHelloCustomizer,
    ours: &Message<'_>,
    context: &ClientHelloContext<'_>,
    ech: Option<PendingEchSeal<'_>>,
) -> Result<Message<'static>, Error> {
    let MessagePayload::Handshake {
        parsed,
        encoded: ours_encoded,
    } = &ours.payload
    else {
        unreachable!("ClientHello is a handshake message");
    };
    let HandshakePayload::ClientHello(ours_ch) = &parsed.0 else {
        unreachable!("ClientHello payload");
    };
    let ours_bytes = ours_encoded.bytes();
    let ours_raw = RawClientHello::parse(ours_bytes).ok_or(CustomClientHelloError::Malformed)?;

    let mut out = Vec::new();
    customizer.customize(context, ours_bytes, &mut out)?;

    let raw = RawClientHello::parse(&out).ok_or(CustomClientHelloError::Malformed)?;
    let ch = parse_client_hello(&out)?;

    if out[raw.random.clone()] != ours_bytes[ours_raw.random.clone()] {
        return Err(CustomClientHelloError::RandomChanged.into());
    }
    if out[raw.session_id.clone()] != ours_bytes[ours_raw.session_id.clone()] {
        return Err(CustomClientHelloError::SessionIdChanged.into());
    }
    if ch.preshared_key_offer.is_some() || ch.early_data_request.is_some() {
        return Err(CustomClientHelloError::PskOrEarlyData.into());
    }
    for typ in MUST_MATCH {
        if raw.find(&out, *typ) != ours_raw.find(ours_bytes, *typ) {
            return Err(CustomClientHelloError::ExtensionMismatch(*typ).into());
        }
    }

    let ours_shares = ours_ch
        .key_shares
        .as_deref()
        .unwrap_or_default();
    let mut seen_groups = Vec::new();
    for share in ch
        .key_shares
        .as_deref()
        .unwrap_or_default()
    {
        let group = u16::from(share.group);
        if is_grease(group) {
            continue;
        }
        if seen_groups.contains(&group) {
            return Err(CustomClientHelloError::DuplicateKeyShare.into());
        }
        seen_groups.push(group);
        let ours = ours_shares
            .iter()
            .any(|o| o.group == share.group && o.payload.0 == share.payload.0);
        if !ours {
            return Err(CustomClientHelloError::ForeignKeyShare.into());
        }
    }

    if !ch
        .supported_versions
        .is_some_and(|v| v.tls13)
    {
        return Err(CustomClientHelloError::Tls13NotOffered.into());
    }

    let ch = match ech {
        None => ch,
        Some(PendingEchSeal {
            state,
            encoded_inner_hello,
        }) => {
            // The ECH extension body is byte-identical to rustls' placeholder (checked
            // above), whose payload is the last `payload_len` bytes of the body.
            let Some(EncryptedClientHello::Outer(placeholder)) = &ours_ch.encrypted_client_hello
            else {
                unreachable!("real ECH offer without outer extension");
            };
            let payload_len = placeholder.payload.0.len();
            let body = raw
                .extensions
                .iter()
                .find(|(t, _)| *t == u16::from(ExtensionType::EncryptedClientHello))
                .map(|(_, body)| body.clone())
                .ok_or(CustomClientHelloError::Malformed)?;

            // ClientHelloOuterAAD: the outer hello without the handshake header, with
            // the payload still zeroed.
            let sealed = state.seal(&out[4..], &encoded_inner_hello)?;
            if sealed.len() != payload_len {
                return Err(Error::General("ECH payload length mismatch".into()));
            }
            out[body.end - payload_len..body.end].copy_from_slice(&sealed);
            parse_client_hello(&out)?
        }
    };

    Ok(Message {
        version: ours.version,
        payload: MessagePayload::Handshake {
            parsed: crate::msgs::handshake::HandshakeMessagePayload(HandshakePayload::ClientHello(
                ch,
            )),
            encoded: Payload::new(out),
        },
    })
}

fn parse_client_hello(msg: &[u8]) -> Result<ClientHelloPayload, CustomClientHelloError> {
    match MessagePayload::new(ContentType::Handshake, ProtocolVersion::TLSv1_2, msg) {
        Ok(MessagePayload::Handshake {
            parsed:
                crate::msgs::handshake::HandshakeMessagePayload(HandshakePayload::ClientHello(ch)),
            ..
        }) => Ok(ch),
        _ => Err(CustomClientHelloError::Malformed),
    }
}

#[cfg(test)]
mod tests {
    use super::is_grease;

    #[test]
    fn grease_values() {
        for hi in 0..16u16 {
            let v = (hi << 12) | 0x0a00 | (hi << 4) | 0x0a;
            assert!(is_grease(v), "{v:#06x}");
        }
        assert!(!is_grease(0x0a1a));
        assert!(!is_grease(0x1a0a));
        assert!(!is_grease(0x001d));
        assert!(!is_grease(0x11ec));
    }
}
