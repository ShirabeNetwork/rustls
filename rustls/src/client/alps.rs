//! Kirika fork: ALPS (`application_settings`) support (fork patch P3).
//!
//! rustls never offers ALPS itself; a [`ClientHelloCustomizer`] may add it to
//! mimic a browser.  When the ClientHello as sent offered ALPS, the server may
//! answer with ALPS for the negotiated ALPN protocol in its
//! EncryptedExtensions.  The server's settings are ignored; the client then
//! sends its own EncryptedExtensions message (handshake type 8) with the same
//! codepoint and empty settings, after the server Finished and before its
//! Certificate / Finished, as Chrome (BoringSSL) and uTLS do.  Without an ALPS
//! offer, ALPS in the server's EncryptedExtensions stays an unsolicited
//! extension.
//!
//! [`ClientHelloCustomizer`]: crate::client::danger::ClientHelloCustomizer

use alloc::vec;
use alloc::vec::Vec;

use super::customize::RawClientHello;
use crate::enums::HandshakeType;
use crate::msgs::codec::{Codec, Reader};
use crate::msgs::enums::ExtensionType;
use crate::msgs::handshake::{ProtocolName, ServerExtensions};

/// `application_settings` codepoints: current (Chrome 131+) and old.
pub(super) const ALPS_CODEPOINTS: [u16; 2] = [0x44cd, 0x4469];

/// One ALPS extension offered in the ClientHello.
#[derive(Debug, Clone)]
pub(super) struct OfferedAlps {
    pub(super) typ: ExtensionType,
    pub(super) protocols: Vec<ProtocolName>,
}

/// ALPS extensions in an encoded ClientHello handshake message.
///
/// The body is `ProtocolName supported_protocols<2..2^16-1>`, the same shape
/// as ALPN.  Unparsable bodies are not treated as an offer.
pub(super) fn offered(hello: &[u8]) -> Vec<OfferedAlps> {
    let Some(raw) = RawClientHello::parse(hello) else {
        return Vec::new();
    };
    raw.extensions
        .iter()
        .filter(|(typ, _)| ALPS_CODEPOINTS.contains(typ))
        .filter_map(|(typ, body)| {
            let mut r = Reader::init(&hello[body.clone()]);
            let protocols = Vec::<ProtocolName>::read(&mut r).ok()?;
            r.expect_empty("ApplicationSettings")
                .ok()?;
            Some(OfferedAlps {
                typ: ExtensionType::from(*typ),
                protocols,
            })
        })
        .collect()
}

/// The ALPS codepoint the server's EncryptedExtensions legitimately answered.
///
/// That is: exactly one ALPS extension, of a codepoint we offered, with an
/// ALPN protocol selected that this offer listed.
pub(super) fn negotiated(
    offers: &[OfferedAlps],
    exts: &ServerExtensions<'_>,
) -> Option<ExtensionType> {
    let present = ALPS_CODEPOINTS
        .iter()
        .filter(|cp| exts.unknown_extensions.contains(cp))
        .collect::<Vec<_>>();
    let [codepoint] = present.as_slice() else {
        return None;
    };
    let selected = exts.selected_protocol.as_ref()?;
    offers
        .iter()
        .find(|o| u16::from(o.typ) == **codepoint && o.protocols.contains(selected.as_ref()))
        .map(|o| o.typ)
}

/// The client EncryptedExtensions message with empty settings for `typ`.
pub(super) fn client_encrypted_extensions(typ: ExtensionType) -> Vec<u8> {
    let mut ext = Vec::new();
    typ.encode(&mut ext);
    ext.extend_from_slice(&[0, 0]); // empty settings

    let mut body = (ext.len() as u16)
        .to_be_bytes()
        .to_vec();
    body.extend_from_slice(&ext);

    let mut msg = vec![u8::from(HandshakeType::EncryptedExtensions)];
    msg.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
    msg.extend_from_slice(&body);
    msg
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_ee_encoding() {
        assert_eq!(
            client_encrypted_extensions(ExtensionType::from(0x44cd)),
            [0x08, 0x00, 0x00, 0x06, 0x00, 0x04, 0x44, 0xcd, 0x00, 0x00]
        );
    }
}
