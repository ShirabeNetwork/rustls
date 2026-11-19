use alloc::boxed::Box;
use alloc::vec::Vec;

use super::ResolvesClientCert;
use crate::log::{debug, trace};
use crate::msgs::enums::{ExtensionType, NamedGroup};
use crate::msgs::handshake::{
    CertificateChain, ClientHelloPayload, DistinguishedName, ProtocolName, ServerExtensions,
};
use crate::sync::Arc;
use crate::{CertificateCompressionAlgorithm, CipherSuite, SignatureScheme, compress, sign};

#[derive(Debug)]
pub(super) struct ServerCertDetails<'a> {
    pub(super) cert_chain: CertificateChain<'a>,
    pub(super) ocsp_response: Vec<u8>,
}

impl<'a> ServerCertDetails<'a> {
    pub(super) fn new(cert_chain: CertificateChain<'a>, ocsp_response: Vec<u8>) -> Self {
        Self {
            cert_chain,
            ocsp_response,
        }
    }

    pub(super) fn into_owned(self) -> ServerCertDetails<'static> {
        let Self {
            cert_chain,
            ocsp_response,
        } = self;
        ServerCertDetails {
            cert_chain: cert_chain.into_owned(),
            ocsp_response,
        }
    }
}

pub(super) struct ClientHelloDetails {
    pub(super) alpn_protocols: Vec<ProtocolName>,
    pub(super) sent_extensions: Vec<ExtensionType>,
    pub(super) extension_order_seed: u16,
    pub(super) offered_cert_compression: bool,
    pub(super) offered_cipher_suites: Vec<CipherSuite>,
    /// Non-GREASE groups in the sent `supported_groups` (Kirika fork).
    pub(super) offered_groups: Vec<NamedGroup>,
    /// Non-GREASE groups of the sent key shares (Kirika fork).
    pub(super) sent_key_share_groups: Vec<NamedGroup>,
    /// ALPS extensions offered (Kirika fork P3).
    pub(super) offered_alps: Vec<super::alps::OfferedAlps>,
}

impl ClientHelloDetails {
    pub(super) fn new(alpn_protocols: Vec<ProtocolName>, extension_order_seed: u16) -> Self {
        Self {
            alpn_protocols,
            sent_extensions: Vec::new(),
            extension_order_seed,
            offered_cert_compression: false,
            offered_cipher_suites: Vec::new(),
            offered_groups: Vec::new(),
            sent_key_share_groups: Vec::new(),
            offered_alps: Vec::new(),
        }
    }

    /// Record what the ClientHello actually sent offers (Kirika fork).
    ///
    /// `ch` is the hello as sent, which differs from the one rustls built
    /// when a `ClientHelloCustomizer` is set.  Extensions rustls cannot parse
    /// are not recorded as offered.
    pub(super) fn record_sent(
        &mut self,
        ch: &ClientHelloPayload,
        encoded: &[u8],
        facts: &mut SentHelloFacts,
    ) {
        self.offered_alps = super::alps::offered(encoded);
        let not_grease = |g: &NamedGroup| !super::customize::is_grease(u16::from(*g));
        self.sent_extensions = ch.collect_used();
        self.offered_cipher_suites = ch.cipher_suites.clone();
        self.offered_cert_compression = ch
            .certificate_compression_algorithms
            .is_some();
        self.offered_groups = ch
            .named_groups
            .iter()
            .flatten()
            .copied()
            .filter(not_grease)
            .collect();
        self.sent_key_share_groups = ch
            .key_shares
            .iter()
            .flatten()
            .map(|kse| kse.group)
            .filter(not_grease)
            .collect();
        facts.cert_compression_algs = ch
            .certificate_compression_algorithms
            .clone()
            .unwrap_or_default();
    }

    pub(super) fn server_sent_unsolicited_extensions(
        &self,
        received_exts: &ServerExtensions<'_>,
        allowed_unsolicited: &[ExtensionType],
    ) -> bool {
        let mut extensions = received_exts.collect_used();
        extensions.extend(
            received_exts
                .unknown_extensions
                .iter()
                .map(|ext| ExtensionType::from(*ext)),
        );
        for ext_type in extensions {
            if !self.sent_extensions.contains(&ext_type) && !allowed_unsolicited.contains(&ext_type)
            {
                trace!("Unsolicited extension {ext_type:?}");
                return true;
            }
        }

        false
    }
}

/// Facts about the ClientHello actually sent that handshake states after
/// EncryptedExtensions check the server's messages against (Kirika fork).
#[derive(Debug, Default)]
pub(super) struct SentHelloFacts {
    /// Offered certificate compression algorithms.
    pub(super) cert_compression_algs: Vec<CertificateCompressionAlgorithm>,
    /// ALPS codepoint the server answered in EncryptedExtensions (P3).
    pub(super) alps: Option<ExtensionType>,
}

pub(super) enum ClientAuthDetails {
    /// Send an empty `Certificate` and no `CertificateVerify`.
    Empty { auth_context_tls13: Option<Vec<u8>> },
    /// Send a non-empty `Certificate` and a `CertificateVerify`.
    Verify {
        certkey: Arc<sign::CertifiedKey>,
        signer: Box<dyn sign::Signer>,
        auth_context_tls13: Option<Vec<u8>>,
        compressor: Option<&'static dyn compress::CertCompressor>,
    },
}

impl ClientAuthDetails {
    pub(super) fn resolve(
        resolver: &dyn ResolvesClientCert,
        canames: Option<&[DistinguishedName]>,
        sigschemes: &[SignatureScheme],
        auth_context_tls13: Option<Vec<u8>>,
        compressor: Option<&'static dyn compress::CertCompressor>,
    ) -> Self {
        let acceptable_issuers = canames
            .unwrap_or_default()
            .iter()
            .map(|p| p.as_ref())
            .collect::<Vec<&[u8]>>();

        if let Some(certkey) = resolver.resolve(&acceptable_issuers, sigschemes) {
            if let Some(signer) = certkey.key.choose_scheme(sigschemes) {
                debug!("Attempting client auth");
                return Self::Verify {
                    certkey,
                    signer,
                    auth_context_tls13,
                    compressor,
                };
            }
        }

        debug!("Client auth requested but no cert/sigscheme available");
        Self::Empty { auth_context_tls13 }
    }
}
