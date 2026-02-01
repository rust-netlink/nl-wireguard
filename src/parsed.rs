// SPDX-License-Identifier: MIT

use base64::{prelude::BASE64_STANDARD, Engine};

use crate::{
    ErrorKind, WireguardAttribute, WireguardCmd, WireguardError,
    WireguardMessage, WireguardPeerParsed,
};

#[derive(Clone, PartialEq, Eq, Default)]
#[non_exhaustive]
pub struct WireguardParsed {
    pub iface_name: Option<String>,
    pub iface_index: Option<u32>,
    /// Base64 encoded public key
    pub public_key: Option<String>,
    /// Base64 encoded private key, this property will be display as
    /// `(hidden)` for `Debug` trait.
    pub private_key: Option<String>,
    pub listen_port: Option<u16>,
    pub fwmark: Option<u32>,
    pub peers: Option<Vec<WireguardPeerParsed>>,
    // TODO: Flags
}

// For simplifying the code on hide `private_key` in Debug display of
// [WireguardParsed]
#[allow(dead_code)]
#[derive(Debug)]
struct _WireguardParsed<'a> {
    iface_name: &'a Option<String>,
    iface_index: &'a Option<u32>,
    public_key: &'a Option<String>,
    private_key: Option<String>,
    listen_port: &'a Option<u16>,
    fwmark: &'a Option<u32>,
    peers: &'a Option<Vec<WireguardPeerParsed>>,
}

impl std::fmt::Debug for WireguardParsed {
    fn fmt(
        &self,
        f: &mut std::fmt::Formatter<'_>,
    ) -> Result<(), std::fmt::Error> {
        let Self {
            iface_name,
            iface_index,
            public_key,
            private_key,
            listen_port,
            fwmark,
            peers,
        } = self;

        std::fmt::Debug::fmt(
            &_WireguardParsed {
                iface_name,
                iface_index,
                public_key,
                private_key: if private_key.is_some() {
                    Some("(hidden)".to_string())
                } else {
                    None
                },
                listen_port,
                fwmark,
                peers,
            },
            f,
        )
    }
}

impl From<WireguardMessage> for WireguardParsed {
    fn from(msg: WireguardMessage) -> Self {
        let mut ret = Self::default();
        for attr in msg.attributes {
            match attr {
                WireguardAttribute::IfName(v) => ret.iface_name = Some(v),
                WireguardAttribute::IfIndex(v) => ret.iface_index = Some(v),
                WireguardAttribute::PrivateKey(v) => {
                    ret.private_key = Some(BASE64_STANDARD.encode(v))
                }
                WireguardAttribute::PublicKey(v) => {
                    ret.public_key = Some(BASE64_STANDARD.encode(v))
                }
                WireguardAttribute::ListenPort(v) => ret.listen_port = Some(v),
                WireguardAttribute::Fwmark(v) => ret.fwmark = Some(v),
                WireguardAttribute::Peers(peers) => {
                    ret.peers = Some(
                        peers
                            .into_iter()
                            .map(WireguardPeerParsed::from)
                            .collect(),
                    );
                }
                _ => {
                    log::debug!("Unsupported WireguardAttribute {attr:?}");
                }
            }
        }
        ret
    }
}

impl WireguardParsed {
    /// Build [WireguardMessage]
    pub fn build(
        &self,
        cmd: WireguardCmd,
    ) -> Result<WireguardMessage, WireguardError> {
        let mut attributes: Vec<WireguardAttribute> = Vec::new();

        if let Some(v) = self.iface_name.as_ref() {
            attributes.push(WireguardAttribute::IfName(v.to_string()));
        }

        if let Some(v) = self.iface_index {
            attributes.push(WireguardAttribute::IfIndex(v));
        }

        if let Some(v) = self.public_key.as_deref() {
            attributes.push(WireguardAttribute::PublicKey(decode_key(
                "public_key",
                v,
            )?));
        }

        if let Some(v) = self.private_key.as_deref() {
            attributes.push(WireguardAttribute::PrivateKey(decode_key(
                "private_key",
                v,
            )?));
        }

        if let Some(v) = self.listen_port {
            attributes.push(WireguardAttribute::ListenPort(v));
        }

        if let Some(v) = self.fwmark {
            attributes.push(WireguardAttribute::Fwmark(v));
        }

        if let Some(peers) = self.peers.as_ref() {
            let mut peer_addrs = Vec::new();
            for peer in peers {
                peer_addrs.push(peer.build()?);
            }
            attributes.push(WireguardAttribute::Peers(peer_addrs));
        }

        Ok(WireguardMessage { cmd, attributes })
    }
}

pub(crate) fn decode_key(
    prop_name: &str,
    key_str: &str,
) -> Result<[u8; WireguardAttribute::WG_KEY_LEN], WireguardError> {
    let key = BASE64_STANDARD.decode(key_str).map_err(|e| {
        WireguardError::new(
            ErrorKind::InvalidKey,
            format!(
                "Invalid {prop_name}: not valid base64 encoded string \
                 {key_str}: {e}"
            ),
            None,
        )
    })?;
    if key.len() != WireguardAttribute::WG_KEY_LEN {
        return Err(WireguardError::new(
            ErrorKind::InvalidKey,
            format!(
                "Invalid {prop_name}: current length {}, but expecting {} \
                 length of u8 encoded base64 string, {key_str}",
                key.len(),
                WireguardAttribute::WG_KEY_LEN
            ),
            None,
        ));
    }
    let mut key_data = [0u8; WireguardAttribute::WG_KEY_LEN];
    key_data.copy_from_slice(&key);
    Ok(key_data)
}
