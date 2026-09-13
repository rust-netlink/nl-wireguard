// SPDX-License-Identifier: MIT

use base64::{prelude::BASE64_STANDARD, Engine};
use netlink_packet_wireguard::{
    WireguardAttribute, WireguardCmd, WireguardDeviceFlags, WireguardMessage,
};

use crate::{ErrorKind, WireguardError, WireguardPeerParsed};

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
    pub flags: Option<Vec<WireguardParsedDeviceFlags>>,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub enum WireguardParsedDeviceFlags {
    ReplacePeers,
    Other(u32),
}

impl From<WireguardParsedDeviceFlags> for WireguardDeviceFlags {
    fn from(flag: WireguardParsedDeviceFlags) -> Self {
        match flag {
            WireguardParsedDeviceFlags::ReplacePeers => {
                WireguardDeviceFlags::ReplacePeers
            }
            WireguardParsedDeviceFlags::Other(bits) => {
                WireguardDeviceFlags::from_bits_retain(bits)
            }
        }
    }
}

impl From<WireguardDeviceFlags> for WireguardParsedDeviceFlags {
    fn from(flag: WireguardDeviceFlags) -> Self {
        match flag {
            WireguardDeviceFlags::ReplacePeers => {
                WireguardParsedDeviceFlags::ReplacePeers
            }
            _ => WireguardParsedDeviceFlags::Other(flag.bits()),
        }
    }
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
    flags: &'a Option<Vec<WireguardParsedDeviceFlags>>,
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
            flags,
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
                flags,
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
                WireguardAttribute::Flags(flag_bits) => {
                    let mut flags = Vec::new();
                    for flag_bit in flag_bits.iter() {
                        flags.push(WireguardParsedDeviceFlags::from(flag_bit));
                    }

                    ret.flags = Some(flags);
                }
                _ => {
                    log::debug!("Unsupported WireguardAttribute {attr:?}");
                }
            }
        }
        ret
    }
}

impl From<Vec<WireguardMessage>> for WireguardParsed {
    fn from(msgs: Vec<WireguardMessage>) -> Self {
        let mut ret = Self::default();

        for msg in msgs {
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
                    WireguardAttribute::ListenPort(v) => {
                        ret.listen_port = Some(v)
                    }
                    WireguardAttribute::Fwmark(v) => ret.fwmark = Some(v),
                    WireguardAttribute::Peers(peers) => {
                        ret.peers.get_or_insert_with(Vec::new).extend(
                            peers.into_iter().map(WireguardPeerParsed::from),
                        );
                    }
                    WireguardAttribute::Flags(flag_bits) => {
                        ret.flags.get_or_insert_with(Vec::new).extend(
                            flag_bits
                                .iter()
                                .map(WireguardParsedDeviceFlags::from),
                        );
                    }
                    _ => {
                        log::debug!("Unsupported WireguardAttribute {attr:?}");
                    }
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

        // The kernel accepts one but not both of `WGDEVICE_A_IFNAME` and
        // `WGDEVICE_A_IFINDEX`, so the interface name wins when a parsed
        // config carries both, which is what `get_by_name()` returns.
        if let Some(iface_name) = self.iface_name.as_ref() {
            attributes.push(WireguardAttribute::IfName(iface_name.to_string()));
        } else if let Some(iface_index) = self.iface_index {
            attributes.push(WireguardAttribute::IfIndex(iface_index));
        } else {
            return Err(WireguardError::new(
                ErrorKind::InvalidInput,
                "Neither `iface_name` nor `iface_index` is defined".to_string(),
                None,
            ));
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

        if let Some(flags) = self.flags.as_ref() {
            let flag_bits = flags
                .iter()
                .map(|&f| WireguardDeviceFlags::from(f))
                .collect();
            attributes.push(WireguardAttribute::Flags(flag_bits));
        }

        Ok(WireguardMessage { cmd, attributes })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn iface_attributes(msg: &WireguardMessage) -> (bool, bool) {
        let mut has_name = false;
        let mut has_index = false;
        for attr in &msg.attributes {
            match attr {
                WireguardAttribute::IfName(_) => has_name = true,
                WireguardAttribute::IfIndex(_) => has_index = true,
                _ => (),
            }
        }
        (has_name, has_index)
    }

    #[test]
    fn build_uses_iface_name_when_both_are_defined() {
        // `get_by_name()` returns both `iface_name` and `iface_index`, the
        // kernel rejects a request carrying both.
        let config = WireguardParsed {
            iface_name: Some("wg0".to_string()),
            iface_index: Some(3),
            ..Default::default()
        };

        let msg = config.build(WireguardCmd::GetDevice).unwrap();

        assert_eq!(iface_attributes(&msg), (true, false));
    }

    #[test]
    fn build_accepts_iface_index_only() {
        let config = WireguardParsed {
            iface_index: Some(3),
            ..Default::default()
        };

        let msg = config.build(WireguardCmd::GetDevice).unwrap();

        assert_eq!(iface_attributes(&msg), (false, true));
    }

    #[test]
    fn build_requires_an_interface() {
        let err = WireguardParsed::default()
            .build(WireguardCmd::GetDevice)
            .unwrap_err();

        assert_eq!(err.kind, ErrorKind::InvalidInput);
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
