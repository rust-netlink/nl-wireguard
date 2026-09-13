// SPDX-License-Identifier: MIT

use base64::{prelude::BASE64_STANDARD, Engine};
use netlink_packet_core::{Emitable, NLA_ALIGNTO, NLA_HEADER_SIZE};
use netlink_packet_wireguard::{
    WireguardAllowedIp, WireguardAttribute, WireguardCmd, WireguardDeviceFlags,
    WireguardMessage, WireguardPeer, WireguardPeerAttribute,
    WireguardPeerFlags,
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
                    WireguardAttribute::Peers(peer_attributes) => {
                        let peers = ret.peers.get_or_insert_with(Vec::new);
                        for peer in peer_attributes {
                            push_peer(peers, WireguardPeerParsed::from(peer));
                        }
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

/// The kernel encodes the length of a netlink attribute in a `u16`,
/// therefore the value of one attribute is limited to this number of bytes
/// once the attribute header and the 4 bytes alignment are accounted for.
const MAX_NLA_VALUE_LEN: usize =
    u16::MAX as usize - NLA_HEADER_SIZE - (NLA_ALIGNTO - 1);

/// Maximum length of an interface name, `IFNAMSIZ` from
/// `include/uapi/linux/if.h` includes the trailing NUL byte.
const IFNAMSIZ: usize = 16;

impl WireguardParsed {
    /// Build [WireguardMessage]
    ///
    /// This fails with [ErrorKind::InvalidInput] when the configuration does
    /// not fit into a single netlink message, please use
    /// [WireguardParsed::build_messages] or
    /// [crate::WireguardHandle::set] for such configuration.
    pub fn build(
        &self,
        cmd: WireguardCmd,
    ) -> Result<WireguardMessage, WireguardError> {
        let mut messages = self.build_messages(cmd)?;
        if messages.len() > 1 {
            return Err(WireguardError::new(
                ErrorKind::InvalidInput,
                format!(
                    "The configuration requires {} netlink messages, please \
                     use `WireguardHandle::set()`",
                    messages.len()
                ),
                None,
            ));
        }
        Ok(messages.remove(0))
    }

    /// Build one or more [WireguardMessage].
    ///
    /// The kernel accepts several `WG_CMD_SET_DEVICE` messages for one
    /// device where each message fills in what the prior messages missed,
    /// therefore configurations with many peers or allowed IPs are split
    /// into messages which are within [MAX_NLA_VALUE_LEN].
    pub fn build_messages(
        &self,
        cmd: WireguardCmd,
    ) -> Result<Vec<WireguardMessage>, WireguardError> {
        let mut messages: Vec<WireguardMessage> = Vec::new();
        let mut peers: Vec<WireguardPeer> = Vec::new();
        let mut peers_len: usize = 0;

        for peer in self.peers.iter().flatten() {
            for chunk in peer_chunks(peer)? {
                let chunk_len = chunk.buffer_len();
                if !peers.is_empty()
                    && peers_len + chunk_len > MAX_NLA_VALUE_LEN
                {
                    let first = messages.is_empty();
                    messages.push(self.build_message(
                        cmd,
                        first,
                        std::mem::take(&mut peers),
                    )?);
                    peers_len = 0;
                }
                peers.push(chunk);
                peers_len += chunk_len;
            }
        }

        if !peers.is_empty() || messages.is_empty() {
            let first = messages.is_empty();
            messages.push(self.build_message(cmd, first, peers)?);
        }

        Ok(messages)
    }

    /// Build [WireguardMessage] using `peers`.
    ///
    /// The interface is required in every message, other device level
    /// properties and `WGDEVICE_F_REPLACE_PEERS` are only sent in the first
    /// message so that the peers of the prior messages are kept.
    fn build_message(
        &self,
        cmd: WireguardCmd,
        first: bool,
        peers: Vec<WireguardPeer>,
    ) -> Result<WireguardMessage, WireguardError> {
        let mut attributes = if first {
            self.device_attributes()?
        } else {
            vec![self.iface_attribute()?]
        };
        if self.peers.is_some() {
            attributes.push(WireguardAttribute::Peers(peers));
        }
        Ok(WireguardMessage { cmd, attributes })
    }

    /// Build the [WireguardAttribute::IfName] or
    /// [WireguardAttribute::IfIndex] attribute.
    fn iface_attribute(&self) -> Result<WireguardAttribute, WireguardError> {
        // The kernel accepts one but not both of `WGDEVICE_A_IFNAME` and
        // `WGDEVICE_A_IFINDEX`, so the interface name wins when a parsed
        // config carries both, which is what `get_by_name()` returns.
        if let Some(iface_name) = self.iface_name.as_ref() {
            if iface_name.len() >= IFNAMSIZ {
                return Err(WireguardError::new(
                    ErrorKind::InvalidInput,
                    format!(
                        "`iface_name` can not be longer than {} bytes, but \
                         `{iface_name}` holds {} bytes",
                        IFNAMSIZ - 1,
                        iface_name.len()
                    ),
                    None,
                ));
            }
            if iface_name.contains('\0') {
                return Err(WireguardError::new(
                    ErrorKind::InvalidInput,
                    "`iface_name` can not hold a NUL byte, the kernel would \
                     use the name in front of it"
                        .to_string(),
                    None,
                ));
            }
            Ok(WireguardAttribute::IfName(iface_name.to_string()))
        } else if let Some(iface_index) = self.iface_index {
            Ok(WireguardAttribute::IfIndex(iface_index))
        } else {
            Err(WireguardError::new(
                ErrorKind::InvalidInput,
                "Neither `iface_name` nor `iface_index` is defined".to_string(),
                None,
            ))
        }
    }

    /// Build all [WireguardMessage] attributes except
    /// [WireguardAttribute::Peers].
    fn device_attributes(
        &self,
    ) -> Result<Vec<WireguardAttribute>, WireguardError> {
        let mut attributes: Vec<WireguardAttribute> = Vec::new();

        attributes.push(self.iface_attribute()?);

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

        if let Some(flags) = self.flags.as_ref() {
            let flag_bits = flags
                .iter()
                .map(|&f| WireguardDeviceFlags::from(f))
                .collect();
            attributes.push(WireguardAttribute::Flags(flag_bits));
        }

        Ok(attributes)
    }
}

/// Split `peer` into [WireguardPeer] chunks which each fit into a single
/// netlink attribute.
///
/// The kernel repeats a peer which does not fit into a single message with
/// only `WGPEER_A_PUBLIC_KEY` and `WGPEER_A_ALLOWEDIPS`, the other
/// attributes are only sent with the first chunk.
fn peer_chunks(
    peer: &WireguardPeerParsed,
) -> Result<Vec<WireguardPeer>, WireguardError> {
    let mut state_attributes = Vec::new();
    let mut allowed_ips = None;
    let mut remove_me = false;

    for attribute in peer.build()?.0 {
        match attribute {
            WireguardPeerAttribute::AllowedIps(ips) => allowed_ips = Some(ips),
            WireguardPeerAttribute::Flags(flags) => {
                remove_me = flags.contains(WireguardPeerFlags::RemoveMe);
                state_attributes.push(WireguardPeerAttribute::Flags(flags));
            }
            attribute => state_attributes.push(attribute),
        }
    }

    let Some(mut allowed_ips) = allowed_ips else {
        return Ok(vec![WireguardPeer(state_attributes)]);
    };

    // The kernel ignores the allowed IPs of a peer which is being removed,
    // and a chunk without the state attributes would re-create the peer.
    if remove_me {
        return Ok(vec![WireguardPeer(state_attributes)]);
    }

    if allowed_ips.is_empty() {
        state_attributes.push(WireguardPeerAttribute::AllowedIps(allowed_ips));
        return Ok(vec![WireguardPeer(state_attributes)]);
    }

    let public_key = state_attributes
        .iter()
        .find(|attribute| {
            matches!(attribute, WireguardPeerAttribute::PublicKey(_))
        })
        .cloned();
    if public_key.is_none() {
        return Err(WireguardError::new(
            ErrorKind::InvalidInput,
            "`peer.public_key` is required for splitting a peer over several \
             netlink messages"
                .to_string(),
            None,
        ));
    }

    let state_len = NLA_HEADER_SIZE
        + state_attributes
            .iter()
            .map(Emitable::buffer_len)
            .sum::<usize>();
    let first_batch = take_allowed_ips_batch(&mut allowed_ips, state_len);
    let mut first_chunk = state_attributes;
    first_chunk.push(WireguardPeerAttribute::AllowedIps(first_batch));
    let mut chunks = vec![WireguardPeer(first_chunk)];

    // The public key is the only state the kernel needs to find the peer
    // again in the following messages.
    let public_key = public_key.expect("checked above");
    let continuation_len = NLA_HEADER_SIZE + public_key.buffer_len();
    while !allowed_ips.is_empty() {
        let batch = take_allowed_ips_batch(&mut allowed_ips, continuation_len);
        chunks.push(WireguardPeer(vec![
            public_key.clone(),
            WireguardPeerAttribute::AllowedIps(batch),
        ]));
    }

    Ok(chunks)
}

/// Remove as many allowed IPs from `ips` as fit into a peer whose other
/// attributes occupy `prefix_len` bytes.
fn take_allowed_ips_batch(
    ips: &mut Vec<WireguardAllowedIp>,
    prefix_len: usize,
) -> Vec<WireguardAllowedIp> {
    let mut len = prefix_len + NLA_HEADER_SIZE;
    let mut count = 0;
    for ip in ips.iter() {
        let ip_len = ip.buffer_len();
        if count > 0 && len + ip_len > MAX_NLA_VALUE_LEN {
            break;
        }
        len += ip_len;
        count += 1;
    }
    ips.drain(..count).collect()
}

/// Append `peer` to `peers`, merging it with the previous entry when the
/// kernel split one peer over several messages.
fn push_peer(peers: &mut Vec<WireguardPeerParsed>, peer: WireguardPeerParsed) {
    if let Some(last) = peers.last_mut() {
        if peer.public_key.is_some() && last.public_key == peer.public_key {
            last.merge_continuation(peer);
            return;
        }
    }
    peers.push(peer);
}

pub(crate) fn decode_key(
    prop_name: &str,
    key_str: &str,
) -> Result<[u8; WireguardAttribute::WG_KEY_LEN], WireguardError> {
    let key = BASE64_STANDARD.decode(key_str).map_err(|e| {
        WireguardError::new(
            ErrorKind::InvalidKey,
            format!(
                "Invalid {prop_name}: not a valid base64 encoded string: {e}"
            ),
            None,
        )
    })?;
    if key.len() != WireguardAttribute::WG_KEY_LEN {
        return Err(WireguardError::new(
            ErrorKind::InvalidKey,
            format!(
                "Invalid {prop_name}: {} bytes expected, but the base64 \
                 encoded string holds {} bytes",
                WireguardAttribute::WG_KEY_LEN,
                key.len()
            ),
            None,
        ));
    }
    let mut key_data = [0u8; WireguardAttribute::WG_KEY_LEN];
    key_data.copy_from_slice(&key);
    Ok(key_data)
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use genetlink::message::RawGenlMessage;
    use netlink_packet_generic::GenlMessage;
    use netlink_packet_wireguard::{
        WireguardAddressFamily, WireguardAllowedIpAttr,
    };

    use super::*;
    use crate::{WireguardIpAddress, WireguardParsedPeerFlags};

    const PEER_PUBLIC_KEY: &str =
        "8bdQrVLqiw3ZoHCucNh1YfH0iCWuyStniRr8t7H24Fk=";

    const DEVICE_PRIVATE_KEY: &str =
        "6LTHiAM4vgKEgi5vm30f/EBIEWFDmySkTc9EWCcIqEs=";

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

    fn peer_with_allowed_ips(count: u32) -> WireguardPeerParsed {
        WireguardPeerParsed {
            public_key: Some(PEER_PUBLIC_KEY.to_string()),
            allowed_ips: Some(
                (0..count)
                    .map(|i| WireguardIpAddress {
                        ip_addr: IpAddr::V4(Ipv4Addr::new(
                            10,
                            213,
                            (i / 256) as u8,
                            (i % 256) as u8,
                        )),
                        prefix_length: 32,
                        flags: None,
                    })
                    .collect(),
            ),
            ..Default::default()
        }
    }

    fn large_config() -> WireguardParsed {
        WireguardParsed {
            iface_name: Some("wg0".to_string()),
            private_key: Some(DEVICE_PRIVATE_KEY.to_string()),
            flags: Some(vec![WireguardParsedDeviceFlags::ReplacePeers]),
            peers: Some(vec![peer_with_allowed_ips(5_000)]),
            ..Default::default()
        }
    }

    fn peers_of(msg: &WireguardMessage) -> Vec<&WireguardPeer> {
        msg.attributes
            .iter()
            .filter_map(|attr| match attr {
                WireguardAttribute::Peers(peers) => Some(peers.as_slice()),
                _ => None,
            })
            .flatten()
            .collect()
    }

    fn allowed_ip_count(msg: &WireguardMessage) -> usize {
        peers_of(msg)
            .iter()
            .map(|peer| {
                peer.0
                    .iter()
                    .map(|attr| match attr {
                        WireguardPeerAttribute::AllowedIps(ips) => ips.len(),
                        _ => 0,
                    })
                    .sum::<usize>()
            })
            .sum()
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

    #[test]
    fn iface_name_is_limited_to_ifnamsiz() {
        // The kernel rejects a longer name with `-EINVAL`.
        let longest = WireguardParsed {
            iface_name: Some("a".repeat(IFNAMSIZ - 1)),
            ..Default::default()
        };
        assert!(longest.build(WireguardCmd::GetDevice).is_ok());

        let too_long = WireguardParsed {
            iface_name: Some("a".repeat(IFNAMSIZ)),
            ..Default::default()
        };
        let err = too_long.build(WireguardCmd::GetDevice).unwrap_err();
        assert_eq!(err.kind, ErrorKind::InvalidInput);

        // The kernel would use the name in front of an embedded NUL.
        let with_nul = WireguardParsed {
            iface_name: Some("wg0\0wg1".to_string()),
            ..Default::default()
        };
        let err = with_nul.build(WireguardCmd::GetDevice).unwrap_err();
        assert_eq!(err.kind, ErrorKind::InvalidInput);
    }

    #[test]
    fn build_messages_splits_large_peer() {
        let messages = large_config()
            .build_messages(WireguardCmd::SetDevice)
            .unwrap();

        assert!(messages.len() > 1);
        let mut total_allowed_ips = 0;
        for (index, msg) in messages.iter().enumerate() {
            // Emitting a message used to panic as soon as the peers
            // attribute passed the 64 KiB netlink attribute limit.
            let _ = RawGenlMessage::from_genlmsg(GenlMessage::from_payload(
                msg.clone(),
            ));
            for attr in &msg.attributes {
                // The kernel encodes the length of an attribute in a `u16`.
                assert!(attr.buffer_len() <= u16::MAX as usize);
            }

            assert_eq!(iface_attributes(msg), (true, false));

            // Device level properties and `WGDEVICE_F_REPLACE_PEERS` are
            // only sent in the first message.
            let has_device_properties = msg.attributes.iter().any(|attr| {
                matches!(
                    attr,
                    WireguardAttribute::PrivateKey(_)
                        | WireguardAttribute::Flags(_)
                )
            });
            assert_eq!(has_device_properties, index == 0);

            total_allowed_ips += allowed_ip_count(msg);
        }

        assert_eq!(total_allowed_ips, 5_000);
    }

    #[test]
    fn build_messages_only_repeats_public_key_and_allowed_ips() {
        let messages = large_config()
            .build_messages(WireguardCmd::SetDevice)
            .unwrap();
        let peers: Vec<&WireguardPeer> =
            messages.iter().flat_map(peers_of).collect();

        assert!(peers.len() > 1);
        for peer in peers.iter().skip(1) {
            for attr in &peer.0 {
                assert!(matches!(
                    attr,
                    WireguardPeerAttribute::PublicKey(_)
                        | WireguardPeerAttribute::AllowedIps(_)
                ));
            }
        }
    }

    #[test]
    fn build_messages_does_not_re_create_removed_peer() {
        let mut config = large_config();
        let peer = WireguardPeerParsed {
            flags: Some(vec![WireguardParsedPeerFlags::RemoveMe]),
            ..peer_with_allowed_ips(5_000)
        };
        config.peers = Some(vec![peer]);

        let messages = config.build_messages(WireguardCmd::SetDevice).unwrap();

        // The kernel ignores the allowed IPs of a peer which is removed,
        // extra messages would re-create the peer.
        assert_eq!(messages.len(), 1);
        assert_eq!(allowed_ip_count(&messages[0]), 0);
    }

    #[test]
    fn build_rejects_configuration_needing_several_messages() {
        let err = large_config().build(WireguardCmd::SetDevice).unwrap_err();

        assert_eq!(err.kind, ErrorKind::InvalidInput);
    }

    fn allowed_ip(ip: &str) -> WireguardAllowedIp {
        let ip: IpAddr = ip.parse().expect("invalid IP address");
        let family = if ip.is_ipv4() {
            WireguardAddressFamily::Ipv4
        } else {
            WireguardAddressFamily::Ipv6
        };
        WireguardAllowedIp(vec![
            WireguardAllowedIpAttr::Cidr(32),
            WireguardAllowedIpAttr::Family(family),
            WireguardAllowedIpAttr::IpAddr(ip),
        ])
    }

    fn reply_with_peer(peer: WireguardPeer) -> WireguardMessage {
        WireguardMessage {
            cmd: WireguardCmd::GetDevice,
            attributes: vec![WireguardAttribute::Peers(vec![peer])],
        }
    }

    #[test]
    fn get_device_replies_are_coalesced() {
        // The kernel repeats a peer which does not fit into a single
        // message with only its public key and the remaining allowed IPs.
        let first_reply = WireguardMessage {
            cmd: WireguardCmd::GetDevice,
            attributes: vec![
                WireguardAttribute::IfName("wg0".to_string()),
                WireguardAttribute::IfIndex(3),
                WireguardAttribute::Peers(vec![WireguardPeer(vec![
                    WireguardPeerAttribute::PublicKey([1u8; 32]),
                    WireguardPeerAttribute::PersistentKeepalive(25),
                    WireguardPeerAttribute::RxBytes(1024),
                    WireguardPeerAttribute::AllowedIps(vec![
                        allowed_ip("10.213.0.1"),
                        allowed_ip("10.213.0.2"),
                    ]),
                ])]),
            ],
        };
        let continuation = reply_with_peer(WireguardPeer(vec![
            WireguardPeerAttribute::PublicKey([1u8; 32]),
            WireguardPeerAttribute::AllowedIps(vec![allowed_ip("10.213.0.3")]),
        ]));
        let last_continuation = reply_with_peer(WireguardPeer(vec![
            WireguardPeerAttribute::PublicKey([1u8; 32]),
            WireguardPeerAttribute::AllowedIps(vec![allowed_ip("10.213.0.4")]),
        ]));

        let parsed = WireguardParsed::from(vec![
            first_reply,
            continuation,
            last_continuation,
        ]);

        assert_eq!(parsed.iface_name.as_deref(), Some("wg0"));
        assert_eq!(parsed.iface_index, Some(3));
        let peers = parsed.peers.expect("no peer parsed");
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].allowed_ips.as_ref().map(Vec::len), Some(4));
        assert_eq!(peers[0].persistent_keepalive, Some(25));
        assert_eq!(peers[0].rx_bytes, Some(1024));
    }

    #[test]
    fn peers_with_different_public_keys_are_not_coalesced() {
        let parsed = WireguardParsed::from(vec![
            reply_with_peer(WireguardPeer(vec![
                WireguardPeerAttribute::PublicKey([1u8; 32]),
                WireguardPeerAttribute::AllowedIps(vec![allowed_ip(
                    "10.213.0.1",
                )]),
            ])),
            reply_with_peer(WireguardPeer(vec![
                WireguardPeerAttribute::PublicKey([2u8; 32]),
                WireguardPeerAttribute::AllowedIps(vec![allowed_ip(
                    "10.213.0.2",
                )]),
            ])),
        ]);

        assert_eq!(parsed.peers.expect("no peer parsed").len(), 2);
    }

    #[test]
    fn invalid_key_is_not_reported_in_the_error() {
        // 31 bytes instead of 32.
        let key = "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQQ==";
        let err = decode_key("private_key", key).unwrap_err();
        assert_eq!(err.kind, ErrorKind::InvalidKey);
        assert!(!err.msg.contains(key));
        assert!(!format!("{err:?}").contains(key));

        let key = "not base64!";
        let err = decode_key("peer.preshared_key", key).unwrap_err();
        assert_eq!(err.kind, ErrorKind::InvalidKey);
        assert!(!err.msg.contains(key));
        assert!(!format!("{err:?}").contains(key));
    }
}
