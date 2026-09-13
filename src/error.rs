// SPDX-License-Identifier: MIT

use netlink_packet_core::NetlinkMessage;
use netlink_packet_generic::GenlMessage;
use netlink_packet_wireguard::WireguardMessage;

#[derive(Clone, Copy, Eq, PartialEq, Debug)]
pub enum ErrorKind {
    Bug,
    NetlinkError,
    DecodeError,
    /// Invalid key, should be base64 encoded of [u8; 32]
    InvalidKey,
    /// Invalid input from the caller, e.g. missing required property
    InvalidInput,
}

impl std::fmt::Display for ErrorKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Self::Bug => "bug",
                Self::NetlinkError => "netlink_error",
                Self::DecodeError => "decode_error",
                Self::InvalidKey => "invalid_key",
                Self::InvalidInput => "invalid_input",
            }
        )
    }
}

#[derive(Clone, Eq, PartialEq, Debug)]
pub struct WireguardError {
    pub kind: ErrorKind,
    pub msg: String,
    pub netlink_msg: Option<NetlinkMessage<GenlMessage<WireguardMessage>>>,
}

impl std::fmt::Display for WireguardError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(nl_msg) = self.netlink_msg.as_ref() {
            write!(
                f,
                "{}: {}, netlink message: {:?}",
                self.kind, self.msg, nl_msg
            )
        } else {
            write!(f, "{}: {}", self.kind, self.msg)
        }
    }
}

impl std::error::Error for WireguardError {}

impl WireguardError {
    /// Create a new [WireguardError].
    ///
    /// Key material is replaced with zeros in `netlink_msg`, so that keys
    /// which the kernel echoed back can not end up in logs.
    pub fn new(
        kind: ErrorKind,
        msg: String,
        netlink_msg: Option<NetlinkMessage<GenlMessage<WireguardMessage>>>,
    ) -> Self {
        Self {
            kind,
            msg,
            netlink_msg: netlink_msg.map(|mut netlink_msg| {
                crate::redact::redact_message(&mut netlink_msg);
                netlink_msg
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroI32;

    use netlink_packet_core::{
        Emitable, ErrorMessage, NetlinkHeader, NetlinkPayload,
    };
    use netlink_packet_wireguard::{
        WireguardAttribute, WireguardCmd, WireguardPeer, WireguardPeerAttribute,
    };

    use super::*;

    const PRIVATE_KEY: [u8; 32] = [0x7b; 32];
    const PRESHARED_KEY: [u8; 32] = [0x5a; 32];
    const PUBLIC_KEY: [u8; 32] = [0x11; 32];

    fn request_message() -> WireguardMessage {
        WireguardMessage {
            cmd: WireguardCmd::SetDevice,
            attributes: vec![
                WireguardAttribute::IfName("wg0".to_string()),
                WireguardAttribute::PrivateKey(PRIVATE_KEY),
                WireguardAttribute::Peers(vec![WireguardPeer(vec![
                    WireguardPeerAttribute::PublicKey(PUBLIC_KEY),
                    WireguardPeerAttribute::PresharedKey(PRESHARED_KEY),
                ])]),
            ],
        }
    }

    fn contains(haystack: &[u8], needle: &[u8]) -> bool {
        haystack
            .windows(needle.len())
            .any(|window| window == needle)
    }

    /// Assert that all keys of `attributes` are zeroed and report whether
    /// a private and a preshared key was found.
    fn assert_redacted(attributes: &[WireguardAttribute]) -> (bool, bool) {
        let mut has_private_key = false;
        let mut has_preshared_key = false;
        for attribute in attributes {
            match attribute {
                WireguardAttribute::PrivateKey(key) => {
                    has_private_key = true;
                    assert_eq!(*key, [0u8; 32]);
                }
                WireguardAttribute::Peers(peers) => {
                    for peer in peers {
                        for attribute in &peer.0 {
                            if let WireguardPeerAttribute::PresharedKey(key) =
                                attribute
                            {
                                has_preshared_key = true;
                                assert_eq!(*key, [0u8; 32]);
                            }
                        }
                    }
                }
                _ => (),
            }
        }
        (has_private_key, has_preshared_key)
    }

    #[test]
    fn keys_are_redacted_from_request_messages() {
        let err = WireguardError::new(
            ErrorKind::NetlinkError,
            "test".to_string(),
            Some(NetlinkMessage::from(GenlMessage::from_payload(
                request_message(),
            ))),
        );

        let stored = err.netlink_msg.as_ref().expect("no netlink message");
        let NetlinkPayload::InnerMessage(genl_msg) = &stored.payload else {
            panic!("unexpected payload {:?}", stored.payload);
        };
        assert_eq!(assert_redacted(&genl_msg.payload.attributes), (true, true));
    }

    #[test]
    fn keys_are_redacted_from_echoed_requests() {
        // The kernel echoes the raw request in its error reply.
        let message = request_message();
        let mut raw = vec![0u8; 16 + 4 + message.buffer_len()];
        // `cmd` and `version` of the generic netlink header.
        raw[16] = 1;
        raw[17] = 1;
        message.emit(&mut raw[20..]);

        let mut error_message = ErrorMessage::default();
        error_message.code = NonZeroI32::new(-22);
        error_message.header = raw;

        let err = WireguardError::new(
            ErrorKind::NetlinkError,
            "test".to_string(),
            Some(NetlinkMessage::new(
                NetlinkHeader::default(),
                NetlinkPayload::Error(error_message),
            )),
        );

        let stored = err.netlink_msg.as_ref().expect("no netlink message");
        let NetlinkPayload::Error(error_message) = &stored.payload else {
            panic!("unexpected payload {:?}", stored.payload);
        };
        assert!(!contains(&error_message.header, &PRIVATE_KEY));
        assert!(!contains(&error_message.header, &PRESHARED_KEY));
        // Public keys are no secrets and are kept for diagnostics.
        assert!(contains(&error_message.header, &PUBLIC_KEY));
        assert!(!format!("{err:?}").contains(&hex(&PRIVATE_KEY)));
        assert!(!format!("{err:?}").contains(&hex(&PRESHARED_KEY)));
    }

    fn hex(key: &[u8]) -> String {
        key.iter()
            .map(|byte| byte.to_string())
            .collect::<Vec<String>>()
            .join(", ")
    }
}
