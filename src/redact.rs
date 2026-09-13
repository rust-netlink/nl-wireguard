// SPDX-License-Identifier: MIT

//! Remove key material from the messages attached to errors.
//!
//! The kernel echoes the request of a rejected netlink message back in its
//! error reply and only zeros the keys of requests which reached its own
//! handler, e.g. a request rejected due to missing `CAP_NET_ADMIN` still
//! holds the keys it was sent with. Therefore the keys of a structured
//! message are zeroed and the raw copy of a request is dropped, the crate
//! attaches the request itself to the error instead.

use netlink_packet_core::{NetlinkMessage, NetlinkPayload};
use netlink_packet_generic::GenlMessage;
use netlink_packet_wireguard::{
    WireguardAttribute, WireguardMessage, WireguardPeerAttribute,
};

/// Replace all key material of `msg` with zeros.
pub(crate) fn redact_message(
    msg: &mut NetlinkMessage<GenlMessage<WireguardMessage>>,
) {
    match &mut msg.payload {
        NetlinkPayload::InnerMessage(genl_msg) => {
            redact_attributes(&mut genl_msg.payload.attributes)
        }
        // Raw bytes of a request can not be redacted reliably, drop them
        // instead of risking that a key ends up in a log.
        NetlinkPayload::Error(err_msg) => err_msg.header.clear(),
        NetlinkPayload::Overrun(bytes) => bytes.clear(),
        _ => (),
    }
}

fn redact_attributes(attributes: &mut [WireguardAttribute]) {
    for attribute in attributes {
        match attribute {
            WireguardAttribute::PrivateKey(key) => key.fill(0),
            WireguardAttribute::Peers(peers) => {
                for peer in peers.iter_mut() {
                    for attribute in peer.0.iter_mut() {
                        if let WireguardPeerAttribute::PresharedKey(key) =
                            attribute
                        {
                            key.fill(0);
                        }
                    }
                }
            }
            _ => (),
        }
    }
}

#[cfg(test)]
mod tests {
    use netlink_packet_core::{ErrorMessage, NetlinkHeader};
    use netlink_packet_wireguard::{
        WireguardCmd, WireguardPeer, WireguardPeerAttribute,
    };

    use super::*;

    fn request() -> WireguardMessage {
        WireguardMessage {
            cmd: WireguardCmd::SetDevice,
            attributes: vec![
                WireguardAttribute::IfName("wg0".to_string()),
                WireguardAttribute::PrivateKey([0x7b; 32]),
                WireguardAttribute::Peers(vec![WireguardPeer(vec![
                    WireguardPeerAttribute::PublicKey([0x11; 32]),
                    WireguardPeerAttribute::PresharedKey([0x5a; 32]),
                ])]),
            ],
        }
    }

    #[test]
    fn keys_of_a_request_are_zeroed() {
        let request = request();
        let mut msg = NetlinkMessage::from(GenlMessage::from_payload(request));

        redact_message(&mut msg);

        let NetlinkPayload::InnerMessage(genl_msg) = &msg.payload else {
            panic!("unexpected payload {:?}", msg.payload);
        };
        for attribute in &genl_msg.payload.attributes {
            match attribute {
                WireguardAttribute::PrivateKey(key) => {
                    assert_eq!(*key, [0u8; 32])
                }
                WireguardAttribute::Peers(peers) => {
                    for peer in peers {
                        for attribute in &peer.0 {
                            if let WireguardPeerAttribute::PresharedKey(key) =
                                attribute
                            {
                                assert_eq!(*key, [0u8; 32]);
                            }
                        }
                    }
                }
                _ => (),
            }
        }
    }

    #[test]
    fn echoed_request_is_dropped() {
        let mut error_message = ErrorMessage::default();
        error_message.header = vec![0x7b; 64];
        let mut msg = NetlinkMessage::new(
            NetlinkHeader::default(),
            NetlinkPayload::Error(error_message),
        );

        redact_message(&mut msg);

        let NetlinkPayload::Error(error_message) = &msg.payload else {
            panic!("unexpected payload {:?}", msg.payload);
        };
        assert!(error_message.header.is_empty());
    }
}
