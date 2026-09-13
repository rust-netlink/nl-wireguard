// SPDX-License-Identifier: MIT

//! Replace key material of netlink messages with zeros.
//!
//! The kernel echoes the request of a rejected netlink message back in its
//! error reply and only zeros the keys of requests which reached its own
//! handler, e.g. a request rejected due to missing `CAP_NET_ADMIN` still
//! contains the keys it was sent with. Therefore every message attached to
//! a [crate::WireguardError] is redacted.

use netlink_packet_core::{NetlinkMessage, NetlinkPayload};
use netlink_packet_generic::GenlMessage;
use netlink_packet_wireguard::{
    WireguardAttribute, WireguardMessage, WireguardPeerAttribute,
};

/// `WGDEVICE_A_PRIVATE_KEY`
const WGDEVICE_A_PRIVATE_KEY: u16 = 3;
/// `WGDEVICE_A_PEERS`
const WGDEVICE_A_PEERS: u16 = 8;
/// `WGPEER_A_PRESHARED_KEY`
const WGPEER_A_PRESHARED_KEY: u16 = 2;

/// `struct nlmsghdr` size
const NLMSG_HDR_LEN: usize = 16;
/// `struct genlmsghdr` size
const GENL_HDR_LEN: usize = 4;
/// `struct nlattr` header size
const NLA_HDR_LEN: usize = 4;
const NLA_ALIGNTO: usize = 4;
/// `NLA_TYPE_MASK`
const NLA_TYPE_MASK: u16 = 0x3fff;

/// Replace all key material of `msg` with zeros.
pub(crate) fn redact_message(
    msg: &mut NetlinkMessage<GenlMessage<WireguardMessage>>,
) {
    match &mut msg.payload {
        NetlinkPayload::InnerMessage(genl_msg) => {
            redact_attributes(&mut genl_msg.payload.attributes)
        }
        NetlinkPayload::Error(err_msg) => redact_raw(&mut err_msg.header),
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

/// Zero the keys of a raw netlink message which the kernel echoed back.
///
/// The message is a netlink header, a generic netlink header and the
/// `WGDEVICE_A_*` attributes, the `WGPEER_A_*` attributes of every peer are
/// nested in `WGDEVICE_A_PEERS`.
fn redact_raw(buffer: &mut [u8]) {
    let start = NLMSG_HDR_LEN + GENL_HDR_LEN;
    if buffer.len() < start {
        return;
    }
    for_each_attribute(&mut buffer[start..], &mut |kind, value| {
        if kind == WGDEVICE_A_PRIVATE_KEY {
            value.fill(0);
        } else if kind == WGDEVICE_A_PEERS {
            redact_peers(value);
        }
    });
}

/// Zero the preshared key of every peer nested in `buffer`.
fn redact_peers(buffer: &mut [u8]) {
    // Every peer is a nested attribute of its own.
    for_each_attribute(buffer, &mut |_, peer| {
        for_each_attribute(peer, &mut |kind, value| {
            if kind == WGPEER_A_PRESHARED_KEY {
                value.fill(0);
            }
        });
    });
}

/// Call `visit` with the kind, without `NLA_F_NESTED`, and with the value
/// of every attribute in `buffer`.
fn for_each_attribute<F>(buffer: &mut [u8], visit: &mut F)
where
    F: FnMut(u16, &mut [u8]),
{
    let mut offset = 0;
    while offset + NLA_HDR_LEN <= buffer.len() {
        let len =
            u16::from_ne_bytes([buffer[offset], buffer[offset + 1]]) as usize;
        if len < NLA_HDR_LEN || offset + len > buffer.len() {
            return;
        }
        let kind = u16::from_ne_bytes([buffer[offset + 2], buffer[offset + 3]])
            & NLA_TYPE_MASK;
        visit(kind, &mut buffer[offset + NLA_HDR_LEN..offset + len]);
        offset += (len + NLA_ALIGNTO - 1) & !(NLA_ALIGNTO - 1);
    }
}
