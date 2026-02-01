// SPDX-License-Identifier: MIT

use netlink_packet_core::NetlinkMessage;
use netlink_packet_generic::GenlMessage;

use crate::WireguardMessage;

#[derive(Clone, Copy, Eq, PartialEq, Debug)]
pub enum ErrorKind {
    Bug,
    NetlinkError,
    DecodeError,
    /// Invalid key, should be base64 encoded of [u8; 32]
    InvalidKey,
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
    pub fn new(
        kind: ErrorKind,
        msg: String,
        netlink_msg: Option<NetlinkMessage<GenlMessage<WireguardMessage>>>,
    ) -> Self {
        Self {
            kind,
            msg,
            netlink_msg,
        }
    }
}
