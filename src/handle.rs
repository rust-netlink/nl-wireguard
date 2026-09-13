// SPDX-License-Identifier: MIT

use std::io;

use futures_util::{Stream, StreamExt};
use genetlink::GenetlinkHandle;
use netlink_packet_core::{
    DecodeError, ErrorMessage, NetlinkMessage, NetlinkPayload, NLM_F_ACK,
    NLM_F_DUMP, NLM_F_REQUEST,
};
use netlink_packet_generic::GenlMessage;
use netlink_packet_wireguard::{WireguardCmd, WireguardMessage};

use crate::{ErrorKind, WireguardError, WireguardParsed};

#[derive(Clone, Debug)]
pub struct WireguardHandle {
    handle: GenetlinkHandle,
}

impl WireguardHandle {
    pub(crate) fn new(handle: GenetlinkHandle) -> Self {
        WireguardHandle { handle }
    }

    pub async fn get_by_name(
        &mut self,
        iface_name: &str,
    ) -> Result<WireguardParsed, WireguardError> {
        let msg = WireguardParsed {
            iface_name: Some(iface_name.to_string()),
            ..Default::default()
        }
        .build(WireguardCmd::GetDevice)?;

        let mut msgs: Vec<WireguardMessage> = Vec::new();

        let mut stream = self
            .request(NLM_F_REQUEST | NLM_F_ACK | NLM_F_DUMP, msg.clone())
            .await?;

        while let Some(reply) = stream.next().await {
            msgs.push(reply?);
        }

        if msgs.is_empty() {
            return Err(WireguardError::new(
                ErrorKind::Bug,
                "Got no reply from kernel for request".to_string(),
                Some(NetlinkMessage::from(GenlMessage::from_payload(msg))),
            ));
        }

        Ok(msgs.into())
    }

    pub async fn set(
        &mut self,
        parsed: WireguardParsed,
    ) -> Result<(), WireguardError> {
        // The kernel limits the length of one netlink attribute to 64 KiB,
        // therefore a large configuration is applied by several messages,
        // each one filling in what the prior messages missed.
        let messages = parsed.build_messages(WireguardCmd::SetDevice)?;
        let total = messages.len();

        for (index, msg) in messages.into_iter().enumerate() {
            let mut stream =
                self.request(NLM_F_REQUEST | NLM_F_ACK, msg).await?;
            while let Some(reply) = stream.next().await {
                if let Err(e) = reply {
                    let WireguardError {
                        kind,
                        msg,
                        netlink_msg,
                    } = e;
                    let msg = if total > 1 {
                        format!(
                            "Failed to apply part {}/{} of the configuration: \
                             {msg}",
                            index + 1,
                            total
                        )
                    } else {
                        msg
                    };
                    return Err(WireguardError::new(kind, msg, netlink_msg));
                }
            }
        }

        Ok(())
    }

    /// Sending arbitrary [WireguardMessage] message and manually handle
    /// [WireguardMessage] reply from kernel.
    pub async fn request(
        &mut self,
        nl_header_flags: u16,
        message: WireguardMessage,
    ) -> Result<
        impl Stream<Item = Result<WireguardMessage, WireguardError>>,
        WireguardError,
    > {
        let mut nl_msg =
            NetlinkMessage::from(GenlMessage::from_payload(message));
        nl_msg.header.flags = nl_header_flags;

        match self.handle.request(nl_msg.clone()).await {
            Ok(stream) => Ok(parse_nl_msg_stream(nl_msg, stream)),
            Err(e) => Err(WireguardError::new(
                ErrorKind::NetlinkError,
                format!("Netlink request failed: {e}"),
                Some(nl_msg),
            )),
        }
    }
}

fn parse_nl_msg_stream(
    nl_msg: NetlinkMessage<GenlMessage<WireguardMessage>>,
    stream: impl Stream<
        Item = Result<
            NetlinkMessage<GenlMessage<WireguardMessage>>,
            DecodeError,
        >,
    >,
) -> impl Stream<Item = Result<WireguardMessage, WireguardError>> {
    stream.map(move |reply| match reply {
        Ok(reply_msg) => {
            let (header, payload) = reply_msg.into_parts();
            match payload {
                NetlinkPayload::InnerMessage(genl_msg) => {
                    let (_genl_hdr, wg_msg) = genl_msg.into_parts();
                    Ok(wg_msg)
                }
                NetlinkPayload::Error(ref err) => Err(WireguardError::new(
                    ErrorKind::NetlinkError,
                    netlink_error_message(err),
                    Some(NetlinkMessage::new(header, payload)),
                )),
                _ => Err(WireguardError::new(
                    ErrorKind::Bug,
                    format!(
                        "Unexpected NetlinkPayload type: {}",
                        payload_type(&payload)
                    ),
                    Some(NetlinkMessage::new(header, payload)),
                )),
            }
        }
        Err(e) => Err(WireguardError::new(
            ErrorKind::DecodeError,
            format!("netlink decode error: {e}"),
            Some(nl_msg.clone()),
        )),
    })
}

/// Describe a netlink error by its errno.
///
/// The payload of an error is a copy of the request, it is attached to the
/// [WireguardError] instead of being rendered into the message, so that key
/// material of the request is redacted.
fn netlink_error_message(err: &ErrorMessage) -> String {
    match err.code {
        Some(code) => format!(
            "Netlink error: {}",
            io::Error::from_raw_os_error(-code.get())
        ),
        None => "Netlink error: no error code".to_string(),
    }
}

/// Name the type of `payload` without rendering its content.
fn payload_type<I>(payload: &NetlinkPayload<I>) -> &'static str {
    match payload {
        NetlinkPayload::Done(_) => "Done",
        NetlinkPayload::Error(_) => "Error",
        NetlinkPayload::Noop => "Noop",
        NetlinkPayload::Overrun(_) => "Overrun",
        NetlinkPayload::InnerMessage(_) => "InnerMessage",
        _ => "Unknown",
    }
}
