// SPDX-License-Identifier: MIT

use std::{io, sync::Arc};

use futures_util::{future::ready, Stream, StreamExt};
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
        //
        // A successful request is acknowledged with an `NLMSG_ERROR`
        // message without an error code, which ends the reply stream
        // without yielding an item, therefore an error is the only way a
        // request fails. Note that an error can leave the device partially
        // configured when the configuration needs several messages.
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
    let nl_msg = Arc::new(nl_msg);

    stream.filter_map(move |reply| {
        let nl_msg = Arc::clone(&nl_msg);
        ready(match reply {
            Ok(reply_msg) => {
                let (header, payload) = reply_msg.into_parts();
                match payload {
                    NetlinkPayload::InnerMessage(genl_msg) => {
                        let (_genl_hdr, wg_msg) = genl_msg.into_parts();
                        Some(Ok(wg_msg))
                    }
                    // An acknowledgement holds no error code and completes
                    // the request.
                    NetlinkPayload::Error(err) if err.code.is_none() => None,
                    // The payload of an error is a copy of the request,
                    // attach the request itself instead: it holds the same
                    // information and its keys are redacted reliably.
                    NetlinkPayload::Error(err) => {
                        Some(Err(WireguardError::new(
                            ErrorKind::NetlinkError,
                            netlink_error_message(&err),
                            Some((*nl_msg).clone()),
                        )))
                    }
                    // A dump reports its error code in the message which
                    // ends the dump.
                    NetlinkPayload::Done(done) => {
                        if done.code == 0 {
                            None
                        } else {
                            Some(Err(WireguardError::new(
                                ErrorKind::NetlinkError,
                                format!(
                                    "Netlink dump failed: {}",
                                    io::Error::from_raw_os_error(-done.code)
                                ),
                                Some((*nl_msg).clone()),
                            )))
                        }
                    }
                    NetlinkPayload::Noop => None,
                    // An overrun message holds raw bytes of a message which
                    // could not be read, attach the request instead.
                    NetlinkPayload::Overrun(_) => {
                        Some(Err(WireguardError::new(
                            ErrorKind::Bug,
                            "Netlink message overrun, messages were lost"
                                .to_string(),
                            Some((*nl_msg).clone()),
                        )))
                    }
                    payload => Some(Err(WireguardError::new(
                        ErrorKind::Bug,
                        format!(
                            "Unexpected NetlinkPayload type: {}",
                            payload_type(&payload)
                        ),
                        Some(NetlinkMessage::new(header, payload)),
                    ))),
                }
            }
            Err(e) => Some(Err(WireguardError::new(
                ErrorKind::DecodeError,
                format!("netlink decode error: {e}"),
                Some((*nl_msg).clone()),
            ))),
        })
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

#[cfg(test)]
mod tests {
    use std::num::NonZeroI32;

    use futures_util::stream;
    use netlink_packet_core::{
        DoneMessage, Emitable, ErrorMessage, NetlinkHeader,
    };
    use netlink_packet_wireguard::{
        WireguardAttribute, WireguardPeer, WireguardPeerAttribute,
    };

    use super::*;

    type NetlinkMsg = NetlinkMessage<GenlMessage<WireguardMessage>>;

    const PUBLIC_KEY: [u8; 32] = [0x11; 32];
    const PRIVATE_KEY: [u8; 32] = [0x7b; 32];
    const PRESHARED_KEY: [u8; 32] = [0x5a; 32];

    fn inner_message() -> NetlinkMsg {
        NetlinkMessage::from(GenlMessage::from_payload(WireguardMessage {
            cmd: WireguardCmd::GetDevice,
            attributes: Vec::new(),
        }))
    }

    fn acknowledgement() -> NetlinkMsg {
        NetlinkMessage::new(
            NetlinkHeader::default(),
            NetlinkPayload::Error(ErrorMessage::default()),
        )
    }

    fn error(code: i32) -> NetlinkMsg {
        let mut error_message = ErrorMessage::default();
        error_message.code = NonZeroI32::new(code);
        NetlinkMessage::new(
            NetlinkHeader::default(),
            NetlinkPayload::Error(error_message),
        )
    }

    fn done(code: i32) -> NetlinkMsg {
        let mut done_message = DoneMessage::default();
        done_message.code = code;
        NetlinkMessage::new(
            NetlinkHeader::default(),
            NetlinkPayload::Done(done_message),
        )
    }

    async fn parse_replies_with(
        request: NetlinkMsg,
        replies: Vec<NetlinkMsg>,
    ) -> Vec<Result<WireguardMessage, WireguardError>> {
        let replies: Vec<Result<NetlinkMsg, DecodeError>> =
            replies.into_iter().map(Ok).collect();
        parse_nl_msg_stream(request, stream::iter(replies))
            .collect()
            .await
    }

    async fn parse_replies(
        replies: Vec<NetlinkMsg>,
    ) -> Vec<Result<WireguardMessage, WireguardError>> {
        parse_replies_with(inner_message(), replies).await
    }

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

    /// Render bytes the way `Debug` renders a `[u8; 32]` or a `Vec<u8>`.
    fn byte_list(bytes: &[u8]) -> String {
        bytes
            .iter()
            .map(|byte| byte.to_string())
            .collect::<Vec<String>>()
            .join(", ")
    }

    #[tokio::test]
    async fn acknowledgement_and_done_are_not_errors() {
        let replies =
            parse_replies(vec![inner_message(), done(0), acknowledgement()])
                .await;

        assert_eq!(replies.len(), 1);
        assert!(replies[0].is_ok());
    }

    #[tokio::test]
    async fn netlink_error_is_reported() {
        let replies = parse_replies(vec![error(-22)]).await;

        assert_eq!(replies.len(), 1);
        let err = replies[0].as_ref().expect_err("expected an error");
        assert_eq!(err.kind, ErrorKind::NetlinkError);
        assert!(
            err.msg.contains("Invalid argument"),
            "unexpected error message: {}",
            err.msg
        );
    }

    #[tokio::test]
    async fn dump_error_is_reported() {
        let replies = parse_replies(vec![done(-19)]).await;

        assert_eq!(replies.len(), 1);
        let err = replies[0].as_ref().expect_err("expected an error");
        assert_eq!(err.kind, ErrorKind::NetlinkError);
        assert!(
            err.msg.contains("No such device"),
            "unexpected error message: {}",
            err.msg
        );
    }

    #[tokio::test]
    async fn overrun_is_reported() {
        let replies = parse_replies(vec![NetlinkMessage::new(
            NetlinkHeader::default(),
            NetlinkPayload::Overrun(Vec::new()),
        )])
        .await;

        assert_eq!(replies.len(), 1);
        let err = replies[0].as_ref().expect_err("expected an error");
        assert_eq!(err.kind, ErrorKind::Bug);
    }

    #[tokio::test]
    async fn error_does_not_report_keys() {
        let request = request_message();
        // The kernel echoes the raw request in its error reply.
        let mut echoed = vec![0u8; 16 + 4 + request.buffer_len()];
        // `cmd` and `version` of the generic netlink header.
        echoed[16] = 1;
        echoed[17] = 1;
        request.emit(&mut echoed[20..]);

        let mut error_message = ErrorMessage::default();
        error_message.code = NonZeroI32::new(-13);
        error_message.header = echoed;
        let replies = parse_replies_with(
            NetlinkMessage::from(GenlMessage::from_payload(request)),
            vec![NetlinkMessage::new(
                NetlinkHeader::default(),
                NetlinkPayload::Error(error_message),
            )],
        )
        .await;

        let err = replies[0].as_ref().expect_err("expected an error");
        // The errno is reported without rendering the echoed request.
        assert!(
            err.msg.contains("Permission denied"),
            "unexpected error message: {}",
            err.msg
        );
        let report = format!("{err:?}");
        assert!(!report.contains(&byte_list(&PRIVATE_KEY)));
        assert!(!report.contains(&byte_list(&PRESHARED_KEY)));

        // The attached request keeps the peer public key and holds no key.
        let stored = err.netlink_msg.as_ref().expect("no netlink message");
        let NetlinkPayload::InnerMessage(genl_msg) = &stored.payload else {
            panic!("unexpected payload {:?}", stored.payload);
        };
        let mut private_key_redacted = false;
        let mut preshared_key_redacted = false;
        for attribute in &genl_msg.payload.attributes {
            match attribute {
                WireguardAttribute::PrivateKey(key) => {
                    assert_eq!(*key, [0u8; 32]);
                    private_key_redacted = true;
                }
                WireguardAttribute::Peers(peers) => {
                    for peer in peers {
                        for attribute in &peer.0 {
                            match attribute {
                                WireguardPeerAttribute::PublicKey(key) => {
                                    assert_eq!(*key, PUBLIC_KEY);
                                }
                                WireguardPeerAttribute::PresharedKey(key) => {
                                    assert_eq!(*key, [0u8; 32]);
                                    preshared_key_redacted = true;
                                }
                                _ => (),
                            }
                        }
                    }
                }
                _ => (),
            }
        }
        assert!(private_key_redacted);
        assert!(preshared_key_redacted);
    }
}
