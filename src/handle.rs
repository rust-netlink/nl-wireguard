// SPDX-License-Identifier: MIT

use futures_util::{Stream, StreamExt};
use genetlink::GenetlinkHandle;
use netlink_packet_core::{
    DecodeError, NetlinkMessage, NetlinkPayload, NLM_F_ACK, NLM_F_DUMP,
    NLM_F_REQUEST,
};
use netlink_packet_generic::GenlMessage;

use crate::{
    ErrorKind, WireguardCmd, WireguardError, WireguardMessage, WireguardParsed,
};

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
        match self
            .request(NLM_F_REQUEST | NLM_F_ACK | NLM_F_DUMP, msg.clone())
            .await?
            .next()
            .await
        {
            None => Err(WireguardError::new(
                ErrorKind::Bug,
                "Got no reply from kernel for request".to_string(),
                Some(NetlinkMessage::from(GenlMessage::from_payload(msg))),
            )),
            Some(reply) => reply.map(WireguardParsed::from),
        }
    }

    pub async fn set(
        &mut self,
        parsed: WireguardParsed,
    ) -> Result<(), WireguardError> {
        let msg = parsed.build(WireguardCmd::SetDevice)?;
        //TODO: Polished this
        match self
            .request(NLM_F_REQUEST | NLM_F_ACK, msg.clone())
            .await?
            .next()
            .await
        {
            None | Some(Ok(_)) => Ok(()),
            Some(Err(e)) => Err(e),
        }
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
                    format!("netlink error: {err:?}"),
                    Some(NetlinkMessage::new(header, payload)),
                )),
                _ => Err(WireguardError::new(
                    ErrorKind::Bug,
                    format!("Unexpected NetlinkPayload type: {payload:?}"),
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
