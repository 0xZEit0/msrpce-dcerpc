use crate::auth::{AuthLevel, RpcAuthProvider as AuthProvider};
use crate::bind::{BindAckPdu, BindNakPdu, PresentationContext};
use crate::error::{Error, Result};
use crate::pdu::{
    BindPdu, FaultPdu, PduHeader, PduPacket, PduType, RequestPdu, ResponsePdu, SecurityTrailer,
    COMMON_HEADER_LEN, PFC_FIRST_FRAG, PFC_LAST_FRAG,
};
use crate::syntax::{InterfaceId, TransferSyntax};
use crate::transport::RpcTransport;
use msrpce_ndr::{Ndr, NdrDeserialize, NdrSerialize};

const REQUEST_HEADER_LEN: usize = 8;
const DEFAULT_MAX_XMIT_FRAG: u16 = 4280;

/// Generic bound MS-RPCE client over an abstract transport.
pub struct RpcClient<T> {
    transport: T,
    context_id: u16,
    call_id: u32,
    max_xmit_frag: u16,
    auth_provider: Option<Box<dyn AuthProvider>>,
}

impl<T: RpcTransport> RpcClient<T> {
    pub fn bind(transport: T, interface: InterfaceId) -> Result<Self> {
        let proposed = vec![PresentationContext::new(
            0,
            interface.syntax_id(),
            vec![TransferSyntax::Ndr32],
        )];
        Self::bind_with_contexts(transport, proposed)
    }

    pub fn bind_with_contexts(transport: T, proposed: Vec<PresentationContext>) -> Result<Self> {
        Self::bind_with_contexts_inner(transport, proposed, None)
    }

    pub fn bind_with_auth_provider<A>(
        transport: T,
        proposed: Vec<PresentationContext>,
        target: &str,
        auth_provider: A,
    ) -> Result<Self>
    where
        A: AuthProvider + 'static,
    {
        Self::bind_with_contexts_inner(transport, proposed, Some((target, Box::new(auth_provider))))
    }

    fn bind_with_contexts_inner(
        mut transport: T,
        proposed: Vec<PresentationContext>,
        auth: Option<(&str, Box<dyn AuthProvider>)>,
    ) -> Result<Self> {
        if proposed.is_empty() {
            return Err(Error::InvalidPdu(
                "bind requires at least one presentation context",
            ));
        }
        let mut auth_provider = auth
            .map(|(target, mut provider)| {
                let token = provider.init_context(target)?;
                Ok::<_, Error>((provider, token))
            })
            .transpose()?;

        let bind = BindPdu::with_contexts(
            DEFAULT_MAX_XMIT_FRAG,
            DEFAULT_MAX_XMIT_FRAG,
            0,
            proposed.clone(),
        );
        let bind_body = bind.encode();
        let call_id = 1;
        #[cfg(feature = "tracing")]
        tracing::debug!(
            call_id,
            context_count = proposed.len(),
            "sending MS-RPCE bind"
        );
        let bind_packet = if let Some((provider, token)) = auth_provider.as_mut() {
            let flags = auth_pfc_flags(provider.as_ref());
            authenticated_packet(
                PduType::Bind,
                call_id,
                flags,
                bind_body.clone(),
                provider.as_mut(),
                token.clone(),
            )?
        } else {
            PduPacket::new(
                PduHeader::new(PduType::Bind, PFC_FIRST_FRAG | PFC_LAST_FRAG, call_id),
                bind_body.clone(),
                Vec::new(),
            )
        };
        transport.send_pdu(&bind_packet.encode()?)?;

        let response = PduPacket::decode(&transport.recv_pdu()?)?;
        #[cfg(feature = "tracing")]
        tracing::debug!(
            call_id = response.header.call_id,
            ptype = ?response.header.ptype,
            frag_length = response.header.frag_length,
            auth_length = response.header.auth_length,
            "received MS-RPCE bind response"
        );
        if response.header.call_id != call_id {
            return Err(Error::InvalidPdu("bind response call id mismatch"));
        }

        match response.header.ptype {
            PduType::BindAck => {
                let ack = BindAckPdu::decode(response.body())?;
                let accepted = ack.accepted_context(&proposed)?;
                if let Some((provider, _)) = auth_provider.as_mut() {
                    if !response.auth_value().is_empty() {
                        let token = provider.step(response.auth_value())?;
                        if !token.is_empty() {
                            let auth3 = authenticated_packet(
                                PduType::Auth3,
                                call_id,
                                auth_pfc_flags(provider.as_ref()),
                                b"    ".to_vec(),
                                provider.as_mut(),
                                token,
                            )?;
                            transport.send_pdu(&auth3.encode()?)?;
                        }
                    }
                }
                #[cfg(feature = "tracing")]
                tracing::debug!(
                    context_id = accepted.context_id,
                    transfer_syntax = %accepted.transfer_syntax.uuid,
                    max_xmit_frag = ack.max_xmit_frag,
                    max_recv_frag = ack.max_recv_frag,
                    "MS-RPCE bind accepted"
                );
                Ok(Self {
                    transport,
                    context_id: accepted.context_id,
                    call_id: call_id + 1,
                    max_xmit_frag: ack.max_xmit_frag,
                    auth_provider: auth_provider.map(|(provider, _)| provider),
                })
            }
            PduType::BindNak => Err(Error::BindRejected(
                BindNakPdu::decode(response.body())?.reject_reason,
            )),
            _ => Err(Error::InvalidPdu("expected bind ack or bind nak PDU")),
        }
    }

    pub fn new_bound(transport: T, context_id: u16) -> Self {
        Self {
            transport,
            context_id,
            call_id: 1,
            max_xmit_frag: DEFAULT_MAX_XMIT_FRAG,
            auth_provider: None,
        }
    }

    pub fn new_bound_with_auth<A>(transport: T, context_id: u16, auth_provider: A) -> Self
    where
        A: AuthProvider + 'static,
    {
        Self {
            transport,
            context_id,
            call_id: 1,
            max_xmit_frag: DEFAULT_MAX_XMIT_FRAG,
            auth_provider: Some(Box::new(auth_provider)),
        }
    }

    pub fn with_max_xmit_frag(mut self, max_xmit_frag: u16) -> Self {
        self.max_xmit_frag = max_xmit_frag;
        self
    }

    pub fn transport(&self) -> &T {
        &self.transport
    }

    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    pub fn call_raw(&mut self, opnum: u16, request_stub: &[u8]) -> Result<Vec<u8>> {
        let call_id = self.next_call_id();
        #[cfg(feature = "tracing")]
        tracing::debug!(
            call_id,
            context_id = self.context_id,
            opnum,
            request_stub_len = request_stub.len(),
            "sending MS-RPCE request"
        );
        self.send_request_fragments(call_id, opnum, request_stub)?;
        let response = self.recv_response_fragments(call_id)?;
        #[cfg(feature = "tracing")]
        tracing::debug!(
            call_id,
            context_id = self.context_id,
            opnum,
            response_stub_len = response.len(),
            "received MS-RPCE response"
        );
        Ok(response)
    }

    pub fn call<Req, Resp>(&mut self, opnum: u16, request: &Req) -> Result<Resp>
    where
        Req: NdrSerialize,
        Resp: NdrDeserialize,
    {
        let ndr = Ndr::new();
        let request_stub = ndr.serialize(request)?;
        let response_stub = self.call_raw(opnum, &request_stub)?;
        Ok(ndr.deserialize(&response_stub)?)
    }

    fn next_call_id(&mut self) -> u32 {
        let call_id = self.call_id;
        self.call_id = self.call_id.wrapping_add(1).max(1);
        call_id
    }

    fn send_request_fragments(
        &mut self,
        call_id: u32,
        opnum: u16,
        request_stub: &[u8],
    ) -> Result<()> {
        let max_stub_per_frag = usize::from(self.max_xmit_frag)
            .checked_sub(COMMON_HEADER_LEN as usize + REQUEST_HEADER_LEN)
            .ok_or(Error::InvalidPdu("max transmit fragment is too small"))?;
        if max_stub_per_frag == 0 {
            return Err(Error::InvalidPdu("max transmit fragment is too small"));
        }

        if request_stub.is_empty() {
            let request = self.request_fragment(opnum, 0, request_stub.to_vec());
            let packet = self.request_packet(call_id, PFC_FIRST_FRAG | PFC_LAST_FRAG, request)?;
            self.transport.send_pdu(&packet.encode()?)?;
            return Ok(());
        }

        let mut offset = 0;
        while offset < request_stub.len() {
            let end = (offset + max_stub_per_frag).min(request_stub.len());
            let mut flags = 0;
            if offset == 0 {
                flags |= PFC_FIRST_FRAG;
            }
            if end == request_stub.len() {
                flags |= PFC_LAST_FRAG;
            }

            let request = self.request_fragment(
                opnum,
                request_stub.len() as u32,
                request_stub[offset..end].to_vec(),
            );
            let packet = self.request_packet(call_id, flags, request)?;
            self.transport.send_pdu(&packet.encode()?)?;
            offset = end;
        }

        Ok(())
    }

    fn request_fragment(&self, opnum: u16, alloc_hint: u32, stub_data: Vec<u8>) -> RequestPdu {
        RequestPdu {
            alloc_hint,
            ctx_id: self.context_id,
            opnum,
            object: None,
            stub_data,
        }
    }

    fn request_packet(
        &mut self,
        call_id: u32,
        pfc_flags: u8,
        request: RequestPdu,
    ) -> Result<PduPacket> {
        let Some(provider) = self.auth_provider.as_mut() else {
            return Ok(PduPacket::from_request_with_flags(
                call_id, pfc_flags, request,
            ));
        };

        match provider.auth_level() {
            AuthLevel::None | AuthLevel::Connect => Ok(PduPacket::from_request_with_flags(
                call_id, pfc_flags, request,
            )),
            AuthLevel::PacketIntegrity => Err(Error::Auth(
                "RPC auth level PacketIntegrity is not supported in v1".to_string(),
            )),
            AuthLevel::PacketPrivacy => Err(Error::Auth(
                "RPC auth level PacketPrivacy is not supported in v1".to_string(),
            )),
        }
    }

    fn recv_response_fragments(&mut self, expected_call_id: u32) -> Result<Vec<u8>> {
        let mut response_stub = Vec::new();
        let mut saw_first = false;

        loop {
            let bytes = self.transport.recv_pdu()?;
            let packet = PduPacket::decode(&bytes)?;
            self.verify_response_packet(&bytes, &packet)?;
            if packet.header.call_id != expected_call_id {
                return Err(Error::InvalidPdu("response call id does not match request"));
            }

            match packet.header.ptype {
                PduType::Response => {
                    if packet.header.pfc_flags & PFC_FIRST_FRAG != 0 {
                        saw_first = true;
                    }
                    if !saw_first {
                        return Err(Error::InvalidPdu("response is missing first fragment"));
                    }
                    let response = ResponsePdu::decode(packet.body())?;
                    response_stub.extend_from_slice(&response.stub_data);
                    if packet.header.pfc_flags & PFC_LAST_FRAG != 0 {
                        return Ok(response_stub);
                    }
                }
                PduType::Fault => {
                    let fault = FaultPdu::decode(packet.body())?;
                    #[cfg(feature = "tracing")]
                    tracing::debug!(
                        call_id = expected_call_id,
                        status = format_args!("0x{:08X}", fault.status),
                        "received MS-RPCE fault"
                    );
                    return Err(Error::Fault {
                        status: fault.status,
                    });
                }
                _ => return Err(Error::InvalidPdu("expected response or fault PDU")),
            }
        }
    }

    fn verify_response_packet(&mut self, _bytes: &[u8], _packet: &PduPacket) -> Result<()> {
        let Some(provider) = self.auth_provider.as_mut() else {
            return Ok(());
        };

        match provider.auth_level() {
            AuthLevel::None | AuthLevel::Connect => Ok(()),
            AuthLevel::PacketIntegrity => Err(Error::Auth(
                "RPC auth level PacketIntegrity is not supported in v1".to_string(),
            )),
            AuthLevel::PacketPrivacy => Err(Error::Auth(
                "RPC auth level PacketPrivacy is not supported in v1".to_string(),
            )),
        }
    }
}

fn authenticated_packet(
    ptype: PduType,
    call_id: u32,
    pfc_flags: u8,
    body: Vec<u8>,
    provider: &mut dyn AuthProvider,
    auth_value: Vec<u8>,
) -> Result<PduPacket> {
    if matches!(
        provider.auth_level(),
        AuthLevel::PacketIntegrity | AuthLevel::PacketPrivacy
    ) {
        return Err(Error::Auth(
            "RPC auth levels above Connect are not supported in v1".to_string(),
        ));
    }

    let header = PduHeader::new(ptype, pfc_flags, call_id);
    let trailer = security_trailer(provider, auth_padding_len(body.len()));
    Ok(PduPacket::with_security_trailer(
        header, body, trailer, auth_value,
    ))
}

fn security_trailer(provider: &dyn AuthProvider, auth_pad_length: u8) -> SecurityTrailer {
    SecurityTrailer {
        auth_type: provider.auth_type(),
        auth_level: provider.auth_level(),
        auth_pad_length,
        auth_reserved: 0,
        auth_context_id: provider.auth_context_id(),
    }
}

fn auth_pfc_flags(provider: &dyn AuthProvider) -> u8 {
    let _ = provider;
    PFC_FIRST_FRAG | PFC_LAST_FRAG
}

fn auth_padding_len(body_len: usize) -> u8 {
    ((4 - (body_len % 4)) % 4) as u8
}
