use std::collections::VecDeque;

use msrpce_dcerpc::{
    BindAckPdu, Error, InterfaceId, PduHeader, PduPacket, PduType, PresentationRejectReason,
    PresentationResult, PresentationResultCode, ResponsePdu, Result, RpcClient, RpcTransport,
    TransferSyntax,
};
use uuid::Uuid;

struct MemoryTransport {
    incoming: VecDeque<Vec<u8>>,
    sent: Vec<Vec<u8>>,
}

impl MemoryTransport {
    fn new(incoming: Vec<Vec<u8>>) -> Self {
        Self {
            incoming: incoming.into(),
            sent: Vec::new(),
        }
    }
}

impl RpcTransport for MemoryTransport {
    fn send_pdu(&mut self, bytes: &[u8]) -> Result<()> {
        self.sent.push(bytes.to_vec());
        Ok(())
    }

    fn recv_pdu(&mut self) -> Result<Vec<u8>> {
        self.incoming
            .pop_front()
            .ok_or_else(|| Error::Transport("no queued PDU available".to_string()))
    }
}

fn main() -> Result<()> {
    let interface = InterfaceId::new(
        Uuid::from_u128(0x11111111_2222_3333_4444_555555555555),
        1,
        0,
    );
    let bind_ack = bind_ack_packet(1);
    let response = PduPacket::from_response(
        2,
        ResponsePdu {
            alloc_hint: 3,
            ctx_id: 0,
            cancel_count: 0,
            stub_data: vec![0xAA, 0xBB, 0xCC],
        },
    )
    .encode()?;

    let transport = MemoryTransport::new(vec![bind_ack, response]);
    let mut client = RpcClient::bind(transport, interface)?;
    let response_stub = client.call_raw(0, &[0x01, 0x02, 0x03])?;

    assert_eq!(response_stub, vec![0xAA, 0xBB, 0xCC]);
    assert_eq!(client.transport().sent.len(), 2);
    Ok(())
}

fn bind_ack_packet(call_id: u32) -> Vec<u8> {
    let ack = BindAckPdu {
        max_xmit_frag: 4280,
        max_recv_frag: 4280,
        assoc_group_id: 1,
        secondary_addr: Vec::new(),
        results: vec![PresentationResult {
            result: PresentationResultCode::Acceptance,
            reason: PresentationRejectReason::ReasonNotSpecified,
            transfer_syntax: TransferSyntax::Ndr32.syntax_id(),
        }],
    };

    let mut body = Vec::new();
    body.extend_from_slice(&ack.max_xmit_frag.to_le_bytes());
    body.extend_from_slice(&ack.max_recv_frag.to_le_bytes());
    body.extend_from_slice(&ack.assoc_group_id.to_le_bytes());
    body.extend_from_slice(&(ack.secondary_addr.len() as u16).to_le_bytes());
    body.extend_from_slice(&ack.secondary_addr);
    while !body.len().is_multiple_of(4) {
        body.push(0);
    }
    body.push(ack.results.len() as u8);
    body.push(0);
    body.extend_from_slice(&0u16.to_le_bytes());
    for result in &ack.results {
        body.extend_from_slice(&(result.result as u16).to_le_bytes());
        body.extend_from_slice(&(result.reason as u16).to_le_bytes());
        body.extend_from_slice(&result.transfer_syntax.encode());
    }

    PduPacket::new(
        PduHeader::new(PduType::BindAck, 3, call_id),
        body,
        Vec::new(),
    )
    .encode()
    .expect("in-memory bind ack should encode")
}
