use std::collections::VecDeque;

use msrpce_dcerpc::{
    AuthLevel, AuthMechanism, AuthProvider, AuthResult, Error, FaultPdu, PduPacket, PduType,
    RequestPdu, ResponsePdu, Result, RpcClient, RpcTransport, PFC_FIRST_FRAG, PFC_LAST_FRAG,
};
use msrpce_ndr::Ndr;

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

struct UnsupportedAuthProvider {
    auth_level: AuthLevel,
}

impl AuthProvider for UnsupportedAuthProvider {
    fn mechanism(&self) -> AuthMechanism {
        AuthMechanism::Kerberos
    }

    fn auth_level(&self) -> AuthLevel {
        self.auth_level
    }

    fn init_context(&mut self, _target: &str) -> AuthResult<Vec<u8>> {
        Ok(Vec::new())
    }

    fn step(&mut self, _challenge: &[u8]) -> AuthResult<Vec<u8>> {
        Ok(Vec::new())
    }
}

#[test]
fn call_raw_sends_request_and_returns_response_stub() {
    let response = PduPacket::from_response(
        1,
        ResponsePdu {
            alloc_hint: 3,
            ctx_id: 4,
            cancel_count: 0,
            stub_data: vec![0xAA, 0xBB, 0xCC],
        },
    )
    .encode()
    .unwrap();
    let transport = MemoryTransport::new(vec![response]);
    let mut client = RpcClient::new_bound(transport, 4);

    let stub = client.call_raw(9, &[1, 2, 3, 4]).unwrap();

    assert_eq!(stub, vec![0xAA, 0xBB, 0xCC]);
    assert_eq!(client.transport().sent.len(), 1);
    let sent = PduPacket::decode(&client.transport().sent[0]).unwrap();
    assert_eq!(sent.header.ptype, PduType::Request);
    let request = RequestPdu::decode(sent.body(), false).unwrap();
    assert_eq!(request.ctx_id, 4);
    assert_eq!(request.opnum, 9);
    assert_eq!(request.alloc_hint, 4);
    assert_eq!(request.stub_data, vec![1, 2, 3, 4]);
}

#[test]
fn call_serializes_and_deserializes_ndr_values() {
    let response = PduPacket::from_response(
        1,
        ResponsePdu {
            alloc_hint: 4,
            ctx_id: 4,
            cancel_count: 0,
            stub_data: Ndr::new().serialize(&0xAABB_CCDDu32).unwrap(),
        },
    )
    .encode()
    .unwrap();
    let transport = MemoryTransport::new(vec![response]);
    let mut client = RpcClient::new_bound(transport, 4);

    let value: u32 = client.call(9, &0x1122_3344u32).unwrap();

    assert_eq!(value, 0xAABB_CCDD);
    let sent = PduPacket::decode(&client.transport().sent[0]).unwrap();
    let request = RequestPdu::decode(sent.body(), false).unwrap();
    assert_eq!(
        request.stub_data,
        Ndr::new().serialize(&0x1122_3344u32).unwrap()
    );
}

#[test]
fn call_raw_maps_fault_pdu_to_error() {
    let fault = PduPacket::from_fault(
        1,
        FaultPdu {
            alloc_hint: 0,
            ctx_id: 4,
            cancel_count: 0,
            status: 0x1C00_0001,
            stub_data: Vec::new(),
        },
    )
    .encode()
    .unwrap();
    let transport = MemoryTransport::new(vec![fault]);
    let mut client = RpcClient::new_bound(transport, 4);

    let err = client.call_raw(9, &[1, 2, 3, 4]).unwrap_err();

    assert_eq!(
        err,
        Error::Fault {
            status: 0x1C00_0001
        }
    );
}

#[test]
fn rpc_fault_errors_display_common_status_names() {
    let err = Error::Fault { status: 5 };

    assert_eq!(
        err.to_string(),
        "RPC fault status: ERROR_ACCESS_DENIED (0x00000005)"
    );
}

#[test]
fn rpc_fault_errors_display_expanded_common_status_names() {
    let cases = [
        (0x1C01_0006, "nca_s_op_rng_error"),
        (0x1C01_0002, "nca_s_unk_if"),
        (0x1C00_0003, "nca_s_fault_ndr"),
        (0x1C00_0002, "nca_s_fault_access_denied"),
        (0x1C00_0009, "nca_s_fault_context_mismatch"),
        (0x0000_06F7, "ERROR_BAD_STUB_DATA"),
    ];

    for (status, name) in cases {
        assert_eq!(
            Error::Fault { status }.to_string(),
            format!("RPC fault status: {name} (0x{status:08X})")
        );
    }
}

#[test]
fn debug_helpers_preview_bytes_without_dumping_redacted_content() {
    assert_eq!(
        msrpce_dcerpc::debug::hex_preview(&[0xAA, 0xBB, 0xCC], 8),
        "AA BB CC"
    );
    assert_eq!(
        msrpce_dcerpc::debug::hex_preview(&[0xAA, 0xBB, 0xCC, 0xDD], 2),
        "AA BB ... (+2 bytes)"
    );
    assert_eq!(
        msrpce_dcerpc::debug::redacted_bytes("auth_value", &[0xDE, 0xAD, 0xBE, 0xEF]),
        "auth_value=<redacted: 4 bytes>"
    );
    assert!(
        !msrpce_dcerpc::debug::redacted_bytes("auth_value", &[0xDE, 0xAD, 0xBE, 0xEF])
            .contains("DE")
    );
}

#[test]
fn call_raw_fragments_request_and_reassembles_response() {
    let first_response = PduPacket::from_response_with_flags(
        1,
        PFC_FIRST_FRAG,
        ResponsePdu {
            alloc_hint: 7,
            ctx_id: 4,
            cancel_count: 0,
            stub_data: vec![0xA1, 0xA2, 0xA3],
        },
    )
    .encode()
    .unwrap();
    let last_response = PduPacket::from_response_with_flags(
        1,
        PFC_LAST_FRAG,
        ResponsePdu {
            alloc_hint: 7,
            ctx_id: 4,
            cancel_count: 0,
            stub_data: vec![0xA4, 0xA5, 0xA6, 0xA7],
        },
    )
    .encode()
    .unwrap();
    let transport = MemoryTransport::new(vec![first_response, last_response]);
    let mut client = RpcClient::new_bound(transport, 4).with_max_xmit_frag(30);

    let stub = client
        .call_raw(9, &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10])
        .unwrap();

    assert_eq!(stub, vec![0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7]);
    assert_eq!(client.transport().sent.len(), 2);

    let first = PduPacket::decode(&client.transport().sent[0]).unwrap();
    assert_eq!(first.header.pfc_flags, PFC_FIRST_FRAG);
    let first_request = RequestPdu::decode(first.body(), false).unwrap();
    assert_eq!(first_request.alloc_hint, 10);
    assert_eq!(first_request.stub_data, vec![1, 2, 3, 4, 5, 6]);

    let last = PduPacket::decode(&client.transport().sent[1]).unwrap();
    assert_eq!(last.header.pfc_flags, PFC_LAST_FRAG);
    let last_request = RequestPdu::decode(last.body(), false).unwrap();
    assert_eq!(last_request.alloc_hint, 10);
    assert_eq!(last_request.stub_data, vec![7, 8, 9, 10]);
}

#[test]
fn call_raw_reassembles_large_fragmented_response() {
    let first_chunk = vec![0xA1; 5000];
    let second_chunk = vec![0xB2; 7000];
    let first_response = PduPacket::from_response_with_flags(
        1,
        PFC_FIRST_FRAG,
        ResponsePdu {
            alloc_hint: 12_000,
            ctx_id: 4,
            cancel_count: 0,
            stub_data: first_chunk.clone(),
        },
    )
    .encode()
    .unwrap();
    let last_response = PduPacket::from_response_with_flags(
        1,
        PFC_LAST_FRAG,
        ResponsePdu {
            alloc_hint: 12_000,
            ctx_id: 4,
            cancel_count: 0,
            stub_data: second_chunk.clone(),
        },
    )
    .encode()
    .unwrap();
    let transport = MemoryTransport::new(vec![first_response, last_response]);
    let mut client = RpcClient::new_bound(transport, 4);

    let stub = client.call_raw(9, &[1, 2, 3]).unwrap();

    assert_eq!(stub.len(), 12_000);
    assert_eq!(&stub[..5000], &first_chunk);
    assert_eq!(&stub[5000..], &second_chunk);
}

#[test]
fn call_raw_rejects_packet_integrity_for_v1_without_sending() {
    let transport = MemoryTransport::new(Vec::new());
    let mut client = RpcClient::new_bound_with_auth(
        transport,
        4,
        UnsupportedAuthProvider {
            auth_level: AuthLevel::PacketIntegrity,
        },
    );

    let err = client.call_raw(9, &[1, 2, 3, 4]).unwrap_err();

    assert_eq!(
        err,
        Error::Auth("RPC auth level PacketIntegrity is not supported in v1".to_string())
    );
    assert!(client.transport().sent.is_empty());
}

#[test]
fn call_raw_rejects_packet_privacy_for_v1_without_sending() {
    let transport = MemoryTransport::new(Vec::new());
    let mut client = RpcClient::new_bound_with_auth(
        transport,
        4,
        UnsupportedAuthProvider {
            auth_level: AuthLevel::PacketPrivacy,
        },
    );

    let err = client.call_raw(9, &[1, 2, 3, 4]).unwrap_err();

    assert_eq!(
        err,
        Error::Auth("RPC auth level PacketPrivacy is not supported in v1".to_string())
    );
    assert!(client.transport().sent.is_empty());
}
