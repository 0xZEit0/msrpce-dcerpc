use std::collections::VecDeque;

use msrpce_dcerpc::{
    AuthLevel, AuthMechanism, AuthProvider, AuthResult, AuthType, BindAckPdu, BindPdu, Error,
    InterfaceId, PduHeader, PduPacket, PduType, PresentationContext, PresentationRejectReason,
    PresentationResult, PresentationResultCode, Result, RpcAuthError, RpcClient, RpcTransport,
    SecurityTrailer, TransferSyntax,
};
use uuid::uuid;

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

fn bind_ack_packet(call_id: u32) -> Vec<u8> {
    bind_ack_packet_with_results(
        call_id,
        vec![PresentationResult {
            result: PresentationResultCode::Acceptance,
            reason: PresentationRejectReason::ReasonNotSpecified,
            transfer_syntax: TransferSyntax::Ndr32.syntax_id(),
        }],
    )
}

fn bind_ack_packet_with_results(call_id: u32, results: Vec<PresentationResult>) -> Vec<u8> {
    let ack = BindAckPdu {
        max_xmit_frag: 4280,
        max_recv_frag: 4280,
        assoc_group_id: 1,
        secondary_addr: Vec::new(),
        results,
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
    .unwrap()
}

fn bind_ack_packet_with_auth(call_id: u32, auth_value: Vec<u8>) -> Vec<u8> {
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

    PduPacket::with_security_trailer(
        PduHeader::new(PduType::BindAck, 3, call_id),
        body,
        SecurityTrailer {
            auth_type: AuthType::WinNt,
            auth_level: AuthLevel::Connect,
            auth_pad_length: 0,
            auth_reserved: 0,
            auth_context_id: 11,
        },
        auth_value,
    )
    .encode()
    .unwrap()
}

struct ConnectAuthProvider {
    init_target: Option<String>,
    stepped_challenge: Option<Vec<u8>>,
    fail_init: bool,
    fail_step: bool,
}

impl ConnectAuthProvider {
    fn new() -> Self {
        Self {
            init_target: None,
            stepped_challenge: None,
            fail_init: false,
            fail_step: false,
        }
    }

    fn failing_init() -> Self {
        Self {
            fail_init: true,
            ..Self::new()
        }
    }

    fn failing_step() -> Self {
        Self {
            fail_step: true,
            ..Self::new()
        }
    }
}

struct IntegrityConnectAuthProvider(ConnectAuthProvider);

impl IntegrityConnectAuthProvider {
    fn new() -> Self {
        Self(ConnectAuthProvider::new())
    }
}

impl AuthProvider for ConnectAuthProvider {
    fn mechanism(&self) -> AuthMechanism {
        AuthMechanism::Ntlm
    }

    fn auth_level(&self) -> AuthLevel {
        AuthLevel::Connect
    }

    fn init_context(&mut self, target: &str) -> AuthResult<Vec<u8>> {
        if self.fail_init {
            return Err(RpcAuthError::Provider("init failed".to_string()));
        }
        self.init_target = Some(target.to_string());
        Ok(vec![0xAA, 0xBB])
    }

    fn step(&mut self, challenge: &[u8]) -> AuthResult<Vec<u8>> {
        if self.fail_step {
            return Err(RpcAuthError::Provider("step failed".to_string()));
        }
        self.stepped_challenge = Some(challenge.to_vec());
        Ok(vec![0xCC, 0xDD, 0xEE])
    }

    fn auth_context_id(&self) -> u32 {
        11
    }
}

impl AuthProvider for IntegrityConnectAuthProvider {
    fn mechanism(&self) -> AuthMechanism {
        AuthMechanism::Kerberos
    }

    fn auth_level(&self) -> AuthLevel {
        AuthLevel::PacketIntegrity
    }

    fn init_context(&mut self, target: &str) -> AuthResult<Vec<u8>> {
        self.0.init_context(target)
    }

    fn step(&mut self, challenge: &[u8]) -> AuthResult<Vec<u8>> {
        self.0.step(challenge)
    }

    fn auth_context_id(&self) -> u32 {
        11
    }
}

#[test]
fn bind_sends_bind_pdu_and_returns_bound_client() {
    let interface = InterfaceId::new(uuid!("367abb81-9844-35f1-ad32-98f038001003"), 2, 0);
    let transport = MemoryTransport::new(vec![bind_ack_packet(1)]);

    let client = RpcClient::bind(transport, interface).unwrap();

    assert_eq!(client.transport().sent.len(), 1);
    let sent = PduPacket::decode(&client.transport().sent[0]).unwrap();
    assert_eq!(sent.header.ptype, PduType::Bind);
    assert_eq!(sent.header.call_id, 1);

    let bind = BindPdu::decode(sent.body()).unwrap();
    let contexts = bind.presentation_context_list().unwrap();
    assert_eq!(
        contexts.contexts,
        vec![PresentationContext::new(
            0,
            interface.syntax_id(),
            vec![TransferSyntax::Ndr32]
        )]
    );
}

#[test]
fn bind_with_contexts_sends_custom_presentation_contexts() {
    let interface = InterfaceId::new(uuid!("367abb81-9844-35f1-ad32-98f038001003"), 2, 0);
    let custom_contexts = vec![
        PresentationContext::new(0, interface.syntax_id(), vec![TransferSyntax::Ndr64]),
        PresentationContext::new(2, interface.syntax_id(), vec![TransferSyntax::Ndr32]),
    ];
    let transport = MemoryTransport::new(vec![bind_ack_packet_with_results(
        1,
        vec![
            PresentationResult {
                result: PresentationResultCode::ProviderRejection,
                reason: PresentationRejectReason::ProposedTransferSyntaxNotSupported,
                transfer_syntax: TransferSyntax::Ndr64.syntax_id(),
            },
            PresentationResult {
                result: PresentationResultCode::Acceptance,
                reason: PresentationRejectReason::ReasonNotSpecified,
                transfer_syntax: TransferSyntax::Ndr32.syntax_id(),
            },
        ],
    )]);

    let client = RpcClient::bind_with_contexts(transport, custom_contexts.clone()).unwrap();

    let sent = PduPacket::decode(&client.transport().sent[0]).unwrap();
    let bind = BindPdu::decode(sent.body()).unwrap();
    assert_eq!(
        bind.presentation_context_list().unwrap().contexts,
        custom_contexts
    );
}

#[test]
fn bind_with_contexts_rejects_empty_context_list() {
    let transport = MemoryTransport::new(vec![]);

    let err = match RpcClient::bind_with_contexts(transport, vec![]) {
        Ok(_) => panic!("empty context list must be rejected"),
        Err(err) => err,
    };

    assert_eq!(
        err,
        Error::InvalidPdu("bind requires at least one presentation context")
    );
}

#[test]
fn bind_with_auth_provider_sends_bind_token_and_auth3_response() {
    let interface = InterfaceId::new(uuid!("367abb81-9844-35f1-ad32-98f038001003"), 2, 0);
    let proposed = vec![PresentationContext::new(
        0,
        interface.syntax_id(),
        vec![TransferSyntax::Ndr32],
    )];
    let transport = MemoryTransport::new(vec![bind_ack_packet_with_auth(1, vec![0x10, 0x20])]);

    let client = RpcClient::bind_with_auth_provider(
        transport,
        proposed,
        "rpc/test-host",
        ConnectAuthProvider::new(),
    )
    .unwrap();

    assert_eq!(client.transport().sent.len(), 2);

    let bind = PduPacket::decode(&client.transport().sent[0]).unwrap();
    assert_eq!(bind.header.ptype, PduType::Bind);
    assert_eq!(bind.auth_value(), &[0xAA, 0xBB]);
    assert_eq!(
        bind.security_trailer(),
        Some(&SecurityTrailer {
            auth_type: AuthType::WinNt,
            auth_level: AuthLevel::Connect,
            auth_pad_length: 0,
            auth_reserved: 0,
            auth_context_id: 11,
        })
    );

    let auth3 = PduPacket::decode(&client.transport().sent[1]).unwrap();
    assert_eq!(auth3.header.ptype, PduType::Auth3);
    assert_eq!(auth3.header.call_id, 1);
    assert_eq!(auth3.body(), b"    ");
    assert_eq!(auth3.auth_value(), &[0xCC, 0xDD, 0xEE]);
    assert_eq!(
        auth3.security_trailer(),
        Some(&SecurityTrailer {
            auth_type: AuthType::WinNt,
            auth_level: AuthLevel::Connect,
            auth_pad_length: 0,
            auth_reserved: 0,
            auth_context_id: 11,
        })
    );
}

#[test]
fn bind_with_packet_integrity_is_rejected_for_v1_without_sending() {
    let interface = InterfaceId::new(uuid!("367abb81-9844-35f1-ad32-98f038001003"), 2, 0);
    let proposed = vec![PresentationContext::new(
        0,
        interface.syntax_id(),
        vec![TransferSyntax::Ndr32],
    )];
    let transport = MemoryTransport::new(vec![bind_ack_packet_with_auth(1, vec![0x10, 0x20])]);

    let err = match RpcClient::bind_with_auth_provider(
        transport,
        proposed,
        "rpc/test-host",
        IntegrityConnectAuthProvider::new(),
    ) {
        Ok(_) => panic!("PacketIntegrity bind should be rejected in v1"),
        Err(err) => err,
    };

    assert_eq!(
        err,
        Error::Auth("RPC auth levels above Connect are not supported in v1".to_string())
    );
}

#[test]
fn bind_with_auth_provider_propagates_init_failure_without_sending() {
    let interface = InterfaceId::new(uuid!("367abb81-9844-35f1-ad32-98f038001003"), 2, 0);
    let proposed = vec![PresentationContext::new(
        0,
        interface.syntax_id(),
        vec![TransferSyntax::Ndr32],
    )];
    let transport = MemoryTransport::new(vec![bind_ack_packet(1)]);

    let err = match RpcClient::bind_with_auth_provider(
        transport,
        proposed,
        "rpc/test-host",
        ConnectAuthProvider::failing_init(),
    ) {
        Ok(_) => panic!("bind init failure must be propagated"),
        Err(err) => err,
    };

    assert_eq!(err, Error::Auth("init failed".to_string()));
}

#[test]
fn bind_with_auth_provider_propagates_challenge_step_failure() {
    let interface = InterfaceId::new(uuid!("367abb81-9844-35f1-ad32-98f038001003"), 2, 0);
    let proposed = vec![PresentationContext::new(
        0,
        interface.syntax_id(),
        vec![TransferSyntax::Ndr32],
    )];
    let transport = MemoryTransport::new(vec![bind_ack_packet_with_auth(1, vec![0x10, 0x20])]);

    let err = match RpcClient::bind_with_auth_provider(
        transport,
        proposed,
        "rpc/test-host",
        ConnectAuthProvider::failing_step(),
    ) {
        Ok(_) => panic!("bind challenge step failure must be propagated"),
        Err(err) => err,
    };

    assert_eq!(err, Error::Auth("step failed".to_string()));
}
