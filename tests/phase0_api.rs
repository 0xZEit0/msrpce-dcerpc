use std::collections::VecDeque;

use msrpce_dcerpc::{
    AuthLevel, AuthMechanism, AuthProvider, AuthResult, AuthType, InterfaceId, PduHeader, PduType,
    Result, RpcTransport, TransferSyntax, PFC_FIRST_FRAG, PFC_LAST_FRAG,
};
use msrpce_ndr::Ndr;
use uuid::Uuid;

struct MemoryTransport {
    incoming: VecDeque<Vec<u8>>,
    sent: Vec<Vec<u8>>,
}

impl RpcTransport for MemoryTransport {
    fn send_pdu(&mut self, bytes: &[u8]) -> Result<()> {
        self.sent.push(bytes.to_vec());
        Ok(())
    }

    fn recv_pdu(&mut self) -> Result<Vec<u8>> {
        self.incoming
            .pop_front()
            .ok_or_else(|| msrpce_dcerpc::Error::Transport("no queued PDU available".to_string()))
    }
}

#[test]
fn phase0_exposes_core_rpc_types() {
    let header = PduHeader::new(PduType::Bind, PFC_FIRST_FRAG | PFC_LAST_FRAG, 7);

    assert_eq!(header.rpc_vers, 5);
    assert_eq!(header.rpc_vers_minor, 0);
    assert_eq!(header.ptype, PduType::Bind);
    assert_eq!(header.pfc_flags, PFC_FIRST_FRAG | PFC_LAST_FRAG);
    assert_eq!(header.packed_drep, [0x10, 0x00, 0x00, 0x00]);
    assert_eq!(header.auth_length, 0);
    assert_eq!(header.call_id, 7);
}

#[test]
fn phase0_exposes_generic_interface_identity() {
    let uuid = Uuid::nil();
    let interface = InterfaceId::new(uuid, 1, 0);

    assert_eq!(interface.uuid, uuid);
    assert_eq!(interface.major_version, 1);
    assert_eq!(interface.minor_version, 0);
    assert_eq!(interface.version_u32(), 0x0000_0001);
}

#[test]
fn phase0_transport_trait_can_be_implemented_by_callers() {
    let mut transport = MemoryTransport {
        incoming: VecDeque::from([vec![0xAA, 0xBB]]),
        sent: Vec::new(),
    };

    transport.send_pdu(&[1, 2, 3]).unwrap();
    assert_eq!(transport.sent, vec![vec![1, 2, 3]]);
    assert_eq!(transport.recv_pdu().unwrap(), vec![0xAA, 0xBB]);
}

#[test]
fn phase0_depends_on_msrpce_ndr_for_stub_payloads() {
    let ndr = Ndr::new();
    let bytes = ndr.serialize(&0x1234_5678u32).unwrap();

    assert_eq!(bytes, vec![0x78, 0x56, 0x34, 0x12]);
    assert_eq!(TransferSyntax::Ndr32.name(), "NDR32");
    assert_eq!(AuthLevel::None as u8, 0);
}

struct Phase0AuthProvider;

impl AuthProvider for Phase0AuthProvider {
    fn mechanism(&self) -> AuthMechanism {
        AuthMechanism::Kerberos
    }

    fn auth_level(&self) -> AuthLevel {
        AuthLevel::PacketIntegrity
    }

    fn init_context(&mut self, _target: &str) -> AuthResult<Vec<u8>> {
        Ok(vec![0xAA])
    }

    fn step(&mut self, _challenge: &[u8]) -> AuthResult<Vec<u8>> {
        Ok(vec![0xBB])
    }
}

#[test]
fn auth_provider_exposes_rpc_auth_trailer_metadata_defaults() {
    let provider = Phase0AuthProvider;

    assert_eq!(provider.auth_type(), AuthType::GssKerberos);
    assert_eq!(provider.auth_context_id(), 0);
}
