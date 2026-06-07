use crate::Result;

/// Transport boundary used by the RPC state machine.
///
/// `ncacn_np` will be the first concrete implementation. The core client
/// should only depend on this trait, not on SMB-specific details.
pub trait RpcTransport {
    fn send_pdu(&mut self, bytes: &[u8]) -> Result<()>;
    fn recv_pdu(&mut self) -> Result<Vec<u8>>;
}
