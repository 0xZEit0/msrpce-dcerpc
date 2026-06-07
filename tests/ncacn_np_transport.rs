use msrpce_dcerpc::{
    BindPdu, Error, NamedPipe, NcacnNpEndpoint, NcacnNpTransport, PduPacket, Result, RpcTransport,
};
use std::collections::VecDeque;

struct ChunkedPipe {
    reads: VecDeque<Vec<u8>>,
    writes: Vec<Vec<u8>>,
}

impl ChunkedPipe {
    fn new(reads: Vec<Vec<u8>>) -> Self {
        Self {
            reads: reads.into(),
            writes: Vec::new(),
        }
    }
}

impl NamedPipe for ChunkedPipe {
    fn read_exact(&mut self, buffer: &mut [u8]) -> Result<()> {
        let mut filled = 0;
        while filled < buffer.len() {
            let chunk = self
                .reads
                .front_mut()
                .ok_or_else(|| Error::Transport("pipe has no queued bytes".to_string()))?;
            let take = (buffer.len() - filled).min(chunk.len());
            buffer[filled..filled + take].copy_from_slice(&chunk[..take]);
            chunk.drain(..take);
            if chunk.is_empty() {
                self.reads.pop_front();
            }
            filled += take;
        }
        Ok(())
    }

    fn write_all(&mut self, bytes: &[u8]) -> Result<()> {
        self.writes.push(bytes.to_vec());
        Ok(())
    }
}

#[test]
fn endpoint_parses_unc_named_pipe_paths() {
    let endpoint = NcacnNpEndpoint::parse(r"\\dc01.example.test\pipe\lsarpc").unwrap();

    assert_eq!(endpoint.server, "dc01.example.test");
    assert_eq!(endpoint.pipe, "lsarpc");
    assert_eq!(endpoint.ipc_share(), r"\\dc01.example.test\IPC$");
    assert_eq!(endpoint.pipe_path(), r"\pipe\lsarpc");
}

#[test]
fn endpoint_rejects_non_pipe_unc_paths() {
    let err = NcacnNpEndpoint::parse(r"\\dc01.example.test\share\file").unwrap_err();

    assert_eq!(
        err,
        Error::Transport("ncacn_np endpoint must be \\\\server\\pipe\\name".to_string())
    );
}

#[test]
fn transport_writes_encoded_pdu_to_named_pipe() {
    let packet = PduPacket::from_bind(
        1,
        BindPdu {
            max_xmit_frag: 4280,
            max_recv_frag: 4280,
            assoc_group_id: 0,
            presentation_context_list: Vec::new(),
        },
    )
    .encode()
    .unwrap();
    let pipe = ChunkedPipe::new(Vec::new());
    let mut transport = NcacnNpTransport::new(pipe);

    transport.send_pdu(&packet).unwrap();

    assert_eq!(transport.pipe().writes, vec![packet]);
}

#[test]
fn transport_reads_one_complete_pdu_using_fragment_length() {
    let packet = PduPacket::from_bind(
        1,
        BindPdu {
            max_xmit_frag: 4280,
            max_recv_frag: 4280,
            assoc_group_id: 0,
            presentation_context_list: vec![1, 2, 3, 4],
        },
    )
    .encode()
    .unwrap();
    let first = packet[..5].to_vec();
    let second = packet[5..17].to_vec();
    let third = packet[17..].to_vec();
    let pipe = ChunkedPipe::new(vec![first, second, third]);
    let mut transport = NcacnNpTransport::new(pipe);

    assert_eq!(transport.recv_pdu().unwrap(), packet);
}

#[test]
fn std_io_named_pipe_adapter_uses_read_write_objects() {
    let packet = PduPacket::from_bind(
        1,
        BindPdu {
            max_xmit_frag: 4280,
            max_recv_frag: 4280,
            assoc_group_id: 0,
            presentation_context_list: Vec::new(),
        },
    )
    .encode()
    .unwrap();
    let cursor = std::io::Cursor::new(packet.clone());
    let mut adapter = msrpce_dcerpc::StdIoNamedPipe::new(cursor);

    let mut header = [0u8; 16];
    NamedPipe::read_exact(&mut adapter, &mut header).unwrap();
    assert_eq!(&header, &packet[..16]);

    NamedPipe::write_all(&mut adapter, b"abc").unwrap();
    let inner = adapter.into_inner().into_inner();
    assert_eq!(&inner[16..19], b"abc");
}
