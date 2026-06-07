use std::io::{Read, Write};

use crate::error::{Error, Result};
use crate::pdu::{PduHeader, COMMON_HEADER_LEN};
use crate::transport::RpcTransport;

/// Parsed `ncacn_np` endpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NcacnNpEndpoint {
    pub server: String,
    pub pipe: String,
}

impl NcacnNpEndpoint {
    pub fn parse(value: &str) -> Result<Self> {
        let rest = value
            .strip_prefix(r"\\")
            .ok_or_else(Self::invalid_endpoint)?;
        let (server, path) = rest.split_once('\\').ok_or_else(Self::invalid_endpoint)?;
        let pipe = path
            .strip_prefix(r"pipe\")
            .ok_or_else(Self::invalid_endpoint)?;

        if server.is_empty() || pipe.is_empty() || pipe.contains('\\') {
            return Err(Self::invalid_endpoint());
        }

        Ok(Self {
            server: server.to_string(),
            pipe: pipe.to_string(),
        })
    }

    pub fn ipc_share(&self) -> String {
        format!(r"\\{}\IPC$", self.server)
    }

    pub fn pipe_path(&self) -> String {
        format!(r"\pipe\{}", self.pipe)
    }

    fn invalid_endpoint() -> Error {
        Error::Transport(r"ncacn_np endpoint must be \\server\pipe\name".to_string())
    }
}

/// Open named-pipe handle used by `ncacn_np`.
///
/// A real SMB implementation should handle session setup, `IPC$` tree connect,
/// opening `\pipe\<name>`, auth/signing, and then expose the opened pipe through
/// this trait.
pub trait NamedPipe {
    fn read_exact(&mut self, buffer: &mut [u8]) -> Result<()>;
    fn write_all(&mut self, bytes: &[u8]) -> Result<()>;
}

/// Adapter for already-opened `Read + Write` pipe-like objects.
pub struct StdIoNamedPipe<T> {
    inner: T,
}

impl<T> StdIoNamedPipe<T> {
    pub fn new(inner: T) -> Self {
        Self { inner }
    }

    pub fn into_inner(self) -> T {
        self.inner
    }
}

impl<T: Read + Write> NamedPipe for StdIoNamedPipe<T> {
    fn read_exact(&mut self, buffer: &mut [u8]) -> Result<()> {
        Read::read_exact(&mut self.inner, buffer)
            .map_err(|err| Error::Transport(format!("named pipe read failed: {err}")))
    }

    fn write_all(&mut self, bytes: &[u8]) -> Result<()> {
        Write::write_all(&mut self.inner, bytes)
            .map_err(|err| Error::Transport(format!("named pipe write failed: {err}")))?;
        Write::flush(&mut self.inner)
            .map_err(|err| Error::Transport(format!("named pipe flush failed: {err}")))
    }
}

/// RPC transport over an already-opened SMB named pipe.
pub struct NcacnNpTransport<P> {
    pipe: P,
}

impl<P> NcacnNpTransport<P> {
    pub fn new(pipe: P) -> Self {
        Self { pipe }
    }

    pub fn pipe(&self) -> &P {
        &self.pipe
    }

    pub fn pipe_mut(&mut self) -> &mut P {
        &mut self.pipe
    }

    pub fn into_pipe(self) -> P {
        self.pipe
    }
}

impl<P: NamedPipe> RpcTransport for NcacnNpTransport<P> {
    fn send_pdu(&mut self, bytes: &[u8]) -> Result<()> {
        if std::env::var_os("MSRPCE_DEBUG_RPC_WIRE").is_some() {
            eprintln!(
                "MSRPCE RPC SEND len={} {}",
                bytes.len(),
                crate::debug::hex_preview(bytes, bytes.len())
            );
        }
        self.pipe.write_all(bytes)
    }

    fn recv_pdu(&mut self) -> Result<Vec<u8>> {
        let mut header_bytes = [0u8; COMMON_HEADER_LEN as usize];
        self.pipe.read_exact(&mut header_bytes)?;
        let header = PduHeader::decode(&header_bytes)?;
        let frag_length = usize::from(header.frag_length);

        if frag_length < COMMON_HEADER_LEN as usize {
            return Err(Error::InvalidPdu(
                "fragment length is smaller than common header",
            ));
        }

        let mut bytes = Vec::with_capacity(frag_length);
        bytes.extend_from_slice(&header_bytes);
        bytes.resize(frag_length, 0);
        self.pipe
            .read_exact(&mut bytes[COMMON_HEADER_LEN as usize..])?;
        if std::env::var_os("MSRPCE_DEBUG_RPC_WIRE").is_some() {
            eprintln!(
                "MSRPCE RPC RECV len={} {}",
                bytes.len(),
                crate::debug::hex_preview(&bytes, bytes.len())
            );
        }
        Ok(bytes)
    }
}
