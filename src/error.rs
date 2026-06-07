use std::fmt;

/// Crate-local result type.
pub type Result<T> = std::result::Result<T, Error>;

/// Errors returned by the MS-RPCE client layers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    InvalidPduType(u8),
    InvalidPdu(&'static str),
    BindRejected(crate::RejectReason),
    PresentationContextRejected {
        context_id: u16,
        result: crate::PresentationResultCode,
        reason: crate::PresentationRejectReason,
    },
    Fault {
        status: u32,
    },
    Transport(String),
    Auth(String),
    Ndr(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPduType(value) => write!(f, "invalid MS-RPCE PDU type: 0x{value:02X}"),
            Self::InvalidPdu(message) => write!(f, "invalid MS-RPCE PDU: {message}"),
            Self::BindRejected(reason) => write!(f, "bind rejected: {reason:?}"),
            Self::PresentationContextRejected {
                context_id,
                result,
                reason,
            } => write!(
                f,
                "presentation context {context_id} rejected: {result:?} ({reason:?})"
            ),
            Self::Fault { status } => {
                if let Some(name) = rpc_fault_status_name(*status) {
                    write!(f, "RPC fault status: {name} (0x{status:08X})")
                } else {
                    write!(f, "RPC fault status: 0x{status:08X}")
                }
            }
            Self::Transport(message) => write!(f, "transport error: {message}"),
            Self::Auth(message) => write!(f, "authentication error: {message}"),
            Self::Ndr(message) => write!(f, "NDR error: {message}"),
        }
    }
}

impl std::error::Error for Error {}

pub fn rpc_fault_status_name(status: u32) -> Option<&'static str> {
    match status {
        0x0000_0005 => Some("ERROR_ACCESS_DENIED"),
        0x0000_06F7 => Some("ERROR_BAD_STUB_DATA"),
        0x1C00_0001 => Some("nca_s_fault_other"),
        0x1C00_0002 => Some("nca_s_fault_access_denied"),
        0x1C00_0003 => Some("nca_s_fault_ndr"),
        0x1C00_0006 => Some("nca_s_fault_invalid_tag"),
        0x1C00_0009 => Some("nca_s_fault_context_mismatch"),
        0x1C00_000B => Some("nca_s_fault_cancel"),
        0x1C00_000D => Some("nca_s_fault_remote_no_memory"),
        0x1C00_000F => Some("nca_s_fault_unspec"),
        0x1C01_0002 => Some("nca_s_unk_if"),
        0x1C01_0003 => Some("nca_s_unsupported_type"),
        0x1C01_0006 => Some("nca_s_op_rng_error"),
        _ => None,
    }
}

impl From<msrpce_ndr::NdrError> for Error {
    fn from(value: msrpce_ndr::NdrError) -> Self {
        Self::Ndr(value.to_string())
    }
}

impl From<crate::auth::RpcAuthError> for Error {
    fn from(value: crate::auth::RpcAuthError) -> Self {
        match value {
            crate::auth::RpcAuthError::Unsupported(message) => Self::Auth(message.to_string()),
            crate::auth::RpcAuthError::Provider(message) => Self::Auth(message),
        }
    }
}
