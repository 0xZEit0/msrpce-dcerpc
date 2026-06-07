//! Generic MS-RPCE client building blocks.
//!
//! This crate owns the MS-RPCE client layer around NDR stubs: PDU metadata,
//! bind/call state, transport boundaries, and authentication token exchange.
//! Interface-specific clients such as LSARPC or SAMR should live in user code
//! or optional downstream crates.

pub mod auth;
pub mod bind;
pub mod client;
pub mod debug;
pub mod error;
pub mod ncacn_np;
pub mod pdu;
pub mod syntax;
pub mod transport;

#[cfg(feature = "ntlm-sspi")]
pub use auth::NtlmRpcAuthProvider;
pub use auth::{
    AuthLevel, AuthMechanism, Result as AuthResult, RpcAuthError, RpcAuthProvider as AuthProvider,
    RpcAuthProvider, RpcAuthType, RpcAuthType as AuthType,
};
#[cfg(feature = "gssapi")]
pub use auth::{GssapiKerberosRpcAuthProvider, GssapiRpcAuthProvider};
pub use bind::{
    AcceptedContext, BindAckPdu, BindNakPdu, PresentationContext, PresentationContextList,
    PresentationRejectReason, PresentationResult, PresentationResultCode,
};
pub use client::RpcClient;
pub use error::{Error, Result};
pub use ncacn_np::{NamedPipe, NcacnNpEndpoint, NcacnNpTransport, StdIoNamedPipe};
pub use pdu::{
    BindPdu, FaultPdu, PduHeader, PduPacket, PduType, RejectReason, RequestPdu, ResponsePdu,
    SecurityTrailer, PFC_CONC_MPX, PFC_DID_NOT_EXECUTE, PFC_FIRST_FRAG, PFC_LAST_FRAG, PFC_MAYBE,
    PFC_OBJECT_UUID, PFC_PENDING_CANCEL, PFC_RESERVED_1, PFC_SUPPORT_HEADER_SIGN,
};
pub use syntax::{
    InterfaceId, SyntaxId, TransferSyntax, BIND_TIME_FEATURE_KEEP_CONNECTION_ON_ORPHAN,
    BIND_TIME_FEATURE_SECURITY_CONTEXT_MULTIPLEXING,
};
pub use transport::RpcTransport;
