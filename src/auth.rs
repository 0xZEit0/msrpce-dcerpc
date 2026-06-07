//! Authentication provider contracts for MS-RPCE clients.
//!
//! This module owns DCE/RPC authentication state and provider boundaries.

use std::fmt;

#[cfg(feature = "gssapi")]
use libgssapi_sys as gss;
#[cfg(feature = "ntlm-sspi")]
use sspi::{
    AuthIdentity, BufferType, ClientRequestFlags, CredentialUse, DataRepresentation, Ntlm,
    SecurityBuffer, SecurityStatus, Sspi, SspiImpl, Username,
};

pub type Result<T> = std::result::Result<T, RpcAuthError>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RpcAuthError {
    Unsupported(&'static str),
    Provider(String),
}

impl fmt::Display for RpcAuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unsupported(message) => write!(f, "unsupported RPC authentication: {message}"),
            Self::Provider(message) => write!(f, "RPC authentication provider error: {message}"),
        }
    }
}

impl std::error::Error for RpcAuthError {}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AuthLevel {
    None = 0,
    Connect = 2,
    PacketIntegrity = 5,
    PacketPrivacy = 6,
}

impl TryFrom<u8> for AuthLevel {
    type Error = RpcAuthError;

    fn try_from(value: u8) -> Result<Self> {
        match value {
            0 => Ok(Self::None),
            2 => Ok(Self::Connect),
            5 => Ok(Self::PacketIntegrity),
            6 => Ok(Self::PacketPrivacy),
            _ => Err(RpcAuthError::Provider(format!(
                "unsupported RPC auth level: 0x{value:02X}"
            ))),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AuthMechanism {
    None,
    Kerberos,
    Ntlm,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RpcAuthType {
    None = 0,
    GssNegotiate = 9,
    WinNt = 10,
    GssKerberos = 16,
}

impl TryFrom<u8> for RpcAuthType {
    type Error = RpcAuthError;

    fn try_from(value: u8) -> Result<Self> {
        match value {
            0 => Ok(Self::None),
            9 => Ok(Self::GssNegotiate),
            10 => Ok(Self::WinNt),
            16 => Ok(Self::GssKerberos),
            _ => Err(RpcAuthError::Provider(format!(
                "unsupported RPC auth type: 0x{value:02X}"
            ))),
        }
    }
}

/// DCE/RPC authentication provider boundary.
///
/// Implementations should delegate Kerberos, NTLM, and SPNEGO to system
/// libraries or external providers. This trait models the RPC authentication
/// context, not SMB authentication. Version 1 supports only `None` and
/// `Connect` authentication levels; packet signing and sealing are deliberately
/// out of scope until their Windows wire semantics are validated.
pub trait RpcAuthProvider {
    fn mechanism(&self) -> AuthMechanism;
    fn auth_level(&self) -> AuthLevel;
    fn init_context(&mut self, target: &str) -> Result<Vec<u8>>;
    fn step(&mut self, challenge: &[u8]) -> Result<Vec<u8>>;

    fn auth_type(&self) -> RpcAuthType {
        match self.mechanism() {
            AuthMechanism::None => RpcAuthType::None,
            AuthMechanism::Kerberos => RpcAuthType::GssKerberos,
            AuthMechanism::Ntlm => RpcAuthType::WinNt,
        }
    }

    fn auth_context_id(&self) -> u32 {
        0
    }

    fn is_context_established(&self) -> bool {
        false
    }
}

#[cfg(feature = "ntlm-sspi")]
pub struct NtlmRpcAuthProvider {
    ntlm: Ntlm,
    identity: AuthIdentity,
    credentials_handle: Option<<Ntlm as SspiImpl>::CredentialsHandle>,
    target: Option<String>,
    auth_level: AuthLevel,
    auth_context_id: u32,
    established: bool,
}

#[cfg(feature = "ntlm-sspi")]
impl NtlmRpcAuthProvider {
    pub fn new(domain: &str, username: &str, password: &str) -> Result<Self> {
        let username = Username::new(username, Some(domain))
            .map_err(|err| RpcAuthError::Provider(format!("NTLM username setup failed: {err}")))?;
        Ok(Self {
            ntlm: Ntlm::new(),
            identity: AuthIdentity {
                username,
                password: password.to_string().into(),
            },
            credentials_handle: None,
            target: None,
            auth_level: AuthLevel::Connect,
            auth_context_id: 0,
            established: false,
        })
    }

    pub fn with_auth_level(mut self, auth_level: AuthLevel) -> Self {
        self.auth_level = auth_level;
        self
    }

    pub fn with_auth_context_id(mut self, auth_context_id: u32) -> Self {
        self.auth_context_id = auth_context_id;
        self
    }

    fn next_token(&mut self, input: Option<&[u8]>) -> Result<Vec<u8>> {
        let credentials_handle = self.credentials_handle.as_mut().ok_or_else(|| {
            RpcAuthError::Provider("NTLM credentials are not initialized".to_string())
        })?;
        let target = self
            .target
            .as_deref()
            .ok_or_else(|| RpcAuthError::Provider("NTLM target is not initialized".to_string()))?;
        let mut output_buffer = vec![SecurityBuffer::new(Vec::new(), BufferType::Token)];
        let mut input_buffer =
            input.map(|token| vec![SecurityBuffer::new(token.to_vec(), BufferType::Token)]);

        let mut builder = self
            .ntlm
            .initialize_security_context()
            .with_credentials_handle(credentials_handle)
            .with_context_requirements(ntlm_rpc_context_flags())
            .with_target_data_representation(DataRepresentation::Native)
            .with_target_name(target)
            .with_output(&mut output_buffer);

        if let Some(input_buffer) = input_buffer.as_mut() {
            builder = builder.with_input(input_buffer);
        }

        let result = self
            .ntlm
            .initialize_security_context_impl(&mut builder)
            .map_err(|err| RpcAuthError::Provider(format!("NTLM initialize failed: {err}")))?
            .resolve_to_result()
            .map_err(|err| {
                RpcAuthError::Provider(format!("NTLM token generation failed: {err}"))
            })?;

        if matches!(
            result.status,
            SecurityStatus::CompleteAndContinue | SecurityStatus::CompleteNeeded
        ) {
            self.ntlm
                .complete_auth_token(&mut output_buffer)
                .map_err(|err| {
                    RpcAuthError::Provider(format!("NTLM complete token failed: {err}"))
                })?;
        }

        self.established = !matches!(
            result.status,
            SecurityStatus::ContinueNeeded | SecurityStatus::CompleteAndContinue
        );
        Ok(output_buffer.remove(0).buffer)
    }
}

#[cfg(feature = "ntlm-sspi")]
impl RpcAuthProvider for NtlmRpcAuthProvider {
    fn mechanism(&self) -> AuthMechanism {
        AuthMechanism::Ntlm
    }

    fn auth_level(&self) -> AuthLevel {
        self.auth_level
    }

    fn auth_context_id(&self) -> u32 {
        self.auth_context_id
    }

    fn init_context(&mut self, target: &str) -> Result<Vec<u8>> {
        let credentials = self
            .ntlm
            .acquire_credentials_handle()
            .with_credential_use(CredentialUse::Outbound)
            .with_auth_data(&self.identity)
            .execute(&mut self.ntlm)
            .map_err(|err| {
                RpcAuthError::Provider(format!("NTLM acquire credentials failed: {err}"))
            })?;
        self.credentials_handle = Some(credentials.credentials_handle);
        self.target = Some(target.to_string());
        self.next_token(None)
    }

    fn step(&mut self, challenge: &[u8]) -> Result<Vec<u8>> {
        self.next_token(Some(challenge))
    }

    fn is_context_established(&self) -> bool {
        self.established
    }
}

#[cfg(feature = "ntlm-sspi")]
fn ntlm_rpc_context_flags() -> ClientRequestFlags {
    ClientRequestFlags::USE_DCE_STYLE
}

#[cfg(feature = "gssapi")]
pub struct GssapiKerberosRpcAuthProvider {
    service_principal: Option<String>,
    context: Option<GssapiClientContext>,
    auth_level: AuthLevel,
}

#[cfg(feature = "gssapi")]
impl GssapiKerberosRpcAuthProvider {
    pub fn new() -> Result<Self> {
        Ok(Self {
            service_principal: None,
            context: None,
            auth_level: AuthLevel::Connect,
        })
    }

    pub fn with_service_principal(mut self, service: impl Into<String>) -> Self {
        self.service_principal = Some(service.into());
        self
    }

    pub fn service_principal(&self) -> Option<&str> {
        self.service_principal.as_deref()
    }

    pub fn with_auth_level(mut self, auth_level: AuthLevel) -> Self {
        self.auth_level = auth_level;
        self
    }

    pub fn service_name_for_target(target: &str) -> String {
        if target.contains('@') {
            return target.to_string();
        }
        target
            .split_once('/')
            .map(|(service, host)| format!("{service}@{host}"))
            .unwrap_or_else(|| target.to_string())
    }

    fn build_context(&self, target: &str) -> Result<GssapiClientContext> {
        let service_name = self
            .service_principal
            .clone()
            .unwrap_or_else(|| Self::service_name_for_target(target));
        GssapiClientContext::new(&service_name)
    }
}

#[cfg(feature = "gssapi")]
pub type GssapiRpcAuthProvider = GssapiKerberosRpcAuthProvider;

#[cfg(feature = "gssapi")]
impl RpcAuthProvider for GssapiKerberosRpcAuthProvider {
    fn mechanism(&self) -> AuthMechanism {
        AuthMechanism::Kerberos
    }

    fn auth_level(&self) -> AuthLevel {
        self.auth_level
    }

    fn init_context(&mut self, target: &str) -> Result<Vec<u8>> {
        let mut context = self.build_context(target)?;
        let token = context
            .step(None)?
            .ok_or_else(|| RpcAuthError::Provider("GSSAPI initial token is empty".to_string()))?;
        self.context = Some(context);
        Ok(token)
    }

    fn step(&mut self, challenge: &[u8]) -> Result<Vec<u8>> {
        let context = self.context.as_mut().ok_or_else(|| {
            RpcAuthError::Provider("GSSAPI context is not initialized".to_string())
        })?;
        context
            .step(Some(challenge))
            .map(|token| token.unwrap_or_default())
    }

    fn is_context_established(&self) -> bool {
        self.context
            .as_ref()
            .map(GssapiClientContext::is_established)
            .unwrap_or(false)
    }
}

#[cfg(feature = "gssapi")]
struct GssapiClientContext {
    credential: gss::gss_cred_id_t,
    name: gss::gss_name_t,
    context: gss::gss_ctx_id_t,
    established: bool,
}

#[cfg(feature = "gssapi")]
impl GssapiClientContext {
    fn new(service_name: &str) -> Result<Self> {
        let name = import_gssapi_service_name(service_name)?;
        match acquire_gssapi_credentials() {
            Ok(credential) => Ok(Self {
                credential,
                name,
                context: std::ptr::null_mut(),
                established: false,
            }),
            Err(err) => {
                release_gssapi_name(name);
                Err(err)
            }
        }
    }

    fn step(&mut self, input: Option<&[u8]>) -> Result<Option<Vec<u8>>> {
        let mut minor = 0;
        let mut actual_mech = std::ptr::null_mut();
        let mut output_token = empty_gssapi_buffer();
        let mut actual_flags = 0;
        let mut lifetime = 0;
        let mut mech_oid = kerberos_mech_oid();
        let mut input_token = input
            .map(input_gssapi_buffer)
            .unwrap_or_else(empty_gssapi_buffer);
        let input_token_ptr = if input.is_some() {
            &mut input_token as *mut gss::gss_buffer_desc
        } else {
            std::ptr::null_mut()
        };

        let major = unsafe {
            gss::gss_init_sec_context(
                &mut minor,
                self.credential,
                &mut self.context,
                self.name,
                &mut mech_oid,
                self.request_flags(),
                0,
                std::ptr::null_mut(),
                input_token_ptr,
                &mut actual_mech,
                &mut output_token,
                &mut actual_flags,
                &mut lifetime,
            )
        };

        if major != gss::GSS_S_COMPLETE && major != gss::GSS_S_CONTINUE_NEEDED {
            release_gssapi_buffer(&mut output_token);
            return Err(RpcAuthError::Provider(format!(
                "GSSAPI init security context failed: major=0x{major:08X} minor=0x{minor:08X}"
            )));
        }

        self.established = major == gss::GSS_S_COMPLETE;
        let token = copy_gssapi_buffer(&output_token);
        release_gssapi_buffer(&mut output_token);
        Ok((!token.is_empty()).then_some(token))
    }

    fn request_flags(&self) -> u32 {
        gss::GSS_C_MUTUAL_FLAG | gss::GSS_C_INTEG_FLAG | gss::GSS_C_DCE_STYLE
    }

    fn is_established(&self) -> bool {
        self.established
    }
}

#[cfg(feature = "gssapi")]
impl Drop for GssapiClientContext {
    fn drop(&mut self) {
        let mut minor = 0;
        if !self.context.is_null() {
            unsafe {
                gss::gss_delete_sec_context(&mut minor, &mut self.context, std::ptr::null_mut());
            }
        }
        if !self.credential.is_null() {
            unsafe {
                gss::gss_release_cred(&mut minor, &mut self.credential);
            }
        }
        release_gssapi_name(self.name);
    }
}

#[cfg(feature = "gssapi")]
fn import_gssapi_service_name(service_name: &str) -> Result<gss::gss_name_t> {
    let mut minor = 0;
    let mut name = std::ptr::null_mut();
    let mut buffer = input_gssapi_buffer(service_name.as_bytes());
    let major = unsafe {
        gss::gss_import_name(
            &mut minor,
            &mut buffer,
            gss::GSS_C_NT_HOSTBASED_SERVICE,
            &mut name,
        )
    };
    if major == gss::GSS_S_COMPLETE {
        Ok(name)
    } else {
        Err(RpcAuthError::Provider(format!(
            "GSSAPI import service name failed: major=0x{major:08X} minor=0x{minor:08X}"
        )))
    }
}

#[cfg(feature = "gssapi")]
fn acquire_gssapi_credentials() -> Result<gss::gss_cred_id_t> {
    let mut minor = 0;
    let mut credential = std::ptr::null_mut();
    let major = unsafe {
        gss::gss_acquire_cred(
            &mut minor,
            std::ptr::null_mut(),
            0,
            std::ptr::null_mut(),
            gss::GSS_C_INITIATE as i32,
            &mut credential,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    if major == gss::GSS_S_COMPLETE {
        Ok(credential)
    } else {
        Err(RpcAuthError::Provider(format!(
            "GSSAPI acquire default credentials failed: major=0x{major:08X} minor=0x{minor:08X}"
        )))
    }
}

#[cfg(feature = "gssapi")]
fn release_gssapi_name(mut name: gss::gss_name_t) {
    if !name.is_null() {
        let mut minor = 0;
        unsafe {
            gss::gss_release_name(&mut minor, &mut name);
        }
    }
}

#[cfg(feature = "gssapi")]
fn empty_gssapi_buffer() -> gss::gss_buffer_desc {
    gss::gss_buffer_desc {
        length: 0,
        value: std::ptr::null_mut(),
    }
}

#[cfg(feature = "gssapi")]
fn input_gssapi_buffer(bytes: &[u8]) -> gss::gss_buffer_desc {
    gss::gss_buffer_desc {
        length: bytes.len(),
        value: bytes.as_ptr() as *mut std::ffi::c_void,
    }
}

#[cfg(feature = "gssapi")]
fn oid_from_static_bytes(bytes: &'static [u8]) -> gss::gss_OID_desc {
    gss::gss_OID_desc {
        length: bytes.len() as gss::OM_uint32,
        elements: bytes.as_ptr() as *mut std::ffi::c_void,
    }
}

#[cfg(feature = "gssapi")]
fn kerberos_mech_oid() -> gss::gss_OID_desc {
    oid_from_static_bytes(b"\x2a\x86\x48\x86\xf7\x12\x01\x02\x02")
}

#[cfg(feature = "gssapi")]
fn copy_gssapi_buffer(buffer: &gss::gss_buffer_desc) -> Vec<u8> {
    if buffer.value.is_null() || buffer.length == 0 {
        return Vec::new();
    }
    unsafe { std::slice::from_raw_parts(buffer.value.cast::<u8>(), buffer.length).to_vec() }
}

#[cfg(feature = "gssapi")]
fn release_gssapi_buffer(buffer: &mut gss::gss_buffer_desc) {
    if !buffer.value.is_null() {
        let mut minor = 0;
        unsafe {
            gss::gss_release_buffer(&mut minor, buffer);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockProvider;

    impl RpcAuthProvider for MockProvider {
        fn mechanism(&self) -> AuthMechanism {
            AuthMechanism::Kerberos
        }

        fn auth_level(&self) -> AuthLevel {
            AuthLevel::Connect
        }

        fn init_context(&mut self, target: &str) -> Result<Vec<u8>> {
            Ok(target.as_bytes().to_vec())
        }

        fn step(&mut self, challenge: &[u8]) -> Result<Vec<u8>> {
            Ok(challenge.to_vec())
        }
    }

    #[test]
    fn auth_levels_match_dce_rpc_wire_values() {
        assert_eq!(AuthLevel::None as u8, 0);
        assert_eq!(AuthLevel::Connect as u8, 2);
        assert_eq!(AuthLevel::PacketIntegrity as u8, 5);
        assert_eq!(AuthLevel::PacketPrivacy as u8, 6);
        assert_eq!(AuthLevel::try_from(5).unwrap(), AuthLevel::PacketIntegrity);
        assert!(AuthLevel::try_from(7).is_err());
    }

    #[test]
    fn auth_types_match_dce_rpc_wire_values() {
        assert_eq!(RpcAuthType::None as u8, 0);
        assert_eq!(RpcAuthType::GssNegotiate as u8, 9);
        assert_eq!(RpcAuthType::WinNt as u8, 10);
        assert_eq!(RpcAuthType::GssKerberos as u8, 16);
        assert_eq!(RpcAuthType::try_from(10).unwrap(), RpcAuthType::WinNt);
        assert!(RpcAuthType::try_from(11).is_err());
    }

    #[test]
    fn provider_maps_mechanism_to_default_auth_type() {
        let provider = MockProvider;
        assert_eq!(provider.auth_type(), RpcAuthType::GssKerberos);
        assert_eq!(provider.auth_context_id(), 0);
        assert!(!provider.is_context_established());
    }

    #[cfg(feature = "ntlm-sspi")]
    #[test]
    fn ntlm_rpc_provider_exposes_rpc_metadata() {
        let provider = NtlmRpcAuthProvider::new("LAB", "Administrator", "Password1").unwrap();
        assert_eq!(provider.mechanism(), AuthMechanism::Ntlm);
        assert_eq!(provider.auth_level(), AuthLevel::Connect);
        assert_eq!(provider.auth_type(), RpcAuthType::WinNt);
        assert!(!provider.is_context_established());
    }
}
