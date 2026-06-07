use crate::auth::{AuthLevel, RpcAuthType as AuthType};
use crate::error::{Error, Result};
use msrpce_ndr::{ByteOrder, DataRepresentation};
use uuid::Uuid;

pub const RPC_VERSION: u8 = 5;
pub const RPC_VERSION_MINOR: u8 = 0;
pub const COMMON_HEADER_LEN: u16 = 16;

pub const PFC_FIRST_FRAG: u8 = 0x01;
pub const PFC_LAST_FRAG: u8 = 0x02;
pub const PFC_PENDING_CANCEL: u8 = 0x04;
pub const PFC_SUPPORT_HEADER_SIGN: u8 = 0x04;
pub const PFC_RESERVED_1: u8 = 0x08;
pub const PFC_CONC_MPX: u8 = 0x10;
pub const PFC_DID_NOT_EXECUTE: u8 = 0x20;
pub const PFC_MAYBE: u8 = 0x40;
pub const PFC_OBJECT_UUID: u8 = 0x80;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SecurityTrailer {
    pub auth_type: AuthType,
    pub auth_level: AuthLevel,
    pub auth_pad_length: u8,
    pub auth_reserved: u8,
    pub auth_context_id: u32,
}

impl SecurityTrailer {
    pub const LEN: usize = 8;

    pub fn encode(&self) -> [u8; Self::LEN] {
        let mut bytes = [0u8; Self::LEN];
        bytes[0] = self.auth_type as u8;
        bytes[1] = self.auth_level as u8;
        bytes[2] = self.auth_pad_length;
        bytes[3] = self.auth_reserved;
        bytes[4..8].copy_from_slice(&self.auth_context_id.to_le_bytes());
        bytes
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < Self::LEN {
            return Err(Error::InvalidPdu("security trailer requires 8 bytes"));
        }
        Ok(Self {
            auth_type: AuthType::try_from(bytes[0])
                .map_err(|_| Error::InvalidPdu("unsupported RPC auth type"))?,
            auth_level: AuthLevel::try_from(bytes[1])
                .map_err(|_| Error::InvalidPdu("unsupported RPC auth level"))?,
            auth_pad_length: bytes[2],
            auth_reserved: bytes[3],
            auth_context_id: u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]),
        })
    }
}

/// MS-RPCE connection-oriented PDU type.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PduType {
    Request = 0x00,
    Ping = 0x01,
    Response = 0x02,
    Fault = 0x03,
    Working = 0x04,
    NoCall = 0x05,
    Reject = 0x06,
    Ack = 0x07,
    ClCancel = 0x08,
    Fack = 0x09,
    CancelAck = 0x0A,
    Bind = 0x0B,
    BindAck = 0x0C,
    BindNak = 0x0D,
    AlterContext = 0x0E,
    AlterContextResponse = 0x0F,
    Auth3 = 0x10,
    Shutdown = 0x11,
    CoCancel = 0x12,
    Orphaned = 0x13,
}

impl TryFrom<u8> for PduType {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self> {
        match value {
            0x00 => Ok(Self::Request),
            0x01 => Ok(Self::Ping),
            0x02 => Ok(Self::Response),
            0x03 => Ok(Self::Fault),
            0x04 => Ok(Self::Working),
            0x05 => Ok(Self::NoCall),
            0x06 => Ok(Self::Reject),
            0x07 => Ok(Self::Ack),
            0x08 => Ok(Self::ClCancel),
            0x09 => Ok(Self::Fack),
            0x0A => Ok(Self::CancelAck),
            0x0B => Ok(Self::Bind),
            0x0C => Ok(Self::BindAck),
            0x0D => Ok(Self::BindNak),
            0x0E => Ok(Self::AlterContext),
            0x0F => Ok(Self::AlterContextResponse),
            0x10 => Ok(Self::Auth3),
            0x11 => Ok(Self::Shutdown),
            0x12 => Ok(Self::CoCancel),
            0x13 => Ok(Self::Orphaned),
            _ => Err(Error::InvalidPduType(value)),
        }
    }
}

/// MS-RPCE common PDU header metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PduHeader {
    pub rpc_vers: u8,
    pub rpc_vers_minor: u8,
    pub ptype: PduType,
    pub pfc_flags: u8,
    pub packed_drep: [u8; 4],
    pub frag_length: u16,
    pub auth_length: u16,
    pub call_id: u32,
}

impl PduHeader {
    /// Creates a header with Windows-default DREP and no auth trailer.
    pub fn new(ptype: PduType, pfc_flags: u8, call_id: u32) -> Self {
        Self {
            rpc_vers: RPC_VERSION,
            rpc_vers_minor: RPC_VERSION_MINOR,
            ptype,
            pfc_flags,
            packed_drep: msrpce_ndr::DataRepresentation::windows_default().to_bytes(),
            frag_length: COMMON_HEADER_LEN,
            auth_length: 0,
            call_id,
        }
    }

    pub fn encode(&self) -> [u8; COMMON_HEADER_LEN as usize] {
        let mut bytes = [0u8; COMMON_HEADER_LEN as usize];
        bytes[0] = self.rpc_vers;
        bytes[1] = self.rpc_vers_minor;
        bytes[2] = self.ptype as u8;
        bytes[3] = self.pfc_flags;
        bytes[4..8].copy_from_slice(&self.packed_drep);
        write_u16(&mut bytes[8..10], self.frag_length, self.byte_order());
        write_u16(&mut bytes[10..12], self.auth_length, self.byte_order());
        write_u32(&mut bytes[12..16], self.call_id, self.byte_order());
        bytes
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < COMMON_HEADER_LEN as usize {
            return Err(Error::InvalidPdu("common header requires 16 bytes"));
        }

        let packed_drep = [bytes[4], bytes[5], bytes[6], bytes[7]];
        let drep = DataRepresentation::from_bytes(packed_drep)?;
        let byte_order = drep.byte_order;

        let header = Self {
            rpc_vers: bytes[0],
            rpc_vers_minor: bytes[1],
            ptype: PduType::try_from(bytes[2])?,
            pfc_flags: bytes[3],
            packed_drep,
            frag_length: read_u16(&bytes[8..10], byte_order),
            auth_length: read_u16(&bytes[10..12], byte_order),
            call_id: read_u32(&bytes[12..16], byte_order),
        };

        if header.rpc_vers != RPC_VERSION {
            return Err(Error::InvalidPdu("unsupported RPC major version"));
        }

        Ok(header)
    }

    fn byte_order(&self) -> ByteOrder {
        DataRepresentation::from_bytes(self.packed_drep)
            .map(|drep| drep.byte_order)
            .unwrap_or(ByteOrder::Little)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PduPacket {
    pub header: PduHeader,
    body: Vec<u8>,
    security_trailer: Option<SecurityTrailer>,
    auth_value: Vec<u8>,
}

impl PduPacket {
    pub fn new(header: PduHeader, body: Vec<u8>, auth_value: Vec<u8>) -> Self {
        Self {
            header,
            body,
            security_trailer: None,
            auth_value,
        }
    }

    pub fn with_security_trailer(
        header: PduHeader,
        body: Vec<u8>,
        security_trailer: SecurityTrailer,
        auth_value: Vec<u8>,
    ) -> Self {
        Self {
            header,
            body,
            security_trailer: Some(security_trailer),
            auth_value,
        }
    }

    pub fn from_bind(call_id: u32, bind: BindPdu) -> Self {
        Self::from_body(PduType::Bind, call_id, bind.encode())
    }

    pub fn from_request(call_id: u32, request: RequestPdu) -> Self {
        Self::from_request_with_flags(call_id, PFC_FIRST_FRAG | PFC_LAST_FRAG, request)
    }

    pub fn from_request_with_flags(call_id: u32, pfc_flags: u8, request: RequestPdu) -> Self {
        let mut header = PduHeader::new(
            PduType::Request,
            pfc_flags | request.object.map(|_| PFC_OBJECT_UUID).unwrap_or(0),
            call_id,
        );
        let body = request.encode();
        header.frag_length = COMMON_HEADER_LEN + body.len() as u16;
        Self {
            header,
            body,
            security_trailer: None,
            auth_value: Vec::new(),
        }
    }

    pub fn from_response(call_id: u32, response: ResponsePdu) -> Self {
        Self::from_response_with_flags(call_id, PFC_FIRST_FRAG | PFC_LAST_FRAG, response)
    }

    pub fn from_response_with_flags(call_id: u32, pfc_flags: u8, response: ResponsePdu) -> Self {
        Self::from_body_with_flags(PduType::Response, call_id, pfc_flags, response.encode())
    }

    pub fn from_fault(call_id: u32, fault: FaultPdu) -> Self {
        Self::from_body(PduType::Fault, call_id, fault.encode())
    }

    pub fn body(&self) -> &[u8] {
        &self.body
    }

    pub fn auth_value(&self) -> &[u8] {
        &self.auth_value
    }

    pub fn security_trailer(&self) -> Option<&SecurityTrailer> {
        self.security_trailer.as_ref()
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        let body_len = self.body.len();
        let auth_len = self.auth_value.len();
        if auth_len > u16::MAX as usize {
            return Err(Error::InvalidPdu("auth value is too large"));
        }
        if auth_len > 0 && self.security_trailer.is_none() {
            return Err(Error::InvalidPdu("auth value requires security trailer"));
        }
        let (padding_len, trailer_len) = self
            .security_trailer
            .map(|trailer| (usize::from(trailer.auth_pad_length), SecurityTrailer::LEN))
            .unwrap_or((0, 0));
        let frag_length =
            COMMON_HEADER_LEN as usize + body_len + padding_len + trailer_len + auth_len;
        if frag_length > u16::MAX as usize {
            return Err(Error::InvalidPdu("fragment is too large"));
        }

        let mut header = self.header.clone();
        header.frag_length = frag_length as u16;
        header.auth_length = auth_len as u16;

        let mut bytes = Vec::with_capacity(frag_length);
        bytes.extend_from_slice(&header.encode());
        bytes.extend_from_slice(&self.body);
        if let Some(security_trailer) = self.security_trailer {
            bytes.resize(
                bytes.len() + usize::from(security_trailer.auth_pad_length),
                0,
            );
            bytes.extend_from_slice(&security_trailer.encode());
        }
        bytes.extend_from_slice(&self.auth_value);
        Ok(bytes)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let header = PduHeader::decode(bytes)?;
        let frag_length = usize::from(header.frag_length);
        let auth_length = usize::from(header.auth_length);

        if frag_length < COMMON_HEADER_LEN as usize {
            return Err(Error::InvalidPdu(
                "fragment length is smaller than common header",
            ));
        }
        if bytes.len() != frag_length {
            return Err(Error::InvalidPdu(
                "fragment length does not match input length",
            ));
        }
        let content_length = frag_length - COMMON_HEADER_LEN as usize;
        if auth_length > content_length {
            return Err(Error::InvalidPdu("auth length exceeds fragment body"));
        }

        let (body_end, security_trailer) = if auth_length == 0 {
            (frag_length, None)
        } else {
            let auth_start = frag_length - auth_length;
            let trailer_start = auth_start
                .checked_sub(SecurityTrailer::LEN)
                .ok_or(Error::InvalidPdu("auth value requires security trailer"))?;
            if trailer_start < COMMON_HEADER_LEN as usize {
                return Err(Error::InvalidPdu("auth value requires security trailer"));
            }
            let trailer = SecurityTrailer::decode(&bytes[trailer_start..auth_start])?;
            let body_end = trailer_start
                .checked_sub(usize::from(trailer.auth_pad_length))
                .ok_or(Error::InvalidPdu("auth padding exceeds fragment body"))?;
            if body_end < COMMON_HEADER_LEN as usize {
                return Err(Error::InvalidPdu("auth padding exceeds fragment body"));
            }
            (body_end, Some(trailer))
        };
        Ok(Self {
            header,
            body: bytes[COMMON_HEADER_LEN as usize..body_end].to_vec(),
            security_trailer,
            auth_value: bytes[frag_length - auth_length..frag_length].to_vec(),
        })
    }

    fn from_body(ptype: PduType, call_id: u32, body: Vec<u8>) -> Self {
        Self::from_body_with_flags(ptype, call_id, PFC_FIRST_FRAG | PFC_LAST_FRAG, body)
    }

    fn from_body_with_flags(ptype: PduType, call_id: u32, pfc_flags: u8, body: Vec<u8>) -> Self {
        let mut header = PduHeader::new(ptype, pfc_flags, call_id);
        header.frag_length = COMMON_HEADER_LEN + body.len() as u16;
        Self {
            header,
            body,
            security_trailer: None,
            auth_value: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BindPdu {
    pub max_xmit_frag: u16,
    pub max_recv_frag: u16,
    pub assoc_group_id: u32,
    pub presentation_context_list: Vec<u8>,
}

impl BindPdu {
    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(8 + self.presentation_context_list.len());
        bytes.extend_from_slice(&self.max_xmit_frag.to_le_bytes());
        bytes.extend_from_slice(&self.max_recv_frag.to_le_bytes());
        bytes.extend_from_slice(&self.assoc_group_id.to_le_bytes());
        bytes.extend_from_slice(&self.presentation_context_list);
        bytes
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 8 {
            return Err(Error::InvalidPdu("bind PDU body requires at least 8 bytes"));
        }
        Ok(Self {
            max_xmit_frag: u16::from_le_bytes([bytes[0], bytes[1]]),
            max_recv_frag: u16::from_le_bytes([bytes[2], bytes[3]]),
            assoc_group_id: u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]),
            presentation_context_list: bytes[8..].to_vec(),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestPdu {
    pub alloc_hint: u32,
    pub ctx_id: u16,
    pub opnum: u16,
    pub object: Option<Uuid>,
    pub stub_data: Vec<u8>,
}

impl RequestPdu {
    pub fn encode(&self) -> Vec<u8> {
        let mut bytes =
            Vec::with_capacity(8 + self.object.map(|_| 16).unwrap_or(0) + self.stub_data.len());
        bytes.extend_from_slice(&self.alloc_hint.to_le_bytes());
        bytes.extend_from_slice(&self.ctx_id.to_le_bytes());
        bytes.extend_from_slice(&self.opnum.to_le_bytes());
        if let Some(object) = self.object {
            bytes.extend_from_slice(object.as_bytes());
        }
        bytes.extend_from_slice(&self.stub_data);
        bytes
    }

    pub fn decode(bytes: &[u8], has_object: bool) -> Result<Self> {
        let object_len = if has_object { 16 } else { 0 };
        if bytes.len() < 8 + object_len {
            return Err(Error::InvalidPdu("request PDU body is too short"));
        }

        let object = if has_object {
            Some(
                Uuid::from_slice(&bytes[8..24])
                    .map_err(|_| Error::InvalidPdu("request object UUID is invalid"))?,
            )
        } else {
            None
        };
        let stub_start = 8 + object_len;

        Ok(Self {
            alloc_hint: u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
            ctx_id: u16::from_le_bytes([bytes[4], bytes[5]]),
            opnum: u16::from_le_bytes([bytes[6], bytes[7]]),
            object,
            stub_data: bytes[stub_start..].to_vec(),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResponsePdu {
    pub alloc_hint: u32,
    pub ctx_id: u16,
    pub cancel_count: u8,
    pub stub_data: Vec<u8>,
}

impl ResponsePdu {
    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(8 + self.stub_data.len());
        bytes.extend_from_slice(&self.alloc_hint.to_le_bytes());
        bytes.extend_from_slice(&self.ctx_id.to_le_bytes());
        bytes.push(self.cancel_count);
        bytes.push(0);
        bytes.extend_from_slice(&self.stub_data);
        bytes
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 8 {
            return Err(Error::InvalidPdu(
                "response PDU body requires at least 8 bytes",
            ));
        }
        Ok(Self {
            alloc_hint: u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
            ctx_id: u16::from_le_bytes([bytes[4], bytes[5]]),
            cancel_count: bytes[6],
            stub_data: bytes[8..].to_vec(),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FaultPdu {
    pub alloc_hint: u32,
    pub ctx_id: u16,
    pub cancel_count: u8,
    pub status: u32,
    pub stub_data: Vec<u8>,
}

impl FaultPdu {
    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(12 + self.stub_data.len());
        bytes.extend_from_slice(&self.alloc_hint.to_le_bytes());
        bytes.extend_from_slice(&self.ctx_id.to_le_bytes());
        bytes.push(self.cancel_count);
        bytes.push(0);
        bytes.extend_from_slice(&self.status.to_le_bytes());
        bytes.extend_from_slice(&self.stub_data);
        bytes
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 12 {
            return Err(Error::InvalidPdu(
                "fault PDU body requires at least 12 bytes",
            ));
        }
        Ok(Self {
            alloc_hint: u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
            ctx_id: u16::from_le_bytes([bytes[4], bytes[5]]),
            cancel_count: bytes[6],
            status: u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]),
            stub_data: bytes[12..].to_vec(),
        })
    }
}

#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RejectReason {
    ReasonNotSpecified = 0x0000,
    AbstractSyntaxNotSupported = 0x0001,
    ProposedTransferSyntaxNotSupported = 0x0002,
    LocalLimitExceeded = 0x0003,
    ProtocolVersionNotSpecified = 0x0004,
    AuthenticationTypeNotRecognized = 0x0008,
    InvalidChecksum = 0x0009,
}

impl TryFrom<u16> for RejectReason {
    type Error = Error;

    fn try_from(value: u16) -> Result<Self> {
        match value {
            0x0000 => Ok(Self::ReasonNotSpecified),
            0x0001 => Ok(Self::AbstractSyntaxNotSupported),
            0x0002 => Ok(Self::ProposedTransferSyntaxNotSupported),
            0x0003 => Ok(Self::LocalLimitExceeded),
            0x0004 => Ok(Self::ProtocolVersionNotSpecified),
            0x0008 => Ok(Self::AuthenticationTypeNotRecognized),
            0x0009 => Ok(Self::InvalidChecksum),
            _ => Err(Error::InvalidPdu("unknown bind nak reject reason")),
        }
    }
}

fn read_u16(bytes: &[u8], byte_order: ByteOrder) -> u16 {
    let array = [bytes[0], bytes[1]];
    match byte_order {
        ByteOrder::Little => u16::from_le_bytes(array),
        ByteOrder::Big => u16::from_be_bytes(array),
    }
}

fn read_u32(bytes: &[u8], byte_order: ByteOrder) -> u32 {
    let array = [bytes[0], bytes[1], bytes[2], bytes[3]];
    match byte_order {
        ByteOrder::Little => u32::from_le_bytes(array),
        ByteOrder::Big => u32::from_be_bytes(array),
    }
}

fn write_u16(bytes: &mut [u8], value: u16, byte_order: ByteOrder) {
    let encoded = match byte_order {
        ByteOrder::Little => value.to_le_bytes(),
        ByteOrder::Big => value.to_be_bytes(),
    };
    bytes.copy_from_slice(&encoded);
}

fn write_u32(bytes: &mut [u8], value: u32, byte_order: ByteOrder) {
    let encoded = match byte_order {
        ByteOrder::Little => value.to_le_bytes(),
        ByteOrder::Big => value.to_be_bytes(),
    };
    bytes.copy_from_slice(&encoded);
}
