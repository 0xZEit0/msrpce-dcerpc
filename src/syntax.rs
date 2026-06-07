use uuid::Uuid;

/// MS-RPCE presentation syntax identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SyntaxId {
    pub uuid: Uuid,
    pub version: u32,
}

impl SyntaxId {
    pub fn new(uuid: Uuid, major_version: u16, minor_version: u16) -> Self {
        Self {
            uuid,
            version: u32::from(major_version) | (u32::from(minor_version) << 16),
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(20);
        bytes.extend_from_slice(&self.uuid.to_bytes_le());
        bytes.extend_from_slice(&self.version.to_le_bytes());
        bytes
    }

    pub fn decode(bytes: &[u8]) -> crate::Result<Self> {
        if bytes.len() < 20 {
            return Err(crate::Error::InvalidPdu(
                "syntax identifier requires 20 bytes",
            ));
        }

        let mut uuid_bytes = [0u8; 16];
        uuid_bytes.copy_from_slice(&bytes[..16]);
        Ok(Self {
            uuid: Uuid::from_bytes_le(uuid_bytes),
            version: u32::from_le_bytes([bytes[16], bytes[17], bytes[18], bytes[19]]),
        })
    }

    pub fn bind_time_feature_negotiation(bitmask: u16) -> Self {
        let bitmask = bitmask.to_le_bytes();
        Self {
            uuid: Uuid::from_fields(
                0x6CB7_1C2C,
                0x9812,
                0x4540,
                &[bitmask[0], bitmask[1], 0, 0, 0, 0, 0, 0],
            ),
            version: 1,
        }
    }
}

pub const BIND_TIME_FEATURE_SECURITY_CONTEXT_MULTIPLEXING: u16 = 0x0001;
pub const BIND_TIME_FEATURE_KEEP_CONNECTION_ON_ORPHAN: u16 = 0x0002;

/// Generic MS-RPCE interface identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct InterfaceId {
    pub uuid: Uuid,
    pub major_version: u16,
    pub minor_version: u16,
}

impl InterfaceId {
    pub fn new(uuid: Uuid, major_version: u16, minor_version: u16) -> Self {
        Self {
            uuid,
            major_version,
            minor_version,
        }
    }

    pub fn version_u32(&self) -> u32 {
        u32::from(self.major_version) | (u32::from(self.minor_version) << 16)
    }

    pub fn syntax_id(&self) -> SyntaxId {
        SyntaxId {
            uuid: self.uuid,
            version: self.version_u32(),
        }
    }
}

/// Transfer syntaxes the generic client can negotiate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TransferSyntax {
    Ndr32,
    Ndr64,
}

impl TransferSyntax {
    pub fn syntax_id(self) -> SyntaxId {
        match self {
            Self::Ndr32 => SyntaxId::new(
                Uuid::from_u128(0x8a885d04_1ceb_11c9_9fe8_08002b104860),
                2,
                0,
            ),
            Self::Ndr64 => SyntaxId::new(
                Uuid::from_u128(0x71710533_beba_4937_8319_b5dbef9ccc36),
                1,
                0,
            ),
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Ndr32 => "NDR32",
            Self::Ndr64 => "NDR64",
        }
    }

    pub fn as_ndr_syntax(self) -> msrpce_ndr::TransferSyntax {
        match self {
            Self::Ndr32 => msrpce_ndr::TransferSyntax::Ndr32,
            Self::Ndr64 => msrpce_ndr::TransferSyntax::Ndr64,
        }
    }
}
