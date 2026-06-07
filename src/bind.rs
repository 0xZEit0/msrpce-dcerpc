use crate::error::{Error, Result};
use crate::pdu::{BindPdu, RejectReason};
use crate::syntax::{SyntaxId, TransferSyntax};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PresentationContext {
    pub context_id: u16,
    pub abstract_syntax: SyntaxId,
    pub transfer_syntaxes: Vec<SyntaxId>,
}

impl PresentationContext {
    pub fn new(
        context_id: u16,
        abstract_syntax: SyntaxId,
        transfer_syntaxes: Vec<TransferSyntax>,
    ) -> Self {
        Self {
            context_id,
            abstract_syntax,
            transfer_syntaxes: transfer_syntaxes
                .into_iter()
                .map(TransferSyntax::syntax_id)
                .collect(),
        }
    }

    pub fn bind_time_feature_negotiation(
        context_id: u16,
        abstract_syntax: SyntaxId,
        bitmask: u16,
    ) -> Self {
        Self {
            context_id,
            abstract_syntax,
            transfer_syntaxes: vec![SyntaxId::bind_time_feature_negotiation(bitmask)],
        }
    }

    fn encode(&self) -> Result<Vec<u8>> {
        if self.transfer_syntaxes.len() > u8::MAX as usize {
            return Err(Error::InvalidPdu("too many transfer syntaxes"));
        }

        let mut bytes = Vec::with_capacity(24 + self.transfer_syntaxes.len() * 20);
        bytes.extend_from_slice(&self.context_id.to_le_bytes());
        bytes.push(self.transfer_syntaxes.len() as u8);
        bytes.push(0);
        bytes.extend_from_slice(&self.abstract_syntax.encode());
        for syntax in &self.transfer_syntaxes {
            bytes.extend_from_slice(&syntax.encode());
        }
        Ok(bytes)
    }

    fn decode(bytes: &[u8]) -> Result<(Self, usize)> {
        if bytes.len() < 24 {
            return Err(Error::InvalidPdu(
                "presentation context requires at least 24 bytes",
            ));
        }

        let context_id = u16::from_le_bytes([bytes[0], bytes[1]]);
        let transfer_count = bytes[2] as usize;
        let needed = 24 + transfer_count * 20;
        if bytes.len() < needed {
            return Err(Error::InvalidPdu("presentation context is truncated"));
        }

        let abstract_syntax = SyntaxId::decode(&bytes[4..24])?;
        let mut transfer_syntaxes = Vec::with_capacity(transfer_count);
        let mut offset = 24;
        for _ in 0..transfer_count {
            transfer_syntaxes.push(SyntaxId::decode(&bytes[offset..offset + 20])?);
            offset += 20;
        }

        Ok((
            Self {
                context_id,
                abstract_syntax,
                transfer_syntaxes,
            },
            needed,
        ))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PresentationContextList {
    pub contexts: Vec<PresentationContext>,
}

impl PresentationContextList {
    pub fn new(contexts: Vec<PresentationContext>) -> Self {
        Self { contexts }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.push(self.contexts.len() as u8);
        bytes.push(0);
        bytes.extend_from_slice(&0u16.to_le_bytes());
        for context in &self.contexts {
            bytes.extend_from_slice(
                &context
                    .encode()
                    .expect("presentation context count was prevalidated"),
            );
        }
        bytes
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 4 {
            return Err(Error::InvalidPdu(
                "presentation context list requires at least 4 bytes",
            ));
        }

        let count = bytes[0] as usize;
        let mut contexts = Vec::with_capacity(count);
        let mut offset = 4;
        for _ in 0..count {
            let (context, len) = PresentationContext::decode(&bytes[offset..])?;
            contexts.push(context);
            offset += len;
        }

        if offset != bytes.len() {
            return Err(Error::InvalidPdu(
                "presentation context list has trailing bytes",
            ));
        }

        Ok(Self { contexts })
    }
}

impl BindPdu {
    pub fn with_contexts(
        max_xmit_frag: u16,
        max_recv_frag: u16,
        assoc_group_id: u32,
        contexts: Vec<PresentationContext>,
    ) -> Self {
        Self {
            max_xmit_frag,
            max_recv_frag,
            assoc_group_id,
            presentation_context_list: PresentationContextList::new(contexts).encode(),
        }
    }

    pub fn presentation_context_list(&self) -> Result<PresentationContextList> {
        PresentationContextList::decode(&self.presentation_context_list)
    }
}

#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PresentationResultCode {
    Acceptance = 0,
    UserRejection = 1,
    ProviderRejection = 2,
    NegotiateAck = 3,
}

impl TryFrom<u16> for PresentationResultCode {
    type Error = Error;

    fn try_from(value: u16) -> Result<Self> {
        match value {
            0 => Ok(Self::Acceptance),
            1 => Ok(Self::UserRejection),
            2 => Ok(Self::ProviderRejection),
            3 => Ok(Self::NegotiateAck),
            _ => Err(Error::InvalidPdu("unknown presentation result code")),
        }
    }
}

#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PresentationRejectReason {
    ReasonNotSpecified = 0,
    AbstractSyntaxNotSupported = 1,
    ProposedTransferSyntaxNotSupported = 2,
    LocalLimitExceeded = 3,
}

impl TryFrom<u16> for PresentationRejectReason {
    type Error = Error;

    fn try_from(value: u16) -> Result<Self> {
        match value {
            0 => Ok(Self::ReasonNotSpecified),
            1 => Ok(Self::AbstractSyntaxNotSupported),
            2 => Ok(Self::ProposedTransferSyntaxNotSupported),
            3 => Ok(Self::LocalLimitExceeded),
            _ => Err(Error::InvalidPdu("unknown presentation reject reason")),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PresentationResult {
    pub result: PresentationResultCode,
    pub reason: PresentationRejectReason,
    pub transfer_syntax: SyntaxId,
}

impl PresentationResult {
    fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 24 {
            return Err(Error::InvalidPdu("presentation result requires 24 bytes"));
        }

        Ok(Self {
            result: PresentationResultCode::try_from(u16::from_le_bytes([bytes[0], bytes[1]]))?,
            reason: PresentationRejectReason::try_from(u16::from_le_bytes([bytes[2], bytes[3]]))?,
            transfer_syntax: SyntaxId::decode(&bytes[4..24])?,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AcceptedContext {
    pub context_id: u16,
    pub transfer_syntax: SyntaxId,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BindAckPdu {
    pub max_xmit_frag: u16,
    pub max_recv_frag: u16,
    pub assoc_group_id: u32,
    pub secondary_addr: Vec<u8>,
    pub results: Vec<PresentationResult>,
}

impl BindAckPdu {
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 12 {
            return Err(Error::InvalidPdu(
                "bind ack body requires at least 12 bytes",
            ));
        }

        let max_xmit_frag = u16::from_le_bytes([bytes[0], bytes[1]]);
        let max_recv_frag = u16::from_le_bytes([bytes[2], bytes[3]]);
        let assoc_group_id = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        let secondary_addr_len = u16::from_le_bytes([bytes[8], bytes[9]]) as usize;
        let secondary_addr_start = 10;
        let secondary_addr_end = secondary_addr_start + secondary_addr_len;
        if bytes.len() < secondary_addr_end {
            return Err(Error::InvalidPdu("bind ack secondary address is truncated"));
        }

        let mut offset = secondary_addr_end;
        while !offset.is_multiple_of(4) {
            offset += 1;
        }
        if bytes.len() < offset + 4 {
            return Err(Error::InvalidPdu("bind ack result list is missing"));
        }

        let result_count = bytes[offset] as usize;
        offset += 4;

        let mut results = Vec::with_capacity(result_count);
        for _ in 0..result_count {
            if bytes.len() < offset + 24 {
                return Err(Error::InvalidPdu("bind ack result list is truncated"));
            }
            results.push(PresentationResult::decode(&bytes[offset..offset + 24])?);
            offset += 24;
        }

        if offset != bytes.len() {
            return Err(Error::InvalidPdu("bind ack body has trailing bytes"));
        }

        Ok(Self {
            max_xmit_frag,
            max_recv_frag,
            assoc_group_id,
            secondary_addr: bytes[secondary_addr_start..secondary_addr_end].to_vec(),
            results,
        })
    }

    pub fn accepted_context(&self, proposed: &[PresentationContext]) -> Result<AcceptedContext> {
        let mut first_rejection = None;

        for (index, result) in self.results.iter().enumerate() {
            let Some(context) = proposed.get(index) else {
                return Err(Error::InvalidPdu(
                    "bind ack result has no matching proposed context",
                ));
            };

            if result.result == PresentationResultCode::Acceptance {
                return Ok(AcceptedContext {
                    context_id: context.context_id,
                    transfer_syntax: result.transfer_syntax,
                });
            }

            if result.result != PresentationResultCode::NegotiateAck {
                first_rejection.get_or_insert(Error::PresentationContextRejected {
                    context_id: context.context_id,
                    result: result.result,
                    reason: result.reason,
                });
            }
        }

        if let Some(err) = first_rejection {
            return Err(err);
        }

        Err(Error::InvalidPdu("bind ack has no presentation results"))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BindNakPdu {
    pub reject_reason: RejectReason,
}

impl BindNakPdu {
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 2 {
            return Err(Error::InvalidPdu("bind nak body requires a reject reason"));
        }
        Ok(Self {
            reject_reason: RejectReason::try_from(u16::from_le_bytes([bytes[0], bytes[1]]))?,
        })
    }
}
