use msrpce_dcerpc::{
    BindAckPdu, BindNakPdu, BindPdu, Error, InterfaceId, PresentationContext,
    PresentationContextList, PresentationRejectReason, PresentationResultCode, SyntaxId,
    TransferSyntax, BIND_TIME_FEATURE_KEEP_CONNECTION_ON_ORPHAN,
    BIND_TIME_FEATURE_SECURITY_CONTEXT_MULTIPLEXING,
};
use uuid::uuid;

#[test]
fn syntax_id_uses_dce_uuid_wire_order() {
    let syntax = SyntaxId::new(uuid!("8a885d04-1ceb-11c9-9fe8-08002b104860"), 2, 0);

    assert_eq!(
        syntax.encode(),
        vec![
            0x04, 0x5D, 0x88, 0x8A, 0xEB, 0x1C, 0xC9, 0x11, 0x9F, 0xE8, 0x08, 0x00, 0x2B, 0x10,
            0x48, 0x60, 0x02, 0x00, 0x00, 0x00,
        ]
    );
    assert_eq!(SyntaxId::decode(&syntax.encode()).unwrap(), syntax);
    assert_eq!(TransferSyntax::Ndr32.syntax_id(), syntax);
}

#[test]
fn bind_time_feature_negotiation_syntax_encodes_feature_bits_in_uuid_tail() {
    let syntax = SyntaxId::bind_time_feature_negotiation(
        BIND_TIME_FEATURE_SECURITY_CONTEXT_MULTIPLEXING
            | BIND_TIME_FEATURE_KEEP_CONNECTION_ON_ORPHAN,
    );

    assert_eq!(
        syntax.uuid.to_string(),
        "6cb71c2c-9812-4540-0300-000000000000"
    );
    assert_eq!(syntax.version, 1);
}

#[test]
fn presentation_context_list_round_trips_one_context_with_ndr32() {
    let interface = InterfaceId::new(uuid!("12345678-1234-abcd-ef00-0123456789ab"), 1, 0);
    let context = PresentationContext::new(0, interface.syntax_id(), vec![TransferSyntax::Ndr32]);
    let list = PresentationContextList::new(vec![context.clone()]);

    let bytes = list.encode();
    assert_eq!(bytes[0..4], [1, 0, 0, 0]);
    assert_eq!(bytes[4..8], [0, 0, 1, 0]);
    assert_eq!(&bytes[8..28], &interface.syntax_id().encode());
    assert_eq!(&bytes[28..48], &TransferSyntax::Ndr32.syntax_id().encode());

    let decoded = PresentationContextList::decode(&bytes).unwrap();
    assert_eq!(decoded.contexts, vec![context]);
}

#[test]
fn presentation_context_list_round_trips_bind_time_feature_context() {
    let interface = InterfaceId::new(uuid!("12345678-1234-abcd-ef00-0123456789ab"), 1, 0);
    let context = PresentationContext::bind_time_feature_negotiation(
        2,
        interface.syntax_id(),
        BIND_TIME_FEATURE_SECURITY_CONTEXT_MULTIPLEXING
            | BIND_TIME_FEATURE_KEEP_CONNECTION_ON_ORPHAN,
    );
    let list = PresentationContextList::new(vec![context.clone()]);

    let decoded = PresentationContextList::decode(&list.encode()).unwrap();

    assert_eq!(decoded.contexts, vec![context]);
}

#[test]
fn bind_ack_decodes_negotiate_ack_result() {
    let mut ack_body = Vec::new();
    ack_body.extend_from_slice(&4280u16.to_le_bytes());
    ack_body.extend_from_slice(&4280u16.to_le_bytes());
    ack_body.extend_from_slice(&7u32.to_le_bytes());
    ack_body.extend_from_slice(&0u16.to_le_bytes());
    while !ack_body.len().is_multiple_of(4) {
        ack_body.push(0);
    }
    ack_body.extend_from_slice(&[1, 0]);
    ack_body.extend_from_slice(&0u16.to_le_bytes());
    ack_body.extend_from_slice(&(PresentationResultCode::NegotiateAck as u16).to_le_bytes());
    ack_body.extend_from_slice(
        &(PresentationRejectReason::ProposedTransferSyntaxNotSupported as u16).to_le_bytes(),
    );
    ack_body.extend_from_slice(
        &SyntaxId::new(uuid!("00000000-0000-0000-0000-000000000000"), 0, 0).encode(),
    );

    let ack = BindAckPdu::decode(&ack_body).unwrap();

    assert_eq!(ack.results[0].result, PresentationResultCode::NegotiateAck);
}

#[test]
fn bind_pdu_can_be_built_from_presentation_contexts() {
    let interface = InterfaceId::new(uuid!("12345678-1234-abcd-ef00-0123456789ab"), 1, 0);
    let context = PresentationContext::new(3, interface.syntax_id(), vec![TransferSyntax::Ndr32]);
    let bind = BindPdu::with_contexts(4280, 4280, 0, vec![context.clone()]);

    let decoded = BindPdu::decode(&bind.encode()).unwrap();
    let list = decoded.presentation_context_list().unwrap();

    assert_eq!(decoded.max_xmit_frag, 4280);
    assert_eq!(decoded.max_recv_frag, 4280);
    assert_eq!(list.contexts, vec![context]);
}

#[test]
fn bind_ack_selects_accepted_transfer_syntax_by_result_index() {
    let interface = InterfaceId::new(uuid!("12345678-1234-abcd-ef00-0123456789ab"), 1, 0);
    let proposed = PresentationContext::new(5, interface.syntax_id(), vec![TransferSyntax::Ndr32]);
    let mut ack_body = Vec::new();
    ack_body.extend_from_slice(&4280u16.to_le_bytes());
    ack_body.extend_from_slice(&4280u16.to_le_bytes());
    ack_body.extend_from_slice(&7u32.to_le_bytes());
    ack_body.extend_from_slice(&1u16.to_le_bytes());
    ack_body.push(0);
    ack_body.push(0);
    ack_body.extend_from_slice(&[1, 0]);
    ack_body.extend_from_slice(&0u16.to_le_bytes());
    ack_body.extend_from_slice(&(PresentationResultCode::Acceptance as u16).to_le_bytes());
    ack_body
        .extend_from_slice(&(PresentationRejectReason::ReasonNotSpecified as u16).to_le_bytes());
    ack_body.extend_from_slice(&TransferSyntax::Ndr32.syntax_id().encode());

    let ack = BindAckPdu::decode(&ack_body).unwrap();
    let accepted = ack.accepted_context(&[proposed]).unwrap();

    assert_eq!(ack.assoc_group_id, 7);
    assert_eq!(accepted.context_id, 5);
    assert_eq!(accepted.transfer_syntax, TransferSyntax::Ndr32.syntax_id());
}

#[test]
fn bind_ack_can_select_later_accepted_context() {
    let interface = InterfaceId::new(uuid!("12345678-1234-abcd-ef00-0123456789ab"), 1, 0);
    let rejected = PresentationContext::new(0, interface.syntax_id(), vec![TransferSyntax::Ndr64]);
    let accepted = PresentationContext::new(2, interface.syntax_id(), vec![TransferSyntax::Ndr32]);
    let ack = BindAckPdu {
        max_xmit_frag: 4280,
        max_recv_frag: 4280,
        assoc_group_id: 0,
        secondary_addr: Vec::new(),
        results: vec![
            msrpce_dcerpc::PresentationResult {
                result: PresentationResultCode::ProviderRejection,
                reason: PresentationRejectReason::ProposedTransferSyntaxNotSupported,
                transfer_syntax: TransferSyntax::Ndr64.syntax_id(),
            },
            msrpce_dcerpc::PresentationResult {
                result: PresentationResultCode::Acceptance,
                reason: PresentationRejectReason::ReasonNotSpecified,
                transfer_syntax: TransferSyntax::Ndr32.syntax_id(),
            },
        ],
    };

    let selected = ack.accepted_context(&[rejected, accepted]).unwrap();

    assert_eq!(selected.context_id, 2);
    assert_eq!(selected.transfer_syntax, TransferSyntax::Ndr32.syntax_id());
}

#[test]
fn bind_ack_reports_provider_rejection() {
    let interface = InterfaceId::new(uuid!("12345678-1234-abcd-ef00-0123456789ab"), 1, 0);
    let proposed = PresentationContext::new(5, interface.syntax_id(), vec![TransferSyntax::Ndr32]);
    let ack = BindAckPdu {
        max_xmit_frag: 4280,
        max_recv_frag: 4280,
        assoc_group_id: 0,
        secondary_addr: Vec::new(),
        results: vec![msrpce_dcerpc::PresentationResult {
            result: PresentationResultCode::ProviderRejection,
            reason: PresentationRejectReason::ProposedTransferSyntaxNotSupported,
            transfer_syntax: TransferSyntax::Ndr32.syntax_id(),
        }],
    };

    let err = ack.accepted_context(&[proposed]).unwrap_err();
    assert_eq!(
        err,
        Error::PresentationContextRejected {
            context_id: 5,
            result: PresentationResultCode::ProviderRejection,
            reason: PresentationRejectReason::ProposedTransferSyntaxNotSupported,
        }
    );
}

#[test]
fn bind_nak_decodes_reject_reason() {
    let bytes = 2u16.to_le_bytes();
    let nak = BindNakPdu::decode(&bytes).unwrap();

    assert_eq!(
        nak.reject_reason,
        msrpce_dcerpc::RejectReason::ProposedTransferSyntaxNotSupported
    );
}

#[test]
fn bind_ack_rejects_truncated_result_list_without_panicking() {
    let mut ack_body = Vec::new();
    ack_body.extend_from_slice(&4280u16.to_le_bytes());
    ack_body.extend_from_slice(&4280u16.to_le_bytes());
    ack_body.extend_from_slice(&0u32.to_le_bytes());
    ack_body.extend_from_slice(&0u16.to_le_bytes());
    while !ack_body.len().is_multiple_of(4) {
        ack_body.push(0);
    }
    ack_body.extend_from_slice(&[1, 0, 0, 0]);
    ack_body.extend_from_slice(&[0xAA; 8]);

    let err = BindAckPdu::decode(&ack_body).unwrap_err();

    assert_eq!(err, Error::InvalidPdu("bind ack result list is truncated"));
}
