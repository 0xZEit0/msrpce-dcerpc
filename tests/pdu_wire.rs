use msrpce_dcerpc::{
    AuthLevel, AuthType, BindPdu, Error, FaultPdu, PduHeader, PduPacket, PduType, RequestPdu,
    ResponsePdu, SecurityTrailer, PFC_FIRST_FRAG, PFC_LAST_FRAG,
};

#[test]
fn common_header_round_trips_windows_wire_format() {
    let mut header = PduHeader::new(PduType::Bind, PFC_FIRST_FRAG | PFC_LAST_FRAG, 0x1122_3344);
    header.frag_length = 0x1234;
    header.auth_length = 0x0055;

    let bytes = header.encode();
    assert_eq!(
        bytes,
        [
            0x05, 0x00, 0x0B, 0x03, 0x10, 0x00, 0x00, 0x00, 0x34, 0x12, 0x55, 0x00, 0x44, 0x33,
            0x22, 0x11,
        ]
    );

    let decoded = PduHeader::decode(&bytes).unwrap();
    assert_eq!(decoded, header);
}

#[test]
fn common_header_rejects_short_or_unknown_wire_data() {
    let short = PduHeader::decode(&[0x05, 0x00, 0x0B]).unwrap_err();
    assert_eq!(short, Error::InvalidPdu("common header requires 16 bytes"));

    let mut unknown_type = [0u8; 16];
    unknown_type[0] = 5;
    unknown_type[2] = 0xFE;
    let err = PduHeader::decode(&unknown_type).unwrap_err();
    assert_eq!(err, Error::InvalidPduType(0xFE));
}

#[test]
fn packet_round_trips_raw_bind_body() {
    let bind = BindPdu {
        max_xmit_frag: 4280,
        max_recv_frag: 4280,
        assoc_group_id: 0,
        presentation_context_list: vec![1, 0, 0, 0],
    };

    let packet = PduPacket::from_bind(1, bind.clone());
    let bytes = packet.encode().unwrap();

    assert_eq!(
        &bytes[..16],
        &[5, 0, 0x0B, 3, 0x10, 0, 0, 0, 28, 0, 0, 0, 1, 0, 0, 0]
    );

    let decoded = PduPacket::decode(&bytes).unwrap();
    assert_eq!(decoded.header.ptype, PduType::Bind);
    assert_eq!(decoded.header.frag_length, 28);
    assert_eq!(BindPdu::decode(decoded.body()).unwrap(), bind);
}

#[test]
fn packet_round_trips_request_response_and_fault_shapes() {
    let request = RequestPdu {
        alloc_hint: 4,
        ctx_id: 2,
        opnum: 7,
        object: None,
        stub_data: vec![0xAA, 0xBB, 0xCC, 0xDD],
    };
    let request_packet = PduPacket::from_request(9, request.clone());
    let decoded_request = PduPacket::decode(&request_packet.encode().unwrap()).unwrap();
    assert_eq!(decoded_request.header.ptype, PduType::Request);
    assert_eq!(
        RequestPdu::decode(decoded_request.body(), false).unwrap(),
        request
    );

    let response = ResponsePdu {
        alloc_hint: 4,
        ctx_id: 2,
        cancel_count: 0,
        stub_data: vec![0x11, 0x22, 0x33, 0x44],
    };
    let response_packet = PduPacket::from_response(9, response.clone());
    let decoded_response = PduPacket::decode(&response_packet.encode().unwrap()).unwrap();
    assert_eq!(decoded_response.header.ptype, PduType::Response);
    assert_eq!(
        ResponsePdu::decode(decoded_response.body()).unwrap(),
        response
    );

    let fault = FaultPdu {
        alloc_hint: 0,
        ctx_id: 2,
        cancel_count: 0,
        status: 0x1C00_0001,
        stub_data: Vec::new(),
    };
    let fault_packet = PduPacket::from_fault(9, fault.clone());
    let decoded_fault = PduPacket::decode(&fault_packet.encode().unwrap()).unwrap();
    assert_eq!(decoded_fault.header.ptype, PduType::Fault);
    assert_eq!(FaultPdu::decode(decoded_fault.body()).unwrap(), fault);
}

#[test]
fn packet_decode_rejects_fragment_length_mismatches() {
    let mut bytes = PduHeader::new(PduType::Response, PFC_FIRST_FRAG | PFC_LAST_FRAG, 1).encode();
    bytes[8] = 15;

    let err = PduPacket::decode(&bytes).unwrap_err();
    assert_eq!(
        err,
        Error::InvalidPdu("fragment length is smaller than common header")
    );
}

#[test]
fn packet_decode_rejects_auth_length_larger_than_fragment_content() {
    let mut bytes = PduHeader::new(PduType::Response, PFC_FIRST_FRAG | PFC_LAST_FRAG, 1).encode();
    bytes[8..10].copy_from_slice(&16u16.to_le_bytes());
    bytes[10..12].copy_from_slice(&1u16.to_le_bytes());

    let err = PduPacket::decode(&bytes).unwrap_err();

    assert_eq!(err, Error::InvalidPdu("auth length exceeds fragment body"));
}

#[test]
fn packet_round_trips_security_trailer_with_padding_and_auth_value() {
    let trailer = SecurityTrailer {
        auth_type: AuthType::WinNt,
        auth_level: AuthLevel::PacketIntegrity,
        auth_pad_length: 2,
        auth_reserved: 0,
        auth_context_id: 7,
    };
    let packet = PduPacket::with_security_trailer(
        PduHeader::new(PduType::Request, PFC_FIRST_FRAG | PFC_LAST_FRAG, 3),
        vec![0xAA, 0xBB],
        trailer,
        vec![0x11, 0x22, 0x33, 0x44],
    );

    let bytes = packet.encode().unwrap();

    assert_eq!(&bytes[8..10], &32u16.to_le_bytes());
    assert_eq!(&bytes[10..12], &4u16.to_le_bytes());
    assert_eq!(&bytes[20..28], &[10, 5, 2, 0, 7, 0, 0, 0]);
    assert_eq!(&bytes[28..32], &[0x11, 0x22, 0x33, 0x44]);

    let decoded = PduPacket::decode(&bytes).unwrap();
    assert_eq!(decoded.body(), &[0xAA, 0xBB]);
    assert_eq!(decoded.security_trailer(), Some(&trailer));
    assert_eq!(decoded.auth_value(), &[0x11, 0x22, 0x33, 0x44]);
}

#[test]
fn packet_decode_rejects_auth_value_without_complete_security_trailer() {
    let mut bytes = PduHeader::new(PduType::Response, PFC_FIRST_FRAG | PFC_LAST_FRAG, 1)
        .encode()
        .to_vec();
    bytes.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD]);
    let len = bytes.len() as u16;
    bytes[8..10].copy_from_slice(&len.to_le_bytes());
    bytes[10..12].copy_from_slice(&1u16.to_le_bytes());

    let err = PduPacket::decode(&bytes).unwrap_err();

    assert_eq!(
        err,
        Error::InvalidPdu("auth value requires security trailer")
    );
}
