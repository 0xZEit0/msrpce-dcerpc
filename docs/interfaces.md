# Interfaces And Typed Calls

`msrpce-dcerpc` does not hardcode Windows RPC interfaces. Callers provide:

- interface UUID.
- major/minor version.
- opnum.
- request/response NDR structs.

## Interface Identity

```rust
use msrpce_dcerpc::InterfaceId;
use uuid::Uuid;

let svcctl = InterfaceId::new(
    Uuid::from_u128(0x367abb81_9844_35f1_ad32_98f038001003),
    2,
    0,
);
```

## Raw Calls

```rust
let response_stub = client.call_raw(0, &request_stub)?;
```

Use raw calls for golden-wire tests, early protocol work, or already-encoded
request stubs.

## Typed Calls

Typed calls use `msrpce-ndr`:

```rust
use msrpce_ndr::{NdrDeserialize, NdrSerialize};

#[derive(NdrSerialize)]
struct Request {
    level: u32,
}

#[derive(NdrDeserialize)]
struct Response {
    return_code: u32,
}

let response: Response = client.call(0, &Request { level: 100 })?;
```

The meaning of opnum `0` is interface-specific and remains caller-owned.

