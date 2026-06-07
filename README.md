# msrpce-dcerpc

Generic connection-oriented MS-RPCE client primitives for Rust.

This crate owns the RPC layer only: PDU encode/decode, bind negotiation,
request/response calls, the `RpcTransport` boundary, and RPC authentication
token exchange. It does not hardcode LSARPC, SAMR, SVCCTL, WKSSVC, or other
Windows interfaces. Interface stubs are expected to live in downstream code or
future optional crates and use `msrpce-ndr` for stub encoding.

For the recommended real-world Windows/AD workflow over `ncacn_np`, start with
`msrpce-smb::NcacnNpClient`. That is the highest-level DCE/RPC API currently
available because `ncacn_np` is concretely SMB named pipes. Use this crate
directly when you need the lower-level RPC state machine, custom transports,
custom presentation contexts, or protocol tests.

## Version 1 Scope

- Connection-oriented DCE/RPC PDUs.
- Generic bind with one or more presentation contexts.
- Generic `call_raw(opnum, stub)` and typed `call<Req, Resp>()` using
  `msrpce-ndr`.
- `ncacn_np` transport adapter over named-pipe-like I/O.
- RPC auth levels `None` and `Connect`.
- NTLM RPC auth provider through the external `sspi` crate.
- Kerberos RPC auth provider through system GSSAPI.

Packet signing and sealing (`PacketIntegrity`, `PacketPrivacy`) are intentionally
not part of v1. Asking for those levels returns an explicit unsupported error
instead of silently emitting invalid wire data.

## Features

- `ntlm` or `ntlm-sspi`: enables `NtlmRpcAuthProvider`.
- `kerberos-gssapi` or `gssapi`: enables `GssapiKerberosRpcAuthProvider`.
- `tracing`: enables internal tracing spans/logs.
- `live-tests`: reserved for live integration tests.

The short feature names are preferred for new code. The older names are kept as
compatibility aliases.

## Core Types

- `RpcClient<T>`: bound or bindable DCE/RPC client over a `RpcTransport`.
- `RpcTransport`: transport trait used by the RPC state machine.
- `InterfaceId`: interface UUID plus major/minor version.
- `PresentationContext`: abstract syntax plus transfer syntaxes.
- `TransferSyntax`: currently NDR32 and NDR64 identifiers.
- `AuthLevel`: DCE/RPC auth levels.
- `RpcAuthProvider`: provider boundary for RPC auth token exchange.
- `NtlmRpcAuthProvider`: RPC NTLM Connect provider when `ntlm` is enabled.
- `GssapiKerberosRpcAuthProvider`: RPC Kerberos Connect provider when
  `kerberos-gssapi` is enabled.

## Recommended High-Level API

For normal client code, use the `NcacnNpClient` facade from `msrpce-smb`:

```rust
use msrpce_dcerpc::InterfaceId;
use msrpce_smb::{NcacnNpClient, RpcAuth};
use uuid::Uuid;

fn example() -> msrpce_dcerpc::Result<()> {
let svcctl = InterfaceId::new(
    Uuid::from_u128(0x367abb81_9844_35f1_ad32_98f038001003),
    2,
    0,
);

let mut client = NcacnNpClient::builder()
    .host("192.168.122.10")
    .server("DC01")
    .pipe("svcctl")
    .ntlm("LAB", "Administrator", "password")
    .rpc_auth(RpcAuth::NtlmConnect)
    .bind(svcctl)?;

let response_stub = client.call_raw(0, &[])?;
let _ = response_stub;
Ok(())
}
```

See [High-Level DCE/RPC API](docs/high-level-api.md).

## Generic Bind

```rust
use msrpce_dcerpc::{InterfaceId, RpcClient};
use uuid::Uuid;

fn example<T: msrpce_dcerpc::RpcTransport>(transport: T) -> msrpce_dcerpc::Result<()> {
let interface = InterfaceId::new(
    Uuid::from_u128(0x6bffd098_a112_3610_9833_46c3f87e345a),
    1,
    0,
);

let mut client = RpcClient::bind(transport, interface)?;
let response_stub = client.call_raw(0, &[])?;
let _ = response_stub;
Ok(())
}
```

## Custom Presentation Contexts

Use `bind_with_contexts` when a server needs multiple contexts or a transfer
syntax other than the default helper.

```rust
use msrpce_dcerpc::{InterfaceId, PresentationContext, RpcClient, TransferSyntax};
use uuid::Uuid;

fn example<T: msrpce_dcerpc::RpcTransport>(transport: T) -> msrpce_dcerpc::Result<()> {
let interface = InterfaceId::new(
    Uuid::from_u128(0x367abb81_9844_35f1_ad32_98f038001003),
    2,
    0,
);
let contexts = vec![PresentationContext::new(
    0,
    interface.syntax_id(),
    vec![TransferSyntax::Ndr32],
)];

let _client = RpcClient::bind_with_contexts(transport, contexts)?;
Ok(())
}
```

## RPC Auth Connect

```rust
#[cfg(feature = "ntlm-sspi")]
fn example<T: msrpce_dcerpc::RpcTransport>(transport: T) -> msrpce_dcerpc::Result<()> {
use msrpce_dcerpc::{
    AuthLevel, InterfaceId, NtlmRpcAuthProvider, PresentationContext, RpcClient,
    TransferSyntax,
};
use uuid::Uuid;

let interface = InterfaceId::new(
    Uuid::from_u128(0x6bffd098_a112_3610_9833_46c3f87e345a),
    1,
    0,
);
let contexts = vec![PresentationContext::new(
    0,
    interface.syntax_id(),
    vec![TransferSyntax::Ndr32],
)];
let auth = NtlmRpcAuthProvider::new("LAB", "Administrator", "password")?
    .with_auth_level(AuthLevel::Connect);

let _client = RpcClient::bind_with_auth_provider(transport, contexts, "host/dc01.lab.local", auth)?;
Ok(())
}
```

## Typed Calls

Typed calls serialize `Req` and deserialize `Resp` with `msrpce-ndr`.

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

fn example<T: msrpce_dcerpc::RpcTransport>(
    client: &mut msrpce_dcerpc::RpcClient<T>,
) -> msrpce_dcerpc::Result<()> {
let response: Response = client.call(0, &Request { level: 100 })?;
let _ = response;
Ok(())
}
```

## More Documentation

- [API Reference](docs/api-reference.md)
- [High-Level DCE/RPC API](docs/high-level-api.md)
- [Protocol Reference](docs/protocol-reference.md)
- [Authentication](docs/authentication.md)
- [Interfaces and Typed Calls](docs/interfaces.md)
