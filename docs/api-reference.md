# msrpce-dcerpc API Reference

`msrpce-dcerpc` owns the generic DCE/RPC layer. It does not open SMB
connections and does not hardcode Windows RPC interfaces.

## `RpcClient<T>`

Generic DCE/RPC client over any `RpcTransport`.

Constructors:

- `RpcClient::bind(transport, interface)`.
- `RpcClient::bind_with_contexts(transport, contexts)`.
- `RpcClient::bind_with_auth_provider(transport, contexts, target, provider)`.
- `RpcClient::new_bound(transport, context_id)`.
- `RpcClient::new_bound_with_auth(transport, context_id, provider)`.

Calls:

- `call_raw(opnum, request_stub)`.
- `call<Req, Resp>(opnum, request)`.

Accessors:

- `transport()`.
- `transport_mut()`.
- `with_max_xmit_frag(value)`.

## `RpcTransport`

Transport abstraction consumed by `RpcClient`:

```rust
pub trait RpcTransport {
    fn send_pdu(&mut self, bytes: &[u8]) -> msrpce_dcerpc::Result<()>;
    fn recv_pdu(&mut self) -> msrpce_dcerpc::Result<Vec<u8>>;
}
```

Implement this when integrating DCE/RPC with a custom transport.

## `InterfaceId`

Interface UUID and version:

```rust
use msrpce_dcerpc::InterfaceId;
use uuid::Uuid;

let interface = InterfaceId::new(
    Uuid::from_u128(0x367abb81_9844_35f1_ad32_98f038001003),
    2,
    0,
);
```

## `PresentationContext`

Use custom presentation contexts when `RpcClient::bind` is not enough:

```rust
use msrpce_dcerpc::{PresentationContext, TransferSyntax};

let context = PresentationContext::new(
    0,
    interface.syntax_id(),
    vec![TransferSyntax::Ndr32],
);
```

## Authentication Providers

The provider boundary is `RpcAuthProvider`.

Built-in v1 providers:

- `NtlmRpcAuthProvider` behind feature `ntlm`.
- `GssapiKerberosRpcAuthProvider` behind feature `kerberos-gssapi`.

Supported v1 auth levels:

- `AuthLevel::None`.
- `AuthLevel::Connect`.

Explicitly unsupported in v1:

- `AuthLevel::PacketIntegrity`.
- `AuthLevel::PacketPrivacy`.

