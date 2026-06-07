# msrpce-dcerpc Authentication

`msrpce-dcerpc` owns DCE/RPC authentication, not SMB authentication.

## Supported V1 Levels

Supported:

- `AuthLevel::None`.
- `AuthLevel::Connect`.

Unsupported:

- `AuthLevel::PacketIntegrity`.
- `AuthLevel::PacketPrivacy`.

Unsupported levels fail explicitly before sending invalid or unverifiable wire
data.

## NTLM Connect

Enabled by feature `ntlm`.

```rust
use msrpce_dcerpc::{
    AuthLevel, NtlmRpcAuthProvider, PresentationContext, RpcClient, TransferSyntax,
};

let contexts = vec![PresentationContext::new(
    0,
    interface.syntax_id(),
    vec![TransferSyntax::Ndr32],
)];

let auth = NtlmRpcAuthProvider::new("LAB", "Administrator", "password")?
    .with_auth_level(AuthLevel::Connect);

let client = RpcClient::bind_with_auth_provider(
    transport,
    contexts,
    "",
    auth,
)?;
```

NTLM protocol work is delegated to the external `sspi` crate.

## Kerberos Connect

Enabled by feature `kerberos-gssapi`.

```rust
use msrpce_dcerpc::{
    AuthLevel, GssapiKerberosRpcAuthProvider, PresentationContext, RpcClient,
    TransferSyntax,
};

let contexts = vec![PresentationContext::new(
    0,
    interface.syntax_id(),
    vec![TransferSyntax::Ndr32],
)];

let auth = GssapiKerberosRpcAuthProvider::new()?
    .with_auth_level(AuthLevel::Connect);

let client = RpcClient::bind_with_auth_provider(
    transport,
    contexts,
    "host/dc01.lab.local",
    auth,
)?;
```

Kerberos work is delegated to system GSSAPI. This crate does not acquire
tickets, contact a KDC, parse ccache files, or implement Kerberos crypto.

## SPNEGO/Negotiate

The `GssNegotiate` wire value is preserved for decoding, but v1 does not expose
SPNEGO/Negotiate as an active backend.

