# High-Level DCE/RPC API

The highest-level API currently available for real Windows/AD calls is
`msrpce_smb::NcacnNpClient`.

That may look surprising from the `msrpce-dcerpc` crate, but it is intentional
for v1: `NcacnNpClient` combines DCE/RPC with the concrete `ncacn_np`
transport, and `ncacn_np` means SMB named pipes. Keeping this facade in
`msrpce-smb` avoids a circular dependency where `msrpce-dcerpc` would need to
depend on the SMB crate that already depends on it.

Use this API for normal client code.

## NTLM

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

## Kerberos

Kerberos uses system GSSAPI. The process must already have a valid credential
cache:

```sh
export KRB5_CONFIG=/path/to/msrpce-krb5.conf
export KRB5CCNAME=FILE:/path/to/Administrator.ccache
```

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
    .server("dc01.lab.local")
    .pipe("svcctl")
    .kerberos()
    .rpc_auth(RpcAuth::KerberosConnect)
    .rpc_auth_target("host/dc01.lab.local")
    .bind(svcctl)?;

let response_stub = client.call_raw(0, &[])?;
let _ = response_stub;
Ok(())
}
```

## Typed Calls

`NcacnNpClient` forwards to `msrpce-dcerpc` for typed calls:

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

fn example<T>(client: &mut msrpce_smb::NcacnNpClient<T>) -> msrpce_dcerpc::Result<()>
where
    T: std::io::Read + std::io::Write,
{
let response: Response = client.call(0, &Request { level: 100 })?;
let _ = response;
Ok(())
}
```

## Crate Boundary

The dependency direction is:

```text
msrpce-smb -> msrpce-dcerpc -> msrpce-ndr
```

So:

- `msrpce-dcerpc` owns generic DCE/RPC behavior.
- `msrpce-smb` owns SMB named pipes and exposes the concrete high-level
  `ncacn_np` facade.
- `msrpce-ndr` owns NDR payload encoding.

If a future transport such as TCP is added, it can have its own facade without
changing the generic `RpcClient` core.

