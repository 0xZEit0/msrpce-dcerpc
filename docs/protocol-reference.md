# msrpce-dcerpc Protocol Reference

This crate implements the connection-oriented DCE/RPC layer used by MS-RPCE.

## Implemented PDUs

- common PDU header.
- request.
- response.
- fault.
- bind.
- bind ack.
- bind nak.
- auth3.
- security trailer.

## Bind Flow

Unauthenticated bind:

```text
client -> BIND
server -> BIND_ACK or BIND_NAK
client stores accepted context id
```

Connect-auth bind:

```text
provider creates initial token
client -> BIND + security trailer + auth token
server -> BIND_ACK + optional challenge
provider processes challenge
client -> optional AUTH3
client stores accepted context id and provider
```

## Call Flow

Raw call:

```text
caller provides opnum and request stub bytes
RpcClient builds request PDU
request is fragmented when needed
transport sends fragments
transport receives response or fault
RpcClient reassembles response fragments
caller receives response stub bytes
```

Typed call:

```text
Req: NdrSerialize
Resp: NdrDeserialize
Req -> NDR bytes -> call_raw -> response bytes -> Resp
```

## Presentation Contexts

A presentation context contains:

- context id.
- abstract syntax: interface UUID and version.
- transfer syntax list: usually NDR32 for v1.

The server returns one result per proposed context. The client selects the first
accepted context and reports explicit rejection errors otherwise.

## Auth Wire Constants

Auth levels recognized:

- `None = 0`.
- `Connect = 2`.
- `PacketIntegrity = 5`.
- `PacketPrivacy = 6`.

Auth types recognized:

- `None = 0`.
- `GssNegotiate = 9`.
- `WinNt = 10`.
- `GssKerberos = 16`.

`GssNegotiate`, `PacketIntegrity`, and `PacketPrivacy` are recognized as wire
values but are not active v1 features.

