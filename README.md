# KelpDAO-294m-PoC

>**Loss** **116,500 rsETH**
>
>| Artifact | Value |
>|---|---|
>| Ethereum attack tx | [`0x1ae232da…db4222`](https://etherscan.io/tx/0x1ae232da212c45f35c1525f851e4c41d529bf18af862d9ce9fd40bf709db4222) |
>| Attack block | `24,908,285` (pre-state captured at `24,908,284`) |
>| GUID (nonce 308) | `0x3f4510d855cf3a805fec59daafae640d290749b7bf1e5450f91b5fb0018b3b4e` |
>| GUID (nonce 309) | `0x19073f141ef29ea2eb2c52046e60942a928b2106651e622b73c68e27c969cfe6` |
>| Raw message (n=308) | `0x0000…8b1b6c9a6db1304000412dd21ae6a70a82d60d3b` ‖ `0x0000001b1ff0ed00` |
>| `amountSD` (6 dec) | `0x1b1ff0ed00` = `116,500,000,000,000` → **116,500 rsETH** in 18 dec |

---

## Summary

attacker obtained the signature of the single required DVN for the Kelp Unichain → Ethereum `rsETH` path and used it to commit a **forged LayerZero packet** on the Ethereum destination endpoint, the packet instructed the Kelp OFT adapter to release **116,500 rsETH** to an attacker-controlled address.

no transaction was ever sent on Unichain, the source outbound nonce never advanced past `307`, `totalSupply` on Unichain was unchanged, and there were no `Transfer` events on the source token during the attack window yet the destination endpoint accepted the message as `nonce=308` and executed delivery, the destination adapter released real user deposits from its custody balance.

second forged packet (`nonce=309`, 40,000 rsETH) was committed to the same destination endpoint and remained claimable until the token/adapter blacklisted the recipient with `TransfersBlocked(...)` shortly after the first drain.

fundamental enabling misconfiguration is a **single DVN required with no optional DVN threshold** on both directions of the path, a compromise or bug in that lone verifier is catastrophic by design.

---

## LayerZero V2 OFT path

LayerZero V2 splits cross-chain messaging into three agents

- **OApp / OFT** on each chain (source burns or locks tokens, destination mints or releases).
- **DVN(s)** — Decentralized Verifier Networks, each configured DVN independently signs the payload hash observed on the source chain and commits it to the destination receive library.
- **Executor** — a permissionless actor that pays gas to call `EndpointV2.lzReceive` on the destination once a packet's hash has been committed.

security model is quorum-based: delivery requires

```
requiredDVNCount signatures + optionalDVNCount ≥ optionalDVNThreshold
```

OApp owner, not LayerZero chooses which DVNs are trusted and how many

## Lock-and-release on the Ethereum side

Kelp OFT **Adapter** on Ethereum (`0x85d4…8Ef3`) is not a mint/burn OFT it is a **lock-and-release adapter** wrapped around the existing `rsETH` ERC20. When a user bridges `Ethereum → Unichain`, their `rsETH` is transferred into the adapter and a message instructs Unichain to mint, on the return leg (`Unichain → Ethereum`), the adapter releases `rsETH` from its locked inventory.

this makes the adapter a **pooled custody contract** for all Ethereum-side Kelp users who have ever bridged out, a single fraudulent release drains from this shared pool, not from the attacker.

## Ethereum endpoint authorization model

`EndpointV2.lzReceive(Origin, receiver, guid, message, extraData)` has **no executor authorization**, any EOA may call it, the only gate is

```solidity
require(
    _inboundPayloadHash[receiver][srcEid][sender][nonce]
        == keccak256(abi.encodePacked(guid, message))
);
```

payload hash is set earlier by the DVN via `ReceiveUln.commitVerification` when quorum is reached, **Once the hash is committed, execution is effectively unconditional.**

---

## Configuration finding 1-of-1 DVN on both ends

on-chain `getConfig(configType=2)` reads for the exact Kelp OApp path returned

// Source side (Unichain)

- `sendLibrary` = `0xC39161c743D0307EB9BCc9FEF03eeb9Dc4802de7`
- `confirmations = 42`
- `requiredDVNCount = 1`
- `optionalDVNCount = 0`
- `optionalDVNThreshold = 0`
- `requiredDVNs = [0x282b3386571f7f794450d5789911a9804fa346b4]`

// Destination side (Ethereum)

- `receiveLibrary` = `0xc02Ab410f0734EFa3F14628780e6e695156024C2`
- `confirmations = 42`
- `requiredDVNCount = 1`
- `optionalDVNCount = 0`
- `optionalDVNThreshold = 0`
- `requiredDVNs = [0x589dedbd617e0cbcb916a9223f4d1300c294236b]`

route is therefore **effectively 1-of-1**, a single verifier failure key compromise, signing bug, misconfigured source chain RPC feeding the DVN, or any equivalent is sufficient to forge arbitrary packets on this route.

---

## 116,500 rsETH release was not backed by a source-side send

// Nonce discontinuity

| Endpoint query | Value |
|---|---|
| `Endpoint(Eth).lazyInboundNonce(adapter, 30320, srcSender)` (post-attack) | `308` |
| `Endpoint(Uni).outboundNonce(srcToken, 30101, adapter)` | **`307`** |

legitimate send would advance the source outbound nonce to `≥ 308`, It did not.

## Source-chain supply and log check

>Unichain `rsETH.totalSupply()`:
>
>| Block | totalSupply |
>|---|---|
>| `45,785,275` | `49.259532 rsETH` |
>| `45,785,276` (LZ Scan creation block for nonce 308) | `49.259532 rsETH` |
>| `45,785,277` | `49.259532 rsETH` |
>| `45,786,000` | `49.259532 rsETH` |

no change during the attack window, and the total supply (~49 rsETH) is smaller than the claimed bridge amount by a factor of ~2,300× a legitimate burn/lock of 116,500 rsETH on Unichain is physically impossible.

`eth_getLogs` for the source token over the relevant block window returned **zero** `Transfer` events and **zero** burns to `0x0`.

## Control case `nonce 307`

previous nonce on this exact path is a clean control, Its source tx on Unichain (`0x32877156…7d778`) emits the canonical OFT debit-and-burn pattern:

```
Transfer(user → adapter,  0.006 rsETH)
Transfer(adapter → 0x0,   0.006 rsETH)
```

and its `amountSD = 0x1770 = 6000` matches the Ethereum-side release of exactly `0.006 rsETH`, the infrastructure clearly works as designed when a real user initiates a send the nonce-308 packet did not come from that path.

---

## Attack TX decomposition

Ethereum tx `0x1ae232da…db4222` (block `24,908,285`) is a **single call** to `EndpointV2.lzReceive`. Decoded call tree

```
EndpointV2.lzReceive(
    Origin{ srcEid: 30320, sender: 0x…c3eacf…9f58, nonce: 308 },
    receiver = 0x85d4…8Ef3              // Kelp OFT adapter
    guid     = 0x3f4510…3b4e,
    message  = 0x0000…8b1b…0D3b ‖ 0x0000001b1ff0ed00,
    extraData = 0x
)
└── KelpOFTAdapter.lzReceive(...)
    ├── rsETH.transfer(0x8B1b…0D3b, 116_500e18)
    │     └── delegatecall → rsETH impl
    │          emit Transfer(adapter → recipient, 116_500e18)
    └── emit OFTReceived(guid, recipient, amountSD=0x7670, amountLD=0x18ab7a47948bcfd00000)
```

## Payload disass

OFT message layout is `bytes32 recipient || uint64 amountSD`:

- `recipient` = `0x8B1b6c9A6DB1304000412dd21Ae6A70a82d60D3b`
- `amountSD` = `0x1b1ff0ed00 = 116,500,000,000,000` in shared decimals (6)
- `amountLD = amountSD × 10^(18 − 6) = 116,500 × 10^18`

endpoint `_clearPayload` confirms `keccak256(guid ‖ message) == inboundPayloadHash`, zeroes the hash slot, then invokes the adapter.

gas used by the whole attack tx: **94,456**.

---

## step by step

- **DVN signs a fabricated packet.** unique required DVN commits a payload hash for `(srcEid=30320, sender=Unichain-OFT, nonce=308, guid=0x3f45…, message=<recipient ‖ amountSD>)`. No corresponding send ever occurred on Unichain.
- **`ReceiveUln.commitVerification`** writes the hash to `EndpointV2._inboundPayloadHash[adapter][30320][srcSender][308]`.
- **Attacker (or any EOA) calls `lzReceive`.** endpoint's only check is hash equality, which passes.
- **Adapter's `lzReceive`** decodes the OFT message and calls `rsETH.transfer(recipient, 116_500e18)` from its own custody balance.
- **116,500 rsETH move out** of the shared custody pool into the attacker address.
- **`_clearPayload` zeroes the hash** and bumps `lazyInboundNonce` to `308`, further masking the anomaly from naive monitors.

there is no reentrancy, no integer bug, no reentrant signature replay, no MEV leverage, it is a pure **verification-path trust failure**.

---

## second packet `nonce 309` corroboration

same DVN committed a second packet (`guid=0x19073f…9cfe6`, `amountSD=40,000,000,000` → 40,000 rsETH). On Ethereum

```
Endpoint.inboundPayloadHash(adapter, 30320, srcSender, 309)
  = 0xbf86af6f10782715c263b7c76c86e7a965b29f2a0119806ea4eb108d197e0c7e
```

Two executor attempts to deliver it failed

- `0x8509533a…83e53` — revert
- `0x48d9b3e8…65d792` — revert

`eth_call` replay of the first failed attempt reverts with

```
TransfersBlocked(0x8B1b6c9A6DB1304000412dd21Ae6A70a82d60D3b, 2026-04-19 18:23:11 UTC)
```

Adapter inventory at those blocks was ~40,357 rsETH enough to cover 40,000, **The failure was not inventory-related.** Kelp had flipped a blacklist/pause affecting that recipient after observing the first drain, the fact that the packet was verified and that its delivery could only be stopped by an app-level blacklist not by the endpoint or the DVN confirms the verification path itself was the compromised layer.

---

## Root cause

proximate, evidence-supported cause is **single-DVN verification failure**, the class of failure fits any of

- **DVN key compromise.** A leaked/stolen signer key would let an attacker produce valid signatures for arbitrary `(guid, nonce, message)` tuples on this route.
- **Faulty DVN off-chain pipeline.** A verifier that accepts work items without genuinely reading the source-chain block/log the way the protocol requires (e.g., a broken or spoofed RPC feed).
- **OApp/DVN mis-binding.** If the source and destination DVN configurations were not coherent, verification semantics break regardless of key custody.

**root architectural cause** is Kelp OApp configuration: `1 required DVN + 0 optional DVNs + threshold 0`, LayerZero documented best practice is "at least two required DVNs, plus an optional-DVN threshold ≥ 1." A 1-of-1 route has no defense-in-depth against any of the three failure modes above.

## Why the lock-and-release adapter amplified the loss

Because the Ethereum side is an adapter over an existing ERC20 (not a mint/burn OFT), the stolen funds are real user deposits `totalSupply` on Ethereum is **unchanged** the attack is economically a theft from the shared custody pool, not an inflationary mint, every user whose `rsETH` sat in the adapter at the attack block is pro-rata exposed until Kelp socializes or recovers.

---

## output

```
Fork block            : 24908284
Token                 : rsETH rsETH

0xf79a27bb975e38a484124e6f31aad957397b6760a15e522241cd4c372663fef4
lazyInboundNonce(308) : 307

recipient (0x8b1b..)  : 0
adapter   (0x85d4..)  : 116723520635500000000000        # 116,723.52 rsETH
rsETH totalSupply     : 629736447879606340903548

payload hash == keccak256(guid|message) : OK

recipient (0x8b1b..)  : 116500000000000000000000        # 116,500.00 rsETH
adapter   (0x85d4..)  : 223520635500000000000           #     223.52 rsETH
rsETH totalSupply     : 629736447879606340903548        # UNCHANGED

stolen to recipient   : 116500000000000000000000 wei
stolen (rsETH whole)  : 116500
drained from adapter  : 116500 rsETH
totalSupply changed?  : false

0x0000000000000000000000000000000000000000000000000000000000000000   # cleared
```

## Appendix A (raw calldata)

```
lzReceive calldata:
  origin.srcEid  = 30320                                              # Unichain
  origin.sender  = 0x000000000000000000000000c3eacf061234...858716db09f58
  origin.nonce   = 308
  receiver       = 0x85d456B2DfF1fd8245387C0BfB64Dfb700e98Ef3          # Kelp adapter
  guid           = 0x3f4510d855cf3a805fec59daafae640d290749b7bf1e5450f91b5fb0018b3b4e
  message        = 0x0000000000000000000000008b1b6c9a6db1304000412dd21ae6a70a82d60d3b
                   ‖ 0x0000001b1ff0ed00
  extraData      = 0x
```

---

## References

- Attack tx: <https://etherscan.io/tx/0x1ae232da212c45f35c1525f851e4c41d529bf18af862d9ce9fd40bf709db4222>
- LayerZero Scan (nonce 308): <https://scan.layerzero-api.com/v1/messages/guid/0x3f4510d855cf3a805fec59daafae640d290749b7bf1e5450f91b5fb0018b3b4e>
- LayerZero Scan (nonce 309): <https://scan.layerzero-api.com/v1/messages/guid/0x19073f141ef29ea2eb2c52046e60942a928b2106651e622b73c68e27c969cfe6>
- LayerZero V2 integration checklist: <https://docs.layerzero.network/v2/tools/integration-checklist>
- LayerZero DVN overview: <https://docs.layerzero.network/v2/workers/off-chain/dvn-overview>
- Control case source tx (nonce 307, Unichain): <https://uniscan.xyz/tx/0x32877156a2d7d186f3a43c8365b1743fb7eff84bd94b8ef2688702ba1447d778>
- Control case destination tx (nonce 307, Ethereum): <https://etherscan.io/tx/0xc232af35a6c98c92fdb0b08675e93d678994c2c97d31e133f909e0cb95960211>
