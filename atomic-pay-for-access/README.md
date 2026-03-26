# Atomic Pay for Access

Hashlock escrow that atomically settles payment and mints an on-chain access credential in a single transaction. One reveal, one payment, one capability — no separate steps, no race conditions.

Two variants: native ETH (`AtomicPayForAccess.sol`) and ERC20/TIP20 tokens (`AtomicPayForAccessERC20.sol`).

## Deployments

| Chain | Contract | Address |
|-------|----------|---------|
| Base Sepolia | AtomicPayForAccess (ETH) | [`0xBE2026C56bb2651fbbC4052754d9f845f94D4964`](https://sepolia.basescan.org/address/0xBE2026C56bb2651fbbC4052754d9f845f94D4964) |
| Tempo Moderato | AtomicPayForAccessERC20 (PathUSD) | [`0x8C0a28819ccafD65A0227d2D5ed1F237ed406Eb4`](https://explore.tempo.xyz/address/0x8C0a28819ccafD65A0227d2D5ed1F237ed406Eb4) |

## How it works

```
Client                          Provider                    Contract
  |                                |                           |
  |  1. negotiate terms off-chain  |                           |
  |<------------------------------>|                           |
  |                                |                           |
  |  2. depositAndConfigure()      |                           |
  |  (locks ETH/tokens + sets      |                           |
  |   capability params)           |-------------------------->|
  |                                |                           |
  |                                |  3. delivers service      |
  |<-------------------------------|                           |
  |                                |                           |
  |                                |  4. revealAndMint()       |
  |                                |  (reveals preimage,       |
  |                                |   settles payment,        |
  |                                |   mints capability)       |
  |                                |-------------------------->|
  |                                |                           |
  |  capability minted to client   |  payment credited         |
  |<-----------------------------------------------------------|
  |                                |                           |
  |                                |  5. withdraw()            |
  |                                |-------------------------->|
```

1. **Client deposits** funds into a hashlock escrow and pre-registers capability parameters (target contract, function selector, expiry, nonce)
2. **Provider delivers** the service off-chain
3. **Provider reveals** the preimage — in one atomic transaction: payment settles with operator fee split AND an x402 capability is minted to the client
4. **Provider withdraws** their earned payment via pull-payment
5. If the provider never reveals, the **client refunds** after the deadline

## What problem does it solve

Today, paying for access to an API, a gated service, or an agent's capability is a two-step process: first you pay, then you get a credential. The gap between "payment confirmed" and "access granted" is where disputes, race conditions, and user friction live.

**Atomic Pay for Access collapses payment and access into one transaction.** The provider can't take payment without granting access. The client can't get access without paying. There is no in-between state.

Specifically:

- **No trust gap** — the hashlock preimage reveal simultaneously settles payment and mints the access credential. Neither side can cheat the other.
- **No push-payment DoS** — pull-payment pattern means a reverting beneficiary can never block settlement.
- **No credential forgery** — capabilities are scoped to deal ID, chain ID, and contract address. Can't replay across chains or contracts.
- **No permanent credentials** — capabilities have enforced maximum duration (365 days) and the burn sentinel prevents re-minting.
- **No admin keys** — fully permissionless, no owner, no governance, no upgrade path.

## Use cases

### Agent-to-agent payments
An AI agent needs to call another agent's API. It deposits payment, the provider agent does the work, reveals the preimage to claim payment, and the calling agent automatically gets a capability token proving it paid. No invoice system, no webhook, no polling.

### Gated API access
A developer pays for access to a rate-limited endpoint. The payment settles and the API key (as an on-chain capability) is issued atomically. The API server checks `capabilities[capId]` — if the holder matches and the expiry is valid, access is granted.

### Pay-per-use content
A reader pays to unlock a document, dataset, or media file. The provider reveals the decryption key (the preimage) and gets paid in the same transaction. The reader's wallet now holds a capability proving they paid, usable for re-access without re-payment.

### Bounty and task settlement
A client posts a bounty with a hashlock. The worker completes the task and learns the preimage (e.g., by delivering to a known endpoint that reveals it). Revealing the preimage claims the bounty and mints a completion credential — useful for reputation systems.

### x402 payment flows
The HTTP 402 "Payment Required" protocol needs atomic pay-then-access. This contract is the settlement layer: the x402 middleware deposits on behalf of the user, the server reveals after serving the response, and the capability serves as the receipt.

### Operator fee splitting
Marketplaces and platforms take a cut. The operator registers once, then every deal that names them as operator automatically splits fees (up to 50%) on reveal. No separate fee collection, no invoicing — it's built into the settlement.

## Contracts

| File | Description | Bytecode |
|------|-------------|----------|
| `src/AtomicPayForAccess.sol` | Main contract — native ETH escrow + capability minting | 4,471 B |
| `src/AtomicPayForAccessERC20.sol` | ERC20/TIP20 variant for chains without native ETH transfers | — |
| `src/base/SplitClaimHashlock.sol` | Standalone hashlock escrow with fee splitting | 2,758 B |
| `src/base/X402Cap.sol` | Standalone capability registry with authorized minter pattern | 1,549 B |

## Security

- Double-audited: manual audit (14 findings) + [Plamen](https://github.com/PlamenTSV/plamen) core autonomous audit (24 findings, 49 agent files)
- All HIGH, MEDIUM, and actionable LOW findings fixed
- 37 unit tests + 14 ERC20 tests passing
- E2E tested on Base Sepolia and Tempo Moderato
- Pull-payment pattern (no push-payment DoS)
- Burn sentinel `address(1)` prevents re-minting after burn
- `MAX_CAP_DURATION = 365 days` prevents permanent credentials
- capId includes `dealId + block.chainid + address(this)` — no collisions, no cross-chain replay
- CEI (Checks-Effects-Interactions) pattern throughout
- No admin, no proxy, no upgradability

See `AUDIT_REPORT.md` and `AUDIT-REPORT.md` for the full audit reports.

## Build and test

```bash
cd atomic-pay-for-access
forge build
forge test
```

## License

MIT
