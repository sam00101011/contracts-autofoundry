# SlotSeal

Destination-scoped slot receipt primitive for Tempo-style batch execution, routed agent work, and paid delivery proofs. A slot is assigned to one assignee, bound to one destination, and can only terminate as completed or reclaimed.

## Deployments

| Chain | Contract | Address |
|-------|----------|---------|
| Base Sepolia | SlotSeal | [`0x9495147e43f36C2345eebe6F25E957B2C18464A8`](https://sepolia.basescan.org/address/0x9495147e43f36C2345eebe6F25E957B2C18464A8) |
| Tempo Moderato | SlotSeal | [`0x08ed58349dc6419e2b8834165abBB777B8cDc873`](https://explore.tempo.xyz/address/0x08ed58349dc6419e2b8834165abBB777B8cDc873) |

## How it works

```
Issuer                        Assignee                      Contract
  |                              |                            |
  |  1. assign()                 |                            |
  |  (destination, nonce,        |                            |
  |   expiry, intentHash)        |--------------------------->|
  |                              |                            |
  |                              |  2. performs routed work   |
  |                              |                            |
  |                              |  3. complete()             |
  |                              |  (same destination +       |
  |                              |   matching completion hash)|
  |                              |--------------------------->|
  |                              |                            |
  |  completion badge available  |                            |
  |<----------------------------------------------------------|
  |                              |                            |
  |  4. reclaim() after expiry   |                            |
  |  if unfinished               |--------------------------->|
```

1. **Issuer assigns** a slot to one assignee for one destination, with a nonce, expiry, and full intent hash.
2. **Assignee completes** before expiry, but only if the submitted completion hash matches the assigned intent.
3. **Issuer reclaims** after expiry if the slot was never completed.
4. **Reclaimed slots are tombstoned** and cannot be silently reused.

The slot id is deterministic and domain-separated by `block.chainid`, `address(this)`, issuer, assignee, destination, and nonce.

## What problem it solves

Most off-chain task and payment flows can prove that something happened, but not that a specific executor was assigned work for a specific destination under a specific scoped identity.

SlotSeal makes that lifecycle explicit:
- who was assigned
- where the work was supposed to go
- when the assignment expired
- whether it completed or lapsed

Useful for:
- routed agent work proofs
- batch execution lanes with destination scope
- paid delivery / x402-style attestation rails
- escrows and settlement systems that need a tiny assignment-complete-reclaim primitive
- parallel execution systems that must safely reclaim stale slots

## Security

- assignee-gated completion
- issuer-gated reclaim
- completion must match the assigned intent hash
- slot ids and badges are domain-separated by chain and contract
- reclaimed slots are tombstoned and non-reusable
- no owner, no admin, no upgradability
- no value custody in the primitive itself

## Contracts

| File | Description | Bytecode |
|------|-------------|----------|
| `src/SlotSeal.sol` | Destination-scoped slot lifecycle primitive | 1,243 B |

## Build and test

```bash
cd slot-seal
forge build
forge test
```

## License

MIT
