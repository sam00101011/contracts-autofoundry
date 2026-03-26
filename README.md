# contracts-autofoundry

Audited smart contract primitives for agent-to-agent payments, capability gating, and streamed settlement. Built with Foundry, tested on testnets, double-audited.

## Contracts

### [atomic-pay-for-access](./atomic-pay-for-access)

Hashlock escrow that atomically settles payment and mints an on-chain access credential in a single transaction. Supports native ETH and ERC20/TIP20 tokens.

**Deployed on:** Base Sepolia, Tempo Moderato

**Use cases:** agent-to-agent payments, gated API access, pay-per-use content, bounty settlement, x402 payment flows, operator fee splitting.

**Security:** Double-audited (manual + [Plamen](https://github.com/PlamenTSV/plamen) autonomous audit), 51 tests passing, E2E verified on-chain.

### [slot-seal](./slot-seal)

Destination-scoped slot receipt primitive for routed work, parallel execution lanes, and paid delivery proofs. A slot is assigned to one assignee for one destination and can only end as completed or reclaimed.

**Deployed on:** Base Sepolia, Tempo Moderato

**Use cases:** routed agent work proofs, destination-scoped batch execution, reclaimable execution slots, x402-style delivery attestations, compact assignment lifecycle receipts.

**Security:** 14 unit tests passing, full intent-hash enforcement, chain-and-contract domain separation, tombstoned reclaim semantics, no admin or upgradability.

## License

MIT
