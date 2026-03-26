# contracts-autofoundry

Audited smart contract primitives for agent-to-agent payments, capability gating, and streamed settlement. Built with Foundry, tested on testnets, double-audited.

## Contracts

### [atomic-pay-for-access](./atomic-pay-for-access)

Hashlock escrow that atomically settles payment and mints an on-chain access credential in a single transaction. Supports native ETH and ERC20/TIP20 tokens.

**Deployed on:** Base Sepolia, Tempo Moderato

**Use cases:** agent-to-agent payments, gated API access, pay-per-use content, bounty settlement, x402 payment flows, operator fee splitting.

**Security:** Double-audited (manual + [Plamen](https://github.com/PlamenTSV/plamen) autonomous audit), 51 tests passing, E2E verified on-chain.

## Origin

These contracts emerged from a tournament-style idea generation process that evaluated 37+ smart contract primitives across 18 rounds, then combined the strongest ideas into integrated protocols. The full tournament archive and ranking methodology are documented separately.

## License

MIT
