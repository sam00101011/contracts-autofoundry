# Security Audit Report — Atomic Pay For Access

**Date**: 2026-03-26
**Auditor**: Automated Security Analysis (Claude Opus 4.6)
**Scope**: Three contracts (369 lines total): `AtomicPayForAccess` (main), `SplitClaimHashlock` (base hashlock), `X402Cap` (base capability registry)
**Language/Version**: Solidity ^0.8.13
**Build Status**: Compiled successfully
**Static Analysis Status**: Slither unavailable; grep-based static analysis performed

---

## Executive Summary

Atomic Pay For Access is a three-contract Solidity system implementing a hashlock-based payment protocol with on-chain capability credential minting. The core design uses a commit-reveal escrow pattern: a depositor locks ETH against a hash commitment, a beneficiary reveals the preimage to trigger payment settlement, and a capability credential is simultaneously minted into an on-chain registry (`X402Cap`) as proof of paid access. The system is fully decentralized — no admin roles, no governance, no owner — making all access control emergent from the protocol's own logic.

The audit identified five High-severity findings, one Medium-severity finding, eleven Low-severity findings, and seven Informational findings. The most critical issues center on `X402Cap`, which can be used as a standalone capability registry with no payment gate: `X402Cap.mint()` is entirely permissionless, allowing anyone to mint credentials for arbitrary amounts and tokens at zero cost. This single root cause enables two compound High-severity attack chains — zero-cost cross-chain credential forgery (exploiting the absence of chain-binding in `capId` computation) and zero-cost persistent access (exploiting the absence of on-chain expiry enforcement after minting). The `SplitClaimHashlock` base contract also contains a direct fund-loss vulnerability where `feeBps = 10000` (100%) is accepted, causing a beneficiary who reveals the preimage to receive zero ETH while the operator receives the full deposit.

The most urgent remediation priorities are: (1) add a payment gate or authorization control to `X402Cap.mint()`; (2) bind the `X402Cap` `capId` computation to `block.chainid` and `address(this)`; (3) fix the off-by-one boundary error in `SplitClaimHashlock.deposit()` that permits 100% fees. The remaining findings are largely design-level issues — no on-chain expiry enforcement after minting, unbounded capability expiry, and a burn-remint recycling pattern that allows off-chain revocation to be contradicted — which should be addressed before production deployment or carefully documented as intentional design constraints for consumers.

---

## Summary

| Severity | Count |
|----------|-------|
| Critical | 0 |
| High | 5 |
| Medium | 1 |
| Low | 11 |
| Informational | 7 |
| **Total** | **24** |

### Components Audited

| Component | Path | Lines | Description |
|-----------|------|-------|-------------|
| `AtomicPayForAccess` | `AtomicPayForAccess.sol` | ~220 | Main contract: hashlock escrow with capability minting |
| `SplitClaimHashlock` | `SplitClaimHashlock.sol` | ~97 | Base hashlock contract with split fee logic |
| `X402Cap` | `X402Cap.sol` | ~52 | Standalone capability registry for payment proofs |

---

## High Findings

### [H-01] SplitClaimHashlock Allows 100% Fee — Beneficiary Reveals Preimage for Zero Payment [VERIFIED]

**Severity**: High
**Location**: `SplitClaimHashlock.sol:L45`; fee calculation at `SplitClaimHashlock.sol:L73-L74`
**Confidence**: HIGH (5 agents confirmed, Static Analysis: N/A, PoC: PASS)

**Description**:

The `SplitClaimHashlock.deposit()` function validates the fee parameter with a strict greater-than check that permits `feeBps = 10000` (100%), causing the beneficiary to receive zero ETH upon revealing the preimage.

```solidity
// SplitClaimHashlock.sol:L41-L47
function deposit(
    bytes32 id,
    bytes32 hash,
    address beneficiary,
    address operator,
    uint32 deadline,
    uint16 feeBps
) external payable {
    if (
        msg.value == 0 ||
        msg.value > type(uint96).max ||
        beneficiary == address(0) ||
        feeBps > 10_000 ||          // @audit: allows feeBps == 10000 (100%)
        deadline <= block.timestamp
    ) revert InvalidDeposit();
```

When `feeBps = 10000`, the reveal calculation at L73-L74 computes:

```solidity
uint256 fee = uint256(d.amount) * d.feeBps / 10_000;  // fee = amount * 10000 / 10000 = amount
balances[d.beneficiary] += uint256(d.amount) - fee;     // beneficiary gets 0
```

The beneficiary performs their obligation (revealing the secret preimage) but receives nothing. The operator receives 100% of the deposited funds. This is a classic off-by-one boundary error: the validation uses `>` instead of `>=`.

Note that the integrated `AtomicPayForAccess.sol` is NOT affected — it caps `feeBps` at `MAX_FEE_BPS = 5000` with the same strict greater-than check (`feeBps > MAX_FEE_BPS`), making the maximum effective fee 49.99%. This finding applies exclusively to the standalone `SplitClaimHashlock` base contract.

**Impact**:

A malicious depositor can create a deal with `feeBps = 10000` and a colluding operator. The beneficiary, who must reveal the preimage to collect payment, receives 0 ETH while the operator receives the full deposit amount. This constitutes direct fund loss for the beneficiary. For a 1 ETH deposit, the beneficiary receives 0 wei and the operator receives the full 1 ETH.

**PoC Result**:

Three Foundry tests executed successfully:
- `test_H1_feeBps10000_beneficiaryReceivesZero`: Deposited 1 ETH with `feeBps=10000`. After reveal, beneficiary `withdraw()` reverted with `NoBalance`. Operator withdrew the full 1 ETH (1,000,000,000,000,000,000 wei).
- `test_H1_feeBps10001_isRejected`: Confirmed `feeBps=10001` is correctly rejected by the validation.
- `test_H1_feeBps9999_beneficiaryReceivesSomething`: Confirmed `feeBps=9999` correctly gives the beneficiary a non-zero payment (100,000,000,000,000 wei).

Evidence tag: [POC-PASS]

**Recommendation**:

Change the validation from strict greater-than to greater-than-or-equal, or align with `AtomicPayForAccess`'s stricter cap:

```solidity
// Option 1: Prevent 100% fee
- feeBps > 10_000 ||
+ feeBps >= 10_000 ||

// Option 2: Align with AtomicPayForAccess (recommended)
+ uint16 private constant MAX_FEE_BPS = 5_000;
  ...
- feeBps > 10_000 ||
+ feeBps > MAX_FEE_BPS ||
```

---

### [H-02] X402Cap mint() Is Permissionless — Anyone Mints Capability Credentials Without Payment [VERIFIED]

**Severity**: High
**Location**: `X402Cap.sol:L14-L29`
**Confidence**: HIGH (5 agents confirmed, Static Analysis: N/A, PoC: PASS)

**Description**:

The `X402Cap.mint()` function has no payment enforcement whatsoever. Any address can call it with arbitrary parameters and receive a stored capability entry in `capabilities[capId]` without making any payment. The `amount` and `token` parameters are used solely as hash inputs for the `capId` — they are never validated against an actual transfer.

```solidity
// X402Cap.sol:L14-L29
function mint(
    uint256 amount,
    address token,
    uint256 nonce,
    uint256 expiry,
    address target,
    bytes4  selector
) external returns (bytes32 capId) {
    if (block.timestamp > expiry) revert Expired();
    capId = keccak256(abi.encode(
        msg.sender, amount, token, nonce, expiry, target, selector
    ));
    if (capabilities[capId] != address(0)) revert AlreadyMinted();
    capabilities[capId] = msg.sender;    // @audit: no payment check
    emit Minted(capId, msg.sender, target, selector, expiry);
}
```

There is no `payable` modifier, no `msg.value` check, no ERC20 `transferFrom`, and no callback to any payment contract. An attacker can declare `amount = 1 ether` and `token = USDC` in the capId hash while paying nothing. Any off-chain or on-chain system that checks `capabilities[capId] != address(0)` as proof of payment is completely bypassed.

Note that `AtomicPayForAccess.sol` mitigates this by minting capabilities only through `revealAndMint()`, which requires a valid hashlock escrow deal with actual ETH deposit. This finding applies to `X402Cap` used as a standalone contract.

**Impact**:

Complete access control bypass for any system consuming X402Cap capabilities as proof of payment. An attacker can forge credentials for any service, any amount, any token, at zero cost. Multiple attackers can independently mint capabilities without any payment, undermining the entire value proposition of the capability registry as a payment proof system. This is the root cause enabling two additional High-severity chain attacks: H-04 (Zero-Cost Cross-Chain Credential Forgery) and H-05 (Zero-Cost Persistent Access).

**PoC Result**:

Two Foundry tests executed successfully:
- `test_H2_permissionless_mint_no_payment`: Attacker minted a capability declaring 1 ETH amount while spending 0 ETH. `capabilities[capId]` returned the attacker's address.
- `test_H2_multiple_attackers_mint_freely`: Three separate attackers each minted capabilities with zero payment, confirming the attack scales without cost.

Evidence tag: [POC-PASS]

**Recommendation**:

Add a payment gate to `X402Cap.mint()`. The simplest approach is to require the function to be called only by a trusted payment contract:

```solidity
// Option 1: Restrict mint to authorized payment contracts
+ mapping(address => bool) public authorizedMinters;
+ modifier onlyAuthorized() {
+     require(authorizedMinters[msg.sender], "Unauthorized");
+     _;
+ }

- function mint(...) external returns (bytes32 capId) {
+ function mint(...) external onlyAuthorized returns (bytes32 capId) {

// Option 2: Require msg.value to match declared amount (for ETH)
+ function mint(...) external payable returns (bytes32 capId) {
+     require(msg.value == amount, "Payment mismatch");
```

---

### [H-03] X402Cap capId Lacks Chain and Contract Binding — Cross-Chain Replay [VERIFIED]

**Severity**: High
**Location**: `X402Cap.sol:L23-L25`
**Confidence**: HIGH (3 agents confirmed, Static Analysis: N/A, PoC: PASS)

**Description**:

The `X402Cap.capId()` computation omits both `block.chainid` and `address(this)` from the hash, making capability identifiers identical across all X402Cap deployments on all EVM chains.

```solidity
// X402Cap.sol:L23-L25
capId = keccak256(abi.encode(
    msg.sender, amount, token, nonce, expiry, target, selector
    // @audit: missing block.chainid and address(this)
));
```

In contrast, `AtomicPayForAccess.sol` correctly includes both fields:

```solidity
// AtomicPayForAccess.sol:L158-L159
capId = keccak256(abi.encode(
    depositor, id, uint256(d.amount), address(0), cc.nonce, cc.expiry,
    cc.target, cc.selector, block.chainid, address(this)  // chain-bound
));
```

When `X402Cap` is deployed on multiple chains (or at multiple addresses on the same chain), the same caller with the same parameters produces a byte-identical `capId` on every deployment. A capability minted on one chain is structurally valid on all others.

**Impact**:

An attacker can mint a capability on the cheapest available chain (e.g., a low-fee L2 or testnet) and the resulting `capId` is valid for verification on any other X402Cap deployment. Off-chain services or cross-chain bridges that check `capabilities[capId]` from one deployment can be deceived by a mint from a different chain. This effectively turns a single-chain capability into a multi-chain credential without additional cost.

**PoC Result**:

Foundry test deployed two separate `X402Cap` instances and compared capIds:
- Chain A (chainid 31337): capId = `0x8d2c986040ac20f82ae422597651460c3022427993db265527909016c04c412e`
- Chain B (chainid 42161): capId = `0x8d2c986040ac20f82ae422597651460c3022427993db265527909016c04c412e` (identical)
- Contrast test confirmed `AtomicPayForAccess` produces different capIds per chain.

Evidence tag: [POC-PASS]

**Recommendation**:

Include `block.chainid` and `address(this)` in the capId computation:

```solidity
capId = keccak256(abi.encode(
-   msg.sender, amount, token, nonce, expiry, target, selector
+   msg.sender, amount, token, nonce, expiry, target, selector, block.chainid, address(this)
));
```

Update the `capId()` view function similarly to accept and include chain and contract parameters.

---

### [H-04] Zero-Cost Cross-Chain Credential Forgery via Free Mint and Missing Chain Binding [VERIFIED]

**Severity**: High
**Location**: `X402Cap.sol:L14-L29` (permissionless mint), `X402Cap.sol:L23-L25` (missing chain binding)
**Confidence**: HIGH (2 confirmed component findings chained, PoC: PASS)

**Description**:

This finding describes a compound attack combining H-02 (X402Cap Permissionless Mint) with H-03 (X402Cap capId Cross-Chain Replay). Together, these two vulnerabilities enable systematic zero-cost credential forgery across all chains where X402Cap is deployed.

The complete attack sequence:

1. The attacker identifies the cheapest available X402Cap deployment (any L2, sidechain, or testnet).
2. The attacker calls `X402Cap.mint(amount=1 ether, token=USDC, nonce=0, expiry=MAX, target=serviceAddr, selector=targetSelector)` with zero payment. The function has no payment gate (see H-02), so this succeeds.
3. `capabilities[capId] = attacker` is recorded on the cheap chain. The `capId` is computed as `keccak256(abi.encode(attacker, 1 ether, USDC, 0, MAX, serviceAddr, targetSelector))`.
4. Because the hash omits `block.chainid` and `address(this)` (see H-03), the identical `capId` is structurally valid on every other X402Cap deployment.
5. The attacker calls `mint()` on all target chains with the same parameters. Each call succeeds at zero payment cost.
6. Any off-chain service checking `capabilities[capId] != address(0)` on any chain concludes the attacker has paid for access.
7. The attacker gains credentials for all services across all chains without any payment.

Neither H-02 nor H-03 alone produces this full attack surface. H-02 alone defeats payment on a single chain. H-03 alone allows legitimate (paid) credentials to replay across chains. Combined, the attacker pays nothing and gains credentials everywhere simultaneously.

**Impact**:

Systematic zero-cost multi-chain credential forgery. Any service that uses X402Cap as a standalone payment proof registry is completely bypassed on all chains. The attacker can forge credentials for arbitrary amounts and arbitrary tokens (e.g., declaring 100 USDC payment while paying 0). The blast radius scales with the number of X402Cap deployments.

**PoC Result**:

Two Foundry tests confirmed the chain:
- `test_CH2_cross_chain_capId_collision`: Deployed two X402Cap instances, minted with identical parameters. Both produced capId `0xe9bfe636da5196169b7e88195c2fd6ad0a3255ddc14524feed6460741f47363d` — byte-identical across deployments.
- `test_CH2_contrast_with_AtomicPayForAccess`: Confirmed X402Cap capId has no chain-specific binding while AtomicPayForAccess includes `block.chainid`.

Evidence tag: [POC-PASS]

**Recommendation**:

Fix both root causes:
1. Add a payment gate to `X402Cap.mint()` (see H-02 recommendation)
2. Add `block.chainid` and `address(this)` to the capId hash (see H-03 recommendation)

Both fixes are required. Adding only the chain binding still allows free credentials on each individual chain. Adding only the payment gate still allows legitimate credentials to replay across chains.

---

### [H-05] Zero-Cost Persistent Access via Free Credential and No On-Chain Expiry Enforcement [VERIFIED]

**Severity**: High
**Location**: `X402Cap.sol:L14-L29` (permissionless mint), `X402Cap.sol:L22` (expiry check only at mint time), `X402Cap.sol:L5` (no expiry in storage mapping)
**Confidence**: HIGH (2 confirmed component findings chained, PoC: PASS)

**Description**:

This finding describes a compound attack combining H-02 (X402Cap Permissionless Mint) with L-01 (No On-Chain Expiry Enforcement). Together, these vulnerabilities allow an attacker to obtain permanent free access to any service that checks the X402Cap registry for credential validity without independently verifying expiry.

The complete attack sequence:

1. The attacker calls `X402Cap.mint(amount=1, token=0xFakeToken, nonce=0, expiry=block.timestamp+1, target=service, selector=0xDEADBEEF)` with zero payment (see H-02).
2. `capabilities[capId] = attacker` is stored. The `capId` hash encodes `expiry=block.timestamp+1`.
3. One block later, the capability is "expired" by its hash parameters.
4. However, `capabilities[capId]` still returns the attacker's address. The X402Cap registry enforces expiry only at mint time (`L22: if (block.timestamp > expiry) revert Expired()`). After minting, no function checks or clears expired entries.

```solidity
// X402Cap.sol:L22 -- expiry checked ONLY here, at mint time
if (block.timestamp > expiry) revert Expired();
// ...
capabilities[capId] = msg.sender;  // L27 -- persists indefinitely
```

5. A consumer contract or off-chain service that checks `capabilities[capId] != address(0)` without reconstructing the capId to verify its encoded expiry sees a valid holder indefinitely.
6. The attacker gains persistent service access at zero cost.
7. The attack is repeatable: the attacker can re-mint with fresh expiry values at zero cost, always appearing "recently valid" to services that do parse capId components.

The `capabilities` mapping (L5) stores only `bytes32 => address` with no separate expiry field:

```solidity
mapping(bytes32 => address) public capabilities;  // no expiry stored
```

Consumers must reconstruct the full capId from all its component fields (including expiry) and compare — a non-trivial requirement that is easy to omit.

**Impact**:

Complete bypass of both payment and temporal access control for any service using X402Cap with a naive registry-presence check. The attacker pays nothing and gains indefinite access. This is particularly dangerous because X402Cap is designed as a trust-minimized registry for off-chain services — naive consumers performing only `capabilities[capId] != address(0)` checks are the likely primary deployment pattern.

**PoC Result**:

Two Foundry tests confirmed the chain:
- `test_CH3_capability_persists_after_expiry`: Minted a capability with short expiry, then warped time forward 2 hours and 1 year past expiry. The `capabilities[capId]` mapping returned the attacker's address at all time points — unchanged.
- `test_CH3_expiry_boundary`: Confirmed that even `expiry=block.timestamp` (the tightest possible expiry) allows minting, and the capability persists after that moment.

Evidence tag: [POC-PASS]

**Recommendation**:

Fix the root cause (H-02) by adding a payment gate to `X402Cap.mint()`. Additionally, consider one of the following approaches for expiry enforcement:

```solidity
// Option 1: Store expiry separately and check on read
mapping(bytes32 => address) public capabilities;
+ mapping(bytes32 => uint256) public capabilityExpiry;

function mint(...) external returns (bytes32 capId) {
    // ... existing logic ...
    capabilities[capId] = msg.sender;
+   capabilityExpiry[capId] = expiry;
}

+ function isValid(bytes32 capId) external view returns (bool) {
+     return capabilities[capId] != address(0) &&
+            block.timestamp <= capabilityExpiry[capId];
+ }

// Option 2: Provide a convenience function that validates expiry
+ function verifyCapability(
+     address payer, uint256 amount, address token, uint256 nonce,
+     uint256 expiry, address target, bytes4 selector
+ ) external view returns (bool) {
+     bytes32 id = keccak256(abi.encode(payer, amount, token, nonce, expiry, target, selector));
+     return capabilities[id] != address(0) && block.timestamp <= expiry;
+ }
```

Fixing H-02 alone eliminates the "zero-cost" aspect. Adding expiry enforcement eliminates the "persistent" aspect for all consumers regardless of their implementation sophistication.

---

## Medium Findings

### [M-01] Permanent Phantom Capability — Burn-Remint with Infinite Expiry Bypasses Off-Chain Revocation [VERIFIED]

**Severity**: Medium
**Location**: `AtomicPayForAccess.sol:L106`, `AtomicPayForAccess.sol:L157-165`, `AtomicPayForAccess.sol:L196-201`
**Confidence**: HIGH (2 agents confirmed component findings independently, chain verified with [POC-PASS]; see also L-02 and L-08 for the underlying root causes)

**Description**:

`AtomicPayForAccess` allows a depositor to set `capExpiry = type(uint256).max` when calling `depositAndConfigure()`. The only expiry validation at L106 is:

```solidity
if (capExpiry == 0 || block.timestamp > capExpiry) revert InvalidCapConfig();
```

`type(uint256).max` satisfies both conditions — it is non-zero and approximately year 584 billion — so it passes without error. The resulting capability stored in `capabilities[capId]` is effectively permanent: no code path in the contract ever evaluates the expiry after minting.

Separately, the `burnCapability()` function at L196-201 removes a capability from the registry using `delete`:

```solidity
function burnCapability(bytes32 capId) external {
    address holder = capabilities[capId];
    if (holder != msg.sender) revert NotHolder();
    delete capabilities[capId];
    emit CapabilityBurned(capId, msg.sender);
}
```

After `delete`, the slot returns to `address(0)`. The `AlreadyMinted` guard in `revealAndMint()` at L161 is:

```solidity
if (capabilities[capId] != address(0)) revert AlreadyMinted();
```

Since the slot is now `address(0)`, this check passes and the same `capId` can be re-minted. Because `capId` is deterministic — derived from a fixed set of deal parameters including `depositor`, `id`, `amount`, `nonce`, `expiry`, `target`, `selector`, `block.chainid`, and `address(this)` — a depositor who reuses the same deal parameters produces the identical `capId` every time.

The combination creates a reliable cycle: mint with `capExpiry = type(uint256).max` → burn (generating a `CapabilityBurned` event that off-chain systems interpret as permanent revocation) → recreate the deal with the same parameters → reveal again (re-minting the same `capId` with the same infinite expiry). The `CapabilityBurned` event provides no finality. Any off-chain system that treats `CapabilityBurned` as a terminal signal will have its revocation record contradicted by a subsequent `CapabilityMinted` event for the same `capId`.

**Complete Attack Sequence**:

1. Depositor calls `depositAndConfigure(id, hash, beneficiary, operator, deadline, feeBps, capTarget, capSelector, type(uint256).max, capNonce)` — the `capExpiry = type(uint256).max` value passes the L106 validation with no upper bound check.
2. Beneficiary calls `revealAndMint()` — payment is settled, `capabilities[capId] = depositor` is written with the permanent expiry baked into the deterministic `capId` hash.
3. Depositor calls `burnCapability(capId)` — `delete capabilities[capId]` resets the slot to `address(0)`. A `CapabilityBurned` event is emitted. Off-chain monitoring systems and service backends record the `capId` as permanently revoked.
4. Depositor calls `depositAndConfigure()` again with the same parameters (same `id`, same `capExpiry = type(uint256).max`, same all other fields). The deal can be recreated because `delete deals[depositor][id]` was executed during the original `revealAndMint()`.
5. Beneficiary calls `revealAndMint()` again — `capabilities[capId] == address(0)` so the `AlreadyMinted` check passes, and `capabilities[capId] = depositor` is re-written. A second `CapabilityMinted` event is emitted for the same `capId`.
6. The off-chain revocation record now contradicts on-chain state: the `capId` is marked revoked in the service backend but is live and permanently valid on-chain.
7. The depositor can repeat this cycle indefinitely. Each cycle requires a second payment (the deal amount), so this is not zero-cost — but the cost is the price of regaining access that the service provider believed was permanently revoked.

**Impact**:

Service providers and backend systems that use `CapabilityBurned` events to cut off a depositor's access cannot rely on those events as final. A depositor who has been "burned" from a service can restore their credential at will by paying the deposit amount again, producing a `CapabilityMinted` event for a `capId` the service considers permanently revoked. The permanent expiry (`type(uint256).max`) ensures the re-minted credential will never age out naturally, compounding the revocation bypass.

Concretely: if a service uses an off-chain revocation list indexed by `capId` and populated from `CapabilityBurned` events, a depositor can evade that list indefinitely as long as they are willing to keep paying. The protocol's burn mechanism provides no access-termination guarantee.

**PoC Result**:

Test `test_CH1_PermanentPhantomCapabilityChain()` — compiled and executed on first attempt, 0 failures.

```
[PASS] test_CH1_PermanentPhantomCapabilityChain() (gas: 371920)
Logs:
  === CH-1: Permanent Phantom Capability Chain ===
  Step 1 - Initial mint (MAX expiry). Holder: 0x00000000000000000000000000000000000000C1
  Step 2 - Capability burned. Holder: 0x0000000000000000000000000000000000000000
  Step 3 - Re-minted. Same capId: true
  Re-minted holder: 0x00000000000000000000000000000000000000C1
  Step 4 - Holder 200 years later: 0x00000000000000000000000000000000000000C1
  CH-1: CONFIRMED - burn event is not final; capability is permanently recyclable
```

The test confirms: (1) a capability with `type(uint256).max` expiry is accepted by the contract; (2) after burn the slot returns to `address(0)`; (3) re-minting with identical parameters produces the same `capId`; (4) the re-minted capability remains active 200 years later.

**Recommendation**:

Address both root causes independently. This finding is broken by fixing either one, but fixing both provides defense in depth.

*For the unbounded expiry (see L-02)*: Add a maximum expiry upper bound in `depositAndConfigure()`:

```solidity
uint256 constant MAX_CAP_DURATION = 365 days; // or protocol-chosen value

// In depositAndConfigure(), replace the existing expiry check:
if (capExpiry == 0 || block.timestamp > capExpiry) revert InvalidCapConfig();
// With:
if (capExpiry == 0 || block.timestamp > capExpiry) revert InvalidCapConfig();
if (capExpiry > block.timestamp + MAX_CAP_DURATION) revert InvalidCapConfig();
```

*For the burn-remint cycle*: Rather than deleting the capabilities slot on burn, mark it as permanently revoked with a sentinel value (e.g., `address(1)`) that is distinct from both `address(0)` (never minted) and any real holder address:

```solidity
address private constant BURNED = address(1);

function burnCapability(bytes32 capId) external {
    address holder = capabilities[capId];
    if (holder != msg.sender) revert NotHolder();
    capabilities[capId] = BURNED;          // sentinel: burned, not re-mintable
    emit CapabilityBurned(capId, msg.sender);
}
```

Update the `AlreadyMinted` check in `revealAndMint()` to reject both active and burned slots:

```solidity
// Replace:
if (capabilities[capId] != address(0)) revert AlreadyMinted();
// With:
if (capabilities[capId] != address(0)) revert AlreadyMinted(); // covers active + BURNED sentinel
```

With `BURNED = address(1)`, the existing check `!= address(0)` already covers the sentinel without requiring a separate error type. This ensures that once a `capId` is burned, neither the original depositor nor any other address can re-mint it, making `CapabilityBurned` events reliable as permanent revocation signals.

---

## Low Findings

### [L-01] No On-Chain Expiry Enforcement After Capability Minting [UNVERIFIED]

**Severity**: Low
**Location**: `AtomicPayForAccess.sol:L157-165`, `X402Cap.sol:L14-29`
**Confidence**: LOW (2 agents confirmed, design-level issue, impact depends on consumer behavior)

**Description**:
When a capability is minted — either via `AtomicPayForAccess.revealAndMint()` or `X402Cap.mint()` — the on-chain registry stores only the holder's address: `capabilities[capId] = depositor`. The capability's expiry is encoded as a field inside the `capId` hash, which prevents tampering, but is never written to a separately queryable storage slot. Once minted, the registry entry `capabilities[capId]` persists indefinitely with no automatic cleanup, no expiry-aware accessor, and no mechanism to distinguish a time-valid capability from a time-expired one using the mapping alone.

A consumer that performs a registry-presence check (`capabilities[capId] != address(0)`) without reconstructing the full `capId` from its constituent fields — including `expiry` — cannot detect that a capability has expired. The protocol's `computeCapId()` helper exists for this purpose, but correct off-chain usage requires the consumer to know all original minting parameters and reconstruct the hash independently.

This is a design-level delegation: expiry enforcement is the consumer's responsibility. The risk materializes when consumers implement naive registry lookups without expiry reconstruction, which is the most common pattern in off-chain integration. See H-05 for the compounded risk when this finding combines with the permissionless minting vulnerability.

**Impact**:
Off-chain consumers performing registry-presence checks without expiry reconstruction will accept expired capabilities as valid. For time-limited access grants (hourly, daily), expired credentials remain permanently queryable as "active" with no on-chain signal that they have lapsed. The practical consequence is that expired capabilities become equivalent to permanent ones from a registry lookup perspective.

**Recommendation**:
Document the consumer verification requirement explicitly in NatSpec and deployment notes: consumers MUST verify expiry by (a) knowing all original capability parameters, (b) recomputing `capId` using `computeCapId()` or an equivalent off-chain hash, and (c) checking that `block.timestamp <= expiry`. Consider adding an `isValid(bytes32 capId, uint256 expiry) external view` helper that performs this check on-chain to reduce integration surface error.

---

### [L-02] capExpiry Unbounded — Single Payment Grants Permanent Capability [UNVERIFIED]

**Severity**: Low
**Location**: `AtomicPayForAccess.sol:L106`, `AtomicPayForAccess.sol:L121`
**Confidence**: MEDIUM (1 agent, boundary evidence with concrete value substitution)

**Description**:
The `depositAndConfigure()` function validates `capExpiry` with two checks at line 106: `capExpiry == 0` (reject zero) and `block.timestamp > capExpiry` (reject already-expired). There is no upper bound validation and no required relationship between `capExpiry` and the deal's `deadline`. A depositor may set `capExpiry = type(uint256).max`, which corresponds to approximately year 584 billion.

```solidity
// AtomicPayForAccess.sol:L106
if (capExpiry == 0 || block.timestamp > capExpiry) revert InvalidCapConfig();
```

With `capExpiry = type(uint256).max`, a single deposit and reveal produces a capability that is, for all practical purposes, permanent. The stored `CapConfig.expiry` value is encoded into the `capId` hash and later written to the `CapabilityMinted` event, but no runtime check prevents unbounded values. See M-01 for the compounded risk when this finding combines with the burn-remint recycling pattern.

**Impact**:
A depositor making a single payment receives a capability that never expires organically. If the protocol intends time-limited access grants, the absence of an upper bound means the time limit is purely advisory. Any `burnCapability()` call remains the only revocation path, and as described in M-01, burn is reversible via re-deposit.

**Recommendation**:
Add a `MAX_CAP_EXPIRY` constant (e.g., 365 days from deposit) and validate: `capExpiry > block.timestamp + MAX_CAP_EXPIRY → revert InvalidCapConfig()`. Alternatively, enforce `capExpiry <= deadline` to tie the capability lifetime to the escrow commitment period, ensuring the payer cannot receive permanent access from a time-bounded payment.

---

### [L-03] capId Encoding Divergence Between AtomicPayForAccess and X402Cap [UNVERIFIED]

**Severity**: Low
**Location**: `AtomicPayForAccess.sol:L158-159`, `X402Cap.sol:L23-24`
**Confidence**: LOW (3 agents, schema analysis — no production verification)

**Description**:
`AtomicPayForAccess` and `X402Cap` use structurally incompatible `capId` encoding schemas. The `AtomicPayForAccess` schema uses 10 fields — including `depositor`, `dealId`, `amount`, a hardcoded `address(0)` token placeholder, `nonce`, `expiry`, `target`, `selector`, `block.chainid`, and `address(this)` — while `X402Cap` uses 7 fields: `msg.sender`, `amount`, `token`, `nonce`, `expiry`, `target`, `selector`.

```solidity
// AtomicPayForAccess.sol:L158-159 — 10-field schema
capId = keccak256(abi.encode(
    depositor, id, uint256(d.amount), address(0), cc.nonce, cc.expiry,
    cc.target, cc.selector, block.chainid, address(this)
));

// X402Cap.sol:L23-24 — 7-field schema
capId = keccak256(abi.encode(
    msg.sender, amount, token, nonce, expiry, target, selector
));
```

A capId produced by `AtomicPayForAccess.revealAndMint()` can never match any capId produced by `X402Cap.mint()` for the same logical access parameters, regardless of parameter alignment. Additionally, `computeCapId()` in `AtomicPayForAccess` implicitly encodes `address(0)` for token and the current `block.chainid` and `address(this)` for contract binding — these three fields are invisible in the function signature, making off-chain reconstruction error-prone.

**Impact**:
Any off-chain system or integration layer that attempts to cross-verify capabilities between the two contracts will always fail. Tooling that uses `X402Cap.capId()` as a universal capability calculator will produce incorrect results for capabilities minted via `AtomicPayForAccess`. Documentation does not warn of this incompatibility.

**Recommendation**:
Document the schema divergence explicitly in NatSpec for both `computeCapId()` and `X402Cap.capId()`. If interoperability is a protocol goal, harmonize the schemas or provide a conversion function. At minimum, add a comment to `computeCapId()` listing all 10 encoding fields — including the implicit `address(0)`, `block.chainid`, and `address(this)` — so off-chain callers can replicate the computation exactly.

---

### [L-04] Fee Truncation to Zero for Dust Deposits (Integer Division) [UNVERIFIED]

**Severity**: Low
**Location**: `AtomicPayForAccess.sol:L147`, `SplitClaimHashlock.sol:L73`
**Confidence**: MEDIUM (3 agents, boundary/variation/trace evidence)

**Description**:
Both `AtomicPayForAccess.revealAndMint()` and `SplitClaimHashlock.reveal()` compute the operator fee using integer division:

```solidity
// AtomicPayForAccess.sol:L147 / SplitClaimHashlock.sol:L73
uint256 fee = uint256(d.amount) * d.feeBps / 10_000;
```

For deposits where `amount * feeBps < 10_000`, integer division truncates the result to zero. For example, a deposit of 9 wei with `feeBps = 1000` (10%) computes `9 * 1000 / 10_000 = 0`. The operator receives no fee despite a configured non-zero basis point rate.

ETH conservation is preserved: the full `amount` is distributed between `beneficiaryAmount` and `fee`, so the beneficiary receives the full dust amount when fee truncates to zero. However, the operator's fee expectation is silently violated without error, event distinction, or documentation.

**Impact**:
Operators accepting dust deposits receive zero fee despite a non-zero `feeBps` configuration. This is self-limiting in practice — dust amounts are economically insignificant — but the truncation is silent and may cause accounting discrepancies in operator tooling that models expected fee revenue. There is no minimum deposit validation that would prevent dust deposits from being created.

**Recommendation**:
Consider documenting the truncation behavior in NatSpec and specifying the minimum economically meaningful deposit for a given `feeBps`. Alternatively, add a minimum deposit check: `if (fee == 0 && feeBps != 0) revert InvalidDeposit()` to prevent operator expectation mismatch. Accept as-is if dust deposits are out of scope by design.

---

### [L-05] Operator Deregistration After Deposit Still Earns Fees [UNVERIFIED]

**Severity**: Low
**Location**: `AtomicPayForAccess.sol:L70-73`, `AtomicPayForAccess.sol:L100-103`
**Confidence**: MEDIUM (2 agents, trace evidence)

> **Note**: This behavior is within the operator's stated permissions. The operator voluntarily self-registers and self-deregisters. Fee collection on pre-existing deals is a natural consequence of the operator's prior registration.

**Description**:
Operator registration is validated only at deposit time. When a depositor calls `depositAndConfigure()`, the contract checks `registeredOperators[operator]` at line 102. At reveal time (`revealAndMint()`), no re-check of operator registration occurs — the deal struct's stored `operator` address receives the fee regardless of whether that address subsequently called `setOperatorRegistration(false)`.

```solidity
// AtomicPayForAccess.sol:L100-103 — checked at deposit only
if (feeBps != 0) {
    if (operator == address(0)) revert InvalidOperator();
    if (!registeredOperators[operator]) revert UnregisteredOperator();
}

// AtomicPayForAccess.sol:L147-152 — no registration re-check at reveal
uint256 fee = uint256(d.amount) * d.feeBps / 10_000;
balances[d.beneficiary] += beneficiaryAmount;
if (fee != 0) { balances[d.operator] += fee; }
```

An operator who deregisters after deals reference them continues to accumulate fee credits in `balances[operator]` for all pre-existing deals until their deadlines pass.

**Impact**:
Deregistered operators continue earning fees on open deals. From a depositor's perspective, the deal terms were set at deposit time and cannot be changed — this is by design. The practical concern is that off-chain tooling showing operator deregistration events may mislead observers into believing the operator no longer participates in fee flows. No funds are at risk; the operator receives fees they were contracted to receive when the deal was created.

**Recommendation**:
Document this behavior in NatSpec for `setOperatorRegistration()`: "Deregistration prevents new deal creation referencing this operator but does not affect fee collection on existing deals." If snapshot-at-deregistration semantics are desired, add a `deregisteredAt` timestamp and check it at reveal time.

---

### [L-06] Zero Hash Deal Is Permanently Unrevealable Until Deadline [UNVERIFIED]

**Severity**: Low
**Location**: `AtomicPayForAccess.sol:L91-97`, `SplitClaimHashlock.sol:L41-47`
**Confidence**: LOW (2 agents — both locations confirmed the pattern, no production verification)

**Description**:
Both `AtomicPayForAccess.depositAndConfigure()` and `SplitClaimHashlock.deposit()` accept `hash = bytes32(0)` without error. The deposit validation blocks only on `msg.value == 0`, value overflow, zero beneficiary, fee bounds, and deadline timing — there is no `hash != bytes32(0)` guard.

```solidity
// AtomicPayForAccess.sol:L91-97 — no hash != bytes32(0) check
if (
    msg.value == 0 ||
    msg.value > type(uint96).max ||
    beneficiary == address(0) ||
    feeBps > MAX_FEE_BPS ||
    deadline <= block.timestamp
) revert InvalidDeposit();
```

At reveal time, the check `keccak256(abi.encodePacked(preimage)) != d.hash` will never pass when `d.hash = bytes32(0)`, because `keccak256` has no preimage that produces the all-zero output. The depositor's ETH is locked until the deal deadline, after which `refund()` becomes callable.

A related consequence: if `revealAndMint()` is used and the `capExpiry` has been set in `capConfigs`, the capability is never minted because the deal can never be revealed. The depositor loses both the payment and the capability they intended to receive, recovering only via refund after the deadline.

**Impact**:
Depositors who accidentally or programmatically pass `hash = bytes32(0)` have their ETH locked until the deal deadline with no reveal path. In `AtomicPayForAccess`, the additionally-configured `capConfigs` entry is also permanently abandoned. The deal cannot be refunded early — the depositor must wait for `block.timestamp > deadline`.

**Recommendation**:
Add `hash == bytes32(0) → revert InvalidDeposit()` to the validation block in both `depositAndConfigure()` and `SplitClaimHashlock.deposit()`. This is a one-line guard that prevents the "permanent lock until deadline" failure mode at zero cost.

---

### [L-07] SplitClaimHashlock Has Zero Event Coverage Across All Operations [UNVERIFIED]

**Severity**: Low
**Location**: `SplitClaimHashlock.sol:L29-97` (all five state-modifying functions)
**Confidence**: LOW (confirmed by 8 independent agent findings, but impact is observability-only)

**Description**:
`SplitClaimHashlock` declares no events and emits none. All five state-modifying operations — `setOperatorRegistration()`, `deposit()`, `reveal()`, `refund()`, and `withdraw()` — execute without producing any log entry.

| Function | State Change | Event Emitted |
|----------|-------------|---------------|
| `setOperatorRegistration(bool)` | `registeredOperators[msg.sender]` | None |
| `deposit(...)` | `deals[depositor][id]` created | None |
| `reveal(...)` | `deals` deleted, `balances` credited | None |
| `refund(bytes32)` | `deals` deleted, `balances` credited | None |
| `withdraw()` | `balances[msg.sender]` zeroed, ETH transferred | None |

The contrast with `AtomicPayForAccess` is stark: the parent contract emits `DealDeposited`, `DealRevealed`, `DealRefunded`, `Withdrawal`, `OperatorRegistration`, `CapabilityMinted`, and `CapabilityBurned`. `SplitClaimHashlock` emits nothing.

ETH withdrawals via `withdraw()` at line 94 are particularly significant — fund movements with no event log are unmonitorable via standard event subscription methods. Off-chain indexers, dispute-resolution tooling, and monitoring systems relying on log-based state reconstruction have zero signal from this contract's entire lifecycle.

**Impact**:
Any off-chain system using `SplitClaimHashlock` directly (rather than through `AtomicPayForAccess`) has no event-based observability for deposits, claims, refunds, or withdrawals. This affects: audit trails for dispute resolution, real-time monitoring for anomalous activity, subgraph/indexer state reconstruction, and operator tooling that models fee accrual.

**Recommendation**:
Add events matching the `AtomicPayForAccess` schema (or a subset appropriate to `SplitClaimHashlock`'s role as a base contract). At minimum: emit on `deposit()` (deal id, depositor, amount, deadline), `reveal()` (deal id, beneficiary amount, fee), `refund()` (deal id, amount), and `withdraw()` (account, amount).

```solidity
event Deposited(address indexed depositor, bytes32 indexed id, uint96 amount, uint32 deadline);
event Revealed(address indexed depositor, bytes32 indexed id, uint256 beneficiaryAmount, uint256 fee);
event Refunded(address indexed depositor, bytes32 indexed id, uint96 amount);
event Withdrawn(address indexed account, uint256 amount);
```

---

### [L-08] Preimage Reuse Across Deals Causes Timing Control Loss [UNVERIFIED]

**Severity**: Low
**Location**: `AtomicPayForAccess.sol:L138`, `SplitClaimHashlock.sol:L69`
**Confidence**: MEDIUM (1 depth agent, trace and variation evidence)

**Description**:
Neither `AtomicPayForAccess` nor `SplitClaimHashlock` enforces hash uniqueness across deals. A depositor may create multiple deals — potentially across different depositor accounts — all sharing the same `hash` value. The protocol stores hashes in a mapping keyed by `(depositor, dealId)`, so the same hash is legally stored in multiple deal entries.

When the beneficiary reveals preimage `p` for any one of these deals, the preimage `p` becomes publicly visible on-chain in the transaction calldata at line 138 (`revealAndMint`) and line 69 (`reveal`). From that moment, any party can call reveal on all remaining deals that use the same hash, forcing settlement of all of them simultaneously regardless of the original depositor's intent.

```solidity
// AtomicPayForAccess.sol:L138 — preimage exposed in calldata
if (keccak256(abi.encodePacked(preimage)) != d.hash) revert BadPreimage();
```

The depositor loses control over the timing and sequencing of reveals for all same-hash deals. If the depositor intended to use the same secret for staggered deliveries — for example, releasing access to multiple users in sequence — a single reveal by any beneficiary discloses the key to all others.

**Impact**:
Multi-deal schemes using a shared preimage lose reveal timing control after the first reveal. All pending deals with the same hash are immediately revealable by any party who observed the first reveal's calldata. This is a subtle operational risk for depositors who reuse secrets across escrow relationships, particularly in programmatic or templated deal creation flows.

**Recommendation**:
Document that each deal should use a unique preimage. Consider adding a protocol-level note discouraging hash reuse. If enforced uniqueness is desired, a `usedHashes` mapping can prevent registering the same hash twice within the same contract, though this restricts some intentional patterns (broadcast delivery).

---

### [L-09] capExpiry=block.timestamp Accepted — Capability Born Already Expired [UNVERIFIED]

**Severity**: Low
**Location**: `AtomicPayForAccess.sol:L106`
**Confidence**: MEDIUM (1 depth agent, boundary evidence with concrete value substitution)

**Description**:
The capability expiry validation at line 106 uses a strict greater-than comparison:

```solidity
// AtomicPayForAccess.sol:L106
if (capExpiry == 0 || block.timestamp > capExpiry) revert InvalidCapConfig();
```

When `capExpiry == block.timestamp` (equal, not strictly greater), the check passes and the deposit succeeds. However, reveal must occur at a strictly later block, at which point `block.timestamp > capExpiry` is already true. The resulting capability has an expiry that is already in the past at the moment of minting.

The boundary `capExpiry == block.timestamp` represents a capability whose valid window is exactly zero blocks — it is expired before the reveal transaction can even be included in the next block. A depositor who sets `capExpiry` to the current block's timestamp (a natural boundary value in many programmatic flows) receives a capability that consumers correctly treating expiry as `block.timestamp <= capExpiry` will immediately reject.

**Impact**:
Depositors who set `capExpiry = block.timestamp` spend ETH (the deposit amount) to mint a capability that is expired upon arrival. No funds are lost to third parties — the depositor can still refund if the reveal is not claimed — but the capability minted at reveal time is useless. Error discovery requires off-chain monitoring; the contract provides no signal that the minted capability is already expired.

**Recommendation**:
Change the validation to use strict greater-than with a minimum buffer, or change the equality boundary: `if (capExpiry == 0 || block.timestamp >= capExpiry) revert InvalidCapConfig()`. A one-character change from `>` to `>=` at L106 closes the born-expired boundary condition.

---

### [L-10] Return Data Gas Bomb in withdraw() — Malicious Recipient OOG [UNVERIFIED]

**Severity**: Low
**Location**: `AtomicPayForAccess.sol:L191`, `SplitClaimHashlock.sol:L94`
**Confidence**: LOW (1 agent, boundary evidence — self-inflicted, no impact on third parties)

**Description**:
Both `withdraw()` implementations use a low-level call to transfer ETH to `msg.sender`:

```solidity
// AtomicPayForAccess.sol:L191
(bool ok,) = msg.sender.call{value: amount}("");
if (!ok) revert EthTransferFailed();

// SplitClaimHashlock.sol:L94
(bool ok,) = msg.sender.call{value: amount}("");
```

When the recipient is a smart contract whose `receive()` or `fallback()` function returns a large data payload, the EVM allocates memory for `RETURNDATASIZE` bytes even though the return data is discarded (the return value is captured as `(bool ok,)` with no bytes variable). Memory expansion cost scales quadratically with the return data size. A recipient that returns, for example, 1 MB of data would cause the caller's transaction to consume substantially more gas than a standard ETH transfer estimate.

This is a self-inflicted risk: only the transaction sender (the recipient of the withdrawal) bears the extra gas cost. No other users, no contract state, and no third-party funds are affected.

**Impact**:
A smart contract that calls `withdraw()` with an exact gas estimate may receive an out-of-gas revert if its own `receive()`/`fallback()` returns unexpected return data. This affects only the caller's own gas accounting and cannot be weaponized against other protocol participants. In practice, EOA withdrawals are unaffected. Smart contract wallets with unexpectedly large return data in their receive hooks may need to increase gas estimates.

**Recommendation**:
Accept as-is given the self-inflicted, zero-third-party-impact nature of this finding. For documentation purposes, note in NatSpec that callers with smart contract recipients should account for potential return data expansion costs when estimating gas. Alternatively, use assembly to limit returndata copying: `assembly { ok := call(gas(), recipient, amount, 0, 0, 0, 0) }`.

---

### [L-11] capSelector Accepts Zero Value — Capability for Undefined Function [UNVERIFIED]

**Severity**: Low
**Location**: `AtomicPayForAccess.sol:L86`, `AtomicPayForAccess.sol:L120`; `X402Cap.sol:L18`, `X402Cap.sol:L23`
**Confidence**: LOW (1 agent, boundary evidence)

**Description**:
Neither `AtomicPayForAccess.depositAndConfigure()` nor `X402Cap.mint()` validates that the `capSelector` / `selector` parameter is non-zero. A depositor or minter may pass `bytes4(0)`, which corresponds to a null function selector — a value that does not map to any real function in any standard contract.

```solidity
// AtomicPayForAccess.sol:L86, L120 (capSelector stored into CapConfig.selector, then encoded into capId)
// X402Cap.sol:L18, L23 (selector parameter encoded into capId hash)
capId = keccak256(abi.encode(
    msg.sender, amount, token, nonce, expiry, target, selector  // selector may be bytes4(0)
));
```

The resulting `capId` encodes `selector = bytes4(0)`. A consumer checking `capabilities[capId]` for access to a specific function would need to reconstruct the capId with the null selector — which would not match any capId computed for a real function selector. The capability is effectively a grant to call function `0x00000000` on the target, which is either nonexistent or the fallback function.

**Impact**:
Depositors or minters who pass `selector = bytes4(0)` produce a capability with an undefined grant target. The minted capability is technically valid in the registry but semantically meaningless for function-level access control. No funds are at risk; the depositor simply receives a useless credential while paying the deposit amount.

**Recommendation**:
Add `if (capSelector == bytes4(0)) revert InvalidCapConfig()` to `depositAndConfigure()` and an analogous check to `X402Cap.mint()`. This prevents capabilities from being minted with a null function selector and aligns with the semantic intent that `capSelector` identifies a specific function being authorized.

---

## Informational Findings

### [I-01] Preimage Front-Running Is Economically Neutral

**Severity**: Informational
**Location**: `AtomicPayForAccess.sol:L131-166`, `SplitClaimHashlock.sol:L65-78`
**Confidence**: MEDIUM (2 agents, trace evidence)

**Description**:
A potential front-running concern exists when a beneficiary submits a reveal transaction: the preimage `p` is visible in the mempool before inclusion, and a mempool observer (such as an MEV bot) could submit a competing `revealAndMint(depositor, id, preimage)` transaction with higher gas priority to be included first.

However, front-running this transaction produces no economic benefit for the attacker. All payment recipients are hardcoded in the deal struct at deposit time: `d.beneficiary` receives the beneficiary amount, and `d.operator` receives the fee — both derived from the deal struct, never from `msg.sender`. The `revealAndMint()` caller is irrelevant to fund distribution.

```solidity
// AtomicPayForAccess.sol:L149-152 — recipients from deal struct, not msg.sender
balances[d.beneficiary] += beneficiaryAmount;
if (fee != 0) { balances[d.operator] += fee; }
```

A front-runner who successfully submits the reveal before the beneficiary does not receive the payment — the beneficiary and operator still receive their shares. In `AtomicPayForAccess`, the capability is minted to `depositor` (also from the deal struct), not to the caller. The front-runner pays gas for a transaction that benefits only the intended recipients.

**Impact**: None. Front-running this protocol produces no profit and is therefore not a rational MEV strategy.

---

### [I-02] ETH Sent via selfdestruct/Coinbase Becomes Permanently Stuck

**Severity**: Informational
**Location**: `AtomicPayForAccess.sol` (no `receive()` function), `SplitClaimHashlock.sol` (no `receive()` function)
**Confidence**: LOW (1 agent, design analysis)

**Description**:
Both contracts use internal `balances` mappings for ETH accounting rather than relying on `address(this).balance`. Neither contract declares a `receive()` or `payable` `fallback()` function, so ordinary ETH transfers will revert. However, ETH can be force-sent to any contract address via two mechanisms that bypass `receive()`: `selfdestruct(target)` (pre-Cancun) or coinbase miner reward assignment.

Any ETH reaching the contract via these paths accumulates in `address(this).balance` but is not credited to any `balances` entry and has no withdrawal path — there is no admin function, sweep function, or recovery mechanism in either contract.

**Impact**: Negligible under normal operating conditions. Force-sent ETH is permanently inaccessible but represents no risk to protocol participants. The accounting invariant holds because both contracts track internal balances independently of `address(this).balance`.

---

### [I-03] Dead Code — cc.expiry != 0 Condition Is Always True

**Severity**: Informational
**Location**: `AtomicPayForAccess.sol:L106`, `AtomicPayForAccess.sol:L157`
**Confidence**: LOW (confirmed by multiple agents — 4 sources — but impact is code quality only)

**Description**:
The `if (cc.expiry != 0)` branch in `revealAndMint()` at line 157 wraps the entire capability minting block. The `false` path of this condition — where `cc.expiry == 0` — is unreachable under all current code paths, because `depositAndConfigure()` enforces `capExpiry != 0` at line 106 before storing the `CapConfig`.

```solidity
// AtomicPayForAccess.sol:L106 — deposit validation
if (capExpiry == 0 || block.timestamp > capExpiry) revert InvalidCapConfig();

// AtomicPayForAccess.sol:L157 — dead conditional in reveal
if (cc.expiry != 0) {  // always true given L106 enforcement
    capId = keccak256(...);
    ...
    capabilities[capId] = depositor;
    emit CapabilityMinted(...);
}
```

When `cc.expiry == 0`, the `if` block is skipped: `capId` is never assigned, the Solidity default of `bytes32(0)` is returned, no event is emitted, and no capability is minted — yet payment to the beneficiary has already been settled. This silent "payment without capability" outcome is theoretically possible if the dead branch were ever activated by a future code change that allows `capExpiry = 0`.

**Impact**: No current vulnerability — the dead branch cannot be reached. The risk is forward-looking: a future developer removing or weakening the deposit validation at L106 could inadvertently enable the `cc.expiry == 0` path, causing depositors to pay without receiving a capability. The dead code introduces maintenance risk without current exploitability.

**Recommendation**: Either remove the `if (cc.expiry != 0)` wrapper and replace it with an assertion (`assert(cc.expiry != 0)`) to make the invariant explicit, or add a comment explaining why the condition is redundant but kept as a defensive guard.

---

### [I-04] computeCapId Silent Mismatch for Large Amounts (> uint96.max)

**Severity**: Informational
**Location**: `AtomicPayForAccess.sol:L208-220`
**Confidence**: LOW (1 agent, boundary analysis)

**Description**:
The `computeCapId()` view function accepts `amount` as a `uint256`, while `depositAndConfigure()` enforces `msg.value <= type(uint96).max` at line 93, meaning all on-chain deposit amounts fit within `uint96`. However, `computeCapId()` applies no corresponding range check:

```solidity
// AtomicPayForAccess.sol:L208-220
function computeCapId(
    address depositor,
    bytes32 dealId,
    uint256 amount,  // no uint96 range check
    ...
) external view returns (bytes32) {
    return keccak256(abi.encode(
        depositor, dealId, amount, address(0), nonce, expiry, target, selector,
        block.chainid, address(this)
    ));
}
```

An off-chain caller passing `amount > type(uint96).max` to `computeCapId()` receives a valid-looking `bytes32` hash that can never correspond to any real on-chain capability. No error is returned, no indication is given that the input is out of the valid range, and the result silently diverges from all on-chain state.

**Impact**: Off-chain tooling or scripts that compute expected `capId` values using amounts larger than `uint96.max` will receive incorrect hashes with no diagnostic signal. This could cause capability verification failures that are difficult to diagnose. No on-chain state is affected.

**Recommendation**: Add `require(amount <= type(uint96).max, "amount exceeds uint96")` to `computeCapId()`, or change the parameter type to `uint96` to match the on-chain constraint. A NatSpec note documenting the `uint96` constraint would also help off-chain integrators.

---

### [I-05] Incomplete Event Parameter Coverage Across All Contracts

**Severity**: Informational
**Location**: `AtomicPayForAccess.sol:L54`, `AtomicPayForAccess.sol:L125`; `X402Cap.sol:L7`, `X402Cap.sol:L28`
**Confidence**: LOW (multiple agents — 5 sources — observability concern only)

**Description**:
Several events across the three contracts omit parameters that would be necessary for full off-chain state reconstruction from logs alone:

| Event | Contract | Missing Parameters |
|-------|----------|-------------------|
| `DealDeposited` | `AtomicPayForAccess.sol:L54` | `feeBps`, `operator`, `hash` |
| `DealRevealed` | `AtomicPayForAccess.sol:L55` | `operator` address |
| `CapabilityMinted` | `AtomicPayForAccess.sol:L45-52` | `amount`, `nonce` |
| `Minted` | `X402Cap.sol:L7` | `amount`, `token`, `nonce` |

```solidity
// AtomicPayForAccess.sol:L54 — missing feeBps, operator, hash
event DealDeposited(address indexed depositor, bytes32 indexed id, address beneficiary, uint96 amount, uint32 deadline);

// X402Cap.sol:L7 — missing amount, token, nonce
event Minted(bytes32 indexed capId, address indexed payer, address target, bytes4 selector, uint256 expiry);
```

For `DealDeposited`, the absence of `hash` means off-chain systems cannot verify deal integrity from the event log without also querying the storage mapping. For `Minted` in `X402Cap`, the absence of `amount`, `token`, and `nonce` means the full `capId` inputs cannot be reconstructed from event history — observers cannot re-derive the `capId` without additional storage calls.

**Impact**: Off-chain indexers and subgraphs that rely on event-only state reconstruction cannot recover complete deal or capability parameters from logs alone. This increases reliance on direct storage reads, which are less efficient and not available for historical state.

**Recommendation**: Add the missing parameters to each event. For `DealDeposited`, add `bytes32 hash`, `address operator`, and `uint16 feeBps`. For `X402Cap.Minted`, add `uint256 amount`, `address token`, and `uint256 nonce`. This is a non-breaking ABI change for the event but requires off-chain listeners to update their decoding.

---

### [I-06] balanceOf Exposes Pending Withdrawal Balances of All Participants

**Severity**: Informational
**Location**: `AtomicPayForAccess.sol:L204-206`
**Confidence**: LOW (1-2 agents, design analysis)

**Description**:
The `balanceOf(address account)` function is declared `external` with no access restriction, making every participant's pending withdrawal balance queryable by any on-chain or off-chain caller:

```solidity
// AtomicPayForAccess.sol:L204-206
function balanceOf(address account) external view returns (uint256) {
    return balances[account];
}
```

The `balances` mapping accumulates ETH for beneficiaries (from reveals), operators (fee shares), and depositors (from refunds) until they call `withdraw()`. Any address — including competitors, MEV bots, or surveillance systems — can enumerate pending balances for all known participants by calling `balanceOf()`.

**Impact**: Pending withdrawal balances are public. This enables observers to infer deal reveal activity, operator fee accumulation rates, and depositor refund patterns without directly monitoring transactions. There is no risk to funds; the ETH is safely held and will be withdrawn by the correct party when they call `withdraw()`. The privacy concern is mild given that all transactions are already publicly visible on-chain.

**Recommendation**: Accept as-is for most use cases — the information is derivable from transaction traces regardless. If privacy is a protocol requirement, consider removing the `balanceOf` helper and relying on event-based accounting, or restricting it to `msg.sender` only: `function balanceOf() external view returns (uint256) { return balances[msg.sender]; }`.

---

### [I-07] Variable Shadowing in X402Cap — capId Return Variable Shadows Function

**Severity**: Informational
**Location**: `X402Cap.sol:L21`, `X402Cap.sol:L31`
**Confidence**: LOW (1 agent, static analysis)

**Description**:
In `X402Cap`, the public view function `capId()` at line 38 shares its name with the named return variable `capId` declared in `mint()` at line 21, and also with the parameter `capId` in `burn()` at line 31:

```solidity
// X402Cap.sol:L14-21 — named return variable shadows function capId()
function mint(...) external returns (bytes32 capId) {
    ...
    capId = keccak256(abi.encode(...));  // local variable, not a call to capId()
}

// X402Cap.sol:L31 — parameter shadows function capId()
function burn(bytes32 capId) external {
    address holder = capabilities[capId];  // local parameter, not a call to capId()
}

// X402Cap.sol:L38 — the function being shadowed
function capId(address payer, ...) external pure returns (bytes32) { ... }
```

Within the scope of `mint()` and `burn()`, any reference to `capId` resolves to the local variable or parameter, making it impossible to call the `capId()` view function from within those functions without renaming. This is a naming collision that does not affect current behavior but creates ambiguity for future developers extending the contract.

**Impact**: No current vulnerability. The shadowing does not affect the compiled bytecode behavior because the local variables and the function resolve to different opcodes. The risk is maintenance-level: a future developer adding logic that attempts to call `capId(...)` inside `mint()` or `burn()` will silently reference the local variable instead of the function, which may produce a subtle bug.

**Recommendation**: Rename the named return variable in `mint()` to `_capId` or `result`, and rename the `burn()` parameter to `_capId`. Alternatively, rename the public view function to `computeCapId()` to match the naming convention already used in `AtomicPayForAccess`.

---

## Priority Remediation Order

1. **H-02**: X402Cap mint() Is Permissionless — Immediate. Root cause of two chain attacks (H-04, H-05). Add payment gate or authorization control before any production deployment.
2. **H-04**: Zero-Cost Cross-Chain Credential Forgery — Immediate. Requires fixing both H-02 (payment gate) and H-03 (chain binding). Any X402Cap deployment on a second chain is exploitable now.
3. **H-05**: Zero-Cost Persistent Access — Immediate. Requires fixing H-02. Naive consumers using registry-presence checks are fully bypassed.
4. **H-01**: SplitClaimHashlock 100% Fee — High Priority. Direct fund loss for beneficiaries. One-character fix (`>` to `>=`). Apply before any standalone `SplitClaimHashlock` deployment.
5. **H-03**: Cross-Chain Replay — High Priority. Add `block.chainid` and `address(this)` to X402Cap capId hash.
6. **M-01**: Permanent Phantom Capability — Medium Priority. Add MAX_CAP_DURATION bound and use sentinel value for burn. Required before any service relies on `CapabilityBurned` as a revocation signal.
7. **L-01** through **L-11** (Low): Address before launch. Prioritize L-06 (zero hash lock), L-07 (zero event coverage in SplitClaimHashlock), and L-09 (born-expired capability) as highest-impact within the Low tier.
8. **I-01** through **I-07** (Informational): Address post-launch or as part of documentation and code quality improvements.

---

## Appendix A: Internal Audit Traceability

> This appendix is for internal reference. It maps pipeline identifiers to report IDs and is not required for client-facing use.

### Master Finding Index

| Report ID | Internal Hypothesis | Verification | Agent Sources |
|-----------|-------------------|--------------|---------------|
| H-01 | H-1 | CONFIRMED [POC-PASS] | CS-2, AC-3, DEPTH-TF-4, DEPTH-EC-1, NSC-1 |
| H-02 | H-2 | CONFIRMED [POC-PASS] | CS-12, DEPTH-TF-7, DEPTH-EC-3, BLIND-A3, VS-4 |
| H-03 | H-4 | CONFIRMED [POC-PASS] | AC-9, DEPTH-EX-6, DEPTH-EC-6 |
| H-04 | CH-2 (H-2 + H-4) | CONFIRMED [POC-PASS] | Chain of H-02 + H-03 components |
| H-05 | CH-3 (H-2 + H-3) | CONFIRMED [POC-PASS] | Chain of H-02 + L-01 components |
| M-01 | CH-1 (H-5 + H-8) | CONFIRMED [POC-PASS] | Chain of L-02 + L-08 components |
| L-01 | H-3 | UNVERIFIED | CS-11, AC-2, BLIND-C3 |
| L-02 | H-5 | UNVERIFIED | BLIND-A1 |
| L-03 | H-6 | UNVERIFIED | CS-8, AC-1, NSC-2, NSC-4 |
| L-04 | H-7 | UNVERIFIED | CS-5, DEPTH-TF-1, DEPTH-EC-2 |
| L-05 | H-9 | UNVERIFIED | CS-3, DEPTH-ST-1 |
| L-06 | H-10 + H-11 (consolidated) | UNVERIFIED | BLIND-B1, VS-1, VS-2 |
| L-07 | H-12 (8 agent sources consolidated) | UNVERIFIED | CS-4, AC-4, AC-7, CS-13, NEC-1, DEPTH-ST-6, DEPTH-EX-7, NSC-5 |
| L-08 | H-13 | UNVERIFIED | DEPTH-EX-4 |
| L-09 | H-14 | UNVERIFIED | DEPTH-EC-5 |
| L-10 | H-15 | UNVERIFIED | BLIND-A2 |
| L-11 | H-16 | UNVERIFIED | BLIND-A4 |
| I-01 | H-17 | UNVERIFIED | CS-1, DEPTH-EX-1 |
| I-02 | H-18 | UNVERIFIED | CS-10 |
| I-03 | H-19 | UNVERIFIED | AC-5, NSC-3, DEPTH-ST-7 |
| I-04 | H-20 | UNVERIFIED | BLIND-A5 |
| I-05 | H-21 | UNVERIFIED | VS-3, NEC-2, NEC-4, NEC-5, VS-5 |
| I-06 | H-22 | UNVERIFIED | BLIND-B2, BLIND-C2 |
| I-07 | H-23 | UNVERIFIED | SLITHER-1 |

### Excluded Findings (Refuted — Not Included in Report)

| Internal ID | Severity | Title | Exclusion Reason |
|-------------|----------|-------|-----------------|
| CS-6 | Refuted | Reentrancy in withdraw() | FALSE_POSITIVE — CEI pattern correctly applied |
| CS-7 | Refuted | Deadline Boundary Dead Zone | FALSE_POSITIVE — boundary conditions are mutually exclusive |
| CS-9 | Refuted | Deal with deadline=1 Cannot Be Created | FALSE_POSITIVE — timestamp validation blocks deadline=1 |
| CS-14 | Refuted | Balance Accounting Invariant | FALSE_POSITIVE — ETH conservation holds across all operations |
| AC-8 | Refuted | Cross-Contract capId Collision Impossible | FALSE_POSITIVE — encoding schema differences prevent collision |
| DEPTH-TF-2 | Refuted | Conservation Invariant (Positive) | FALSE_POSITIVE — positive confirmation, not a vulnerability |
| DEPTH-TF-3 | Refuted | No address(this).balance Dependency | FALSE_POSITIVE — protocol does not rely on balance() for accounting |
| DEPTH-TF-6 | Refuted | Refund Credits Correctly | FALSE_POSITIVE — ETH distribution is sound |
| DEPTH-ST-3 | Refuted | Positive Invariant Confirmation | FALSE_POSITIVE — invariant holds, not a vulnerability |
| DEPTH-ST-5 | Refuted | Cross-Function Reentrancy Safe | FALSE_POSITIVE — protocol is safe from cross-function reentrancy |
| DEPTH-EX-2 | Refuted | Double-Claim Impossible | FALSE_POSITIVE — preimage+deal+user uniqueness prevents double-claim |
| NEC-3 | Refuted | Positive Confirmation — Event Order Correct | FALSE_POSITIVE — positive verification, not a vulnerability |
