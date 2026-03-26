# Security Audit Report — AtomicPayForAccess

**Date:** 2026-03-26
**Auditor:** Claude Code (automated, following audit.md methodology)
**Commit:** current HEAD
**Scope:** All Solidity source files in `src/`

---

## 1. Scope Summary

### Contracts in scope

| File | Lines | Description |
|------|-------|-------------|
| `src/AtomicPayForAccess.sol` | 200 | Main contract: hashlock escrow + capability minting |
| `src/base/SplitClaimHashlock.sol` | 97 | Base hashlock escrow (standalone, not inherited) |
| `src/base/X402Cap.sol` | 51 | Base capability token (standalone, not inherited) |

### Architecture

`AtomicPayForAccess` is a monolithic contract that combines the logic of both base contracts into a single atomic flow: deposit ETH with hashlock → reveal preimage → settle payment with fee split → mint capability token. It does **not** inherit from the base contracts; it inlines the logic.

### Assets at risk
- ETH deposited in escrow deals
- Capability tokens (access credentials)

### Privileges
- **Depositor (client):** creates deals, receives capabilities, can refund after deadline
- **Beneficiary:** knows preimage, triggers reveal to claim payment
- **Operator:** receives fee split, must be registered
- **Anyone:** can call `revealAndMint` if they know the preimage

### Trust assumptions
- Off-chain: preimage is shared securely between parties
- On-chain: operator registration is self-service (no admin)
- No proxy, no upgrades, no admin keys

---

## 2. Threat Model

| Actor | Can steal? | Can censor? | Can brick funds? | Can mint value? |
|-------|-----------|-------------|-------------------|-----------------|
| Depositor | No | Can withhold preimage (but beneficiary knows it) | Can self-grief by reusing capId params | Can reuse nonce to collide capIds |
| Beneficiary | No (pull-payment) | Can delay reveal until near deadline | No (pull-payment protects) | No |
| Operator | No | Can deregister (no effect on existing deals) | No | No |
| External attacker | No | Can front-run reveal (but can't change outcome) | No | No |
| Reverting receiver | No | No | Only their own withdraw (by design) | No |

### Key invariants
1. `sum(balances) + sum(active deal amounts) == address(this).balance`
2. Each deal can only be resolved once (reveal OR refund, never both)
3. A capability is minted at most once per capId
4. Only the capability holder can burn it

---

## 3. Baseline Verification

```
forge build      → OK (compilation successful, solc 0.8.28)
forge test       → 11/11 passed
forge test --fuzz-runs 1000 → 22/22 passed (including audit tests)
```

No compiler errors. One minor warning about `pure` mutability on a fuzz test (in audit test file only).

---

## 4. Findings

### M-01: Capability ID Collision Allows Griefing of Future Deals

**Severity:** Medium
**File:** `src/AtomicPayForAccess.sol`, lines 142-146
**Root cause:** `capId` is derived from `(depositor, amount, address(0), nonce, expiry, target, selector)` but is **not** scoped to the deal ID. Two deals with the same cap parameters produce the same `capId`.

**Exploit scenario:**
1. Depositor creates Deal A with `(nonce=42, amount=1 ether, capTarget=X, capSelector=Y, capExpiry=Z)`
2. Beneficiary reveals Deal A → capability minted with capId C
3. Depositor creates Deal B with identical cap parameters but different deal ID
4. Beneficiary reveals Deal B → `AlreadyMinted` revert
5. Beneficiary cannot claim payment. Depositor must wait for deadline to refund.

**Impact:** Beneficiary loses access to earned payment until deadline passes (griefing). If depositor is malicious, they can intentionally reuse parameters to create deals that can never be claimed.

**Proved by:** `test_capIdCollisionBlocksSecondReveal` in `test/AuditFindings.t.sol`

**Remediation:** Include `id` (the deal ID) in the `capId` hash:
```solidity
capId = keccak256(abi.encode(
    depositor, id, uint256(d.amount), address(0), cc.nonce, cc.expiry, cc.target, cc.selector
));
```
This also requires updating `computeCapId` to accept and include the deal ID.

---

### L-01: capExpiry=0 Silently Skips Capability Minting

**Severity:** Low
**File:** `src/AtomicPayForAccess.sol`, line 141
**Root cause:** The `if (cc.expiry != 0)` guard means that when `capExpiry` is 0, the entire capability minting block is skipped. The depositor pays but receives no capability.

**Exploit scenario:**
1. Off-chain integration bug or user error passes `capExpiry = 0`
2. Beneficiary reveals → payment is settled, beneficiary and operator get paid
3. Depositor receives no capability — they paid for nothing

**Impact:** Loss of expected value for the depositor. No on-chain signal that minting was skipped (capId returned is `bytes32(0)`).

**Proved by:** `test_zeroCapExpirySkipsMinting` in `test/AuditFindings.t.sol`

**Remediation:** Either:
- Require `capExpiry != 0` in `depositAndConfigure`, or
- Emit a distinct event when minting is skipped so off-chain systems can detect it

---

### L-02: Operator Can Deregister After Deposit Without Affecting Active Deals

**Severity:** Low (informational)
**File:** `src/AtomicPayForAccess.sol`, lines 61-63, 90-93
**Root cause:** Operator registration is only checked at deposit time. An operator who deregisters afterward still receives fees from existing deals.

**Impact:** No direct loss, but violates a potential expectation that deregistered operators shouldn't receive fees. This is arguably correct behavior (the deal was valid when created).

**Proved by:** `test_operatorDeregisterAfterDeposit` in `test/AuditFindings.t.sol`

**Remediation:** Document this as intended behavior. If operator deregistration should affect pending deals, add a check in `revealAndMint`.

---

### L-03: 100% Fee (feeBps=10000) Leaves Beneficiary With Zero Payment

**Severity:** Low
**File:** `src/AtomicPayForAccess.sol`, line 134
**Root cause:** `feeBps` up to 10000 (100%) is allowed. This means the operator gets the entire payment and the beneficiary gets zero.

**Impact:** Beneficiary has no economic incentive to reveal. Could be used to create "operator-only" deals, but is likely not intended.

**Proved by:** `test_maxFeeBps` in `test/AuditFindings.t.sol`

**Remediation:** Consider capping `feeBps` to a maximum like 5000 (50%), or document that 100% fee is intentional.

---

### I-01: Missing Zero-Address Check on `capTarget`

**Severity:** Informational
**File:** `src/AtomicPayForAccess.sol`, line 75
**Root cause:** No validation that `capTarget` is non-zero. A capability pointing to `address(0)` is meaningless.

**Remediation:** Add `if (capTarget == address(0)) revert InvalidDeposit();` when `capExpiry != 0`.

---

### I-02: Missing Events on Deposit, Reveal, and Refund

**Severity:** Informational
**File:** `src/AtomicPayForAccess.sol`
**Root cause:** Only capability-related events (`CapabilityMinted`, `CapabilityBurned`) are emitted. No events for `depositAndConfigure`, `revealAndMint` (payment settlement), `refund`, `withdraw`, or `setOperatorRegistration`.

**Impact:** Off-chain indexing and monitoring is incomplete. Cannot track deal lifecycle without parsing storage diffs.

**Remediation:** Add events for all state-changing operations.

---

### I-03: No Chain ID or Contract Address in capId Hash

**Severity:** Informational
**File:** `src/AtomicPayForAccess.sol`, line 142
**Root cause:** `capId` does not include `block.chainid` or `address(this)`. If the contract is deployed on multiple chains, the same parameters produce the same `capId`.

**Impact:** Off-chain systems checking capabilities across chains could be confused. On-chain this is not exploitable since each deployment has its own storage.

**Remediation:** For cross-chain deployments, include `block.chainid` and `address(this)` in the hash.

---

## 5. Checklist Verification

| # | Check | Result |
|---|-------|--------|
| 1 | `abi.encodePacked` collision risk | **SAFE** — single `bytes32` arg, no multi-dynamic-type packing |
| 2 | Force-feeding via `selfdestruct` | **SAFE** — contract never reads `address(this).balance`; uses internal `balances` mapping |
| 3 | Pull-payment correctness | **SAFE** — CEI pattern followed; balance zeroed before external call |
| 4 | Reentrancy on withdraw | **SAFE** — state updated before low-level call; no callback can re-enter meaningfully |
| 5 | Fee calculation overflow | **SAFE** — `uint256(d.amount) * d.feeBps` max is `2^96 * 10000 ≈ 2^110`, well under `2^256` |
| 6 | uint96 cast safety | **SAFE** — `msg.value > type(uint96).max` check precedes the cast |
| 7 | Capability mint atomicity | **SEE M-01** — mint can revert on collision, leaving payment unsettled |
| 8 | Capability replay / capId collision | **SEE M-01** — same parameters → same capId |
| 9 | Deal ID collision | **SAFE** — depositor-scoped, `DealExists` check on `deadline != 0` |
| 10 | Deadline check boundary | **SAFE** — `block.timestamp > d.deadline` for reveal (inclusive at boundary), `block.timestamp <= d.deadline` for refund (exclusive at boundary). No gap or overlap. |
| 11 | Zero-address checks | **PARTIAL** — beneficiary and operator checked; capTarget not checked |
| 12 | Event emission completeness | **INCOMPLETE** — see I-02 |
| 13 | Stale capabilities (expired but still minted) | **YES** — capabilities can expire but remain in the `capabilities` mapping. Off-chain consumers must check expiry. No on-chain enforcement of expiry after mint. |
| 14 | Integration vs base contracts | **N/A** — `AtomicPayForAccess` is standalone, does not inherit. Logic is copy-inlined. |

---

## 6. Tests Run

### Original test suite (11 tests)
```
test_depositAndRevealMintsCapability     PASS
test_revealAfterDeadlineReverts          PASS
test_refundDoesNotMintCapability         PASS
test_capabilityCanBeBurned               PASS
test_operatorFeesSplitCorrectly          PASS
test_pullPaymentPreserved                PASS
test_revertingBeneficiaryCannotBrickRevealOrMint  PASS
test_badPreimageReverts                  PASS
test_doubleDepositReverts                PASS
test_zeroFeeBpsSkipsOperatorCheck        PASS
test_nonHolderCannotBurnCapability       PASS
```

### Audit test suite (11 tests, added in `test/AuditFindings.t.sol`)
```
test_capIdCollisionBlocksSecondReveal    PASS  (proves M-01)
test_zeroCapExpirySkipsMinting           PASS  (proves L-01)
test_operatorDeregisterAfterDeposit      PASS  (proves L-02)
test_maxFeeBps                           PASS  (proves L-03)
test_doubleRevealReverts                 PASS  (state machine)
test_revealAfterRefundReverts            PASS  (state machine)
test_revealAtExactDeadline               PASS  (boundary)
test_refundAtExactDeadlineFails          PASS  (boundary)
test_withdrawCEIPattern                  PASS  (reentrancy safety)
testFuzz_feeCalculationConservation      PASS  (1000 runs, conservation)
testFuzz_uint96CastRejectsOverflow       PASS  (1000 runs, overflow)
```

**Total: 22/22 tests passed with --fuzz-runs 1000**

---

## 7. Open Questions

1. **Is capExpiry=0 intended to mean "no capability"?** If so, document it. If not, require non-zero.
2. **Should expired capabilities be enforced on-chain?** Currently, `capabilities[capId]` returns the holder even after expiry. Consumers must check expiry themselves.
3. **Is 100% feeBps intentional?** It creates a degenerate case where the beneficiary has no incentive to reveal.
4. **Should `revealAndMint` succeed even if the capability part fails?** Currently, a capId collision reverts the entire transaction including payment settlement.
5. **Are the base contracts (`SplitClaimHashlock`, `X402Cap`) dead code?** They are not inherited or referenced. If they're reference implementations, they should be documented as such.

---

## 8. Residual Risks

| Risk | Likelihood | Impact | Notes |
|------|-----------|--------|-------|
| Front-running reveal near deadline | Low | Low | Anyone can call `revealAndMint`; front-running doesn't change the outcome (same payment split, same capability recipient) |
| Beneficiary never reveals | Medium | Low | Depositor can refund after deadline; funds are not permanently locked |
| Preimage leaked to third party | Medium | Medium | Third party can call `revealAndMint`; payment settles correctly but depositor gets capability, which is the intended outcome |
| Stale expired capabilities | Medium | Low | Off-chain consumers must validate expiry; no on-chain guard post-mint |
| ETH stuck in reverting receiver balance | Low | Low | By design (pull-payment); user's problem, not protocol's |
| capId collision (M-01) | Medium | Medium | Can block payment settlement; requires parameter reuse |
| Contract balance drift from force-feeding | Low | None | Internal accounting is independent of `address(this).balance` |

---

## 9. Summary

The `AtomicPayForAccess` contract is well-structured with proper CEI ordering, pull-payment pattern, and input validation. The main finding (M-01) is a capability ID collision that can block payment settlement when deal parameters are reused. Three low-severity issues relate to edge cases in parameter validation and event completeness. No critical or high-severity vulnerabilities were found.

**Overall assessment: The contract is production-ready with the recommended fix for M-01 (include deal ID in capId hash).**
