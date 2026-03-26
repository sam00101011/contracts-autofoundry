# E2E Results — AtomicPayForAccessERC20

## Contract Details
- **Contract**: `AtomicPayForAccessERC20`
- **Deployed to**: `0x8C0a28819ccafD65A0227d2D5ed1F237ed406Eb4`
- **Network**: Tempo Moderato (Chain ID: 42431)
- **Payment Token**: PathUSD (`0x20C0000000000000000000000000000000000000`, 6 decimals)
- **Deploy TX**: `0x97f67807893aa9f3ca55badade5b1da7ee05026e46a65c5388252141eee31030`
- **Explorer**: https://explore.tempo.xyz/address/0x8C0a28819ccafD65A0227d2D5ed1F237ed406Eb4

## Forge Unit Tests (14/14 passed)
- test_paymentToken ✅
- test_depositAndConfigure ✅
- test_revealAndMint ✅
- test_withdraw ✅
- test_burnCapability ✅
- test_refund ✅
- test_fullLifecycle ✅
- test_computeCapId ✅
- test_revert_depositZero ✅
- test_revert_dealExists ✅
- test_revert_badPreimage ✅
- test_revert_burnNotHolder ✅
- test_revert_refundBeforeDeadline ✅
- test_revert_withdrawNoBalance ✅

## E2E Tests on Tempo Moderato (all passed)

### Step 1: Register Operator ✅
- TX: `0xf7aff7cebb8b19537b24fc4bcf1330c8f66f9777278fb224e36f9b62be26b535`

### Step 2: Approve PathUSD ✅
- Approved 1,000 PathUSD (1000000000 raw) for contract
- TX: `0xf3fb373dda6ccbe6be6cef10457834cbc64629d08546a588ad54f81260ab11f7`

### Step 3: Deposit and Configure (1 PathUSD, 5% fee) ✅
- Deal ID: `0xaaaa...0001`
- Amount: 1,000,000 (1 PathUSD)
- Fee: 5% (500 bps)
- TX: `0xe45bfb66fda4c5512819d0c4e60d86468357266aac5acbe213d882a309e9e61f`
- Contract token balance after: 1,000,000 ✅

### Step 4: Reveal and Mint ✅
- Preimage revealed, payment settled, capability minted
- Beneficiary gets 950,000 (95%), Operator gets 50,000 (5%)
- Cap ID: `0xf4dbe5dcf4ba6b062797aba2f946fa659ab5b03c8344b59c33a74c017801bb8f`
- Cap holder: deployer ✅
- TX: `0xa2525430348964d37eb2d573f0cc2af12f5b17fb27c67964a0ba105180c23159`

### Step 5: Withdraw ✅
- Internal balance (beneficiary+operator, same address): 1,000,000
- Tokens transferred back to deployer via ERC20 transfer
- TX: `0x0a4bdc4529b99bc2a0e27155d17423dd9e193c1bd03d75e083edc655f1fbfd2c`

### Step 6: Burn Capability ✅
- Cap holder after burn: `0x0000000000000000000000000000000000000001` (BURNED sentinel) ✅
- TX: `0x9aef8951a45ac8c31745f744b9f9bf7086ef17503ce4165a3fa7244724219541`

### Step 7: Refund Test ✅
- Deposited 1 PathUSD with 30s deadline
- Waited for deadline to pass
- Refund TX: `0x1307b727fa3635274f02526b69f1730510786f4a1d1f63f5fd8e9a34b9f013f7`
- Internal balance after refund: 1,000,000 ✅
- Withdraw refund TX: `0x5ba1aa6ca50413546209f65a6b1f662a0e70369a66bd88553214cf58817a4d07`

## Summary
All E2E lifecycle operations work correctly with ERC20 (PathUSD) tokens:
1. ✅ Operator registration
2. ✅ Token approval → deposit (transferFrom pulls tokens)
3. ✅ Reveal preimage → settle fees → mint capability
4. ✅ Withdraw (ERC20 transfer out)
5. ✅ Burn capability (sentinel = address(1))
6. ✅ Refund after deadline + withdraw refund

**Date**: 2025-07-24
