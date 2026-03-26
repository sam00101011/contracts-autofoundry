// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {Test} from "forge-std/Test.sol";
import {AtomicPayForAccess} from "../src/AtomicPayForAccess.sol";

contract RevertingReceiverSec {
    receive() external payable { revert(); }
}

contract SecurityTestsTest is Test {
    AtomicPayForAccess apa;

    address client      = address(0xC1);
    address beneficiary = address(0xBE);
    address operator    = address(0x09);

    bytes32 preimage1 = keccak256("secret1");
    bytes32 hash1     = keccak256(abi.encodePacked(preimage1));
    bytes32 preimage2 = keccak256("secret2");
    bytes32 hash2     = keccak256(abi.encodePacked(preimage2));

    address capTarget   = address(0xDA);
    bytes4  capSelector = bytes4(keccak256("getData()"));
    uint256 capExpiry;
    uint256 capNonce = 42;

    function setUp() public {
        apa = new AtomicPayForAccess();
        capExpiry = block.timestamp + 1 days;

        vm.prank(operator);
        apa.setOperatorRegistration(true);
        vm.deal(client, 100 ether);
    }

    // ─── M-01 FIXED: capId includes dealId, so different deals get different capIds ──
    function test_capIdIncludesDealId() public {
        bytes32 dealId1 = bytes32(uint256(1));
        bytes32 dealId2 = bytes32(uint256(2));
        uint32 deadline = uint32(block.timestamp + 1 hours);

        // First deposit+reveal
        vm.prank(client);
        apa.depositAndConfigure{value: 1 ether}(
            dealId1, hash1, beneficiary, operator, deadline, 500,
            capTarget, capSelector, capExpiry, capNonce
        );
        vm.prank(beneficiary);
        bytes32 capId1 = apa.revealAndMint(client, dealId1, preimage1);
        assertEq(apa.capabilities(capId1), client);

        // Second deposit with SAME cap parameters but different deal ID — should succeed now
        vm.prank(client);
        apa.depositAndConfigure{value: 1 ether}(
            dealId2, hash2, beneficiary, operator, deadline, 500,
            capTarget, capSelector, capExpiry, capNonce
        );
        vm.prank(beneficiary);
        bytes32 capId2 = apa.revealAndMint(client, dealId2, preimage2);
        assertEq(apa.capabilities(capId2), client);

        // capIds are different because dealId is included
        assertTrue(capId1 != capId2);
    }

    // ─── I-03 FIXED: capId includes chainId ──────────────────────
    function test_capIdIncludesChainId() public {
        bytes32 dealId1 = bytes32(uint256(1));

        // Compute capId on current chain
        bytes32 capIdChain1 = apa.computeCapId(
            client, dealId1, 1 ether, capNonce, capExpiry, capTarget, capSelector
        );

        // Simulate different chainid by computing manually
        bytes32 capIdChain2 = keccak256(abi.encode(
            client, dealId1, uint256(1 ether), address(0), capNonce, capExpiry, capTarget, capSelector, block.chainid + 1, address(apa)
        ));

        // Different chains produce different capIds
        assertTrue(capIdChain1 != capIdChain2);
    }

    // ─── L-01 FIXED: capExpiry=0 now reverts ─────────────────────
    function test_zeroCapExpiryReverts() public {
        bytes32 dealId = bytes32(uint256(1));
        uint32 deadline = uint32(block.timestamp + 1 hours);

        vm.prank(client);
        vm.expectRevert(AtomicPayForAccess.InvalidCapConfig.selector);
        apa.depositAndConfigure{value: 1 ether}(
            dealId, hash1, beneficiary, operator, deadline, 500,
            capTarget, capSelector, 0, capNonce
        );
    }

    // ─── I-01 FIXED: capTarget=address(0) now reverts ────────────
    function test_capTargetZeroReverts() public {
        bytes32 dealId = bytes32(uint256(1));
        uint32 deadline = uint32(block.timestamp + 1 hours);

        vm.prank(client);
        vm.expectRevert(AtomicPayForAccess.InvalidCapConfig.selector);
        apa.depositAndConfigure{value: 1 ether}(
            dealId, hash1, beneficiary, operator, deadline, 500,
            address(0), capSelector, capExpiry, capNonce
        );
    }

    // ─── L-03 FIXED: feeBps > 5000 (50%) reverts ────────────────
    function test_maxFeeBpsCapped() public {
        bytes32 dealId = bytes32(uint256(1));
        uint32 deadline = uint32(block.timestamp + 1 hours);

        // 5001 bps should revert
        vm.prank(client);
        vm.expectRevert(AtomicPayForAccess.InvalidDeposit.selector);
        apa.depositAndConfigure{value: 1 ether}(
            dealId, hash1, beneficiary, operator, deadline, 5001,
            capTarget, capSelector, capExpiry, capNonce
        );

        // 5000 bps should succeed
        vm.prank(client);
        apa.depositAndConfigure{value: 1 ether}(
            dealId, hash1, beneficiary, operator, deadline, 5000,
            capTarget, capSelector, capExpiry, capNonce
        );
    }

    // ─── I-02 FIXED: events are emitted ──────────────────────────
    function test_eventsEmitted() public {
        bytes32 dealId = bytes32(uint256(1));
        uint32 deadline = uint32(block.timestamp + 1 hours);

        // DealDeposited event
        vm.prank(client);
        vm.expectEmit(true, true, false, true);
        emit AtomicPayForAccess.DealDeposited(client, dealId, beneficiary, 1 ether, deadline, hash1, operator, 500);
        apa.depositAndConfigure{value: 1 ether}(
            dealId, hash1, beneficiary, operator, deadline, 500,
            capTarget, capSelector, capExpiry, capNonce
        );

        // DealRevealed event
        uint256 fee = 1 ether * 500 / 10_000;
        uint256 benAmount = 1 ether - fee;
        vm.prank(beneficiary);
        vm.expectEmit(true, true, false, true);
        emit AtomicPayForAccess.DealRevealed(client, dealId, beneficiary, benAmount, fee, operator);
        apa.revealAndMint(client, dealId, preimage1);

        // Withdrawal event
        vm.prank(beneficiary);
        vm.expectEmit(true, false, false, true);
        emit AtomicPayForAccess.Withdrawal(beneficiary, benAmount);
        apa.withdraw();

        // OperatorRegistration event
        vm.prank(operator);
        vm.expectEmit(true, false, false, true);
        emit AtomicPayForAccess.OperatorRegistration(operator, false);
        apa.setOperatorRegistration(false);
    }

    function test_refundEventEmitted() public {
        bytes32 dealId = bytes32(uint256(1));
        uint32 deadline = uint32(block.timestamp + 1 hours);

        vm.prank(client);
        apa.depositAndConfigure{value: 1 ether}(
            dealId, hash1, beneficiary, operator, deadline, 500,
            capTarget, capSelector, capExpiry, capNonce
        );

        vm.warp(deadline + 1);

        vm.prank(client);
        vm.expectEmit(true, true, false, true);
        emit AtomicPayForAccess.DealRefunded(client, dealId, 1 ether);
        apa.refund(dealId);
    }

    // ─── State machine: double reveal reverts ────────────────────
    function test_doubleRevealReverts() public {
        bytes32 dealId = bytes32(uint256(1));
        uint32 deadline = uint32(block.timestamp + 1 hours);

        vm.prank(client);
        apa.depositAndConfigure{value: 1 ether}(
            dealId, hash1, beneficiary, operator, deadline, 500,
            capTarget, capSelector, capExpiry, capNonce
        );

        vm.prank(beneficiary);
        apa.revealAndMint(client, dealId, preimage1);

        vm.prank(beneficiary);
        vm.expectRevert(AtomicPayForAccess.MissingDeal.selector);
        apa.revealAndMint(client, dealId, preimage1);
    }

    // ─── State machine: reveal after refund reverts ──────────────
    function test_revealAfterRefundReverts() public {
        bytes32 dealId = bytes32(uint256(1));
        uint32 deadline = uint32(block.timestamp + 1 hours);

        vm.prank(client);
        apa.depositAndConfigure{value: 1 ether}(
            dealId, hash1, beneficiary, operator, deadline, 500,
            capTarget, capSelector, capExpiry, capNonce
        );

        vm.warp(deadline + 1);
        vm.prank(client);
        apa.refund(dealId);

        vm.prank(beneficiary);
        vm.expectRevert(AtomicPayForAccess.MissingDeal.selector);
        apa.revealAndMint(client, dealId, preimage1);
    }

    // ─── Boundary: reveal at exact deadline succeeds ─────────────
    function test_revealAtExactDeadline() public {
        bytes32 dealId = bytes32(uint256(1));
        uint32 deadline = uint32(block.timestamp + 1 hours);

        vm.prank(client);
        apa.depositAndConfigure{value: 1 ether}(
            dealId, hash1, beneficiary, operator, deadline, 500,
            capTarget, capSelector, capExpiry, capNonce
        );

        vm.warp(deadline);

        vm.prank(beneficiary);
        bytes32 capId = apa.revealAndMint(client, dealId, preimage1);
        assertEq(apa.capabilities(capId), client);
    }

    // ─── Boundary: refund at exact deadline fails ────────────────
    function test_refundAtExactDeadlineFails() public {
        bytes32 dealId = bytes32(uint256(1));
        uint32 deadline = uint32(block.timestamp + 1 hours);

        vm.prank(client);
        apa.depositAndConfigure{value: 1 ether}(
            dealId, hash1, beneficiary, operator, deadline, 500,
            capTarget, capSelector, capExpiry, capNonce
        );

        vm.warp(deadline);

        vm.prank(client);
        vm.expectRevert(AtomicPayForAccess.DeadlineNotPassed.selector);
        apa.refund(dealId);
    }

    // ─── CEI pattern: withdraw zeroes balance before transfer ────
    function test_withdrawCEIPattern() public {
        bytes32 dealId = bytes32(uint256(1));
        uint32 deadline = uint32(block.timestamp + 1 hours);

        vm.prank(client);
        apa.depositAndConfigure{value: 1 ether}(
            dealId, hash1, beneficiary, operator, deadline, 0,
            capTarget, capSelector, capExpiry, capNonce
        );

        vm.prank(beneficiary);
        apa.revealAndMint(client, dealId, preimage1);

        assertEq(apa.balanceOf(beneficiary), 1 ether);

        uint256 balBefore = beneficiary.balance;
        vm.prank(beneficiary);
        apa.withdraw();
        assertEq(beneficiary.balance - balBefore, 1 ether);
        assertEq(apa.balanceOf(beneficiary), 0);
    }

    // ─── Fuzz: fee calculation conservation ──────────────────────
    function testFuzz_feeCalculationConservation(uint96 amount, uint16 feeBps) public pure {
        vm.assume(amount > 0);
        vm.assume(feeBps <= 5_000);

        uint256 fee = uint256(amount) * feeBps / 10_000;
        uint256 beneficiaryAmount = uint256(amount) - fee;

        assertEq(fee + beneficiaryAmount, amount);
        assertLe(fee, amount);
    }

    // ─── Fuzz: uint96 cast rejects overflow ──────────────────────
    function testFuzz_uint96CastRejectsOverflow(uint256 amount) public {
        vm.assume(amount > type(uint96).max);
        vm.deal(client, amount);

        bytes32 dealId = bytes32(uint256(1));
        uint32 deadline = uint32(block.timestamp + 1 hours);

        vm.prank(client);
        vm.expectRevert(AtomicPayForAccess.InvalidDeposit.selector);
        apa.depositAndConfigure{value: amount}(
            dealId, hash1, beneficiary, operator, deadline, 500,
            capTarget, capSelector, capExpiry, capNonce
        );
    }

    // ─── L-02: Operator deregister after deposit (documented as intended) ──
    function test_operatorDeregisterAfterDeposit() public {
        bytes32 dealId = bytes32(uint256(1));
        uint32 deadline = uint32(block.timestamp + 1 hours);

        vm.prank(client);
        apa.depositAndConfigure{value: 1 ether}(
            dealId, hash1, beneficiary, operator, deadline, 500,
            capTarget, capSelector, capExpiry, capNonce
        );

        // Operator deregisters
        vm.prank(operator);
        apa.setOperatorRegistration(false);

        // Reveal still works — operator address is stored in the deal
        vm.prank(beneficiary);
        bytes32 capId = apa.revealAndMint(client, dealId, preimage1);
        assertEq(apa.capabilities(capId), client);
        assertGt(apa.balanceOf(operator), 0);
    }

    // ─── Reverting beneficiary safety (pull-payment) ─────────────
    function test_revertingBeneficiarySafety() public {
        RevertingReceiverSec revBenef = new RevertingReceiverSec();
        bytes32 dealId = bytes32(uint256(1));
        uint32 deadline = uint32(block.timestamp + 1 hours);

        vm.prank(client);
        apa.depositAndConfigure{value: 1 ether}(
            dealId, hash1, address(revBenef), operator, deadline, 500,
            capTarget, capSelector, capExpiry, capNonce
        );

        // Reveal succeeds because payment is pull-based
        vm.prank(address(revBenef));
        bytes32 capId = apa.revealAndMint(client, dealId, preimage1);
        assertEq(apa.capabilities(capId), client);

        // Beneficiary has balance but cannot withdraw
        uint256 benBal = apa.balanceOf(address(revBenef));
        assertGt(benBal, 0);

        vm.prank(address(revBenef));
        vm.expectRevert(AtomicPayForAccess.EthTransferFailed.selector);
        apa.withdraw();
    }
}
