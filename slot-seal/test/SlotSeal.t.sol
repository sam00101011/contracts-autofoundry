// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "../src/SlotSeal.sol";

interface Vm {
    function prank(address) external;
    function warp(uint256) external;
    function expectRevert(bytes4) external;
}

contract SlotSealTest {
    Vm internal constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));
    SlotSeal internal seal;

    address internal constant ISSUER = address(0xBEEF);
    address internal constant ASSIGNEE = address(0xA11CE);
    address internal constant OTHER = address(0xCAFE);
    address internal constant DESTINATION = address(0xD357);
    uint256 internal constant NONCE = 7;
    bytes32 internal constant INTENT_HASH = keccak256("intent");
    bytes32 internal constant COMPLETION_HASH = keccak256("completion");

    function setUp() external {
        seal = new SlotSeal();
    }

    function assertEq(address a, address b) internal pure {
        if (a != b) revert("assert address eq");
    }

    function assertEq(uint256 a, uint256 b) internal pure {
        if (a != b) revert("assert uint eq");
    }

    function assertEq(bytes32 a, bytes32 b) internal pure {
        if (a != b) revert("assert bytes32 eq");
    }

    function testAssignAndCompleteStoresDeterministicBadge() external {
        uint40 expiry = uint40(block.timestamp + 1 days);
        bytes32 slotId = seal.slotIdFor(ISSUER, ASSIGNEE, DESTINATION, NONCE);

        vm.prank(ISSUER);
        bytes32 assignedSlotId = seal.assign(ASSIGNEE, DESTINATION, NONCE, expiry, INTENT_HASH);

        vm.prank(ASSIGNEE);
        (bytes32 completedSlotId, bytes32 badge) = seal.complete(ISSUER, DESTINATION, NONCE, INTENT_HASH);

        (address assignee, uint40 storedExpiry, uint8 state, bytes32 intentHash, bytes32 storedBadge) = seal.slot(slotId);

        assertEq(assignedSlotId, slotId);
        assertEq(completedSlotId, slotId);
        assertEq(assignee, ASSIGNEE);
        assertEq(storedExpiry, expiry);
        assertEq(state, 2);
        assertEq(intentHash, INTENT_HASH);
        assertEq(storedBadge, keccak256(abi.encode(slotId, ASSIGNEE, INTENT_HASH)));
        assertEq(badge, storedBadge);
    }

    function testAssignRejectsZeroAssignee() external {
        vm.prank(ISSUER);
        vm.expectRevert(SlotSeal.InvalidAssignee.selector);
        seal.assign(address(0), DESTINATION, NONCE, uint40(block.timestamp + 1 days), INTENT_HASH);
    }

    function testAssignRejectsExpiredWindow() external {
        vm.prank(ISSUER);
        vm.expectRevert(SlotSeal.InvalidExpiry.selector);
        seal.assign(ASSIGNEE, DESTINATION, NONCE, uint40(block.timestamp), INTENT_HASH);
    }

    function testSlotIdIsDeterministic() external view {
        bytes32 expected = keccak256(abi.encode(block.chainid, address(seal), ISSUER, ASSIGNEE, DESTINATION, NONCE));
        assertEq(seal.slotIdFor(ISSUER, ASSIGNEE, DESTINATION, NONCE), expected);
    }

    function testSlotIdDependsOnDestination() external view {
        bytes32 a = seal.slotIdFor(ISSUER, ASSIGNEE, DESTINATION, NONCE);
        bytes32 b = seal.slotIdFor(ISSUER, ASSIGNEE, OTHER, NONCE);
        if (a == b) revert("slot id should depend on destination");
    }

    function testSlotIdDependsOnContractDomain() external {
        SlotSeal otherSeal = new SlotSeal();
        bytes32 a = seal.slotIdFor(ISSUER, ASSIGNEE, DESTINATION, NONCE);
        bytes32 b = otherSeal.slotIdFor(ISSUER, ASSIGNEE, DESTINATION, NONCE);
        if (a == b) revert("slot id should depend on contract");
    }

    function testOnlyAssigneeCanComplete() external {
        vm.prank(ISSUER);
        seal.assign(ASSIGNEE, DESTINATION, NONCE, uint40(block.timestamp + 1 days), INTENT_HASH);

        vm.prank(OTHER);
        vm.expectRevert(SlotSeal.BadState.selector);
        seal.complete(ISSUER, DESTINATION, NONCE, COMPLETION_HASH);
    }

    function testCannotCompleteAfterExpiry() external {
        vm.prank(ISSUER);
        seal.assign(ASSIGNEE, DESTINATION, NONCE, uint40(block.timestamp + 1 hours), INTENT_HASH);

        vm.warp(block.timestamp + 1 hours + 1);

        vm.prank(ASSIGNEE);
        vm.expectRevert(SlotSeal.Expired.selector);
        seal.complete(ISSUER, DESTINATION, NONCE, COMPLETION_HASH);
    }

    function testReclaimMarksSlotReclaimed() external {
        bytes32 slotId = seal.slotIdFor(ISSUER, ASSIGNEE, DESTINATION, NONCE);

        vm.prank(ISSUER);
        seal.assign(ASSIGNEE, DESTINATION, NONCE, uint40(block.timestamp + 1 hours), INTENT_HASH);

        vm.warp(block.timestamp + 1 hours + 1);

        vm.prank(ISSUER);
        seal.reclaim(ASSIGNEE, DESTINATION, NONCE);

        (address assignee,, uint8 state, bytes32 intentHash, bytes32 badge) = seal.slot(slotId);

        assertEq(assignee, ASSIGNEE);
        assertEq(state, 3);
        assertEq(intentHash, INTENT_HASH);
        assertEq(badge, bytes32(0));
    }

    function testCannotReclaimBeforeExpiry() external {
        vm.prank(ISSUER);
        seal.assign(ASSIGNEE, DESTINATION, NONCE, uint40(block.timestamp + 1 days), INTENT_HASH);

        vm.prank(ISSUER);
        vm.expectRevert(SlotSeal.NotExpired.selector);
        seal.reclaim(ASSIGNEE, DESTINATION, NONCE);
    }

    function testRejectsZeroCompletionHash() external {
        vm.prank(ISSUER);
        seal.assign(ASSIGNEE, DESTINATION, NONCE, uint40(block.timestamp + 1 days), INTENT_HASH);

        vm.prank(ASSIGNEE);
        vm.expectRevert(SlotSeal.InvalidCompletion.selector);
        seal.complete(ISSUER, DESTINATION, NONCE, bytes32(0));
    }

    function testRejectsWrongCompletionHash() external {
        vm.prank(ISSUER);
        seal.assign(ASSIGNEE, DESTINATION, NONCE, uint40(block.timestamp + 1 days), INTENT_HASH);

        vm.prank(ASSIGNEE);
        vm.expectRevert(SlotSeal.InvalidCompletion.selector);
        seal.complete(ISSUER, DESTINATION, NONCE, COMPLETION_HASH);
    }

    function testWrongDestinationCannotComplete() external {
        vm.prank(ISSUER);
        seal.assign(ASSIGNEE, DESTINATION, NONCE, uint40(block.timestamp + 1 days), INTENT_HASH);

        vm.prank(ASSIGNEE);
        vm.expectRevert(SlotSeal.BadState.selector);
        seal.complete(ISSUER, OTHER, NONCE, COMPLETION_HASH);
    }

    function testCannotReuseReclaimedSlot() external {
        vm.prank(ISSUER);
        seal.assign(ASSIGNEE, DESTINATION, NONCE, uint40(block.timestamp + 1 hours), INTENT_HASH);

        vm.warp(block.timestamp + 1 hours + 1);

        vm.prank(ISSUER);
        seal.reclaim(ASSIGNEE, DESTINATION, NONCE);

        vm.prank(ISSUER);
        vm.expectRevert(SlotSeal.BadState.selector);
        seal.assign(ASSIGNEE, DESTINATION, NONCE, uint40(block.timestamp + 2 hours), INTENT_HASH);
    }
}
