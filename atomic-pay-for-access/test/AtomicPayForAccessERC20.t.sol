// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import "forge-std/Test.sol";
import "../src/AtomicPayForAccessERC20.sol";

/// @notice Minimal mock ERC20 for testing
contract MockERC20 is IERC20 {
    string public name = "Mock USD";
    string public symbol = "MUSD";
    uint8 public decimals = 6;
    uint256 public totalSupply;
    mapping(address => uint256) public balances;
    mapping(address => mapping(address => uint256)) public allowances;

    function mint(address to, uint256 amount) external {
        balances[to] += amount;
        totalSupply += amount;
    }

    function balanceOf(address account) external view override returns (uint256) {
        return balances[account];
    }

    function approve(address spender, uint256 amount) external override returns (bool) {
        allowances[msg.sender][spender] = amount;
        return true;
    }

    function transfer(address to, uint256 amount) external override returns (bool) {
        require(balances[msg.sender] >= amount, "insufficient");
        balances[msg.sender] -= amount;
        balances[to] += amount;
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external override returns (bool) {
        require(balances[from] >= amount, "insufficient");
        require(allowances[from][msg.sender] >= amount, "allowance");
        allowances[from][msg.sender] -= amount;
        balances[from] -= amount;
        balances[to] += amount;
        return true;
    }
}

contract AtomicPayForAccessERC20Test is Test {
    AtomicPayForAccessERC20 apa;
    MockERC20 token;

    address depositor = address(0xDEAD);
    address beneficiary = address(0xBEEF);
    address operator = address(0xCAFE);

    bytes32 preimage = keccak256("secret");
    bytes32 hash_;

    address capTarget = address(0x1234);
    bytes4 capSelector = bytes4(0xaabbccdd);
    uint256 capExpiry;
    uint256 capNonce = 42;

    uint96 depositAmount = 1_000_000; // 1 MUSD (6 decimals)

    function setUp() public {
        token = new MockERC20();
        apa = new AtomicPayForAccessERC20(address(token));

        hash_ = keccak256(abi.encodePacked(preimage));
        capExpiry = block.timestamp + 1 days;

        // Fund depositor
        token.mint(depositor, 100_000_000); // 100 MUSD

        // Register operator
        vm.prank(operator);
        apa.setOperatorRegistration(true);
    }

    // ─── Helpers ────────────────────────────────────────────
    function _approveAndDeposit(bytes32 id, uint16 feeBps) internal {
        vm.startPrank(depositor);
        token.approve(address(apa), depositAmount);
        apa.depositAndConfigure(
            id, hash_, beneficiary, operator,
            uint32(block.timestamp + 1 hours),
            feeBps,
            capTarget, capSelector, capExpiry, capNonce,
            depositAmount
        );
        vm.stopPrank();
    }

    // ─── Tests ──────────────────────────────────────────────

    function test_paymentToken() public view {
        assertEq(address(apa.paymentToken()), address(token));
    }

    function test_depositAndConfigure() public {
        bytes32 id = keccak256("deal1");
        _approveAndDeposit(id, 500);

        // Check token was transferred
        assertEq(token.balances(address(apa)), depositAmount);
        assertEq(token.balances(depositor), 100_000_000 - depositAmount);
    }

    function test_revealAndMint() public {
        bytes32 id = keccak256("deal2");
        _approveAndDeposit(id, 1000); // 10% fee

        // Reveal
        vm.prank(beneficiary);
        bytes32 capId = apa.revealAndMint(depositor, id, preimage);

        // Check internal balances
        uint256 fee = uint256(depositAmount) * 1000 / 10_000; // 100_000
        uint256 beneficiaryAmt = uint256(depositAmount) - fee; // 900_000

        assertEq(apa.balanceOf(beneficiary), beneficiaryAmt);
        assertEq(apa.balanceOf(operator), fee);

        // Cap minted to depositor
        assertEq(apa.capabilities(capId), depositor);
    }

    function test_withdraw() public {
        bytes32 id = keccak256("deal3");
        _approveAndDeposit(id, 0); // no fee

        // Reveal
        vm.prank(beneficiary);
        apa.revealAndMint(depositor, id, preimage);

        assertEq(apa.balanceOf(beneficiary), depositAmount);

        // Withdraw
        uint256 before = token.balances(beneficiary);
        vm.prank(beneficiary);
        apa.withdraw();

        assertEq(apa.balanceOf(beneficiary), 0);
        assertEq(token.balances(beneficiary), before + depositAmount);
    }

    function test_burnCapability() public {
        bytes32 id = keccak256("deal4");
        _approveAndDeposit(id, 0);

        vm.prank(beneficiary);
        bytes32 capId = apa.revealAndMint(depositor, id, preimage);

        assertEq(apa.capabilities(capId), depositor);

        // Burn
        vm.prank(depositor);
        apa.burnCapability(capId);

        assertEq(apa.capabilities(capId), address(1)); // BURNED sentinel
    }

    function test_refund() public {
        bytes32 id = keccak256("deal5");
        _approveAndDeposit(id, 0);

        // Warp past deadline
        vm.warp(block.timestamp + 2 hours);

        vm.prank(depositor);
        apa.refund(id);

        assertEq(apa.balanceOf(depositor), depositAmount);

        // Withdraw refund
        uint256 before = token.balances(depositor);
        vm.prank(depositor);
        apa.withdraw();
        assertEq(token.balances(depositor), before + depositAmount);
    }

    function test_revert_depositZero() public {
        vm.startPrank(depositor);
        token.approve(address(apa), 0);
        vm.expectRevert(AtomicPayForAccessERC20.InvalidDeposit.selector);
        apa.depositAndConfigure(
            keccak256("x"), hash_, beneficiary, operator,
            uint32(block.timestamp + 1 hours), 0,
            capTarget, capSelector, capExpiry, capNonce,
            0 // zero amount
        );
        vm.stopPrank();
    }

    function test_revert_dealExists() public {
        bytes32 id = keccak256("dup");
        _approveAndDeposit(id, 0);

        vm.startPrank(depositor);
        token.approve(address(apa), depositAmount);
        vm.expectRevert(AtomicPayForAccessERC20.DealExists.selector);
        apa.depositAndConfigure(
            id, hash_, beneficiary, operator,
            uint32(block.timestamp + 1 hours), 0,
            capTarget, capSelector, capExpiry, capNonce,
            depositAmount
        );
        vm.stopPrank();
    }

    function test_revert_badPreimage() public {
        bytes32 id = keccak256("bad");
        _approveAndDeposit(id, 0);

        vm.expectRevert(AtomicPayForAccessERC20.BadPreimage.selector);
        apa.revealAndMint(depositor, id, keccak256("wrong"));
    }

    function test_revert_burnNotHolder() public {
        bytes32 id = keccak256("bnh");
        _approveAndDeposit(id, 0);

        vm.prank(beneficiary);
        bytes32 capId = apa.revealAndMint(depositor, id, preimage);

        vm.prank(address(0x999));
        vm.expectRevert(AtomicPayForAccessERC20.NotHolder.selector);
        apa.burnCapability(capId);
    }

    function test_revert_refundBeforeDeadline() public {
        bytes32 id = keccak256("early");
        _approveAndDeposit(id, 0);

        vm.prank(depositor);
        vm.expectRevert(AtomicPayForAccessERC20.DeadlineNotPassed.selector);
        apa.refund(id);
    }

    function test_revert_withdrawNoBalance() public {
        vm.prank(address(0x999));
        vm.expectRevert(AtomicPayForAccessERC20.NoBalance.selector);
        apa.withdraw();
    }

    function test_fullLifecycle() public {
        bytes32 id = keccak256("lifecycle");
        uint16 feeBps = 500; // 5%

        // 1. Approve + Deposit
        _approveAndDeposit(id, feeBps);
        assertEq(token.balances(address(apa)), depositAmount);

        // 2. Reveal
        vm.prank(beneficiary);
        bytes32 capId = apa.revealAndMint(depositor, id, preimage);

        // 3. Check balances
        uint256 fee = uint256(depositAmount) * feeBps / 10_000;
        uint256 beneficiaryAmt = uint256(depositAmount) - fee;
        assertEq(apa.balanceOf(beneficiary), beneficiaryAmt);
        assertEq(apa.balanceOf(operator), fee);

        // 4. Beneficiary withdraws
        vm.prank(beneficiary);
        apa.withdraw();
        assertEq(token.balances(beneficiary), beneficiaryAmt);

        // 5. Operator withdraws
        vm.prank(operator);
        apa.withdraw();
        assertEq(token.balances(operator), fee);

        // 6. Burn capability
        vm.prank(depositor);
        apa.burnCapability(capId);
        assertEq(apa.capabilities(capId), address(1));

        // 7. Contract should have zero token balance
        assertEq(token.balances(address(apa)), 0);
    }

    function test_computeCapId() public view {
        bytes32 id = keccak256("compute");
        bytes32 expected = keccak256(abi.encode(
            depositor, id, uint256(depositAmount), address(0), capNonce, capExpiry, capTarget, capSelector, block.chainid, address(apa)
        ));
        bytes32 computed = apa.computeCapId(depositor, id, depositAmount, capNonce, capExpiry, capTarget, capSelector);
        assertEq(computed, expected);
    }
}
