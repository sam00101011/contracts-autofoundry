// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

/// @notice Minimal ERC20 interface — no SafeERC20, just direct calls + require.
interface IERC20 {
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function transfer(address to, uint256 amount) external returns (bool);
    function approve(address spender, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}

/// @title AtomicPayForAccessERC20
/// @notice ERC20 token variant of AtomicPayForAccess.
///         Combines SplitClaimHashlock escrow with X402Cap capability minting.
///         One transaction: approve → deposit → reveal preimage → settle fees → mint access credential.
contract AtomicPayForAccessERC20 {
    // ─── Errors ───────────────────────────────────────────────
    error InvalidDeposit();
    error MissingDeal();
    error DealExists();
    error DeadlinePassed();
    error DeadlineNotPassed();
    error BadPreimage();
    error NoBalance();
    error InvalidOperator();
    error UnregisteredOperator();
    error TokenTransferFailed();
    error AlreadyMinted();
    error NotHolder();
    error CapExpired();
    error InvalidCapConfig();

    // ─── Constants ──────────────────────────────────────────────
    uint16 private constant MAX_FEE_BPS = 5_000;
    address private constant BURNED = address(1);
    uint256 private constant MAX_CAP_DURATION = 365 days;

    // ─── Immutables ─────────────────────────────────────────────
    IERC20 public immutable paymentToken;

    // ─── Structs ──────────────────────────────────────────────
    struct Deal {
        bytes32 hash;
        address beneficiary;
        address operator;
        uint96  amount;
        uint32  deadline;
        uint16  feeBps;
    }

    struct CapConfig {
        address target;
        bytes4  selector;
        uint256 expiry;
        uint256 nonce;
    }

    // ─── Events ───────────────────────────────────────────────
    event CapabilityMinted(
        bytes32 indexed capId,
        address indexed depositor,
        bytes32 indexed dealId,
        address target,
        bytes4  selector,
        uint256 expiry,
        uint256 amount,
        uint256 nonce
    );
    event CapabilityBurned(bytes32 indexed capId, address indexed holder);
    event DealDeposited(address indexed depositor, bytes32 indexed id, address beneficiary, uint96 amount, uint32 deadline, bytes32 hash, address operator, uint16 feeBps);
    event DealRevealed(address indexed depositor, bytes32 indexed id, address beneficiary, uint256 beneficiaryAmount, uint256 operatorFee, address operator);
    event DealRefunded(address indexed depositor, bytes32 indexed id, uint96 amount);
    event Withdrawal(address indexed account, uint256 amount);
    event OperatorRegistration(address indexed operator, bool enabled);

    // ─── State ────────────────────────────────────────────────
    mapping(address => mapping(bytes32 => Deal))      private deals;
    mapping(address => mapping(bytes32 => CapConfig))  private capConfigs;
    mapping(address => uint256)                        private balances;
    mapping(address => bool)                           private registeredOperators;

    /// @notice Capability registry: capId → holder address (address(0) = not minted)
    mapping(bytes32 => address) public capabilities;

    // ─── Constructor ────────────────────────────────────────────
    constructor(address _paymentToken) {
        paymentToken = IERC20(_paymentToken);
    }

    // ─── Operator registration ────────────────────────────────
    function setOperatorRegistration(bool enabled) external {
        registeredOperators[msg.sender] = enabled;
        emit OperatorRegistration(msg.sender, enabled);
    }

    // ─── Deposit + configure capability ───────────────────────
    /// @notice Pull ERC20 tokens into hashlock escrow and pre-register capability parameters.
    ///         Caller must have approved this contract for >= amount on the paymentToken.
    function depositAndConfigure(
        bytes32 id,
        bytes32 hash,
        address beneficiary,
        address operator,
        uint32  deadline,
        uint16  feeBps,
        address capTarget,
        bytes4  capSelector,
        uint256 capExpiry,
        uint256 capNonce,
        uint96  amount
    ) external {
        // ── Hashlock deposit validation ──
        if (
            amount == 0 ||
            beneficiary == address(0) ||
            hash == bytes32(0) ||
            feeBps > MAX_FEE_BPS ||
            deadline <= block.timestamp
        ) revert InvalidDeposit();
        if (deals[msg.sender][id].deadline != 0) revert DealExists();

        if (feeBps != 0) {
            if (operator == address(0)) revert InvalidOperator();
            if (!registeredOperators[operator]) revert UnregisteredOperator();
        }

        // ── Capability config validation ──
        if (capExpiry == 0 || block.timestamp >= capExpiry) revert InvalidCapConfig();
        if (capExpiry > block.timestamp + MAX_CAP_DURATION) revert InvalidCapConfig();
        if (capTarget == address(0)) revert InvalidCapConfig();
        if (capSelector == bytes4(0)) revert InvalidCapConfig();

        // ── Pull tokens (CEI: state update after validation, before external call is ok
        //    because transferFrom is the *source* of funds, not a reentrancy vector) ──
        bool ok = paymentToken.transferFrom(msg.sender, address(this), amount);
        if (!ok) revert TokenTransferFailed();

        deals[msg.sender][id] = Deal({
            hash:        hash,
            beneficiary: beneficiary,
            operator:    operator,
            amount:      amount,
            deadline:    deadline,
            feeBps:      feeBps
        });

        capConfigs[msg.sender][id] = CapConfig({
            target:   capTarget,
            selector: capSelector,
            expiry:   capExpiry,
            nonce:    capNonce
        });

        emit DealDeposited(msg.sender, id, beneficiary, amount, deadline, hash, operator, feeBps);
    }

    // ─── Reveal + atomic mint ─────────────────────────────────
    /// @notice Reveal the preimage to settle payment AND atomically mint the capability.
    ///         Anyone can call this (typically the beneficiary who knows the preimage).
    function revealAndMint(address depositor, bytes32 id, bytes32 preimage)
        external
        returns (bytes32 capId)
    {
        Deal memory d = deals[depositor][id];
        if (d.deadline == 0) revert MissingDeal();
        if (block.timestamp > d.deadline) revert DeadlinePassed();
        if (keccak256(abi.encodePacked(preimage)) != d.hash) revert BadPreimage();

        CapConfig memory cc = capConfigs[depositor][id];

        // ── Clear state before effects ──
        delete deals[depositor][id];
        delete capConfigs[depositor][id];

        // ── Settle payment with fee split ──
        uint256 fee = uint256(d.amount) * d.feeBps / 10_000;
        uint256 beneficiaryAmount = uint256(d.amount) - fee;
        balances[d.beneficiary] += beneficiaryAmount;
        if (fee != 0) {
            balances[d.operator] += fee;
        }

        emit DealRevealed(depositor, id, d.beneficiary, beneficiaryAmount, fee, d.operator);

        // ── Mint capability to the depositor ──
        capId = keccak256(abi.encode(
            depositor, id, uint256(d.amount), address(0), cc.nonce, cc.expiry, cc.target, cc.selector, block.chainid, address(this)
        ));
        if (capabilities[capId] != address(0)) revert AlreadyMinted();
        capabilities[capId] = depositor;

        emit CapabilityMinted(capId, depositor, id, cc.target, cc.selector, cc.expiry, uint256(d.amount), cc.nonce);
    }

    // ─── Refund (no capability minted) ────────────────────────
    /// @notice Refund after deadline. No capability is minted.
    function refund(bytes32 id) external {
        Deal memory d = deals[msg.sender][id];
        if (d.deadline == 0) revert MissingDeal();
        if (block.timestamp <= d.deadline) revert DeadlineNotPassed();

        delete deals[msg.sender][id];
        delete capConfigs[msg.sender][id];

        balances[msg.sender] += d.amount;

        emit DealRefunded(msg.sender, id, d.amount);
    }

    // ─── Withdraw (pull-payment) ──────────────────────────────
    function withdraw() external {
        uint256 amount = balances[msg.sender];
        if (amount == 0) revert NoBalance();

        balances[msg.sender] = 0;
        emit Withdrawal(msg.sender, amount);

        bool ok = paymentToken.transfer(msg.sender, amount);
        if (!ok) revert TokenTransferFailed();
    }

    // ─── Capability burn passthrough ──────────────────────────
    function burnCapability(bytes32 capId) external {
        address holder = capabilities[capId];
        if (holder != msg.sender) revert NotHolder();
        capabilities[capId] = BURNED;
        emit CapabilityBurned(capId, msg.sender);
    }

    // ─── View helpers ─────────────────────────────────────────
    function balanceOf(address account) external view returns (uint256) {
        return balances[account];
    }

    function computeCapId(
        address depositor,
        bytes32 dealId,
        uint96  amount,
        uint256 nonce,
        uint256 expiry,
        address target,
        bytes4  selector
    ) external view returns (bytes32) {
        return keccak256(abi.encode(
            depositor, dealId, amount, address(0), nonce, expiry, target, selector, block.chainid, address(this)
        ));
    }
}
