// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

contract SplitClaimHashlock {
    error InvalidDeposit();
    error MissingDeal();
    error DealExists();
    error DeadlinePassed();
    error DeadlineNotPassed();
    error BadPreimage();
    error NoBalance();
    error InvalidOperator();
    error UnregisteredOperator();
    error EthTransferFailed();

    uint16 private constant MAX_FEE_BPS = 5_000;

    event Deposited(address indexed depositor, bytes32 indexed id, bytes32 hash, address beneficiary, address operator, uint96 amount, uint32 deadline, uint16 feeBps);
    event Revealed(address indexed depositor, bytes32 indexed id, address beneficiary, uint256 beneficiaryAmount, address operator, uint256 operatorFee);
    event Refunded(address indexed depositor, bytes32 indexed id, uint96 amount);
    event Withdrawn(address indexed account, uint256 amount);
    event OperatorRegistered(address indexed operator, bool enabled);

    struct Deal {
        bytes32 hash;
        address beneficiary;
        address operator;
        uint96 amount;
        uint32 deadline;
        uint16 feeBps;
    }

    mapping(address => mapping(bytes32 => Deal)) private deals;
    mapping(address => uint256) private balances;
    mapping(address => bool) private registeredOperators;

    function setOperatorRegistration(bool enabled) external {
        registeredOperators[msg.sender] = enabled;
        emit OperatorRegistered(msg.sender, enabled);
    }

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
            hash == bytes32(0) ||
            feeBps > MAX_FEE_BPS ||
            deadline <= block.timestamp
        ) revert InvalidDeposit();
        if (deals[msg.sender][id].deadline != 0) revert DealExists();

        if (feeBps != 0) {
            if (operator == address(0)) revert InvalidOperator();
            if (!registeredOperators[operator]) revert UnregisteredOperator();
        }

        deals[msg.sender][id] = Deal({
            hash: hash,
            beneficiary: beneficiary,
            operator: operator,
            amount: uint96(msg.value),
            deadline: deadline,
            feeBps: feeBps
        });

        emit Deposited(msg.sender, id, hash, beneficiary, operator, uint96(msg.value), deadline, feeBps);
    }

    function reveal(address depositor, bytes32 id, bytes32 preimage) external {
        Deal memory d = deals[depositor][id];
        if (d.deadline == 0) revert MissingDeal();
        if (block.timestamp > d.deadline) revert DeadlinePassed();
        if (keccak256(abi.encodePacked(preimage)) != d.hash) revert BadPreimage();

        delete deals[depositor][id];

        uint256 fee = uint256(d.amount) * d.feeBps / 10_000;
        uint256 beneficiaryAmount = uint256(d.amount) - fee;
        balances[d.beneficiary] += beneficiaryAmount;
        if (fee != 0) {
            balances[d.operator] += fee;
        }

        emit Revealed(depositor, id, d.beneficiary, beneficiaryAmount, d.operator, fee);
    }

    function refund(bytes32 id) external {
        Deal memory d = deals[msg.sender][id];
        if (d.deadline == 0) revert MissingDeal();
        if (block.timestamp <= d.deadline) revert DeadlineNotPassed();

        delete deals[msg.sender][id];
        balances[msg.sender] += d.amount;

        emit Refunded(msg.sender, id, d.amount);
    }

    function withdraw() external {
        uint256 amount = balances[msg.sender];
        if (amount == 0) revert NoBalance();

        balances[msg.sender] = 0;
        emit Withdrawn(msg.sender, amount);

        (bool ok,) = msg.sender.call{value: amount}("");
        if (!ok) revert EthTransferFailed();
    }
}
