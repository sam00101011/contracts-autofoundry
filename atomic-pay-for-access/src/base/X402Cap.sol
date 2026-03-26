// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

contract X402Cap {
    mapping(bytes32 => address) public capabilities;

    address public immutable owner;
    mapping(address => bool) public authorizedMinters;

    event Minted(bytes32 indexed capId, address indexed payer, address target, bytes4 selector, uint256 expiry);
    event Burned(bytes32 indexed capId, address indexed payer);

    error AlreadyMinted();
    error NotHolder();
    error Expired();
    error Unauthorized();
    error NotOwner();
    error InvalidSelector();

    constructor() {
        owner = msg.sender;
    }

    function setMinterAuthorization(address minter, bool authorized) external {
        if (msg.sender != owner) revert NotOwner();
        authorizedMinters[minter] = authorized;
    }

    function mint(
        uint256 amount,
        address token,
        uint256 nonce,
        uint256 expiry,
        address target,
        bytes4  selector
    ) external returns (bytes32 capId) {
        if (!authorizedMinters[msg.sender]) revert Unauthorized();
        if (block.timestamp > expiry) revert Expired();
        if (selector == bytes4(0)) revert InvalidSelector();
        capId = keccak256(abi.encode(
            msg.sender, amount, token, nonce, expiry, target, selector, block.chainid, address(this)
        ));
        if (capabilities[capId] != address(0)) revert AlreadyMinted();
        capabilities[capId] = msg.sender;
        emit Minted(capId, msg.sender, target, selector, expiry);
    }

    function burn(bytes32 capId) external {
        address holder = capabilities[capId];
        if (holder != msg.sender) revert NotHolder();
        delete capabilities[capId];
        emit Burned(capId, msg.sender);
    }

    function computeCapId(
        address payer,
        uint256 amount,
        address token,
        uint256 nonce,
        uint256 expiry,
        address target,
        bytes4  selector
    ) external view returns (bytes32) {
        return keccak256(abi.encode(
            payer, amount, token, nonce, expiry, target, selector, block.chainid, address(this)
        ));
    }
}
