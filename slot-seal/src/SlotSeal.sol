// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract SlotSeal {
    error BadState();
    error Expired();
    error NotAssignee();
    error NotExpired();
    error InvalidAssignee();
    error InvalidExpiry();
    error InvalidCompletion();

    event Assigned(
        bytes32 indexed slotId,
        address indexed issuer,
        address indexed assignee,
        address destination,
        uint40 expiry
    );
    event Completed(bytes32 indexed slotId, address indexed assignee, bytes32 completionHash, bytes32 badge);
    event Reclaimed(bytes32 indexed slotId, address indexed issuer);

    uint8 internal constant STATE_EMPTY = 0;
    uint8 internal constant STATE_ASSIGNED = 1;
    uint8 internal constant STATE_COMPLETED = 2;
    uint8 internal constant STATE_RECLAIMED = 3;

    // word: assignee(160) | expiry(40) | state(8)
    mapping(bytes32 => uint256) private slotWord;
    mapping(bytes32 => bytes32) private slotIntentHash;
    mapping(bytes32 => bytes32) private slotBadge;

    function slotIdFor(address issuer, address assignee, address destination, uint256 nonce)
        public
        view
        returns (bytes32)
    {
        return keccak256(abi.encode(block.chainid, address(this), issuer, assignee, destination, nonce));
    }

    function assign(address assignee, address destination, uint256 nonce, uint40 expiry, bytes32 intentHash)
        external
        returns (bytes32 slotId)
    {
        if (assignee == address(0)) revert InvalidAssignee();
        if (expiry <= block.timestamp) revert InvalidExpiry();

        slotId = slotIdFor(msg.sender, assignee, destination, nonce);
        if (slotWord[slotId] != 0) revert BadState();

        slotWord[slotId] =
            (uint256(uint160(assignee)) << 48) |
            (uint256(expiry) << 8) |
            STATE_ASSIGNED;
        slotIntentHash[slotId] = intentHash;

        emit Assigned(slotId, msg.sender, assignee, destination, expiry);
    }

    function complete(address issuer, address destination, uint256 nonce, bytes32 completionHash)
        external
        returns (bytes32 slotId, bytes32 badge)
    {
        if (completionHash == bytes32(0)) revert InvalidCompletion();

        slotId = slotIdFor(issuer, msg.sender, destination, nonce);
        uint256 word = slotWord[slotId];
        // forge-lint: disable-next-line(unsafe-typecast)
        uint8 state = uint8(word);
        // forge-lint: disable-next-line(unsafe-typecast)
        uint40 expiry = uint40(word >> 8);

        if (state != STATE_ASSIGNED) revert BadState();
        if (block.timestamp > expiry) revert Expired();
        if (slotIntentHash[slotId] != completionHash) revert InvalidCompletion();

        badge = keccak256(abi.encode(slotId, msg.sender, completionHash));
        slotWord[slotId] = (word & ~uint256(0xff)) | STATE_COMPLETED;
        slotBadge[slotId] = badge;

        emit Completed(slotId, msg.sender, completionHash, badge);
    }

    function reclaim(address assignee, address destination, uint256 nonce) external returns (bytes32 slotId) {
        slotId = slotIdFor(msg.sender, assignee, destination, nonce);
        uint256 word = slotWord[slotId];
        // forge-lint: disable-next-line(unsafe-typecast)
        uint8 state = uint8(word);
        // forge-lint: disable-next-line(unsafe-typecast)
        uint40 expiry = uint40(word >> 8);

        if (state != STATE_ASSIGNED) revert BadState();
        if (block.timestamp <= expiry) revert NotExpired();

        slotWord[slotId] = (word & ~uint256(0xff)) | STATE_RECLAIMED;

        emit Reclaimed(slotId, msg.sender);
    }

    function slot(bytes32 slotId)
        external
        view
        returns (address assignee, uint40 expiry, uint8 state, bytes32 intentHash, bytes32 badge)
    {
        uint256 word = slotWord[slotId];
        // forge-lint: disable-next-line(unsafe-typecast)
        assignee = address(uint160(word >> 48));
        // forge-lint: disable-next-line(unsafe-typecast)
        expiry = uint40(word >> 8);
        // forge-lint: disable-next-line(unsafe-typecast)
        state = uint8(word);
        intentHash = slotIntentHash[slotId];
        badge = slotBadge[slotId];
    }
}
