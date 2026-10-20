// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Educational example: access control added.
contract SecureContract {
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    // Only the current owner can transfer ownership.
    function changeOwner(address newOwner) public {
        require(msg.sender == owner, "Only owner can change owner");
        require(newOwner != address(0), "Invalid owner");
        owner = newOwner;
    }
}
