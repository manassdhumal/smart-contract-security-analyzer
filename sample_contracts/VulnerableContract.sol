// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Educational example: missing access control.
contract VulnerableContract {
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    // VULNERABILITY: Anyone can call this function and become the owner.
    function changeOwner(address newOwner) public {
        require(newOwner != address(0), "Invalid owner");
        owner = newOwner;
    }
}
