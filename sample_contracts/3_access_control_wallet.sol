// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title VulnerableAccessControlTreasury
 * @notice Educational demonstration contract containing Access Control weaknesses
 *         (tx.origin authentication and unprotected administrative delegatecall).
 *         For defensive testing and academic evaluation only.
 */
contract VulnerableAccessControlTreasury {
    address public owner;
    address public LogicContract;

    constructor() payable {
        owner = msg.sender;
    }

    // VULNERABILITY 1: Authentication using tx.origin enables phishing attacks
    function sweepFunds(address payable recipient, uint256 amount) public {
        require(tx.origin == owner, "Not authorized via tx.origin");
        require(address(this).balance >= amount, "Insufficient treasury funds");
        recipient.transfer(amount);
    }

    // VULNERABILITY 2: Unprotected delegatecall allows arbitrary storage manipulation
    function executeDelegate(address target, bytes memory data) public payable {
        (bool ok, ) = target.delegatecall(data);
        require(ok, "Delegatecall failed");
    }

    // VULNERABILITY 3: Selfdestruct guarded by tx.origin
    function destroyTreasury(address payable beneficiary) public {
        require(tx.origin == owner, "Only origin owner");
        selfdestruct(beneficiary);
    }

    receive() external payable {}
}
