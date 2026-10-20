// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title VulnerableUncheckedCallDistributor
 * @notice Educational demonstration contract containing Unchecked Low-Level Calls.
 *         For defensive testing and academic evaluation only.
 */
contract VulnerableUncheckedCallDistributor {
    mapping(address => uint256) public pendingPayouts;
    address public admin;

    constructor() payable {
        admin = msg.sender;
    }

    function allocatePayout(address beneficiary, uint256 amount) external {
        require(msg.sender == admin, "Only admin");
        pendingPayouts[beneficiary] += amount;
    }

    function processPayout(address payable payee) public {
        uint256 amount = pendingPayouts[payee];
        require(amount > 0, "Nothing to pay");
        pendingPayouts[payee] = 0;

        // VULNERABILITY 1: Return value of low-level .send() is not checked
        payee.send(amount);
    }

    function forwardData(address payable target, bytes calldata payload) public payable {
        // VULNERABILITY 2: Return value of low-level .call() is ignored
        target.call{value: msg.value}(payload);
    }
}
