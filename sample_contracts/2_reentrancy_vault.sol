// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title VulnerableReentrancyVault
 * @notice Educational demonstration contract containing a classic Reentrancy weakness.
 *         For defensive testing and academic evaluation only.
 */
contract VulnerableReentrancyVault {
    mapping(address => uint256) public balances;

    event Deposited(address indexed user, uint256 amount);
    event Withdrawn(address indexed user, uint256 amount);

    function deposit() public payable {
        require(msg.value > 0, "Must deposit positive ETH");
        balances[msg.sender] += msg.value;
        emit Deposited(msg.sender, msg.value);
    }

    function withdrawAll() public {
        uint256 userBalance = balances[msg.sender];
        require(userBalance > 0, "Insufficient balance");

        // VULNERABILITY: Low-level external call sending ETH BEFORE updating state
        (bool success, ) = msg.sender.call{value: userBalance}("");
        require(success, "ETH transfer failed");

        // State update occurs AFTER external interaction (Checks-Effects-Interactions violation)
        balances[msg.sender] = 0;
        emit Withdrawn(msg.sender, userBalance);
    }

    function getVaultBalance() public view returns (uint256) {
        return address(this).balance;
    }
}
