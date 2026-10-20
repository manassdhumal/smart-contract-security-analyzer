// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title SimpleSafeLedger
 * @notice Educational demonstration contract without known security weaknesses.
 *         Uses Solidity 0.8.20 built-in overflow protection, strict access control,
 *         and contains no external calls or unchecked value transfers.
 */
contract SimpleSafeLedger {
    address public immutable owner;
    uint256 public totalRecorded;
    mapping(address => uint256) private _records;

    event RecordUpdated(address indexed account, uint256 newAmount);

    modifier onlyOwner() {
        require(msg.sender == owner, "SimpleSafeLedger: caller is not the owner");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    function setRecord(address account, uint256 amount) external onlyOwner {
        require(account != address(0), "SimpleSafeLedger: zero address");
        uint256 previous = _records[account];
        _records[account] = amount;
        totalRecorded = totalRecorded - previous + amount;
        emit RecordUpdated(account, amount);
    }

    function getRecord(address account) external view returns (uint256) {
        return _records[account];
    }
}
