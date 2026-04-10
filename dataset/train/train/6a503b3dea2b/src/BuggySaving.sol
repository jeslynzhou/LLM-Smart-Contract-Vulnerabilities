// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract BuggySaving {
    address public owner;
    uint256 public savedAmount;
    uint256 public savedDays;
    uint256 public target = 20 ether;

    constructor() {
        owner = msg.sender;
    }

    function deposit(uint256 _days) external payable {
        savedAmount += _days;
        savedDays += msg.value;
    }

    function canIBuy() public view returns (bool) {
        return savedAmount >= target;
    }

    function withdraw() external {
        require(msg.sender == owner, "Not owner");
        require(canIBuy(), "Not enough saved!");
        (bool success, ) = owner.call{value: address(this).balance}("");
        require(success, "Withdraw failed");
    }
}