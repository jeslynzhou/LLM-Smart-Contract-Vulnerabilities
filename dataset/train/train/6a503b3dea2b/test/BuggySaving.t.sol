// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Test, console} from "forge-std/Test.sol";
import {BuggySaving} from "../src/BuggySaving.sol";

contract BuggySavingTest is Test {
    BuggySaving public saving;

    function setUp() public {
        saving = new BuggySaving();
        vm.deal(address(this), 100 ether);
    }

    function test_Deposit() public {
        uint256 depositAmount = 5 ether;
        uint256 numDays = 30;
        
        saving.deposit{value: depositAmount}(numDays);
        
        assertEq(address(saving).balance, depositAmount);
    }

    function test_DepositMultipleTimes() public {
        saving.deposit{value: 3 ether}(10);
        saving.deposit{value: 2 ether}(5);
        
        assertEq(address(saving).balance, 5 ether);
    }

    receive() external payable {}
}
