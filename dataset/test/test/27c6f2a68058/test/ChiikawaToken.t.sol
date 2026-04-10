// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test, console} from "forge-std/Test.sol";
import {ChiikawaToken} from "../src/ChiikawaToken.sol";

contract ChiikawaTokenTest is Test {
    ChiikawaToken public token;
    address public owner;
    address public user1;
    address public user2;

    uint256 constant INITIAL_SUPPLY = 100_000_000 * 10**18;

    function setUp() public {
        owner = address(this);
        user1 = makeAddr("user1");
        user2 = makeAddr("user2");
        
        token = new ChiikawaToken(owner);
    }

    function test_Initialization() public {
        assertEq(token.name(), "Chiikawa Token");
        assertEq(token.symbol(), "CHIIKAWA");
        assertEq(token.decimals(), 18);
        assertEq(token.totalSupply(), INITIAL_SUPPLY);
        assertEq(token.balanceOf(owner), INITIAL_SUPPLY);
    }

    function test_Transfer() public {
        uint256 transferAmount = 1000 * 10**18;
        
        token.transfer(user1, transferAmount);
        
        assertEq(token.balanceOf(user1), transferAmount);
        assertEq(token.balanceOf(owner), INITIAL_SUPPLY - transferAmount);
    }

    function test_Approve() public {
        uint256 approvalAmount = 5000 * 10**18;
        
        token.approve(user1, approvalAmount);
        
        assertEq(token.allowance(owner, user1), approvalAmount);
    }

    function test_TransferFrom() public {
        uint256 amount = 2000 * 10**18;
        
        token.approve(user1, amount);
        
        vm.prank(user1);
        token.transferFrom(owner, user2, amount);
        
        assertEq(token.balanceOf(user2), amount);
        assertEq(token.balanceOf(owner), INITIAL_SUPPLY - amount);
    }

    function test_Mint() public {
        uint256 mintAmount = 10_000 * 10**18;
        
        token.mint(user1, mintAmount);
        
        assertEq(token.balanceOf(user1), mintAmount);
        assertEq(token.totalSupply(), INITIAL_SUPPLY + mintAmount);
    }

    function test_Burn() public {
        uint256 burnAmount = 1_000 * 10**18;
        uint256 transferAmount = 5_000 * 10**18;
        
        token.transfer(user1, transferAmount);
        
        vm.prank(user1);
        token.burn(burnAmount);
        
        assertEq(token.balanceOf(user1), transferAmount - burnAmount);
        assertEq(token.totalSupply(), INITIAL_SUPPLY - burnAmount);
    }

    function test_BurnFrom() public {
        uint256 burnAmount = 500 * 10**18;
        uint256 transferAmount = 5_000 * 10**18;
        
        token.transfer(user1, transferAmount);
        
        vm.prank(user1);
        token.approve(owner, burnAmount);
        
        token.burnFrom(user1, burnAmount);
        
        assertEq(token.balanceOf(user1), transferAmount - burnAmount);
        assertEq(token.totalSupply(), INITIAL_SUPPLY - burnAmount);
    }

    function testFuzz_Transfer(uint256 amount) public {
        vm.assume(amount <= INITIAL_SUPPLY);
        
        token.transfer(user1, amount);
        
        assertEq(token.balanceOf(user1), amount);
        assertEq(token.balanceOf(owner), INITIAL_SUPPLY - amount);
    }
}
