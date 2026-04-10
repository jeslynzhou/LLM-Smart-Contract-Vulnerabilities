// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Script, console} from "forge-std/Script.sol";
import {ChiikawaToken} from "../src/ChiikawaToken.sol";

contract DeployChiikawaToken is Script {
    function run() external returns (ChiikawaToken) {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        address deployerAddress = vm.addr(deployerPrivateKey);
        
        vm.startBroadcast(deployerPrivateKey);
        
        ChiikawaToken token = new ChiikawaToken(deployerAddress);
        
        console.log("ChiikawaToken deployed to:", address(token));
        console.log("Initial owner:", deployerAddress);
        console.log("Total supply:", token.totalSupply());
        
        vm.stopBroadcast();
        
        return token;
    }
}
