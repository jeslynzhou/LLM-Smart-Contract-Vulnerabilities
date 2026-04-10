// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/token/ERC20/extensions/ERC20Burnable.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

/**
 * @title ChiikawaToken
 * @dev Chiikawa ERC20 token contract
 * @notice This is an ERC20 token with burn functionality
 */
contract ChiikawaToken is ERC20, ERC20Burnable, Ownable {
    /// @dev Token decimals
    uint8 private constant DECIMALS = 18;
    
    /// @dev Initial supply: 100 million tokens
    uint256 private constant INITIAL_SUPPLY = 100_000_000 * 10**DECIMALS;

    /**
     * @dev Constructor
     * @param initialOwner Initial owner address
     */
    constructor(address initialOwner) 
        ERC20("Chiikawa Token", "CHIIKAWA") 
        Ownable(initialOwner)
    {
        _mint(initialOwner, INITIAL_SUPPLY);
    }

    /**
     * @dev Mint new tokens
     * @param to Recipient address
     * @param amount Amount to mint
     */
    function mint(address to, uint256 amount) public  {
        _mint(to, amount);
    }

    /**
     * @dev Returns the token decimals
     */
    function decimals() public pure override returns (uint8) {
        return DECIMALS;
    }
}
