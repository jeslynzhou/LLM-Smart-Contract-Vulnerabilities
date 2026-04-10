// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/token/ERC721/ERC721.sol";

/**
 * @title ChiikawaSticker
 * @dev Contract demonstrating safeMint reentrancy vulnerability
 */
contract ChiikawaSticker is ERC721 {
    // NFT price
    uint256 public stickerPrice;
    
    // Current token ID
    uint256 private _currentTokenId = 0;
    
    // Maximum supply
    uint256 public maxSupply;
    
    // Whether user can claim NFT
    mapping(address => bool) public canClaim;
    
    // Events
    event NFTPurchased(address indexed buyer);
    event NFTClaimed(address indexed claimer, uint256 tokenId);
    
    /**
     * @dev Constructor
     */
    constructor(
        uint256 _price,
        uint256 _maxSupply,
        string memory
    ) ERC721("Chiikawa Sticker", "CHIIKAWA") {
        stickerPrice = _price;
        maxSupply = _maxSupply;
    }
    
    /**
     * @dev Buy NFT (payment)
     */
    function buyNFT() external payable {
        require(msg.value == stickerPrice, "Must pay exact price");
        require(!canClaim[msg.sender], "Already purchased");
        
        canClaim[msg.sender] = true;
        emit NFTPurchased(msg.sender);
    }
    
    /**
     * @dev Claim NFT 
     */
    function claim() external {
        require(canClaim[msg.sender], "You must buy NFT first");
        require(_currentTokenId < maxSupply, "Sold out");
        
        _currentTokenId++;
        uint256 newTokenId = _currentTokenId;
        
        
        
        _safeMint(msg.sender, newTokenId);
        
      
        canClaim[msg.sender] = false;
        
        emit NFTClaimed(msg.sender, newTokenId);
    }
    
    /**
     * @dev Get total minted count
     */
    function totalMinted() external view returns (uint256) {
        return _currentTokenId;
    }
}
