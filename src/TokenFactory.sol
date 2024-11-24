// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import { Ownable } from "@openzeppelin/contracts/access/Ownable.sol";

// OK
/* 
* @title TokenFactory
* @dev Allows the owner to deploy new ERC20 contracts
* @dev This contract will be deployed on both an L1 & an L2
*/
contract TokenFactory is Ownable {
    mapping(string tokenSymbol => address tokenAddress) private s_tokenToAddress;

    event TokenDeployed(string symbol, address addr);

    constructor() Ownable(msg.sender) { }

    /*
     * @dev Deploys a new ERC20 contract
     * @param symbol The symbol of the new token
     * @param contractBytecode The bytecode of the new token
     */
    function deployToken(string memory symbol, bytes memory contractBytecode) public onlyOwner returns (address addr) {
        // q why this is out-of-scope  
        // q Is this a gas efficient way to do this?
        assembly {
            // create(amountOfWei, bytecodeOffset, bytecodeLength);
            // X Large
            // load the contract bytecode into memory
            // create a contract
            // @audit HIGH - This won't work on ZKSync
            // https://docs.zksync.io/build/developer-reference/ethereum-differences/evm-instructions
            addr := create(0, add(contractBytecode, 0x20), mload(contractBytecode))
        // a - We are creating a token contract copy from the byte code info. 

        }
        // @ audit ??? -> Check if addr is a null address = address(0)
        s_tokenToAddress[symbol] = addr;
        emit TokenDeployed(symbol, addr);
    }

    // @ audit-info Should be external not public
    function getTokenAddressFromSymbol(string memory symbol) public view returns (address addr) {
        return s_tokenToAddress[symbol];
    }
}
