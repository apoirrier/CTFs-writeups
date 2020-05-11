# Warmup

## Setup

The challenge is available at http://ethereum.sharkyctf.xyz/level/4

Before starting, it is recommended to follow the suggested steps at http://ethereum.sharkyctf.xyz/help to setup Metamask, get Ether from a Ropsten faucet, and Remix IDE.

## Challenge

The contract to attack is the following :

```solidity
pragma solidity = 0.4.25;

contract Shashasha {
    address public owner;
    uint256 public money;
    
    mapping(address => uint256) private contributions;    
    
    bool public hacker;
    uint[] public godlike;
    
    constructor() public payable {
        owner = msg.sender;
        contributions[owner] = msg.value * 9999999999999;
        money += msg.value;
        hacker = false;
    }
    
    function becomingHacker() public {
        require(address(this).balance != money);
        contributions[msg.sender] = 100;
        hacker = true;
    }

    function remove() public{
        require(hacker);
        godlike.length--;
    }
 
    function append(uint256 _value) public{
        require(hacker);
        godlike.push(_value);
    }
 
    function update(uint256 _key, uint256 _value) public {
        require(hacker);        
        godlike[_key] = _value;
    }
    
    function withdraw() public payable {
        require(contributions[msg.sender] > contributions[owner]);
        msg.sender.call.value(address(this).balance)();
    }
    
    function getContrib(address _key) public view returns(uint256) {
        return contributions[_key];
    }
}
```

The goal is then to be able to call `withdraw()` from the contract.

## Hint

This contract can be hacked in two steps.

First, it seems that we need to become a hacker, but how would we do that if the balance is equal to the money, and we cannot call anything ? Is there a way to send ether directly to the contract ?

Secondly, once you become a hacker there seems to be very few things to do. But does access to the `godlike` mapping provide you with 'godlike' powers ?

## Solution

This challenge can be solved in two steps, first become a hacker, then exploit the `godlike` mapping to modify the state of the other variables.

To do the first one, you need to exploit the fact that when contracts call `selfdestruct(target)`, the ether they contained will be sent to the target, without calling any fallback function. This way, we can just create a contract we will selfdestruct to disturb the balance of our target contract, allowing us to become hacker.

Then we need to exploit the `godlike` mapping. To do so, we will follow the mapping exploit, explained here https://medium.com/coinmonks/smart-contract-exploits-part-2-featuring-capture-the-ether-math-31a289da0427 at point 10. about mappings. The idea is to underflow the mapping, then change the value of owner.

To attack this contract, we will create another contract called Attack, which will be called to attack the first contract.

In the same Solidity file, add the following code :

```solidity
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