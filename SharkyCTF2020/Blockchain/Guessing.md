# Warmup

## Setup

The challenge is available at http://ethereum.sharkyctf.xyz/level/2

Before starting, it is recommended to follow the suggested steps at http://ethereum.sharkyctf.xyz/help to setup Metamask, get Ether from a Ropsten faucet, and Remix IDE.

## Challenge

The contract to attack is the following :

```solidity
pragma solidity = 0.4.25;

contract Guessing {
    address public owner;    
    bytes32 private passphrase;
    
    constructor(bytes32 _passphrase) public payable {
        owner = msg.sender;
        passphrase = keccak256(abi.encodePacked(_passphrase));
    }
    
    function withdraw() public {
        require(msg.sender == owner);
        msg.sender.call.value(address(this).balance)();
    }

    function claim(bytes32 _secret) public payable {
        require(keccak256(abi.encodePacked(_secret)) == passphrase);
        owner = msg.sender; 
    }
}
```

The goal is then to be able to call `withdraw()` from the contract.

## Hint

There seems to be a passphrase needed to unlock the contract, and it is hashed by keccak256, so it seems to be secure. Nonetheless, are transactions on a public blockchain readable ?

## Solution

All transactions on a public blockchain are recorded and can read by anyone, including the first transaction that created a contract. Therefore, if a secret is passed to a contract at its creation, one should be able to read what it was just by doing at the records of the initial transaction.

Records of the Ethereum blockchain can be found on Etherscan, in our case we just need to have a look at the contract provided to us on Etherscan Ropsten.

Then we simply have to look at the logs of the first transaction, decode it to UTF-8 and find that the initial passphrase was "I'm pr3tty sur3 y0u brut3f0rc3d!".

To attack this contract, we will create another contract called Attack, which will be called to attack the first contract.

In the same Solidity file, add the following code :

```solidity
contract Attack {
    Guessing public target;
    
    constructor (address _adress) public {
        target = Guessing(_adress);
    }
    
    function attack() public pure returns(bytes) {
        bytes32 _passphrase = "I'm pr3tty sur3 y0u brut3f0rc3d!";
        bytes  memory output = abi.encodePacked(_passphrase);
        return output;
    }
}
```