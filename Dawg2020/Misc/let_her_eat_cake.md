# Let her eat cake

## Description

> She's hungry!
> 
> https://clearedge.ctf.umbccd.io/

## Solution

On the web site we read

```
America's first female cryptanalyst, she said: "Our office doesn't make 'em, we only break 'em". On this day, let her eat cake!

Hwyjpgxwkmgvbxaqgzcsnmaknbjktpxyezcrmlja?
GqxkiqvcbwvzmmxhspcsqwxyhqentihuLivnfzaknagxfxnctLcchKCH{CtggsMmie_kteqbx}
```

I identify it a a vigenere, and give it to [decode](https://www.dcode.fr/vigenere-cipher), who solves it. The clear text is

```
Howdoyoukeepaprogrammerintheshowerallday?
GivehimabottleofshampoowhichsaysLatherrinserepeatDawgCTF{ClearEdge_crypto}
```

Flag: `DawgCTF{ClearEdge_crypto}`