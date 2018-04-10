## Key Aggregation example for Schnorr Signatures

[schnorr/schnorr.py](schnorr/schnorr.py) and [schnorr/schonnr_d.py](schnorr/schnorr_d.py) contain the code simulating the signing and verifying schnorr, BN(Bellare-Neven) & MuSig scheme. The code is based on Elliptic Curve Cryptography implementation ([ecc.py](ecc.py)) from the course material of [Programming Blockchain](http://programmingblockchain.com) seminar given by [Jimmy Song](https://twitter.com/jimmysong). The original Programming Blockchain(PB) codebase can be found in [https://github.com/jimmysong/pb-exercises](https://github.com/jimmysong/pb-exercises).

The implementation is based on 
- Jimmy Song's presentation [Schnorr Signatures](https://prezi.com/amezx3cubxy0/schnorr-signatures/) and 
- his youtube on this topic [What is Schnorr, BN, Musig?](https://www.youtube.com/watch?v=thfCtc4jJZo)

I also found this blog helpful - [Key Aggregation for Schnorr Signatures](https://blockstream.com/2018/01/23/musig-key-aggregation-schnorr-signatures.html)

## Discrete Log Contracts example
[schnorr/dlc.py](schnorr/dlc.py) to simulate DLC execution using [ecc.py](ecc.py)

Based on [Discreet Log Contracts](https://adiabat.github.io/dlc.pdf) paper by [Tadge Dryja](https://twitter.com/tdryja).

## Extensino to Tx (transaction) to support segwit
[wtx.py](wtx.py) contains extension for Segwit to the original [tx.py](tx.py) from the PB codebase.

Currently (April 8 2018), 
- parsing and serializing Segwit transaction
- sign and verification for P2WPK transaction [test_p2wpkh.py](test_p2wpkh.py)

are implemented. More to come as my learning about bitcoin progresses!

### Third party code
All codes are based on PB codebase ([https://github.com/jimmysong/pb-exercises](https://github.com/jimmysong/pb-exercises)) except
[segwit_addr.py](segwit_addr.py) which is from [https://github.com/sipa/bech32](https://github.com/sipa/bech32).
