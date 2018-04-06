# Programming Blochain Exercise

This repository contains some working exercise code for understanding Bitcoin internals. The code is based off of and extends the codebase used in ["Programming Blockchain"](http://programmingblockchain.com/)  seminar given by [Jimmy Song](https://twitter.com/jimmysong). The original Programming Blockchain(PB) codebase can be found in [https://github.com/jimmysong/pb-exercises](https://github.com/jimmysong/pb-exercises).

## Key Aggregation for Schnorr Signatures

[Schonnr.py](Schonnr.py) and [Schonnr_d.py](Schonnr_d.py) contain the code simulating schnorr, BN(Bellare-Neven) & MuSig signing and verification using Elliptic curve Cryptography code ([ecc.py](ecc.py)) from the original PB codebase. The implementation is based on Jimmy Song's presentation [Schnorr Signatures](https://prezi.com/amezx3cubxy0/schnorr-signatures/) and his youtube on this topic [What is Schnorr, BN, Musig?](https://www.youtube.com/watch?v=thfCtc4jJZo). I found this blog also helpful - [Key Aggregation for Schnoor Signatures](https://blockstream.com/2018/01/23/musig-key-aggregation-schnorr-signatures.html)
