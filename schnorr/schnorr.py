# implementation of schnorr, BN(Bellare-Neven) & MuSig based on 
# Jimmy Song's presentation (https://prezi.com/amezx3cubxy0/schnorr-signatures/)
# Also checks his youtube on this - https://www.youtube.com/watch?v=thfCtc4jJZo (What is Schnorr, BN, Musig?)

# using the codebase which is used in Programming Blockchain seminar(http://programmingblockchain.com/) 
# The codebase can be found in (https://github.com/jimmysong/pb-exercises)

# additional pointer for MuSig
# Key Aggregation for Schnoor Signatures(https://blockstream.com/2018/01/23/musig-key-aggregation-schnorr-signatures.html)

import sys
sys.path.append("..")
import ecc
from ecc import PrivateKey
from random import randint
from helper import double_sha256, little_endian_to_int

# hash
def H(*args):
    return double_sha256(b''.join(args))

# int(hash)
def HI(*args):
    return little_endian_to_int(H(*args))

def gen_msg():
    return randint(0, 2**256).to_bytes(256//8, 'little')

def schnorr():
    pk = PrivateKey(randint(0, 2**256))
    point = pk.point # public point

    def sign(pk, z):
        k = randint(0, 2**256) # nonce
        R = k * ecc.G          # nonce point
        s = (k + HI(R.sec(), z) * pk.secret)%ecc.N
        return R, s

    def verify(R, s, z):
        Q = s * ecc.G - HI(R.sec(),z) * point
        return Q == R

    z = gen_msg()
    R, s = sign(pk, z)
    assert verify(R, s, z)

def BN(Ns=10): # num sig
    pks = [PrivateKey(randint(0, 2**256)) for _ in range(Ns)]
    points = [pk.point for pk in pks]

    def sign(pks, z):
        ks = [randint(0, 2**256) for _ in range(len(pks))]

        L = H(*[p.sec() for p in points])
        Rs = [k*ecc.G for k in ks]
        R = sum(Rs, ecc.S256Point(None,None))
        cs = [HI(L,p.sec(),R.sec(),z) for p in points]
        s = sum(k + c*pk.secret for k,c,pk in zip(ks,cs,pks))%ecc.N
        return R, s

    def verify(R, s, z):
        L = H(*[p.sec() for p in points])
        cs = [HI(L,p.sec(),R.sec(),z) for p in points]
        return R == s*ecc.G - sum((c*p for c,p in zip(cs, points)),ecc.S256Point(None,None))

    z = gen_msg()
    R, s = sign(pks, z)
    assert verify(R, s, z)

def Mu(Ns=10):
    pks = [PrivateKey(randint(0, 2**256)) for _ in range(Ns)]
    points = [pk.point for pk in pks]

    def sign(pks, z):
        L = H(*[p.sec() for p in points])
        ks = [randint(0, 2**256) for _ in range(len(pks))]
        Rs = [k*ecc.G for k in ks]
        R = sum(Rs, ecc.S256Point(None,None))
        # aggregate key
        P = sum((HI(L, p.sec())*p for p in points), ecc.S256Point(None,None))
        cs = [HI(R.sec(),z)*HI(L,p.sec()) for p in points]
        s = sum([k+c*pk.secret for k,c,pk in zip(ks,cs,pks)]) % ecc.N
        return R, s, P

    def verify(R, s, z, P):
        return R == s*ecc.G - HI(R.sec(),z)*P

    z = gen_msg()
    R, s, P = sign(pks, z)
    assert verify(R, s, z, P)

funcs = [schnorr, BN, Mu]
[f() for f in funcs]
