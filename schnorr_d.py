# implementation of schnorr, BN(Bellare-Neven) & MuSig based on 
# Jimmy Song's presentation (https://prezi.com/amezx3cubxy0/schnorr-signatures/)
# Also checks his youtube on this - https://www.youtube.com/watch?v=thfCtc4jJZo (What is Schnorr, BN, Musig?)

# using the codebase which is used in Programming Blockchain seminar(http://programmingblockchain.com/) 
# The codebase can be found in (https://github.com/jimmysong/pb-exercises)

# additional pointer for MuSig
# Key Aggregation for Schnoor Signatures(https://blockstream.com/2018/01/23/musig-key-aggregation-schnorr-signatures.html)

import ecc
from ecc import PrivateKey
from random import randint
from helper import double_sha256, little_endian_to_int

from schnorr import H, HI, gen_msg

def BN(Ns=5):
    class Agent:
        def __init__(self):
            self.pk = PrivateKey(randint(0, 2**256))
            self.point = self.pk.point

        def round1(self):
            self.ki = randint(0, 2**256) # Each signer chooses a random nonce k_i
            Ri = self.ki*ecc.G # and shares R_i = r_i * G
            return Ri

        def round2(self, R, z, L): # calculate s_i
            ci = HI(L, self.pk.point.sec(), R.sec(), z)
            si = self.ki + ci * self.pk.secret
            return si

    def verify(R, s, z, points):
        cs = [HI(L, p.sec(), R.sec(), z) for p in points]
        return R == s*ecc.G - sum((c*p for c,p in zip(cs, points)), ecc.S256Point(None,None))

    def sign(agents, z, L):
        R = sum([a.round1() for a in agents], ecc.S256Point(None, None)) # collect R_i & sum it
        s = sum([a.round2(R, z, L) for a in agents])%ecc.N  # collect s_i & sum it
        return R, s

    agents = [Agent() for _ in range(Ns)]
    z = gen_msg()

    points = [a.point for a in agents]
    L = H(*[p.sec() for p in points])

    R, s = sign(agents, z, L)
    assert verify(R, s, z, points)

def Mu(Ns=5):
    class Agent:
        def __init__(self):
            self.pk = PrivateKey(randint(0, 2**256))
            self.point = self.pk.point

        def round1(self):
            self.ki = randint(0, 2**256)
            Ri = self.ki*ecc.G
            return Ri

        def round2(self, R, z, L):
            ci = HI(R.sec(), z) * HI(L, self.pk.point.sec())
            si = self.ki + ci*self.pk.secret
            return si

    def sign(agents, z, L):
        R = sum([a.round1() for a in agents], ecc.S256Point(None, None))
        s = sum([a.round2(R, z, L) for a in agents])%ecc.N
        return R, s

    def verify(R, s, z, P):
        return R == s*ecc.G - HI(R.sec(), z)*P


    agents = [Agent() for _ in range(Ns)]
    z = gen_msg()

    points = [a.point for a in agents]
    L = H(*[p.sec() for p in points])
    # Key aggregation
    P = sum((HI(L, p.sec())*p for p in points), ecc.S256Point(None,None))

    R, s = sign(agents, z, L)
    assert verify(R, s, z, P) # note we don't need points[]

BN()
Mu()
