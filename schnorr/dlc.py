# using the codebase which is used in Programming Blockchain seminar(http://programmingblockchain.com/) 
# The codebase can be found in (https://github.com/jimmysong/pb-exercises)

# Based on 
# [Discret Log Contracts Paper](https://adiabat.github.io/dlc.pdf)

import sys
sys.path.append("..")
import ecc
from ecc import PrivateKey
from random import randint
from helper import double_sha256, little_endian_to_int
from schnorr import H, HI

def B(v):
    return v.to_bytes(256//8, 'little')

class Tx:
    # output pubkey (address) corresponding to a specific value (winning number)
    def __init__(self, output_pub):
        self.output_pub = output_pub

    # simplifcation - instead of signing transaction secret (discrete log of output_pub is provided)
    def redeem(self, s):
        return PrivateKey(s).point == self.output_pub

class Agent:
    def __init__(self):
        self.pk = PrivateKey(randint(0, 2**256))

    # public point
    def point(self):
        return self.pk.point

    # populate Contract Execution Transactions for a range of possible values
    # stored on the agent's computer
    # using V, R and a range of values (1 ~ 6)
    def CET(self, V, R, vals):
        # calculate public key to where the payout to be sent for each possible value
        pubout = lambda m: self.pk.point + R - HI(H(B(m)), R.sec()) * V
        self.txs = {m: Tx(pubout(m)) for m in vals}

    # sign & broadcast
    def redeem(self, s, m):
        return self.txs[m].redeem((self.pk.secret + s)%ecc.N)

class Oracle: 
    def __init__(self):
        self.pk = PrivateKey(randint(0, 2**256))

    # pre-commit R and publish it with its public point V
    def pre_commit(self):
        self.k = randint(0, 2**256)
        self.R = self.k * ecc.G
        V = self.pk.point
        return V, self.R

    # announce winner and sign it
    def endorse_state(self):
        m = randint(1, 6)
        v = self.pk.secret
        s = self.k - HI(H(B(m)), self.R.sec()) * v
        return m, s

def dlc():
    olivia = Oracle()
    V, R = olivia.pre_commit() 

    bob = Agent()
    alice = Agent()

    bob_bet = [1, 2, 3, 4, 5]
    bob.CET(V, R, bob_bet)
    alice_bet = [6]
    alice.CET(V, R, alice_bet)

    m, s = olivia.endorse_state()

    if m in bob_bet:
        assert bob.redeem(s, m)
    else:
        assert alice.redeem(s, m)

dlc()
