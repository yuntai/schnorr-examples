import ecc
from ecc import PrivateKey
from random import randint
from helper import double_sha256, little_endian_to_int

# patch
ecc.FieldElement.__neg__ = lambda self: self.__class__(self.prime - self.num, self.prime)
ecc.Point.__sub__ = lambda self, other: self + (-other)
ecc.Point.__neg__ = lambda self: self.__class__(None, None, self.a, self.b) if self.x is None else self.__class__(self.x, -self.y, self.a, self.b)

# hash
def H(*args):
    return double_sha256(b''.join(args))

# int(hash)
def HI(*args):
    return little_endian_to_int(H(*args))

def schnorr():
    pk = PrivateKey(randint(0, 2**256))
    point = pk.point

    def sign(pk, z):
        k = randint(0, 2**256)
        R = k * ecc.G
        s = (k + HI(R.sec(),z) * pk.secret)%ecc.N
        return R, s

    def verify(R, s, z):
        Q = s * ecc.G - HI(R.sec(),z) * point
        return Q == R

    z = randint(0, 2**256).to_bytes(256//8, 'little')
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

    z = randint(0, 2**256).to_bytes(256//8, 'little')

    R, s = sign(pks, z)
    assert verify(R, s, z)

# distributed version
def BN_d(Ns=10):
    points = []

    class Agent:
        def __init__(self):
            self.pk = PrivateKey(randint(0, 2**256))
            points.append(self.pk.point)

        def sign_1(self):
            self.ki = randint(0, 2**256)
            Ri = self.ki*ecc.G
            return Ri

        def sign_2(self, R, z):
            L = H(*[p.sec() for p in points])
            ci = HI(L, self.pk.point.sec(), R.sec(), z)
            si = self.ki + ci * self.pk.secret
            return si

    def verify(R, s, z):
        L = H(*[p.sec() for p in points])
        cs = [HI(L,p.sec(), R.sec(),z) for p in points]
        return R == s*ecc.G - sum((c*p for c,p in zip(cs, points)), ecc.S256Point(None,None))


    def sign(z):
        agents = [Agent() for _ in range(Ns)]
        R = sum([a.sign_1() for a in agents], ecc.S256Point(None, None))
        s = sum([a.sign_2(R, z) for a in agents])%ecc.N
        return R, s

    z = randint(0, 2**256).to_bytes(256//8, 'little')
    R, s = sign(z)
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

    z = randint(0, 2**256).to_bytes(256//8, 'little')
    R, s, P = sign(pks, z)
    assert verify(R, s, z, P)


def Mu_d(Ns=10):
    points = []

    class Agent:
        def __init__(self):
            self.pk = PrivateKey(randint(0, 2**256))
            points.append(self.pk.point)

        def sign_1(self):
            self.ki = randint(0, 2**256)
            Ri = self.ki*ecc.G
            return Ri

        def sign_2(self,R, z, L):
            ci = HI(R.sec(), z)*HI(L, self.pk.point.sec())
            si = self.ki + ci*self.pk.secret
            return si

    def sign(agents, z):
        L = H(*[p.sec() for p in points])
        P = sum((HI(L, p.sec())*p for p in points), ecc.S256Point(None,None))

        R = sum([a.sign_1() for a in agents], ecc.S256Point(None, None))
        s = sum([a.sign_2(R, z, L) for a in agents])%ecc.N
        return R, s, P

    def verify(R, s, z, P):
        return R == s*ecc.G - HI(R.sec(),z)*P


    agents = [Agent() for _ in range(Ns)]
    z = randint(0, 2**256).to_bytes(256//8, 'little')
    R, s, P = sign(agents, z)
    assert verify(R, s, z, P)

schnorr()
BN()
BN_d()
Mu()
Mu_d()