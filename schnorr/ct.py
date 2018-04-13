import sys
sys.path.append("..")
import ecc
from ecc import PrivateKey, S256Point
from random import randint
from helper import double_sha256, little_endian_to_int
from schnorr import HI

# related to "confidential transaction" following
# https://www.elementsproject.org/elements/confidential-transactions/investigation.html

def homomorphic():
  """ homomorphic property """
  pk0 = PrivateKey()
  pk1 = PrivateKey()
  assert pk0.point + pk1.point == ((pk0.secret + pk1.secret)%ecc.N)*ecc.G
homomorphic()

def gen_geneartor(point):
  bin_sec = point.sec(compressed=True)
  k = int.from_bytes(double_sha256(bin_sec),'big')
  return k*ecc.G

def random_secret():
  return randint(0, 2**256-1)

H = gen_geneartor(ecc.G)

def pederson_commit():
  def commit_amount(x, a):
    """ x: secret binding factor, a: amount """
    return x*ecc.G + a*H


  def tx_commit(input_amounts, output_amounts):
    input_binding_factors = [random_secret() for _ in range(len(input_amounts))]
    output_binding_factors = [random_secret() for _ in range(len(output_amounts)-1)]
    # the author of a transaction takes care in picking their blinding factors so that they add up correctly
    output_binding_factors.append((sum(input_binding_factors)-sum(output_binding_factors))%ecc.N)
    assert (sum(input_binding_factors)-sum(output_binding_factors))%ecc.N == 0

    fee = (sum(input_amounts) - sum(output_amounts))%ecc.N

    input_commits = [commit_amount(bf, amt) for bf, amt in zip(input_binding_factors, input_amounts)]
    output_commits = [commit_amount(bf, amt) for bf, amt in zip(output_binding_factors, output_amounts)]

    return input_commits, output_commits, fee

  def verify(input_commits, output_commits, fee):
    return sum(input_commits, S256Point.inf)\
            - sum(output_commits + [fee*H],S256Point.inf) == S256Point.inf

  input_commits, output_commits, fee = tx_commit([10,20,30,40], [9,18,27,30])
  assert verify(input_commits, output_commits, fee) # ok

  input_commits, output_commits, fee = tx_commit([10,20,30,40], [9, ecc.N-18, 18+27, 30])
  assert verify(input_commits, output_commits, fee) #uh oh
  # from the paper - 
  # So, instead, we need to prove that a committed amount is within the range but reveal nothing else about it
pederson_commit()

def number_commit():

  z = lambda p: HI(p.sec())
  # Using the public key in the signature is required to prevent setting the signature to arbitrary values and solving for the commitment

  def commit_number(n):
    pk = PrivateKey()
    C = pk.point + n * H  # secret * G + n * H
    return C, pk.sign(z(C))

  def verify(C, sig, n):
    C_ = C - n*H
    return C_.verify(z(C), sig)

  for n in [0,1,randint(0, 2**256)]:
    C, sig = commit_number(n)
    assert verify(C, sig, n) # giving away number!
number_commit()

def ring_signature():
  pass

