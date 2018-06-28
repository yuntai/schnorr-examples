import ecc
from ecc import PrivateKey
from random import randint
from helper import sha256, little_endian_to_int

def SHA256(*args):
    return sha256(b''.join(args))

#BOLT03 Appendix E
base_secret=0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
per_commitment_secret=0x1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100

basepoint_expected="0x036d6caac248af96f6afa7f904f550253a0f3ef3f5aa2fe6838a95b216691468e2"
per_commitment_point_expected="0x025f7117a78150fe2ef97db7cfc83bd57b2e2c0d0dd25eaf467a4a1c2a45ce1486"

basepoint = base_secret*ecc.G
per_commitment_point = per_commitment_secret*ecc.G

assert '0x'+basepoint.sec().hex() == basepoint_expected
assert '0x'+per_commitment_point.sec().hex() == per_commitment_point_expected

# name: derivation of pubkey from basepoint and per_commitment_point
sha_expected='0xcbcdd70fcfad15ea8e9e5c5a12365cf00912504f08ce01593689dd426bca9ff0'
v = SHA256(per_commitment_point.sec(), basepoint.sec())
assert '0x'+v.hex() == sha_expected

localpubkey_expected="0x0235f2dbfaa89b57ec7b055afe29849ef7ddfeb1cefdb9ebdc43f5494984db29e5"
pubkey = basepoint + int.from_bytes(v,'big') * ecc.G
assert '0x'+pubkey.sec().hex() == localpubkey_expected

# name: derivation of private key from basepoint secret and per_commitment_secret
localprivkey_expected="0xcbced912d3b21bf196a766651e436aff192362621ce317704ea2f75d87e7be0f"

privkey = base_secret + int.from_bytes(v, 'big')

localprivkey_expected = 0xcbced912d3b21bf196a766651e436aff192362621ce317704ea2f75d87e7be0f
assert privkey == localprivkey_expected


