# HD wallet implementation using ecc implementation provided by the part of
# `Programming Bitcoin` class given by Jimmy Song

# https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki

import hashlib
import hmac
from unittest import TestCase
from io import BytesIO

import ecc
from helper import hash160, encode_base58_checksum
import itertools

ver_keys = list(itertools.product(['mainnet', 'testnet'],
                                  ['public','private']))
ver_vals = [0x0488B21E,0x0488ADE4,0x043587CF,0x04358394]
VERSIONS = dict(zip(ver_keys, ver_vals))
VER_RMAP = dict(zip(ver_vals, ver_keys))

INF = ecc.S256Point(None, None)

def point(pk):
  return pk.point

def ser_p(point: ecc.S256Point) -> bytes:
  return point.sec(compressed=True)

def ser_32(i):
  return i.to_bytes(4, 'big')

def ser_256(v):
  return v.to_bytes(32, 'big')

def parse_256(b):
  return int.from_bytes(b, 'big')

def split_512(I):
  return I[:32], I[32:]

def rng(sz):
  return randint(0, 2**sz).to_bytes(sz//8, 'big')

def hmac_sha512(Key=None, Data=None):
  return hmac.new(Key, Data, hashlib.sha512).digest()

concat = lambda *args: b''.join(args)

def master_key_gen(S = None):
  S = rng(256) if S is None else S
  I = hmac_sha512(Key="Bitcoin seed".encode(), Data=S)

  I_L, I_R = split_512(I)

  pv = parse_256(I_L)
  if 0 < pv < ecc.N:
    return pv, I_R

def CKDpriv(k_par, c_par, i):
  if i >= 2**31: # hardened child
    I = hmac_sha512(Key = c_par, Data = concat(b'\x00', ser_256(k_par.secret), ser_32(i)))
  else: # normal child
    I = hmac_sha512(Key = c_par, Data = concat(ser_p(point(k_par)), ser_32(i)))

  I_L, I_R = split_512(I)

  pv = parse_256(I_L)
  if pv < ecc.N:
    k_i = (pv + k_par.secret) % ecc.N
    if k_i == 0:
      return None
    return ecc.PrivateKey(k_i), I_R

def CKDpub(K_par, c_par, i):
  if i >= 2**31:
    raise Exception("Invalid operation")
  else:
    I = hmac_sha512(Key = c_par, Data = concat(ser_p(K_par), ser_32(i)))

  I_L, I_R = split_512(I)
  pv = parse_256(I_L)
  if pv < ecc.N:
    K_i = point(ecc.PrivateKey(pv)) + K_par
    if K_i == INF:
      return None
    return K_i, I_R

class ExtendedKey:
  def __init__(self, parent_fingerprint, depth, key, chain_code, child_index, network_type):
    self.parent_fingerprint = parent_fingerprint
    self.depth = depth
    self.key = key
    self.chain_code = chain_code
    self.child_index = child_index
    self.network_type = network_type

  def parse_node(self, n):
    if type(n) == int:
      return n
    assert type(n) == str

    if len(n) > 1 and n[-1] == 'H':
      ix = int(n[:-1]) + 2**31
    else:
      ix = int(n)

    return ix

  def set_version(self, version):
    self.network, self.key_type = VER_RMAP[version]

  def serialize(self):
    "78 bytes structure"
    result = ser_32(self.version())
    result += bytes([self.depth])
    result += self.parent_fingerprint
    result += ser_32(self.child_index)
    result += self.chain_code
    result += self.ser_key()
    assert(len(result) == 78)
    return result

  @classmethod
  def parse(cls, key_bin):
    s = BytesIO(key_bin)
    ver = int.from_bytes(s.read(4), 'big')
    depth = int.from_bytes(s.read(1), 'big')
    parent_fingerprint = s.read(4)
    child_index = int.from_bytes(s.read(4), 'big')
    chain_code = s.read(32)
    rawkey = s.read(33)
    network_type, key_type = VER_RMAP[ver]
    cls = ExtendedPrivateKey if key_type == 'private' else ExtendedPublicKey
    if key_type == 'private':
      assert bytes([rawkey[0]]) == b'\x00'
      key = ecc.PrivateKey(parse_256(rawkey[1:]))
      res = ExtendedPrivateKey(parent_fingerprint, depth, key, chain_code, child_index, network_type)
    elif key_type == 'public':
      key = S256Point.parse(rawkey)
      res = ExtendedPublicKey(parent_fingerprint, depth, key, chain_code, child_index, network_type)
    return res

  def fingerprint(self):
    return self.identifier()[:4]

  def encode(self):
    return encode_base58_checksum(self.serialize())


  def __eq__(self, other):
    if type(self) != type(other):
      return False;
    if any(self.__dict__[k] != other.__dict__[k] for k in
           ['network_type','depth','parent_fingerprint','child_index','chain_code']):
      return false
    if isinstance(self, ExtendedPrivateKey):
      return self.key.secret == other.key.secret
    elif isinstance(self, ExtendedPublicKey):
      # __eq__ is defined for ecc.Point
      return self.key == other.key
    else:
      raise Exception("Unknown type!")

class ExtendedPrivateKey(ExtendedKey):
  def __init__(self, parent_fingerprint, depth, key, chain_code, child_index, network_type):
    ExtendedKey.__init__(self, parent_fingerprint, depth, key, chain_code, child_index, network_type)

  def neuter(self):
    return ExtendedPublicKey(self.parent_fingerprint, self.depth, point(self.key), self.chain_code,
                             self.child_index,
                             self.network_type)

  def version(self):
    return VERSIONS[(self.network_type, 'private')]

  def derive(self, n):
    ix = self.parse_node(n)
    res = CKDpriv(self.key, self.chain_code, ix)
    if res is not None:
      pk, chain_code = res
      key = ExtendedPrivateKey(self.fingerprint(), self.depth+1, pk, chain_code, ix,
                        self.network_type)
      return key

  def identifier(self):
    return hash160(point(self.key).sec())

  def ser_key(self):
    return concat(b'\x00', ser_256(self.key.secret))

class ExtendedPublicKey(ExtendedKey):
  def __init__(self, parent_fingerprint, depth, key, chain_code, child_index, network_type):
    ExtendedKey.__init__(self, parent_fingerprint, depth, key, chain_code, child_index, network_type)

  def version(self):
    return VERSIONS[(self.network_type, 'public')]

  def derive(self, n):
    ix = self.parse_node(n)
    res = CKDpub(self.key, self.chain_code, ix)
    if res is not None:
      pk, chain_code = res
      key = ExtendedPublicKeyKey(self.fingerprint(), self.depth+1, pk, chain_code, ix,
                        self.network_type)
      return key

  def identifier(self):
    return hash160(self.key.sec())

  def ser_key(self):
    return ser_p(self.key)

class MasterKey(ExtendedPrivateKey):
  def __init__(self, seed=None, network_type='testnet'):
    res = None
    while res is None:
      res = master_key_gen(seed)
    key, chain_code = res
    ExtendedPrivateKey.__init__(self, b'\x00\x00\x00\x00', 0, ecc.PrivateKey(key), chain_code, 0, network_type)

class KeyChain:
  def __init__(self, seed, network_type='testnet'):
    self.seed = seed
    self.network_type = network_type

  # parse path and return ExtendedKey
  def derive(self, path):
    nodes = path.split("/")
    h = nodes.pop(0)
    assert(h in "mM")

    root = MasterKey(self.seed, self.network_type)
    if h == 'M':
      root = root.neuter()

    cur = root
    for n in nodes:
      cur = cur.derive(n)
    return cur

class ExtendedKeyTest(TestCase):
  def test_serde_roundtrip(self):
    seed = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    path = "m/0H/1/2H/2/1000000000"
    key = KeyChain(seed, 'mainnet').derive(path)
    key_bin = key.serialize()
    expected = ExtendedKey.parse(key_bin)
    self.assertEqual(key, expected)

  def fullpath_test(self, seed, path, expected):
    cur = None
    for ix, n in enumerate(path.split('/')):
      cur = n if cur is None else "/".join([cur, n])
      key = KeyChain(seed, 'mainnet').derive(cur)
      pub_key = key.neuter()
      self.assertEqual(pub_key.encode(), expected[ix*2])
      self.assertEqual(key.encode(), expected[ix*2+1])

  def iterative_test(self, seed, path, expected):
    key = None
    for ix, n in enumerate(path.split('/')):
      if key is None:
        assert n in "mM"
        key = KeyChain(seed, 'mainnet').derive(n)
      else:
        key = key.derive(n)

      pub_key = key.neuter()
      self.assertTrue(pub_key.encode(), expected[ix*2])
      self.assertTrue(key.encode(), expected[ix*2+1])

  def test_vector1(self):
    seed = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    path = "m/0H/1/2H/2/1000000000"
    expected = [
      "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8",
      "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi",
      "xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw",
      "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7",
      "xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ",
      "xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs",
      "xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2dFDFGTsxxpG5uJh7n7epu4trkrX7x7DogT5Uv6fcLW5",
      "xprv9z4pot5VBttmtdRTWfWQmoH1taj2axGVzFqSb8C9xaxKymcFzXBDptWmT7FwuEzG3ryjH4ktypQSAewRiNMjANTtpgP4mLTj34bhnZX7UiM",
      "xpub6FHa3pjLCk84BayeJxFW2SP4XRrFd1JYnxeLeU8EqN3vDfZmbqBqaGJAyiLjTAwm6ZLRQUMv1ZACTj37sR62cfN7fe5JnJ7dh8zL4fiyLHV",
      "xprvA2JDeKCSNNZky6uBCviVfJSKyQ1mDYahRjijr5idH2WwLsEd4Hsb2Tyh8RfQMuPh7f7RtyzTtdrbdqqsunu5Mm3wDvUAKRHSC34sJ7in334",
      "xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy",
      "xprvA41z7zogVVwxVSgdKUHDy1SKmdb533PjDz7J6N6mV6uS3ze1ai8FHa8kmHScGpWmj4WggLyQjgPie1rFSruoUihUZREPSL39UNdE3BBDu76",
    ]
    self.fullpath_test(seed, path, expected)
    self.iterative_test(seed, path, expected)


  def test_vector2(self):
    seed = bytes.fromhex("fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542")
    path = "m/0/2147483647H/1/2147483646H/2"
    expected = [
      "xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB",
      "xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U",
      "xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH",
      "xprv9vHkqa6EV4sPZHYqZznhT2NPtPCjKuDKGY38FBWLvgaDx45zo9WQRUT3dKYnjwih2yJD9mkrocEZXo1ex8G81dwSM1fwqWpWkeS3v86pgKt",
      "xpub6ASAVgeehLbnwdqV6UKMHVzgqAG8Gr6riv3Fxxpj8ksbH9ebxaEyBLZ85ySDhKiLDBrQSARLq1uNRts8RuJiHjaDMBU4Zn9h8LZNnBC5y4a",
      "xprv9wSp6B7kry3Vj9m1zSnLvN3xH8RdsPP1Mh7fAaR7aRLcQMKTR2vidYEeEg2mUCTAwCd6vnxVrcjfy2kRgVsFawNzmjuHc2YmYRmagcEPdU9",
      "xpub6DF8uhdarytz3FWdA8TvFSvvAh8dP3283MY7p2V4SeE2wyWmG5mg5EwVvmdMVCQcoNJxGoWaU9DCWh89LojfZ537wTfunKau47EL2dhHKon",
      "xprv9zFnWC6h2cLgpmSA46vutJzBcfJ8yaJGg8cX1e5StJh45BBciYTRXSd25UEPVuesF9yog62tGAQtHjXajPPdbRCHuWS6T8XA2ECKADdw4Ef",
      "xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL",
      "xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc",
      "xpub6FnCn6nSzZAw5Tw7cgR9bi15UV96gLZhjDstkXXxvCLsUXBGXPdSnLFbdpq8p9HmGsApME5hQTZ3emM2rnY5agb9rXpVGyy3bdW6EEgAtqt",
      "xprvA2nrNbFZABcdryreWet9Ea4LvTJcGsqrMzxHx98MMrotbir7yrKCEXw7nadnHM8Dq38EGfSh6dqA9QWTyefMLEcBYJUuekgW4BYPJcr9E7j"
    ]
    self.fullpath_test(seed, path, expected)
    self.iterative_test(seed, path, expected)

  def test_vector3(self):
    # These vectors test for the retention of leading zeros. See bitpay/bitcore-lib#47 and iancoleman/bip39#58 for more information.
    seed = bytes.fromhex("4b381541583be4423346c643850da4b320e46a87ae3d2a4e6da11eba819cd4acba45d239319ac14f863b8d5ab5a0d0c64d2e8a1e7d1457df2e5a3c51c73235be")
    path = "m/0H"

    expected = [
      "xpub661MyMwAqRbcEZVB4dScxMAdx6d4nFc9nvyvH3v4gJL378CSRZiYmhRoP7mBy6gSPSCYk6SzXPTf3ND1cZAceL7SfJ1Z3GC8vBgp2epUt13",
      "xprv9s21ZrQH143K25QhxbucbDDuQ4naNntJRi4KUfWT7xo4EKsHt2QJDu7KXp1A3u7Bi1j8ph3EGsZ9Xvz9dGuVrtHHs7pXeTzjuxBrCmmhgC6",
      "xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y",
      "xprv9uPDJpEQgRQfDcW7BkF7eTya6RPxXeJCqCJGHuCJ4GiRVLzkTXBAJMu2qaMWPrS7AANYqdq6vcBcBUdJCVVFceUvJFjaPdGZ2y9WACViL4L",
    ]
    self.fullpath_test(seed, path, expected)
    self.iterative_test(seed, path, expected)

if __name__ == '__main__':
  import unittest
  unittest.main()
