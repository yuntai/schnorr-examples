import ecc
from helper import double_sha256, little_endian_to_int
from random import randint

def H_(*args):
  def _sb(v):
    assert type(v) == bytes or type(v) == int
    return v if type(v)==bytes else v.to_bytes(256//8,'little')

  args = [v.sec() if isinstance(v, ecc.Point) else _sb(v) for v in args]
  return double_sha256(b''.join(args))

gen_nonce = lambda: randint(0,2*256)

def H(*args):
    return little_endian_to_int(H_(*args))

def gen_msg():
    return randint(0, 2**256).to_bytes(256//8, 'little')
