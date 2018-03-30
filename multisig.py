# https://gist.github.com/gavinandresen/3966071
import pprint

raw="""\
0491bba2510912a5bd37da1fb5b1673010e43d2c6d812c514e91bfa9f2eb129e1c183329db55bd868e209aac2fbc02cb33d98fe74bf23f0c235d6126b1d8334f86/5JaTXbAUmfPYZFRwrYaALK48fN6sFJp4rHqq2QSXs8ucfpE4yQU
04865c40293a680cb9c020e7b1e106d8c1916d3cef99aa431a56d253e69256dac09ef122b1a986818a7cb624532f062c1d1f8722084861c5c3291ccffef4ec6874/5Jb7fCeh1Wtm4yBBg3q3XbT6B525i17kVhy3vMC9AqfR6FH2qGk
048d2455d2403e08708fc1f556002f1b6cd83f992d085097f9974ab08a28838f07896fbab08f39495e15fa6fad6edbfb1e754e35fa1c7844c41f322a1863d46213/5JFjmGo5Fww9p8gvx48qBYDJNAzR9pmH5S389axMtDyPT8ddqmw\
"""
from ecc import PrivateKey, S256Point
from helper import little_endian_to_int, big_endian_to_int
from binascii import unhexlify, hexlify
import script
import helper
from tx import TxIn, TxOut, Tx

key_pairs = [x.split('/') for x in map(str.strip,raw.split('\n'))]
key_pairs = [(S256Point.parse(unhexlify(sec)), PrivateKey.parse(wif, compressed=False)) for sec, wif in key_pairs]
assert all(p == pk.point for p,pk in key_pairs)
pubkeys = [p for p, _ in key_pairs]

OP_n = lambda n: 0x51 + n - 1

n_required = 2
elements = [OP_n(n_required)] + [pk.sec(compressed=False) for pk in pubkeys] + [OP_n(len(pubkeys))] + [174]
redeemScript = script.Script(elements)

address=helper.h160_to_p2sh_address(helper.hash160(redeemScript.serialize()), testnet=False)
redeemScript=hexlify(redeemScript.serialize())
assert address=="3QJmV3qfvL9SuYo34YihAf3sRCW3qSinyC"
assert redeemScript=="52410491bba2510912a5bd37da1fb5b1673010e43d2c6d812c514e91bfa9f2eb129e1c183329db55bd868e209aac2fbc02cb33d98fe74bf23f0c235d6126b1d8334f864104865c40293a680cb9c020e7b1e106d8c1916d3cef99aa431a56d253e69256dac09ef122b1a986818a7cb624532f062c1d1f8722084861c5c3291ccffef4ec687441048d2455d2403e08708fc1f556002f1b6cd83f992d085097f9974ab08a28838f07896fbab08f39495e15fa6fad6edbfb1e754e35fa1c7844c41f322a1863d4621353ae".encode('ascii')
print(hexlify(helper.hash160(unhexlify(redeemScript))))

prev_tx = 'd6f72aab8ff86ff6289842a0424319bf2ddba85dc7c52757912297f948286389'
prev_index = 0
tx_in = TxIn(unhexlify(prev_tx), prev_index, b'')

h160 = helper.decode_base58_checksum(address)[1:]
tx_out = TxOut(int(0.01*100e6), script_pubkey=helper.p2sh_script(h160))
t = Tx(version=1, tx_ins=[tx_in], tx_outs=[tx_out], locktime=0, testnet=False)
raw_transaction = hexlify(t.serialize())
assert raw_transaction == "010000000189632848f99722915727c5c75da8db2dbf194342a0429828f66ff88fab2af7d60000000000ffffffff0140420f000000000017a914f815b036d9bbbce5e9f2a00abd1bf3dc91e955108700000000".encode('ascii')
print(t)

#tx.sign_input(input_index=0, private_key='', hash_type=helper.SIGHASH_ALL)



