# https://gist.github.com/gavinandresen/3966071

raw="""0491bba2510912a5bd37da1fb5b1673010e43d2c6d812c514e91bfa9f2eb129e1c183329db55bd868e209aac2fbc02cb33d98fe74bf23f0c235d6126b1d8334f86 / 5JaTXbAUmfPYZFRwrYaALK48fN6sFJp4rHqq2QSXs8ucfpE4yQU
04865c40293a680cb9c020e7b1e106d8c1916d3cef99aa431a56d253e69256dac09ef122b1a986818a7cb624532f062c1d1f8722084861c5c3291ccffef4ec6874 / 5Jb7fCeh1Wtm4yBBg3q3XbT6B525i17kVhy3vMC9AqfR6FH2qGk
048d2455d2403e08708fc1f556002f1b6cd83f992d085097f9974ab08a28838f07896fbab08f39495e15fa6fad6edbfb1e754e35fa1c7844c41f322a1863d46213 / 5JFjmGo5Fww9p8gvx48qBYDJNAzR9pmH5S389axMtDyPT8ddqmw"""
from ecc import PrivateKey, S256Point
from helper import little_endian_to_int
from binascii import unhexlify

key_pairs = [x.split(' / ') for x in map(str.strip,raw.split('\n'))]
print(key_pairs)
print([[len(a),len(b)] for a,b in key_pairs])

key_pairs = [(S256Point.parse(unhexlify(sec)), PrivateKey(unhexlify(pk_secret))) for sec, pk_secret in key_pairs]
print(key_pairs)




