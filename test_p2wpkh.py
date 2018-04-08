from binascii import hexlify, unhexlify
from io import BytesIO
from unittest import TestCase

import random
import requests

from ecc import PrivateKey, S256Point, Signature
from helper import (
    decode_base58,
    double_sha256,
    encode_varint,
    int_to_little_endian,
    little_endian_to_int,
    p2pkh_script,
    read_varint,
    SIGHASH_ALL,
)
from script import Script
from wtx import Tx, TxIn, TxOut

class TxTest(TestCase):

    def test_sign_witness(self):
        # from https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki

        secret0 = "bbc27228ddcb9209d7fd6f36b02f7dfa6252af40bb2f1cbc7a557da8027ff866"
        private_key0 = PrivateKey(secret=int.from_bytes(unhexlify(secret0), 'big'))
        pub_sec0 = unhexlify("03c9f4836b9a4f77fc0d81f7bcb01b7f1b35916864b9476c241ce9fc198bd25432")
        self.assertEqual(private_key0.point.sec(), pub_sec0)
        value0 = 6.25

        secret1 = "619c335025c7f4012e556c2a58b2506e30b8511b53ade95ea316fd8c3286feb9"
        private_key1 = PrivateKey(secret=int.from_bytes(unhexlify(secret1), 'big'))
        pub_sec1 = unhexlify("025476c2e83188368da1ff3e292e7acafcdb3566bb0ad253f62fc70f07aeee6357")
        self.assertEqual(private_key1.point.sec(), pub_sec1)
        value1 = 6

        raw_tx_hex = '0100000002fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f0000000000eeffffffef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a0100000000ffffffff02202cb206000000001976a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac9093510d000000001976a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac11000000'
        tx = Tx.parse(BytesIO(unhexlify(raw_tx_hex)))

        self.assertEqual(hexlify(tx.txid()).decode(), "3335ffae0df20c5407e8de12b49405c8e912371f00fe4132bfaf95ad49c40243")
        self.assertEqual(hexlify(tx.hash()).decode(), "3335ffae0df20c5407e8de12b49405c8e912371f00fe4132bfaf95ad49c40243")

        # check against
        # bitcoin-cli decoderawtransaction 0100000002fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f0000000000eeffffffef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a0100000000ffffffff02202cb206000000001976a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac9093510d000000001976a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac11000000

        self.assertEqual(tx.version, 1)

        self.assertEqual(len(tx.tx_ins), 2)
        self.assertEqual(tx.tx_ins[0].prev_tx, unhexlify('9f96ade4b41d5433f4eda31e1738ec2b36f6e7d1420d94a6af99801a88f7f7ff'))
        self.assertEqual(tx.tx_ins[0].prev_index, 0)
        self.assertEqual(tx.tx_ins[0].script_sig.serialize(), b'')
        self.assertEqual(tx.tx_ins[0].sequence, 4294967278)

        self.assertEqual(tx.tx_ins[1].prev_tx, unhexlify('8ac60eb9575db5b2d987e29f301b5b819ea83a5c6579d282d189cc04b8e151ef'))
        self.assertEqual(tx.tx_ins[1].prev_index, 1)
        self.assertEqual(tx.tx_ins[1].script_sig.serialize(), b'')
        self.assertEqual(tx.tx_ins[1].sequence, 4294967295)
        self.assertEqual(tx.locktime, 17)

        self.assertEqual(len(tx.tx_outs), 2)
        self.assertEqual(tx.tx_outs[0].amount, int(1.1234*1e8))
        want = unhexlify('76a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac')
        self.assertEqual(tx.tx_outs[0].script_pubkey.serialize(), want)
        self.assertEqual(tx.tx_outs[1].amount, int(2.2345*1e8))
        want = unhexlify('76a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac')
        self.assertEqual(tx.tx_outs[1].script_pubkey.serialize(), want)

        self.assertEqual(tx.serialize(), unhexlify(raw_tx_hex))

        # test helper functions
        self.assertEqual(hexlify(tx.hash_prevouts()).decode(), '96b827c8483d4e9b96712b6713a7b68d6e8003a781feba36c31143470b4efd37')
        self.assertEqual(hexlify(tx.hash_sequence()).decode(), '52b0a642eea2fb7ae638c36f6252b6750293dbe574a806984b8e4d8548339a3b')
        self.assertEqual(hexlify(tx.hash_outputs()).decode(), '863ef3e1a92afbfdb97f31ad0fc7683ee943e9abcf2501590ff8f6551f47e5e5')

        
        tx0 = TxOut(int(6.25*1e8), unhexlify("2103c9f4836b9a4f77fc0d81f7bcb01b7f1b35916864b9476c241ce9fc198bd25432ac"))
        tx1 = TxOut(int(6*1e8), unhexlify("00141d0f172a0ecb48aee1be1f2687d2963ae33f71a1"))

        self.assertEqual(tx0.script_pubkey.address(), '1HkrFxLyNoQydvW889WmubyRHycE4bvw1Y')
        self.assertEqual(tx1.script_pubkey.address(), 'bc1qr583w2swedy2acd7rung055k8t3n7udp7vyzyg')

        # precache with a dummy previous transaction
        TxIn.cache[unhexlify('9f96ade4b41d5433f4eda31e1738ec2b36f6e7d1420d94a6af99801a88f7f7ff')]=Tx(1, [], [tx0], 0)
        TxIn.cache[unhexlify('8ac60eb9575db5b2d987e29f301b5b819ea83a5c6579d282d189cc04b8e151ef')]=Tx(1, [], [tx0, tx1], 0)

        hash_preimage=unhexlify("0100000096b827c8483d4e9b96712b6713a7b68d6e8003a781feba36c31143470b4efd3752b0a642eea2fb7ae638c36f6252b6750293dbe574a806984b8e4d8548339a3bef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a010000001976a9141d0f172a0ecb48aee1be1f2687d2963ae33f71a188ac0046c32300000000ffffffff863ef3e1a92afbfdb97f31ad0fc7683ee943e9abcf2501590ff8f6551f47e5e51100000001000000")
        self.assertTrue(tx.sig_hash_w0_preimage(1, SIGHASH_ALL), hash_preimage)

        self.assertTrue(tx.sign_input(0, private_key0, SIGHASH_ALL))
        self.assertTrue(tx.sign_input(1, private_key1, SIGHASH_ALL))
