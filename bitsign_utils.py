#!/usr/bin/env python
'''
Version: 0.0.1
Utils functions to deal with signatures, addresses and signed messages
Code strongly inspired by:
- ELECTRUM:
    Repo at https://github.com/spesmilo/electrum 
    Credits to https://github.com/spesmilo/ (Thomas Voegtlin) 
- PYBITCOINTOOLS
    Repo at https://github.com/vbuterin/pybitcointools/blob/master/bitcoin/main.py 
    Credits to Vitalik Buterin (https://github.com/vbuterin)  
Requires:
- PYCOIN:
    repo     = https://github.com/richardkiss/pycoin
    install  = pip install pycoin
'''
import binascii
import base64
from pycoin.ecdsa.secp256k1 import generator_secp256k1
from pycoin.ecdsa.ecdsa import possible_public_pairs_for_signature
from pycoin.encoding import double_sha256, public_pair_to_bitcoin_address,\
                            is_valid_bitcoin_address, from_bytes_32, byte_to_int

# Elliptic curves
G = generator_secp256k1
N = G.order()

# Python 2 / 3 compatibility functions
def to_bytes(x): return x if bytes == str else x.encode()

        


'''
Signatures
'''
def orderlen(n):
    return (1 + len("%x" % n)) // 2 

def string_to_number(s, n):
    length = orderlen(n)
    if len(s) != length: raise BaseException("Wrong signature length")
    return int(binascii.hexlify(s), 16)

def sig_decode_string(sign, n):
    length = orderlen(n)
    if len(sign) != 2 * length: raise BaseException("Wrong signature length")
    r = string_to_number(sign[:length], n)
    s = string_to_number(sign[length:], n)
    return r,s

def decode_sig(sign):
    ds = base64.b64decode(sign) 
    if len(ds) != 65: raise BaseException("Wrong encoding")
    v = byte_to_int(ds[0])
    r,s = sig_decode_string(ds[1:], N)
    return v,r,s

'''
Signed messages
'''
def int_sig_hash(msg):
    padded = "\x18Bitcoin Signed Message:\n" + chr(len(msg)) + msg
    return from_bytes_32(double_sha256(padded.encode()))

'''
Validation of message, signature, address
'''
def verify_sign_addr(msghash, vrs, addr, is_test=False):
    v,r,s = vrs
    if v < 27 or v >= 35:
        return False
    cmprs = True if v >= 31 else False
    pubpairs = possible_public_pairs_for_signature(G, msghash, (r,s))
    for pair in pubpairs:
        if addr == public_pair_to_bitcoin_address(pair, cmprs, is_test): return True
    return False

'''
Addresses
'''
def is_valid_address(addr, allow_mainnet, allow_testnet):
    return is_valid_bitcoin_address(addr, allow_mainnet, allow_testnet)

  
    