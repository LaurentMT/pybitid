#!/usr/bin/env python
'''
Version: 0.0.2
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
from pycoin.ecdsa.ecdsa import verify
from pycoin.encoding import double_sha256, public_pair_to_bitcoin_address,\
                            is_valid_bitcoin_address, from_bytes_32, byte_to_int
from pycoin.ecdsa import numbertheory, ellipticcurve

# Elliptic curves
G = generator_secp256k1
N = G.order()
N_LEN = (1 + len("%x" % N)) // 2 

# Python 2 / 3 compatibility functions
def to_bytes(x): return x if bytes == str else x.encode()

        


'''
Signatures
'''
def string_to_number(s):
    if len(s) != N_LEN: raise BaseException("Wrong signature length")
    return int(binascii.hexlify(s), 16)

def sig_decode_string(sign):
    if len(sign) != 2 * N_LEN: raise BaseException("Wrong signature length")
    r = string_to_number(sign[:N_LEN])
    s = string_to_number(sign[N_LEN:])
    return r,s

def decode_sig(sign):
    ds = base64.b64decode(sign) 
    if len(ds) != 65: raise BaseException("Wrong encoding")
    v = byte_to_int(ds[0])
    r,s = sig_decode_string(ds[1:])
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
    '''
    Inspiration from :
     - possible_public_pairs_for_signature() in pycoin.ecdsa.ecdsa
     - https://github.com/michaelgpearce/bitcoin-cigs/blob/master/lib/bitcoin_cigs.rb
    '''
    curve = G.curve()
    p = curve.p()
    v,r,s = vrs
    if v < 27 or v >= 35:
        return False
    if v >= 31:
        cmprs = True
        v -= 4
    recid = v - 27
    # 1.1
    inv_r = numbertheory.inverse_mod(r,N)
    minus_e = -msghash % N
    x = (r + (recid // 2) * N) % p
    # 1.3
    alpha = ( pow(x,3,p)  + curve.a() * x + curve.b() ) % p
    beta = numbertheory.modular_sqrt(alpha, p)
    if (beta - recid) % 2 == 0:
        y = beta
    else:
        y = p - beta
    # 1.4 the constructor checks that nR is at infinity
    R = ellipticcurve.Point(curve, x, y, N)
    # 1.6 compute Q = r^-1 (sR - eG)
    Q = inv_r * ( s * R + minus_e * G )
    public_pair = (Q.x(), Q.y())
    # check that Q is the public key
    if verify(G, public_pair, msghash, (r, s)):
        # Checks that addresses match
        return True if addr == public_pair_to_bitcoin_address(public_pair, cmprs, is_test) else False
    else:
        return False


'''
Addresses
'''
def is_valid_address(addr, allow_mainnet, allow_testnet):
    return is_valid_bitcoin_address(addr, allow_mainnet, allow_testnet)

  
    