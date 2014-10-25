#!/usr/bin/python
'''
Version: 0.0.4
Bitcoin utils library
This library is a subset of original code developed by Vitalik Buterin for pybitcointools
  (https://github.com/vbuterin/pybitcointools/blob/master/bitcoin/main.py) 
Code has been adapted for compatibility with Python 2.7 / 3.3
'''
import hashlib, re, base64, binascii
from pybitid.pysix import b2i, i2b, to_bytes


### Elliptic curve parameters (secp256k1)

P = 2**256-2**32-2**9-2**8-2**7-2**6-2**4-1
N = 115792089237316195423570985008687907852837564279074904382605163141518161494337
A = 0
B = 7
Gx = 55066263022277343669578718895168534326250603453777594175500187360389116729240
Gy = 32670510020758816978083085130507043184471273380659243275938904335757337482424
G = (Gx,Gy)


### Extended Euclidean Algorithm

def inv(a,n):
    lm, hm = 1,0
    low, high = a%n,n
    while low > 1:
        r = high//low
        nm, new = hm-lm*r, high-low*r
        lm, low, hm, high = nm, new, lm, low
    return lm % n


### Base switching

def get_code_string(base):
    if base == 2: return '01'
    elif base == 10: return b'0123456789'
    elif base == 16: return b'0123456789abcdef'
    elif base == 32: return b'abcdefghijklmnopqrstuvwxyz234567'
    elif base == 58: return b'123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    elif base == 256: return b''.join([i2b(x) for x in range(256)])
    else: raise ValueError("Invalid base!")

def lpad(msg,symbol,length):
    if len(msg) >= length: return msg
    return symbol * (length - len(msg)) + msg

def encode(val,base,minlen=0):
    base, minlen = int(base), int(minlen)
    code_string = get_code_string(base)
    result = b''   
    while val > 0:
        idx = val % base
        result = code_string[idx:idx+1] + result
        val //= base
    return lpad(result, code_string[0:1], minlen)

def decode(string,base):
    base = int(base)
    code_string = get_code_string(base)
    result = 0
    if base == 16: string = string.lower()
    while len(string) > 0:
        result *= base
        result += code_string.find(string[0])
        string = string[1:]
    return result

def changebase(string,frm,to,minlen=0):
    if frm == to: return lpad(string,minlen)
    return encode(decode(string,frm),to,minlen)


### Elliptic Curve functions

def isinf(p): return p[0] == 0 and p[1] == 0

def base10_add(a,b):
    if isinf(a): return b[0],b[1]
    if isinf(b): return a[0],a[1]
    if a[0] == b[0]: 
        if a[1] == b[1]: return base10_double((a[0],a[1]))
        else: return (0,0)
    m = ((b[1]-a[1]) * inv(b[0]-a[0],P)) % P
    x = (m*m-a[0]-b[0]) % P
    y = (m*(a[0]-x)-a[1]) % P
    return (x,y)

def base10_double(a):
    if isinf(a): return (0,0)
    m = ((3*a[0]*a[0]+A)*inv(2*a[1],P)) % P
    x = (m*m-2*a[0]) % P
    y = (m*(a[0]-x)-a[1]) % P
    return (x,y)

def base10_multiply(a,n):
    if isinf(a) or n == 0: return (0,0)
    if n == 1: return a
    if n < 0 or n >= N: return base10_multiply(a,n%N)
    if (n%2) == 0: return base10_double(base10_multiply(a,n//2))
    if (n%2) == 1: return base10_add(base10_double(base10_multiply(a,n//2)),a)


# Functions for handling pubkey and privkey formats

def get_pubkey_format(pub):
    if isinstance(pub,(tuple,list)): return 'decimal'
    elif len(pub) == 65 and pub[0:1] == b'\x04': return 'bin'
    elif len(pub) == 130 and pub[0:2] == b'04': return 'hex'
    elif len(pub) == 33 and pub[0:1] in [b'\x02',b'\x03']: return 'bin_compressed'
    elif len(pub) == 66 and pub[0:2] in [b'02',b'03']: return 'hex_compressed'
    elif len(pub) == 64: return 'bin_electrum'
    elif len(pub) == 128: return 'hex_electrum'
    else: raise Exception("Pubkey not in recognized format")
    
def encode_pubkey(pub,formt):
    if not isinstance(pub,(tuple,list)):
        pub = decode_pubkey(pub)
    if formt == 'decimal': return pub
    elif formt == 'bin': return b'\x04' + encode(pub[0],256,32) + encode(pub[1],256,32)
    elif formt == 'bin_compressed': return encode(2+(pub[1]%2),256) + encode(pub[0],256,32)
    elif formt == 'hex': return b'04' + encode(pub[0],16,64) + encode(pub[1],16,64)
    elif formt == 'hex_compressed': return b'0'+ encode(2+(pub[1]%2), 16) + encode(pub[0],16,64)
    elif formt == 'bin_electrum': return encode(pub[0],256,32) + encode(pub[1],256,32)
    elif formt == 'hex_electrum': return encode(pub[0],16,64) + encode(pub[1],16,64)
    else: raise Exception("Invalid format!")
    
def decode_pubkey(pub,formt=None):
    if not formt: formt = get_pubkey_format(pub)
    if formt == 'decimal': return pub
    elif formt == 'bin': return (decode(pub[1:33],256),decode(pub[33:65],256))
    elif formt == 'bin_compressed':
        x = decode(pub[1:33],256)
        beta = pow(x*x*x+B,(P+1)//4,P)
        y = (P-beta) if ((beta + b2i(pub[0])) % 2) else beta
        return (x,y)
    elif formt == 'hex': return (decode(pub[2:66],16),decode(pub[66:130],16))
    elif formt == 'hex_compressed': return decode_pubkey(binascii.unhexlify(pub),'bin_compressed')
    elif formt == 'bin_electrum': return (decode(pub[:32],256),decode(pub[32:64],256))
    elif formt == 'hex_electrum': return (decode(pub[:64],16),decode(pub[64:128],16))
    else: raise Exception("Invalid format!")

def neg_pubkey(pubkey): 
    f = get_pubkey_format(pubkey)
    pubkey = decode_pubkey(pubkey,f)
    return encode_pubkey((pubkey[0],(P-pubkey[1]) % P),f)


### Hashes

def bin_hash160(string):
    intermed = hashlib.sha256(string).digest()
    return hashlib.new('ripemd160',intermed).digest()
def bin_dbl_sha256(string):
    return hashlib.sha256(hashlib.sha256(string).digest()).digest()

def hash_to_int(x):
    if len(x) in [40,64]: return decode(x,16)
    else: return decode(x,256)

def num_to_var_int(x):
    x = int(x)
    if x < 253: return i2b(x)
    elif x < 65536: return i2b(253) + encode(x,256,2)[::-1]
    elif x < 4294967296: return i2b(254) + encode(x,256,4)[::-1]
    else: return i2b(255) + encode(x,256,8)[::-1]

def electrum_sig_hash(message):
    padded = b'\x18Bitcoin Signed Message:\n' + num_to_var_int(len(message)) + message
    return bin_dbl_sha256(padded)


### Encodings

def bin_to_b58check(inp,magicbyte=0):
    inp_fmtd = i2b(magicbyte) + inp
    leadingzbytes = len(re.match(b'^\x00*',inp_fmtd).group(0))
    checksum = bin_dbl_sha256(inp_fmtd)[:4]
    return b'1' * leadingzbytes + changebase(inp_fmtd+checksum,256,58)

def get_version_byte(inp):
    leadingzbytes = len(re.match(b'^1*',inp).group(0))
    data = b'\x00' * leadingzbytes + changebase(inp,58,256)
    assert bin_dbl_sha256(data[:-4])[:4] == data[-4:]
    return b2i(data[0])
    
def pubkey_to_address(pubkey,magicbyte=0):
    if isinstance(pubkey,(list,tuple)):
        pubkey = encode_pubkey(pubkey,'bin')
    if len(pubkey) in [66,130]:
        return bin_to_b58check(bin_hash160(binascii.unhexlify(pubkey)), magicbyte)
    return bin_to_b58check(bin_hash160(pubkey),magicbyte)

pubtoaddr = pubkey_to_address

def pubbyte_prefix(istest):
    return 111 if istest else 0


### EDCSA

def decode_sig(sig):
    bytez = base64.b64decode(sig)
    return b2i(bytez[0]), decode(bytez[1:33],256), decode(bytez[33:],256)

def ecdsa_raw_verify(msghash,vrs,pub):
    v,r,s = vrs
    w = inv(s,N)
    z = hash_to_int(msghash)
    u1, u2 = z*w % N, r*w % N
    x,y = base10_add(base10_multiply(G,u1), base10_multiply(decode_pubkey(pub), u2))
    return r == x

def ecdsa_verify(msg,sig,pub):
    return ecdsa_raw_verify(electrum_sig_hash(msg), decode_sig(sig), pub)

def ecdsa_raw_recover(msghash,vrs):
    v,r,s = vrs
    x = r
    beta = pow(x*x*x+B,(P+1)//4,P)
    y = beta if v%2 ^ beta%2 else (P - beta)
    z = hash_to_int(msghash)
    Qr = base10_add(neg_pubkey(base10_multiply(G,z)),base10_multiply((x,y),s))
    Q = base10_multiply(Qr,inv(r,N))
    if ecdsa_raw_verify(msghash,vrs,Q): return Q
    return False

def ecdsa_recover(msg,sig):
    Q = ecdsa_raw_recover(electrum_sig_hash(msg), decode_sig(sig))
    return encode_pubkey(Q, 'hex') if Q else False

def ecdsa_is_compressed(vrs):
    v,r,s = vrs
    return False if v < 31 or v >= 35 else True
        

# High level verifications

def signature_verify(msg, sig, addr, istest=False):
    try:
        msg = to_bytes(msg)
        sig = to_bytes(sig)
        addr = to_bytes(addr)
        # Recovers public key (and checks signature is valid)
        Q = ecdsa_recover(msg,sig)
        if not Q: return False
        if ecdsa_is_compressed(decode_sig(sig)): Q = encode_pubkey(Q, 'hex_compressed')
        # Checks given address is equal to address associated to public key
        return True if pubkey_to_address(Q, pubbyte_prefix(istest)) == addr else False
    except AssertionError:
        return False
    
def address_verify(addr, istest=False):
    try:
        addr = to_bytes(addr)
        # Checks checksum
        leadingzbytes = len(re.match(b'^1*',addr).group(0))
        data = b'\x00' * leadingzbytes + changebase(addr,58,256)
        csum_ok = bin_dbl_sha256(data[:-4])[:4] == data[-4:]
        # Checks network
        vb = get_version_byte(addr)
        ntw_ok = (vb == 0 and not istest) or (vb == 111 and istest)
        # Result
        return csum_ok and ntw_ok
    except AssertionError:
        return False


