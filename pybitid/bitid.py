#!/usr/bin/env python
'''
Version: 0.0.3
Functions for a python backend implementation of Bitid protocol
All string parameters are unicode.
'''
import os
import random
import time
import hashlib
from pybitid import pybitcointools as bittools
from pybitid.pysix import to_bytes

SECURE_SCHEME       = "https"    
BITID_SCHEME        = "bitid"
PARAM_NONCE         = "x"
PARAM_UNSECURE      = "u"
# TODO: do we need to give more data to Google ? 
QRCODE_SERV_URI     = "http://chart.apis.google.com/chart?cht=qr&chs=300x300&chl="
# TODO - check what should be the max length of a nonce in bitid
NONCE_LEN           = 16

try:
    from urllib import quote
    import urlparse
    # Fix for bug in urlparse (see http://bugs.python.org/issue9374)
    urlparse.uses_netloc.append(BITID_SCHEME)
    urlparse.uses_query.append(BITID_SCHEME)
    urlparse.uses_params.append(BITID_SCHEME)
    urlparse.uses_fragment.append(BITID_SCHEME)
    from urlparse import urlparse, urlunparse, parse_qs
except ImportError:
    from urllib.parse import urlparse, urlunparse, parse_qs, quote


def build_uri(callback_uri, nonce=None):
    '''
    Builds a bitid uri upon a template (callback uri)
    Parameters:
        callback_uri = callback uri used as template
        nonce        = nonce to embed in the bitid uri. If None, a nonce is automatically generated
    '''
    parsed = urlparse(callback_uri)
    scheme = parsed.scheme
    netloc = parsed.netloc
    path   = parsed.path
    if (not scheme) or (not netloc) or (not path): 
        raise BaseException("Missing or invalid parameter: callback_uri")
        
    if nonce is None: nonce = generate_nonce()
    query = "%s=%s" % (PARAM_NONCE, nonce)
    if scheme != SECURE_SCHEME: query += "&%s=1" % PARAM_UNSECURE
    return urlunparse((BITID_SCHEME, netloc, path, "", query, ""))
    

def challenge_valid(addr, sign, bitid_uri, callback_uri, is_testnet=False):
    '''
    Checks data returned by the client (address, bitid uri and signature)
    Parameters:
        addr         = bitcoin address
        sign         = signature
        bitid_uri    = bitid uri
        callback_uri = callback uri used by the website
        is_test      = True if validation done for test network, False for main network (optional, default = False)        
    '''
    if not address_valid(addr, is_testnet): return False
    if not uri_valid(bitid_uri, callback_uri): return False
    if not signature_valid(addr, sign, bitid_uri, callback_uri, is_testnet): return False
    return True


def signature_valid(addr, sign, bitid_uri, callback_uri, is_testnet=False):
    '''
    Checks signature against given message and address
    Parameters:
        addr         = bitcoin address
        sign         = signature
        bitid_uri    = bitid uri
        callback_uri = callback uri used by the website
        is_test      = True if validation done for test network, False for main network (optional, default = False)        
    '''
    try:
        if not bittools.signature_verify(bitid_uri, sign, addr, is_testnet): return False
    except: 
        return False
    return True
     

def extract_nonce(bitid_uri):
    '''
    Extracts the nonce from a bitid uri
    Returns None if nonce not found or invalid
    Parameters:
        bitid_uri = bitid uri
    '''
    parsed_bitid = urlparse(bitid_uri)
    nonces = parse_qs(parsed_bitid.query).get(PARAM_NONCE, "")
    if (nonces is None) or (len(nonces) != 1):
        return None
    else:
        return nonces[0]   
    

def qrcode(bitid_uri):
    '''
    Generates a qrcode embedding a bitid uri
    Returns the uri to display the qrcode
    Parameters:
        bitid_uri = bitid uri        
    '''
    return QRCODE_SERV_URI + quote(bitid_uri)


def uri_valid(bitid_uri, callback_uri):
    '''
    Checks that a bitid uri is valid
    Parameters:
        bitid_uri    = bitid uri to check
        callback_uri = callback uri used by the website       
    '''
    parsed_bitid = urlparse(bitid_uri)
    nonce        = extract_nonce(bitid_uri)
    unsec_param  = extract_unsecure(bitid_uri)
    
    parsed_callb = urlparse(callback_uri)
    unsecure     = parsed_callb.scheme != SECURE_SCHEME
    
    not_empty   = not bitid_uri is None
    scheme_ok   = parsed_bitid.scheme == BITID_SCHEME
    host_ok     = parsed_bitid.netloc == parsed_callb.netloc
    path_ok     = parsed_bitid.path   == parsed_callb.path
    nonce_ok    = False if not nonce else True
    unsecure_ok = True if (unsecure and unsec_param == "1") or (not unsecure and unsec_param is None) else False
    
    return not_empty & scheme_ok & host_ok & path_ok & nonce_ok & unsecure_ok
    
    
def address_valid(addr, is_testnet=False):
    '''
    Checks that an address is valid for a given network
    Parameters:
        addr = address
        is_testnet = True if address must be checked for the testnet, False for the mainnet (default)
    '''
    return bittools.address_verify(addr, is_testnet)

      
def extract_unsecure(bitid_uri):
    '''
    Extracts the unsecure parameter from a bitid uri
    Returns None if parameter not found or invalid
    Parameters:
        bitid_uri = bitid uri
    '''
    parsed_bitid = urlparse(bitid_uri)
    unsecures = parse_qs(parsed_bitid.query).get(PARAM_UNSECURE, "")
    if (unsecures is None) or (len(unsecures) != 1) or not (unsecures[0] in ("0", "1")):
        return None
    else:
        return unsecures[0]


def generate_nonce():
    '''
    Generates a random nonce
    Inspired from random_key() in https://github.com/vbuterin/pybitcointools/blob/master/bitcoin/main.py 
    Credits to https://github.com/vbuterin    
    '''
    entropy = str(os.urandom(32)) + str(random.randrange(2**256)) + str(int(time.time())**7)
    return hashlib.sha256(to_bytes(entropy)).hexdigest()[:NONCE_LEN]
    
    