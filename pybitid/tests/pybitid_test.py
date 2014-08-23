#!/usr/bin/env python
'''
Version: 0.0.2
UnitTest of bitid functions
Requires:
- PYCOIN:
    repo     = https://github.com/richardkiss/pycoin
    install  = pip install pycoin
'''
import unittest
import pybitid.bitid as bitid
try:
    from urllib import quote
    from urlparse import urlparse, parse_qs
except ImportError:
    from urllib.parse import urlparse, parse_qs, quote


NONCE             = "fe32e61882a71074"
NETLOC            = "localhost:3000"
PATH              = "/callback"
CALLBACK_URI      = "http://%s%s" % (NETLOC, PATH)
SEC_CALLBACK_URI  = "https://%s%s" % (NETLOC, PATH)
BITID_URI         = "bitid://%s%s?x=%s" % (NETLOC, PATH, NONCE)
QRCODE_BASE_URI   = "http://chart.apis.google.com/chart?cht=qr&chs=300x300&chl="
ADDRESS           = "1HpE8571PFRwge5coHiFdSCLcwa7qetcn"
SIGNATURE         = "IPKm1/EZ1AKscpwSZI34F5NiEkpdr7QKHeLOPPSGs6TXJHULs7CSNtjurcfg72HNuKvL2YgNXdOetQRyARhX7bg="

NONCE_TEST        = "3893a2a881dd4a1e"
NETLOC_TEST       = "bitid.bitcoin.blue"
PATH_TEST         = "/callback"
CALLBACK_URI_TEST = "http://%s%s" % (NETLOC_TEST, PATH_TEST)
ADDRESS_TEST      = "mpsaRD2ugdCY1iFrQdsDYRT4qeZzCnvGHW",
BITID_URI_TEST    = "bitid://%s%s?x=%s&u=1" % (NETLOC_TEST, PATH_TEST, NONCE_TEST)
SIGNATURE_TEST    = "ID5heI0WOeWoryGhZHaxoOH5vkmmcwDsfc4nDQ5vPcXSWh2jyETDGkSNO5zk4nbESGD6k0tgFxYA3HzlEGOf5Uc="

NONCE_LENGTH    = 16

class PyBitIdTestCase(unittest.TestCase):
    
    def test_build_uri(self):
        bitid_uri   = bitid.build_uri(CALLBACK_URI, NONCE)
        parsed      = urlparse(bitid_uri)
        qs_bitid    = parse_qs(parsed.query, strict_parsing=True)
        qs_nonce    = qs_bitid.get(bitid.PARAM_NONCE, "")
        
        self.assertIsNotNone(bitid_uri)
        self.assertEqual(bitid.BITID_SCHEME, parsed.scheme)
        self.assertEqual(NETLOC, parsed.netloc)        
        self.assertEqual(PATH, parsed.path)
        self.assertEqual(len(qs_nonce), 1)
        self.assertEqual(qs_nonce[0], NONCE)

    def test_build_qrcode(self):
        qrcode = bitid.qrcode(BITID_URI)
        check_qrcode = QRCODE_BASE_URI + quote(BITID_URI)
        self.assertEqual(check_qrcode, qrcode)
           
    def test_build_uri_secure(self):
        try:
            bitid_uri = bitid.build_uri(CALLBACK_URI, NONCE)
            regexp = "\Abitid\:\/\/localhost\:3000\/callback\?x=[a-z0-9]+\Z"
            self.assertRegex(bitid_uri, regexp)
        except:
            pass
              
    def test_build_uri_unsecure(self):
        try:
            bitid_uri = bitid.build_uri(SEC_CALLBACK_URI, NONCE)
            regexp = "\Abitid\:\/\/localhost\:3000\/callback\?x=[a-z0-9]+&u=1\Z"
            self.assertRegex(bitid_uri, regexp)
        except:
            pass
        
    def test_verify_uri(self):
        bitid_uri = bitid.build_uri(CALLBACK_URI, NONCE)
        is_valid = bitid.uri_valid(bitid_uri, CALLBACK_URI)
        self.assertTrue(is_valid)
        
    def test_fail_uri_verification_if_bad_uri(self):
        is_valid = bitid.uri_valid("garbage", CALLBACK_URI)
        self.assertFalse(is_valid)
        
    def test_fail_uri_verification_if_bad_scheme(self):
        bad_bitid_uri = "%s?x=%s" % (CALLBACK_URI, NONCE)
        is_valid = bitid.uri_valid(bad_bitid_uri, CALLBACK_URI)
        self.assertFalse(is_valid)
        
    def test_fail_uri_verification_if_invalid_callback_url(self):
        bad_bitid_uri = "%s%s?x=%s" % (NETLOC, PATH, NONCE)
        is_valid = bitid.uri_valid(bad_bitid_uri, CALLBACK_URI)
        self.assertFalse(is_valid)
        
    def test_fail_uri_verification_if_missing_nonce(self):
        bad_bitid_uri = "%s%s" % (NETLOC, PATH)
        is_valid = bitid.uri_valid(bad_bitid_uri, CALLBACK_URI)
        self.assertFalse(is_valid)
        
    def test_fail_uri_verification_if_invalid_insecure(self):
        bad_bitid_uri = bitid.build_uri(SEC_CALLBACK_URI, NONCE)
        is_valid = bitid.uri_valid(bad_bitid_uri, CALLBACK_URI)
        self.assertFalse(is_valid)
        bad_bitid_uri = bitid.build_uri(CALLBACK_URI, NONCE)
        is_valid = bitid.uri_valid(bad_bitid_uri, SEC_CALLBACK_URI)
        self.assertFalse(is_valid)
    
    def test_verify_signature(self):
        bitid_uri = bitid.build_uri(SEC_CALLBACK_URI, NONCE)
        is_valid = bitid.signature_valid(ADDRESS, SIGNATURE, bitid_uri, SEC_CALLBACK_URI)
        self.assertTrue(is_valid)
    
    def test_fail_verification_if_invalid_signature(self):
        bitid_uri = bitid.build_uri(CALLBACK_URI, NONCE)
        is_valid = bitid.signature_valid(ADDRESS, "garbage", bitid_uri, CALLBACK_URI)
        self.assertFalse(is_valid)
        
    def test_fail_verification_if_signature_text_doesnt_match(self):
        bitid_uri = bitid.build_uri(CALLBACK_URI, NONCE)
        bad_signature = "H4/hhdnxtXHduvCaA+Vnf0TM4UqdljTsbdIfltwx9+w50gg3mxy8WgLSLIiEjTnxbOPW9sNRzEfjibZXnWEpde4="
        is_valid = bitid.signature_valid(ADDRESS, bad_signature, bitid_uri, CALLBACK_URI)
        self.assertFalse(is_valid)
    
    def test_generate_nonce(self):
        len_nonce = len(bitid.generate_nonce())
        self.assertEqual(NONCE_LENGTH, len_nonce)  
     
    def test_testnet(self):
        bitid_uri   = bitid.build_uri(CALLBACK_URI_TEST, NONCE_TEST)
        parsed      = urlparse(bitid_uri)
        qs_bitid    = parse_qs(parsed.query, strict_parsing=True)
        qs_nonce    = qs_bitid.get(bitid.PARAM_NONCE, "")
        
        self.assertIsNotNone(bitid_uri)
        self.assertEqual(bitid.BITID_SCHEME, parsed.scheme)
        self.assertEqual(NETLOC_TEST, parsed.netloc)        
        self.assertEqual(PATH_TEST, parsed.path)
        self.assertEqual(len(qs_nonce), 1)
        self.assertEqual(qs_nonce[0], NONCE_TEST)
        
if __name__ == '__main__':
    unittest.main()
