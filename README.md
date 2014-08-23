# PyBitID

This is a python implementation of the BitID authentication protocol (https://github.com/bitid/bitid). 

Demo application using this library can be found at : https://github.com/LaurentMT/pybitid_demo
Video demonstration : https://www.youtube.com/watch?v=3eepEWTnRTc


WORK IN PROGRESS !!! CONTRIBUTORS ARE WELCOME !


## Python versions

Unit tests passed for Python 2.7.6 and 3.3.3


## Dependencies

No more dependency on external libraries. All crypto stuff is embedded inside the library.
Credits to V.Buterin for the original pybitcointools lib.


## Installation

```
Gets the library from Github : https://github.com/LaurentMT/pybitid/archive/master.zip
Unzips the archive in a temp directory
python setup.py install
```

## Todo

- Double-check of the code
- Tests, tests, tests...


## Usage

### Challenge

To build a challenge, you need first to build a BitId uri with a nonce and a callback uri.
The nonce is an random string associated with the user's session id.
The callback uri is the uri where the wallet will post the challenge's signature.


To build the BitId uri with a nonce automatically generated
```
import pybitid.bitid as bitid
# Secure callback uri
bitid_uri = bitid.build_uri("https://www.mysite.com:8080/")
# Unsecure callback uri (for dev purpose)
bitid_uri = bitid.build_uri("http://www.mysite.com:8080/")
```

To generate a nonce manually with the library
```
import pybitid.bitid as bitid
nonce = bitid.generate_nonce()
```

To build the BitId uri with a nonce you've generated
```
import pybitid.bitid as bitid
callback = "https://www.mysite.com:8080/"
nonce = "fe32e61882a71074"
bitid_uri = bitid.build_uri(callback, nonce)
```

To get the BitId uri as a QRcode (actually an URL pointing to a QRcode generated with Google charts api)
```
import pybitid.bitid as bitid
bitid_uri = ...
qrcode_uri = bitid.qrcode(bitid_uri)
```
Note: 
This method is provided for convenience during development / tests. 
Production code should always generate QRCode image on server to enforce privacy (see  https://pypi.python.org/pypi/qrcode)


### Verification

When getting the callback from the wallet, you receive 3 parameters: 
- bitcoin address 
- bitid uri 
- signature

You must check that:
- the address is a valid bitcoin address,
- the bitid uri is valid,
- the signature is valid (i.e. corresponds to the bitid uri signed by the private key associated to the address)


To check the validity of an address
```
import pybitid.bitid as bitid
# Check validity for the main network
is_valid = bitid.address_valid(address)
# ... or check validity for the test network
is_valid = bitid.address_valid(address, True)
```

To check the validity of a BitId uri 
```
import pybitid.bitid as bitid
is_valid = bitid.uri_valid(bitid_uri)
```

To check the validity of a signature 
```
import pybitid.bitid as bitid
# Check validity for the main network
is_valid = bitid.signature_valid(addr, sign, bitid_uri, callback_uri)
# ... or check validity for the test network
is_valid = bitid.signature_valid(addr, sign, bitid_uri, callback_uri, True)
```

To check the validity of the signature, address and bitid uri in one step 
```
import pybitid.bitid as bitid
# Check validity for the main network
is_valid = bitid.challenge_valid(addr, sign, bitid_uri, callback_uri)
# ... or check validity for the test network
is_valid = bitid.challenge_valid(addr, sign, bitid_uri, callback_uri, True)
```
If this function returns True then you can authenticate the user's session with the address (public Bitcoin address used to sign the challenge).


To extract the nonce from a BitId uri 
```
import pybitid.bitid as bitid
nonce = bitid.extract_nonce(bitid_uri)
```

To extract the secure/unsecure parameter from a BitId uri 
```
import pybitid.bitid as bitid
sec_param = bitid.extract_unsecure(bitid_uri)
```


## Integration example

Demo application in python : https://github.com/LaurentMT/pybitid_demo
Live demonstration (Ruby on Rails): http://bitid-demo.herokuapp.com/


## Author
Twitter: @LaurentMT


## Contributing

1. Fork it
2. Create your feature branch (`git checkout -b my-new-feature`)
3. Commit your changes (`git commit -am 'Add some feature'`)
4. Push to the branch (`git push origin my-new-feature`)
5. Create new Pull Request
