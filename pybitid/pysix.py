#!/usr/bin/python
'''
Version: 0.0.1
Utils functions used for compatibility with Python 2.7 / 3.3
'''

'''
Encodes a unicode string in bytes (utf8 encoding)
'''
def to_bytes(x): return x if bytes == str else x.encode()

'''
Converts an integer to a bytes
'''
i2b = chr if bytes == str else lambda x: bytes([x])

'''
Converts a bytes to an integer
'''
b2i = ord if bytes == str else lambda x: x
