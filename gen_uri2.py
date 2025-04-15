#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
    Author: LibreMai(libremai@localhost)
"""

from cryptography import x509  
from cryptography.hazmat.backends import default_backend  
from cryptography.hazmat.primitives import hashes
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

import binascii
import hashlib
import base64

BLOCK_SIZE = 128
KEY_SIZE = 256
AES_KEY = b""
AES_IV = b""

def construct_uri2(hex_string):    
    inverted_data = bytearray(~b & 0xFF for b in bytearray.fromhex(hex_string))
    
    encrypted_data = encrypt(inverted_data)

    base64_encoded = base64.b64encode(encrypted_data)
    byteArray = bytearray(base64_encoded)
    
    byteArray[43] = 61

    return byteArray.decode()  

def verify_uri2(uri2):  
    byteArray = bytearray([ord(c) for c in uri2])

    byteArray[43] = 61  

    hex_string = binascii.hexlify(byteArray).decode()  

    decrypted_data = decrypt(base64.b64decode(byteArray))

    inverted_data = bytearray(~b & 0xFF for b in decrypted_data)  

    target_hex_string = binascii.hexlify(inverted_data[-20:]).decode()  
    return target_hex_string

def gen_uri2_from_cert(fileName):
    with open(fileName, 'rb') as f:  
        cert_pem = f.read()  
    
    cert = x509.load_pem_x509_certificate(cert_pem, default_backend())  
    
    sha1_fingerprint = cert.fingerprint(hashes.SHA1())  
    sha1_hex = ''.join(['{:02X}'.format(b) for b in sha1_fingerprint]).lower()

    return construct_uri2(sha1_hex)
    

def decrypt(encrypted_data):  
    cipher = AES.new(AES_KEY, AES.MODE_CBC, iv=AES_IV)  
    decrypted_data = unpad(cipher.decrypt(encrypted_data), AES.block_size)  
    return decrypted_data  

def encrypt(data):
    cipher = AES.new(AES_KEY, AES.MODE_CBC, iv=AES_IV)
    encrypted_data = cipher.encrypt(pad(data, AES.block_size))
    return encrypted_data


# GET URI2 FROM CERT SHA-1
cert_sha1_lowercase = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
uri2 = construct_uri2(cert_sha1_lowercase)
print("uri2:", uri2)

# GET CERT SHA-1 FROM GERENATED URI2

uri2_1 = "5DEaDBEEfn7P2T8fzNn7dnyW82B5ztRF3IoAeVn1V1/A="
uri2_2 = "DEAdbeefe2Mtp3EtV+BH1C+w+VHelbUxBivzLgG9Hg6"
s1 = verify_uri2(uri2_1)
s2 = verify_uri2(uri2_2)
print(s1, s1==cert_sha1_lowercase)
print(s2, s2==cert_sha1_lowercase)

# GENERATE URI2 FROM CERT
print("uri2 gen from cert:", gen_uri2_from_cert('certificate.pem'))