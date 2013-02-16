#####
#
# Year47 Software Library Resource
# Copyright (C) 2010-2012 Year47. All Rights Reserved.
# 
# Author: Glenn T Norton
# Contact: glenn@year47.com
#
# This software is provided 'as-is', without any express or implied
# warranty.  In no event will the authors be held liable for any damages
# arising from the use of this software.
# 
# Permission is granted to anyone to use this software for any purpose,
# including commercial applications, and to alter it and redistribute it
# freely, subject to the following restrictions:
# 
# 1. The origin of this software must not be misrepresented; you must not
#    claim that you wrote the original software. If you use this software
#    in a product, an acknowledgment in the product documentation would be
#    appreciated but is not required.
#
# 2. Altered source versions must be plainly marked as such, and must not be
#    misrepresented as being the original software.
#
# 3. This notice may not be removed or altered from any source distribution.
#
#
#####

from Crypto.Cipher import AES
from Crypto import Random

class Encryption(object):
    def __init__(self, passkey=None, mode=None, iv=None):
        self.passkey = passkey
	self.mode = mode
        self.iv = iv
    
    def setPasskey(self, p):
        self.passkey = p

    def setMode(self, m):
        self.mode = m

    def setIV(self, iv):
        self.iv = iv

    def encrypt(self, s):
        if not self.passkey: raise ValueError('Passkey not set')
        if not self.mode: self.mode = AES.MODE_CFB
        if not self.iv: self.iv = Random.new().read(AES.block_size)

        self.aes = AES.new(self.passkey, self.mode, self.iv)
        return self.aes.encrypt(s)

    def decrypt(self, s):
        if not self.passkey: raise ValueError('Passkey not set')
        if not self.mode: self.mode = AES.MODE_CFB
        if not self.iv: self.iv = Random.new().read(AES.block_size)

        self.aes = AES.new(self.passkey, self.mode, self.iv)
        return self.aes.decrypt(s)


##########################
# EXAMPLE
# >>> import Encryption
# >>> passkey = b'1234567890ABCDEF'
# >>> s = b'This is a string'
# >>> e = Encryption.Encryption(passkey=passkey)
# >>> enc = e.encrypt(s)
# >>> print enc
# >>> enc
# '\xcf\x90\xf7\xfd\x08\x02*T\x97\x1a (\xe3J\x17\xfb'
# >>> ss = e.decrypt(enc)
# >>> ss
# 'This is a string'
# >>> 
##########################

import unittest
class TestEncryption(unittest.TestCase):
    
    def setUp(self):
        self.passkey = b'0123456789ABCDEF'
        self.s = b'This is a string'
        self.e = Encryption(self.passkey)

    def testEncrypt(self):
        self.enc = self.e.encrypt(self.s)
        self.assertTrue(self.enc != self.s)

    def testDecrypt(self):
        self.enc = self.e.encrypt(self.s)
        self.ss = self.e.decrypt(self.enc)
        self.assertTrue(self.ss == self.s)

    def tearDown(self):
        del self.passkey
        del self.s
        del self.e

if __name__ == '__main__':
    unittest.main()

