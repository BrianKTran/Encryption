from Crypto.Cipher import AES
class Encryption(object):
    def __init__(self, passkey=None, mode=None):
        self.passkey = passkey
	self.mode = mode
        self.aes = None
    
    def setPasskey(self, p):
        self.passkey = p

    def setMode(self, m):
        self.mode = m

    def encrypt(self, s):
        if not self.passkey: raise ValueError('Passkey not set')
        if not self.mode: self.mode = AES.MODE_CFB

        self.aes = AES.new(self.passkey, self.mode)
        return self.aes.encrypt(s)

    def decrypt(self, s):
        if not self.passkey: raise ValueError('Passkey not set')
        if not self.mode: self.mode = AES.MODE_CFB

        self.aes = AES.new(self.passkey, self.mode)
        return self.aes.decrypt(s)
