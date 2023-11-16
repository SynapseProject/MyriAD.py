import json
import sys

class LdapCrypto():
    def __init__(self, crypto: dict = None):
        if crypto != None:
            self.text = crypto.get("text") if crypto.get("text") else None
            self.iv = crypto.get("iv") if crypto.get("iv") else None
            self.salt = crypto.get("salt") if crypto.get("salt") else None
            self.passphrase = crypto.get("passphrase") if crypto.get("passphrase") else None
        else:
            self.text = None
            self.iv = None
            self.salt = None
            self.passphrase = None