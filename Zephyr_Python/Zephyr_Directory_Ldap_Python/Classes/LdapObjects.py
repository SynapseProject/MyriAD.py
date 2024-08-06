import json
import sys

class LdapObject():
    def __init__(self):
        self.dn = None
        self.attributes = {}