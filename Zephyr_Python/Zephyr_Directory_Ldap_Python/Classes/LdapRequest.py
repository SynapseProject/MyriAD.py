import sys
import json
from Zephyr_Directory_Ldap_Python.Classes import *
from Zephyr_Directory_Ldap_Python.Classes.LdapConfig import LdapConfig
from Zephyr_Directory_Ldap_Python.Classes.LdapCrypto import LdapCrypto
from enum import Enum
import ldap3
#GET MORE INFO ON THIS TYPE OF CLASS
class ObjectType(Enum):
    User = 0
    Group = 1
    OrganizationalUnit = 2
    Ou = 3 
    Contact = 4
    PrintQueue = 5
    Printer = 6
    Computer = 7
    Volume = 8
    Domain = 9
    DomainController = 10
    Dn = 11
    DistinguishedName = 12

class PingType(Enum):
    Echo = 0,
    NoEcho = 1

class SearchScopeType(Enum):
    # All = LdapConnection.ScopeSub,
    # One = LdapConnection.ScopeOne,
    # Base = LdpaConnection.ScopeBase
    All = ldap3.SUBTREE
    Base = ldap3.BASE
    One = ldap3.LEVEL

class LdapRequest():
    def __init__(self, data:dict):
        self.object_type = data.get("objectType").capitalize() if data.get("objectType") else None
        self.domain = data.get("domain") if data.get("domain") else None
        self.searchValue = data.get("searchValue") if data.get("searchValue") else None
        self.searchBase = data.get("searchBase") if data.get("searchBase") else None
        self.searchScope = data.get("searchScope") if data.get("searchScope") else None
        self.maxResults = int(data.get("maxResults")) if data.get("maxResults") else None
        self.nextToken = data.get("nextToken") if data.get("nextToken") else None
        self.wildcardToken = data.get("wildcardSearch") if data.get("wildcardSearch") else None
        self.attributes = data.get("attributes") if data.get("attributes") else None
        self.config = data.get("config") if data.get("config") else None
        self.crypto = data.get("crypto") if data.get("crypto") else None
        self.ping = data.get("ping") if data.get("ping") else None
        self.present = self.Is_Attributes_In_Data(data=data)

    def Is_Attributes_In_Data(self, data):
        if "attributes" in data:
            self.present = True
        else:
            self.present = False
        return self.present
    def ObjectType(self):
        if self.object_type == None:
            pass
        elif self.object_type == "User":
            self.object_type = ObjectType.User
        elif self.object_type == "Group":
            self.object_type = ObjectType.Group
        elif self.object_type == "Organizationalunit":
            self.object_type = ObjectType.OrganizationalUnit
        elif self.object_type == "Ou":
            self.object_type = ObjectType.Ou
        elif self.object_type == "Contact":
            self.object_type = ObjectType.Contact
        elif self.object_type == "Printqueue":
            self.object_type = ObjectType.PrintQueue
        elif self.object_type == "Printer":
            self.object_type = ObjectType.Printer
        elif self.object_type == "Computer":
            self.object_type = ObjectType.Computer
        elif self.object_type == "Volume":
            self.object_type = ObjectType.Volume
        elif self.object_type == "Domain":
            self.object_type = ObjectType.Domain
        elif self.object_type == "Domaincontroller":
            self.object_type = ObjectType.DomainController
        elif self.object_type == "Dn":
            self.object_type = ObjectType.Dn
        elif self.object_type == "DistinguishedName":
            self.object_type = ObjectType.DistinguishedName
        else:
            print("ObjectType was not Found!")
        return self.object_type
        
    def SearchScope(self):
        if self.searchScope == None:
            pass
        elif self.searchScope == "All":
            self.searchScope = SearchScopeType.All
        elif self.searchScope == "Base":
            self.searchScope = SearchScopeType.Base
        elif self.searchScope == "One":
            self.searchScope = SearchScopeType.One
        else:
            print("SearchScope was not found")
        return self.searchScope
    def Config(self):
        config = LdapConfig(config=self.config)
        return config
    def Crypto(self):
        crypto = LdapCrypto(self.crypto)
        return crypto
    def Ping(self):
        if self.ping == "Echo":
            ping = PingType.Echo
        if self.ping == "NoEcho":
            ping = PingType.NoEcho
        return ping
    