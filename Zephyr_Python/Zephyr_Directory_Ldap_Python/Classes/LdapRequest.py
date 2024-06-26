from Zephyr_Crypto_Python.Rijndael import Rijndael
from Zephyr_Directory_Ldap_Python.Classes.LdapConfig import LdapConfig
from Zephyr_Directory_Ldap_Python.Classes.LdapResponse import LdapResponse
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
    
# class SearchScopeType2(Enum):
#     All = bonsai.LDAPSearchScope.SUBTREE
#     Base = bonsai.LDAPSearchScope.BASE
#     One = bonsai.LDAPSearchScope.ONELEVEL

class LdapRequest():
    def __init__(self, data:dict):
        self.jobID = data.get("jobID") if data.get("jobID") else None
        self.recordsID = data.get("recordsID") if data.get("recordsID") else None
        self.object_type = data.get("objectType").capitalize() if data.get("objectType") else None
        self.domain = data.get("domain") if data.get("domain") else None
        self.searchValue = data.get("searchValue") if data.get("searchValue") else None
        self.searchBase = data.get("searchBase") if data.get("searchBase") else None
        self.searchScope = data.get("searchScope") if data.get("searchScope") else None
        self.maxResults = int(data.get("maxResults")) if data.get("maxResults") else None
        self.MultipleSearches = data.get("union") if data.get("union") else None
        self.nextToken = data.get("nextToken") if data.get("nextToken") else None
        self.wildcardToken = data.get("wildcardSearch") if type(data.get("wildcardSearch")) == bool else None
        self.attributes = data.get("attributes") if data.get("attributes") else None
        self.raise_exceptions = data.get("raise_exceptions") if data.get("raise_exceptions")!= None else True
        self.Timestamp = data.get("Timestamp") if data.get("Timestamp") else None
        self.expireAt = data.get("expireAt") if data.get("expireAt") else None
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
        elif self.object_type == "Distinguishedname":
            self.object_type = ObjectType.DistinguishedName
        else:
            pass
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
            pass
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

    def toJson_Ping_or_Crypto(response: LdapResponse):
        if response.success == True:
            dictionary = {"success": response.success, "message": str(response.message)}
        return dictionary

    def MyriAD_Search(self, response:LdapResponse, cryptography: Rijndael, test_config: LdapConfig, lambdaClient, data, isPing: bool):
        from Zephyr_Directory_Ldap_Python.Ldap_Server import LDapServer
        from Zephyr_Directory_Ldap_Python.Utilities.LdapUtils import LdapUtils 
        from Zephyr_Directory_Ldap_Python.Utilities.DynamoDBTools import DynamoDBTools 
        if test_config.batch == True and test_config.retrieval == False:
            response = DynamoDBTools.InvokeLambda(lambdaClient, data)
        elif test_config.batch == False and test_config.retrieval == True:
            response = DynamoDBTools.Batch_Retrieval(data, self)
        else:
            if self.Crypto().text != None:
                crypto = LdapUtils.ApplyDefaultandValidate(crypto=self.Crypto())
                print(crypto.text, crypto.passphrase, crypto.salt, crypto.iv)
                response.message = cryptography.Encrypt(crypto.text, crypto.passphrase, crypto.salt, crypto.iv)
                response = LdapRequest.toJson_Ping_or_Crypto(response)
            elif isPing:
                response.message = "Hello From MyriAD."
                response = LdapRequest.toJson_Ping_or_Crypto(response)
            else:
                try:
                    print("In Try Block:\n")
                    LdapUtils.ApplyDefaultsAndValidate(self)
                    searchstring = LdapUtils.GetSearchString(self)
                    ldap = LDapServer(self.config.server_name, self.config.port, self.config.ssl, self.config.maxRetries, self.config.maxPageSize, self.config.followReferrals, self.config.returnTypes)
                    if self.config.Token_type == "Server" or self.config.Token_type == "Client" or self.config.server_name_present == True:
                        if self.config.batch == True and self.config.retrieval == True:
                            partitionKey = data["jobID"]
                            timestamp = data["Timestamp"]
                            RecordsID = data["recordsID"]
                            unix = data["expireAt"]
                            DynamoDBTools.add_entry(partitionKey, timestamp, unix, RecordsID)
                        ldap.Connect(self.config, request=self)
                        self.object_type = self.ObjectType()
                        self.searchScope = self.SearchScope()
                        self.config.outputType = self.config.OutputType()
                        response = ldap.Search(request=self, searchFilter=searchstring, attributes=self.attributes, searchScope=self.searchScope, maxResults=self.maxResults, nextTokenStr=self.nextToken)
                        ldap.Disconnect()
                    else:
                        raise Exception("TokenType must be set to Server or Client or Server/Client")
                except Exception as e:
                    response = ldap.ReturnError(e, self.config, request=self)
                    if self.config.batch == True and self.config.retrieval == True:
                        partitionKey = data["jobID"]
                        timestamp = data["Timestamp"]
                        RecordsID = data["recordsID"]
                        DynamoDBTools.add_entry(partitionKey, timestamp, RecordsID)
                if self.config.batch == True and self.config.retrieval == True:
                    DynamoDBTools.update_entry(response, data)
        return response
                