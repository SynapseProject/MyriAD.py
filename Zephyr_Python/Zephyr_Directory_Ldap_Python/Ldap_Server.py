import sys
import array
import binascii
import ssl
import pickle
import base64
from ldap3 import Server, Connection, ALL, SAFE_SYNC, ALL_ATTRIBUTES, DSA, SUBTREE, NO_ATTRIBUTES, ALL_OPERATIONAL_ATTRIBUTES
from ldap3.core.exceptions import LDAPSocketOpenError, LDAPReferralError, LDAPException
from Zephyr_Directory_Ldap_Python.Classes import LdapConfig, LdapRequest, LdapResponse, LdapObject, LdapAttributeTypes
from Zephyr_Directory_Ldap_Python.Classes.LdapRequest import SearchScopeType
from Zephyr_Directory_Ldap_Python.Utilites.JsonTools import JsonTools
from Zephyr_Directory_Ldap_Python.Utilites.SidUtils import SidUtils
from cryptography import x509
from Zephyr_Crypto_Python.Rijndael import Rijndael
from Zephyr_Directory_Ldap_Python.KnownAttributes import KnownAttributes
import time
import conversion
import json
import uuid

class Options:
    def __init__(self, timeLimit, maxResults, serverTimeLimit, referralfollowing):
        self.TimeLimit = timeLimit
        self.MaxResults = maxResults
        self.ServerTimeLimit = serverTimeLimit
        self.ReferralFollowing = referralfollowing

class LDapServer:
    _SERVER = None
    _PORT = None
    _USESSL = None
    _MAXRETRIES = 0
    _MAXPAGESIZE = 512
    _FOLLOWREFERRALS = False
    _RETURNTYPES = {}

    def __init__(self, server: str, port: int, useSSL:bool, maxRetries:int = None, maxPageSize:int = None, followReferrals: int = None, attributeReturnTypes:dict = None):
        print("Creating LDAP Server Object")
        self.conn = Connection
        self.server = Server
        self._SERVER = server
        self._PORT = port
        self._USESSL = useSSL
        self._RETURNTYPES = attributeReturnTypes

        if maxRetries != None:
            self._MAXRETRIES = maxRetries
        if maxPageSize != None:
            self._MAXPAGESIZE = maxPageSize
        if followReferrals != None:
            self._FOLLOWREFERRALS
        if self._RETURNTYPES == None:
            self._RETURNTYPES = {}

        self.conn.socket = self._USESSL
        print(self._SERVER)
        
    # def __str__(self):
    #     return json.dumps(dict(self), ensure_ascii=False)

    # def __repr__(self):
    #     return self.__str__()

    def ToString(self):
        if self._USESSL:
            return f"ldaps://{self._SERVER}:{self._PORT}"
        else:
            return f"ldaps://{self._SERVER}:{self._PORT}"
        
    # def Bind(self, config:LdapConfig):
    #     self.conn.bind(self.srv)
        
    def Connect(self, config, request):
        flag = False
        print(f"{config.username}", ",", f"{config.password}")
        attempts = 0
        while attempts  <= 0 and flag == False:
            try:
                print("While Loop")
                self.server = Server(self._SERVER, self._PORT, use_ssl=True, get_info=ALL)
                self.conn = Connection(server = self.server, user=config.username, password=config.password, auto_bind= True, return_empty_attributes=False, check_names=True)
                if self.conn:
                    print("Connected")
                    flag = True
            except LDAPSocketOpenError as e:
                attempts += 1
                print(f"Error {e}")
    
    def Disconnect(self):
        self.conn.unbind()
        print("Disconnected")

    def Bind(self):
        self.conn.bind()

    def AddValueWithUnknownType(self, rec, key, attribute):
        print("Entering AddValueWithUnknownType")
        # try:
        # print("In Try")
        # values = list(attribute)
        # if len(values) > 1:
        #     rec[key] = values
        # else:
        #     rec[key] = values[0]
        # except:
        print("oops something went wrong, get values from here")
        if type(attribute) == list:
            values = attribute
        else:
            values = [str(attribute)]
        print(values)
        if len(values) > 1:
            rec[key] = values
            print(rec[key])
        else:
            rec[key] = str(values[0])
            print(rec[key])

    def ParseResults(self, entries, request: LdapRequest):
        # for i in self._RETURNTYPES.keys():
        #     print(i)
        print("-------------")
        # entries = JsonTools.Deserialize(entries)
        response = LdapResponse()
        response.records = entries

        for record in response.records:
            try:
                attributes = record['attributes']
                # print(attributes)
                for key in attributes.keys():
                    attribute = attributes[key]
                    attrType = LdapAttributeTypes.Unknown
                    if key in self._RETURNTYPES.keys():
                        print("Found in RETURNTYPE")
                        attrType = self._RETURNTYPES[key]
                        print(attrType)
                    elif key in KnownAttributes().DefaultTypes.keys():
                        print("Found in KnownAttributes")
                        attrType = KnownAttributes().DefaultTypes[key]
                        print(attrType)
                    if attrType == LdapAttributeTypes.Bytes or attrType == "Bytes":
                        print("HERE -> 1")
                        print(key, ": ", attribute)
                        if "encoded" in attribute:
                            print("HELLO")
                            i = attribute["encoded"].encode()
                            i = base64.b64decode(i)
                            print(i.hex())
                            attributes[key] = "0x"+i.hex()
                        # i = binascii.hexlify(attribute.encode('utf8'))
                        # i = i.decode()
                        # print(i)
                        # attributes[key] = "0x"+ i
                        else:
                            i = attribute.encode("ascii")
                            i = base64.b64decode(i)
                            print(i.hex())
                            attributes[key] = "0x"+i.hex()
                    elif attrType == LdapAttributeTypes.BytesArray or attrType == "BytesArray":
                        print("HERE -> 2")
                        strs = []
                        for b in attribute:
                            i = binascii.hexlify(b.encode('utf8'))
                            i = i.decode()
                            strs.append("0x"+ i)
                        attributes[key] = strs
                    elif attrType == LdapAttributeTypes.Guid or attrType == "Guid":
                        print("HERE -> 3")
                        print(key)
                        print(attribute)
                        if "encoded" in attribute:
                            print("HERE :")
                            # i = Rijndael().Decrypt(attribute["encoded"], request.crypto.passphrase, request.crypto.salt, request.crypto.iv)
                            i = attribute["encoded"].encode()
                            # print(i, ": 1")
                            i = base64.b64decode(i)
                            # # b'0qz\x02U\x9f&E\xb7\xf5\xd3\xf1?u\r\xe3'
                            if sys.byteorder == "little":
                                attributes[key] = str(uuid.UUID(bytes_le=i))
                            else:
                                attributes[key] = str(uuid.UUID(bytes=i))
                        else:
                            print(attribute)
                            attributes[key] = str(uuid.UUID(attribute))
                    elif attrType == LdapAttributeTypes.GuidArray or attrType == "GuidArray":
                        print("HERE -> 4")
                        guid_list = []
                        for i in attributes[key]:
                            i = uuid.UUID(str(attribute)).hex
                            guid_list.append(i)
                        attributes[key] = guid_list
                        print(attributes[key])
                    elif attrType == LdapAttributeTypes.Sid or attrType == "Sid":
                        print("HERE -> 5")
                        attributes[key] = SidUtils.New_Bytes_To_SID(SidUtils.New_String_to_Bytes(attribute))
                        print(attributes[key])
                    elif attrType == LdapAttributeTypes.SidArray or attrType == "SidArray":
                        print("HERE -> 6")
                        attributes[key] = list(SidUtils.New_Bytes_To_SID(SidUtils.New_String_to_Bytes(attribute)))
                        print(attributes[key])
                        
                    elif attrType == LdapAttributeTypes.String:
                        print("HERE -> 7")
                        attributes[key] = str(attribute)
                        
                    elif attrType == LdapAttributeTypes.StringArray:
                        print("HERE -> 8")
                        print(attribute)
                        attributes[key] = list(attribute)
                        print(attributes[key])
                        
                    elif attrType == LdapAttributeTypes.Number:
                        print("HERE -> 9")
                        print(key, " : ", attribute)
                        attributes[key] = attribute
                        print(attributes[key])
                        
                    elif attrType == LdapAttributeTypes.NumberArray:
                        print("HERE -> 10")
                        print(attribute)
                        attributes[key] = list(attribute)
                        print(attributes[key])
                        
                    elif attrType == LdapAttributeTypes.Boolean:
                        print("HERE -> 11")
                        attributes[key] = bool(attribute)
                        print(attributes[key])
                        
                    elif attrType == LdapAttributeTypes.BooleanArray:
                        print("HERE -> 12")
                        attributes[key] = list(attribute)
                        print(attributes[key])
                        
                    else:
                        print("HERE -> 13")
                        print(key, ': ', attribute)
                        # attributes[key] = str(attribute)
                        self.AddValueWithUnknownType(rec=attributes, key=key,attribute=attribute)
                # print("Appending")
                # response.records.append(rec)
                # response.records = JsonTools().Deserialize(response.records)
            except LDAPReferralError as e:
                print("------", e)
            except LDAPException as e:
                response.message = f"Page Size Limit Exceeded. Current Value is {self._MAXPAGESIZE}. Please increase"
        response.totalRecords = len(entries)
        return response
    
    def toJson(self, response: LdapResponse):
        if response.success == True:
            if response.nextToken != None:
                dictionary = {"success": response.success, "server": f"{response.server}:{self._PORT}", "searchBase": response.searchBase, "searchFilter": response.searchFilter, "NexToken": response.nextToken, "totalRecords": response.totalRecords, "records": response.records}
            else:    
                dictionary = {"success": response.success, "server": f"{response.server}:{self._PORT}", "searchBase": response.searchBase, "searchFilter": response.searchFilter, "totalRecords": response.totalRecords, "records": response.records}
        else:
            dictionary = {"success": response.success, "server": response.server, "message": str(response.message)}
        return dictionary
        

    def Search(self, request: LdapRequest, searchFilter: str, attributes = None, searchScope: SearchScopeType = None, maxResults: int = sys.maxsize, nextTokenStr:str = None):
        response = LdapResponse()
        entries = []
        # nextToken = bytearray(nextTokenStr)

        try:
            if searchFilter == None or searchFilter == '':
                print("HERE: A")
                raise Exception("Search Filter Not Provided")
            if not self.conn:
                print("HERE: B")
                response.message = f"Server {self} Is not connected"
                response.success = False
            if not self.conn.bound:
                print("HERE: C")
                response.message = f"Server {self} Is Not Bound."
                response.success = False
            # ldap_server = Server(self._SERVER, self._PORT, use_ssl=True, get_info=ALL)
            rootDSE = JsonTools().Deserialize(var=self.server.info.to_json())
            if request.searchBase == None:
                request.searchBase = rootDSE['raw']['defaultNamingContext'][0]
            
            results = None
            options = Options(0,maxResults,3600,self._FOLLOWREFERRALS)

            while True:
                # LOOK INTO THE MAX SEARCH VALUE ISSUE
                # print(attributes == None)
                maxPageSize = self._MAXPAGESIZE
                maxSearchResults = 999999
                # print(maxSearchResults, "<-----------")
                if maxResults != None:
                    print("HERE: 1")
                    maxSearchResults = maxResults
                if maxSearchResults - len(entries) < self._MAXPAGESIZE:
                    print("HERE 2")
                    maxPageSize = maxSearchResults-len(entries)
                if request.present == True and attributes == None:
                    print("HERE 3")
                    attributes = NO_ATTRIBUTES # or NO_ATTRIBUTES
                if request.present == False:
                    print("HERE 4")
                    attributes = ALL_ATTRIBUTES
                scope = SUBTREE
                if searchScope != None and scope != searchScope:
                    print("HERE 5")
                    scope = searchScope
                # print(request.searchBase, ",", searchFilter, ",", attributes, ",", scope, ",", options.TimeLimit, ",", maxSearchResults, ",", maxPageSize, ",", nextTokenStr)
                print("Starting Search")
                self.conn.search(request.searchBase, searchFilter, attributes=attributes, search_scope=scope, types_only=False, time_limit=options.ServerTimeLimit, size_limit=maxSearchResults, paged_size=maxPageSize, paged_cookie=nextTokenStr)
                print("Got out of search")
                # print(self.conn.response)
                # print(self.conn.response_to_ldif())
                # self.conn.response_to_json()
                # results = JsonTools().Deserialize(self.conn.response_to_ldif(self.conn.result))
                results = JsonTools().Deserialize(self.conn.response_to_json(self.conn.result, sort=True))
                # results = JsonTools().Deserialize(self.conn.entries)
                # print(results)
                try:
                    for i in results['entries']:
                        if i is not None:
                            del i['raw']
                            entries.append(i)
                except LDAPReferralError as e:
                    print(e) 
                
                nextTokenStr = self.conn.result['controls']['1.2.840.113556.1.4.319']['value']['cookie']

                if nextTokenStr == None or len(nextTokenStr) == 0:
                    break
                if maxSearchResults <= len(entries):
                    break
                print(len(entries), "/", maxResults )
            print("Out of While(True)")
            # print(maxSearchResults)
            response = self.ParseResults(entries, request)
            if nextTokenStr != None and len(nextTokenStr) > 0:
                #COMEBACK HERE LATER
                response.nextToken = f"{nextTokenStr}" # nextTokenStr
        except Exception as e:
            response.message = e
            response.success = False
        response.server = self._SERVER
        response.searchBase = request.searchBase
        response.searchFilter = searchFilter
        print(response.totalRecords)
        print(response.nextToken)
        print("--------------")
        time.sleep(5)
        response = self.toJson(response=response)
        return response
    
    def ReturnError(self, e: Exception, config: LdapConfig):
        response = LdapResponse
        response.success = False
        response.server = config.server_name
        response.message = f"{e}"

        response = self.toJson(response=response)

        return response

    def Print(self):
         print(f"Server:{self._SERVER}, port:{self._PORT}, ssl: {self._USESSL}, maxRetries: {self._MAXRETRIES}, maxpagesize: {self._MAXPAGESIZE}, followReferrals: {self._FOLLOWREFERRALS}, returnTypes: {self._RETURNTYPES}")

    