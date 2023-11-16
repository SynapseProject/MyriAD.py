import sys
import binascii
import base64
import copy
import threading
from multiprocessing import Process
import bonsai
from ldap3 import Server, Connection, ALL, ALL_ATTRIBUTES, SUBTREE, NO_ATTRIBUTES, ALL_OPERATIONAL_ATTRIBUTES, DEREF_ALWAYS
from ldap3.core.exceptions import LDAPSocketOpenError, LDAPReferralError, LDAPException
from Zephyr_Directory_Ldap_Python.Classes import LdapConfig, LdapRequest, LdapResponse, LdapAttributeTypes
from Zephyr_Directory_Ldap_Python.Classes.LdapRequest import SearchScopeType
from Zephyr_Directory_Ldap_Python.Classes.LdapResponse import StatusCode
from Zephyr_Directory_Ldap_Python.Utilites.JsonTools import JsonTools
from Zephyr_Directory_Ldap_Python.Utilites.SidUtils import SidUtils
from Zephyr_Directory_Ldap_Python.KnownAttributes import KnownAttributes
import time
import uuid

class Options:
    def __init__(self, timeLimit, maxResults, serverTimeLimit, referralfollowing):
        self.TimeLimit = timeLimit
        self.MaxResults = maxResults
        self.ServerTimeLimit = serverTimeLimit
        self.ReferralFollowing = referralfollowing

class LDapServer:
    _URL = None
    _SERVER = None
    _PORT = None
    _USESSL = None
    _MAXRETRIES = 0
    _MAXPAGESIZE = 512
    _FOLLOWREFERRALS = False
    _RETURNTYPES = {}
    _IGNOREWARNINGS = False
    _CONNECTED = False

    def __init__(self, server: str, port: int, useSSL:bool, maxRetries:int = None, maxPageSize:int = None, followReferrals: int = None, attributeReturnTypes:dict = None, ignoreWarnings:bool = None):
        self.conn = Connection
        self.server = Server
        self._URL = None
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
        if ignoreWarnings != None:
            self._IGNOREWARNINGS = ignoreWarnings

        self.conn.socket = self._USESSL
        print(self._SERVER)

    def ToString(self):
        if self._USESSL:
            return f"ldaps://{self._SERVER}:{self._PORT}"
        else:
            return f"ldap://{self._SERVER}:{self._PORT}"
        
    def Connect(self, config, request):
        flag = False
        print(f"{config.username}", ",", f"{config.password}")
        attempts = 0
        while attempts  <= self._MAXRETRIES and flag == False:
            try:
                self.server = Server(self._SERVER, self._PORT, use_ssl = self._USESSL, get_info=ALL)
                self.conn = Connection(server = self.server, user=config.username, password=config.password, auto_bind= True, return_empty_attributes=False, check_names=True)
                if self.conn:
                    print("Connected")
                    self._CONNECTED = True
                    flag = True
            except LDAPSocketOpenError as e:
                attempts += 1
    
    def Connect_bonsai(self, config, request):
        flag = False
        attempts = 0
        self._URL = f"ldap://{self._SERVER}:{self._PORT}"
        if self._USESSL:    
            self._URL = f"ldaps://{self._SERVER}:{self._PORT}"
        while attempts <= self._MAXRETRIES and flag == False:
            try:
                self.server = bonsai.LDAPClient(self._URL, self._USESSL)
                self.server.set_auto_page_acquire(False)
                print(self.server.auto_page_acquire)
                self.server.set_credentials("SIMPLE", user= config.username, password= config.password)
                self.conn = self.server.connect()
                if self.conn:
                    print("Connected")
                    self._CONNECTED = True
                    flag = True
            except LDAPSocketOpenError as e:
                attempts += 1

    def Disconnect(self):
        if self._CONNECTED:
            self.conn.unbind()
            print("Disconnected")
    
    def Disconnect_bonsai(self):
        if self._CONNECTED:
            self.conn.close()
            print("Disconnected")

    def Bind(self):
        self.conn.bind()

    def CheckAttributes(self, attributes, response: LdapResponse, config: LdapConfig):
        attributes_ = []
        error_attributes = []
        for attribute in attributes:
            if attribute in self.server.schema.attribute_types:
                attributes_.append(attribute)
            else:
                error_attributes.append(attribute)
        if len(error_attributes) > 0 and config.IgnoreWarnings == False:
            response.status = StatusCode.SuccessWithWarnings.name
            response.message["LDAPInvalidAttributeType"] = f"Invalid Attribute(s): {', '.join(error_attributes)}"
        return attributes_, response
    
    def CheckAttributes2(self, attributes, keylist, response: LdapResponse, config: LdapConfig, present:bool):
        attributes_ = []
        error_attributes = []
        if attributes == None and present == False:
            attributes = keylist
        if attributes == None and present == True:
            attributes = []
        for attribute in attributes:
            if attribute in keylist and attribute != "dn":
                attributes_.append(attribute)
            else:
                error_attributes.append(attribute)
        if len(error_attributes) > 0 and config.IgnoreWarnings == False:
            response.status = StatusCode.SuccessWithWarnings.name
            response.message["LDAPInvalidAttributeType"] = f"Invalid Attribute(s): {', '.join(error_attributes)}"
        return attributes_, response

    def AddValueWithUnknownType(self, rec, key, attribute):
        print(type(attribute))
        if type(attribute) == list or type(attribute) == bonsai.ldapvaluelist.LDAPValueList:
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

    def ParseResults(self, entries, response: LdapResponse):
        print("-------------")
        response.records = entries

        for record in response.records:
            try:
                attributes = record['attributes']
                for key in attributes.keys():
                    attribute = attributes[key]
                    attrType = LdapAttributeTypes.Unknown
                    if key in self._RETURNTYPES.keys():
                        attrType = self._RETURNTYPES[key]
                        print(attrType)
                    elif key in KnownAttributes().DefaultTypes.keys():
                        attrType = KnownAttributes().DefaultTypes[key]
                        print(attrType)
                    if attrType == LdapAttributeTypes.Bytes or attrType == "Bytes":
                        print("HERE -> 1")
                        print(key, ": ", attribute)
                        try:
                            if "encoded" in attribute:
                                print("HELLO")
                                i = attribute["encoded"].encode()
                                i = base64.b64decode(i)
                                print(i.hex())
                                attributes[key] = "0x"+i.hex()
                            else:
                                i = binascii.hexlify(attribute[0].encode('utf8'))
                                i = i.decode()
                                attributes[key] = "0x"+i
                        except:
                            print(attribute[0].hex())
                            attributes[key] = "0x"+attribute.hex()
                    elif attrType == LdapAttributeTypes.BytesArray or attrType == "BytesArray":
                        print("HERE -> 2")
                        print(type(attribute))
                        strs = []
                        for b in attribute:
                            print(type(b))
                            if 'encoded' in b:
                                try:
                                    i = b['encoded'].encode()
                                    i = base64.b64decode(i)
                                    strs.append('0x'+i.hex())
                                except:
                                    i = attribute["encoded"].encode()
                                    i = base64.b64decode(i)
                                    strs.append('0x'+i.hex())
                            else:
                                i = binascii.hexlify(b.encode('utf8'))
                                i = i.decode()
                                strs.append("0x"+ i)
                        attributes[key] = strs
                    elif attrType == LdapAttributeTypes.Guid or attrType == "Guid":
                        print("HERE -> 3")
                        print(key)
                        print(attribute)
                        print(type(attribute))
                        try:
                            if "encoded" in attribute:
                                print("HERE :")
                                i = attribute["encoded"].encode()
                                i = base64.b64decode(i)
                                if sys.byteorder == "little":
                                    attributes[key] = str(uuid.UUID(bytes_le=i))
                                else:
                                    attributes[key] = str(uuid.UUID(bytes=i))
                            else:
                                print(attribute)
                                attributes[key] = str(uuid.UUID(attribute))
                        except:
                            if sys.byteorder == "little":
                                attributes[key] = str(uuid.UUID(bytes_le=attribute))
                                print(attributes[key])
                            else:
                                attributes[key] = str(uuid.UUID(bytes=attribute))
                    elif attrType == LdapAttributeTypes.GuidArray or attrType == "GuidArray":
                        print("HERE -> 4")
                        guid_list = []
                        if type(attribute) == str:
                            guid_list.append(str(uuid.UUID(attribute)))
                        else:
                            for i in attribute:
                                if type(i) == dict:
                                    for j in i:
                                        print(i[j])
                                        if "encoded" in i[j]:
                                            print("HERE")
                                            x = i[j]["encoded"].encode()
                                            x = base64.b64decode(x)
                                            if sys.byteorder == "little":
                                                guid_list.append(str(uuid.UUID(bytes_le=x)))
                                            else:
                                                guid_list.append(str(uuid.UUID(bytes=x)))
                                else:
                                    print(i)
                                    guid_list.append(str(uuid.UUID(i)))
                        attributes[key] = guid_list
                        print(attributes[key])
                    elif attrType == LdapAttributeTypes.Sid or attrType == "Sid":
                        print("HERE -> 5")
                        if type(attribute) == bytes:
                            attributes[key] = SidUtils.New_Bytes_To_SID(attribute)
                        else:
                            try:
                                x = uuid.UUID(attribute)
                                attributes[key] = SidUtils.New_Bytes_To_SID(x.bytes_le) if sys.byteorder == "little" else SidUtils.New_Bytes_To_SID(x.bytes)
                            except:
                                attributes[key] = SidUtils.New_Bytes_To_SID(SidUtils.New_String_to_Bytes(attribute))
                        print(attributes[key])
                    elif attrType == LdapAttributeTypes.SidArray or attrType == "SidArray":
                        print("HERE -> 6")
                        if type(attribute) == bytes:
                            attributes[key] = list(SidUtils.New_Bytes_To_SID(attribute))
                        else:  
                            attributes[key] = [SidUtils.New_Bytes_To_SID(SidUtils.New_String_to_Bytes(attribute))]
                        print(attributes[key])
                        
                    elif attrType == LdapAttributeTypes.String or attrType == "String":
                        if type(attribute) == list:
                            attributes[key] = str(attribute[0])
                        else:
                            attributes[key] = str(attribute)
                        
                    elif attrType == LdapAttributeTypes.StringArray or attrType == "StringArray":
                        print("HERE -> 8")
                        print(key, " : ", attribute)
                        print(type(attribute))
                        if type(attribute) == list or type(attribute) == bonsai.ldapvaluelist.LDAPValueList:
                            attributes[key] = attribute
                        else:
                            stringarray = []
                            stringarray.append(attribute)
                            attributes[key] = stringarray
                        print(attributes[key])
                        
                    elif attrType == LdapAttributeTypes.Number or attrType == "Number":
                        print("HERE -> 9")
                        print(key, " : ", attribute)
                        try:
                            attributes[key] = int(attribute)
                        except:
                            attributes[key] = attribute
                        print(attributes[key])
                        
                    elif attrType == LdapAttributeTypes.NumberArray or attrType == "NumberArray":
                        print("HERE -> 10")
                        print(attribute)
                        attributes[key] = [int(attribute)]
                        print(attributes[key])
                        
                    elif attrType == LdapAttributeTypes.Boolean or attrType == "Boolean":
                        print("HERE -> 11")
                        attributes[key] = bool(attribute)
                        print(attributes[key])
                        
                    elif attrType == LdapAttributeTypes.BooleanArray or attrType == "BooleanArray":
                        print("HERE -> 12")
                        attributes[key] = [attribute]
                        print(attributes[key])
                        
                    else:
                        print("HERE -> 13")
                        print(key, ': ', attribute)
                        self.AddValueWithUnknownType(rec=attributes, key=key,attribute=attribute)
            except LDAPReferralError as e:
                print("------", e)
            except LDAPException as e:
                response.message[e.__class__.__name__] = f"Page Size Limit Exceeded. Current Value is {self._MAXPAGESIZE}. Please increase"
        response.totalRecords = len(entries)
        return response
    
    def format_Message(self, messages: dict):
        formatted_message = f'Found {len(messages)} Errors: '
        for message in messages.keys():
            print(message, messages[message])
            formatted_message = formatted_message + f"{message}: {messages[message]}. "
        return formatted_message.strip()
            
    def test_func(self, results, index, searchFilter, attributes,scope, ServerTimeLimit, maxSearchResults, maxPageSize, nextTokenStr):
        self.conn.search("DC=bp1,DC=ad,DC=bp,DC=com", searchFilter, attributes=attributes, search_scope=scope, types_only=False, time_limit=ServerTimeLimit, size_limit=maxSearchResults, paged_size=maxPageSize, paged_cookie=nextTokenStr)
        results[index] = JsonTools().Deserialize(self.conn.response_to_json(self.conn.result, sort=True))

    def toJson(self, response: LdapResponse, request:LdapRequest):
        print(request.config.IgnoreWarnings)
        if response.success == True and request.config.IgnoreWarnings == True or len(response.message) == 0:
            print("HERE a")
            if response.nextToken != None:
                dictionary = {"statusCode": 200, "success": response.success, "server": self.ToString(), "searchBase": response.searchBase, "searchFilter": response.searchFilter, "nextToken": response.nextToken, "status": response.status, "totalRecords": response.totalRecords, "records": response.records}
            else:    
                dictionary = {"statusCode": 200, "success": response.success, "server": self.ToString(), "searchBase": response.searchBase, "searchFilter": response.searchFilter, "status": response.status, "totalRecords": response.totalRecords, "records": response.records}
        elif response.success == True and request.config.IgnoreWarnings == False:
            if response.nextToken != None:
                dictionary = {"statusCode": 200, "success": response.success, "server": self.ToString(), "searchBase": response.searchBase, "searchFilter": response.searchFilter, "status": response.status, "message": self.format_Message(response.message), "nextToken": response.nextToken, "totalRecords": response.totalRecords, "records": response.records}
            else:    
                dictionary = {"statusCode": 200, "success": response.success, "server": self.ToString(), "searchBase": response.searchBase, "searchFilter": response.searchFilter, "status": response.status, "message": self.format_Message(response.message), "totalRecords": response.totalRecords, "records": response.records}
        else:
            print("Here b")
            dictionary = {"statusCode": 200, "success": response.success, "server": response.server, "status": response.status, "message": self.format_Message(response.message)}
        return dictionary
        

    def Search(self, request: LdapRequest, searchFilter: str, attributes = None, searchScope: SearchScopeType = None, maxResults: int = sys.maxsize, nextTokenStr = None):
        response = LdapResponse()
        entries = []
        print(len(entries))
        if nextTokenStr != None:
            nextTokenStr = nextTokenStr.encode()
            nextTokenStr = base64.b64decode(nextTokenStr)
        print(nextTokenStr)

        try:
            if searchFilter == None or searchFilter == '':
                print("HERE: A")
                raise Exception("Search Filter Not Provided")
            if not self.conn or not self._CONNECTED:
                print("HERE: B")
                raise LDAPSocketOpenError(f"Server '{self._SERVER}' Is not connected")
            if not self.conn.bound:
                print("HERE: C")
                raise LDAPException(f"Server '{self._SERVER}' is Not Bound")
            request.config.IgnoreWarnings = SidUtils().Convert_Str_to_Bool(ignoreWarnings=request.config.IgnoreWarnings)
            rootDSE = JsonTools().Deserialize(var=self.server.info.to_json())
            if request.searchBase == None:
                request.searchBase = rootDSE['raw']['defaultNamingContext'][0]
            response.status = StatusCode.Success.name
            if attributes != None:
                attributes,response = self.CheckAttributes(attributes, response, request.config)
            results = None
            options = Options(0,maxResults,3600,self._FOLLOWREFERRALS)
            print("Attributes :" , attributes)
            while True:
                maxPageSize = self._MAXPAGESIZE
                maxSearchResults = 999999
                if maxResults != None:
                    print("HERE: 1")
                    maxSearchResults = maxResults
                if maxSearchResults - len(entries) < self._MAXPAGESIZE:
                    print("HERE 2")
                    maxPageSize = maxSearchResults-len(entries)
                if request.present == True and attributes == None:
                    print("HERE 3")
                    attributes = NO_ATTRIBUTES
                if request.present == False:
                    print("HERE 4")
                    attributes = ALL_ATTRIBUTES
                scope = SUBTREE
                if searchScope != None and scope != searchScope:
                    print("HERE 5")
                    print(scope, searchScope.value)
                    scope = searchScope.value
                print("Starting Search")
                ###############################
                results = [None] *10
                start_time = time.time()
                t1 = threading.Thread(target=self.test_func, args=(results, 0, searchFilter, attributes, scope, options.ServerTimeLimit, maxSearchResults, maxPageSize, nextTokenStr))
                t2 = threading.Thread(target=self.test_func, args=(results, 1, '(sAMAccountName=0195tw)', attributes, scope, options.ServerTimeLimit, maxSearchResults, maxPageSize, nextTokenStr))
                t1.start()
                t2.start()
                t1.join()
                t2.join()
                end_time = time.time()
                elapsed_time = end_time - start_time
                ################################
                self.conn.search(request.searchBase, searchFilter, attributes=attributes, search_scope=scope, types_only=False, time_limit=options.ServerTimeLimit, size_limit=maxSearchResults, paged_size=maxPageSize, paged_cookie=nextTokenStr)
                print("Got out of search")
                results = JsonTools().Deserialize(self.conn.response_to_json(self.conn.result, sort=True))
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
            response = self.ParseResults(entries, response)
            if nextTokenStr != None and len(nextTokenStr) > 0:
                nextTokenStr = base64.b64encode(nextTokenStr).decode()
                response.nextToken = nextTokenStr
        except Exception as e:
            response.message[e.__class__.__name__] = f"{e}"
            response.success = False
            response.status = StatusCode.Failure.name
        response.server = self._SERVER
        response.searchBase = request.searchBase
        response.searchFilter = searchFilter
        print(response.totalRecords)
        print(response.nextToken)
        print("--------------")
        response = self.toJson(response=response, request=request)
        return response
    
    def Search2(self, request: LdapRequest, searchFilter: str, attributes = None, searchScope: SearchScopeType = None, maxResults: int = sys.maxsize, nextTokenStr = None):
        response = LdapResponse()
        entries = []
        print(len(entries))
        if nextTokenStr != None:
            nextTokenStr = nextTokenStr
        print(nextTokenStr)

        try:
            if searchFilter == None or searchFilter == '':
                print("HERE: A")
                raise Exception("Search Filter Not Provided")
            if not self.conn or not self._CONNECTED:
                print("HERE: B")
                raise LDAPSocketOpenError(f"Server '{self._SERVER}' Is not connected")
            # if not self.conn.bound:
            request.config.IgnoreWarnings = SidUtils().Convert_Str_to_Bool(ignoreWarnings=request.config.IgnoreWarnings)
            rootDSE = self.server.get_rootDSE()['namingContexts'][2]
            if request.searchBase == None:
                request.searchBase =rootDSE
            response.status = StatusCode.Success.name
            results = None
            options = Options(0,maxResults,3600,self._FOLLOWREFERRALS)
            print("Attributes :" , attributes)
            while True:
                maxPageSize = self._MAXPAGESIZE
                maxSearchResults = 999999
                if maxResults != None:
                    print("HERE: 1")
                    maxSearchResults = maxResults
                if maxSearchResults - len(entries) < self._MAXPAGESIZE:
                    print("HERE 2")
                    maxPageSize = maxSearchResults-len(entries)
                scope = SUBTREE
                if searchScope != None and scope != searchScope:
                    print("HERE 5")
                    print(scope, searchScope.value)
                    scope = searchScope.value
                print("Starting Search")
                if request.maxResults == None:
                    results = self.conn.search(base=request.searchBase, scope=bonsai.LDAPSearchScope.SUBTREE, filter_exp=searchFilter, attrlist=request.attributes, timeout= options.ServerTimeLimit, sizelimit=maxSearchResults)
                    entry_list = []
                    for i in results:
                        entry_list.append(i)
                    key_list = list(entry_list[0].keys()) if entry_list else []
                    attributes,response = self.CheckAttributes2(attributes, key_list, response, request.config, request.present)
                    for z in entry_list:
                        entry = {}
                        entry["dn"] = str(z["dn"])
                        attributez = {}
                        for j in attributes:
                            try:
                                if len(i[j]) > 1:
                                    attributez[j] = i[j]
                                else:
                                    attributez[j] = i[j][0]
                            except:
                                pass
                        entry["attributes"] = attributez
                        entries.append(entry)
                else:
                    if nextTokenStr == None:
                        results = self.conn.paged_search(base=request.searchBase, scope=bonsai.LDAPSearchScope.SUBTREE, filter_exp=searchFilter, attrlist=request.attributes, timeout= options.ServerTimeLimit, sizelimit=maxSearchResults, page_size=request.maxResults)
                        entry_list = []
                        for i in results:
                            entry_list.append(i)
                        key_list = list(entry_list[0].keys()) if entry_list else []
                        attributes,response = self.CheckAttributes2(attributes, key_list, response, request.config, request.present)
                        for i in entry_list:
                            print(i)
                            entry = {}
                            entry["dn"] = str(i["dn"])
                            attributez = {}
                            for j in attributes:
                                try:
                                    if len(i[j]) > 1:
                                        attributez[j] = i[j]
                                    else:
                                        attributez[j] = i[j][0]
                                except:
                                    pass
                            entry["attributes"] = attributez
                            entries.append(entry)
                    else:
                        results = self.conn.paged_search(base=request.searchBase, scope=bonsai.LDAPSearchScope.SUBTREE, filter_exp=searchFilter, attrlist=request.attributes, timeout= options.ServerTimeLimit, sizelimit=maxSearchResults, page_size=request.maxResults)
                        difference = nextTokenStr - results.acquire_next_page()
                        i = 0
                        while i < difference-1:
                            x = results.acquire_next_page()
                            self.conn._evaluate(x)
                            i += 1
                        results.acquire_next_page()
                        results = self.conn._evaluate(nextTokenStr)
                        entry_list = []
                        for i in results:
                            entry_list.append(i)
                        key_list = list(entry_list[0].keys()) if entry_list else []
                        attributes,response = self.CheckAttributes2(attributes, key_list, response, request.config, request.present)
                        for i in entry_list:
                            print(i)
                            entry = {}
                            entry["dn"] = str(i["dn"])
                            attributez = {}
                            for j in attributes:
                                try:
                                    if len(i[j]) > 1:
                                        attributez[j] = i[j]
                                    else:
                                        attributez[j] = i[j][0]
                                except:
                                    pass
                            entry["attributes"] = attributez
                            entries.append(entry)
                print(entries)
                try:
                    nextTokenStr  = results.acquire_next_page()
                except:
                    nextTokenStr = None
                if nextTokenStr == None:
                    break
                if maxSearchResults <= len(entries):
                    break
                print(len(entries), "/", maxResults )
            print("Out of While(True)")
            response = self.ParseResults(entries, response)
            if nextTokenStr != None:
                response.nextToken = nextTokenStr
        except Exception as e:
            response.message[e.__class__.__name__] = f"{e}"
            response.success = False
            response.status = StatusCode.Failure.name
        response.server = self._SERVER
        response.searchBase = request.searchBase
        response.searchFilter = searchFilter
        print(response.totalRecords)
        print(response.nextToken)
        print("--------------")
        response = self.toJson(response=response, request=request)
        return response
    
    def ReturnError(self, e: Exception, config: LdapConfig, request: LdapRequest):
        response = LdapResponse()
        response.success = False
        response.status = StatusCode.Failure.name
        response.server = config.server_name
        response.message[e.__class__.__name__] = f"{e}"
        response = self.toJson(response=response, request=request)

        return response

    def Print(self):
         print(f"Server:{self._SERVER}, port:{self._PORT}, ssl: {self._USESSL}, maxRetries: {self._MAXRETRIES}, maxpagesize: {self._MAXPAGESIZE}, followReferrals: {self._FOLLOWREFERRALS}, returnTypes: {self._RETURNTYPES}")