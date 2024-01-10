from sys import maxsize, byteorder
from binascii import hexlify
from base64 import b64decode, b64encode
from threading import Thread
from collections import deque
from ldap3 import Server, Connection, ALL, ALL_ATTRIBUTES, SUBTREE, NO_ATTRIBUTES, ALL_OPERATIONAL_ATTRIBUTES
from ldap3.core.exceptions import LDAPSocketOpenError, LDAPReferralError, LDAPException
from Zephyr_Directory_Ldap_Python.Classes import LdapConfig, LdapRequest, LdapResponse, LdapAttributeTypes
from Zephyr_Directory_Ldap_Python.Classes.LdapRequest import SearchScopeType2
from Zephyr_Directory_Ldap_Python.Classes.LdapResponse import StatusCode
from Zephyr_Directory_Ldap_Python.Utilities.JsonTools import JsonTools
from Zephyr_Directory_Ldap_Python.Utilities.SidUtils import SidUtils
from Zephyr_Directory_Ldap_Python.Utilities.LdapUtils import LdapUtils
from Zephyr_Directory_Ldap_Python.KnownAttributes import KnownAttributes
from uuid import UUID
import bonsai

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
    _CONNECTED = False

    def __init__(self, server: str, port: int, useSSL:bool, maxRetries:int = None, maxPageSize:int = None, followReferrals: int = None, attributeReturnTypes:dict = None, ignoreWarnings:bool = None):
        self.conn = Connection
        self.server = Server
        self._URL = None
        self._SERVER = server
        self._PORT = port
        self._USESSL = useSSL
        self._RETURNTYPES = attributeReturnTypes
        self._IGNOREWARNINGS = False

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

    def ToString(self):
        if self._USESSL:
            return f"ldaps://{self._SERVER}:{self._PORT}"
        else:
            return f"ldap://{self._SERVER}:{self._PORT}"
        
    # def Bind(self, config:LdapConfig):
    #     self.conn.bind(self.srv)
        
    # def Connect(self, config, request):
    #     flag = False
    #     attempts = 0
    #     while attempts  <= self._MAXRETRIES and flag == False:
    #         try:
    #             self.server = Server(self._SERVER, self._PORT, use_ssl=self._USESSL, get_info=ALL)
    #             self.conn = Connection(server = self.server, user=config.username, password=config.password, auto_bind= True, return_empty_attributes=False, check_names=True)
    #             if self.conn:
    #                 flag = True
    #                 self._CONNECTED = True
    #         except LDAPSocketOpenError as e:
    #             attempts += 1
    
    def Connect_bonsai(self, config, request):
        flag = False
        attempts = 0
        self._URL = self.ToString()
        while attempts <= self._MAXRETRIES and flag == False:
            try:
                self.server = bonsai.LDAPClient(self._URL, self._USESSL)
                self.server.ca_cert = '/opt/BP Root CA 19.crt'
                self.server.set_auto_page_acquire(False)
                self.server.set_credentials("SIMPLE", user= config.username, password= config.password)
                self.conn = self.server.connect()
                if self.conn:
                    self._CONNECTED = True
                    flag = True
            except LDAPSocketOpenError as e:
                attempts += 1

    # def Disconnect(self):
    #     if self._CONNECTED:
    #         self.conn.unbind()

    def Disconnect_bonsai(self):
        if self._CONNECTED:
            self.conn.close()

    # def Bind(self):
    #     self.conn.bind()

    # def CheckAttributes(self, attributes, response: LdapResponse, config: LdapConfig):
    #     attributes_ = []
    #     error_attributes = []
    #     for attribute in attributes:
    #         if attribute in self.server.schema.attribute_types:
    #             attributes_.append(attribute)
    #         else:
    #             error_attributes.append(attribute)
    #     if len(error_attributes) > 0 and config.IgnoreWarnings == False:
    #         response.status = StatusCode.SuccessWithWarnings.name
    #         response.message["LDAPInvalidAttributeType"] = f"Invalid Attribute(s): {', '.join(error_attributes)}"
    #     return attributes_, response
    
    def CheckAttributes2(self, attributes, keylist, response: LdapResponse, config: LdapConfig, present:bool):
        attributes_ = deque()
        error_attributes = deque()
        # attributes = deque(keylist) if attributes == None and present == False else deque()
        if attributes == None and present == False:
            attributes = deque(keylist)
        if attributes == None and present == True:
            attributes = deque()
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
        values = attribute if type(attribute) == list or type(attribute) == bonsai.ldapvaluelist.LDAPValueList else [str(attribute)]
        rec[key] = values if len(values) > 1 else str(values[0])
        # if type(attribute) == list or type(attribute) == bonsai.ldapvaluelist.LDAPValueList:
        #     values = attribute
        # else:
        #     values = [str(attribute)]
        # if len(values) > 1:
        #     rec[key] = values
        # else:
        #     rec[key] = str(values[0])

    def ParseResults(self, entries, response: LdapResponse):
        response.records = entries

        for record in response.records:
            try:
                attributes = record['attributes']
                for key in attributes.keys():
                    attribute = attributes[key]
                    attrType = LdapAttributeTypes.Unknown
                    if key in self._RETURNTYPES.keys():
                        attrType = self._RETURNTYPES[key]
                    elif key in KnownAttributes().DefaultTypes.keys():
                        attrType = KnownAttributes().DefaultTypes[key]
                    if attrType == LdapAttributeTypes.Bytes or attrType == "Bytes":
                        try:
                            if "encoded" in attribute:
                                i = attribute["encoded"].encode()
                                i = b64decode(i)
                                attributes[key] = "0x"+i.hex()
                            else:
                                i = hexlify(attribute[0].encode('utf8'))
                                i = i.decode()
                                attributes[key] = "0x"+i
                        except:
                            attributes[key] = "0x"+attribute.hex()
                    elif attrType == LdapAttributeTypes.BytesArray or attrType == "BytesArray":
                        strs = deque()
                        try:
                            for b in attribute:
                                if 'encoded' in b:
                                    i = b['encoded'].encode()
                                    i = b64decode(i)
                                    strs.append('0x'+i.hex())
                                else:
                                    i = hexlify(b.encode('utf8'))
                                    i = i.decode()
                                    strs.append("0x"+ i)
                        except:
                            strs.append("0x"+attribute.hex())
                        attributes[key] = list(strs)
                    elif attrType == LdapAttributeTypes.Guid or attrType == "Guid":
                        try:
                            attributes[key] = str(UUID(bytes_le=b64decode(attribute["encoded"].encode()))) if byteorder == "little" else str(UUID(bytes=b64decode(attribute["encoded"].encode()))) if "encoded" in attribute else str(UUID(attribute))
                            # if "encoded" in attribute:
                            #     i = attribute["encoded"].encode()
                            #     i = b64decode(i)
                            #     attributes[key] = str(UUID(bytes_le=i)) if byteorder == "little" else str(UUID(bytes=i))
                            #     # if byteorder == "little":
                            #     #     attributes[key] = str(UUID(bytes_le=i))
                            #     # else:
                            #     #     attributes[key] = str(UUID(bytes=i))
                            # else:
                            #     attributes[key] = str(UUID(attribute))
                        except:
                            attributes[key] = str(UUID(bytes_le=attribute)) if byteorder == "little" else str(UUID(bytes=attribute)) 
                            # if byteorder == "little":
                            #     attributes[key] = str(UUID(bytes_le=attribute))
                            # else:
                            #     attributes[key] = str(UUID(bytes=attribute))                          
                    elif attrType == LdapAttributeTypes.GuidArray or attrType == "GuidArray":
                        guid_list = deque()
                        if type(attribute) == str:
                            guid_list.append(str(UUID(attribute)))
                        else:
                            try:
                                for i in attribute:
                                    if type(i) == dict:
                                        for j in i:
                                            if "encoded" in i[j]:
                                                x = i[j]["encoded"].encode()
                                                x = b64decode(x)
                                                # guid_list.append(str(UUID(bytes_le=x)) if byteorder == "little" else str(UUID(bytes=x)))
                                                if byteorder == "little":
                                                    guid_list.append(str(UUID(bytes_le=x)))
                                                else:
                                                    guid_list.append(str(UUID(bytes=x)))
                                    else:
                                        guid_list.append(str(UUID(i)))
                            except:
                                guid_list.append(str(UUID(bytes_le=attribute)))
                        attributes[key] = list(guid_list)
                    elif attrType == LdapAttributeTypes.Sid or attrType == "Sid":
                        if type(attribute) == bytes:
                            attributes[key] = SidUtils.New_Bytes_To_SID(attribute)
                        else:
                            try:
                                x = UUID(attribute)
                                attributes[key] = SidUtils.New_Bytes_To_SID(x.bytes_le) if byteorder == "little" else SidUtils.New_Bytes_To_SID(x.bytes)
                            except:
                                attributes[key] = SidUtils.New_Bytes_To_SID(SidUtils.New_String_to_Bytes(attribute))
                    elif attrType == LdapAttributeTypes.SidArray or attrType == "SidArray":
                        attributes[key] = [SidUtils.New_Bytes_To_SID(attribute)] if type(attribute) == bytes else [SidUtils.New_Bytes_To_SID(SidUtils.New_String_to_Bytes(attribute))]
                        # if type(attribute) == bytes:
                        #     attributes[key] = [SidUtils.New_Bytes_To_SID(attribute)]
                        # else:  
                        #     attributes[key] = [SidUtils.New_Bytes_To_SID(SidUtils.New_String_to_Bytes(attribute))]
                    elif attrType == LdapAttributeTypes.String or attrType == "String":
                        attributes[key] = str(attribute[0]) if type(attribute) == list or type(attribute) == bonsai.ldapvaluelist.LDAPValueList else str(attribute)
                        # if type(attribute) == list or type(attribute) == bonsai.ldapvaluelist.LDAPValueList:
                        #     attributes[key] = str(attribute[0])
                        # else:
                        #     attributes[key] = str(attribute)
                    elif attrType == LdapAttributeTypes.StringArray or attrType == "StringArray":
                        attributes[key] = attribute if type(attribute) == list or type(attribute) == bonsai.ldapvaluelist.LDAPValueList else [attribute]
                        # if type(attribute) == list or type(attribute) == bonsai.ldapvaluelist.LDAPValueList:
                        #     attributes[key] = attribute
                        # else:
                        #     stringarray = []
                        #     stringarray.append(attribute)
                        #     attributes[key] = stringarray
                    elif attrType == LdapAttributeTypes.Number or attrType == "Number":
                        try:
                            attributes[key] = int(attribute)
                        except:
                            attributes[key] = attribute
                    elif attrType == LdapAttributeTypes.NumberArray or attrType == "NumberArray":
                        attributes[key] = [int(attribute)]
                    elif attrType == LdapAttributeTypes.Boolean or attrType == "Boolean":
                        attributes[key] = bool(attribute)
                    elif attrType == LdapAttributeTypes.BooleanArray or attrType == "BooleanArray":
                        attributes[key] = [attribute]
                    else:
                        # attributes[key] = str(attribute)
                        self.AddValueWithUnknownType(rec=attributes, key=key,attribute=attribute)
            except LDAPReferralError as e:
                print("------", e)
            except LDAPException as e:
                response.message[e.__class__.__name__] = f"Page Size Limit Exceeded. Current Value is {self._MAXPAGESIZE}. Please increase"
        response.totalRecords = len(entries)
        response.records = list(response.records)
        return response
    
    def format_Message(self, messages: dict):
        formatted_message = f'Found {len(messages)} Errors: '
        for message in messages.keys():
            formatted_message = formatted_message + f"{message}: {messages[message]}. "
        return formatted_message.strip()
            

    def toJson(self, response: LdapResponse, request:LdapRequest, returning_error:bool = False):
        # dictionary = {"success": response.success, "server": f"{response.server}:{self._PORT}", "searchBase": response.searchBase, "searchFilter": response.searchFilter, "message": str(response.message), "NexToken": response.nextToken, "totalRecords": response.totalRecords, "records": response.records}
        if response.searchBases != None and response.searchFilters != None and not returning_error:
            if request.config.IgnoreWarnings == True or len(response.message) == 0:
                if response.nextToken != None:
                    dictionary = {"statusCode": 200, "success": response.success, "server": self.ToString(), "searchBases": response.searchBases, "searchFilters": response.searchFilters, "nextToken": response.nextToken, "status": response.status, "totalRecords": response.totalRecords, "records": response.records}
                else:    
                    dictionary = {"statusCode": 200, "success": response.success, "server": self.ToString(), "searchBases": response.searchBases, "searchFilters": response.searchFilters, "status": response.status, "totalRecords": response.totalRecords, "records": response.records}
            elif request.config.IgnoreWarnings == False:
                if response.nextToken != None:
                    dictionary = {"statusCode": 200, "success": response.success, "server": self.ToString(), "searchBases": response.searchBases, "searchFilters": response.searchFilters, "status": response.status, "message": self.format_Message(response.message), "nextToken": response.nextToken, "totalRecords": response.totalRecords, "records": response.records}
                else:    
                    dictionary = {"statusCode": 200, "success": response.success, "server": self.ToString(), "searchBases": response.searchBases, "searchFilters": response.searchFilters, "status": response.status, "message": self.format_Message(response.message), "totalRecords": response.totalRecords, "records": response.records}
        elif response.searchBases == None and response.searchFilters == None and not returning_error:
            if request.config.IgnoreWarnings == True or len(response.message) == 0:
                if response.nextToken != None:
                    dictionary = {"statusCode": 200, "success": response.success, "server": self.ToString(), "searchBase": response.searchBase, "searchFilter": response.searchFilter, "nextToken": response.nextToken, "status": response.status, "totalRecords": response.totalRecords, "records": response.records}
                else:    
                    dictionary = {"statusCode": 200, "success": response.success, "server": self.ToString(), "searchBase": response.searchBase, "searchFilter": response.searchFilter, "status": response.status, "totalRecords": response.totalRecords, "records": response.records}
            elif request.config.IgnoreWarnings == False:
                if response.nextToken != None:
                    dictionary = {"statusCode": 200, "success": response.success, "server": self.ToString(), "searchBase": response.searchBase, "searchFilter": response.searchFilter, "status": response.status, "message": self.format_Message(response.message), "nextToken": response.nextToken, "totalRecords": response.totalRecords, "records": response.records}
                else:    
                    dictionary = {"statusCode": 200, "success": response.success, "server": self.ToString(), "searchBase": response.searchBase, "searchFilter": response.searchFilter, "status": response.status, "message": self.format_Message(response.message), "totalRecords": response.totalRecords, "records": response.records}
        else:
            dictionary = {"statusCode": 200, "success": response.success, "server": response.server, "status": response.status, "message": self.format_Message(response.message)}

        return dictionary
        

    # def Search(self, request: LdapRequest, searchFilter: str, attributes = None, searchScope: SearchScopeType = None, maxResults: int = maxsize, nextTokenStr:str = None):
    #     response = LdapResponse()
    #     entries = []
    #     if nextTokenStr != None:
    #         nextTokenStr = nextTokenStr.encode()
    #         nextTokenStr = b64decode(nextTokenStr)
    #     # nextToken = nextTokenStr.fromhex()

    #     try:
    #         if searchFilter == None or searchFilter == '':
    #             raise Exception("Search Filter Not Provided")
    #         if not self.conn or not self._CONNECTED:
    #             raise LDAPSocketOpenError(f"Server '{self._SERVER}' Is not connected")
    #         if not self.conn.bound:
    #             raise LDAPException(f"Server '{self._SERVER}' is Not Bound")
    #         request.config.IgnoreWarnings = SidUtils().Convert_Str_to_Bool(ignoreWarnings=request.config.IgnoreWarnings)
    #         rootDSE = JsonTools().Deserialize(var=self.server.info.to_json())
    #         request.searchBase = rootDSE['raw']['defaultNamingContext'][0] if request.searchBase == None else request.searchBase
    #         # if request.searchBase == None:
    #         #     request.searchBase = rootDSE['raw']['defaultNamingContext'][0]
    #         response.status = StatusCode.Success.name
    #         if attributes != None:
    #             attributes,response = self.CheckAttributes(attributes, response, request.config)
    #         results = None
    #         options = Options(0,maxResults,3600,self._FOLLOWREFERRALS)
    #         while True:
    #             maxPageSize = self._MAXPAGESIZE
    #             maxSearchResults = 999999
    #             if maxResults != None:
    #                 maxSearchResults = maxResults
    #             if maxSearchResults - len(entries) < self._MAXPAGESIZE:
    #                 maxPageSize = maxSearchResults-len(entries)
    #             if request.present == True and attributes == None:
    #                 attributes = NO_ATTRIBUTES
    #             if request.present == False:
    #                 attributes = ALL_ATTRIBUTES
    #             scope = SUBTREE
    #             if searchScope != None and scope != searchScope:
    #                 scope = searchScope.value
    #             self.conn.search(request.searchBase, searchFilter, attributes=attributes, search_scope=scope, types_only=False, time_limit=options.ServerTimeLimit, size_limit=maxSearchResults, paged_size=maxPageSize, paged_cookie=nextTokenStr)
    #             results = JsonTools().Deserialize(self.conn.response_to_json(self.conn.result, sort=True))
    #             try:
    #                 for i in results['entries']:
    #                     if i is not None:
    #                         del i['raw']
    #                         entries.append(i)
    #             except LDAPReferralError as e:
    #                 print(e) 
                
    #             nextTokenStr = self.conn.result['controls']['1.2.840.113556.1.4.319']['value']['cookie']

    #             if nextTokenStr == None or len(nextTokenStr) == 0:
    #                 break
    #             if maxSearchResults <= len(entries):
    #                 break
    #         response = self.ParseResults(entries, response)
    #         if nextTokenStr != None and len(nextTokenStr) > 0:
    #             nextTokenStr = b64encode(nextTokenStr).decode()
    #             response.nextToken = nextTokenStr
    #     except Exception as e:
    #         response.message[e.__class__.__name__] = f"{e}"
    #         response.success = False
    #         response.status = StatusCode.Failure.name
    #     response.server = self._SERVER
    #     response.searchBase = request.searchBase
    #     response.searchFilter = searchFilter
    #     response = self.toJson(response=response, request=request)
    #     return response
    
    def test_func_bonsai(self, results, searchBase, searchValue, attributes, scope, ServerTimeLimit, maxSearchResults, maxPageSize, nextTokenStr, paged: False):
        if not paged:
            results.append(self.conn.search(base=searchBase, scope=scope, filter_exp=searchValue, attrlist=attributes, timeout=ServerTimeLimit, sizelimit=maxSearchResults))
        else:
            results.append(self.conn.paged_search(base=searchBase, scope=bonsai.LDAPSearchScope.SUBTREE, filter_exp=searchValue, attrlist=attributes, timeout=ServerTimeLimit, sizelimit=maxSearchResults, page_size=maxPageSize))

    def Search2(self, request: LdapRequest, searchFilter: str, attributes = None, searchScope: SearchScopeType2 = None, maxResults: int = maxsize, nextTokenStr = None):
        response = LdapResponse()
        entries = deque()
        if nextTokenStr != None:
            nextTokenStr = nextTokenStr

        try:
            if searchFilter == None or searchFilter == '':
                raise Exception("Search Filter Not Provided")
            if not self.conn or not self._CONNECTED:
                raise LDAPSocketOpenError(f"Server '{self._SERVER}' Is not connected")
            # if not self.conn.bound:
            request.config.IgnoreWarnings = SidUtils().Convert_Str_to_Bool(ignoreWarnings=request.config.IgnoreWarnings)
            rootDSE = self.server.get_rootDSE()['namingContexts'][2] if "BP1" in self._SERVER else self.server.get_rootDSE()['namingContexts'][0]
            request.searchBase = rootDSE if request.searchBase == None else request.searchBase
            # if request.searchBase == None:
            #     request.searchBase =rootDSE
            response.status = StatusCode.Success.name
            searchFilter_list = [searchFilter]
            searchBase_list = [request.searchBase]
            if request.MultipleSearches != None:
                for i  in request.MultipleSearches:
                    searchBase_flag = 'searchBase' in i.keys()
                    searchValue_flag = 'searchValue' in i.keys()
                    if searchBase_flag == False and searchValue_flag == True:
                        i['searchBase'] = request.searchBase
                    elif searchBase_flag == True and searchValue_flag == False:
                        i['searchValue'] = searchFilter
                    i['searchValue'] = LdapUtils.CheckforError(request, i['searchValue'], i['searchBase'])
                    searchFilter_list.append(i["searchValue"])
                    searchBase_list.append(i["searchBase"])
            results = deque()
            options = Options(0,maxResults,3600,self._FOLLOWREFERRALS)
            while True:
                # maxPageSize = self._MAXPAGESIZE
                maxSearchResults = maxResults if maxResults != None else 999999
                # if maxResults != None:
                #     maxSearchResults = maxResults
                maxPageSize = maxSearchResults-len(entries) if maxSearchResults - len(entries) < self._MAXPAGESIZE else self._MAXPAGESIZE
                # if maxSearchResults - len(entries) < self._MAXPAGESIZE:
                #     maxPageSize = maxSearchResults-len(entries)
                scope = searchScope.value if searchScope != None else bonsai.LDAPSearchScope.SUBTREE
                # if searchScope != None:
                #     scope = searchScope.value
                # entry_list = []
                if request.maxResults == None:
                    results.append(self.conn.search(base=request.searchBase, scope=scope, filter_exp=searchFilter, attrlist=request.attributes, timeout= options.ServerTimeLimit, sizelimit=maxSearchResults))
                    if request.MultipleSearches != None:
                        for i in request.MultipleSearches:
                            thread_obj = Thread(target=self.test_func_bonsai, args=(results, i['searchBase'], i['searchValue'], attributes, scope, options.ServerTimeLimit, maxSearchResults, maxPageSize, nextTokenStr, False))
                            thread_obj.start()
                            thread_obj.join()
                    # for i in results:
                    #     for j in i:
                    #         entry_list.append(j)
                    entry_list = [j for i in results for j in i]
                    key_list = list(entry_list[0].keys()) if entry_list else []
                    attributes,response = self.CheckAttributes2(attributes, key_list, response, request.config, request.present)
                    for i in entry_list:
                        entry = {}
                        entry["dn"] = str(i["dn"])
                        attributez = {}
                        for j in attributes:
                            try:
                                attributez[j] = i[j] if len(i[j]) > 1 else i[j][0]
                                # if len(i[j]) > 1:
                                #     attributez[j] = i[j]
                                # else:
                                #     attributez[j] = i[j][0]
                            except:
                                pass
                        entry["attributes"] = attributez
                        entries.append(entry)
                else:
                    if nextTokenStr == None:
                        results.append(self.conn.paged_search(base=request.searchBase, scope=scope, filter_exp=searchFilter, attrlist=request.attributes, timeout= options.ServerTimeLimit, sizelimit=maxSearchResults, page_size=request.maxResults))
                        if request.MultipleSearches != None:
                            for i in request.MultipleSearches:
                                thread_obj = Thread(target=self.test_func_bonsai, args=(results, i['searchBase'], i['searchValue'], attributes, scope, options.ServerTimeLimit, maxSearchResults, maxPageSize, nextTokenStr, True))
                                thread_obj.start()
                                thread_obj.join()
                        # for i in results:
                        #     for j in i:
                        #         entry_list.append(j)
                        entry_list = [j for i in results for j in i]
                        key_list = list(entry_list[0].keys()) if entry_list else []
                        attributes,response = self.CheckAttributes2(attributes, key_list, response, request.config, request.present)
                        for i in entry_list:
                            entry = {}
                            entry["dn"] = str(i["dn"])
                            attributez = {}
                            for j in attributes:
                                try:
                                    attributez[j] = i[j] if len(i[j]) > 1 else i[j][0]
                                    # if len(i[j]) > 1:
                                    #     attributez[j] = i[j]
                                    # else:
                                    #     attributez[j] = i[j][0]
                                except:
                                    pass
                            entry["attributes"] = attributez
                            entries.append(entry)
                    else:
                        results.append(self.conn.paged_search(base=request.searchBase, scope=scope, filter_exp=searchFilter, attrlist=request.attributes, timeout= options.ServerTimeLimit, sizelimit=maxSearchResults, page_size=request.maxResults))
                        flag = False
                        while True:
                            x = results[0].acquire_next_page()
                            if x == nextTokenStr:
                                flag = True
                                break
                            self.conn._evaluate(x)
                            if x == nextTokenStr - 1:
                                break
                        if not flag:
                            results[0].acquire_next_page()
                        results[0] = self.conn._evaluate(nextTokenStr)
                        # for i in results:
                        #     entry_list.append(i)
                        entry_list = [j for i in results for j in i]
                        key_list = list(entry_list[0].keys()) if entry_list else []
                        attributes,response = self.CheckAttributes2(attributes, key_list, response, request.config, request.present)
                        for i in entry_list:
                            entry = {}
                            entry["dn"] = str(i["dn"])
                            attributez = {}
                            for j in attributes:
                                try:
                                    attributez[j] = i[j] if len(i[j]) > 1 else i[j][0]
                                    # if len(i[j]) > 1:
                                    #     attributez[j] = i[j]
                                    # else:
                                    #     attributez[j] = i[j][0]
                                except:
                                    pass
                            entry["attributes"] = attributez
                            entries.append(entry)
                try:
                    nextTokenStr  = results[0].acquire_next_page()
                except:
                    nextTokenStr = None
                if nextTokenStr == None:
                    break
                if maxSearchResults <= len(entries):
                    break
            # response = self.ParseResults(entries, response)
            response = self.ParseResults(entries, response)
            response.nextToken = nextTokenStr if nextTokenStr != None else None
            # if nextTokenStr != None:
            #     response.nextToken = nextTokenStr
        except Exception as e:
            response.message[e.__class__.__name__] = f"{e}"
            response.success = False
            response.status = StatusCode.Failure.name
        response.server = self._SERVER
        if request.MultipleSearches != None:
            response.searchBases = searchBase_list
            response.searchFilters = searchFilter_list
        else:
            response.searchBase = request.searchBase
            response.searchFilter = searchFilter

        response = self.toJson(response=response, request=request)
        return response
    
    def ReturnError(self, e: Exception, config: LdapConfig, request: LdapRequest):
        returning_error = True
        response = LdapResponse()
        response.success = False
        response.status = StatusCode.Failure.name
        response.server = config.server_name
        response.message[e.__class__.__name__] = f"{e}"
        response = self.toJson(response=response, request=request, returning_error=returning_error)

        return response
    
    def Print(self):
         print(f"Server:{self._SERVER}, port:{self._PORT}, ssl: {self._USESSL}, maxRetries: {self._MAXRETRIES}, maxpagesize: {self._MAXPAGESIZE}, followReferrals: {self._FOLLOWREFERRALS}, returnTypes: {self._RETURNTYPES}")

    