from sys import maxsize, byteorder
from binascii import hexlify
from base64 import b64decode, b64encode
from threading import Thread
from ldap3 import Server, Connection, ALL, ALL_ATTRIBUTES, SUBTREE, NO_ATTRIBUTES
from ldap3.core.exceptions import LDAPSocketOpenError, LDAPReferralError, LDAPException
from Zephyr_Directory_Ldap_Python.Classes import LdapConfig, LdapRequest, LdapResponse, LdapAttributeTypes
from Zephyr_Directory_Ldap_Python.Classes.LdapConfig import OutputTypes
from Zephyr_Directory_Ldap_Python.Classes.LdapRequest import SearchScopeType
from Zephyr_Directory_Ldap_Python.Classes.LdapResponse import StatusCode
from Zephyr_Directory_Ldap_Python.Utilities.LdapUtils import LdapUtils
from Zephyr_Directory_Ldap_Python.Utilities.JsonTools import JsonTools
from Zephyr_Directory_Ldap_Python.Utilities.SidUtils import SidUtils
from Zephyr_Directory_Ldap_Python.Utilities.XMLTools import XMLTools
from Zephyr_Directory_Ldap_Python.Utilities.CSVTools import CSVTools
from Zephyr_Directory_Ldap_Python.KnownAttributes import KnownAttributes
from uuid import UUID
import struct

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
        
    def Connect(self, config, request):
        flag = False
        attempts = 0
        while attempts  <= self._MAXRETRIES and flag == False:
            try:
                self.server = Server(self._SERVER, self._PORT, use_ssl=self._USESSL, get_info=ALL)
                self.conn = Connection(server = self.server, user=config.username, password=config.password, auto_bind= True, return_empty_attributes=False, check_names=True)
                if self.conn:
                    flag = True
                    self._CONNECTED = True
            except LDAPSocketOpenError as e:
                attempts += 1

    def Disconnect(self):
        if self._CONNECTED:
            self.conn.unbind()

    def CheckAttributes(self, attributes, response: LdapResponse, config: LdapConfig):
        attributes_ = []
        error_attributes = []
        item_list = [e for e in attributes if e not in ('')]
        for attribute in item_list:
            if attribute in self.server.schema.attribute_types:
                attributes_.append(attribute)
            else:
                error_attributes.append(attribute)
        if len(error_attributes) > 0 and config.IgnoreWarnings == False:
            response.status = StatusCode.SuccessWithWarnings.name
            response.message["LDAPInvalidAttributeType"] = f"Invalid Attribute(s): {', '.join(error_attributes)}"
        return attributes_, response

    def AddValueWithUnknownType(self, rec, key, attribute):
        try:
            if "encoded" in attribute:
                i = attribute["encoded"].encode()
                i = b64decode(i)
                attribute = i
        except:
            print("")
        values = attribute if type(attribute) == list else [str(attribute)]
        rec[key] = values if len(values) > 1 else str(values[0])

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
                        strs = list()
                        try:
                            for b in attribute:
                                if 'encoded' in b:
                                    i = attribute['encoded'].encode()
                                    i = b64decode(i)
                                    strs.append('0x'+i.hex())
                                elif 'encoding' in b:
                                    break
                                else:
                                    i = hexlify(b.encode('utf8'))
                                    i = i.decode()
                                    strs.append("0x"+ i)
                        except:
                            strs.append("0x"+attribute.hex())
                        attributes[key] = list(strs)
                    elif attrType == LdapAttributeTypes.Guid or attrType == "Guid":
                        try:
                            # attributes[key] = str(UUID(bytes_le=b64decode(attribute["encoded"].encode()))) if byteorder == "little" else str(UUID(bytes=b64decode(attribute["encoded"].encode()))) if "encoded" in attribute else str(UUID(attribute))
                            if "encoded" in attribute:
                                i = attribute["encoded"].encode()
                                i = b64decode(i)
                                attributes[key] = str(UUID(bytes_le=i)) if byteorder == "little" else str(UUID(bytes=i))
                            else:
                                attributes[key] = str(UUID(attribute))
                        except:
                            attributes[key] = str(UUID(bytes_le=attribute)) if byteorder == "little" else str(UUID(bytes=attribute)) 
                    elif attrType == LdapAttributeTypes.GuidArray or attrType == "GuidArray":
                        guid_list = list()
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
                        try:
                            if type(attribute) == bytes:
                                attributes[key] = [SidUtils.New_Bytes_To_SID(attribute)]
                            else:  
                                attributes[key] = [SidUtils.New_Bytes_To_SID(SidUtils.New_String_to_Bytes(attribute))]
                        except:
                            SID_list = list()
                            for i in attribute:
                                if "encoded" in i:
                                    x = i["encoded"].encode()
                                    x = b64decode(x)
                                    SID_list.append(SidUtils.New_Bytes_To_SID(x))
                            attributes[key] = list(SID_list)
                    elif attrType == LdapAttributeTypes.String or attrType == "String":
                        attributes[key] = str(attribute[0]) if type(attribute) == list else str(attribute)
                    elif attrType == LdapAttributeTypes.StringArray or attrType == "StringArray":
                        attributes[key] = attribute if type(attribute) == list else [attribute]
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
                        self.AddValueWithUnknownType(rec=attributes, key=key,attribute=attribute)
            except LDAPReferralError as e:
                print("------", e)
            except LDAPException as e:
                response.message[e.__class__.__name__] = f"Page Size Limit Exceeded. Current Value is {self._MAXPAGESIZE}. Please increase"
        response.totalRecords = len(response.records)
        response.records = list(response.records)
        return response
    
    def format_Message(self, messages: dict):
        formatted_message = f'Found {len(messages)} Errors: '
        for message in messages.keys():
            formatted_message = formatted_message + f"{message}: {messages[message]}. "
        return formatted_message.strip()
            
    # Look into Return Token when search is complete but still returning next Token.
    def toJson(self, response: LdapResponse, request:LdapRequest, returning_error:bool = False):
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
        
    def Multiple_Searches_python_ldap(self, results, searchBase, searchFilter, attributes, scope, server_time_limit, maxSearchResults, maxPageSize, nextTokenStr):
        self.conn.search(search_base=searchBase, search_filter=searchFilter, attributes=attributes, search_scope=scope, types_only=False, time_limit=server_time_limit, size_limit=maxSearchResults, paged_size=maxPageSize, paged_cookie=nextTokenStr)
        results.append(JsonTools().Deserialize(self.conn.response_to_json(self.conn.result, sort=True)))

    def Search(self, request: LdapRequest, searchFilter: str, attributes = None, searchScope: SearchScopeType = None, maxResults: int = maxsize, nextTokenStr:str = None):
        response = LdapResponse()
        entries = []
        Pick_up_here = 1
        Parser = 0
        # Decoding for Server and Client Token Types
        if nextTokenStr != None:
            try:
                if request.config.Token_type == "Client":
                    nextTokenStr = b64decode(nextTokenStr).decode()
                nextTokenStr_Split = nextTokenStr.rsplit("-", 1)
                nextTokenStr = nextTokenStr_Split[0]
                Pick_up_here = int(nextTokenStr_Split[1])
                if nextTokenStr == "MDAwMAAAAAAAAA==":
                    nextTokenStr = None
                else:
                    if request.config.Token_type == "Server":
                        nextTokenStr = nextTokenStr.encode()
                        nextTokenStr = b64decode(nextTokenStr)
            except:
                nextTokenStr = nextTokenStr.encode()
                nextTokenStr = b64decode(nextTokenStr)

        try:
            if searchFilter == None or searchFilter == '':
                raise Exception("Search Filter Not Provided")
            if not self.conn or not self._CONNECTED:
                raise LDAPSocketOpenError(f"Server '{self._SERVER}' Is not connected")
            if not self.conn.bound:
                raise LDAPException(f"Server '{self._SERVER}' is Not Bound")
            request.config.IgnoreWarnings = SidUtils().Convert_Str_to_Bool(ignoreWarnings=request.config.IgnoreWarnings)
            rootDSE = JsonTools().Deserialize(var=self.server.info.to_json())
            request.searchBase = rootDSE['raw']['defaultNamingContext'][0] if request.searchBase == None else request.searchBase
            response.status = StatusCode.Success.name
            if attributes != None:
                # Check for Invalid Attributes
                attributes,response = self.CheckAttributes(attributes, response, request.config)
            searchFilter_list = [searchFilter]
            searchBase_list = [request.searchBase]
            if request.MultipleSearches != None:
                # Validate each entry in the Union Property
                for i  in request.MultipleSearches:
                    searchBase_flag = 'searchBase' in i.keys()
                    searchValue_flag = 'searchValue' in i.keys()
                    if searchBase_flag == False and searchValue_flag == True:
                        i['searchBase'] = request.searchBase
                    elif searchBase_flag == True and searchValue_flag == False:
                        i['searchValue'] = searchFilter
                    i['searchValue'] = LdapUtils.CheckforError(request, i['searchValue'], i['searchBase'])
                    searchBase_list.append(i["searchBase"])
                    searchFilter_list.append(i['searchValue'])
            results = []
            options = Options(0,maxResults,3600,self._FOLLOWREFERRALS)
            while True:
                maxPageSize = self._MAXPAGESIZE
                maxSearchResults = 999999
                if maxResults != None:
                    maxSearchResults = maxResults
                if maxSearchResults - len(entries) < self._MAXPAGESIZE:
                    maxPageSize = maxSearchResults-len(entries)
                if request.present == True and attributes == None:
                    attributes = NO_ATTRIBUTES
                if request.present == False:
                    attributes = ALL_ATTRIBUTES
                scope = SUBTREE
                if searchScope != None and scope != searchScope:
                    scope = searchScope.value
                # Pick_up_Here is used to determine where the previous search finished, if Pick_up_Here is > 1 that means that the search finished in a Multiple Searches Entry
                if Pick_up_here > 1:
                    # These conditional statements also determine the size_limit for the search
                    if nextTokenStr == None:
                        self.conn.search(request.MultipleSearches[Pick_up_here-2]['searchBase'], request.MultipleSearches[Pick_up_here-2]['searchValue'], attributes=attributes, search_scope=scope, types_only=False, time_limit=options.ServerTimeLimit, size_limit=maxSearchResults, paged_size=maxPageSize, paged_cookie=nextTokenStr)
                        results.append(JsonTools().Deserialize(self.conn.response_to_json(self.conn.result, sort=True)))
                        nextTokenStr = self.conn.result['controls']['1.2.840.113556.1.4.319']['value']['cookie'] if self.conn.result['controls']['1.2.840.113556.1.4.319']['value']['cookie'] else None
                    else:
                        if request.config.Token_type != "Server":
                            Parser = nextTokenStr
                            self.conn.search(request.MultipleSearches[Pick_up_here-2]['searchBase'], request.MultipleSearches[Pick_up_here-2]['searchValue'], attributes=attributes, search_scope=scope, types_only=False, time_limit=options.ServerTimeLimit, size_limit=maxSearchResults+int(nextTokenStr), paged_size=maxPageSize+int(nextTokenStr), paged_cookie=None)
                            results.append(JsonTools().Deserialize(self.conn.response_to_json(self.conn.result, sort=True)))
                            nextTokenStr = self.conn.result['controls']['1.2.840.113556.1.4.319']['value']['cookie'] if self.conn.result['controls']['1.2.840.113556.1.4.319']['value']['cookie'] else None
                            results[0]['entries'] = results[0]['entries'][int(Parser):]
                        else:
                            self.conn.search(request.MultipleSearches[Pick_up_here-2]['searchBase'], request.MultipleSearches[Pick_up_here-2]['searchValue'], attributes=attributes, search_scope=scope, types_only=False, time_limit=options.ServerTimeLimit, size_limit=maxSearchResults, paged_size=maxPageSize, paged_cookie=nextTokenStr)
                            results.append(JsonTools().Deserialize(self.conn.response_to_json(self.conn.result, sort=True)))
                            nextTokenStr = self.conn.result['controls']['1.2.840.113556.1.4.319']['value']['cookie'] if self.conn.result['controls']['1.2.840.113556.1.4.319']['value']['cookie'] else None
                else:
                    if nextTokenStr == None:
                        self.conn.search(request.searchBase, searchFilter, attributes=attributes, search_scope=scope, types_only=False, time_limit=options.ServerTimeLimit, size_limit=maxSearchResults, paged_size=maxPageSize, paged_cookie=nextTokenStr)
                        results.append(JsonTools().Deserialize(self.conn.response_to_json(self.conn.result, sort=True)))
                        nextTokenStr = self.conn.result['controls']['1.2.840.113556.1.4.319']['value']['cookie'] if self.conn.result['controls']['1.2.840.113556.1.4.319']['value']['cookie'] else None
                    else:
                        if request.config.Token_type != "Server":
                            Parser = nextTokenStr
                            try:
                                int_parser = int(Parser)
                                self.conn.search(request.searchBase, searchFilter, attributes=attributes, search_scope=scope, types_only=False, time_limit=options.ServerTimeLimit, size_limit=maxSearchResults+int(nextTokenStr), paged_size=maxPageSize, paged_cookie= None)
                                results.append(JsonTools().Deserialize(self.conn.response_to_json(self.conn.result, sort=True)))
                                nextTokenStr = self.conn.result['controls']['1.2.840.113556.1.4.319']['value']['cookie'] if self.conn.result['controls']['1.2.840.113556.1.4.319']['value']['cookie'] else None
                                results[0]['entries'] = results[0]['entries'][int_parser:]
                            except:
                                self.conn.search(request.searchBase, searchFilter, attributes=attributes, search_scope=scope, types_only=False, time_limit=options.ServerTimeLimit, size_limit=maxSearchResults, paged_size=maxPageSize, paged_cookie= Parser)
                                results.append(JsonTools().Deserialize(self.conn.response_to_json(self.conn.result, sort=True)))
                                nextTokenStr = self.conn.result['controls']['1.2.840.113556.1.4.319']['value']['cookie'] if self.conn.result['controls']['1.2.840.113556.1.4.319']['value']['cookie'] else None
                        else:
                            self.conn.search(request.searchBase, searchFilter, attributes=attributes, search_scope=scope, types_only=False, time_limit=options.ServerTimeLimit, size_limit=maxSearchResults, paged_size=maxPageSize, paged_cookie=nextTokenStr)
                            results.append(JsonTools().Deserialize(self.conn.response_to_json(self.conn.result, sort=True)))
                            nextTokenStr = self.conn.result['controls']['1.2.840.113556.1.4.319']['value']['cookie'] if self.conn.result['controls']['1.2.840.113556.1.4.319']['value']['cookie'] else None
                continueToken = None
                try:
                    currentRecords = len(results[0]['entries'])
                    if len(results) > 1:
                        currentRecords = currentRecords + len(results[-1]['entries'])
                except:
                    currentRecords = 0
                if request.config.Token_type == "Server":
                    # Searching process for Server Based Token
                    if request.MultipleSearches != None:
                        iteration = Pick_up_here
                        if nextTokenStr == None:
                            for i in range(Pick_up_here-1, len(request.MultipleSearches)):
                                recordsLeft = maxSearchResults - currentRecords
                                if recordsLeft <= maxSearchResults and currentRecords != maxSearchResults:
                                    # Multi Threading for Multiple Searches, the new entries will be added to the results list
                                    thread_obj = Thread(target=self.Multiple_Searches_python_ldap, args=(results, request.MultipleSearches[i]['searchBase'], request.MultipleSearches[i]['searchValue'], attributes, scope, options.ServerTimeLimit, maxSearchResults, recordsLeft, nextTokenStr))
                                    thread_obj.start()
                                    thread_obj.join()
                                    currentRecords = currentRecords + len(results[-1]['entries'])
                                    nextTokenStr = self.conn.result['controls']['1.2.840.113556.1.4.319']['value']['cookie'] if self.conn.result['controls']['1.2.840.113556.1.4.319']['value']['cookie'] else None
                                    if nextTokenStr != None:
                                        continueToken = f"-0{iteration}"
                                        nextTokenStr = nextTokenStr if nextTokenStr else struct.pack('10s', bytes("0000", 'utf-8'))
                                    iteration += 1
                                    if nextTokenStr == None and i == len(request.MultipleSearches)-1:
                                        # No Token is present and index is at the last entry. In other words the search is finished
                                        nextTokenStr = None
                                        break
                                    if nextTokenStr != None:
                                        continueToken = f"-0{iteration}"
                                else:
                                    nextTokenStr = self.conn.result['controls']['1.2.840.113556.1.4.319']['value']['cookie'] if self.conn.result['controls']['1.2.840.113556.1.4.319']['value']['cookie'] else None
                                    if nextTokenStr != None:
                                        continueToken = f"-0{iteration}"
                                    else:
                                        continueToken = f"-0{iteration+1}"
                                    nextTokenStr = self.conn.result['controls']['1.2.840.113556.1.4.319']['value']['cookie'] if self.conn.result['controls']['1.2.840.113556.1.4.319']['value']['cookie'] else struct.pack('10s', bytes("0000", 'utf-8'))
                                    break
                        else:
                            if nextTokenStr != None:
                                continueToken = f"-0{Pick_up_here}"
                            else:
                                continueToken = f"-0{Pick_up_here+1}"
                else:
                    # Searching process for Client Based Token
                    if request.MultipleSearches != None:
                        iteration = Pick_up_here
                        if nextTokenStr == None:
                            for i in range(Pick_up_here-1, len(request.MultipleSearches)):
                                recordsLeft = maxSearchResults - currentRecords
                                if recordsLeft <= maxSearchResults and currentRecords != maxSearchResults:
                                    # Multi Threading for Multiple Searches, the new entries will be added to the results list
                                    thread_obj = Thread(target=self.Multiple_Searches_python_ldap, args=(results, request.MultipleSearches[i]['searchBase'], request.MultipleSearches[i]['searchValue'], attributes, scope, options.ServerTimeLimit, maxSearchResults, recordsLeft, nextTokenStr))
                                    thread_obj.start()
                                    thread_obj.join()
                                    currentRecords = currentRecords + len(results[-1]['entries'])
                                    nextTokenStr = self.conn.result['controls']['1.2.840.113556.1.4.319']['value']['cookie'] if self.conn.result['controls']['1.2.840.113556.1.4.319']['value']['cookie'] else None
                                    if nextTokenStr != None:
                                        continueToken = f"-0{iteration}"
                                        nextTokenStr = str(recordsLeft)
                                    iteration += 1
                                    if nextTokenStr == None and i == len(request.MultipleSearches)-1:
                                        # No Token is present and index is at the last entry. In other words the searxch is finished
                                        nextTokenStr = None
                                        break
                                    if nextTokenStr != None:
                                        continueToken = f"-0{iteration}"
                                else:
                                    if nextTokenStr != None:
                                        continueToken = f"-0{iteration}"
                                    else:
                                        nextTokenStr = str(recordsLeft)
                                        continueToken = f"-0{iteration+1}"
                                        break
                        else:
                            if nextTokenStr != None:
                                nextTokenStr = str(currentRecords+int(Parser))
                                continueToken = f"-0{Pick_up_here}"
                            else:
                                continueToken = f"-0{Pick_up_here+1}"
                    else:
                        # Union is not present, meaning its just an ordinary search
                        if nextTokenStr != None and currentRecords == maxResults:
                            try:
                                nextTokenStr = str(currentRecords+int(Parser))
                            except:
                                nextTokenStr = str(currentRecords)
                            continueToken = f"-0{Pick_up_here}"
                try:
                    for result in results:
                        for i in result['entries']:
                            if i is not None:
                                try:
                                    del i['raw']
                                except:
                                    continue
                                entries.append(i)
                except LDAPReferralError as e:
                    print(e) 

                if nextTokenStr == None or len(nextTokenStr) == 0:
                    break
                if maxSearchResults <= len(entries):
                    break
                # if request.config.Token_type == "Client":
                #     nextTokenStr = None
            response = self.ParseResults(entries, response)
            if nextTokenStr != None and len(nextTokenStr) > 0 and type(nextTokenStr) == bytes:
                nextTokenStr = b64encode(nextTokenStr).decode()
                response.nextToken = nextTokenStr + continueToken if continueToken != None else nextTokenStr
            elif nextTokenStr != None and len(nextTokenStr) > 0 and type(nextTokenStr) == str:
                encoded_text = nextTokenStr + continueToken
                response.nextToken = b64encode(encoded_text.encode()).decode() if continueToken != None else b64encode(nextTokenStr).decode()
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
        if request.config.outputType == OutputTypes.XML:
            response = XMLTools().json_to_xml(response)
        elif request.config.outputType == OutputTypes.CSV:
            response = CSVTools().convert_to_csv(response["records"])
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