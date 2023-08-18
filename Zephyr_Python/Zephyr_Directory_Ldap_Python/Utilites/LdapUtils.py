import json
import sys
import os
import re
import uuid
import socket
from Zephyr_Directory_Ldap_Python.Utilites.SidUtils import SidUtils
from Zephyr_Directory_Ldap_Python.Classes.LdapCrypto import LdapCrypto
from Zephyr_Directory_Ldap_Python.Classes.LdapRequest import LdapRequest, ObjectType
from Zephyr_Directory_Ldap_Python.Classes.LdapConfig import LdapConfig, LdapAttributeTypes
from Zephyr_Directory_Ldap_Python.Utilites.JsonTools import JsonTools
from Zephyr_Crypto_Python.Rijndael import Rijndael

class LdapUtils():
    # os.environ["IV"] = "293464BAFE31A0B7"
    # os.environ['PASSPHRASE'] = 'mYr1Ad22p4SSPHr4s'
    # os.environ['SALT'] = 'mYR4nd0MSaLtV1ue'
    def GetDomainShortName(searchVal: str):
        domain = None
        if searchVal != None:
            ntid = searchVal.replace('/', '\\')
            if '\\' in ntid:
                domain = ntid[0:ntid.index('\\')]
        return domain
    
    def GetDomainNameFromUPN(searchVal: str):
        domain = None
        # print(searchVal[index])
        if searchVal != None or searchVal != '':
            if '@' in searchVal:
                # r = re.search(searchVal,'@')
                # r.lastindex
                last_instance2 =  searchVal[::-1].index('.')
                last_instance = searchVal[::-1].index('@')
                index = len(searchVal) - last_instance - 1
                index2 = len(searchVal) - last_instance2 - 1
                domain = searchVal[index + 1: index2]
        return domain
    
    def GetDomainName(searchVal: str):
        pattern = r"DC=([^,]+)"
        r = re.findall(pattern,searchVal)
        joined_str = '.'.join(r)
        return joined_str


    def GetConfigProfileFromMap(map, key):
        # print(map, "=", key)
        config = LdapConfig()
        # print(map["server"])
        if key != None:
            upKey = key.upper()
            if upKey in map:
                config = LdapConfig(JsonTools().Deserialize(os.environ[map[upKey]]))
        return config

    def GetEnviromentVariable(self, name, defaultValue):
        if name in os.environ:
            value = os.environ.get(name)
        else:
            value = str(defaultValue)
        return value
    
    def SetConfigValues(target: LdapConfig, source: LdapConfig):
        if source == None:
            return target
        
        if target.server_name == None:
            target.server_name = source.server_name

        if target.port == None:
            target.port = source.port

        if target.ssl == None:
            target.ssl = source.ssl

        if target.username == None:
            target.username = source.username

        if target.password == None:
            target.password = source.password

        if target.maxRetries == None:
            target.maxRetries = source.maxRetries

        if target.maxPageSize == None:
            target.maxPageSize = source.maxPageSize

        if target.followReferrals == None:
            target.followReferrals = source.followReferrals

        if target.returnTypes == None:
            target.returnTypes = source.returnTypes

        if source.returnTypes != None:
            for key in source.returnTypes:
                if not target.returnTypes.get(key):
                    print("Adding Key")
                    target.returnTypes[key] = source.returnTypes[key]
        return target
    
    def GetConfigProfile(request: LdapRequest):
        #CHECK THE JSON DESERIALIZE FUNCON AND IMPLEMENT THE DEFAULT VALUE
        # print(type(request.Config()))
        Config = LdapConfig()
        configMap = JsonTools().Deserialize(os.environ["DOMAIN_MAPPINGS"])
        print("Before:")
        request.Config().Print()
        # print(configMap["BP1"], "=>", request.Config().maxRetries)
        if not request.Config().is_Null():
            print("HERE 1")
            LdapUtils.SetConfigValues(Config, request.Config())
        if request.domain != None:
            print("HERE 2")
            dmConfig = LdapConfig()
            if type(dmConfig) != dict:
                print("HERE 2.A")
                dmConfig = LdapUtils.GetConfigProfileFromMap(configMap, request.domain)
                # print(dmConfig.server_name)
            if dmConfig == None:
                print("HERE 2.B")
                dmConfig = JsonTools().Deserialize(request.domain.upper())
            if dmConfig != None:
                print("HERE 2.C")
                # x = LdapUtils.SetConfigValues(Config, dmConfig)
                LdapUtils.SetConfigValues(Config, dmConfig)
        elif configMap is not None:
            print("trying to find domain")
            if request.searchBase is not None:
                print("Here 3")
                domain = LdapUtils.GetDomainName(request.searchBase)
                print(domain)
                # domain = "BP1.AD.BP.COM"
                sbConfig = LdapConfig()
                sbConfig = LdapUtils.GetConfigProfileFromMap(configMap, domain)
                sbConfig = LdapUtils.SetConfigValues(Config, sbConfig)
                # request.domain = domain
            if request.searchBase == None or request.searchBase == "":
                print("HERE 4")
                domainKey = None
                svConfig = LdapConfig()
                # svConfig.Print()
                if svConfig.is_Null:
                    print("HERE 4.A")
                    domainKey = LdapUtils.GetDomainShortName(request.searchValue)
                    # print(domainKey)
                    svConfig = LdapUtils.GetConfigProfileFromMap(configMap, domainKey)
                    request.domain = domainKey
                    # svConfig.Print()
                if svConfig.is_Null():
                    print("HERE 4.B")
                    domainKey = LdapUtils.GetDomainNameFromUPN(request.searchValue)
                    # print(domainKey)
                    svConfig = LdapUtils.GetConfigProfileFromMap(configMap, domainKey)
                    request.domain = domainKey
                    # svConfig.Print()
                if svConfig.is_Null():
                    print("HERE 4.C")
                    domainKey = LdapUtils.GetDomainName(request.searchValue)
                    print(domainKey)
                    svConfig = LdapUtils.GetConfigProfileFromMap(configMap, domainKey)
                    request.domain = domainKey
                    # svConfig.Print()
                if not svConfig.is_Null():
                    print("HERE 4.D")
                    LdapUtils.SetConfigValues(Config, svConfig)
                
        data = JsonTools().Deserialize(os.environ["DEFAULT_CONFIG"])
        envConfig = LdapConfig(data)
        LdapUtils.SetConfigValues(Config, envConfig)
        Config.Print()
        if Config.server_name == None:
            # config.server_name = Enviroment.MachineName?????
            Config.server_name = socket.gethostname()
        if Config.ssl == None:
            Config.ssl = False
        if Config.port == None:
            # Config.port = Config.ssl == True ? 636 : 389;???????
            Config.port = 636 if Config.ssl == True  else 389
        if Config.maxPageSize == None:
                Config.maxPageSize = 512
        # print(Config.server_name, "=>", request.Config().server_name)
        # Config.Print()
        return Config

    def ApplyDefaultandValidate(crypto: LdapCrypto):
        if crypto == None:
            crypto = LdapCrypto
        if crypto.iv == None:
            crypto.iv = LdapUtils().GetEnviromentVariable('IV', "1234567890ABCDEF")
        if crypto.salt == None:
            crypto.salt = LdapUtils().GetEnviromentVariable("SALT", "DefaultSaltValue")
        if crypto.passphrase == None:
            crypto.passphrase = LdapUtils().GetEnviromentVariable("PASSPHRASE", "DefaultPassPhrase")
        return crypto
    
    def ApplyDefaultsAndValidate(request: LdapRequest):
        request.config = LdapUtils.GetConfigProfile(request)
        attrConfigStr = os.environ['RETURN_TYPES']
        #TEST THISSS-------
        if attrConfigStr != None or '':
            ReturnTypes = JsonTools().Deserialize(attrConfigStr)
            if not request.config.returnTypes:
                print("returntypes is null")
                request.config.returnTypes = {}
            for i in ReturnTypes.keys():
                if i not in request.config.returnTypes.keys():
                    # print("Adding: ", i, ":", ReturnTypes[i])
                    request.config.returnTypes[i] = ReturnTypes[i]
        # print(request.config.returnTypes)
        request.crypto = LdapUtils.ApplyDefaultandValidate(request.Crypto())

        try:
            # print(request.config.password)
            # "5iG6IK+FzNxP8/o4eVPmlTZRC43975UCJrbqh8eCLqI="
            # request.config.password = Rijndael().Encrypt(request.config.password, request.crypto.passphrase, request.crypto.salt, request.crypto.iv)
            print("Decrypting")
            request.config.password = Rijndael().Decrypt(request.config.password, request.crypto.passphrase, request.crypto.salt, request.crypto.iv)
            print(request.config.password)
        except Exception as e:
            pass
        # print(type(returnTypes))
        # print(returnTypes.keys())
        # print(request.domain)
        # print("RETURNING . . .")
        print("\nAfter:")
        request.config.Print()
        return request
    
    def ContainsKnownDomain(val):
        rc = False
        if '\\' in val or '/' in val:
            configMap = JsonTools().Deserialize(os.environ["DOMAIN_MAPPINGS"])
            if configMap is not None:
                domainShortName = LdapUtils.GetDomainShortName(val)
                if domainShortName != None and domainShortName.upper() in configMap:
                    rc = True
        return rc

    def GetIdentitySearchString(request: LdapRequest):
        identity = None
        searchVal = request.searchValue
        print(searchVal)
        g = uuid.UUID(int= 0)
        dnRegexString = "^\s*?(cn\s*=|ou\s*=|dc\s*=)"
        if LdapUtils.ContainsKnownDomain(searchVal):
            print("In IF STATEMENT 1")
            searchVal = searchVal.replace('/','\\')
            searchVal = searchVal[searchVal.index('\\') + 1:]
        searchVal = searchVal.replace("\\", r"\5C")
        searchVal = searchVal.replace(r"(", r"\28")
        searchVal = searchVal.replace(r")", r"\29")
        
        if request.object_type == ObjectType.Dn or request.object_type == ObjectType.DistinguishedName or (request.wildcardToken != None and request.wildcardToken == False):
            print("In IF STATEMENT 2")
            searchVal = searchVal.replace(r"*", r"\2A")
 
        try:
            print("CHANGE THIS")
            g = uuid.UUID(searchVal)
            print(g)
        except Exception as e:
            print(e)
        # print("HELLO")
        r2 = re.compile(dnRegexString, re.IGNORECASE)
        #WORK ON THIS!!!
        if g != uuid.UUID(int= 0):
            request.searchBase = f"<GUID={g}>"
            identity = f"(cn=*)"
        elif SidUtils.IsSid_str(sid = searchVal):
            request.searchBase = f"<SID={searchVal}>"
            identity = f"(cn=*)"
        elif r2.match(searchVal):
            print("HERE 2")
            identity = f"(distinguishedName={searchVal})"
        elif '@' in searchVal and request.object_type == ObjectType.User:
            print("HERE 3")
            identity = f"(|(cn={searchVal})(name={searchVal})(userPrincipalName={searchVal}))"
        else:
            print("HERE 4")
            if request.object_type == ObjectType.Contact or request.object_type == ObjectType.Printer or request.object_type == ObjectType.PrintQueue or request.object_type == ObjectType.Volume:
                print("HERE 4.1")
                identity = f"(|(cn={searchVal})(name={searchVal}))"
            elif request.object_type == ObjectType.Ou or request.object_type == ObjectType.OrganizationUnit:
                print("HERE 4.2")
                identity = f"(|(ou={searchVal})(name={searchVal}))"
            elif request.object_type == ObjectType.Domain:
                print("HERE 4.3")
                identity = f"(name={searchVal})"
            else:
                print("HERE 4.4")
                identity = f"(|(cn={searchVal})(name={searchVal})(sAMAccountName={searchVal}))"
            

        return identity
        
        
    # # #START POINT
    def GetSearchString(request: LdapRequest):
        request.ObjectType()
        searchFilter = None
        if request.object_type == None:
            print("HERE 1")
            searchFilter = request.searchValue
        else:
            id = LdapUtils.GetIdentitySearchString(request)
            if request.object_type == ObjectType.Ou:
                print("HERE 5.1")
                searchFilter = f"(&(objectCategory=OrganizationalUnit){id})"
            elif request.object_type == ObjectType.Contact:
                print("HERE 5.2")
                searchFilter = f"(&(objectCategory=Person)(objectClass=Contact){id})"
            elif request.object_type == ObjectType.DomainController:
                print("HERE 5.3")
                searchFilter = f"(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192){id})".format(id=id)
            elif request.object_type == ObjectType.Printer:
                print("HERE 5.4")
                searchFilter = f"(&(objectCategory=PrintQueue){id})"
            elif request.object_type == ObjectType.Dn or request.object_type == ObjectType.DistinguishedName:
                print("HERE 5.5")
                searchFilter = id
            else:
                print("HERE 5.6")
                searchFilter = f"(&(objectCategory={request.object_type.name}){id})"
            
        return searchFilter
    