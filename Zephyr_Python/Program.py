import sys
import os
import re
from win32api import *
from Zephyr_Crypto_Python.Rijndael import Rijndael
from Zephyr_Directory_Ldap_Python.Ldap_Server import LDapServer
from Zephyr_Directory_Ldap_Python.Utilites.JsonTools import JsonTools
from Zephyr_Directory_Ldap_Python.Utilites.LdapUtils import LdapUtils
from Zephyr_Directory_Ldap_Python.Utilites.SidUtils import SidUtils
from Zephyr_Directory_Ldap_Python.Classes.LdapRequest import LdapRequest, PingType, ObjectType
from Zephyr_Directory_Ldap_Python.Classes.LdapResponse import LdapResponse

import json
import conversion
import io
import time
import uuid

_FILEPATH  = "Zephyr.Directory-1.1.23165.0/Zephyr_Python/Zephyr_Directory_Test/TestFiles/myriad.json"
# Cryptography
# os.environ['IV'] = '293464BAFE31A0B7'
# os.environ['PASSPHRASE'] = 'mYr1Ad22p4SSPHr4s'
# os.environ['SALT'] = 'mYR4nd0MSaLtV1ue'
# Config
# os.environ['CD1_CONFIG'] = { "server": "ldap-cd1-zu4.cd1.bp.com", "ssl" : True, "username": "-ldap-synapse-CD1", "password": "TLa/V5QPZwOc0QHa0FtgnbUoMz3mefbCw3bf5IYME0I=" }
# os.environ['CD2_CONFIG'] = { "server": "ldap-cd2-wu2.cd2.bp.com", "ssl" : True, "username": "-ldap-synapse-CD2", "password": "k12rymmfWTEuYG+37Z8AcNKT3tPScV2rT3SZ5pMqS+g=", "maxRetries": 2 }
# os.environ['DEFAULT_CONFIG'] = { "server": "LDAP-BP1-WU2H1.bp.com", "ssl" : True, "username": "-serv-cd2-synergy", "password": "5iG6IK+FzNxP8/o4eVPmlTZRC43975UCJrbqh8eCLqI=" }
# os.environ['DOMAIN_MAPPINGS'] = { "BP1": "DEFAULT_CONFIG", "BP1.AD.BP.COM": "DEFAULT_CONFIG", "CD1": "CD1_CONFIG", "CD1.BP.COM": "CD1_CONFIG", "CD2": "CD2_CONFIG", "CD2.BP.COM": "CD2_CONFIG"}
# os.environ['RETURN_TYPES'] = {"comment":"Bytes","mS-DS-ConsistencyGuid":"Guid","msExchArchiveGUID":"Guid","msExchMailboxGuid":"Guid","thumbnailPhoto":"Bytes","directReports":"StringArray","showInAddressBook":"StringArray","msRTCSIP-UserPolicies":"BytesArray","bp-DN-Multi-04": "StringArray"}
def toJson_Ping_or_Crypto(response: LdapResponse):
        if response.success == True:
            dictionary = {"success": response.success, "message": str(response.message)}
        return dictionary

cryptography = Rijndael()
JsonFile = JsonTools(_FILEPATH)
# Figure out how to pass in a Json 
Domain_MAPPINGS = os.environ["DOMAIN_MAPPINGS"]

# encrypted_ = crypto.Encrypt("Plain Text", "MyPassPhrase", "MySaltValue", "MyInitVector1234")
# print(encrypted_)
# decrypted_ = crypto.Decrypt("+QDpKrDz3olRgoVQPBqOzg==", "MyPassPhrase", "MySaltValue", "MyInitVector1234")
# print(decrypted_)

data = JsonFile.Deserialize()
# print(data["config"]["maxRetries"])
# data2 = JsonFile.Deserialize(var=Domain_MAPPINGS)
# print(type(data2))
request = LdapRequest(data)
# print(request.Config().maxRetries)
isPing = True if request.ping != None else False
response = LdapResponse()
# isPing = False

# ans = request.searchValue[::-1].index('a')
# index = len(request.searchValue) - ans -1
# print(index, request.searchValue[index])

# pattern = r"DC=([^,]+)"
# parts = []
# r = re.search(pattern,request.searchValue)
# print(r.lastindex)

# lst = ["Hi", "My", "Name", "is", "Lee"]
# joined_str = ""
# for i in lst:
#     joined_str = joined_str + i

# print(socket.gethostname())
# print(request.Config().maxRetries)
# print(request.Config().maxRetries)

# g_zeros = uuid.UUID(int= 0)
# print(g_zeros)
# g = uuid.UUID("6ba7b810-9dad-11d1-80b4-00c04fd430c8")
# if g != g_zeros:
#     print(g)
# print("Here: {0}".format(g))S

# sear = "S-1-5-1"
# SidUtils.ConvertStringSidToBytes(sear)
dnRegexString = "^\s*?(cn\s*=|ou\s*=|dc\s*=)"
# r2 = re.compile(dnRegexString)S
print(request.searchValue)
r2 = re.compile(dnRegexString, re.IGNORECASE)
# print(r2.search(request.searchValue))

if request.Crypto().text != None:
    crypto = LdapUtils.ApplyDefaultandValidate(crypto=request.Crypto())
    print(crypto.text, crypto.passphrase, crypto.salt, crypto.iv)
    # _encrypt = cryptography.Encrypt(request.Crypto().text, request.Crypto().passphrase, request.Crypto().salt, request.Crypto().iv)
    response.message = cryptography.Encrypt(crypto.text, crypto.passphrase, crypto.salt, crypto.iv)
    # _decrypt = cryptography.Decrypt("5iG6IK+FzNxP8/o4eVPmlTZRC43975UCJrbqh8eCLqI=", crypto.passphrase, crypto.salt, crypto.iv)
    response = toJson_Ping_or_Crypto(response)
elif isPing:
    response.message = "Hello From MyriAD ("  ")."
    response = toJson_Ping_or_Crypto(response)
    if request.Ping() == PingType.Echo:
        print("Ping")
else:
    try:
        print("In Try Block:\n")
        LdapUtils.ApplyDefaultsAndValidate(request)
        searchstring = LdapUtils.GetSearchString(request)
        print("SearchString:",searchstring)
        print("SearchBase:", request.searchBase)
        print("Creating LDAP Server:")
        # print(request.config.server_name)
        # Check the init function
        # Ask Guy if he evr had that issue
        # print(request.config.server_name, request.config.port, request.config.ssl, request.config.maxRetries, request.config.maxPageSize, request.config.followReferrals, request.config.returnTypes)
        ldap = LDapServer(request.config.server_name, request.config.port, request.config.ssl, request.config.maxRetries, request.config.maxPageSize, request.config.followReferrals, request.config.returnTypes)
        ldap.Connect(request.config, request=request)
        print(searchstring)
        request.object_type = request.ObjectType()
        request.searchScope = request.SearchScope()
        # print(request.searchScope.value)
        print("MaxResults:", request.maxResults)
        print("Attributes :" , request.attributes)
        response = ldap.Search(request=request, searchFilter=searchstring, attributes=request.attributes, searchScope=request.searchScope, maxResults=request.maxResults, nextTokenStr=request.nextToken)
        ldap.Disconnect()
        # print(result)
        print("Exiting Try Block")
    except Exception as e:
        print("error", e)
        response = ldap.ReturnError(e, request.config)
    # print(response.__dict__)

    # jsonformat = json.dumps(response)
    # print(jsonformat)
print(JsonTools().Serialize(response, True))
    # print(response)
# (&(objectCategory=User)(distinguishedName=CN=Waguespack\\5C\\5C, Guy,OU=Users,OU=HTN,OU=rST,OU=DWP,OU=Client,DC=bp1,DC=ad,DC=bp,DC=com))
# (&(objectCategory=ObjectType.User)(|(cn=CN=Waguespack\5C\5C, Guy,OU=Users,OU=HTN,OU=rST,OU=DWP,OU=Client,DC=bp1,DC=ad,DC=bp,DC=com)(name=CN=Waguespack\5C\5C, Guy,OU=Users,OU=HTN,OU=rST,OU=DWP,OU=Client,DC=bp1,DC=ad,DC=bp,DC=com)(sAMAccountName=CN=Waguespack\5C\5C, Guy,OU=Users,OU=HTN,OU=rST,OU=DWP,OU=Client,DC=bp1,DC=ad,DC=bp,DC=com)))
# 30717a02-559f-2645-b7f5-d3f13f750de3
