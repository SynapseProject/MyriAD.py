import os
import re
from multiprocessing import Process
from Zephyr_Crypto_Python.Rijndael import Rijndael
from Zephyr_Directory_Ldap_Python.Ldap_Server import LDapServer
from Zephyr_Directory_Ldap_Python.Utilities.JsonTools import JsonTools
from Zephyr_Directory_Ldap_Python.Utilities.LdapUtils import LdapUtils
from Zephyr_Directory_Ldap_Python.Classes.LdapRequest import LdapRequest, PingType
from Zephyr_Directory_Ldap_Python.Classes.LdapResponse import LdapResponse

_FILEPATH  = "C:/Users/0195tw/OneDrive - BP/Desktop/MyriAD.Core.py/Zephyr_Python/Zephyr_Directory_Test/TestFiles/myriad.json"
def toJson_Ping_or_Crypto(response: LdapResponse):
        if response.success == True:
            dictionary = {"success": response.success, "message": str(response.message)}
        return dictionary

def Test_add():
    return 1+1

cryptography = Rijndael()
JsonFile = JsonTools(_FILEPATH)
Domain_MAPPINGS = os.environ["DOMAIN_MAPPINGS"]
data = JsonFile.Deserialize()
request = LdapRequest(data)
isPing = True if request.ping != None else False
response = LdapResponse()
dnRegexString = "^\s*?(cn\s*=|ou\s*=|dc\s*=)"
print(request.searchValue)
r2 = re.compile(dnRegexString, re.IGNORECASE)
guid_list = []

if request.Crypto().text != None:
    crypto = LdapUtils.ApplyDefaultandValidate(crypto=request.Crypto())
    print(crypto.text, crypto.passphrase, crypto.salt, crypto.iv)
    response.message = cryptography.Encrypt(crypto.text, crypto.passphrase, crypto.salt, crypto.iv)
    test = cryptography.Decrypt("3TBCF+kzaX3Qnjv3CLLmywI8nZB9SAswjE3CAaG4A4P10+kPAJ/1fOEu7TcBhW0D2UJt2kEpQuWwaMsLFrXONA==", crypto.passphrase, crypto.salt, crypto.iv)
    print(test)
    response = toJson_Ping_or_Crypto(response)
elif isPing:
    response.message = "Hello From MyriAD."
    response = toJson_Ping_or_Crypto(response)
    if request.Ping() == PingType.Echo:
        print("Ping")
else:
    try:
        print("In Try Block:\n")
        LdapUtils.ApplyDefaultsAndValidate(request)
        searchstring = LdapUtils.GetSearchString(request)
        ldap = LDapServer(request.config.server_name, request.config.port, request.config.ssl, request.config.maxRetries, request.config.maxPageSize, request.config.followReferrals, request.config.returnTypes)
        # if request.object_type != None and request.MultipleSearches != None:
        #     raise Exception("Warning: Myriad currently does not support this type of call: Union with objectType")
        # LdapUtils.CheckforError(request)
        print("SearchString:",searchstring)
        print("SearchBase:", request.searchBase)
        print("Creating LDAP Server:")
        if request.config.Token_type == "Server":
            ldap.Connect(request.config, request=request)
            request.object_type = request.ObjectType()
            request.searchScope = request.SearchScope()
            response = ldap.Search(request=request, searchFilter=searchstring, attributes=request.attributes, searchScope=request.searchScope, maxResults=request.maxResults, nextTokenStr=request.nextToken)
            ldap.Disconnect()
        elif request.config.Token_type == "Client":
            ldap.Connect_bonsai(request.config, request=request)
            request.object_type = request.ObjectType()
            request.searchScope = request.SearchScope()
            response = ldap.Search2(request=request, searchFilter=searchstring, attributes=request.attributes, searchScope=request.searchScope, maxResults=request.maxResults, nextTokenStr=request.nextToken)
            ldap.Disconnect_bonsai()
        else:
            raise Exception("Token Type is Invalid")
        print("Exiting Try Block")
    except Exception as e:
        print("error", e)
        response = ldap.ReturnError(e, request.config, request=request)
print(JsonTools().Serialize(response, True))
