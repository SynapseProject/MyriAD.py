import os
import re
from win32api import GetFileVersionInfo, LOWORD, HIWORD
from Zephyr_Crypto_Python.Rijndael import Rijndael
from Zephyr_Directory_Ldap_Python.Ldap_Server import LDapServer
from Zephyr_Directory_Ldap_Python.Utilites.JsonTools import JsonTools
from Zephyr_Directory_Ldap_Python.Utilites.LdapUtils import LdapUtils
from Zephyr_Directory_Ldap_Python.Classes.LdapRequest import LdapRequest, PingType
from Zephyr_Directory_Ldap_Python.Classes.LdapResponse import LdapResponse

_FILEPATH  = "Zephyr_Python/Zephyr_Directory_Test/TestFiles/myriad.json"
def toJson_Ping_or_Crypto(response: LdapResponse):
        if response.success == True:
            dictionary = {"success": response.success, "message": str(response.message)}
        return dictionary

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
        print("SearchString:",searchstring)
        print("SearchBase:", request.searchBase)
        print("Creating LDAP Server:")
        ldap = LDapServer(request.config.server_name, request.config.port, request.config.ssl, request.config.maxRetries, request.config.maxPageSize, request.config.followReferrals, request.config.returnTypes)
        ldap.Connect(request.config, request=request)
        print(searchstring)
        request.object_type = request.ObjectType()
        request.searchScope = request.SearchScope()
        print("MaxResults:", request.maxResults)
        print("Attributes :" , request.attributes)
        response = ldap.Search(request=request, searchFilter=searchstring, attributes=request.attributes, searchScope=request.searchScope, maxResults=request.maxResults, nextTokenStr=request.nextToken)
        ldap.Disconnect()
        print("Exiting Try Block")
    except Exception as e:
        print("error", e)
        response = ldap.ReturnError(e, request.config, request=request)
print(JsonTools().Serialize(response, True))
