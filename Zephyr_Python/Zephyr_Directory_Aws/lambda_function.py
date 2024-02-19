from Zephyr_Crypto_Python.Rijndael import Rijndael
from Zephyr_Directory_Ldap_Python.Ldap_Server import LDapServer
from Zephyr_Directory_Ldap_Python.Classes.LdapRequest import LdapRequest, PingType
from Zephyr_Directory_Ldap_Python.Classes.LdapResponse import LdapResponse
from Zephyr_Directory_Ldap_Python.Classes.LdapConfig import LdapConfig
from Zephyr_Directory_Ldap_Python.Utilities.LdapUtils import LdapUtils

def toJson_Ping_or_Crypto(response: LdapResponse):
    if response.success == True:
        dictionary = {"success": response.success, "message": str(response.message)}
    return dictionary

def lambda_handler(event, context):
    # TODO implement
    cryptography = Rijndael()
    response = LdapResponse()
    request = LdapRequest(event)
    isPing = True if request.ping != None else False
    if request.Crypto().text != None:
        crypto = LdapUtils.ApplyDefaultandValidate(crypto=request.Crypto())
        # _encrypt = cryptography.Encrypt(request.Crypto().text, request.Crypto().passphrase, request.Crypto().salt, request.Crypto().iv)
        response.message = cryptography.Encrypt(crypto.text, crypto.passphrase, crypto.salt, crypto.iv)
        # _decrypt = cryptography.Decrypt("5iG6IK+FzNxP8/o4eVPmlTZRC43975UCJrbqh8eCLqI=", crypto.passphrase, crypto.salt, crypto.iv)
        response = toJson_Ping_or_Crypto(response)
    elif isPing:
        response.message = "Hello From MyriAD"
        response = toJson_Ping_or_Crypto(response)
    else:
        try:
            LdapUtils.ApplyDefaultsAndValidate(request)
            searchstring = LdapUtils.GetSearchString(request)
            ldap = LDapServer(request.config.server_name, request.config.port, request.config.ssl, request.config.maxRetries, request.config.maxPageSize, request.config.followReferrals, request.config.returnTypes)
            # if request.object_type != None and request.MultipleSearches != None:
            #     raise Exception("Warning: Myriad currently does not support this type of call: Union with objectType")
            if request.config.Token_type == "Client":
                ldap.Connect_bonsai(request.config, request=request)
                request.object_type = request.ObjectType()
                request.searchScope = request.SearchScope()
                response = ldap.Search2(request=request, searchFilter=searchstring, attributes=request.attributes, searchScope=request.searchScope, maxResults=request.maxResults, nextTokenStr=request.nextToken)
                ldap.Disconnect_bonsai()
            elif request.config.Token_type == "Server" or request.config.Token_type == "Server/Client" or request.config.server_name_present == True:
                ldap.Connect(request.config, request=request)
                request.object_type = request.ObjectType()
                request.searchScope = request.SearchScope()
                response = ldap.Search(request=request, searchFilter=searchstring, attributes=request.attributes, searchScope=request.searchScope, maxResults=request.maxResults, nextTokenStr=request.nextToken)
                ldap.Disconnect()
        except Exception as e:
            response = ldap.ReturnError(e, request.config, request=request)
    return response
