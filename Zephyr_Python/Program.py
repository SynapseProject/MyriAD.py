import os
import re
import boto3
from multiprocessing import Process
from Zephyr_Crypto_Python.Rijndael import Rijndael
from Zephyr_Directory_Ldap_Python.Ldap_Server import LDapServer
from Zephyr_Directory_Ldap_Python.Utilities.JsonTools import JsonTools
from Zephyr_Directory_Ldap_Python.Utilities.LdapUtils import LdapUtils
from Zephyr_Directory_Ldap_Python.Classes.LdapRequest import LdapRequest, PingType
from Zephyr_Directory_Ldap_Python.Classes.LdapResponse import LdapResponse
from Zephyr_Directory_Ldap_Python.Classes.LdapConfig import OutputTypes
from Zephyr_Directory_Ldap_Python.Utilities.DynamoDBTools import DynamoDBTools

_FILEPATH  = "C:/Users/0195tw/OneDrive - BP/Desktop/Github-MyriAD.py/MyriAD.py/Zephyr_Python/Zephyr_Directory_Test/TestFiles/myriad.json"
def toJson_Ping_or_Crypto(response: LdapResponse):
    if response.success == True:
        dictionary = {"success": response.success, "message": str(response.message)}
    return dictionary

# lambdaClient = boto3.client('lambda')
JsonFile = JsonTools(_FILEPATH)
data = JsonFile.Deserialize()

cryptography = Rijndael()
response = LdapResponse()
request = LdapRequest(data)
test_config = LdapUtils.ApplyDefaulsAndValidate_config(request.Config())
print(test_config.batch)
isPing = True if request.ping != None else False
if test_config.batch == True and test_config.retrieval == False:
    response = DynamoDBTools.InvokeLambda(lambdaClient, data)
elif test_config.batch == False and test_config.retrieval == True:
    print("Here")
    response = DynamoDBTools.Batch_Retrieval(data, request)
    # print(response)
else:
    if request.Crypto().text != None:
        crypto = LdapUtils.ApplyDefaultandValidate(crypto=request.Crypto())
        print(crypto.text, crypto.passphrase, crypto.salt, crypto.iv)
        response.message = cryptography.Encrypt(crypto.text, crypto.passphrase, crypto.salt, crypto.iv)
        response = toJson_Ping_or_Crypto(response)
    elif isPing:
        response.message = "Hello From MyriAD."
        response = toJson_Ping_or_Crypto(response)
    else:
        try:
            print("In Try Block:\n")
            LdapUtils.ApplyDefaultsAndValidate(request)
            searchstring = LdapUtils.GetSearchString(request)
            ldap = LDapServer(request.config.server_name, request.config.port, request.config.ssl, request.config.maxRetries, request.config.maxPageSize, request.config.followReferrals, request.config.returnTypes)
            if request.config.Token_type == "Server" or request.config.Token_type == "Client" or request.config.server_name_present == True:
                if request.config.batch == True and request.config.retrieval == True:
                    partitionKey = data["jobID"]
                    timestamp = data["Timestamp"]
                    RecordsID = data["recordsID"]
                    unix = data["expireAt"]
                    DynamoDBTools.add_entry(partitionKey, timestamp, unix, RecordsID)
                ldap.Connect(request.config, request=request)
                request.object_type = request.ObjectType()
                request.searchScope = request.SearchScope()
                request.config.outputType = request.config.OutputType()
                response = ldap.Search(request=request, searchFilter=searchstring, attributes=request.attributes, searchScope=request.searchScope, maxResults=request.maxResults, nextTokenStr=request.nextToken)
                ldap.Disconnect()
            else:
                raise Exception("TokenType must be set to Server or Client or Server/Client")
        except Exception as e:
            response = ldap.ReturnError(e, request.config, request=request)
            if request.config.batch == True and request.config.retrieval == True:
                partitionKey = data["jobID"]
                timestamp = data["Timestamp"]
                RecordsID = data["recordsID"]
                DynamoDBTools.add_entry(partitionKey, timestamp, RecordsID)
        if request.config.batch == True and request.config.retrieval == True:
                DynamoDBTools.update_entry(response, data)
        if request.config.outputType == OutputTypes.Json or request.config.outputType == OutputTypes.CSV:
            print(JsonTools().Serialize(response, True))
        else:
            print(response)
