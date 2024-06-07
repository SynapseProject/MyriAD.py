from Zephyr_Crypto_Python.Rijndael import Rijndael
from Zephyr_Directory_Ldap_Python.Ldap_Server import LDapServer
from Zephyr_Directory_Ldap_Python.Classes.LdapRequest import LdapRequest, PingType
from Zephyr_Directory_Ldap_Python.Classes.LdapResponse import LdapResponse
from Zephyr_Directory_Ldap_Python.Classes.LdapConfig import LdapConfig, OutputTypes
from Zephyr_Directory_Ldap_Python.Utilities.LdapUtils import LdapUtils
from Zephyr_Directory_Ldap_Python.Utilities.DynamoDBTools import DynamoDBTools
from uuid import uuid4
from datetime import datetime
import json
import time
import boto3
import os


def toJson_Ping_or_Crypto(response: LdapResponse):
    if response.success == True:
        dictionary = {"success": response.success, "message": str(response.message)}
    return dictionary

lambdaClient = boto3.client('lambda')
def lambda_handler(event, context):
    # TODO implement
    batch = False
    cryptography = Rijndael()
    response = LdapResponse()
    request = LdapRequest(event)
    test_config = LdapUtils.ApplyDefaulsAndValidate_config(request.Config())
    print(test_config.batch)
    isPing = True if request.ping != None else False
    if test_config.batch == True and test_config.retrieval == False:
        response = DynamoDBTools.InvokeLambda(lambdaClient, event)
    elif test_config.batch == False and test_config.retrieval == True:
        print("Here")
        response = DynamoDBTools.Batch_Retrieval(event, request)
        # print(response)
    else:
        if request.Crypto().text != None:
            crypto = LdapUtils.ApplyDefaultandValidate(crypto=request.Crypto())
            response.message = cryptography.Encrypt(crypto.text, crypto.passphrase, crypto.salt, crypto.iv)
            response = toJson_Ping_or_Crypto(response)
        elif isPing:
            response.message = "Hello From MyriAD"
            response = toJson_Ping_or_Crypto(response)
        else:
            try:
                LdapUtils.ApplyDefaultsAndValidate(request)
                searchstring = LdapUtils.GetSearchString(request)
                ldap = LDapServer(request.config.server_name, request.config.port, request.config.ssl, request.config.maxRetries, request.config.maxPageSize, request.config.followReferrals, request.config.returnTypes, batch)
                if request.config.Token_type == "Server" or request.config.Token_type == "Client" or request.config.server_name_present == True:
                    if request.config.batch == True and request.config.retrieval == True:
                        partitionKey = event["jobID"]
                        timestamp = event["Timestamp"]
                        RecordsID = event["recordsID"]
                        unix = event["expireAt"]
                        DynamoDBTools.add_entry(partitionKey, timestamp, RecordsID, unix)
                    ldap.Connect(request.config, request=request)
                    request.object_type = request.ObjectType()
                    request.searchScope = request.SearchScope()
                    request.config.outputType = request.config.OutputType()
                    response = ldap.Search(request=request, searchFilter=searchstring, attributes=request.attributes, searchScope=request.searchScope, maxResults=request.maxResults, nextTokenStr=request.nextToken)
                    ldap.Disconnect()
                else:
                    raise Exception("TokenType must be set to Server or Client")
            except Exception as e:
                response = ldap.ReturnError(e, request.config, request=request)
                if request.config.batch == True and request.config.retrieval == True:
                    partitionKey = event["jobID"]
                    timestamp = event["Timestamp"]
                    RecordsID = event["recordsID"]
                    DynamoDBTools.add_entry(partitionKey, timestamp, RecordsID)
            if request.config.batch == True and request.config.retrieval == True:
                DynamoDBTools.update_entry(response, event)
    return response
