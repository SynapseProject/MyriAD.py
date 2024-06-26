from Zephyr_Crypto_Python.Rijndael import Rijndael
from Zephyr_Directory_Ldap_Python.Ldap_Server import LDapServer
from Zephyr_Directory_Ldap_Python.Classes.LdapRequest import LdapRequest
from Zephyr_Directory_Ldap_Python.Classes.LdapResponse import LdapResponse
from Zephyr_Directory_Ldap_Python.Utilities.LdapUtils import LdapUtils
from Zephyr_Directory_Ldap_Python.Utilities.DynamoDBTools import DynamoDBTools
import boto3


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
    isPing = True if request.ping != None else False
    response = LdapRequest.MyriAD_Search(request,response,cryptography,test_config, lambdaClient, event, isPing)
    return response
