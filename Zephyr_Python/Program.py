import boto3
from Zephyr_Directory_Ldap_Python.Ldap_Server import LDapServer
from Zephyr_Directory_Ldap_Python.Classes.LdapRequest import LdapRequest
from Zephyr_Directory_Ldap_Python.Utilities.LdapUtils import LdapUtils
from Zephyr_Crypto_Python.Rijndael import Rijndael
from Zephyr_Directory_Ldap_Python.Utilities.JsonTools import JsonTools
from Zephyr_Directory_Ldap_Python.Classes.LdapResponse import LdapResponse
from Zephyr_Directory_Ldap_Python.Classes.LdapConfig import OutputTypes
from Zephyr_Directory_Ldap_Python.Utilities.DynamoDBTools import DynamoDBTools

_FILEPATH  = "C:/Users/0195tw/OneDrive - BP/Desktop/Github-MyriAD.py/MyriAD.py/Zephyr_Python/Zephyr_Directory_Test/TestFiles/myriad.json"
def toJson_Ping_or_Crypto(response: LdapResponse):
    if response.success == True:
        dictionary = {"success": response.success, "message": str(response.message)}
    return dictionary

lambdaClient = boto3.client('lambda', region_name='us-east-2')
JsonFile = JsonTools(_FILEPATH)
data = JsonFile.Deserialize()

cryptography = Rijndael()
response = LdapResponse()
request = LdapRequest(data)
test_config = LdapUtils.ApplyDefaulsAndValidate_config(request.Config())
isPing = True if request.ping != None else False
response = LdapRequest.MyriAD_Search(request,response,cryptography,test_config, lambdaClient, data, isPing)
try:
    if request.config.outputType == OutputTypes.Json or request.config.outputType == OutputTypes.CSV:
        print(JsonTools().Serialize(response, True))
    else:
        print(response)
except:
    if test_config.outputType == OutputTypes.Json or test_config.outputType == OutputTypes.CSV:
        print(JsonTools().Serialize(response, True))
    else:
        print(response)