from flask import Flask
import json
import boto3
from flask import request
from Zephyr_Directory_Ldap_Python.Classes.LdapRequest import LdapRequest
from Zephyr_Directory_Ldap_Python.Classes.LdapResponse import LdapResponse
from Zephyr_Directory_Ldap_Python.Classes.LdapConfig import LdapConfig
from Zephyr_Directory_Ldap_Python.Utilities.LdapUtils import LdapUtils
from Zephyr_Directory_Ldap_Python.Utilities.JsonTools import JsonTools
from Zephyr_Crypto_Python.Rijndael import Rijndael

app = Flask(__name__)

def create_json(objectType, value):
    rq = {
        "domain": request.args.get('domain') if request.args.get('domain') else None,
        "searchBase": request.args.get('searchBase') if request.args.get('searchBase') else None,
        "searchScope": request.args.get('searchScope') if request.args.get('searchScope') else None,
        "maxResults": request.args.get('maxResults') if request.args.get('maxResults') else None,
        "nextToken": request.args.get('nextToken') if request.args.get('nextToken') else None,
        "objectType": objectType,
        "attributes": request.args.get('attrs').split(',') if request.args.get('attrs') else None,
        "searchValue": value
    }
    if request.args.get('maxPageSize'):
        rq["config"] = {"maxPageSize": request.args.get('maxPageSize')}
    filtered = {k: v for k, v in rq.items() if v is not None}
    rq.clear()
    rq.update(filtered)
    return rq

@app.route('/GET/<string:objectType>/<string:value>/', methods=['GET'])
def Get(objectType, value):
    #set($inputRoot = $input.path('$'))
    #set($attrs = $method.request.multivaluequerystring.attr)
    #set($domain = $method.request.querystring.domain)
    #set($maxPageSize = $method.request.querystring.maxPageSize)
    #set($maxResults = $method.request.querystring.maxResults)
    #set($nextToken = $method.request.querystring.nextToken)
    #set($searchScope = $method.request.querystring.searchScope)
    #set($searchBase = $method.request.querystring.searchBase)
    #set($searchValue = $util.escapeJavaScript($util.urlDecode($input.params('value'))))
    #set($jobID = $method.request.querystring.jobID)
    # {
    #   #if($domain != "")"domain": "$domain",#end
    #   #if($searchBase != "")"searchBase": "$searchBase",#end
    #   #if($searchScope != "")"searchScope": "$searchScope",#end
    #   #if($maxResults != "")"maxResults": "$maxResults",#end
    #   #if($nextToken != "")"nextToken": "$nextToken",#end
    #   "objectType": "$util.urlDecode($input.params('type'))",
    #   #foreach ($attr in $attrs)#if($foreach.count == 1)"attributes": [#end"$attr"#if($foreach.hasNext),#else],#end#end
    #   #if($maxPageSize != "")"config": { "maxPageSize": "$maxPageSize" },#end
    #   "searchValue": "$searchValue"
    # }
    rq = create_json(objectType, value)
    lambdaClient = boto3.client('lambda', region_name='us-east-2')
    myriad_request = LdapRequest(rq)
    cryptography = Rijndael()
    response = LdapResponse()
    test_config = LdapUtils.ApplyDefaulsAndValidate_config(myriad_request.Config())
    isPing = True if myriad_request.ping != None else False
    response = LdapRequest.MyriAD_Search(myriad_request,response,cryptography,test_config, lambdaClient, rq, isPing)
    return response

@app.route('/search', methods=['POST'])
def Search():
    content_type = request.headers.get('Content-Type')
    if (content_type == 'application/json'):
        lambdaClient = boto3.client('lambda', region_name='us-east-2')
        myriad_request = LdapRequest(request.json)
        cryptography = Rijndael()
        response = LdapResponse()
        test_config = LdapUtils.ApplyDefaulsAndValidate_config(myriad_request.Config())
        isPing = True if myriad_request.ping != None else False
        response = LdapRequest.MyriAD_Search(myriad_request,response,cryptography,test_config, lambdaClient, request.json, isPing)
        return json.dumps(obj=response,indent=4)
    else:
        return 'Content-Type not supported!'

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=105)