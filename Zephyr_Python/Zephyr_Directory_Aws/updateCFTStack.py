import json
import boto3
import os

def lambda_handler(event, context):
    # TODO implement
    print(event)
    parameters_myriad = [
        {
            'ParameterKey': 'ApiDefaultKeyName',
            'UsePreviousValue': True 
        },
        {
            'ParameterKey': 'ApiDefaultUsagePlanName',
            'UsePreviousValue': True  
        },
        {
            'ParameterKey': 'ApiGatewayId',
            'UsePreviousValue': True 
        },
        {
            'ParameterKey': 'ApiGatewayStageName',
            'UsePreviousValue': True 
        },
        {
            'ParameterKey': 'DeployToStage',
            'UsePreviousValue': True 
        },
        {
            'ParameterKey': 'LambdaCoreRoleArn',
            'UsePreviousValue': True 
        },
        {
            'ParameterKey': 'UpdateMyriadCoreFunctionName',
            'UsePreviousValue': True
        },
        {
            'ParameterKey': 'MyriadCodeBucketKey',
            'UsePreviousValue': True 
        },
        {
            'ParameterKey': 'MyriadCodeBucketName',
            'UsePreviousValue': True 
        },
        {
            'ParameterKey': 'MyriadCoreFunctionName',
            'UsePreviousValue': True 
        },
        {
            'ParameterKey': 'MyriadCoreS3ObjectVersion',
            'UsePreviousValue': True 
        },
        {
            'ParameterKey': 'MyriadEnvDefaultConfig',
            'UsePreviousValue': True 
        },
        {
            'ParameterKey': 'MyriadEnvDomainMapping',
            'UsePreviousValue': True 
        },
        {
            'ParameterKey': 'MyriadEnvReturnTypes',
            'UsePreviousValue': True 
        },
        {
            'ParameterKey': 'MyriadEnvCD1',
            'UsePreviousValue': True
        },
        {
            'ParameterKey': 'MyriadEnvCD2',
            'UsePreviousValue': True
        },
        {
            'ParameterKey': 'MyriadEnvIV',
            'UsePreviousValue': True
        },
        {
            'ParameterKey': 'MyriadEnvPassphrase',
            'UsePreviousValue': True
        },
        {
            'ParameterKey': 'MyriadEnvSaltValue',
            'UsePreviousValue': True
        },
        {
            'ParameterKey': 'MyriadLayerBucketKey',
            'UsePreviousValue': True 
        },
        {
            'ParameterKey': 'MyriadLayerBucketName',
            'UsePreviousValue': True 
        },
        {
            'ParameterKey': 'MyriadLayerS3ObjectVersion',
            'UsePreviousValue': True 
        },
        {
            'ParameterKey': 'MyriadVpcSecurityGroupIds',
            'UsePreviousValue': True 
        },
        {
            'ParameterKey': 'MyriadVpcSubnetIds',
            'UsePreviousValue': True 
        },
        {
            'ParameterKey': 'RootResourceId',
            'UsePreviousValue': True 
        },
        {
            'ParameterKey': 'SecureWithApiKey',
            'UsePreviousValue': True 
        }]
        
    latestVersion = event['Records'][0]['s3']['object']['versionId']
    objectKey = event['Records'][0]['s3']['object']['key']
        
    if 'code/source' in objectKey:
        # stackName = os.environ['']
        parameters_myriad.extend(
            [
                {
                    'ParameterKey': 'MyriadCoreS3ObjectVersion',
                    'ParameterValue': latestVersion
                },
                {
                    'ParameterKey': 'MyriadLayerS3ObjectVersion',
                    'UsePreviousValue': True
                }
            ]
        )
    elif 'code/layers' in objectKey:
        # stackName = os.environ['']
        parameters_myriad.extend(
            [
                {
                    'ParameterKey': 'MyriadLayerS3ObjectVersion',
                    'ParameterValue': latestVersion
                },
                {
                    'ParameterKey': 'MyriadCoreS3ObjectVersion',
                    'UsePreviousValue': True
                }
            ]
        )
    stackName = os.environ['CoreStackName']
    client = boto3.client('cloudformation')
    response = client.update_stack(
        StackName = stackName,
        UsePreviousTemplate = True,
        Parameters = parameters_myriad
    )
    return {
        'statusCode': 200,
        'body': response
    }
