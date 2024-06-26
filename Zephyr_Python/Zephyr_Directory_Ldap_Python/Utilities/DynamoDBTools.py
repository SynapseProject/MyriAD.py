from Zephyr_Directory_Ldap_Python.Classes.LdapResponse import LdapResponse
from datetime import datetime
from uuid import uuid4
from sys import getsizeof
from boto3.dynamodb.conditions import Key
from boto3.dynamodb.conditions import Attr
import time
import boto3
import json
import os

class DynamoDBTools():
    def add_entry(partitionKey, sortKey, unix, RecordsID = ""):
        dynamodb = boto3.resource('dynamodb')
        dynamoTableName = os.environ['Myriad_Batch_Request_Table']
        tableName = dynamodb.Table(dynamoTableName)
        Record = {
            "JobID": partitionKey,
            "TotalRecords": 0,
            "Completed": "In Progress",
            "recordsID": RecordsID,
            "Timestamp": sortKey,
            "expireAt": unix
        }
        try:
            with tableName.batch_writer() as batch:
                batch.put_item(Item=Record)
        except Exception as e:
            raise e
            
    def update_entry(response, event):
        updated_totalRecords = response["totalRecords"] if "records" in response.keys() else 0
        updated_message = response["message"] if "message" in response.keys() else ""
        updated_status = response["status"]
        updated_records = response["records"] if "records" in response.keys() else "None"
        DynamoDBTools.write_to_records_Table(updated_records,event)
        dynamodb = boto3.resource('dynamodb')
        dynamoTableName = os.environ['Myriad_Batch_Request_Table']
        print(getsizeof(updated_records))
        if updated_status == "Success":
            table = dynamodb.Table(dynamoTableName)
            # table.update_item(Key={'JobID': event["jobID"]}, UpdateExpression='set TotalRecords = :totalRecords', ExpressionAttributeValues={':totalRecords': updated_totalRecords}, ReturnValues="UPDATED_NEW")
            table.update_item(Key={'JobID': event["jobID"]}, UpdateExpression='set Completed = :status', ExpressionAttributeValues={':status': updated_status}, ReturnValues="UPDATED_NEW")
            # table.update_item(Key={'JobID': event["jobID"]}, UpdateExpression='set RecordsID = :updated_records', ExpressionAttributeValues={':updated_records': updated_records}, ReturnValues="UPDATED_NEW")
            # table.update_item(Key={'JobID': event["jobID"]}, UpdateExpression='set Message = :updated_message', ExpressionAttributeValues={':updated_message': updated_message}, ReturnValues="UPDATED_NEW")
        else:
            table = dynamodb.Table(dynamoTableName)
            table.update_item(Key={'JobID': event["jobID"]}, UpdateExpression='set TotalRecords = :totalRecords', ExpressionAttributeValues={':totalRecords': updated_totalRecords}, ReturnValues="UPDATED_NEW")
            table.update_item(Key={'JobID': event["jobID"]}, UpdateExpression='set Completed = :status', ExpressionAttributeValues={':status': updated_status}, ReturnValues="UPDATED_NEW")
            table.update_item(Key={'JobID': event["jobID"]}, UpdateExpression='set Message = :updated_message', ExpressionAttributeValues={':updated_message': updated_message}, ReturnValues="UPDATED_NEW")

    def decrease_size(records, MB = False, GB = False, KB = False):
        if MB:
            print("MB")
            records.pop()
            size = DynamoDBTools.check_size(records)
            print(records[-1])
        elif GB:
            print("GB")
            records.pop()
            size = DynamoDBTools.check_size(records)
        elif KB:
            print("KB")
            print(records[-1])
            records.pop()
            size = DynamoDBTools.check_size(records)
        return size
    
    def check_size(records):
        size = getsizeof(records)
        if size < 1024:
            memory_size = f"{size} bytes"
        elif size < pow(1024,2):
            number = round(size/1024, 2)
            if number >= 1:
                 memory_size = DynamoDBTools.decrease_size(records, KB = True)
            # memory_size =  f"{round(size/1024, 2)} KB"
        elif size < pow(1024,3):
            number = round(size/(pow(1024,2)), 2)
            if number >= 6:
                memory_size = DynamoDBTools.decrease_size(records, MB = True)
            else:
                memory_size = f"{round(size/(pow(1024,2)), 2)} MB"
        elif size < pow(1024,4):
            number = round(size/(pow(1024,3)), 2)
            memory_size = DynamoDBTools.decrease_size(records, GB = True)
            # Split records
            # memory_size = f"{round(size/(pow(1024,3)), 2)} GB"
        return memory_size
        
    
    def InvokeLambda(lambdaClient, event):
        event["config"]["batch"] = True
        event["config"]["retrieval"] = True
        jobID = uuid4()
        RecordsID = uuid4().hex[0:6]
        timestamp = datetime.now()
        unix_time = int(time.time()+int(os.environ["TimeToLive"])* 24 * 60 * 60)
        print(unix_time)
        payload_input = {
            "jobID": f"{jobID}",
            "recordsID": f"{RecordsID}",
            "Timestamp": f"{timestamp}",
            "expireAt": unix_time
        }
        event["jobID"] = f"{jobID}"
        event["recordsID"] = f"{RecordsID}"
        event["Timestamp"] =  f"{timestamp}"
        event["expireAt"] = unix_time
        print(json.dumps(event))
        response = lambdaClient.invoke(
        FunctionName = 'arn:aws:lambda:us-east-2:801115126580:function:myriad-core-dev',
        InvocationType= 'Event',
        Payload= json.dumps(event)
        )
        payload_response = {
            "statusCode": 200,
            "jobID": f"{jobID}",
            "recordsID": f"{RecordsID}"
        }
        response = payload_response
        return response
        
    def Batch_Retrieval(event, request):
        jobID = event['jobID']
        dynamodb = boto3.resource('dynamodb')
        dynamoTableName = os.environ['Myriad_Batch_Request_Table']
        table = dynamodb.Table(dynamoTableName)
        try:
            check = table.get_item(Key={'JobID': jobID}, AttributesToGet=['recordsID', 'TotalRecords', 'Completed', 'Message'])
            status = check['Item']['Completed']
            response = check['Item']
            if response['Completed'] == "Failure":
                raise Exception(f"Batch Failed with the following error: {response['Message']}")
            else:
                dynamoTableName = os.environ['Myriad_Batch_Records_Table']
                table = dynamodb.Table(dynamoTableName)
                keyConditionExpression=Key('RecordsID').eq(response['recordsID'])
                if request.nextToken != None and request.maxResults != None:
                    maxResultsFilter = Key('RecordNumber').between(request.nextToken+1,request.nextToken+request.maxResults)
                elif request.nextToken == None and request.maxResults != None:
                    maxResultsFilter = Key('RecordNumber').lte(request.maxResults)
                elif request.nextToken != None and request.maxResults == None:
                    maxResultsFilter = Key('RecordNumber').gt(request.nextToken)
                else:
                    maxResultsFilter = Key('RecordNumber').lte(response["TotalRecords"])
                response2 = table.query(
                    KeyConditionExpression = keyConditionExpression & maxResultsFilter,
                    ProjectionExpression='#r',
                    ExpressionAttributeNames = {'#r': 'Record'}
                    # Limit = request.maxResults
                )
                # print(response2)
                records_list = []
                for i in response2["Items"]:
                    try:
                        records_list.append({"attributes": i["Record"]["attributes"], "dn": i["Record"]["dn"]})
                    except:
                        records_list.append({"Attributes": i["Record"]["attributes"], "dn": i["Record"]["DistinguishedName"]})
                # print(records_list)                
                records = {"records": records_list}
                if response2["ScannedCount"] < response["TotalRecords"]:
                    if request.nextToken != None:
                        if request.nextToken + response2["ScannedCount"] < response["TotalRecords"]:
                            records["nextToken"] = response2["ScannedCount"] + request.nextToken
                    else:
                        records["nextToken"] = len(response2['Items'])
                print(records)
                    
        except Exception as e:
            response = {"message": f"{e}"}
            return response
        records_size_before = records["records"]
        records["Size"] = DynamoDBTools.check_size(records["records"])
        if len(records["records"]) != records_size_before:
            records["nextToken"] = len(records["records"])
            records["message"] = "Records was resized to comply with the API's 6MB response limit."
        return records
        
    def write_to_records_Table(records, event):
        dynamodb_Records = boto3.resource('dynamodb')
        dynamo_Records_TableName = os.environ['Myriad_Batch_Records_Table']
        table_Records_Name = dynamodb_Records.Table(dynamo_Records_TableName)
        dbRecords = []
        index = 1
        if records != "None":
            for record in records:
                recordNumber = index
                Entry = {
                    "RecordsID": event["recordsID"],
                    "RecordNumber": recordNumber,
                    "Record": record,
                    "Timestamp": event["Timestamp"],
                    "expireAt": event["expireAt"]
                }
                index = index + 1
                dbRecords.append(Entry)
            print(dbRecords)
            try:
                dynamo_Records_TableName2 = os.environ['Myriad_Batch_Request_Table']
                table_Requests_Name = dynamodb_Records.Table(dynamo_Records_TableName2)
                with table_Records_Name.batch_writer() as batch:
                    for dbRecord in dbRecords:
                        table_Requests_Name.update_item(Key={'JobID': event["jobID"]}, UpdateExpression='set TotalRecords = :totalRecords', ExpressionAttributeValues={':totalRecords': dbRecord['RecordNumber']}, ReturnValues="UPDATED_NEW")
                        batch.put_item(Item=dbRecord)
            except Exception as e:
                raise e