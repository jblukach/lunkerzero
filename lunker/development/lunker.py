import boto3
import json
import ipaddress
import os
import requests
from boto3.dynamodb.conditions import Key

dynamodb = boto3.resource('dynamodb')
table = dynamodb.Table(os.environ['DYNAMODB_TABLE'])
tldtable = dynamodb.Table(os.environ['DYNAMODB_TLDTABLE'])

def primarykey(pk):
    response = table.query(
        KeyConditionExpression = Key('pk').eq(pk)
    )
    results = response['Items']
    while 'LastEvaluatedKey' in response:
        response = table.query(
            KeyConditionExpression = Key('pk').eq(pk),
            ExclusiveStartKey = response['LastEvaluatedKey']
        )
        results.update(response['Items'])
    return results

def sortkey(pk, sk):
    response = table.query(
        KeyConditionExpression = Key('pk').eq(pk) & Key('sk').begins_with(sk)
    )
    results = response['Items']
    while 'LastEvaluatedKey' in response:
        response = table.query(
            KeyConditionExpression = Key('pk').eq(pk) & Key('sk').begins_with(sk),
            ExclusiveStartKey = response['LastEvaluatedKey']
        )
        results.update(response['Items'])
    return results

def tldlist(pk):
    response = tldtable.query(
        KeyConditionExpression = Key('pk').eq(pk)
    )
    results = response['Items']
    while 'LastEvaluatedKey' in response:
        response = tldtable.query(
            KeyConditionExpression = Key('pk').eq(pk),
            ExclusiveStartKey = response['LastEvaluatedKey']
        )
        results.update(response['Items'])
    return results

def handler(event, context):

    print(event) ### DEBUG ###

    code = 200
    msg = 'Hello from Lunker!'

    return {
        'statusCode': code,
        'body': json.dumps(msg)
    }