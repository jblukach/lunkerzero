import boto3
import json
import ipaddress
import os
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

    try:

        keys = event.keys()

        for key in keys:

            if key.lower() == 'add':

                count = primarykey('IOCS#')
                if len(count) >= int(os.environ['LUNKER_LIMIT']):
                    code = 403
                    msg = 'Maximum Quota Reached'
                else:
                    code = 403
                    msg = 'Invalid '+str(event['add'])
                    try:
                        if ipaddress.ip_network(event['add']).version == 4:
                            table.put_item(
                                Item = {
                                    'pk': 'IOCS#',
                                    'sk': 'IOCS#IPV4#'+str(event['add']),
                                    'ioc': str(event['add'])
                                }
                            )
                            code = 200
                            msg = 'Added '+str(event['add'])
                    except:
                        pass
                    try:
                        if ipaddress.ip_network(event['add']).version == 6:
                            table.put_item(
                                Item = {
                                    'pk': 'IOCS#',
                                    'sk': 'IOCS#IPV6#'+str(event['add']),
                                    'ioc': str(event['add'])
                                }
                            )
                            code = 200
                            msg = 'Added '+str(event['add'])
                    except:
                        pass
                    try:
                        tlds = tldlist('TLD#')
                        tlds = [x['sk'] for x in tlds]
                        if event['add'].lower().split('.')[-1] in tlds:
                            if event['add'].lower().startswith('http://'):
                                event['add'] = event['add'][7:]
                            if event['add'].lower().startswith('https://'):
                                event['add'] = event['add'][8:]
                            table.put_item(
                                Item = {
                                    'pk': 'IOCS#',
                                    'sk': 'IOCS#DNS#'+str(event['add'].lower()),
                                    'ioc': str(event['add'].lower())
                                }
                            )
                            code = 200
                            msg = 'Added '+str(event['add'])
                    except:
                        pass

            elif key.lower() == 'list':

                code = 200
                if event['list'].lower() == 'dns':
                    msg = sortkey('IOCS#', 'IOCS#DNS#')
                    msg = [x['ioc'] for x in msg]
                elif event['list'].lower() == 'ipv4':
                    msg = sortkey('IOCS#', 'IOCS#IPV4#')
                    msg = [x['ioc'] for x in msg]
                elif event['list'].lower() == 'ipv6':
                    msg = sortkey('IOCS#', 'IOCS#IPV6#')
                    msg = [x['ioc'] for x in msg]
                else:
                    msg = primarykey('IOCS#')
                    msg = [x['ioc'] for x in msg]

            elif key.lower() == 'remove':

                code = 403
                msg = 'Failure '+str(event['remove'])
                try:
                    if ipaddress.ip_network(event['remove']).version == 4:
                        table.delete_item(
                            Key = {
                                'pk': 'IOCS#',
                                'sk': 'IOCS#IPV4#'+str(event['remove'])
                            }
                        )
                        msg = 'Removed '+str(event['remove'])
                except:
                    pass
                try:
                    if ipaddress.ip_network(event['remove']).version == 6:
                        table.delete_item(
                            Key = {
                                'pk': 'IOCS#',
                                'sk': 'IOCS#IPV6#'+str(event['remove'])
                            }
                        )
                        msg = 'Removed '+str(event['remove'])
                except:
                    pass
                try:
                    tlds = tldlist('TLD#')
                    tlds = [x['sk'] for x in tlds]
                    if event['remove'].lower().split('.')[-1] in tlds:
                        if event['remove'].lower().startswith('http://'):
                            event['remove'] = event['remove'][7:]
                        if event['remove'].lower().startswith('https://'):
                            event['remove'] = event['remove'][8:]
                        table.delete_item(
                            Key = {
                                'pk': 'IOCS#',
                                'sk': 'IOCS#DNS#'+str(event['remove']).lower()
                            }
                        )
                        msg = 'Removed '+str(event['remove'])
                except:
                    pass

    except Exception as e:
        msg = 'Where the Internet Ends'
        code = 404

    return {
        'statusCode': code,
        'body': json.dumps(msg)
    }