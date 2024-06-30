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

    try:

        keys = event.keys()

        for key in keys:

            if key.lower() == 'add':

                count = primarykey('IOC#')
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
                                    'pk': 'IOC#',
                                    'sk': 'IOC#IPV4#'+str(event['add']),
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
                                    'pk': 'IOC#',
                                    'sk': 'IOC#IPV6#'+str(event['add']),
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
                                    'pk': 'IOC#',
                                    'sk': 'IOC#DNS#'+str(event['add'].lower()),
                                    'ioc': str(event['add'].lower())
                                }
                            )
                            code = 200
                            msg = 'Added '+str(event['add'])
                    except:
                        pass

            elif key.lower() == 'as':

                cidrlist = []
                existing = primarykey('AS#')
                existing = [x['cidr'] for x in existing]

                headers = {'User-Agent': 'Lunker Zero a.k.a. LZ (https://github.com/jblukach/lunkerzero)'}
                r = requests.get('https://rdap.arin.net/registry/arin_originas0_networksbyoriginas/'+str(event['as'][2:]), headers=headers)
                data = r.json()

                code = 200
                msg = {}
                msg['added'] = []
                msg['removed'] = []

                for item in data['arin_originas0_networkSearchResults']:

                    if item['ipVersion'] == 'v4':

                        value = item['cidr0_cidrs'][0]['v4prefix']+'/'+str(item['cidr0_cidrs'][0]['length'])
                        cidrlist.append(value)

                        if value not in existing:

                            table.put_item(
                                Item = {
                                    'pk': 'AS#',
                                    'sk': 'AS#IPV4#'+value,
                                    'name': event['as'].upper(),
                                    'cidr': value
                                }
                            )
                            msg['added'].append(value)

                    elif item['ipVersion'] == 'v6':

                        value = item['cidr0_cidrs'][0]['v6prefix']+'/'+str(item['cidr0_cidrs'][0]['length'])
                        cidrlist.append(value)

                        if value not in existing:

                            table.put_item(
                                Item = {
                                    'pk': 'AS#',
                                    'sk': 'AS#IPV6#'+value,
                                    'name': event['as'].upper(),
                                    'cidr': value
                                }
                            )
                            msg['added'].append(value)

                for cidr in existing:

                    if cidr not in cidrlist:

                        hostmask = cidr.split('/')
                        iptype = ipaddress.ip_address(hostmask[0])
                        table.delete_item(Key={'pk': 'AS#', 'sk': 'AS#IPV'+str(iptype.version)+'#'+cidr})
                        msg['removed'].append(cidr)

            elif key.lower() == 'list':

                code = 200
                if event['list'].lower() == 'as':
                    msg = primarykey('AS#')
                    msg = [x['cidr'] for x in msg]
                elif event['list'].lower() == 'dns':
                    msg = sortkey('IOC#', 'IOC#DNS#')
                    msg = [x['ioc'] for x in msg]
                elif event['list'].lower() == 'ipv4':
                    msg = sortkey('IOC#', 'IOC#IPV4#')
                    msg = [x['ioc'] for x in msg]
                elif event['list'].lower() == 'ipv6':
                    msg = sortkey('IOC#', 'IOC#IPV6#')
                    msg = [x['ioc'] for x in msg]
                else:
                    msg = primarykey('IOC#')
                    msg = [x['ioc'] for x in msg]

            elif key.lower() == 'remove':

                code = 403
                msg = 'Failure '+str(event['remove'])
                try:
                    if ipaddress.ip_network(event['remove']).version == 4:
                        table.delete_item(
                            Key = {
                                'pk': 'IOC#',
                                'sk': 'IOC#IPV4#'+str(event['remove'])
                            }
                        )
                        msg = 'Removed '+str(event['remove'])
                except:
                    pass
                try:
                    if ipaddress.ip_network(event['remove']).version == 6:
                        table.delete_item(
                            Key = {
                                'pk': 'IOC#',
                                'sk': 'IOC#IPV6#'+str(event['remove'])
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
                                'pk': 'IOC#',
                                'sk': 'IOC#DNS#'+str(event['remove']).lower()
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