import boto3
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
                    msg = {}
                    msg['quota'] = str(os.environ['LUNKER_LIMIT'])
                else:
                    code = 403
                    msg = {}
                    msg['invalid'] = str(event['add'])
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
                            msg = {}
                            msg['added'] = str(event['add'])
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
                            msg = {}
                            msg['added'] = str(event['add'])
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
                            msg = {}
                            msg['added'] = str(event['add'])
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

            elif key.lower() == 'cidr':

                code = 403
                msg = {}
                msg['invalid'] = str(event['cidr'])
                try:
                    hostmask = event['cidr'].split('/')
                    if ipaddress.ip_network(hostmask[0]).version == 4:
                        table.put_item(
                            Item = {
                                'pk': 'CIDR#',
                                'sk': 'CIDR#IPV4#'+str(event['cidr']),
                                'cidr': str(event['cidr'])
                            }
                        )
                        code = 200
                        msg = {}
                        msg['added'] = str(event['cidr'])
                except:
                    pass
                try:
                    hostmask = event['cidr'].split('/')
                    if ipaddress.ip_network(hostmask[0]).version == 6:
                        table.put_item(
                            Item = {
                                'pk': 'CIDR#',
                                'sk': 'CIDR#IPV6#'+str(event['cidr']),
                                'cidr': str(event['cidr'])
                            }
                        )
                        code = 200
                        msg = {}
                        msg['added'] = str(event['cidr'])
                except:
                    pass

            elif key.lower() == 'delete':

                code = 200
                msg = {}
                msg['deleted'] = str(event['delete'])

                if event['delete'] == 'all':
                    rows = primarykey('IOC#')
                    for row in rows:
                        table.delete_item(
                            Key = {
                                'pk': row['pk'],
                                'sk': row['sk']
                            }
                        )
                elif event['delete'] == 'as':
                    rows = primarykey('AS#')
                    for row in rows:
                        table.delete_item(
                            Key = {
                                'pk': row['pk'],
                                'sk': row['sk']
                            }
                        )
                elif event['delete'] == 'cidr':
                    rows = primarykey('CIDR#')
                    for row in rows:
                        table.delete_item(
                            Key = {
                                'pk': row['pk'],
                                'sk': row['sk']
                            }
                        )
                elif event['delete'] == 'dns':
                    rows = sortkey('IOC#', 'IOC#DNS#')
                    for row in rows:
                        table.delete_item(
                            Key = {
                                'pk': row['pk'],
                                'sk': row['sk']
                            }
                        )
                elif event['delete'] == 'ipv4':
                    rows = sortkey('IOC#', 'IOC#IPV4#')
                    for row in rows:
                        table.delete_item(
                            Key = {
                                'pk': row['pk'],
                                'sk': row['sk']
                            }
                        )
                elif event['delete'] == 'ipv6':
                    rows = sortkey('IOC#', 'IOC#IPV6#')
                    for row in rows:
                        table.delete_item(
                            Key = {
                                'pk': row['pk'],
                                'sk': row['sk']
                            }
                        )

            elif key.lower() == 'handle':

                cidrlist = []
                existing = primarykey('AS#')
                existing = [x['cidr'] for x in existing]

                headers = {'User-Agent': 'Lunker Zero a.k.a. LZ (https://github.com/jblukach/lunkerzero)'}
                r = requests.get('https://rdap.arin.net/registry/entity/'+str(event['handle'].upper()), headers=headers)
                data = r.json()

                code = 200
                msg = {}
                msg['added'] = []
                msg['removed'] = []

                for item in data['networks']:

                    if item['ipVersion'] == 'v4':

                        value = item['cidr0_cidrs'][0]['v4prefix']+'/'+str(item['cidr0_cidrs'][0]['length'])
                        cidrlist.append(value)

                        if value not in existing:

                            table.put_item(
                                Item = {
                                    'pk': 'AS#',
                                    'sk': 'AS#IPV4#'+value,
                                    'name': data['autnums'][0]['handle'],
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
                                    'name': data['autnums'][0]['handle'],
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
                msg = {}
                if event['list'].lower() == 'as':
                    values = primarykey('AS#')
                    msg['list'] = [x['cidr'] for x in values]
                elif event['list'].lower() == 'cidr':
                    values = primarykey('CIDR#')
                    msg['list'] = [x['cidr'] for x in values]
                elif event['list'].lower() == 'dns':
                    values = sortkey('IOC#', 'IOC#DNS#')
                    msg['list'] = [x['ioc'] for x in values]
                elif event['list'].lower() == 'ipv4':
                    values = sortkey('IOC#', 'IOC#IPV4#')
                    msg['list'] = [x['ioc'] for x in values]
                elif event['list'].lower() == 'ipv6':
                    values = sortkey('IOC#', 'IOC#IPV6#')
                    msg['list'] = [x['ioc'] for x in values]
                else:
                    values = primarykey('IOC#')
                    msg['list'] = [x['ioc'] for x in values]

            elif key.lower() == 'remove':

                code = 403
                msg = {}
                msg['failure'] = str(event['remove'])
                try:
                    if ipaddress.ip_network(event['remove']).version == 4:
                        table.delete_item(
                            Key = {
                                'pk': 'IOC#',
                                'sk': 'IOC#IPV4#'+str(event['remove'])
                            }
                        )
                        msg = {}
                        msg['removed'] = str(event['remove'])
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
                        msg = {}
                        msg['removed'] = str(event['remove'])
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
                        msg = {}
                        msg['removed'] = str(event['remove'])
                except:
                    pass

    except Exception as e:
        msg = 'Where the Internet Ends'
        code = 404

    return {
        'statusCode': code,
        'body': msg
    }