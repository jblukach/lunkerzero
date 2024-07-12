import boto3
import ipaddress
import json
import os
import netaddr
import sqlite3
from boto3.dynamodb.conditions import Key
from censys.search import CensysHosts
from datetime import datetime, timezone

s3 = boto3.client('s3')
sns = boto3.client('sns')
ssm = boto3.client('ssm')
securityhub = boto3.client('securityhub')

dynamodb = boto3.resource('dynamodb')
table = dynamodb.Table(os.environ['DYNAMODB_TABLE'])

def alertnotify(title, description):

    account = os.environ['AWS_ACCOUNT']
    fish = os.environ['LUNKER_FISH']
    region = os.environ['REGION']

    now = datetime.now(timezone.utc).isoformat().replace('+00:00','Z')

    securityhub.batch_import_findings(
        Findings = [
            {
                "SchemaVersion": "2018-10-08",
                "Id": region+"/"+account+"/"+fish,
                "ProductArn": "arn:aws:securityhub:"+region+":"+account+":product/"+account+"/default", 
                "GeneratorId": fish,
                "AwsAccountId": account,
                "CreatedAt": now,
                "UpdatedAt": now,
                "Title": title,
                "Description": description,
                "Resources": [
                    {
                        "Type": "AwsLambda",
                        "Id": "arn:aws:lambda:"+region+":"+account+":function:"+fish
                    }
                ],
                "FindingProviderFields": {
                    "Confidence": 100,
                    "Severity": {
                        "Label": "MEDIUM"
                    },
                    "Types": [
                        "security/lunkerzero"
                    ]
                }
            }
        ]
    )

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

def handler(event, context):

    keys = event.keys()

    for key in keys:

        if key.lower() == 'censys':

            if event[key].lower() == 'search':

                asns = sortkey('AS#','AS#')
                asns = [x['name'][2:] for x in asns]
                asns = list(set(asns))

                if len(asns) == 1:

                    api = ssm.get_parameter(Name='/censys/api', WithDecryption=True)['Parameter']['Value']
                    key = ssm.get_parameter(Name='/censys/key', WithDecryption=True)['Parameter']['Value']

                    os.environ['CENSYS_API_ID'] = api
                    os.environ['CENSYS_API_SECRET'] = key

                    h = CensysHosts()

                    query = h.search(
                        'autonomous_system.asn: '+asns[0],
                        per_page = 100,
                        pages = 100,
                        fields = [
                            'services.port'
                        ]
                    )

                    ports = sortkey('PORT#','PORT#')
                    ports = [x['sk'] for x in ports]

                    opened = []

                    for page in query:

                        for address in page:

                            for port in address['services']:

                                opened.append('PORT#'+str(port['port'])+'#IP#'+str(address['ip']))

                                if 'PORT#'+str(port['port'])+'#IP#'+str(address['ip']) not in ports:

                                    table.put_item(
                                        Item = {
                                            'pk': 'PORT#',
                                            'sk': 'PORT#'+str(port['port'])+'#IP#'+str(address['ip']),
                                            'address': str(address['ip']),
                                            'port': str(port['port'])
                                        }
                                    )
                                    alertnotify('PORT Opened', str(address['ip'])+':'+str(port['port']))

                    for address in ports:

                        if address not in opened:

                            table.delete_item(Key={'pk': 'PORT#', 'sk': address})
                            output = address.split('#')
                            alertnotify('PORT Closed', output[3]+':'+output[1])

        elif key.lower() == 'osint':

            if event[key].lower() == 'dns':

                addresses = []

                iocs = sortkey('IOC#','IOC#DNS#')
                iocs = [x['ioc'] for x in iocs]

                for ioc in iocs:
                    addresses.append(ioc)

                s3.download_file(os.environ['S3_BUCKET'], 'dns.txt', '/tmp/dns.txt')

                with open('/tmp/dns.txt', 'r') as f:
                    comparison = f.read().splitlines()

                matchlist = list(set(addresses) & set(comparison))

                artifacts = sortkey('OSINT#','OSINT#DNS#')
                artifacts = [x['osint'] for x in artifacts]

                for match in matchlist:
                    if match not in artifacts:
                        table.put_item(
                            Item = {
                                'pk': 'OSINT#',
                                'sk': 'OSINT#DNS#'+match,
                                'osint': match
                            }
                        )
                        alertnotify('OSINT Detection', match)

                for address in artifacts:

                    if address not in matchlist:

                        table.delete_item(Key={'pk': 'OSINT#', 'sk': 'OSINT#DNS#'+address})
                        alertnotify('OSINT Resolved', address)

            elif event[key].lower() == 'ipv4':

                addresses = []

                cidrs = sortkey('AS#','AS#IPV4#')
                cidrs = [x['cidr'] for x in cidrs]

                for cidr in cidrs:
                    network = netaddr.IPNetwork(cidr)
                    for address in network:
                        addresses.append(str(address))

                cidrs = sortkey('CIDR#','CIDR#IPV4#')
                cidrs = [x['cidr'] for x in cidrs]

                for cidr in cidrs:
                    network = netaddr.IPNetwork(cidr)
                    for address in network:
                        addresses.append(str(address))

                iocs = sortkey('IOC#','IOC#IPV4#')
                iocs = [x['ioc'] for x in iocs]

                for ioc in iocs:
                    addresses.append(ioc)

                s3.download_file(os.environ['S3_BUCKET'], 'ipv4.txt', '/tmp/ipv4.txt')

                with open('/tmp/ipv4.txt', 'r') as f:
                    comparison = f.read().splitlines()

                matchlist = list(set(addresses) & set(comparison))

                artifacts = sortkey('OSINT#','OSINT#IPV4#')
                artifacts = [x['osint'] for x in artifacts]

                for match in matchlist:
                    if match not in artifacts:
                        table.put_item(
                            Item = {
                                'pk': 'OSINT#',
                                'sk': 'OSINT#IPV4#'+match,
                                'osint': match
                            }
                        )
                        alertnotify('OSINT Detection', match)

                for address in artifacts:

                    if address not in matchlist:

                        table.delete_item(Key={'pk': 'OSINT#', 'sk': 'OSINT#IPV4#'+address})
                        alertnotify('OSINT Resolved', address)

            elif event[key].lower() == 'ipv6':

                if os.path.exists('/tmp/distillery.sqlite3'):
                    os.remove('/tmp/distillery.sqlite3')

                db = sqlite3.connect('/tmp/distillery.sqlite3')
                db.execute('CREATE TABLE IF NOT EXISTS distillery (pk INTEGER PRIMARY KEY, cidr  BLOB, firstip INTEGER, lastip INTEGER)')
                db.execute('CREATE INDEX firstip_index ON distillery (firstip)')
                db.execute('CREATE INDEX lastip_index ON distillery (lastip)')

                cidrs = sortkey('AS#','AS#IPV6#')
                cidrs = [x['cidr'] for x in cidrs]

                for cidr in cidrs:

                    netrange = ipaddress.IPv6Network(cidr)
                    first, last = netrange[0], netrange[-1]
                    firstip = int(ipaddress.IPv6Address(first))
                    lastip = int(ipaddress.IPv6Address(last))

                    db.execute('INSERT INTO distillery (cidr, firstip, lastip) VALUES (?, ?, ?)', (str(cidr), str(firstip), str(lastip)))

                cidrs = sortkey('CIDR#','CIDR#IPV6#')
                cidrs = [x['cidr'] for x in cidrs]

                for cidr in cidrs:

                    netrange = ipaddress.IPv6Network(cidr)
                    first, last = netrange[0], netrange[-1]
                    firstip = int(ipaddress.IPv6Address(first))
                    lastip = int(ipaddress.IPv6Address(last))

                    db.execute('INSERT INTO distillery (cidr, firstip, lastip) VALUES (?, ?, ?)', (str(cidr), str(firstip), str(lastip)))

                iocs = sortkey('IOC#','IOC#IPV6#')
                iocs = [x['ioc'] for x in iocs]

                for ioc in iocs:

                    netrange = ipaddress.IPv6Network(ioc)
                    first, last = netrange[0], netrange[-1]
                    firstip = int(ipaddress.IPv6Address(first))
                    lastip = int(ipaddress.IPv6Address(last))

                    db.execute('INSERT INTO distillery (cidr, firstip, lastip) VALUES (?, ?, ?)', (str(ioc), str(firstip), str(lastip)))

                db.commit()
                db.close()

                s3.download_file(os.environ['S3_BUCKET'], 'ipv6.txt', '/tmp/ipv6.txt')

                with open('/tmp/ipv6.txt', 'r') as f:
                    ipv6s = f.read().splitlines()

                artifacts = sortkey('OSINT#','OSINT#IPV6#')
                artifacts = [x['osint'] for x in artifacts]

                conn = sqlite3.connect('/tmp/distillery.sqlite3')
                c = conn.cursor()

                for ipv6 in ipv6s:

                    intip = int(ipaddress.IPv6Address(ipv6))

                    c.execute("SELECT cidr FROM distillery WHERE firstip <= ? AND lastip >= ?", (str(intip), str(intip)))
                    results = c.fetchall()

                    if len(results) > 0:

                        if ipv6 not in artifacts:

                            table.put_item(
                                Item = {
                                    'pk': 'OSINT#',
                                    'sk': 'OSINT#IPV6#'+str(ipv6),
                                    'osint': str(ipv6)
                                }
                            )
                            alertnotify('OSINT Detection', str(ipv6))

                    else:

                        if ipv6 in artifacts:

                            table.delete_item(Key={'pk': 'OSINT#', 'sk': 'OSINT#IPV6#'+str(ipv6)})
                            alertnotify('OSINT Resolved', str(ipv6))

                conn.close()

    return {
        'statusCode': 200,
        'body': json.dumps('Gone Fishing!')
    }