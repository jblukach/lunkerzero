import boto3
import json
import os

def handler(event, context):

    crawlid = event['Records'][0]['s3']['object']['key'][:-5]
    crawlid = crawlid.split('/')[1]
    os.environ['CRAWL_ID'] = crawlid
    print('Crawl ID: ' + crawlid)

    subids = []
    subids.append(os.environ['SUBNET_ID'])
    
    sgids = []
    sgids.append(os.environ['SECURITY_GROUP'])
    
    ecs = boto3.client('ecs')
    
    response = ecs.run_task(
        cluster=os.environ['CLUSTER_NAME'],
        launchType = 'FARGATE',
        taskDefinition=os.environ['TASK_DEFINITION'],
        overrides={
            'containerOverrides': [
                {
                    'name': os.environ['CONTAINER_NAME'],
                    'environment': [
                        {
                            'name': 'CRAWL_ID',
                            'value': os.environ['CRAWL_ID']
                        },
                        {
                            'name': 'S3_DOWNLOAD',
                            'value': os.environ['S3_DOWNLOAD']
                        },
                        {
                            'name': 'S3_INSPECT',
                            'value': os.environ['S3_INSPECT']
                        }
                    ]
                }
            ]
        },
        count = 1,
        platformVersion='LATEST',
        networkConfiguration={
            'awsvpcConfiguration': {
                'subnets': subids,
                'securityGroups': sgids,
                'assignPublicIp': 'ENABLED'
            }
        }
    )

    return {
        'statusCode': 200,
        'body': json.dumps('Process WACZ Archive')
    }