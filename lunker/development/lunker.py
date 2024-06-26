import json

def handler(event, context):

    code = 200
    msg = {
        'message': 'Hello, Lunker!'
    }

    return {
        'statusCode': code,
        'body': json.dumps(msg, indent = 4)
    }