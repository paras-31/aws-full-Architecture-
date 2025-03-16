import json

def lambda_handler(event, context):
    print("Hello From AWS-WARF from paras")
    return {
        'statusCode': 200,
        'body': 'Hello, World!'
    }