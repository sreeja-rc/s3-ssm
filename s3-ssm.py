import boto3
import json
import argparse
import base64

def do_ssm_copy(region, awsAccountName, applicationname, environment, segment, qualifier, aws_accounts):
    sts_connection = boto3.client('sts', region_name=region)
    role_name=f"arn:aws:iam::{aws_accounts[awsAccountName]}:role/deployer-role" 
    try:
        acct_b = sts_connection.assume_role(
            RoleArn=role_name,
            RoleSessionName="Test_deploy"
        )
        ACCESS_KEY = acct_b['Credentials']['AccessKeyId']
        SECRET_KEY = acct_b['Credentials']['SecretAccessKey']
        SESSION_TOKEN = acct_b['Credentials']['SessionToken']
    except:
        print("Error while assuming role")
    s3_client = boto3.client('s3',
        aws_access_key_id=ACCESS_KEY,
        aws_secret_access_key=SECRET_KEY,
        aws_session_token=SESSION_TOKEN,
        region_name=region)
    ssm_client = boto3.client('ssm',
        aws_access_key_id=ACCESS_KEY,
        aws_secret_access_key=SECRET_KEY,
        aws_session_token=SESSION_TOKEN,
        region_name=region)
    ####database txt output
    try:
        database_out =  s3_client.get_object(
        Bucket=f'{awsAccountName}-secrets',
        Key=f'{applicationname}/{environment}/database.txt',)
        db_dict={}
        for line in database_out["Body"].read().splitlines():
            each_line = line.decode('utf-8')
            print(each_line)
            if each_line:
                    key, value = each_line.split('=')
                    db_dict[key] = value
        db_json_string = json.dumps(db_dict)
        print(db_json_string)
    except:
        print("Error while copying data from S3 bucket for Database.txt file, check path or values")
    #####Config txt output
    try:
        config_out =  s3_client.get_object(
        Bucket=f'{awsAccountName}-secrets',
        Key=f'{applicationname}/{environment}/config.txt',)
        config_dict={}
        for line in config_out["Body"].read().splitlines():
            each_line = line.decode('utf-8')
            print(each_line)
            if each_line:
                    key, value = each_line.split('=')
                    config_dict[key] = value
    except:
        print("Error for config copy")
    try:
        base64_message_obj=s3_client.get_object(
            Bucket=f'{awsAccountName}-secrets',
            Key=f'{applicationname}/{environment}/token-keystore')
        base64_message = base64_message_obj['Body'].read()
        base64_bytes = base64.b64encode(base64_message)
        print("the config dict value is")
        config_dict['KEY_STORE_CONTENT']=str(base64_bytes,'utf-8')
        config_json_string = json.dumps(config_dict)
        print(config_json_string)
    except:
        print("Error while copying data from S3 bucket for tokenkeystore.txt or config.txt file, check path or values")
    ##SSM parameter store update
    try:
        ssm_client.put_parameter(
        Name=f'/eks/application/{applicationname}/{segment}/{qualifier}/{environment}/config.json',
        Value=db_json_string,
        Type='SecureString',
        Overwrite=True
        )
        print("Updated config.json successfully")
    except:
        print("Error while updating DB config SSM parameter")
    try:
        ssm_client.put_parameter(
        Name=f'/eks/application/{applicationname}/{segment}/{qualifier}/{environment}/keystore_content.json',
        Value=config_json_string,
        Type='SecureString',
        Overwrite=True
        )
        print("Updated keystore_content.json successfully")
    except:
        print("Error while updating Key store content SSM parameter")
    


def main():
    aws_accounts = {

        "test-dev": "xxxxxxxxxxxx"

     }
    harnessDelegateTag=""
    harness_delegate = {
    
        "test-dev": "test-test"

    }
    
    parser = argparse.ArgumentParser(description='Read Inputs given to update SSM parameter values',
                                     formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument('--region', required=True,
                        help='Pass a valid AWS Region, us-east-1 or us-west-2')
    parser.add_argument('--awsAccountName', required=True,
                        help='Pass a valid AWS account Name')
    parser.add_argument('--applicationname', required=True,
                        help='Pass a valid application name to the input')
    parser.add_argument('--environment', required=True,
                        help='Pass a valid environment value')
    parser.add_argument('--segment', required=True,
                        help='Pass a valid segment name')
    parser.add_argument('--qualifier', required=True,
                        help='Pass a valid Qualifier Name')
    args = parser.parse_args()
    # Sanity check
    assert args.region is not None and (str(args.region) == "us-east-1" or str(args.region) == "us-west-2"), "Not a valid AWS region: {}".format(args.region)
    assert args.awsAccountName is not None and (args.awsAccountName in aws_accounts), "Not a valid AWS Account Name: {}".format(args.awsAccountName)
    assert args.applicationname is not None or (args.applicationname == ""), "Not a valid Application Name: {}".format(args.applicationname)
    assert args.environment is not None or (args.environment == ""), "Not a valid Environment Name: {}".format(args.environment)
    assert args.segment is not None or (args.segment == ""), "Not a valid Segment Name: {}".format(args.segment)
    assert args.qualifier is not None or (args.qualifier == ""), "Not a valid qualifier Name: {}".format(args.qualifier)
    harnessDelegateTag= harness_delegate[args.awsAccountName]
    do_ssm_copy(args.region, args.awsAccountName, args.applicationname, args.environment, args.segment, args.qualifier, aws_accounts)

if __name__ == '__main__':
    main()