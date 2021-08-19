import boto3
import json
import argparse
import base64

# Assume deployer-role
def assume_role_creds(region, awsAccounts, awsAccountName):
    sts_connection = boto3.client('sts', region_name=region)
    role_name=f"arn:aws:iam::{awsAccounts[awsAccountName]}:role/deployer-role" 
    try:
        acct_b = sts_connection.assume_role(
            RoleArn=role_name,
            RoleSessionName="aws-cli-session"
        )
        ACCESS_KEY = acct_b['Credentials']['AccessKeyId']
        SECRET_KEY = acct_b['Credentials']['SecretAccessKey']
        SESSION_TOKEN = acct_b['Credentials']['SessionToken']
        return ACCESS_KEY,SECRET_KEY,SESSION_TOKEN
    except:
        print("Error while assuming role")

# Download files from S3 and convert them to json
def s3_copy(ACCESS_KEY,SECRET_KEY, SESSION_TOKEN, region, bucketName, bucketPath):
    s3_client = boto3.client('s3',
        aws_access_key_id=ACCESS_KEY,
        aws_secret_access_key=SECRET_KEY,
        aws_session_token=SESSION_TOKEN,
        region_name=region)
    db_json_string = ""
    config_json_string = ""

    # database.txt output
    try:
        database_out =  s3_client.get_object(
        Bucket=f'{bucketName}',
        Key=f'{bucketPath}/database.txt',)
        db_dict={}
        for line in database_out["Body"].read().splitlines():
            each_line = line.decode('utf-8')
            if each_line:
                    key, value = each_line.split('=')
                    db_dict[key] = value
        db_json_string = json.dumps(db_dict)
    except:
        print("Application doesn't have Database.txt file in the given path")
    
    #Config txt output
    try:
        config_out =  s3_client.get_object(
        Bucket=f'{bucketName}',
        Key=f'{bucketPath}/config.txt',)
        config_dict={}
        for line in config_out["Body"].read().splitlines():
            each_line = line.decode('utf-8')
            if each_line:
                    key, value = each_line.split('=')
                    config_dict[key] = value
    except:
        print("Error while copying data from config.txt file, check if the file exist in the given path")
    
    # token-keystore output
    try:
        token_file_info=s3_client.get_object(
            Bucket=f'{bucketName}',
            Key=f'{bucketPath}/security.info')
        for line in token_file_info["Body"].read().splitlines():
            each_line = line.decode('utf-8')
            if "keystore_file" in each_line:
                info=each_line.split('=')
                token_file= info[1]
                break
        base64_message_obj=s3_client.get_object(
            Bucket=f'{bucketName}',
            Key=f'{bucketPath}/{token_file}')
        base64_message = base64_message_obj['Body'].read()
        base64_bytes = base64.b64encode(base64_message)
        config_dict['KEY_STORE_CONTENT']=str(base64_bytes,'utf-8')
    except:
        print("Application doesn't have security.info/token-keystore file in the given path")
                
    config_json_string = json.dumps(config_dict)
    return db_json_string,config_json_string

# Create config and keystore_content parameters in ssm
def do_ssm_copy(region, awsAccountName, bucketName, bucketPath, parameterStorePaths, awsAccounts):
    ACCESS_KEY,SECRET_KEY,SESSION_TOKEN = assume_role_creds(region, awsAccounts, awsAccountName) 
    db_json_string,config_json_string=s3_copy(ACCESS_KEY,SECRET_KEY, SESSION_TOKEN, region, bucketName, bucketPath)
    ssm_client = boto3.client('ssm',
        aws_access_key_id=ACCESS_KEY,
        aws_secret_access_key=SECRET_KEY,
        aws_session_token=SESSION_TOKEN,
        region_name=region)
           
    for ssmPath in parameterStorePaths.split(","):
        try:
            if db_json_string != "":
                ssm_client.put_parameter(
                Name=f'{ssmPath}/config.json',
                Value=db_json_string,
                Type='SecureString',
                Overwrite=True
                )
                print("Created {ssmPath}/config.json parameter successfully")
        except:
            print(f"Error while updating {ssmPath}/config.json")
        try:
            if config_json_string != "":
                ssm_client.put_parameter(
                Name=f'{ssmPath}/keystore_content.json',
                Value=config_json_string,
                Type='SecureString',
                Overwrite=True
                )
                print("Created {ssmPath}/keystore_content.json parameter successfully")
        except:
            print(f"Error while updating {ssmPath}/keystore_content.json parameter")

def main():
    awsAccounts = {
        "test-dev": "xxxxxxxx",
     }  
    parser = argparse.ArgumentParser(description='Read Inputs given to update SSM parameter values',
                                     formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument('--region', required=True,
                        help='Pass a valid AWS Region, us-west-2')
    parser.add_argument('--awsAccountName', required=True,
                        help='Pass a valid AWS account name')
    parser.add_argument('--bucketPath', required=True,
                        help='Pass a valid Bucket Path')
    parser.add_argument('--parameterStorePaths', required=True,
                        help='SSM Parameter Path(should not end with "/"), If there are multiple separate with commas Eg./eks/application/app1/seg1/qual1/env1,/eks/application/app1/seg2/qual2/env1,/eks/application/app1/seg3/qual3/env1')
    args = parser.parse_args()

    # args.region = os.getenv("region")
    # args.awsAccountName = os.getenv("awsAccountName")
    # args.bucketPath = os.getenv("bucketPath")
    # args.parameterStorePaths = os.getenv("parameterStorePaths")
    
    # Sanity check
    assert args.region is not None and (str(args.region) == "us-west-2" or str(args.region) == "us-east-1"), "Not a valid AWS region: {}".format(args.region)
    assert args.awsAccountName is not None and (args.awsAccountName in awsAccounts), "Not a valid AWS Account Name: {}".format(args.awsAccountName)
    assert args.bucketPath is not None or (args.bucketPath == ""), "Not a valid Bucket Path: {}".format(args.bucketPath)
    assert args.parameterStorePaths is not None or (args.parameterStorePaths == ""), "Not a valid SSM parameter Path: {}".format(args.parameterStorePaths)    
    
    bucketName = (args.bucketPath).split('/', 1)[0]
    bucketPath  = (args.bucketPath).split('/', 1)[1]
    do_ssm_copy(args.region, args.awsAccountName, args.bucketName, args.bucketPath, args.parameterStorePaths, awsAccounts)

if __name__ == '__main__':
    main()
