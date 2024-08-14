import boto3
import json
from datetime import datetime, timezone
from botocore.exceptions import ClientError

# Initialize Boto3 clients
s3 = boto3.client('s3')
iam = boto3.client('iam')
lambda_client = boto3.client('lambda')

# Open the output file
output_file = open('aws-results.txt', 'w')

def log(message):
    """Helper function to print to console and write to file."""
    print(message)
    output_file.write(message + '\n')

def check_s3_buckets():
    log("Checking S3 Buckets for security risks...\n")
    try:
        buckets = s3.list_buckets()
        for bucket in buckets['Buckets']:
            bucket_name = bucket['Name']
            log(f"Bucket: {bucket_name}")
            # Check Bucket ACL
            acl = s3.get_bucket_acl(Bucket=bucket_name)
            for grant in acl['Grants']:
                if grant['Grantee']['Type'] == 'Group' and 'AllUsers' in grant['Grantee']['URI']:
                    log(f"  WARNING: Bucket {bucket_name} is publicly accessible!")

            # Check Bucket Policies
            try:
                policy = s3.get_bucket_policy(Bucket=bucket_name)
                policy_statements = json.loads(policy['Policy'])['Statement']
                for statement in policy_statements:
                    if statement['Effect'] == 'Allow' and statement.get('Principal', '*') == '*':
                        log(f"  WARNING: Bucket {bucket_name} has a public access policy!")
            except ClientError as e:
                if e.response['Error']['Code'] == 'NoSuchBucketPolicy':
                    log(f"  INFO: No policy found for bucket {bucket_name}.")
                else:
                    log(f"  ERROR: Unable to get policy for bucket {bucket_name}: {e}")

    except ClientError as e:
        log(f"ERROR: {e}")

def check_iam_users_without_mfa():
    log("\nChecking IAM Users without MFA...\n")
    try:
        users = iam.list_users()
        for user in users['Users']:
            user_name = user['UserName']
            mfa_devices = iam.list_mfa_devices(UserName=user_name)
            if not mfa_devices['MFADevices']:
                # Check if the user has a password set (indicates console access)
                try:
                    login_profile = iam.get_login_profile(UserName=user_name)
                    log(f"  WARNING: User {user_name} has console access but no MFA enabled!")
                except ClientError as e:
                    if not e.response['Error']['Code'] == 'NoSuchEntity':
                        log(f"  ERROR: Unable to retrieve login profile for {user_name}: {e}")

    except ClientError as e:
        log(f"ERROR: {e}")

def check_lambda_functions():
    log("\nChecking Lambda Functions for security risks...\n")
    try:
        functions = lambda_client.list_functions()
        for function in functions['Functions']:
            function_name = function['FunctionName']
            log(f"Lambda Function: {function_name}")
            # Check IAM Role permissions
            role_arn = function['Role']
            role_name = role_arn.split('/')[-1]
            role_policy = iam.get_role(RoleName=role_name)
            log(f"  Role: {role_name}")
            if 'FullAccess' in role_policy['Role']['AssumeRolePolicyDocument']:
                log(f"  WARNING: {role_name} has Full Access!")

            # Check for environment variables with secrets
            env_vars = function.get('Environment', {}).get('Variables', {})
            for key, value in env_vars.items():
                if "KEY" in key or "SECRET" in key:
                    log(f"  WARNING: {function_name} has sensitive environment variables: {key}")

    except ClientError as e:
        log(f"ERROR: {e}")

def main():
    check_s3_buckets()
    check_iam_users_without_mfa()
    check_lambda_functions()

if __name__ == "__main__":
    main()

# Close the output file
output_file.close()