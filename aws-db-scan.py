import boto3

# Create a session using your AWS profile or specify access keys
session = boto3.Session(profile_name='default')  # Use default profile

# Connect to the RDS service
rds_client = session.client('rds')

# List all RDS instances
def list_rds_instances():
    try:
        # Call describe_db_instances method
        response = rds_client.describe_db_instances()
        # Print the DB instances
        for db in response['DBInstances']:
            print(f"DBInstanceIdentifier: {db['DBInstanceIdentifier']}")
            print(f"DBInstanceClass: {db['DBInstanceClass']}")
            print(f"Engine: {db['Engine']}")
            print(f"DBInstanceStatus: {db['DBInstanceStatus']}")
            print(f"Endpoint: {db['Endpoint']['Address']}")
            print(f"Region: {db['AvailabilityZone']}")
            print("======================================")

    except Exception as e:
        print(f"An error occurred: {str(e)}")

if __name__ == "__main__":
    list_rds_instances()