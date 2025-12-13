import boto3, botocore

try:
    # No profile name: AWS Vault will inject credentials via environment variables
    sess = boto3.Session()
    sts = sess.client("sts")
    print(sts.get_caller_identity())
except botocore.exceptions.ClientError as e:
    print("ClientError:", e)
except Exception as e:
    print("Error:", e)
