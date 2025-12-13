# test_public_bucket.py
"""
Create a temporary public S3 bucket, run the scanner, then clean up.
- Safe for testing in a non-production account.
- Requires boto3 and your scanner package to be importable (run from project root).
- The script uses the same AWS profile as your environment or the AWS_PROFILE env var.
"""

import time
import uuid
import boto3
from botocore.exceptions import ClientError

# Import the scanner entrypoint function that returns findings.
# This assumes your project exposes scan_all_buckets_live(session) as shown earlier.
from scanner.aws_s3 import scan_all_buckets_live

# Configuration: change these if needed
AWS_PROFILE = None            # e.g., "scanner-user" or None to use default
AWS_REGION = "us-east-1"      # region for the test bucket
MAKE_POLICY_PUBLIC = True     # also attach a public bucket policy (in addition to ACL)

def unique_bucket_name(prefix="test-public-bucket"):
    """Return a globally unique bucket name for testing."""
    return f"{prefix}-{uuid.uuid4().hex[:8]}"

def create_bucket(s3, bucket_name, region):
    """Create a bucket in the given region."""
    params = {"Bucket": bucket_name}
    if region and region != "us-east-1":
        params["CreateBucketConfiguration"] = {"LocationConstraint": region}
    s3.create_bucket(**params)

def make_bucket_public_acl(s3, bucket_name):
    """Set a public-read ACL on the bucket (adds AllUsers READ grant)."""
    s3.put_bucket_acl(Bucket=bucket_name, ACL="public-read")

def put_public_policy(s3, bucket_name):
    """Attach a simple public-read bucket policy (Principal '*')."""
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "PublicReadGetObject",
                "Effect": "Allow",
                "Principal": "*",
                "Action": ["s3:GetObject"],
                "Resource": [f"arn:aws:s3:::{bucket_name}/*"]
            }
        ]
    }
    s3.put_bucket_policy(Bucket=bucket_name, Policy=json.dumps(policy))

def upload_sample_object(s3, bucket_name, key="hello.txt", body=b"hello world"):
    """Upload a small object and make it public (object ACL)."""
    s3.put_object(Bucket=bucket_name, Key=key, Body=body)
    s3.put_object_acl(Bucket=bucket_name, Key=key, ACL="public-read")

def empty_and_delete_bucket(s3, bucket_name):
    """Remove all objects and delete the bucket."""
    # Delete objects (list + delete)
    paginator = s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=bucket_name):
        for obj in page.get("Contents", []):
            s3.delete_object(Bucket=bucket_name, Key=obj["Key"])
    # Remove bucket policy if present
    try:
        s3.delete_bucket_policy(Bucket=bucket_name)
    except ClientError:
        pass
    # Finally delete bucket
    s3.delete_bucket(Bucket=bucket_name)

def main():
    import os, json
    # Resolve session (profile -> env -> default)
    session = boto3.Session(profile_name=AWS_PROFILE, region_name=AWS_REGION) if AWS_PROFILE else boto3.Session(region_name=AWS_REGION)
    s3 = session.client("s3")

    bucket_name = unique_bucket_name()
    print(f"Creating test bucket: {bucket_name} in region {AWS_REGION}")

    try:
        create_bucket(s3, bucket_name, AWS_REGION)
        # Wait a moment for bucket to exist
        time.sleep(2)

        print("Applying public ACL to bucket")
        make_bucket_public_acl(s3, bucket_name)

        print("Uploading a sample object and making it public")
        upload_sample_object(s3, bucket_name, key="hello.txt")

        if MAKE_POLICY_PUBLIC:
            print("Attaching a public bucket policy")
            # attach policy using client.put_bucket_policy
            policy = {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Sid": "PublicReadGetObject",
                        "Effect": "Allow",
                        "Principal": "*",
                        "Action": ["s3:GetObject"],
                        "Resource": [f"arn:aws:s3:::{bucket_name}/*"]
                    }
                ]
            }
            s3.put_bucket_policy(Bucket=bucket_name, Policy=json.dumps(policy))

        print("Running scanner against the account (this may take a moment)...")
        findings = scan_all_buckets_live(session)

        # Print findings summary to terminal
        print("\n--- Scanner findings (test run) ---")
        if not findings:
            print("No findings detected")
        else:
            for f in findings:
                print(f"- {f.resource} | {f.issue} | severity={f.severity}")
                print(f"  details: {f.details[:200]}")  # truncate details for readability

    except ClientError as e:
        print("AWS API error:", e)
    finally:
        # Cleanup: remove objects and delete bucket
        print("Cleaning up test bucket and objects...")
        try:
            empty_and_delete_bucket(s3, bucket_name)
            print("Cleanup complete.")
        except ClientError as e:
            print("Cleanup error (manual cleanup may be required):", e)

if __name__ == "__main__":
    main()
