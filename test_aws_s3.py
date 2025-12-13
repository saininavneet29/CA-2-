# tests/test_aws_s3.py
"""
Unit and integration tests for the S3 scanner.

- Uses moto to mock AWS S3 for live-mode tests.
- Verifies that reports are created and contain expected content.
- Uses tmp_path to isolate report outputs.
"""

import json
from moto import mock_s3
import boto3
import pytest
from scanner.aws_s3 import scan_all_buckets_from_json, scan_all_buckets_live
from utils import save_report, load_json_file
import os

def test_dummy_public_bucket_and_reports(tmp_path):
    # Dummy data with one public bucket
    data = {
        "buckets": [
            {
                "Name": "public-bucket",
                "ACL": {
                    "Grants": [
                        {
                            "Grantee": {"Type": "Group", "URI": "http://acs.amazonaws.com/groups/global/AllUsers"},
                            "Permission": "READ"
                        }
                    ]
                }
            }
        ]
    }

    findings = scan_all_buckets_from_json(data)
    assert len(findings) == 1

    # Save reports to temporary directory and assert files exist
    paths = save_report(findings, mode="dummy", extra={"source":"test"}, out_dir=str(tmp_path))
    assert os.path.exists(paths["json"])
    assert os.path.exists(paths["csv"])
    assert os.path.exists(paths["html"])

    # Basic JSON content checks
    with open(paths["json"], "r", encoding="utf-8") as fh:
        report = json.load(fh)
    assert report["mode"] == "dummy"
    assert report["summary"]["findings_count"] == 1
    assert any("public-bucket" in f.get("resource","") for f in report["findings"])

@mock_s3
def test_live_public_bucket_and_reports(tmp_path):
    # Create a mocked S3 environment with moto
    s3 = boto3.client("s3", region_name="us-east-1")
    s3.create_bucket(Bucket="test-bucket")
    s3.put_bucket_acl(Bucket="test-bucket", ACL="public-read")

    session = boto3.Session()
    findings = scan_all_buckets_live(session)
    assert any(f.resource == "s3://test-bucket" for f in findings)

    paths = save_report(findings, mode="aws", extra={"test":"moto"}, out_dir=str(tmp_path))
    assert os.path.exists(paths["json"])
    assert os.path.exists(paths["csv"])
    assert os.path.exists(paths["html"])
