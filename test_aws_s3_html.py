# tests/test_aws_s3_html.py
"""
HTML validation tests using BeautifulSoup.

- Parses the generated HTML report and asserts the presence of expected rows and metadata.
- Requires beautifulsoup4 in test environment.
"""

from moto import mock_s3
import boto3
from scanner.aws_s3 import scan_all_buckets_from_json, scan_all_buckets_live
from utils import save_report
from bs4 import BeautifulSoup
import os

def test_dummy_html_report_contains_public_bucket(tmp_path):
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
    paths = save_report(findings, mode="dummy", extra={"source":"test"}, out_dir=str(tmp_path))
    html_path = paths["html"]
    assert os.path.exists(html_path)

    with open(html_path, "r", encoding="utf-8") as fh:
        soup = BeautifulSoup(fh, "html.parser")

    header_text = soup.find("h2").get_text(strip=True)
    assert "mode: dummy" in header_text

    table = soup.find("table")
    assert table is not None
    rows = table.find_all("tr")
    assert len(rows) >= 2
    found = False
    for tr in rows[1:]:
        cols = [td.get_text(strip=True) for td in tr.find_all("td")]
        if cols and "s3://public-bucket" in cols[0]:
            assert "Public ACL" in cols[1]
            assert cols[2] == "9"
            found = True
    assert found

@mock_s3
def test_live_html_report_contains_test_bucket(tmp_path):
    s3 = boto3.client("s3", region_name="us-east-1")
    s3.create_bucket(Bucket="test-bucket")
    s3.put_bucket_acl(Bucket="test-bucket", ACL="public-read")

    session = boto3.Session()
    findings = scan_all_buckets_live(session)
    paths = save_report(findings, mode="aws", extra={"test":"moto"}, out_dir=str(tmp_path))
    html_path = paths["html"]
    assert os.path.exists(html_path)

    with open(html_path, "r", encoding="utf-8") as fh:
        soup = BeautifulSoup(fh, "html.parser")
    table = soup.find("table")
    assert table is not None
    assert "s3://test-bucket" in table.get_text()
