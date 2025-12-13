# scanner/aws_s3.py
"""
S3 scanning logic.

- Contains pure-rule functions that accept plain dicts or API responses.
- scan_all_buckets_live enumerates buckets and applies multiple checks:
  * ACL checks for public grants
  * Bucket policy checks for public principals
  * Object ACL checks for public objects
  * Public access block configuration
  * Default encryption presence
  * Website hosting enabled
  * Logging enabled
  * Versioning enabled
- Each check returns zero or more Finding objects.
"""

import json
from typing import List, Dict, Any, Optional
from botocore.exceptions import ClientError
from models import Finding
from config import DEFAULT_SEVERITY_PUBLIC_BUCKET, DEFAULT_SEVERITY_WARNING

# --- Pure rule helpers -----------------------------------------------------

def acl_has_public_grant(acl: Dict[str, Any]) -> bool:
    """
    Return True if ACL grants include AllUsers or AuthenticatedUsers group URIs.
    """
    for grant in acl.get("Grants", []):
        grantee = grant.get("Grantee", {})
        uri = grantee.get("URI", "") or ""
        if "AllUsers" in uri or "AuthenticatedUsers" in uri:
            return True
    return False

def bucket_policy_is_public(policy_text: str) -> bool:
    """
    Conservative check for public bucket policy patterns.

    - Flags statements with Effect Allow and Principal "*" or AWS "*".
    - This is intentionally simple; complex policies may require more analysis.
    """
    try:
        policy = json.loads(policy_text)
    except Exception:
        return False
    for stmt in policy.get("Statement", []):
        if stmt.get("Effect") != "Allow":
            continue
        principal = stmt.get("Principal")
        if principal == "*" or principal == {"AWS": "*"}:
            return True
        if isinstance(principal, dict):
            aws_pr = principal.get("AWS")
            if aws_pr == "*" or aws_pr == ["*"]:
                return True
    return False

def object_acl_has_public_grant(acl: Dict[str, Any]) -> bool:
    """
    Same logic as bucket ACL but for object ACLs.
    """
    return acl_has_public_grant(acl)

# --- Live AWS helpers -----------------------------------------------------

def list_buckets_live(session) -> List[str]:
    """
    List bucket names using a boto3 Session.
    Caller should handle ClientError if credentials/permissions are missing.
    """
    s3 = session.client("s3")
    resp = s3.list_buckets()
    return [b["Name"] for b in resp.get("Buckets", [])]

def get_bucket_acl_live(session, bucket_name: str) -> Dict[str, Any]:
    """
    Retrieve the ACL for a bucket from AWS.
    """
    s3 = session.client("s3")
    return s3.get_bucket_acl(Bucket=bucket_name)

def get_bucket_policy_live(session, bucket_name: str) -> Optional[str]:
    """
    Return the bucket policy JSON text or None if not present or not accessible.
    """
    s3 = session.client("s3")
    try:
        resp = s3.get_bucket_policy(Bucket=bucket_name)
        return resp.get("Policy", "")
    except ClientError:
        return None

def list_objects_live(session, bucket_name: str) -> List[Dict[str, Any]]:
    """
    List objects in a bucket (first page only). Returns empty list on error.
    """
    s3 = session.client("s3")
    try:
        resp = s3.list_objects_v2(Bucket=bucket_name)
        return resp.get("Contents", []) or []
    except ClientError:
        return []

def get_object_acl_live(session, bucket_name: str, key: str) -> Optional[Dict[str, Any]]:
    """
    Return object ACL or None on error.
    """
    s3 = session.client("s3")
    try:
        return s3.get_object_acl(Bucket=bucket_name, Key=key)
    except ClientError:
        return None

def get_public_access_block_live(session, bucket_name: str) -> Optional[Dict[str, Any]]:
    """
    Return PublicAccessBlock configuration or None if not set or not accessible.
    """
    s3 = session.client("s3")
    try:
        resp = s3.get_public_access_block(Bucket=bucket_name)
        return resp.get("PublicAccessBlockConfiguration", {})
    except ClientError:
        return None

def get_bucket_encryption_live(session, bucket_name: str) -> Optional[Dict[str, Any]]:
    """
    Return bucket encryption configuration or None if not set.
    """
    s3 = session.client("s3")
    try:
        return s3.get_bucket_encryption(Bucket=bucket_name)
    except ClientError:
        return None

def get_bucket_website_live(session, bucket_name: str) -> Optional[Dict[str, Any]]:
    """
    Return website configuration or None if not set.
    """
    s3 = session.client("s3")
    try:
        return s3.get_bucket_website(Bucket=bucket_name)
    except ClientError:
        return None

def get_bucket_logging_live(session, bucket_name: str) -> Optional[Dict[str, Any]]:
    """
    Return logging configuration (empty dict if not enabled).
    """
    s3 = session.client("s3")
    try:
        return s3.get_bucket_logging(Bucket=bucket_name)
    except ClientError:
        return None

def get_bucket_versioning_live(session, bucket_name: str) -> Optional[Dict[str, Any]]:
    """
    Return versioning configuration or None on error.
    """
    s3 = session.client("s3")
    try:
        return s3.get_bucket_versioning(Bucket=bucket_name)
    except ClientError:
        return None

# --- High-level scanning --------------------------------------------------

def scan_bucket_acl_from_acl_dict(bucket_name: str, acl: Dict[str, Any]) -> List[Finding]:
    """
    Inspect an ACL dict and return Findings for public ACL grants.
    """
    findings: List[Finding] = []
    if acl_has_public_grant(acl):
        details = f"ACL Grants: {acl.get('Grants')}"
        findings.append(Finding(
            resource=f"s3://{bucket_name}",
            issue="Public ACL",
            severity=DEFAULT_SEVERITY_PUBLIC_BUCKET,
            details=details,
            metadata={"rule_id": "S3-ACL-001"}
        ))
    return findings

def scan_bucket_policy_from_text(bucket_name: str, policy_text: Optional[str]) -> List[Finding]:
    """
    Inspect a bucket policy text and return Findings for public policy statements.
    """
    findings: List[Finding] = []
    if not policy_text:
        return findings
    if bucket_policy_is_public(policy_text):
        findings.append(Finding(
            resource=f"s3://{bucket_name}",
            issue="Public Bucket Policy",
            severity=DEFAULT_SEVERITY_PUBLIC_BUCKET,
            details=f"Policy: {policy_text}",
            metadata={"rule_id": "S3-POLICY-001"}
        ))
    return findings

def scan_objects_for_public_acls(session, bucket_name: str) -> List[Finding]:
    """
    List objects and check each object's ACL for public grants.
    This checks only the first page of objects for speed; extend as needed.
    """
    findings: List[Finding] = []
    objects = list_objects_live(session, bucket_name)
    for obj in objects:
        key = obj.get("Key")
        if not key:
            continue
        acl = get_object_acl_live(session, bucket_name, key)
        if not acl:
            continue
        if object_acl_has_public_grant(acl):
            findings.append(Finding(
                resource=f"s3://{bucket_name}/{key}",
                issue="Public Object ACL",
                severity=DEFAULT_SEVERITY_PUBLIC_BUCKET,
                details=f"Object ACL Grants: {acl.get('Grants')}",
                metadata={"rule_id": "S3-OBJ-ACL-001"}
            ))
    return findings

def scan_bucket_configuration(session, bucket_name: str) -> List[Finding]:
    """
    Check bucket-level configuration items that indicate risk or missing protections.
    Returns Findings for:
    - Public access block disabled or permissive
    - Missing default encryption
    - Website hosting enabled
    - Logging disabled
    - Versioning disabled
    """
    findings: List[Finding] = []

    # Public access block
    pab = get_public_access_block_live(session, bucket_name)
    if pab is None:
        # Could be access denied; skip but note as low severity
        findings.append(Finding(
            resource=f"s3://{bucket_name}",
            issue="Public Access Block Unknown",
            severity=DEFAULT_SEVERITY_WARNING,
            details="Could not read PublicAccessBlock configuration",
            metadata={"rule_id": "S3-PAB-001"}
        ))
    else:
        # If any of the recommended blocks are false, flag as warning
        recommended = {
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True
        }
        for k, expected in recommended.items():
            if pab.get(k) is not expected:
                findings.append(Finding(
                    resource=f"s3://{bucket_name}",
                    issue="Public Access Block Permissive",
                    severity=DEFAULT_SEVERITY_WARNING,
                    details=f"{k} is {pab.get(k)}",
                    metadata={"rule_id": "S3-PAB-002", "setting": k}
                ))
                break

    # Default encryption
    enc = get_bucket_encryption_live(session, bucket_name)
    if enc is None:
        findings.append(Finding(
            resource=f"s3://{bucket_name}",
            issue="Missing Default Encryption",
            severity=DEFAULT_SEVERITY_WARNING,
            details="No default bucket encryption configured",
            metadata={"rule_id": "S3-ENC-001"}
        ))

    # Website hosting
    website = get_bucket_website_live(session, bucket_name)
    if website is not None:
        findings.append(Finding(
            resource=f"s3://{bucket_name}",
            issue="Website Hosting Enabled",
            severity=DEFAULT_SEVERITY_WARNING,
            details=f"Website configuration: {website}",
            metadata={"rule_id": "S3-WEB-001"}
        ))

    # Logging
    logging_cfg = get_bucket_logging_live(session, bucket_name)
    # If logging is empty or missing TargetBucket, flag it
    if logging_cfg is None or not logging_cfg.get("LoggingEnabled"):
        findings.append(Finding(
            resource=f"s3://{bucket_name}",
            issue="Access Logging Disabled",
            severity=DEFAULT_SEVERITY_WARNING,
            details="Bucket access logging is not enabled",
            metadata={"rule_id": "S3-LOG-001"}
        ))

    # Versioning
    versioning = get_bucket_versioning_live(session, bucket_name)
    if versioning is None or versioning.get("Status") != "Enabled":
        findings.append(Finding(
            resource=f"s3://{bucket_name}",
            issue="Versioning Not Enabled",
            severity=DEFAULT_SEVERITY_WARNING,
            details=f"Versioning status: {versioning}",
            metadata={"rule_id": "S3-VERS-001"}
        ))

    return findings

def scan_all_buckets_from_json(data: Dict[str, Any]) -> List[Finding]:
    """
    Dummy-mode scanner: accepts a JSON-like dict describing buckets.
    Expected shape:
    {
      "buckets": [
        { "Name": "bucket1", "ACL": { "Grants": [ ... ] }, "Policy": "..." },
        ...
      ]
    }
    """
    findings: List[Finding] = []
    for b in data.get("buckets", []):
        name = b.get("Name")
        acl = b.get("ACL", {}) or {}
        findings.extend(scan_bucket_acl_from_acl_dict(name, acl))
        findings.extend(scan_bucket_policy_from_text(name, b.get("Policy")))
        # object ACLs not present in dummy data unless provided
    return findings

def scan_all_buckets_live(session) -> List[Finding]:
    """
    High-level live scan: list buckets, fetch ACLs/policies/configs, apply rules, aggregate findings.

    - Records a Finding for list-buckets failure.
    - Records a Finding for per-bucket ACL read errors.
    - Adds multiple checks per bucket for broader coverage.
    """
    findings: List[Finding] = []
    try:
        bucket_names = list_buckets_live(session)
    except ClientError as e:
        return [Finding(resource="aws:s3:list_buckets", issue="ListBucketsError", severity=DEFAULT_SEVERITY_WARNING, details=str(e))]

    for name in bucket_names:
        # ACL check
        try:
            acl = get_bucket_acl_live(session, name)
            findings.extend(scan_bucket_acl_from_acl_dict(name, acl))
        except ClientError as e:
            findings.append(Finding(resource=f"s3://{name}", issue="ACL read error", severity=DEFAULT_SEVERITY_WARNING, details=str(e)))
            # continue to attempt other checks where possible

        # Bucket policy check
        policy_text = get_bucket_policy_live(session, name)
        findings.extend(scan_bucket_policy_from_text(name, policy_text))

        # Object ACLs (first page)
        findings.extend(scan_objects_for_public_acls(session, name))

        # Configuration checks (encryption, public access block, website, logging, versioning)
        findings.extend(scan_bucket_configuration(session, name))

    return findings
