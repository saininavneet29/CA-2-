"""
Central configuration and tunable constants.

- Default AWS profile and region can be overridden by CLI args or environment variables.
- Severity thresholds are centralized for easy tuning.
"""

# Severity scale: 0 (info) to 10 (critical)
DEFAULT_SEVERITY_PUBLIC_BUCKET = 9
DEFAULT_SEVERITY_WARNING = 5

# AWS Vault model:
# - We do NOT use a default profile (AWS Vault injects credentials)
# - We DO need a default region for boto3.Session(region_name=...)
DEFAULT_AWS_PROFILE = None
DEFAULT_AWS_REGION = "eu-west-1"   # or "us-east-1" if you prefer
