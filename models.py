# models.py
"""
Data models used by the scanner.

- Keep simple, serializable dataclasses for findings.
- Extend Finding with metadata for rule IDs and context.
"""

from dataclasses import dataclass, field
from typing import Dict

@dataclass
class Finding:
    """
    Represents a single security finding.

    Fields:
    - resource: canonical identifier (e.g., "s3://my-bucket" or "aws:s3:list_buckets")
    - issue: short human-readable description (e.g., "Public ACL")
    - severity: numeric severity (0-10)
    - details: free-text details useful for triage
    - metadata: optional structured metadata (rule id, region, etc.)
    """
    resource: str
    issue: str
    severity: int
    details: str = ""
    metadata: Dict[str, str] = field(default_factory=dict)
