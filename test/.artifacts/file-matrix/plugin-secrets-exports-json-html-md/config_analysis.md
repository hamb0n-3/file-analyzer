```
=== File Analysis Results ===
Run Details:
  Generated: 2025-09-17 11:05:48
  File: /Users/tristan/AI/Scripts/Red/file-analyzer/test/fixtures/sample_project/config.ini
  Plugins: secrets
  Scan Mode: file

File Metadata:
  Accessed: 1758131160.200531
  Created: 1758131158.977397
  File size: 318 bytes
  Filename: config.ini
  Group ID: 20
  Modified: 1758131158.977397
  Owner ID: 501
  Permissions: 33188

Total Findings: 16

Authentication (1 findings):
  Access Token (1 found):
    - fixture-refresh-token

API & Keys (7 findings):
  Api Key (7 found):
    - us-west-2
    - db-pass-123
    - sample-project
    - fixture-client-id
    - fixture-client-secret
    - https://hooks.example.internal/notify
    - postgresql://sample:db-pass-123@db.internal.local:5432/sample

================================================================================
WARNING DISCLAIMER:
--------------------------------------------------------------------------------
This analysis is based on pattern matching and heuristics, and may not be exhaustive.
Some API endpoints, credentials, or sensitive data might not be detected.
Successful API request examples are based on contextual clues and might be incomplete.
For critical security analysis, always perform manual verification.
================================================================================
```