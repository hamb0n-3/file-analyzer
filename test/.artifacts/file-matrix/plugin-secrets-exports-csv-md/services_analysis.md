```
=== File Analysis Results ===
Run Details:
  Generated: 2025-09-17 11:05:47
  File: /Users/tristan/AI/Scripts/Red/file-analyzer/test/fixtures/sample_project/services.py
  Plugins: secrets
  Scan Mode: file

File Metadata:
  Accessed: 1758131150.3061883
  Created: 1758131149.85321
  File size: 852 bytes
  Filename: services.py
  Group ID: 20
  Modified: 1758131149.85321
  Owner ID: 501
  Permissions: 33188

Total Findings: 14

Authentication (1 findings):
  Access Token (1 found):
    - os.environ.get("SERVICE_API_SECRET", "fixture-service-secret")

API & Keys (5 findings):
  Api Key (5 found):
    - int = 10
    - svc-key-555
    - str = SERVICE_ENDPOINT
    - oauth-client-secret-abc
    - https://service.example.com

================================================================================
WARNING DISCLAIMER:
--------------------------------------------------------------------------------
This analysis is based on pattern matching and heuristics, and may not be exhaustive.
Some API endpoints, credentials, or sensitive data might not be detected.
Successful API request examples are based on contextual clues and might be incomplete.
For critical security analysis, always perform manual verification.
================================================================================
```