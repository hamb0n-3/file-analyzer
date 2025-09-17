```
=== File Analysis Results ===
Run Details:
  Generated: 2025-09-17 11:05:50
  File: /Users/tristan/AI/Scripts/Red/file-analyzer/test/fixtures/sample_project/services.py
  Plugins: all
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

Total Findings: 23

Network Information (2 findings):
  Domain Keywords (2 found):
    - self.timeout
    - os.environ.get

Authentication (1 findings):
  Access Token (1 found):
    - os.environ.get("SERVICE_API_SECRET", "fixture-service-secret") (/Users/tristan/AI/Scripts/Red/file-analyzer/test/fixtures/sample_project/services.py:15)

API & Keys (5 findings):
  Api Key (5 found):
    - int = 10 (/Users/tristan/AI/Scripts/Red/file-analyzer/test/fixtures/sample_project/services.py:27)
    - svc-key-555 (/Users/tristan/AI/Scripts/Red/file-analyzer/test/fixtures/sample_project/services.py:10)
    - str = SERVICE_ENDPOINT (/Users/tristan/AI/Scripts/Red/file-analyzer/test/fixtures/sample_project/services.py:26)
    - oauth-client-secret-abc (/Users/tristan/AI/Scripts/Red/file-analyzer/test/fixtures/sample_project/services.py:11)
    - https://service.example.com (/Users/tristan/AI/Scripts/Red/file-analyzer/test/fixtures/sample_project/services.py:9)

API Frameworks (1 findings):
  Api Framework (1 found):
    - JavaScript framework: Jest

Code Quality (2 findings):
  Security Smells (2 found):
    - Hardcoded sensitive value in variable 'SERVICE_API_KEY' at line 10
    - Hardcoded sensitive value in variable 'OAUTH_CLIENT_SECRET' at line 11

Network (4 findings):
  Network Protocols (4 found):
    - ICMP
    - HTTPS
    - Network protocol: ICMP
    - Network protocol: HTTPS

================================================================================
WARNING DISCLAIMER:
--------------------------------------------------------------------------------
This analysis is based on pattern matching and heuristics, and may not be exhaustive.
Some API endpoints, credentials, or sensitive data might not be detected.
Successful API request examples are based on contextual clues and might be incomplete.
For critical security analysis, always perform manual verification.
================================================================================
```