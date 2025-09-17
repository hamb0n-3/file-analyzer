```
=== File Analysis Results ===
Run Details:
  Generated: 2025-09-17 11:05:46
  File: /Users/tristan/AI/Scripts/Red/file-analyzer/test/fixtures/sample_project/routes/api_routes.js
  Plugins: all
  Scan Mode: file

File Metadata:
  Accessed: 1758131155.261154
  Created: 1758131154.7830415
  File size: 457 bytes
  Filename: api_routes.js
  Group ID: 20
  Modified: 1758131154.7830415
  Owner ID: 501
  Permissions: 33188

Total Findings: 19

Network Information (7 findings):
  Domain Keywords (7 found):
    - req.body
    - res.json
    - router.get
    - Object.keys
    - router.post
    - express.Router
    - module.exports

API Frameworks (2 findings):
  Api Framework (2 found):
    - JavaScript framework: Express
    - JavaScript framework: Webpack

Code Quality (2 findings):
  Code Complexity (1 found):
    - Complex regex pattern at line 7
  Security Smells (1 found):
    - Unsanitized Inputs (line 12): const payload = req.body;

================================================================================
WARNING DISCLAIMER:
--------------------------------------------------------------------------------
This analysis is based on pattern matching and heuristics, and may not be exhaustive.
Some API endpoints, credentials, or sensitive data might not be detected.
Successful API request examples are based on contextual clues and might be incomplete.
For critical security analysis, always perform manual verification.
================================================================================
```