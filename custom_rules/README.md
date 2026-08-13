### Rule 100200: Windows Guest Account Activation

- **Severity Level:** `12` (High)
- **Description:** Detects when the built-in **Guest** account is enabled on a Windows system.
- **Trigger Conditions:**
  - Parent Rule: `60103`
  - Event ID: `4722` (User Account Enabled)
  - Target User: `Guest`
- **MITRE ATT&CK:** [T1078 - Valid Accounts](https://attack.mitre.org/techniques/T1078/)
- **Rule Groups:** `windows_security`, `account_enabled`, `guest_account`, `adduser`
