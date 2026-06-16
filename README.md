# Microsoft Sentinel Detection Engineering Lab
A production-grade SIEM detection engineering project built from scratch on Microsoft Azure.
## What this project does
Ingests real endpoint telemetry from Microsoft Defender for Endpoint into Microsoft Sentinel
and detects attacker behaviour using MITRE ATT&CK-mapped KQL analytics rules.
## Architecture
## Tech stack
- Microsoft Azure (Azure CLI, ARM)
- Microsoft Sentinel
- Microsoft Defender for Endpoint (MDE)
- Microsoft Defender XDR connector
- KQL (Kusto Query Language)
- Log Analytics (PerGB2018, 90-day retention)
- MITRE ATT&CK framework
## Detection rules
| Rule | MITRE | Tactic | Severity |
|------|-------|--------|----------|
| Suspicious PowerShell Execution | T1059.001 | Execution | Medium |
| Suspicious User Enumeration | T1087.001 | Discovery | Medium |
| Suspicious Outbound Network Connection | T1071.001 | Command and Control | Medium |
| Persistence via Registry Run Key | T1547.001 | Persistence | High |
| Multiple Failed Logon Attempts | T1078 | Credential Access | High |
## Biggest technical challenge
Cross-tenant architecture: MDE provisioned in M365 tenant, Sentinel originally in
university Azure tenant. Cross-tenant connector flow is blocked by Microsoft architecture.
Solution: created second Sentinel workspace inside the M365 tenant and connected via
the Defender XDR connector.
## Project phases
- [x] Phase 1 - Infrastructure (Azure, Log Analytics, Sentinel)
- [x] Phase 2 - MDE data ingestion and validation
- [x] Phase 3 - 5 KQL detection rules with MITRE ATT&CK mapping
- [ ] Phase 4 - SOAR playbooks (Logic Apps, device isolation)
- [ ] Phase 5 - Tuning and false positive reduction
- [ ] Phase 6 - Purple team exercises and CI/CD rule deployment
## Author
Kundan Kishor Vidhate
SRH University, Germany
