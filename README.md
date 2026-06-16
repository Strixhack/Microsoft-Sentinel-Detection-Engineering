# Microsoft Sentinel Detection Engineering Lab

![Azure](https://img.shields.io/badge/Microsoft%20Azure-0078D4?style=flat&logo=microsoftazure&logoColor=white)
![Sentinel](https://img.shields.io/badge/Microsoft%20Sentinel-0078D4?style=flat&logo=microsoft&logoColor=white)
![KQL](https://img.shields.io/badge/KQL-Kusto%20Query%20Language-blue?style=flat)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-Mapped-red?style=flat)
![Status](https://img.shields.io/badge/Status-Active-green?style=flat)

A production-grade detection engineering lab built from scratch on Microsoft Azure. Ingests real endpoint telemetry from Microsoft Defender for Endpoint into Microsoft Sentinel and detects adversary behaviour using MITRE ATT&CK-mapped KQL analytics rules.

---

## Overview

| Component | Details |
|-----------|---------|
| **SIEM** | Microsoft Sentinel |
| **Data source** | Microsoft Defender for Endpoint (MDE) |
| **Endpoint** | Windows Server 2019 VM (Azure) |
| **Query language** | KQL (Kusto Query Language) |
| **Detection framework** | MITRE ATT&CK |
| **Log retention** | 90 days |
| **Rules deployed** | 5 scheduled analytics rules |

---

## Architecture

```
┌─────────────────────────────────────────┐
│         Azure VM — vm-mde-lab           │
│         Windows Server 2019             │
│         MDE Sense sensor: Running       │
└───────────────────┬─────────────────────┘
                    │ Telemetry stream (HTTPS)
                    ▼
┌─────────────────────────────────────────┐
│    Microsoft Defender for Endpoint      │
│    M365 tenant: SentinelLab677          │
│    Device status: Onboarded / Active    │
└───────────────────┬─────────────────────┘
                    │ Defender XDR connector (10 tables)
                    ▼
┌─────────────────────────────────────────┐
│   Log Analytics Workspace               │
│   law-sentinel-m365                     │
│   Retention: 90 days │ Cap: 1 GB/day   │
└───────────────────┬─────────────────────┘
                    │ Scheduled KQL rules (every 5 min)
                    ▼
┌─────────────────────────────────────────┐
│         Microsoft Sentinel              │
│   Analytics rules → Alerts → Incidents  │
│   Entity mapping │ MITRE ATT&CK tags    │
└─────────────────────────────────────────┘
```

---

## Detection Rules

| # | Rule Name | MITRE Technique | Tactic | Severity | Data Source |
|---|-----------|----------------|--------|----------|-------------|
| 1 | [Suspicious PowerShell Execution](rules/T1059.001-suspicious-powershell.kql) | T1059.001 | Execution | Medium | DeviceProcessEvents |
| 2 | [Suspicious User Enumeration](rules/T1087.001-user-enumeration.kql) | T1087.001 | Discovery | Medium | DeviceProcessEvents |
| 3 | [Suspicious Outbound Network Connection](rules/T1071.001-suspicious-network.kql) | T1071.001 | Command & Control | Medium | DeviceNetworkEvents |
| 4 | [Persistence via Registry Run Key](rules/T1547.001-registry-persistence.kql) | T1547.001 | Persistence | High | DeviceRegistryEvents |
| 5 | [Multiple Failed Logon Attempts](rules/T1078-failed-logons.kql) | T1078 | Credential Access | High | DeviceLogonEvents |

---

## MITRE ATT&CK Coverage

```
Reconnaissance   Initial Access   Execution        Persistence      Privilege Esc
                                  ██ T1059.001      ██ T1547.001
                                  
Defense Evasion  Credential Access Discovery        Lateral Movement Command & Control
                 ██ T1078         ██ T1087.001                       ██ T1071.001
```

---

## Rule Design Principles

**Precision over recall** — Each rule targets specific behavioural indicators rather than broad signatures, reducing false positives while maintaining detection coverage.

**Tuned exclusions** — Rules exclude known-good system processes (e.g. `sensecm.exe`, `MsSense.exe`) identified from observed telemetry. This is real tuning based on actual data, not theoretical allow-lists.

**Entity mapping** — Every rule maps `Host` and `Account` entities, enabling Sentinel's investigation graph and UEBA correlation.

**Alert grouping** — Related alerts from the same rule are grouped into single incidents within a 5-hour window, reducing analyst queue noise.

---

## MDE Data Tables

The Microsoft Defender XDR connector streams 10 tables into Sentinel:

| Table | Captures |
|-------|---------|
| `DeviceProcessEvents` | Process creation — parent/child relationships, command lines, hashes |
| `DeviceNetworkEvents` | Network connections — remote IP, port, URL, initiating process |
| `DeviceFileEvents` | File create/modify/delete — path, hash, initiating process |
| `DeviceRegistryEvents` | Registry create/modify — key, value name, value data |
| `DeviceLogonEvents` | Authentication events — logon type, account, source IP |
| `DeviceInfo` | Machine metadata — OS, domain, sensor version |
| `DeviceNetworkInfo` | Network adapter properties |
| `DeviceImageLoadEvents` | DLL loads — used for injection detection |
| `DeviceEvents` | Miscellaneous security events — AV, USB, firewall |
| `DeviceFileCertificateInfo` | Code signing — detecting unsigned binaries |

---

## Key Technical Decisions

### 90-day log retention
Default is 30 days. Extended to 90 days for anomaly baselining — detecting outliers requires sufficient historical context. Also aligns with NIS2 and ISO 27001 guidance on log retention.

### 1 GB daily ingestion cap
Protects against runaway costs from misconfigured verbose data sources. In production, cap is set at expected ingestion volume plus 20% buffer.

### PerGB2018 pricing tier
Pay-per-GB is optimal for lab-scale ingestion. At production scale (>100 GB/day) a commitment tier reduces cost per GB significantly.

### Cross-tenant architecture
MDE was provisioned in an M365 trial tenant separate from the original Azure tenant. Since Sentinel can only receive connector data from within the same tenant, a second Sentinel workspace was created inside the M365 tenant. This is the Microsoft-recommended architecture for this scenario — not a workaround.

### Scheduled rules at 5-minute frequency
Balances detection latency against compute cost. End-to-end latency from endpoint event to incident is approximately 3–12 minutes. For critical detections, NRT (Near Real-Time) rules running every ~1 minute would reduce this further.

---

## Attack Simulations

Each rule was validated by simulating the target technique on the monitored VM and confirming incident generation in Sentinel.

| Rule | Simulation command | Incident generated |
|------|-------------------|-------------------|
| PowerShell Execution | `powershell.exe -NoProfile -NonInteractive -Command "IEX('Get-Process')"` | ✅ Yes |
| User Enumeration | `net user`, `whoami /all`, `net localgroup administrators` | ✅ Yes |
| Network Connection | `Invoke-WebRequest -Uri "http://pastebin.com"` | ✅ Yes |
| Registry Persistence | `reg add HKCU\...\Run /v MaliciousApp /d malware.exe` | ✅ Yes |
| Failed Logons | 5x failed `Start-Process` with wrong credentials | ✅ Yes |

---

## Project Phases

- [x] **Phase 1** — Infrastructure (Azure tenant, Log Analytics, Sentinel, RBAC)
- [x] **Phase 2** — MDE data ingestion (VM onboarding, XDR connector, table validation)
- [x] **Phase 3** — Detection rules (5 KQL rules, MITRE mapping, attack simulation)
- [ ] **Phase 4** — SOAR playbooks (Logic Apps: device isolation, Teams notification)
- [ ] **Phase 5** — Tuning (watchlists, false positive reduction, threshold optimisation)
- [ ] **Phase 6** — Purple team exercises and CI/CD rule deployment (Bicep/ARM)

---

## Repository Structure

```
Microsoft-Sentinel-Detection-Engineering/
├── README.md                              # Project documentation
├── rules/                                 # KQL detection rules
│   ├── T1059.001-suspicious-powershell.kql
│   ├── T1087.001-user-enumeration.kql
│   ├── T1071.001-suspicious-network.kql
│   ├── T1547.001-registry-persistence.kql
│   └── T1078-failed-logons.kql
├── docs/                                  # Technical documentation
│   ├── architecture.md                    # Component deep dive
│   └── data-flow.md                       # Event lifecycle walkthrough
└── screenshots/                           # Incident evidence
    ├── 01-incidents-list.png
    ├── 02-incident-detail.png
    ├── 03-analytics-rules.png
    └── 04-attack-story.png
```

---

## Author

**Kundan Kishor Vidhate**  
Security Operations | Detection Engineering  
SRH University, Germany  

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Connect-blue?style=flat&logo=linkedin)](https://linkedin.com/in/YOUR-LINKEDIN)
[![GitHub](https://img.shields.io/badge/GitHub-Strixhack-black?style=flat&logo=github)](https://github.com/Strixhack)
