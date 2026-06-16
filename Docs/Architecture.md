# Architecture — Microsoft Sentinel Detection Engineering Lab

## Component Overview

### Azure VM — vm-mde-lab

- **OS:** Windows Server 2019 (Build 17763)
- **Size:** Standard_DC2s_v3 (2 vCPU, 8 GB RAM)
- **Location:** East US
- **Purpose:** The monitored endpoint. Runs the MDE Sense sensor which captures all process, network, file, registry, and logon activity.
- **MDE sensor:** `Sense` service — hooks into Windows ETW (Event Tracing for Windows) at kernel level

### Log Analytics Workspace — law-sentinel-m365

- **SKU:** PerGB2018 (pay per GB ingested)
- **Retention:** 90 days hot storage
- **Daily cap:** 1 GB (cost protection)
- **Purpose:** The data store. Sentinel has no storage of its own — it runs on top of Log Analytics. All telemetry lands here and is queryable via KQL.

### Microsoft Sentinel

- **Workspace:** law-sentinel-m365
- **Tenant:** SentinelLab677 (M365 tenant)
- **Connected to:** Microsoft Defender portal via Unified SecOps platform
- **Purpose:** The SIEM layer. Runs KQL analytics rules on a schedule, generates alerts, correlates alerts into incidents, and manages the analyst workflow.

### Microsoft Defender for Endpoint

- **Tenant:** SentinelLab677 (M365 tenant)
- **Device:** vm-mde-lab (onboarded, active)
- **Connector:** Microsoft Defender XDR (10 tables streamed to Sentinel)
- **Purpose:** The EDR layer. Collects raw endpoint telemetry and streams it into the Log Analytics workspace via the XDR connector.

---

## Cross-Tenant Architecture

The lab uses two Azure tenants:

| Tenant | Contains | Why |
|--------|---------|-----|
| University tenant (787048c4) | Azure VM, original resource group | Azure free trial provisioned here |
| M365 tenant (11cbb0c4) | MDE, Sentinel workspace, XDR connector | M365 trial with Defender for Business |

**The problem:** Sentinel can only natively receive connector data from within the same tenant. The VM's MDE telemetry was flowing to the M365 tenant's Defender instance, but the original Sentinel workspace was in the university tenant — cross-tenant connector flow is blocked by Microsoft's architecture.

**The solution:** Create a second Sentinel workspace (`law-sentinel-m365`) inside the M365 tenant. Connect it to the Defender portal. Enable the Microsoft Defender XDR connector there. Now MDE telemetry flows directly into Sentinel within the same tenant.

This is the Microsoft-recommended architecture for this scenario.

---

## RBAC Configuration

| Role | Scope | Purpose |
|------|-------|---------|
| Microsoft Sentinel Contributor | law-sentinel-m365 workspace | Create/edit rules, playbooks, workbooks |
| Owner | M365 subscription | Required for connector configuration |
| Security Administrator | M365 Azure AD | Required for Defender portal access |

---

## Cost Controls

| Control | Value | Reason |
|---------|-------|--------|
| Daily ingestion cap | 1 GB/day | Prevents runaway costs |
| VM deallocated when idle | $0/hour compute | Only pay for disk (~$2/month) |
| PerGB2018 SKU | Pay per GB | Optimal for <10 GB/day ingestion |
| Log retention | 90 days hot | Balance between cost and query range |
