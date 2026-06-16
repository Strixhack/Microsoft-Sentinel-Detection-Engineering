# Data Flow — Event Lifecycle

How a security event on the monitored endpoint becomes a triageable incident in Microsoft Sentinel.

---

## End-to-End Flow

```
1. EVENT OCCURS ON ENDPOINT
   powershell.exe -NoProfile -NonInteractive -Command "IEX('...')"
   Windows kernel creates process object
          │
          ▼
2. MDE SENSOR CAPTURES EVENT
   Sense service hooks Windows ETW (Event Tracing for Windows)
   Captures: process name, command line, parent process,
             user account, timestamp, SHA256 hash
          │
          ▼ HTTPS (port 443) — ~30 seconds latency
3. EVENT LANDS IN MDE BACKEND
   Stored as DeviceProcessEvents record
   MDE runs built-in detections → DeviceAlertEvents
          │
          ▼ XDR connector polling — 2-5 min latency
4. EVENT STREAMS TO LOG ANALYTICS
   DeviceProcessEvents record lands in law-sentinel-m365
   Now queryable via KQL in Sentinel Logs blade
          │
          ▼ Rule runs every 5 minutes
5. SCHEDULED ANALYTICS RULE EVALUATES
   KQL query scans last 1 hour of DeviceProcessEvents
   Filters for PowerShell with suspicious flags
   Excludes known-good processes (sensecm.exe)
          │
          ▼ If results > 0
6. ALERT GENERATED
   SecurityAlert record created
   Entity mapping extracts: Host (vm-mde-lab), Account (sentineladmin)
   MITRE ATT&CK tags applied: Execution / T1059.001
          │
          ▼ Incident engine
7. INCIDENT CREATED AND CORRELATED
   Multiple alerts from same host/account grouped (5hr window)
   Attack story timeline constructed
   Evidence artifacts attached
          │
          ▼
8. L1 ANALYST TRIAGES
   Reviews: severity, entity, command line, timeline
   Decision: escalate to L2 or close as false positive
```

---

## Latency Breakdown

| Stage | Typical latency |
|-------|----------------|
| Event on endpoint → MDE backend | ~30 seconds |
| MDE backend → Log Analytics workspace | 2–5 minutes |
| Data in workspace → rule evaluates | 0–5 minutes (rule runs every 5 min) |
| Rule fires → incident appears | < 1 minute |
| **Total end-to-end** | **~3–12 minutes** |

---

## KQL Execution Model

When a scheduled rule runs:

1. Sentinel calls the Log Analytics query API
2. KQL engine scans the specified table for the lookback window (1 hour)
3. Each row is evaluated against the `where` filters
4. Matching rows are returned as alert evidence
5. If row count > threshold (0), an alert is created
6. Entity mapping extracts structured entities from result columns
7. Alert is passed to the incident engine for correlation

---

## Alert Grouping Logic

```
Alert A: PowerShell execution — vm-mde-lab / sentineladmin — 10:37 PM
Alert B: PowerShell execution — vm-mde-lab / sentineladmin — 10:51 PM
         │
         ▼ Same rule + same entities + within 5-hour window
         │
Incident #2: Suspicious PowerShell Execution
             2 alerts │ vm-mde-lab │ sentineladmin
             First activity: 10:37 PM
             Last activity:  10:51 PM
```

Two separate detections become one incident. The analyst triages one ticket instead of two.
