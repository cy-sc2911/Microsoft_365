> 📘 Documentation and notes for the [M365 Monitoring Basics](https://tryhackme.com/room/m365monitoringbasics) room on TryHackMe.

## 📋 Overview

Step into the role of a **L2 SOC Analyst** investigating a suspicious cloud identity incident. The organization relies entirely on **Microsoft Entra ID** for authentication and **Microsoft 365 (M365)** for collaboration. There are no endpoint alerts, no network indicators — every clue lives in the logs of these cloud solutions.

The scenario covers a full attack chain: multiple failed authentications → successful compromise → post-compromise M365 activity.


## 🎯 Learning Objectives

- Understand the risks of identities and why attackers target them in modern cloud environments
- Understand Entra ID and M365 as critical log sources for SOC investigations
- Understand Entra ID and M365 log types and their core structure
- Use logs to identify attacks through Entra ID Sign-in Logs, Audit Logs, and M365 Unified Audit Logs

## 🗂️ Room Details

| Field           | Details                                                                                    |
|-----------------|--------------------------------------------------------------------------------------------|
| 🔗 Room URL     | [tryhackme.com/room/m365monitoringbasics](https://tryhackme.com/room/m365monitoringbasics) |
| 🏷️ Platform    | TryHackMe                                                                                  |
| 🧩 Category     | Blue Team / Cloud Security / Identity & Access Management                                  |
| 🛠️ Tools       | Splunk, Microsoft Entra ID, Microsoft 365                                                  |


### Prerequisites
- [Splunk: Exploring SPL](https://tryhackme.com/room/splunkexploringspl)
- [Intro to Log Analysis](https://tryhackme.com/room/introtologanalysis)

## 🧠 Key Concepts

### 1. Identity Types

| Identity Type       | Description                                                             |
|---------------------|-------------------------------------------------------------------------|
| Human Identities    | Employees, contractors, partners, customers                            |
| Workload Identities | Applications, services, scripts, containers                             |
| Device Identities   | Desktops, laptops, mobile phones, IoT devices                          |

An **Identity Provider (IdP)** — like Microsoft Entra ID — centralizes authentication, authorization, and auditing across all connected services.

### 2. Why Attackers Target Cloud Identities

- **Remote access from anywhere** — No internal network access needed
- **SSO unlocks everything** — One valid credential = email, files, chat, and apps
- **Evades traditional tools** — Firewalls and endpoint tools may see nothing suspicious
- **Direct access to high-value data** — Email, documents, and the ability to reset credentials

### 3. Common Misconfigurations Exploited

- No MFA enforcement on accounts
- Overly permissive Conditional Access policies
- Excessive admin privileges / standing access
- Weak password policies
- Disabled Identity Protection risk policies
- Insufficient logging and monitoring

## 📂 Log Sources

### Entra ID Sign-in Logs
Captures **every authentication attempt** — successes, failures, MFA challenges, and context (IP, location, device, app).

**Key Fields:**
| Field | Description |
|---|---|
| `userPrincipalName` | The user's email / UPN |
| `ipAddress` | Source IP of the authentication |
| `appDisplayName` | Application the user logged into |
| `status.errorCode` | `0` = success; non-zero = failure |
| `location` | City, state, country from IP geolocation |
| `appliedConditionalAccessPolicies` | Which access policies were evaluated |

**Common Error Codes:**
| Code | Meaning |
|---|---|
| `50126` | Invalid username or password |
| `50053` | Account locked (too many failures) |
| `50074` | MFA required but not provided |
| `50055` | Password expired |

### Entra ID Audit Logs
Captures **administrative actions and changes** — password resets, MFA method changes, role assignments, app registrations, and more.

**Key Fields:**
| Field | Description |
|---|---|
| `activityDisplayName` | The action performed (e.g., "Change user password") |
| `initiatedBy` | Account or app that performed the action |
| `targetResources` | The object/account affected by the action |

### M365 Unified Audit Logs
Centralized logs for **Exchange, SharePoint, OneDrive, Teams**, and other M365 services. Reveals what the attacker did *after* gaining access.

**Key Fields:**
| Field | Description |
|---|---|
| `Operation` | Specific action (e.g., `New-InboxRule`, `FileAccessed`, `Send`) |
| `UserId` | Account that performed the action |
| `ClientIP` / `ClientIPAddress` | Source IP (may sometimes be an Office 365 IP) |
| `Workload` | M365 service (Exchange, SharePoint, OneDrive) |
| `ObjectId` | Target resource (email, file path, mailbox) |

## 🔍 Splunk Queries

```spl
// List all Entra ID Sign-in events
index=scenario sourcetype="azure:aad:signin"

// List all failed sign-ins
index="scenario" sourcetype="azure:aad:signin" "status.errorCode"!=0
| stats count as event_count values(ipAddress) as ip_addresses
  values(appDisplayName) as applications values(status.errorCode) as errorCodes
  by userPrincipalName
| sort - event_count
| table applications, userPrincipalName, ip_addresses, errorCodes, event_count

// Successful sign-ins from a suspicious IP
index=scenario sourcetype="azure:aad:signin" "status.errorCode"=0 ipAddress="<IP>"
| stats values(ipAddress) as ip_addresses values(appDisplayName) as applications
  by userPrincipalName
| table applications, userPrincipalName, ip_addresses

// Audit logs - changes targeting a specific user
index=scenario sourcetype="azure:aad:audit" targetResources{}.userPrincipalName="<USER-EMAIL>"
| eval initiator=coalesce('initiatedBy.user.userPrincipalName', 'initiatedBy.app.displayName')
| sort - _time
| table _time, initiator, activityDisplayName, result, targetResources{}.userPrincipalName

// Audit logs - changes performed by a user
index=scenario sourcetype="azure:aad:audit" initiatedBy.user.userPrincipalName="<USER-EMAIL>"
| sort - _time
| table _time, initiatedBy.user.userPrincipalName, activityDisplayName, result, targetResources{}.userPrincipalName

// All M365 audit logs
index="scenario" sourcetype="o365:management:activity"

// M365 actions performed by a specific user
index="scenario" sourcetype="o365:management:activity" UserId="<USER-EMAIL>"
| sort - _time
| eval sourceIP=coalesce('ClientIP', 'ClientIPAddress')
| table _time, Operation, UserId, sourceIP, Workload, ObjectId
```

## ⚔️ Post-Compromise Activity Patterns

### Identity-Level (Entra ID Audit Logs)
- Password reset to maintain access
- Adding new MFA methods or devices
- Assigning privileged roles for escalation
- Registering malicious applications

### M365-Level (Unified Audit Logs)
- **Mailbox:** Creating inbox rules to forward/delete emails, mass email deletion, sending emails to external addresses
- **Files:** Mass downloads from SharePoint/OneDrive, accessing sensitive documents, sharing to external domains

---

## 🔧 Tools & Resources

| Tool / Resource | Purpose |
|---|---|
| [Splunk](https://www.splunk.com) | SIEM used for log analysis in this room |
| [Microsoft Entra Admin Center](https://entra.microsoft.com) | Identity and access management portal |
| [M365 Admin Center](https://admin.microsoft.com) | Microsoft 365 service management |
| [MS Error Code Lookup](https://login.microsoftonline.com/error) | Decode Entra ID sign-in error codes |
| [Entra ID Audit Activity Reference](https://learn.microsoft.com/en-us/entra/identity/monitoring-health/reference-audit-activities) | All audit log activity names |
| [M365 Audit Log Reference](https://learn.microsoft.com/en-us/purview/audit-log-activities) | Complete M365 unified audit log activities |

---

## 📚 References

- [Microsoft Entra ID Documentation](https://learn.microsoft.com/en-us/entra/identity/)
- [M365 Unified Audit Log Overview](https://learn.microsoft.com/en-us/purview/audit-solutions-overview)
- [MITRE ATT&CK — T1078: Valid Accounts](https://attack.mitre.org/techniques/T1078/)
- [MITRE ATT&CK — T1114: Email Collection](https://attack.mitre.org/techniques/T1114/)
- [TryHackMe Room](https://tryhackme.com/room/m365monitoringbasics)
- [Related Room — Entra ID Monitoring](https://tryhackme.com/room/entraidmonitoring)

