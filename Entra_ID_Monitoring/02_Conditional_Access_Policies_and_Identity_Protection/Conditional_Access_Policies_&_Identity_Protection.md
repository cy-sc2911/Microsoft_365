A successful password spray can give an attacker valid credentials. In most Entra ID tenants, the answer is a combination of two controls: Conditional Access Policies and Identity Protection. Understanding both and their blind spots is essential fro a SOC analyst because attackers actively look for gaps in these controls, and logs will tell when they find one.

## Conditional Access Policies
Think of Conditional Access Policies (CAP) as Entra ID's **if/then engine**. Every sign-in is evaluated against a set of policies, and based on the policy's findings, it either grants access, requires an additional controls (such as MFA), or blocks the request entirely.

## Common Policy Examples

| Policy | What it does |
|--------|--------------|
| Require MFA for all users | Forces MFA for every interactive sign-in. |
| Block legacy authentication | Prevents clients that can't perform MFA. (IMAP, SMTP, older Office clients) |
| Block sign-ins from risky locations | Restricts access from anonymous proxies, Tor exit nodes, or untrusted countries. |
| Require compliant device | Blocks sign-ins from personal or unmanaged devices. Only devices enrolled in and meeting the company's security standards are allowed. |
| Risk-based block | Blocks or restricts access when Identity Protection detects a high-risk sign-in or account. |

It's important to mention that a policy is only as effective as scope. If it doesn't cover the right accounts and conditions, it leaves gaps that attackers actively look for.

A real-world example of this is when an organization has a policy requiring MFA for all users, but excludes a handful of service accounts to avoid breaking automated workflows. If one of those accounts is later targeted in a password spray attack, there's nothing standing between the attacker and a successful login.

## CAP in Sign-in Logs
Every Sign-in log event includes an **appliedConditionalAccessPolicies** field that tells exactly which policies were evaluated, and what the outcome was for each:

    appDisplayName: "One Outlook Web"
    appId: "9199bf20-a13f-4107-85dc-02114787ef48"
    appliedConditionalAccessPolicies: [
        {
        displayName: "Require MFA" // Applied Policy
        enforcedGrantControls: [
            "Block"
        ]
        enforcedSessionControls: [
        ]
        id: "c63499f4-64b6-4943-bfc3-52fbb641ef10"
        result: "notApplied" // Resulted action
        }
    ]

The possible results are:

| Result | Meaning |
|--------|---------|
| **success** | Policy conditions were met, and controls were satisfied. |
| **failure** | Policy blocked, or the required control wasn't satisfied. |
| **notApplied** | Policy conditions were not met, or the user/app was not in scope. |
| **reportOnly** | Policy is in audit mode — it would have applied, but didn't enforce. |

Use the following query to start a hunt for suspicious CAP results:

### List blocked sign-ins by CAP

    index="task-3" sourcetype="azure:aad:signin" conditionalAccessStatus=failure
    | spath output=policies path=appliedConditionalAccessPolicies{}
    | mvexpand policies
    | spath input=policies output=policy_result path=result
    | spath input=policies output=policy_name path=displayName
    | where policy_result="failure"
    | stats values(policy_name) as FailedPolicies by _time, appDisplayName, userDisplayName, ipAddress, conditionalAccessStatus
    | eval FailedPolicies=mvjoin(FailedPolicies, ", ")
    | table _time, appDisplayName, userDisplayName, ipAddress, conditionalAccessStatus, FailedPolicies
    | sort - _time

## Identity Protection
Conditional Access enforces your rules, while **Identity Protection** is what tells Conditional Access when something looks suspicious in the first place.
Identity Protection is Entra ID's built in ML-based risk detection engine. It continuously analyses sign-in behaviour and user account signals, assigns risk scores, and feeds those scores into Conditional Access so risk-based policies can act on them.

There are two types of risk: Sign-in Risk and User Risk.
Both types of risk use a three-tier scale: Low, Medium, High.


### Sign-in Risk
It evaluates the suspiciousness of a specific sign-in attempt.
This is evaluated in real time, per authentication event. Below are examples of what raises sign-in risk:

- **Suspicious Source IP**: Sign-in from a known risky or anonymous IP. (e.g., Tor, known proxy services, or VPM providers)
- **Impossible Travel**: Two sign-ins from geographically distant locations within an impossible timeframe. (e.g., First login from London and after 5 minutes, a login from New York)
- **Umfamiliar Sign-in Properties**: New device, new location, or new ASN that doesn't match the user's historical pattern.

### User Risk
It evaluates the likelihood that a specific account will be compromised.
This accumulates over time, based on the account's history. Examples:
- **Leaked credentials**: Validates if the account's password appeared in a known breach dump.
- **Multiple high-risk sign-ins**: Check related risky sign-ins that weren't remediated.
- **Suspicious M365 activity**: Check potential post-compromise M365 activity. (e.g., Suspicious inbox-rules)

## Identity Protection in Sign-in Logs
We can look for Identity Protection log details in three different **sourcetype** values:

- Sign-in logs(**azure::aad:signin**)

To access the risk level of a specific sign-in attempt, we can use the **riskLevelDuringSignIn** field. For the cumulative risk associated with the user account as a whole, refer to **riskLevelAggregated**.

Below is a Splunk query that uses these fields to analyse risky sign-ins.

### List high-risk sign-ins

    index="task-3" sourcetype="azure:aad:signin"
    | where riskLevelDuringSignIn="high"
    | table _time, userPrincipalName, appDisplayName, ipAddress, location.countryOrRegion, riskLevelDuringSignIn, riskLevelAggregated
    | sort - _time

### Risk Detection Logs (azure:aad:riskdetection)

This log type is a detailed log generated when risks are detected. The difference between the regular sign-in log fields is the additional details related to the detection, for example:
- **riskEventType**: The type of the risk identified (e.g., anonymizedIPAddress, impossibleTravel).
- **riskLevel**: Shows how risky the detection is.

These logs also generate detections in other usage steps of M365 and Entra ID. We can check the type of activity that is being alerted by looking at the **activity** field.

    It's important to mention that we should not blindly trust the risk detections. For example, if no impossible travel alerts were generated, it doesn't mean that it didn't happen.
    Always validate sign-in logs when we suspect user behavior or when performing proactive threat hunting.

Below are two Splunk queries to analyse risk detection logs:
### List all risk detection logs

    index="task-3" sourcetype="azure:aad:identity_protection:riskdetection"

### List all risk detections related to anonymized IPs

    index="task-3" sourcetype="azure:aad:identity_protection:riskdetection"
    | where riskEventType="anonymizedIPAddress"
    | table _time, userPrincipalName, activity, ipAddress, location.countryOrRegion, riskLevel, riskEventType
    | sort - _time

### Risky User Logs (azure:aad:identity_protection:risky_user)
Every user has a risk level in Entra ID. This is calculated based on risk detection, and it's a way for Microsoft to alert admins to users who are likely compromised (or almost compromised) and require their attention.

Once a user changes its risk state, a risky user log is generated. This makes this log type a good trigger to perform proactive threat hunting to identify users who are likely compromised.

Below is a Splunk query to filter all risky user logs:
### List all risky user alerts

    index="task-3" sourcetype="azure:aad:identity_protection:risky_user"
    | table _time, userPrincipalName, riskLevel, riskState, riskDetail
    | sort - _time
