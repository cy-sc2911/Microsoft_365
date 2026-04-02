## Exploring M365 Logs
    In the Splunk instance, we can filter M365 unified audit logs with

        List all M365 Audit logs

            index="scenario" sourcetype="o365:management:activity"

        Each event has its own specific structure, but below are key fields in M365 audit logs that appear in all log types:

            Operation:
                The specific action performed (e.g., "New-InboxRule", "FileAccessed", "Send").
            UserId:
                The account that performed the action, usually an email address
            ClientIP or ClientIPAddress:
                The source IP address (Note that sometimes this information can be an Office 365 IP address. Ensure to always check the registrant for ClientIP).
            WorkLoad:
                The M365 service where the action occured (Exchange, SharePoint, OneDrive).
            ObjectId:
                The target resource (email address, file path, mailbox).

# Hunting for Post-Compromise M365 Activities
    For our investigation into M365 logs, identifying suspicious activities on the compromised account is essential. Here are some common post-compromise activities to be aware of:

        Mailbox Manipulation:
            Creation of inbox rules to delete, forward, or move emails
            Mass email deletion or moves to the deleted items
            Emails sent to external addresses
            Access from unusual IP addresses or locations

        File Operations:
            Mass file downloads from SharePoint or OneDrive
            Access to sensitive or executive-level documents
            File sharing to external domains
            Downloads of files the user wouldn't normally access

    Below is an enhanced Splunk query that might help as a starting point to identify what the attacker did with the user account found in task 4 by replacing the <ADD-USER=EMAIL> placeholder:

        List actions performed by a user
            index="scenario" sourcetype="o365:management:activity" UserId="<ADD-USER-EMAIL>"
            | sort - _time
            | eval sourceIP=coalesce('ClientIP', 'ClientIPAddress')
            | table _time, Operation, UserId, sourceIP, Workload, ObjectId

