## M365 Introduction
    Entra ID tells you who authenticated, Microsoft 365 logs tell you what they did after.

# What is Microsoft 365?
    Microsoft 365 is a collection of cloud-based productivity and collaboration services tied to Entra ID identities. Once a user authenticates through Entra ID, they gain access to services like:

        Exchange Online (Outlook):
            Email, calendars, and mailbox management
        SharePoint Online:
            Document storage, file sharing, and team sites
        OneDrive:
            Personal cloud storage
        Teams:
            Chat, meetings, and collaboration
        Other services:
            Power Bl, Dynamics, and various Microsoft apps

# Why M365 is a High-Value Target
    For an attacker with valid credentials, M365 services provide:

        Access to sensivite communications:
            Email contains business decisions, credentials, financial information, and confidential discussions.
        Document repositories:
            SharePoint and OneDrive store the company's intellectual property, customer data, and strategic plans.
        Persistent mechanisms:
            Mailbox rules, forwarding rules, and application permissions allow attackers to maintain access even after password changes.
        Further credential harvesting:
            Attackers can search for credentials, API keys, or sensitive information in emails and files.

# M365 Relevant Logs
    M365 generates detailed audit logs for user and administrative actions across all services. These logs are centralized in the Unified Audit Log, which captures events from Exchange, SharePoint, OneDrive, Teams, and other M365 services.

    Below are some key log categories relevant to investigations:

        Exchange (Mailbox) Logs:
            Mailbox access and email operations (read, send, delete)
            Mailbox rule creation (often used for persistence or email exfiltration)
            Mailbox permission changes
            Forwarding rule creation

        SharePoint and OneDrive Logs:
            File accessed, downloaded, or modified
            File sharing and permission changes
            Folder operations

        General M365 Activity
            Application permissions granted
            Service configurations changed
            Administrative actions performed
