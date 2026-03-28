## Identity as the Target
    In a cloud-first organization like FineGalo, Entra ID is the gateway to everything. It authenticates users and authorizes access to services like Outlook, Teams, SharePoint, and internal applications. That means a single compromised account, especially a privileged one, can give an attacker legitimate access without needing malware, local system access, or foothold inside the network.

# Why attackers are targeting cloud credentials
    Attackers target cloud-based identity providers because they provide:
        Remote access from anywhere:
            Authentication occurs over the internet, so attackers don't need access to the internal network.

        Legitimate access to multiple services via SSO:
            One successful sign-in can unlock emails, files, chat, and connected apps for a user.

        Out of the radar of traditional tools:
            Firewalls and endpoint tools may see nothing suspicous because the attacker is using valid credentials or the authentication is occuring outside of their visibility.

        Direct access to high-value resources:
            Email and collaboration platforms contain sensitive data, internal communication, and often allow resetting account credentials and other authentication factors.

# Cloud Identity provides security gaps
    Cloud identity providers usually offer strong security controls, but those controls only work when they're properly configured and consistently enforced. In many incidents, attackers don't rely on advanced exploits; they simply exploit the lack of these security configurations.
