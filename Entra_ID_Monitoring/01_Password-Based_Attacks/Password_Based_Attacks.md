## Password-Based Attacks
    Stolen credentials are cheap. Credential-dumping sites and breach database provide attackers with ready-made lists of real usernames and passwords. Many of these credentials are tied to active corporate accounts where users have reused passwords from personal services.

    Entra ID is an especially attractive target because its authentication endpoints are internet-exposed by design. Any attacker with a username list can start attempting logins without ever touching the target's network perimeter. And when a login succeeds, it can look identical to a legitimate one, with no exploit, no malware, and no network anomalies. The only way to catch it is through log analysis.

# Password Spraying
    The attacker tries a small set of common passwords against many accounts. The goal is to stay under the lockout thresholds.
    Lockout thresholds are protection policies that lock accounts after reaching a pre-defined number of failed attempts. When a user is locked, they can't access their account until an admin or a defined timeout unlocks the account.

    How it looks in logs:

        Many failed sign-ins from the same IP address
        Failures spread across multiple different usernames
        All attempts occur within a short time window

# Brute Force
    In brute-force attacks, the attacker tries many passwords against a single account. This technique is less common against Entra ID due to the lockout policies. However, attacker can bypass this by throttling their attempts ad spreading them over a long period so they never exceed the lockout threshold.

    How it looks in logs:

        Many failed sign-ins against a single username
        High volume of attempts from a single IP or a small number of IPs
