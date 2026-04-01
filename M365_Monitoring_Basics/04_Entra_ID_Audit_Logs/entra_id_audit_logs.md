## Entra ID Audit Logs
    After confirming a compromised account, the next step is to identify the changes the attacker made to it. This is where we should use Audit Logs.

    Audit logs capture administrative actions and changes made within the Entra ID environment. Below are examples of post-compromise activites an attacker can perform, and we can hunt with logs:

        Resetting passwords to maintain access
        Adding new MFA methods or devices
        Assigning priviledged roles to escalate access
        Modifying user attributes
        Registering malicious applications

# Hunting for Post-Compromise Activity
    Within the same Splunk instance as the previous task, we can use the following query to filter for Entra ID audit logs and see account or environment changes:

        List all Audit logs
            " index=scenario sourcetype="azure:aad:audit" "

    Each event has its own particular properties, but you should pay additional attention to the fields below, since they appear in all events and can reveal what was changed, who changed, and the target:

        activityDisplayName
            The detailed activity or action that was performed by a user or app. All activites that generate logs are documented on Microsoft Entra audit log categories and activities (e.g., "Change user password". "Disable account").

        initiatedBy
            The account or app that performed the action. When the source of the action is a user account, this field contains its email address. In the case of an app. it will have the app name.

                initiatedBy: {
                app: {
                    appId: null
                    displayName: Microsoft password reset service // An app executed the change.
                    servicePrincipalId: d6871dee-b91e-42a7-b98e-beeb5357dfff
                    servicePrincipalName: null
                }
                user: null
                }

        targetResources
            The account or object that has been changed or affected by an action

                 targetResources: [
                {
                    displayName: null
                    groupType: null
                    id: d15f0e8c-80f7-41c0-b861-207d79cbb734
                    modifiedProperties: [
                {
                    displayName: ForceChangePassword
                    newValue: "True"
                    oldValue: "False"
                }
                {
                    displayName: Password // The Resource that was changed
                    newValue: null
                    oldValue: null
                }
                    ]
                    type: User
                    userPrincipalName: email@example.thm // The target identity
                 }
                 ]

        With that context, we can query specifically for the changes related to the compromised account we found in the previous task by using its user email address and changing the <ADD-USER-MAIL> placeholder in the following queries:

            List changes targeting a specific user

                index=scenario sourcetype="azure:aad:audit" targetResources{}.userPrincipalName="<ADD-USER-EMAIL>"
                | eval initiator=coalesce('initiatedBy.user.userPrincipalName', 'initiatedBy.app.displayName')
                | sort - _time
                | table _time, initiator, activityDisplayName, result, targetResources{}.userPrincipalName

            List changes performed by a user

                index=scenario sourcetype="azure:aad:audit" initiatedBy.user.userPrincipalName="<ADD-USER-EMAIL>"
                | sort - _time
                | table _time, initiatedBy.user.userPrincipalName, activityDisplayName, result, targetResources{}.userPrincipalName
