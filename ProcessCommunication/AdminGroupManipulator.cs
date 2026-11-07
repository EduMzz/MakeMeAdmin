// 
// Copyright © 2010-2025, Sinclair Community College
// Licensed under the GNU General Public License, version 3.
// See the LICENSE file in the project root for full license information.  
//
// This file is part of Make Me Admin.
//
// Make Me Admin is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, version 3.
//
// Make Me Admin is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with Make Me Admin. If not, see <http://www.gnu.org/licenses/>.
//

namespace SinclairCC.MakeMeAdmin
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Security.Principal;
    using System.ServiceModel;
    using System.ServiceModel.Channels;

    /// <summary>
    /// This class implements the WCF service contract.
    /// </summary>
    [ServiceBehavior(InstanceContextMode = InstanceContextMode.Single, IncludeExceptionDetailInFaults = false)]
    public class AdminGroupManipulator : IAdminGroup
    {
        /// <summary>
        /// Adds a user to the local Administrators group.
        /// </summary>
        public void AddUserToAdministratorsGroup()
        {
            WindowsIdentity userIdentity = GetCallerIdentity();
            DemandManagementAdministrator(userIdentity);

            string remoteAddress = null;

            if (OperationContext.Current != null)
            {
                if (OperationContext.Current.IncomingMessageProperties != null)
                {
                    if (OperationContext.Current.IncomingMessageProperties.ContainsKey(RemoteEndpointMessageProperty.Name))
                    {
                        remoteAddress = ((RemoteEndpointMessageProperty)OperationContext.Current.IncomingMessageProperties[RemoteEndpointMessageProperty.Name]).Address;
                        if (remoteAddress != null)
                        {
                            ApplicationLog.WriteEvent(string.Format(Properties.Resources.RequestSentFromHost, remoteAddress), EventID.RemoteRequestInformation, System.Diagnostics.EventLogEntryType.Information);
                        }

                    }
                }
            }

            if (userIdentity != null)
            {
                EnsureNotAlreadyAdministrator(userIdentity);
                int timeoutMinutes = GetTimeoutForUser(userIdentity);
                DateTime expirationTime = DateTime.Now.AddMinutes(timeoutMinutes);
                if (!LocalAdministratorGroup.AddUser(userIdentity, expirationTime, remoteAddress, true))
                {
                    throw new InvalidOperationException("Windows did not add the account to the local Administrators group.");
                }
                ApplicationLog.WriteEvent(string.Format("Administrator {0} explicitly approved a temporary grant for {1}.", userIdentity.Name, userIdentity.User.Value), EventID.UserAddedToAdminsSuccess, System.Diagnostics.EventLogEntryType.Information);
            }
        }

        /// <summary>
        /// Grants temporary administrator membership to the interactive user in a session.
        /// This method is only callable by an administrator token. The session id is bound
        /// to that token so a standard user cannot target another logged-on account.
        /// </summary>
        public void AddSessionUserToAdministratorsGroup(int sessionID)
        {
            WindowsIdentity approver = GetCallerIdentity();
            // This is the only operation the narrow UAC helper may invoke. The
            // approved credential may be a different administrator account, so
            // authorization is bound to the authenticated token and session below.
            DemandAdministrator(approver);
            DemandSecureUacConfiguration(approver);

            int callerSessionID = GetTokenSessionId(approver);
            if ((sessionID <= 0) || (sessionID != callerSessionID))
            {
                ApplicationLog.WriteEvent(string.Format("Denied UAC grant request by {0}: requested session {1} did not match authenticated caller session {2}.", approver.Name, sessionID, callerSessionID), EventID.RemoteAccessFailure, System.Diagnostics.EventLogEntryType.Warning);
                throw new UnauthorizedAccessException("The approved session must be the session in which the administrator-authenticated helper is running.");
            }

            WindowsIdentity target = LsaLogonSessions.LogonSessions.GetWindowsIdentityForSessionId(sessionID);
            if ((target == null) || (target.User == null))
            {
                ApplicationLog.WriteEvent(string.Format("Denied UAC grant for session {0}: the session has no authenticated interactive user.", sessionID), EventID.RemoteAccessFailure, System.Diagnostics.EventLogEntryType.Warning);
                throw new UnauthorizedAccessException("There is no authenticated interactive user in the requested session.");
            }

            if (!UserIsAuthorized(target, Settings.LocalAllowedEntities, Settings.LocalDeniedEntities))
            {
                ApplicationLog.WriteEvent(string.Format("Denied UAC grant for session {0}, user {1}: the configured local request rules do not allow this account.", sessionID, target.User.Value), EventID.RemoteAccessFailure, System.Diagnostics.EventLogEntryType.Warning);
                throw new UnauthorizedAccessException("The account is denied by the configured local request rules.");
            }

            EnsureNotAlreadyAdministrator(target);
            EnsureNoExistingTemporaryGrant(target.User);
            int timeoutMinutes = GetTimeoutForUser(target);
            DateTime expirationTime = DateTime.Now.AddMinutes(timeoutMinutes);
            if (!LocalAdministratorGroup.AddUser(target, expirationTime, null, true))
            {
                ApplicationLog.WriteEvent(string.Format("Failed to grant temporary administrator membership to {0} after UAC approval.", target.User.Value), EventID.UserAddedToAdminsFailure, System.Diagnostics.EventLogEntryType.Warning);
                throw new InvalidOperationException("Windows did not add the account to the local Administrators group.");
            }
            ApplicationLog.WriteEvent(string.Format("Administrator {0} approved a temporary grant for session {1}, user {2}.", approver.Name, sessionID, target.User.Value), EventID.UserAddedToAdminsSuccess, System.Diagnostics.EventLogEntryType.Information);
        }

        /// <summary>
        /// Resolves the requester from the administrator-authenticated helper's own
        /// interactive session. A caller cannot choose another session's identity.
        /// </summary>
        public RemoteRequestIdentity GetRequestIdentityForSession(int sessionID)
        {
            WindowsIdentity approver = GetCallerIdentity();
            DemandAdministrator(approver);
            DemandSecureUacConfiguration(approver);
            int callerSessionID = GetTokenSessionId(approver);
            if ((sessionID <= 0) || (sessionID != callerSessionID))
            {
                throw new UnauthorizedAccessException("The helper may only identify the user in its authenticated session.");
            }

            using (WindowsIdentity target = LsaLogonSessions.LogonSessions.GetWindowsIdentityForSessionId(sessionID))
            {
                if ((target == null) || (target.User == null) || (target.Groups == null))
                {
                    throw new UnauthorizedAccessException("The helper session has no complete authenticated user identity.");
                }

                SecurityIdentifier[] groups = LsaLogonSessions.LogonSessions.GetGroupMemberships(target.Token);
                if ((groups != null) && (groups.Length > 2048))
                {
                    throw new InvalidOperationException("The requester has too many security groups for a bounded remote request.");
                }
                return new RemoteRequestIdentity
                {
                    Sid = target.User.Value,
                    Name = target.Name,
                    GroupSids = (groups ?? new SecurityIdentifier[0]).Select(group => group.Value).Distinct(StringComparer.OrdinalIgnoreCase).ToArray()
                };
            }
        }

        /// <summary>
        /// Processes a remote request only after the destination authenticates an
        /// administrator token. The requester identity is session-bound by the local
        /// service before the UAC helper sends it here.
        /// </summary>
        public void AddRemoteSessionUserToAdministratorsGroup(RemoteRequestIdentity target, int timeoutMinutes)
        {
            WindowsIdentity approver = GetCallerIdentity();
            DemandAdministrator(approver);
            SecurityIdentifier targetSid = ValidateRemoteRequestIdentity(target);
            if ((timeoutMinutes < 1) || (timeoutMinutes > 1440))
            {
                throw new ArgumentOutOfRangeException("timeoutMinutes", "Remote grant durations must be between 1 and 1440 minutes.");
            }
            if (!Settings.AllowRemoteRequests)
            {
                throw new UnauthorizedAccessException("Remote requests are disabled by this computer's configuration or policy.");
            }
            if (!UserIsAuthorized(target, Settings.LocalAllowedEntities, Settings.LocalDeniedEntities)
                || !UserIsAuthorized(target, Settings.RemoteAllowedEntities, Settings.RemoteDeniedEntities))
            {
                throw new UnauthorizedAccessException("The requester is denied by this computer's local or remote request rules.");
            }
            EnsureNotAlreadyAdministrator(targetSid, target.GroupSids.Select(sid => new SecurityIdentifier(sid)).ToArray());
            EnsureNoExistingTemporaryGrant(targetSid);

            string remoteAddress = null;
            if ((OperationContext.Current != null) && OperationContext.Current.IncomingMessageProperties.ContainsKey(RemoteEndpointMessageProperty.Name))
            {
                remoteAddress = ((RemoteEndpointMessageProperty)OperationContext.Current.IncomingMessageProperties[RemoteEndpointMessageProperty.Name]).Address;
            }

            int effectiveTimeout = GetTimeoutForUser(target, timeoutMinutes);
            DateTime expirationTime = DateTime.Now.AddMinutes(effectiveTimeout);
            if (!LocalAdministratorGroup.AddRemoteUser(targetSid, target.Name, expirationTime, remoteAddress))
            {
                throw new InvalidOperationException("Windows did not add the approved remote account to the local Administrators group.");
            }
            ApplicationLog.WriteEvent(string.Format("Administrator {0} approved a remote temporary grant for requester {1} ({2}) from {3}.", approver.Name, target.Name, targetSid.Value, remoteAddress ?? "unknown host"), EventID.UserAddedToAdminsSuccess, System.Diagnostics.EventLogEntryType.Information);
        }

        /// <summary>
        /// Performs an explicit administrator grant for a logged-on user. This method is
        /// intended for the administrator management interface and SSH command mode.
        /// </summary>
        public void AdminGrantSessionUser(int sessionID, int timeoutMinutes)
        {
            WindowsIdentity approver = GetCallerIdentity();
            DemandManagementAdministrator(approver);
            if ((sessionID <= 0) || (timeoutMinutes < 1) || (timeoutMinutes > 1440))
            {
                ApplicationLog.WriteEvent(string.Format("Denied administrator grant request by {0}: invalid session or duration ({1}, {2}).", approver.Name, sessionID, timeoutMinutes), EventID.RemoteAccessFailure, System.Diagnostics.EventLogEntryType.Warning);
                throw new ArgumentOutOfRangeException("timeoutMinutes", "Session IDs must be positive and grant durations must be between 1 and 1440 minutes.");
            }

            WindowsIdentity target = LsaLogonSessions.LogonSessions.GetWindowsIdentityForSessionId(sessionID);
            if ((target == null) || (target.User == null))
            {
                ApplicationLog.WriteEvent(string.Format("Denied administrator grant request by {0}: session {1} has no authenticated user.", approver.Name, sessionID), EventID.RemoteAccessFailure, System.Diagnostics.EventLogEntryType.Warning);
                throw new ArgumentException("The requested session does not have an authenticated user.", "sessionID");
            }

            EnsureNotAlreadyAdministrator(target);
            EnsureNoExistingTemporaryGrant(target.User);
            if (!LocalAdministratorGroup.AddUser(target, DateTime.Now.AddMinutes(timeoutMinutes), null, true))
            {
                ApplicationLog.WriteEvent(string.Format("Failed to grant administrator membership to {0} after administrator authorization.", target.User.Value), EventID.UserAddedToAdminsFailure, System.Diagnostics.EventLogEntryType.Warning);
                throw new InvalidOperationException("Windows did not add the account to the local Administrators group.");
            }
            ApplicationLog.WriteEvent(string.Format("Administrator {0} granted {1} minutes of temporary administrator membership to session {2}, user {3}.", approver.Name, timeoutMinutes, sessionID, target.User.Value), EventID.UserAddedToAdminsSuccess, System.Diagnostics.EventLogEntryType.Information);
        }

        /// <summary>
        /// Checks whether the authenticated caller is permitted to use an administrator
        /// management surface. Only a small operation label is accepted and logged.
        /// </summary>
        public void AuthorizeAdminManagement(string operation)
        {
            WindowsIdentity approver = GetCallerIdentity();
            DemandManagementAdministrator(approver);
            string safeOperation = (operation == "config" || operation == "grants" || operation == "audit" || operation == "management") ? operation : "management";
            ApplicationLog.WriteEvent(string.Format("Administrator {0} used the {1} management interface.", approver.Name, safeOperation), EventID.DebugMessage, System.Diagnostics.EventLogEntryType.Information);
        }

        /// <summary>
        /// Lists logged-on sessions using the service's LocalSystem token. This
        /// information is exposed only to authenticated administrators.
        /// </summary>
        public string[] GetLoggedOnSessions()
        {
            WindowsIdentity approver = GetCallerIdentity();
            DemandManagementAdministrator(approver);
            List<string> sessions = new List<string>();
            foreach (int sessionID in LsaLogonSessions.LogonSessions.GetLoggedOnUserSessionIds())
            {
                if (sessionID <= 0) { continue; }
                using (WindowsIdentity user = LsaLogonSessions.LogonSessions.GetWindowsIdentityForSessionId(sessionID))
                {
                    if ((user != null) && (user.User != null))
                    {
                        sessions.Add(string.Format(System.Globalization.CultureInfo.InvariantCulture, "{0}\t{1}\t{2}", sessionID, user.User.Value, user.Name));
                    }
                }
            }
            return sessions.ToArray();
        }

        /// <summary>
        /// Removes a specified account from the Administrators group after verifying that
        /// the caller has an administrator token.
        /// </summary>
        public void AdminRemoveUserFromAdministratorsGroup(string sid, RemovalReason reason)
        {
            WindowsIdentity approver = GetCallerIdentity();
            DemandManagementAdministrator(approver);

            SecurityIdentifier targetSid;
            try
            {
                targetSid = new SecurityIdentifier(sid);
            }
            catch (ArgumentException exception)
            {
                throw new ArgumentException("A valid non-Administrators user SID is required.", "sid", exception);
            }
            if (targetSid.IsWellKnown(WellKnownSidType.BuiltinAdministratorsSid))
            {
                throw new ArgumentException("A valid non-Administrators user SID is required.", "sid");
            }
            if (!targetSid.IsAccountSid())
            {
                throw new ArgumentException("A user account SID is required.", "sid");
            }
            if (!Enum.IsDefined(typeof(RemovalReason), reason))
            {
                throw new ArgumentOutOfRangeException("reason", "A defined removal reason is required.");
            }

            EncryptedSettings grants = new EncryptedSettings(EncryptedSettings.SettingsFilePath);
            if (!grants.ContainsSID(targetSid))
            {
                ApplicationLog.WriteEvent(string.Format("Denied revocation request by {0} for {1}: no temporary Make Me Admin grant exists.", approver.Name, targetSid.Value), EventID.RemoteAccessFailure, System.Diagnostics.EventLogEntryType.Warning);
                throw new InvalidOperationException("The SID is not a temporary grant managed by Make Me Admin; permanent Administrators membership was left unchanged.");
            }

            if (!LocalAdministratorGroup.RemoveUser(targetSid, reason))
            {
                throw new InvalidOperationException("Windows could not revoke the tracked administrator grant.");
            }
            ApplicationLog.WriteEvent(string.Format("Administrator {0} revoked temporary administrator membership for {1}.", approver.Name, targetSid.Value), EventID.UserRemovedFromAdminsSuccess, System.Diagnostics.EventLogEntryType.Information);
        }

        private static WindowsIdentity GetCallerIdentity()
        {
            if ((ServiceSecurityContext.Current == null) || (ServiceSecurityContext.Current.WindowsIdentity == null))
            {
                throw new UnauthorizedAccessException("The service could not authenticate the caller.");
            }

            return ServiceSecurityContext.Current.WindowsIdentity;
        }

        private static void DemandAdministrator(WindowsIdentity identity)
        {
            SecurityIdentifier administrators = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
            if ((identity == null) || !identity.IsAuthenticated || !new WindowsPrincipal(identity).IsInRole(administrators))
            {
                string caller = (identity == null) ? "unknown caller" : identity.Name;
                ApplicationLog.WriteEvent(string.Format("Denied privileged IPC operation from {0}; an authenticated administrator token was not presented.", caller), EventID.RemoteAccessFailure, System.Diagnostics.EventLogEntryType.Warning);
                throw new FaultException("An authenticated Windows administrator token is required.");
            }
        }

        private static void DemandSecureUacConfiguration(WindowsIdentity identity)
        {
            if (Settings.UserGrantUacSecurityRequirementsSatisfied) { return; }

            string caller = (identity == null) ? "unknown caller" : identity.Name;
            ApplicationLog.WriteEvent(string.Format("Denied UAC grant helper for {0}: Windows is not configured to require UAC credentials on the secure desktop.", caller), EventID.RemoteAccessFailure, System.Diagnostics.EventLogEntryType.Warning);
            throw new UnauthorizedAccessException("Local user grants require Windows UAC, credential prompting, and secure desktop prompting. Enable the Windows UAC policies at their management source before requesting access.");
        }

        /// <summary>
        /// Management commands may run in an SSH service session (session 0) or
        /// in the administrator's own desktop session. This prevents an ordinary
        /// user from asking the UAC grant helper to become a general-purpose
        /// administrative console with alternate credentials.
        /// </summary>
        private static void DemandManagementAdministrator(WindowsIdentity identity)
        {
            DemandAdministrator(identity);
            int sessionID = GetTokenSessionId(identity);
            if (sessionID <= 0) { return; }

            using (WindowsIdentity sessionUser = LsaLogonSessions.LogonSessions.GetWindowsIdentityForSessionId(sessionID))
            {
                if ((sessionUser == null) || (sessionUser.User == null) || (sessionUser.User != identity.User))
                {
                    string caller = (identity.User == null) ? identity.Name : identity.User.Value;
                    ApplicationLog.WriteEvent(string.Format("Denied administrator management from {0}: the caller is not the account logged on to session {1}.", caller, sessionID), EventID.RemoteAccessFailure, System.Diagnostics.EventLogEntryType.Warning);
                    throw new FaultException("Administrator management from an interactive session must use the administrator account logged on to that session. Use the authorized SSH administrator session for headless management.");
                }
            }
        }

        private static void EnsureNotAlreadyAdministrator(WindowsIdentity identity)
        {
            if (LocalAdministratorGroup.IsMemberOfAdministrators(identity))
            {
                ApplicationLog.WriteEvent(string.Format("Denied temporary grant for {0}: target already has administrator membership.", identity.User.Value), EventID.RemoteAccessFailure, System.Diagnostics.EventLogEntryType.Warning);
                throw new InvalidOperationException("The target user already has administrator membership; Make Me Admin will not create a timed grant that could later remove permanent membership.");
            }
        }

        private static void EnsureNotAlreadyAdministrator(SecurityIdentifier userSid, SecurityIdentifier[] groupSids)
        {
            if (LocalAdministratorGroup.IsMemberOfAdministrators(userSid, groupSids))
            {
                throw new InvalidOperationException("The remote requester already has administrator membership on this computer.");
            }
        }

        private static SecurityIdentifier ValidateRemoteRequestIdentity(RemoteRequestIdentity target)
        {
            if ((target == null) || string.IsNullOrWhiteSpace(target.Sid) || string.IsNullOrWhiteSpace(target.Name)
                || (target.Sid.Length > 184) || (target.Name.Length > 1024) || (target.GroupSids == null) || (target.GroupSids.Length > 2048))
            {
                throw new ArgumentException("The remote requester identity is incomplete or exceeds its supported limits.", "target");
            }

            SecurityIdentifier targetSid;
            try { targetSid = new SecurityIdentifier(target.Sid); }
            catch (ArgumentException exception) { throw new ArgumentException("The remote requester SID is invalid.", "target", exception); }
            if (!targetSid.IsAccountSid()) { throw new ArgumentException("A user account SID is required.", "target"); }

            foreach (string groupSid in target.GroupSids)
            {
                if (string.IsNullOrWhiteSpace(groupSid) || (groupSid.Length > 184)) { throw new ArgumentException("A remote requester group SID is invalid.", "target"); }
                try { new SecurityIdentifier(groupSid); }
                catch (ArgumentException exception) { throw new ArgumentException("A remote requester group SID is invalid.", "target", exception); }
            }
            return targetSid;
        }

        private static bool UserIsAuthorized(RemoteRequestIdentity identity, string[] allowedSidsList, string[] deniedSidsList)
        {
            SecurityIdentifier userSid = new SecurityIdentifier(identity.Sid);
            SecurityIdentifier[] groupSids = identity.GroupSids.Select(sid => new SecurityIdentifier(sid)).ToArray();
            if (AccountListContainsIdentity(deniedSidsList, userSid, groupSids)) { return false; }
            return (allowedSidsList == null) || (allowedSidsList.Length == 0) || AccountListContainsIdentity(allowedSidsList, userSid, groupSids);
        }

        private static int GetTimeoutForUser(RemoteRequestIdentity identity, int requestedTimeoutMinutes)
        {
            int timeoutMinutes = Math.Max(Settings.AdminRightsTimeout, requestedTimeoutMinutes);
            Dictionary<string, string> overrides = Settings.TimeoutOverrides;
            IEnumerable<string> identities = new[] { identity.Sid }.Concat(identity.GroupSids);
            foreach (string sid in identities)
            {
                string value;
                int overrideMinutes;
                if (overrides.TryGetValue(sid, out value) && int.TryParse(value, out overrideMinutes))
                {
                    timeoutMinutes = Math.Max(timeoutMinutes, overrideMinutes);
                }
            }
            return Math.Max(1, Math.Min(1440, timeoutMinutes));
        }

        private static bool AccountListContainsIdentity(string[] accountList, SecurityIdentifier userSid, SecurityIdentifier[] groupSids)
        {
            if (accountList == null) { return false; }
            foreach (string account in accountList)
            {
                SecurityIdentifier configuredSid = LocalAdministratorGroup.GetSIDFromAccountName(account);
                if (configuredSid == userSid) { return true; }
                if ((configuredSid != null) && groupSids.Any(groupSid => groupSid == configuredSid)) { return true; }
            }
            return false;
        }

        private static void EnsureNoExistingTemporaryGrant(SecurityIdentifier sid)
        {
            EncryptedSettings grants = new EncryptedSettings(EncryptedSettings.SettingsFilePath);
            if (grants.ContainsSID(sid))
            {
                ApplicationLog.WriteEvent(string.Format("Denied duplicate temporary grant for {0}.", sid.Value), EventID.RemoteAccessFailure, System.Diagnostics.EventLogEntryType.Warning);
                throw new InvalidOperationException("Make Me Admin already tracks a temporary grant for this user; a duplicate grant was rejected.");
            }
        }

        private static int GetTokenSessionId(WindowsIdentity identity)
        {
            int sessionID;
            int returnedLength;
            if (!NativeMethods.GetTokenInformation(identity.Token, 12, out sessionID, sizeof(int), out returnedLength))
            {
                throw new System.ComponentModel.Win32Exception(System.Runtime.InteropServices.Marshal.GetLastWin32Error());
            }
            return sessionID;
        }

        /// <summary>
        /// Removes a user from the local Administrators group.
        /// </summary>
        /// <param name="reason">
        /// The reason that the rights are being removed.
        /// </param>
        public void RemoveUserFromAdministratorsGroup(RemovalReason reason)
        {
            WindowsIdentity userIdentity = null;

            if (ServiceSecurityContext.Current != null)
            {
                userIdentity = ServiceSecurityContext.Current.WindowsIdentity;
            }

            if (userIdentity != null)
            {
                if (!LocalAdministratorGroup.RemoveUser(userIdentity.User, reason))
                {
                    throw new InvalidOperationException("Windows could not remove the current user's managed administrator membership.");
                }
            }
        }

        /// <summary>
        /// Returns a value indicating whether a user is in the
        /// list of added users.
        /// </summary>
        /// <returns>
        /// Returns true if the given user is already in the list of added
        /// users. Otherwise, false is returned.
        /// </returns>
        public bool UserIsInList()
        {
            WindowsIdentity userIdentity = null;

            if (ServiceSecurityContext.Current != null)
            {
                userIdentity = ServiceSecurityContext.Current.WindowsIdentity;
            }

            if (userIdentity != null)
            {
                EncryptedSettings encryptedSettings = new EncryptedSettings(EncryptedSettings.SettingsFilePath);
                return encryptedSettings.ContainsSID(userIdentity.User);
            }
            else
            {
                return false;
            }
        }

        
        public bool UserSessionIsInList(int sessionID)
        {
            SecurityIdentifier sid = LsaLogonSessions.LogonSessions.GetSidForSessionId(sessionID);
            if (sid != null)
            {
                EncryptedSettings encryptedSettings = new EncryptedSettings(EncryptedSettings.SettingsFilePath);
                return encryptedSettings.ContainsSID(sid);
            }
            else
            {
                return false;
            }
        }
        

        /// <summary>
        /// Determines whether the given array of SIDs/Identities contains the given target user identity.
        /// </summary>
        /// <param name="accountList">
        /// An array to be searched for the target identity.
        /// </param>
        /// <param name="userIdentity">
        /// The user identity to check to see if they or one of the groups they belong to are in the list of identities.
        /// </param>
        /// <returns>
        /// Returns true if the given target identity is present in the array of SIDs/Identities.
        /// If the array is null or empty, false is returned.
        /// </returns>
        private static bool AccountListContainsIdentity(string[] accountList, WindowsIdentity userIdentity)
        {
            if ((accountList != null) && (accountList.Length > 0))
            {
                foreach (string account in accountList)
                {
                    SecurityIdentifier sid = LocalAdministratorGroup.GetSIDFromAccountName(account);
                    /*
#if DEBUG
                    ApplicationLog.WriteEvent(string.Format("Checking user against SID {0}.", sid.Value), EventID.DebugMessage, System.Diagnostics.EventLogEntryType.Information);
#endif
                    */


                    // If the user's SID or name is in the list, return true
                    if (userIdentity.User == sid)
                    {
                        /*
#if DEBUG
                        ApplicationLog.WriteEvent(string.Format("User SID matches {0}.", sid.Value), EventID.DebugMessage, System.Diagnostics.EventLogEntryType.Information);
#endif
                        */
                        return true;
                    }

                    // If any of the user's authorization groups are in the denied list, the user is not authorized.
                    foreach (IdentityReference groupsid in userIdentity.Groups)
                    {
                        // Translate the NT Account (Domain\User) to SID if needed, and check the resulting values.
                        if (sid == (SecurityIdentifier)groupsid.Translate(typeof(SecurityIdentifier)))
                        {
                            /*
#if DEBUG
                            ApplicationLog.WriteEvent("SIDs match!", EventID.DebugMessage, System.Diagnostics.EventLogEntryType.Information);
#endif
                            */
                            return true;
                        }
                    }
                }
            }
#if DEBUG
            ApplicationLog.WriteEvent("Was not able to find a matching SID.", EventID.DebugMessage, System.Diagnostics.EventLogEntryType.Information);
#endif
            return false;
        }


        /// <summary>
        /// Determines whether the given user is authorized to obtain administrator rights.
        /// </summary>
        /// <param name="userIdentity">
        /// An identity object representing the user whose authorization is to be checked.
        /// </param>
        /// <param name="allowedSidsList">
        /// The list of allowed SIDs and principal names against which the user's identity is checked.
        /// </param>
        /// <param name="deniedSidsList">
        /// The list of denied SIDs and principal names against which the user's identity is checked.
        /// </param>
        /// <returns>
        /// Returns true if the user is authorized to obtain administrator rights.
        /// </returns>
        public bool UserIsAuthorized(WindowsIdentity userIdentity, string[] allowedSidsList, string[] deniedSidsList)
        {
            /*
            WindowsIdentity userIdentity = null;

            if (ServiceSecurityContext.Current != null)
            {
                userIdentity = ServiceSecurityContext.Current.WindowsIdentity;
            }
            */

            if (userIdentity == null)
            {
#if DEBUG
                ApplicationLog.WriteEvent("User identity is null.", EventID.DebugMessage, System.Diagnostics.EventLogEntryType.Information);
#endif
                return false;
            }

            if (((deniedSidsList != null) && (deniedSidsList.Length > 0)) && AccountListContainsIdentity(deniedSidsList, userIdentity))
            { // The denied list contains entries. Check the user against that list first.
#if DEBUG
                ApplicationLog.WriteEvent("User is denied.", EventID.DebugMessage, System.Diagnostics.EventLogEntryType.Information);
#endif
                return false;
            }

            // The user hasn't been denied yet, so now we check for authorization.

            // Check the authorization list.
            if (allowedSidsList == null)
            { // The allowed list is null, meaning everyone is allowed administrator rights.
                /*
#if DEBUG
                ApplicationLog.WriteEvent("Allowed SIDs list is null.", EventID.DebugMessage, System.Diagnostics.EventLogEntryType.Information);
#endif
                */

                return true;
            }
            else if (allowedSidsList.Length == 0)
            { // The allowed list is empty, meaning no one is allowed administrator rights.
                /*
#if DEBUG
                ApplicationLog.WriteEvent("Allowed SIDs list is empty.", EventID.DebugMessage, System.Diagnostics.EventLogEntryType.Information);
#endif
                */

                return false;
            }
            else
            { // The allowed list has entries.
#if DEBUG
                ApplicationLog.WriteEvent("Made it to the allowed list check. That's good.", EventID.DebugMessage, System.Diagnostics.EventLogEntryType.Information);
#endif
                if (AccountListContainsIdentity(allowedSidsList, userIdentity))
                {
                    return true;
                }

                // The user was not found in the allowed list, so the user is not authorized.
                return false;
            }
        }

        /// <summary>
        /// Gets the administrator rights timeout value for the given user.
        /// </summary>
        /// <param name="userIdentity">
        /// An identity object representing the user whose authorization is to be checked.
        /// </param>
        /// <returns>
        /// Returns the number of minutes at which the user's administrator rights should expire.
        /// </returns>
        public static int GetTimeoutForUser(WindowsIdentity userIdentity)
        {
            Dictionary<string, string> overrides = Settings.TimeoutOverrides;

            int overrideMinutes = int.MinValue;
            int timeoutMinutes = Settings.AdminRightsTimeout;

            if (overrides.ContainsKey(userIdentity.User.Value))
            {
                overrideMinutes = int.MinValue;
                if (int.TryParse(overrides[userIdentity.User.Value], out overrideMinutes))
                {
                    timeoutMinutes = Math.Max(timeoutMinutes, overrideMinutes);
                }
            }

            foreach (SecurityIdentifier sid in userIdentity.Groups)
            {
                if (overrides.ContainsKey(sid.Value))
                {
                    overrideMinutes = int.MinValue;
                    if (int.TryParse(overrides[sid.Value], out overrideMinutes))
                    {
                        timeoutMinutes = Math.Max(timeoutMinutes, overrideMinutes);
                    }
                }
            }

            return Math.Max(1, Math.Min(1440, timeoutMinutes));
        }
    }
}
