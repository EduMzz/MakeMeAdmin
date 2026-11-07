//
// Copyright © 2010-2025, Sinclair Community College
// Licensed under the GNU General Public License, version 3.
//
// Make Me Admin's privileged module. The service runs under the Service Control
// Manager; the same protected executable provides administrator-only command mode.
//
namespace SinclairCC.MakeMeAdmin
{
    using System;
    using System.Collections.Generic;
    using System.Diagnostics;
    using System.Globalization;
    using System.Linq;
    using System.Reflection;
    using System.Runtime.InteropServices;
    using System.Security.Principal;
    using System.ServiceModel;
    using System.ServiceProcess;

    /// <summary>
    /// Contains the service and administrator command-line entry points.
    /// </summary>
    internal static class Program
    {
        private const uint AttachParentConsole = 0xFFFFFFFF;

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool AttachConsole(uint processId);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool FreeConsole();

        /// <summary>
        /// The service binary supports a narrow UAC helper operation and an
        /// administrator-only management CLI in addition to service mode.
        /// </summary>
        [STAThread]
        private static int Main(string[] args)
        {
            if ((args != null) && (args.Length > 0))
            {
                if (string.Equals(args[0], "--grant-session", StringComparison.OrdinalIgnoreCase))
                {
                    FreeConsole();
                    return RunUacGrant(args);
                }
                if (string.Equals(args[0], "--grant-remote", StringComparison.OrdinalIgnoreCase))
                {
                    FreeConsole();
                    return RunUacRemoteGrant(args);
                }
                if (string.Equals(args[0], "admin", StringComparison.OrdinalIgnoreCase))
                {
                    if ((args.Length > 1) && string.Equals(args[1], "gui", StringComparison.OrdinalIgnoreCase)) { FreeConsole(); }
                    AttachConsole(AttachParentConsole);
                    Console.SetOut(new System.IO.StreamWriter(Console.OpenStandardOutput()) { AutoFlush = true });
                    Console.SetError(new System.IO.StreamWriter(Console.OpenStandardError()) { AutoFlush = true });
                    return RunAdministratorCommand(args.Skip(1).ToArray());
                }

                AttachConsole(AttachParentConsole);
                Console.SetOut(new System.IO.StreamWriter(Console.OpenStandardOutput()) { AutoFlush = true });
                Console.SetError(new System.IO.StreamWriter(Console.OpenStandardError()) { AutoFlush = true });
                if (string.Equals(args[0], "--help", StringComparison.OrdinalIgnoreCase)
                    || string.Equals(args[0], "-h", StringComparison.OrdinalIgnoreCase)
                    || string.Equals(args[0], "/?", StringComparison.OrdinalIgnoreCase))
                {
                    PrintHelp();
                    return 0;
                }

                Console.Error.WriteLine("Unknown service command. Use --help for command-line usage.");
                PrintHelp();
                return 2;
            }

            ServiceBase.Run(new MakeMeAdminService());
            return 0;
        }

        private static int RunUacGrant(string[] args)
        {
            int sessionID;
            if ((args.Length != 2) || !int.TryParse(args[1], NumberStyles.None, CultureInfo.InvariantCulture, out sessionID) || (sessionID <= 0))
            {
                return 2;
            }

            if (!IsAdministratorToken(WindowsIdentity.GetCurrent()))
            {
                return 5;
            }

            try
            {
                IAdminGroup channel = CreateLocalChannel();
                try
                {
                    channel.AddSessionUserToAdministratorsGroup(sessionID);
                    CloseChannel(channel);
                    return 0;
                }
                catch
                {
                    AbortChannel(channel);
                    throw;
                }
            }
            catch (Exception exception)
            {
                try { Console.Error.WriteLine(exception.Message); } catch { }
                return 1;
            }
        }

        private static int RunUacRemoteGrant(string[] args)
        {
            try { return RunUacRemoteGrantCore(args); }
            catch (Exception exception)
            {
                System.Windows.Forms.MessageBox.Show(exception.Message, "Make Me Admin — remote request failed", System.Windows.Forms.MessageBoxButtons.OK, System.Windows.Forms.MessageBoxIcon.Warning);
                return 1;
            }
        }

        private static int RunUacRemoteGrantCore(string[] args)
        {
            if ((args.Length != 2) || string.IsNullOrWhiteSpace(args[1]) || (args[1].Length > 253)
                || (Uri.CheckHostName(args[1]) == UriHostNameType.Unknown)
                || args[1].Any(char.IsWhiteSpace) || args[1].IndexOfAny(new[] { '/', '\\', '"' }) >= 0)
            {
                return 2;
            }
            if (!IsAdministratorToken(WindowsIdentity.GetCurrent())) { return 5; }

            int sessionID = Process.GetCurrentProcess().SessionId;
            RemoteRequestIdentity requester;
            IAdminGroup localChannel = CreateLocalChannel();
            try
            {
                requester = localChannel.GetRequestIdentityForSession(sessionID);
                CloseChannel(localChannel);
            }
            catch
            {
                AbortChannel(localChannel);
                throw;
            }

            string message = string.Format(CultureInfo.CurrentCulture,
                "Approve a request to add {0} ({1}) to the Administrators group on {2}? The destination applies its configured local and remote access rules and grant duration.",
                requester.Name, requester.Sid, args[1]);
            if (System.Windows.Forms.MessageBox.Show(message, "Make Me Admin — remote approval", System.Windows.Forms.MessageBoxButtons.YesNo, System.Windows.Forms.MessageBoxIcon.Warning, System.Windows.Forms.MessageBoxDefaultButton.Button2) != System.Windows.Forms.DialogResult.Yes)
            {
                return 1223;
            }

            Uri endpoint = new UriBuilder("net.tcp", args[1], Settings.TCPServicePort, "/MakeMeAdmin/Service").Uri;
            NetTcpBinding binding = new NetTcpBinding(System.ServiceModel.SecurityMode.Transport)
            {
                MaxBufferSize = 1048576,
                MaxReceivedMessageSize = 1048576
            };
            ChannelFactory<IAdminGroup> factory = new ChannelFactory<IAdminGroup>(binding, new EndpointAddress(endpoint));
            IAdminGroup remoteChannel = factory.CreateChannel();
            try
            {
                remoteChannel.AddRemoteSessionUserToAdministratorsGroup(requester, Math.Max(1, Math.Min(1440, Settings.AdminRightsTimeout)));
                CloseChannel(remoteChannel);
                return 0;
            }
            catch
            {
                AbortChannel(remoteChannel);
                throw;
            }
        }

        private static int RunAdministratorCommand(string[] args)
        {
            bool administrator = IsAdministratorToken(WindowsIdentity.GetCurrent());
            if (!administrator)
            {
                if ((args.Length == 1) && string.Equals(args[0], "gui", StringComparison.OrdinalIgnoreCase) && IsAdministratorAccount(WindowsIdentity.GetCurrent()))
                {
                    FreeConsole();
                    Process.Start(new ProcessStartInfo(Assembly.GetExecutingAssembly().Location, "admin gui") { UseShellExecute = true, Verb = "runas", WorkingDirectory = AppDomain.CurrentDomain.BaseDirectory });
                    return 0;
                }
            }

            try
            {
                if ((args.Length == 0) || string.Equals(args[0], "help", StringComparison.OrdinalIgnoreCase))
                {
                    PrintHelp();
                    return 0;
                }

                AuthorizeManagement(args.Length > 0 ? args[0] : "management");
                if ((args.Length == 1) && string.Equals(args[0], "gui", StringComparison.OrdinalIgnoreCase))
                {
                    System.Windows.Forms.Application.EnableVisualStyles();
                    System.Windows.Forms.Application.SetCompatibleTextRenderingDefault(false);
                    System.Windows.Forms.Application.Run(new AdminManagementForm());
                    return 0;
                }

                if (string.Equals(args[0], "config", StringComparison.OrdinalIgnoreCase))
                {
                    return RunConfigCommand(args.Skip(1).ToArray());
                }
                if (string.Equals(args[0], "grants", StringComparison.OrdinalIgnoreCase) && (args.Length == 2) && string.Equals(args[1], "list", StringComparison.OrdinalIgnoreCase))
                {
                    return ListGrants();
                }
                if (string.Equals(args[0], "sessions", StringComparison.OrdinalIgnoreCase) && (args.Length == 2) && string.Equals(args[1], "list", StringComparison.OrdinalIgnoreCase))
                {
                    return ListSessions();
                }
                if (string.Equals(args[0], "grant-session", StringComparison.OrdinalIgnoreCase) && ((args.Length == 2) || (args.Length == 3)))
                {
                    int sessionID;
                    int duration = Settings.AdminRightsTimeout;
                    if (!int.TryParse(args[1], NumberStyles.None, CultureInfo.InvariantCulture, out sessionID) || (sessionID <= 0)) { throw new ArgumentException("Session ID must be a positive integer."); }
                    if ((args.Length == 3) && (!int.TryParse(args[2], NumberStyles.None, CultureInfo.InvariantCulture, out duration) || (duration < 1) || (duration > 1440))) { throw new ArgumentException("Duration must be between 1 and 1440 minutes."); }
                    IAdminGroup channel = CreateLocalChannel();
                    try { channel.AdminGrantSessionUser(sessionID, duration); CloseChannel(channel); }
                    catch { AbortChannel(channel); throw; }
                    Console.WriteLine("Granted {0} minutes to the authenticated user in session {1}.", duration, sessionID);
                    return 0;
                }
                if (string.Equals(args[0], "revoke", StringComparison.OrdinalIgnoreCase) && (args.Length == 2))
                {
                    IAdminGroup channel = CreateLocalChannel();
                    try { channel.AdminRemoveUserFromAdministratorsGroup(args[1], RemovalReason.UserRequest); CloseChannel(channel); }
                    catch { AbortChannel(channel); throw; }
                    Console.WriteLine("Revocation request sent for {0}.", args[1]);
                    return 0;
                }
                if (string.Equals(args[0], "audit", StringComparison.OrdinalIgnoreCase))
                {
                    int count = 50;
                    if ((args.Length > 2) || ((args.Length == 2) && (!int.TryParse(args[1], out count) || (count < 1) || (count > 500)))) { throw new ArgumentException("Audit count must be between 1 and 500."); }
                    return ShowAudit(count);
                }

                PrintHelp();
                return 2;
            }
            catch (Exception exception)
            {
                Console.Error.WriteLine("Error: " + exception.Message);
                return 1;
            }
        }

        private static void AuthorizeManagement(string operation)
        {
            IAdminGroup channel = CreateLocalChannel();
            try
            {
                channel.AuthorizeAdminManagement(operation);
                CloseChannel(channel);
            }
            catch
            {
                AbortChannel(channel);
                throw;
            }
        }

        internal static string ExecuteAdminCommandForGui(string commandLine)
        {
            System.IO.StringWriter output = new System.IO.StringWriter(CultureInfo.InvariantCulture);
            System.IO.StringWriter error = new System.IO.StringWriter(CultureInfo.InvariantCulture);
            System.IO.TextWriter oldOut = Console.Out;
            System.IO.TextWriter oldError = Console.Error;
            try
            {
                Console.SetOut(output);
                Console.SetError(error);
                int result = RunAdministratorCommand(SplitCommandLine(commandLine));
                if (result != 0) { error.WriteLine("Command exit code: " + result.ToString(CultureInfo.InvariantCulture)); }
                return output.ToString() + error.ToString();
            }
            finally
            {
                Console.SetOut(oldOut);
                Console.SetError(oldError);
                output.Dispose();
                error.Dispose();
            }
        }

        private static string[] SplitCommandLine(string text)
        {
            List<string> arguments = new List<string>();
            System.Text.StringBuilder current = new System.Text.StringBuilder();
            bool quoted = false;
            bool tokenStarted = false;
            foreach (char character in text ?? string.Empty)
            {
                if (character == '"') { quoted = !quoted; tokenStarted = true; }
                else if (char.IsWhiteSpace(character) && !quoted)
                {
                    if (tokenStarted) { arguments.Add(current.ToString()); current.Length = 0; tokenStarted = false; }
                }
                else { current.Append(character); tokenStarted = true; }
            }
            if (quoted) { throw new FormatException("Unclosed quote in command."); }
            if (tokenStarted) { arguments.Add(current.ToString()); }
            return arguments.ToArray();
        }

        private static int RunConfigCommand(string[] args)
        {
            if ((args.Length == 1) && string.Equals(args[0], "list", StringComparison.OrdinalIgnoreCase))
            {
                PropertyInfo[] properties = typeof(Settings).GetProperties(BindingFlags.Public | BindingFlags.Static)
                    .Where(p => p.CanRead && p.CanWrite && p.Name != "SIDs" && p.Name != "RequireAuthenticationForPrivileges" && p.Name != "AutomaticAddAllowed" && p.Name != "AutomaticAddDenied" && p.Name != "RenewalsAllowed")
                    .OrderBy(p => p.Name, StringComparer.OrdinalIgnoreCase).ToArray();

                foreach (PropertyInfo property in properties)
                {
                    object value = property.GetValue(null, null);
                    string display = FormatSettingValue(value);
                    string source = Settings.GetConfigurationSource(property.Name);
                    Console.WriteLine("{0}={1} [{2}]", property.Name, display, source);
                }
                Console.WriteLine("LocalUserRequestAuthorization=UAC-required [Enforced]");
                Console.WriteLine("UserGrantUacSecurity=" + (Settings.UserGrantUacSecurityRequirementsSatisfied ? "enabled" : "disabled") + " [Windows policy; local UAC grant helpers fail closed when disabled]");
                Console.WriteLine("AutomaticAdd=Disabled [Security invariant; legacy automatic-add rules are ignored]");
                Console.WriteLine("RenewalsAllowed=0 [Enforced; a new grant requires administrator authorization]");
                Console.WriteLine("Policy values are read-only here and take precedence over local values.");
                return 0;
            }

            if ((args.Length == 3) && string.Equals(args[0], "set", StringComparison.OrdinalIgnoreCase))
            {
                string settingName = args[1];
                if (string.Equals(settingName, "RequireAuthenticationForPrivileges", StringComparison.OrdinalIgnoreCase))
                {
                    throw new InvalidOperationException("Every local user request requires UAC authentication; this security invariant cannot be disabled.");
                }
                if (string.Equals(settingName, "AutomaticAddAllowed", StringComparison.OrdinalIgnoreCase) || string.Equals(settingName, "AutomaticAddDenied", StringComparison.OrdinalIgnoreCase))
                {
                    throw new InvalidOperationException("Automatic grants on logon are disabled. Use LocalAllowedEntities and LocalDeniedEntities to define which accounts may submit a UAC-authenticated request.");
                }
                if (string.Equals(settingName, "RenewalsAllowed", StringComparison.OrdinalIgnoreCase))
                {
                    throw new InvalidOperationException("A user-only prompt cannot renew administrator access. The grant expires; a new request must receive administrator authorization.");
                }

                PropertyInfo property = typeof(Settings).GetProperty(settingName, BindingFlags.Public | BindingFlags.Static | BindingFlags.IgnoreCase);
                if ((property == null) || !property.CanWrite || (property.Name == "SIDs")) { throw new ArgumentException("Unknown or read-only setting: " + settingName); }
                string source = Settings.GetConfigurationSource(property.Name);
                if (source == "Policy") { throw new InvalidOperationException(settingName + " is controlled by Windows Policy. Change it at the policy source; the local preference was not changed."); }

                object value = ParseSettingValue(property.PropertyType, args[2]);
                ValidateSetting(property.Name, value);
                property.SetValue(null, value, null);
                ApplicationLog.WriteEvent(string.Format("Administrator {0} changed local Make Me Admin setting {1}.", WindowsIdentity.GetCurrent().Name, property.Name), EventID.DebugMessage, EventLogEntryType.Information);
                Console.WriteLine("Set {0}; source=Local. Restart the Make Me Admin service if the setting affects its network listener.", property.Name);
                return 0;
            }

            Console.Error.WriteLine("Usage: MakeMeAdminService.exe admin config list | config set <name> <value>");
            return 2;
        }

        private static object ParseSettingValue(Type type, string text)
        {
            if (type == typeof(string[]))
            {
                return string.IsNullOrEmpty(text) ? new string[0] : text.Split(new[] { ';' }, StringSplitOptions.RemoveEmptyEntries).Select(s => s.Trim()).ToArray();
            }
            if (type == typeof(Dictionary<string, string>))
            {
                Dictionary<string, string> values = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                if (!string.IsNullOrEmpty(text))
                {
                    foreach (string item in text.Split(new[] { ';' }, StringSplitOptions.RemoveEmptyEntries))
                    {
                        int split = item.IndexOf('=');
                        if (split <= 0) { throw new FormatException("Dictionary values use key=value pairs separated by semicolons."); }
                        values[item.Substring(0, split).Trim()] = item.Substring(split + 1).Trim();
                    }
                }
                return values;
            }
            if (type == typeof(List<SyslogServerInfo>))
            {
                List<SyslogServerInfo> servers = new List<SyslogServerInfo>();
                if (!string.IsNullOrEmpty(text))
                {
                    foreach (string item in text.Split(new[] { ';' }, StringSplitOptions.RemoveEmptyEntries))
                    {
                        string[] parts = item.Split(':');
                        int port;
                        if ((parts.Length != 4) || !int.TryParse(parts[1], NumberStyles.None, CultureInfo.InvariantCulture, out port)) { throw new FormatException("Syslog endpoints use host:port:udp|tcp:3164|5424, separated by semicolons."); }
                        SyslogServerInfo server = new SyslogServerInfo(parts[0], port, parts[2], parts[3]);
                        if (!server.IsValid) { throw new FormatException("Invalid syslog endpoint: " + item); }
                        servers.Add(server);
                    }
                }
                return servers;
            }
            if (type == typeof(bool))
            {
                bool boolValue;
                if (bool.TryParse(text, out boolValue)) { return boolValue; }
                if (text == "1") { return true; }
                if (text == "0") { return false; }
                throw new FormatException("Boolean values must be true/false or 1/0.");
            }
            if (type.IsEnum)
            {
                object enumValue = Enum.Parse(type, text, true);
                if (!Enum.IsDefined(type, enumValue)) { throw new FormatException("The value is not a defined " + type.Name + "."); }
                return enumValue;
            }
            return Convert.ChangeType(text, type, CultureInfo.InvariantCulture);
        }

        private static void ValidateSetting(string name, object value)
        {
            if (!(value is int)) { return; }
            int number = (int)value;
            if ((name == "AdminRightsTimeout") && ((number < 1) || (number > 1440))) { throw new ArgumentOutOfRangeException(name, "Value must be between 1 and 1440."); }
            if ((name == "RenewalsAllowed") && ((number < 0) || (number > 100))) { throw new ArgumentOutOfRangeException(name, "Value must be between 0 and 100."); }
            if ((name == "TCPServicePort") && ((number < 1) || (number > 65535))) { throw new ArgumentOutOfRangeException(name, "Value must be between 1 and 65535."); }
            if ((name == "MaximumReasonLength") && ((number < 5) || (number > 4096))) { throw new ArgumentOutOfRangeException(name, "Value must be between 5 and 4096."); }
            if ((name == "LogOffAfterExpiration") && (number < 0)) { throw new ArgumentOutOfRangeException(name, "Value cannot be negative."); }
        }

        private static string FormatSettingValue(object value)
        {
            if (value == null) { return string.Empty; }
            if (value is string[]) { return string.Join(";", (string[])value); }
            if (value is Dictionary<string, string>)
            {
                return string.Join(";", ((Dictionary<string, string>)value).Select(pair => pair.Key + "=" + pair.Value));
            }
            if (value is IEnumerable<SyslogServerInfo>)
            {
                return string.Join(";", ((IEnumerable<SyslogServerInfo>)value).Select(server => string.Format(CultureInfo.InvariantCulture, "{0}:{1}:{2}:{3}", server.Hostname, server.Port, server.Protocol, server.RFC)));
            }
            return Convert.ToString(value, CultureInfo.InvariantCulture);
        }

        private static int ListGrants()
        {
            EncryptedSettings settings = new EncryptedSettings(EncryptedSettings.SettingsFilePath);
            foreach (User user in settings.AddedUsers)
            {
                Console.WriteLine("{0}\t{1}\t{2}", user.SidString, user.Name, user.ExpirationTime.HasValue ? user.ExpirationTime.Value.ToString("o", CultureInfo.InvariantCulture) : "never");
            }
            return 0;
        }

        private static int ListSessions()
        {
            IAdminGroup channel = CreateLocalChannel();
            try
            {
                foreach (string session in channel.GetLoggedOnSessions()) { Console.WriteLine(session); }
                CloseChannel(channel);
            }
            catch { AbortChannel(channel); throw; }
            return 0;
        }

        private static int ShowAudit(int count)
        {
            EventLog log = new EventLog("Application");
            try
            {
                EventLogEntry[] entries = log.Entries.Cast<EventLogEntry>()
                    .Where(entry => string.Equals(entry.Source, "Make Me Admin", StringComparison.OrdinalIgnoreCase))
                    .Reverse().Take(count).Reverse().ToArray();
                foreach (EventLogEntry entry in entries)
                {
                    Console.WriteLine("{0:o}\t{1}\t{2}", entry.TimeGenerated, entry.EntryType, entry.Message.Replace(Environment.NewLine, " "));
                }
                return 0;
            }
            finally { log.Close(); }
        }

        private static IAdminGroup CreateLocalChannel()
        {
            NetTcpBinding binding = new NetTcpBinding(SecurityMode.Transport)
            {
                PortSharingEnabled = false,
                MaxBufferSize = 1048576,
                MaxReceivedMessageSize = 1048576
            };
            string serviceSpn = "HOST/" + Settings.FullyQualifiedHostName;
            EndpointAddress address = new EndpointAddress(new Uri(Settings.LocalTcpServiceBaseAddress), EndpointIdentity.CreateSpnIdentity(serviceSpn));
            ChannelFactory<IAdminGroup> factory = new ChannelFactory<IAdminGroup>(binding, address);
            return factory.CreateChannel();
        }

        private static void CloseChannel(IAdminGroup channel)
        {
            IClientChannel clientChannel = channel as IClientChannel;
            if (clientChannel != null) { clientChannel.Close(); }
        }

        private static void AbortChannel(IAdminGroup channel)
        {
            IClientChannel clientChannel = channel as IClientChannel;
            if (clientChannel != null) { clientChannel.Abort(); }
        }

        private static bool IsAdministratorToken(WindowsIdentity identity)
        {
            SecurityIdentifier administrators = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
            return (identity != null) && identity.IsAuthenticated && new WindowsPrincipal(identity).IsInRole(administrators);
        }

        private static bool IsAdministratorAccount(WindowsIdentity identity)
        {
            SecurityIdentifier administrators = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
            return (identity != null) && (identity.Groups != null) && identity.Groups.Contains(administrators);
        }

        private static void PrintHelp()
        {
            Console.WriteLine("Make Me Admin administrator CLI");
            Console.WriteLine("  MakeMeAdminService.exe admin gui");
            Console.WriteLine("  MakeMeAdminService.exe admin config list");
            Console.WriteLine("  MakeMeAdminService.exe admin config set <name> <value>");
            Console.WriteLine("    Arrays use semicolons; dictionaries use key=value;key=value.");
            Console.WriteLine("    Syslog endpoints use host:port:udp|tcp:3164|5424;...");
            Console.WriteLine("  MakeMeAdminService.exe admin grants list");
            Console.WriteLine("  MakeMeAdminService.exe admin sessions list");
            Console.WriteLine("  MakeMeAdminService.exe admin grant-session <sessionId> [minutes]");
            Console.WriteLine("  MakeMeAdminService.exe admin revoke <userSid>");
            Console.WriteLine("  MakeMeAdminService.exe admin audit [count]");
            Console.WriteLine("  MakeMeAdminService.exe --grant-session <sessionId>  (UAC helper)");
            Console.WriteLine("  MakeMeAdminService.exe --grant-remote <host>  (UAC helper)");
        }
    }
}
