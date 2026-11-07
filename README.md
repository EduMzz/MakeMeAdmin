# Make Me Admin — protected two-module fork

This fork keeps the upstream GPL-3.0 license and changes the local request flow so a standard user cannot grant themselves administrator membership by calling the service directly.

## Modules

1. **Privileged module:** `MakeMeAdminService.exe`, installed machine-wide by an administrator and run by the Windows Service Control Manager. Its protected install location also contains its administrator GUI and command mode.
2. **Standard-user module:** `MakeMeAdminUI.exe`, which runs without elevation. Local requests and the remote-request window both start the protected service executable with the Windows `runas` verb. Windows presents its UAC credential prompt for every request. A local request is bound to the logged-on user in that session. A remote request resolves that same session identity through the local service, then shows an elevated confirmation naming the destination and user before contacting the remote service.

The UAC helper does not accept a password argument or send a password over IPC. A request without a valid administrator token is rejected by the service, including a direct named-pipe or TCP request. Local allow/deny rules apply to local requests. Remote grants require an administrator token accepted by the destination, and the destination enforces both local and remote allow/deny rules and its configured grant duration. Administrators can grant and revoke temporary access explicitly. Automatic grants on logon are disabled; legacy non-expiring grants are removed during service startup before its IPC endpoints open.

Before a local helper grant or remote-request identity handoff, the service checks the Windows UAC policies `EnableLUA`, `PromptOnSecureDesktop`, and `ConsentPromptBehaviorUser`. If UAC is disabled, secure-desktop prompting is disabled, standard-user elevation is configured to auto-deny, or a policy value is malformed/unreadable, the service denies the request. Missing values use Microsoft's documented Windows defaults. These system policies remain controlled by Windows or central management, not by Make Me Admin.

The Start Menu shortcut **Make Me Admin Remote Request** opens the remote request interface within `MakeMeAdminUI.exe`; it is a second entry point into the standard-user module, not a separately installed executable. The elevated helper displays the target user and computer for administrator confirmation. The destination must have remote requests enabled and configured, and the UAC-authenticated administrator account must also be an administrator on that destination.

## Administrator GUI and SSH command line

The Start Menu shortcut **Make Me Admin Administration** opens the privileged module's management GUI. The GUI and CLI use the same command handlers.

From an already configured, key-authenticated Windows OpenSSH session running with an administrator token:

```powershell
& "$env:ProgramFiles\Make Me Admin\MakeMeAdminService.exe" admin help
& "$env:ProgramFiles\Make Me Admin\MakeMeAdminService.exe" admin config list
& "$env:ProgramFiles\Make Me Admin\MakeMeAdminService.exe" admin config set AdminRightsTimeout 20
& "$env:ProgramFiles\Make Me Admin\MakeMeAdminService.exe" admin sessions list
& "$env:ProgramFiles\Make Me Admin\MakeMeAdminService.exe" admin grants list
& "$env:ProgramFiles\Make Me Admin\MakeMeAdminService.exe" admin grant-session 3 20
& "$env:ProgramFiles\Make Me Admin\MakeMeAdminService.exe" admin revoke S-1-5-21-...
& "$env:ProgramFiles\Make Me Admin\MakeMeAdminService.exe" admin audit 100
```

The session grant command targets the logged-on user in that session. It accepts durations from 1 through 1440 minutes. The revoke command requires a valid SID and never permits targeting the built-in Administrators group SID.

For list-valued settings, use semicolons between values. Timeout overrides use `SID=minutes;SID=minutes`. Syslog endpoints use `host:port:udp|tcp:3164|5424;...`. Quote a value containing spaces in PowerShell.

The CLI shows each setting's source: `Default`, `Local`, or `Policy`. A Policy-sourced value is read-only in this application because Windows Policy has precedence over local preferences and can be reapplied by Windows or central management. The CLI refuses the local write and identifies the setting. Network listener settings may need a service restart after changing.

## Security notes

- Windows UAC authentication is mandatory for grants initiated by a standard user; the legacy `RequireAuthenticationForPrivileges` setting cannot disable it.
- Local UAC grants fail closed unless Windows enables UAC, credential prompting for standard users, and the secure desktop. The administrator can inspect this state with `admin config list`; change a policy-controlled value at its Windows policy source.
- User-only renewal prompts are disabled. Expiration removes the grant, and a new request must receive administrator authorization again.
- The service validates authorization on the privileged side, not in the user interface.
- Service IPC is authenticated with Windows transport security. Privileged operations require a Windows administrator token.
- A standard-user UAC grant is bound to the helper's authenticated session, preventing the requester from selecting another session by changing client arguments.
- The service audit is written to the Windows Application event log. The CLI can display the most recent Make Me Admin events.
- The encrypted grant database is ACL-restricted to LocalSystem and local Administrators. The standard-user client reads grant status through the service.
- The original automatic-add settings remain as legacy registry data but no longer authorize grants. The admin UI/CLI shows that automatic grants are disabled, and attempts to set those legacy options are rejected.
- This protects against bypassing the client while the account remains standard and the administrator credential remains secret. It does not protect against compromise of an administrator credential, a local administrator, or an exploitable Windows/service vulnerability.
- During an approved grant, Windows places the requester in the local Administrators group. That account can then use ordinary Windows administrator capabilities, including changing the service or creating other privileged accounts. Expiration removes the managed membership in normal operation; it is not a containment boundary against a user who is already acting as a local administrator. Use a brokered, task-specific service instead if the requester must never receive general local-administrator powers.

## Build

Build with Visual Studio 2022 MSBuild and restore NuGet dependencies first:

```powershell
dotnet restore Service\Service.csproj -p:RuntimeIdentifier=win-x64
& "$env:ProgramFiles\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\MSBuild.exe" Service\Service.csproj /t:Build /p:Platform=x64 /p:Configuration=Release /p:RuntimeIdentifier=win-x64
& "$env:ProgramFiles\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\MSBuild.exe" UserRequestApp\LocalUI.csproj /t:Build /p:Platform=x64 /p:Configuration=Release /p:RuntimeIdentifier=win-x64
```

The MSI installs the service module and standard-user client. On upgrade, the existing MSI product identity is retained and the version is advanced to 2.5.6. A migration action preserves the original MSI's local preferences while the old product is removed. During uninstall the service tries to revoke its tracked temporary grants. Local preferences, the encrypted grant database (retained if revocation fails), and the Windows Application event log are preserved. The original remote request workflow is integrated into the standard-user executable so the MSI still installs only two executable modules.
