ShareScope 1.0.0
Read-only SMB share and permission auditor

ShareScope lists SMB shares on Windows servers, reads share and NTFS permissions, and flags access that is broader than it should be. It is a single executable for 64-bit Windows 10 and Windows 11. No installer and no separate .NET runtime are required.

Read-only
ShareScope never changes share permissions, NTFS permissions, ownership, or files. It only reads them. Opening a share starts Explorer. Export writes a file you choose.

Start the desktop app
Double-click ShareScope.exe.

The local computer is in the target list. Add other server names or IP addresses, paste a list, or import a CSV or text file. If this PC is joined to a domain, "From Active Directory" can add the Servers OU or every Windows Server computer. If it is not domain-joined, that step is skipped and you add names yourself.

Scan shares. Hide administrative and hidden ($) shares when you only want the shares people use. Turn on "Scan subfolders" and set a depth (default 2, maximum 10) to look for broken inheritance and broad write access under each share. Cancel stops the walk. Servers are scanned a few at a time so one audit does not open every machine at once.

Select a share to see the share ACL, the NTFS ACL, the owner, and the risk notes. Use Open in Explorer, Copy UNC path, or Copy details. "Who has access" asks which user or group can reach the shares in the current results. On a domain it expands group membership. Otherwise it matches direct entries only and says so.

Export CSV or a self-contained HTML report. Save and load the target list as a text file.

Risk levels
OK      No flags.
Review  Worth a look: broad read, broken inheritance, an orphaned SID, a Deny entry, or a share aimed at a system folder.
High    Everyone, Authenticated Users, Domain Users, or Users can change data; Everyone can reach a sensitive-looking share; or Guest or anonymous access is allowed.

Command line
ShareScope.exe --scan servers.txt --csv out.csv --html out.html

  --scan <file>     Text or CSV list of servers
  --csv <file>      Write CSV results
  --html <file>     Write an HTML report
  --hide-admin      Skip administrative and hidden $ shares
  --depth <0-10>    Subfolder levels to walk (default 0)
  --help            Show help

Exit codes
  0   Finished, and no High-risk share was found
  1   Finished, and at least one High-risk share was found
  2   The arguments or the server list could not be used, or the scan read no shares

A High result is a nonzero exit code so a scheduled task can alert.
