Function Lateral-RDP {

    <#
        .SYNOPSIS
            Enables RDP on target host.

        .DESCRIPTION
            Create a GPO for a target computer which adds a user to the restricted group "Remote Desktop Users", enables the RDP service, and opens the RDP specific ports.
            Required: Rsat.RemoteAccess.Management.Tools, Rsat.GroupPolicy.Management.Tools
            Reference: https://github.com/xbufu/ADLab/blob/main/GPOs/Set-RDP.ps1

        .PARAMETER GPOName
            The name of the new GPO.
    #>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false, HelpMessage="The name of the new GPO.")]
        [String]$GPOName = "Lateral RDP",

        [Parameter(Mandatory=$true, HelpMessage="The user which is granted local rdp access.")]
        [String]$Username,

        [Parameter(Mandatory=$true, HelpMessage="The target computer the GPO is applied to.")]
        [String]$ComputerName,

        [Parameter(Mandatory=$false, HelpMessage="Domain Controller to pull domain information from.")]
        [String]$Server
    )

    # check if username and computername exist
    try {
        $User = Get-ADUser -Identity $Username 
        $SID = $User.SID
    }
    catch [Microsoft.ActiveDirectory.Management.ADIdentityResolutionException] {
        Write-Host "User does not exist." 
        return
    }
    try {
        Get-ADComputer -Identity $ComputerName | Out-Null
    }
    catch [Microsoft.ActiveDirectory.Management.ADIdentityResolutionException] {
        Write-Host "Computer does not exist."
        return
    }

    $Params = @{
    }
    if ($Server) { $Params.Server = $Server }
    $Domain = Get-ADDomain @Params
    $Forest = $Domain.Forest
    $DC = Get-ADDomainController
    $HostName = $DC.HostName
    $DN = $Domain.DistinguishedName

    Write-Verbose "Creating GPO..."
    $GPO = New-GPO -Name $GPOName
    $GUID = $GPO.Id

    Write-Verbose "Configuring RDP service..."
    $Params = @{
        Name = $GPOName;
        Key = 'HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server';
    }
    try {
        Set-GPRegistryValue @Params -ValueName 'fDenyTSConnections' -Value 0 -Type DWord | Out-Null
    } catch { 
        Write-Error "Error while configuring RDP policy!"
        return
    }

    # $Params = @{
    #     Name = $GPOName;
    #     Key = 'HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp';
    # }
    # try { #     Set-GPRegistryValue @Params -ValueName 'UserAuthentication' -Value 1 -Type DWord | Out-Null # } catch { 
    #     Write-Error "Error while configuring NLA policy!"
    # }

    Write-Verbose "Configuring Firewall rules..."
    $TargetOU = $DN
    $PolicyStoreName = "$Forest\$GPOName"

    $GPOSessionName = Open-NetGPO -PolicyStore $PolicyStoreName
    New-NetFirewallRule -DisplayName "Allow RDP" -Profile Any -Direction Inbound -GPOSession $GPOSessionName -PolicyStore $GPOName -Protocol TCP -LocalPort 3389 | Out-Null
    Save-NetGPO -GPOSession $GPOSessionName

    Write-Verbose "Configuring Security Filter..."
    Set-GPPermission -Name $GPOName -TargetName "Authenticated Users" -targettype group -permissionlevel None | Out-Null
    Set-GPPermissions -Name $GPOName -PermissionLevel GpoApply -TargetName $ComputerName -targettype computer | Out-Null

    Write-Verbose "Configuring Restricted Groups..."

    # add gPCMachineExtensionNames Restricted Groups extension
    # Restricted Group Clientside extension: {827D319E-6EAC-11D2-A4EA-00C04F79F83A}
    $PolicyEntry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://CN={$GUID},CN=Policies,CN=System,$DN")
    $PolicyEntry.Properties["gPCMachineExtensionNames"].Value = "[{35378EAC-683F-11D2-A89A-00C04FBBCFA2}{D02B1F72-3407-48AE-BA88-E8213C6761F1}{827D319E-6EAC-11D2-A4EA-00C04F79F83A}]"
    $PolicyEntry.CommitChanges()

    # add GptTmpl.inf file to sysvol share
    New-Item "\\$Hostname\sysvol\$Forest\Policies\{$GUID}\Machine\Microsoft\Windows NT\SecEdit" -ItemType Directory | Out-Null
    '[Unicode]
    Unicode=yes
    [Version]
    signature="$CHICAGO$"
    Revision=1
    [Group Membership]
    *S-1-5-32-555__Memberof =
    *S-1-5-32-555__Members = *{0}' -f $SID | Out-File -Encoding Unicode "\\$Hostname\sysvol\$Forest\Policies\{$GUID}\Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf"

    Write-Verbose "Linking and enabling new GPO..."
    New-GPLink -Name $GPOName -Target $TargetOU -LinkEnabled Yes -Enforced Yes | Out-Null
}
