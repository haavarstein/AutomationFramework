 function New-VMwareVM {
    <#
    .SYNOPSIS
    Create a new VMware VM
    .DESCRIPTION
    This function creates a VMware VM
    .LINK
    New-VMware-VM
    .EXAMPLE
    New-VMware-VM -VMName $VMName -vCPU $vCPU -MemoryGB $MemoryGB -DiskGB $DiskGB -DiskType $VMDiskType -Network $NetName -vCenter $VCenter -VCUser $VCUser -VCPwd $VCPwd -DataStore $VMDS -GuestId $VMGuestOS
    .EXAMPLE
    New-VMware-VM -VMName $VMName -vCPU $vCPU -MemoryGB 4 -DiskGB 50 -DiskType $VMDiskType -ISO $ISO -Network $NetName -NetworkType $NICType -vCenter $VCenter -VCUser $VCUser -VCPwd $VCPwd -DataStore $VMDS -GuestId $VMGuestOS
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$True,HelpMessage='Name')]
        [ValidateNotNullOrEmpty()]
        [string]
        $VMName
        ,
        [Parameter(Mandatory=$True,HelpMessage='vCPU')]
        [ValidateNotNullOrEmpty()]
        [string]
        $vCPU
        ,
        [Parameter(Mandatory=$True,HelpMessage='Memory (GB)')]
        [ValidateNotNullOrEmpty()]
        [string]
        $MemoryGB
        ,
        [Parameter(Mandatory=$True,HelpMessage='Disk (GB)')]
        [ValidateNotNullOrEmpty()]
        [string]
        $DiskGB
        ,
        [Parameter(Mandatory=$True,HelpMessage='Disk Type (Thin/Thick)')]
        [ValidateNotNullOrEmpty()]
        [string]
        $DiskType
        ,
        [Parameter(Mandatory=$False,HelpMessage='ISO Image')]
        [ValidateNotNullOrEmpty()]
        [string]
        $ISO
        ,
        [Parameter(Mandatory=$True,HelpMessage='Network')]
        [ValidateNotNullOrEmpty()]
        [string]
        $Network
        ,
        [Parameter(Mandatory=$False,HelpMessage='Network Type')]
        [ValidateNotNullOrEmpty()]
        [string]
        $NetworkType
        ,
        [Parameter(Mandatory=$True,HelpMessage='vCenter')]
        [ValidateNotNullOrEmpty()]
        [string]
        $vCenter
        ,
        [Parameter(Mandatory=$True,HelpMessage='vCenter User')]
        [ValidateNotNullOrEmpty()]
        [string]
        $VCUser
        ,
        [Parameter(Mandatory=$True,HelpMessage='vCenter Password')]
        [ValidateNotNullOrEmpty()]
        [string]
        $VCPwd
                ,
        [Parameter(Mandatory=$True,HelpMessage='vCenter Datastore')]
        [ValidateNotNullOrEmpty()]
        [string]
        $DataStore
        ,
        [Parameter(Mandatory=$True,HelpMessage='vCenter GuestOS')]
        [ValidateNotNullOrEmpty()]
        [string]
        $GuestId
    )

    Write-Verbose "Installing Modules" -Verbose 
    if (!(Test-Path -Path "C:\Program Files\PackageManagement\ProviderAssemblies\nuget")) {Find-PackageProvider -Name 'Nuget' -ForceBootstrap -IncludeDependencies}
    Set-PSRepository -Name "PSGallery" -InstallationPolicy Trusted
    if (!(Get-Module -ListAvailable -Name VMware.PowerCLI)) {Install-Module -Name VMware.PowerCLI -AllowClobber}

    Write-Verbose "Importing VMware PowerCli Module" -Verbose
    Set-PowerCLIConfiguration -DisplayDeprecationWarnings 0 -Confirm:$false | out-null
    Set-PowerCLIConfiguration -InvalidCertificateAction Ignore -Confirm:$false | out-null    
    Import-Module VMware.DeployAutomation

    Write-Verbose "Connecting to vCenter $vCenter" -Verbose
    Connect-VIServer $vCenter -User $VCUser -Password $VCPwd | Out-Null
    $Resource = Get-ResourcePool
    $ResourceName = $Resource.Name
    New-VM -Name $VMName -numcpu $vCPU -MemoryGB $MemoryGB -DiskGB $DiskGB -DiskStorageFormat $DiskType -Network $Network -DataStore $DataStore -GuestId $GuestId -ResourcePool $ResourceName -CD | Out-Null
    Get-VM $VMName | Get-CDDrive | Set-CDDrive -ISOPath $ISO -StartConnected:$true -Confirm:$false | out-null
}

Function Get-RandomMAC {
    <#
    .SYNOPSIS
    Get a Random MAC Address based on the Machine Type Ex.VMware, Citrix, Nutanix, Microsoft
    .DESCRIPTION
    This function generates and retuns Random MAC Address based on the Machine Type. MachineType Parameter is Mandatory.
    .LINK
    Get-RandomMAC
    .EXAMPLE
    Get-RandomMAC -MachineType VMware
    .EXAMPLE
    Get-RandomMAC -MachineType Citrix
     .EXAMPLE
    Get-RandomMAC -MachineType Nutanix
     .EXAMPLE
    Get-RandomMAC -MachineType Microsoft
    #>
	[CmdletBinding()]
	Param(
        [Parameter(Mandatory=$True,HelpMessage='Machine Type Ex.VMware, Citrix, Nutanix, Microsoft')]
        [ValidateNotNullOrEmpty()]
        [string]
        $MachineType
        ,
		[Parameter()]
		[string] $Separator = ":"
	)

    Switch ($MachineType)
    {
        {$_ -like 'Vmware'} 
            {
                $Prefix = [string]::join($Separator, @("00","50","56","00"))
            }
        {$_ -like 'Citrix'} 
            {
                $Prefix = [string]::join($Separator, @("06","91","C9","00"))
            }
        {$_ -like 'Nutanix'} 
            {
            $Prefix = [string]::join($Separator, @("50","6B","8D","00"))
            }
        {$_ -like 'Microsoft'} 
            {
            $Prefix = [string]::join($Separator, @("00","15","5D","00"))
        }
        default 
            {
            Write-Verbose "MachineType is not valid. Please use any value ex. VMware, Citrix, Nutanix, Microsoft " -Verbose
            break
        }
    }

	[string]::join($Separator, @(
		# "Locally administered address"
		# any of x2, x6, xa, xe
		$Prefix
		("{0:X2}" -f (Get-Random -Minimum 0 -Maximum 255)),
		("{0:X2}" -f (Get-Random -Minimum 0 -Maximum 255))
	))
}

Function Protect-Password{
    <#
    .SYNOPSIS
    Encrpts the User's Password with AES Encrption Method
    .DESCRIPTION
    This function generates and retuns AES Encrpted Secure Password File & Secure Key File.Username, Password, Output Parameters are Mandatory.
    .LINK
    Protect-Password
    .EXAMPLE
    Protect-Password -Username "TestUser" -Password "TestPassword" -Output "TestFiles"
    #>
	[CmdletBinding()]
	Param(
        [Parameter(Mandatory=$True,HelpMessage='Username')]
        [ValidateNotNullOrEmpty()]
        [string]
        $UserName
        ,
        [Parameter(Mandatory=$True,HelpMessage='Password')]
        [ValidateNotNullOrEmpty()]
        [string]
        $Password
        ,
		[Parameter(Mandatory=$True,HelpMessage='Output')]
        [ValidateNotNullOrEmpty()]
        [string]
        $Output
	)
    Write-Verbose "Encrypting $Username's Password with AES Security Key" -Verbose
    $SecureStringPwd = ConvertTo-SecureString $Password –asplaintext –force
    $OutputFile = $Output + ".txt"
    $KeyFile = $Output + ".key"
    $Key = New-Object Byte[] 16 
    [Security.Cryptography.RNGCryptoServiceProvider]::Create().GetBytes($Key)
    $Key | out-file $KeyFile
    $Encrypted = ConvertFrom-SecureString -SecureString $SecureStringPwd -Key $Key
    $Encrypted | Set-Content $OutputFile
    Write-Verbose "$Username's Password is Encrypted with AES Security Key in $OutputFile Files" -Verbose
}

