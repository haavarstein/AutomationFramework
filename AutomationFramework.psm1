 function New-VMwareVM {
    <#
    .SYNOPSIS
    Create a new VMware VM
    .DESCRIPTION
    This function creates a VMware VM
    .LINK
    New-VMwareVM
    .EXAMPLE
    New-VMwareVM -VMName $VMName -vCPU $vCPU -MemoryGB $MemoryGB -DiskGB $DiskGB -DiskType $VMDiskType -Network $NetName -vCenter $VCenter -VCUser $VCUser -VCPwd $VCPwd -DataStore $VMDS -GuestId $VMGuestOS
    .EXAMPLE
    New-VMwareVM -VMName $VMName -vCPU $vCPU -MemoryGB $MemoryGB -DiskGB $DiskGB -DiskType $VMDiskType -ISO $ISO -Network $NetName -NetworkType $NICType -vCenter $VCenter -VCUser $VCUser -VCPwd $VCPwd -DataStore $VMDS -GuestId $VMGuestOS
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

    Write-Verbose "Installing VMware PowerCli Module" -Verbose 
    Set-PSRepository -Name "PSGallery" -InstallationPolicy Trusted
    if (!(Test-Path -Path "C:\Program Files\PackageManagement\ProviderAssemblies\nuget")) {Find-PackageProvider -Name 'Nuget' -ForceBootstrap -IncludeDependencies}
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
        {$_ -like 'VMware'} 
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
    $SecureStringPwd = ConvertTo-SecureString $Password -AsPlainText -Force
    $OutputFile = $Output + ".txt"
    $KeyFile = $Output + ".key"
    $Key = New-Object Byte[] 16 
    [Security.Cryptography.RNGCryptoServiceProvider]::Create().GetBytes($Key)
    $Key | out-file $KeyFile
    $Encrypted = ConvertFrom-SecureString -SecureString $SecureStringPwd -Key $Key
    $Encrypted | Set-Content $OutputFile
    Write-Verbose "$Username's Password is Encrypted with AES Security Key in $OutputFile Files" -Verbose
}

Function Set-SecureBoot {
    <#
    .SYNOPSIS Enable/Disable Seure Boot setting for a VM in vSphere 6.5
    .NOTES  Author:  William Lam
    .NOTES  Site:    www.virtuallyghetto.com
    .PARAMETER Vm
      VM to enable/disable Secure Boot
    .EXAMPLE
      Get-VM -Name Windows10 | Set-SecureBoot -Enabled
    .EXAMPLE
      Get-VM -Name Windows10 | Set-SecureBoot -Disabled
    #>
    param(
        [Parameter(
            Mandatory=$true,
            ValueFromPipeline=$true,
            ValueFromPipelineByPropertyName=$true)
        ]
        [VMware.VimAutomation.ViCore.Impl.V1.Inventory.InventoryItemImpl]$Vm,
        [Switch]$Enabled,
        [Switch]$Disabled
     )

    if($Enabled) {
        $secureBootSetting = $true
        $reconfigMessage = "Enabling Secure Boot for $Vm"
    }
    if($Disabled) {
        $secureBootSetting = $false
        $reconfigMessage = "Disabling Secure Boot for $Vm"
    }

    $spec = New-Object VMware.Vim.VirtualMachineConfigSpec
    $bootOptions = New-Object VMware.Vim.VirtualMachineBootOptions
    $bootOptions.EfiSecureBootEnabled = $secureBootSetting
    $spec.BootOptions = $bootOptions
  
    #Write-Host "`n$reconfigMessage ..."
    $task = $vm.ExtensionData.ReconfigVM_Task($spec)
    $task1 = Get-Task -Id ("Task-$($task.value)")
    $task1 | Wait-Task | Out-Null
}

function New-NutanixVM {
    <#
    .DESCRIPTION
    This function creates a VMware VM
    .LINK
    New-NutanixVM
    .EXAMPLE
    New-NutanixVM -VMName $VMName -vCPU $vCPU -MemoryMB $MemoryMB -DiskMB $DiskMB -Container $Container -Network $Network -CVM $CVM -User $User -Pwd $Password -ISO $ISO
    .EXAMPLE
    New-NutanixVM -VMName Test2 -vCPU 2 -MemoryMB 2048 -DiskMB 50000 -Container $Container -Network $Network -CVM $CVM -User $User -Pwd $Password
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
        [Parameter(Mandatory=$True,HelpMessage='Memory (MB)')]
        [ValidateNotNullOrEmpty()]
        [string]
        $MemoryMB
        ,
        [Parameter(Mandatory=$True,HelpMessage='Disk (MB)')]
        [ValidateNotNullOrEmpty()]
        [string]
        $DiskMB
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
        [Parameter(Mandatory=$True,HelpMessage='Nutanix Controller VM')]
        [ValidateNotNullOrEmpty()]
        [string]
        $CVM
        ,
        [Parameter(Mandatory=$True,HelpMessage='Nutanix User')]
        [ValidateNotNullOrEmpty()]
        [string]
        $User
        ,
        [Parameter(Mandatory=$True,HelpMessage='Nutanix Password')]
        [ValidateNotNullOrEmpty()]
        [string]
        $Pwd
        ,
        [Parameter(Mandatory=$True,HelpMessage='Nutanix Container')]
        [ValidateNotNullOrEmpty()]
        [string]
        $Container
        )

    Write-Verbose "Connecting to Nutanix Cluster $CVM" -Verbose
    Connect-NTNXCluster -server $CVM -username $User -password $Password -AcceptInvalidSSLCerts -ForcedConnection | out-null

    New-NTNXVirtualMachine -Name $VMName -NumVcpus $vCPU -MemoryMb $MemoryMB | out-null

    Start-Sleep -s 5

    # Get the VmID of the VM
    $vminfo = Get-NTNXVM | where {$_.vmName -eq $VMName}
    $vmId = ($vminfo.vmid.split(":"))[2]

    Start-Sleep -s 5

    # Disk Creation
    $diskCreateSpec = New-NTNXObject -Name VmDiskSpecCreateDTO
    $diskcreatespec.containerName = "$Container"
    $diskcreatespec.sizeMb = $DiskMB

    # Creating the Disk
    $vmDisk =  New-NTNXObject -Name VMDiskDTO
    $vmDisk.vmDiskCreate = $diskCreateSpec

    # Adding the Disk to the VM
    Add-NTNXVMDisk -Vmid $vmId -Disks $vmDisk | Out-Null

    # Set NIC for VM on default vlan (Get-NTNXNetwork -> NetworkUuid)
    $VMMAC = Get-RandomMAC -MachineType Nutanix   
    $nic = New-NTNXObject -Name VMNicSpecDTO
    $nic.networkUuid = $Network
    $nic.macAddress = $VMMAC
    Add-NTNXVMNic -Vmid $vmId -SpecList $nic | Out-Null
     
    # Mount ISO Image
    $diskCloneSpec = New-NTNXObject -Name VMDiskSpecCloneDTO
    $ISOImage = (Get-NTNXImage | ?{$_.name -eq $ISO})
    $diskCloneSpec.vmDiskUuid = $ISOImage.vmDiskId
    
    # Setup the new ISO disk from the Cloned Image
    $vmISODisk = New-NTNXObject -Name VMDiskDTO
    
    # Specify that this is a CDrom
    $vmISODisk.isCdrom = $true
    $vmISODisk.vmDiskClone = $diskCloneSpec
    $vmDisk = @($vmDisk)
    $vmDisk += $vmISODisk

    # Get the VmID of the VM
    $vminfo = Get-NTNXVM | where {$_.vmName -eq $VMName}
    $vmId = ($vminfo.vmid.split(":"))[2]

    # Adding the Disk ^ ISO to the VM
    Add-NTNXVMDisk -Vmid $vmId -Disks $vmDisk | Out-Null
}





function Remove-MachineCatalog {
    <#
    .SYNOPSIS
    Removes a machine catalog with all associated objects
    .DESCRIPTION
    The following objects will be removed: virtual machines, computer accounts, broker catalog, account identity pool, provisioning scheme
    .PARAMETER Name
    Name of the objects to remove
    .LINK
    New-MachineCatalog
    Rename-MachineCatalog
    .EXAMPLE
    Remove-BrokerCatalog -Name 'test'
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$True,HelpMessage='Name of the objects to remove')]
        [ValidateNotNullOrEmpty()]
        [string]
        $Name
    )

    Get-BrokerMachine | Where-Object CatalogName -eq $Name | Remove-BrokerMachine
    Get-ProvVM -ProvisioningSchemeName $Name | foreach {
        Unlock-ProvVM -ProvisioningSchemeName $Name -VMID $_.VMId
        Remove-ProvVM -ProvisioningSchemeName $Name -VMName $_.VMName
    }
    Get-AcctADAccount    -IdentityPoolName $Name       -ErrorAction SilentlyContinue | Remove-AcctADAccount -IdentityPoolName $Name
    Get-BrokerCatalog    -Name $Name                   -ErrorAction SilentlyContinue | Remove-BrokerCatalog
    Get-AcctIdentityPool -IdentityPoolName $Name       -ErrorAction SilentlyContinue | Remove-AcctIdentityPool
    Get-ProvScheme       -ProvisioningSchemeName $Name -ErrorAction SilentlyContinue | Remove-ProvScheme
}

function Rename-MachineCatalog {
    <#
    .SYNOPSIS
    Renames a machine catalog
    .DESCRIPTION
    The following objects are renamed: BrokerCatalog, ProvScheme, AcctIdentityPool
    .PARAMETER Name
    Name of the existing catalog
    .PARAMETER NewName
    New name for the catalog
    .LINK
    Remove-MachineCatalog
    New-MachineCatalog
    .EXAMPLE
    Rename-MachineCatalog -Name 'OldName' -NewName 'NewName'
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$True,HelpMessage='Name of the existing catalog')]
        [ValidateNotNullOrEmpty()]
        [string]
        $Name
        ,
        [Parameter(Mandatory=$True,HelpMessage='New name for the catalog')]
        [ValidateNotNullOrEmpty()]
        [string]
        $NewName
    )

    Rename-BrokerCatalog    -Name                   $Name -NewName                   $NewName
    Rename-ProvScheme       -ProvisioningSchemeName $Name -NewProvisioningSchemeName $NewName
    Rename-AcctIdentityPool -IdentityPoolName       $Name -NewIdentityPoolName       $NewName
}

function Update-DeliveryGroup {
    <#
    .SYNOPSIS
    Substitutes machines in a desktop group
    .DESCRIPTION
    The machines contained in the desktop group are removed and new machines are added from the specified catalog
    .PARAMETER Name
    Name of an existing desktop group
    .PARAMETER CatalogName
    Name of the catalog containing new machines
    .PARAMETER Count
    Number of machines to add
    .LINK
    New-MachineCatalog
    Sync-MachineCatalog
    .EXAMPLE
    The following command adds all machines from the given catalog to the specified desktop group
    Update-DeliveryGroup -Name 'DG-SessionHost' -CatalogName 'MCS-SessionHost'
    .EXAMPLE
    The following command adds two machines from the given catalog to the specified desktop group
    Update-DeliveryGroup -Name 'DG-SessionHost' -CatalogName 'MCS-SessionHost' -Count 2
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$True,HelpMessage='Name of an existing desktop group')]
        [ValidateNotNullOrEmpty()]
        [string]
        $Name
        ,
        [Parameter(Mandatory=$True,HelpMessage='Name of the catalog containing new machines')]
        [ValidateNotNullOrEmpty()]
        [string]
        $CatalogName
        ,
        [Parameter(Mandatory=$False,HelpMessage='Number of machines to add')]
        [ValidateNotNullOrEmpty()]
        [int]
        $Count
    )

    Write-Verbose ('[{0}] Retrieving machines in desktop group named {1}' -f $MyInvocation.MyCommand, $Name)
    $ExistingMachines = Get-BrokerMachine | Where-Object DesktopGroupName -eq $Name
    $ExistingMachines | foreach { Write-Debug ('[{0}]   {1}' -f $MyInvocation.MyCommand, $_.MachineName) }
    
    $Catalog = Get-BrokerCatalog -Name $CatalogName
    if (-Not $Count) {
        $Count = $Catalog.UnassignedCount
    }
    Write-Verbose ('[{0}] Adding {2} machines from catalog {1} to desktop group <{3}>' -f $MyInvocation.MyCommand, $CatalogName, $Count, $Name)
    $AddedCount = Add-BrokerMachinesToDesktopGroup -DesktopGroup $Name -Catalog $Catalog -Count $Count

    Write-Verbose ('[{0}] Removing old machines from desktop group named {1}' -f $MyInvocation.MyCommand, $Name)
    $ExistingMachines | Set-BrokerMachine -InMaintenanceMode $True | Out-Null
    $ExistingMachines | Remove-BrokerMachine -DesktopGroup $Name | Out-Null

    Write-Verbose ('[{0}] Starting new machines in delivery group named {1}' -f $MyInvocation.MyCommand, $Name)
    Get-BrokerMachine -DesktopGroupName $Name | Where-Object { $_.SupportedPowerActions -icontains 'TurnOn' } | foreach {
        New-BrokerHostingPowerAction -Action 'TurnOn' -MachineName $_.MachineName
    }
}

function New-HostingConnection {
    <#
    .SYNOPSIS
    Create a new hosting connection
    .DESCRIPTION
    This function only creates a connection to a hosting environment without choosing any resources (see New-HostingResource)
    .PARAMETER Name
    Name of the hosting connection
    .PARAMETER ConnectionType
    Connection type can be VCenter, XenServer and SCVMM among several others
    .PARAMETER HypervisorAddress
    This contains the URL to the vCenter web API
    .PARAMETER HypervisorCredential
    A credentials object for authentication against the hypervisor
    .LINK
    New-HostingResource
    .EXAMPLE
    New-HostingConnection -Name vcenter-01 -ConnectionType VCenter -HypervisorAddress https://vcenter-01.example.com/sdk -HypervisorCredential (Get-Credential)
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$True,HelpMessage='Name of the hosting connection')]
        [ValidateNotNullOrEmpty()]
        [string]
        $Name
        ,
        [Parameter(Mandatory=$True,HelpMessage='Connection type can be VCenter, XenServer and SCVMM among several others')]
        [ValidateSet('VCenter','XenServer','SCVMM')]
        [string]
        $ConnectionType
        ,
        [Parameter(Mandatory=$True,HelpMessage='This contains the URL to the vCenter web API')]
        [ValidateNotNullOrEmpty()]
        [string]
        $HypervisorAddress
        ,
        [Parameter(Mandatory=$True,HelpMessage='A credentials object for authentication against the hypervisor')]
        [ValidateNotNullOrEmpty()]
        [pscredential]
        $HypervisorCredential
    )

    if (-Not (Test-Path -Path XDHyp:\Connections\$Name)) {
        $HostingConnection = New-Item -Path XDHyp:\Connections\$Name -ConnectionType $ConnectionType -HypervisorAddress $HypervisorAddress -HypervisorCredential $HypervisorCredential -Persist
    } else {
        $HostingConnection = Get-Item XDHyp:\Connections\$Name
    }
    $HypervisorConnectionUid = $HostingConnection.HypervisorConnectionUid | Select-Object -ExpandProperty Guid
    New-BrokerHypervisorConnection -HypHypervisorConnectionUid $HypervisorConnectionUid | Out-Null
}

function New-HostingResource {
    <#
    .SYNOPSIS
    Create a new hosting resource
    .DESCRIPTION
    This function creates a resource (network and storage) based on a hosting connection (see New-HostingConnection)
    .PARAMETER Name
    Name of the hosting resource
    .PARAMETER HypervisorConnectionName
    Name of the hosting connection
    .PARAMETER ClusterName
    Name of the host cluster in vCenter
    .PARAMETER NetworkName
    Array of names of networks in vCenter
    .PARAMETER StorageName
    Array of names of datastores in vCenter
    .LINK
    New-HostingConnection
    .EXAMPLE
    New-HostingResource -Name cluster-01 -HypervisorConnectionName vcenter-01 -ClusterName cluster-01 -NetworkName (vlan_100,vlan_101) -StorageName (datastore1,datastore2)
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$True,HelpMessage='Name of the hosting resource')]
        [ValidateNotNullOrEmpty()]
        [string]
        $Name
        ,
        [Parameter(Mandatory=$True,HelpMessage='Name of the hosting connection')]
        [ValidateNotNullOrEmpty()]
        [string]
        $HypervisorConnectionName
        ,
        [Parameter(Mandatory=$True,HelpMessage='Name of the host cluster in vCenter')]
        [ValidateNotNullOrEmpty()]
        [string]
        $ClusterName
        ,
        [Parameter(Mandatory=$True,HelpMessage='Array of names of networks in vCenter')]
        [ValidateNotNullOrEmpty()]
        [string[]]
        $NetworkName
        ,
        [Parameter(Mandatory=$True,HelpMessage='Array of names of datastores in vCenter')]
        [ValidateNotNullOrEmpty()]
        [string[]]
        $StorageName
    )

    $HypervisorConnectionPath = Join-Path -Path XDHyp:\Connections -ChildPath $HypervisorConnectionName
    $BasePath = Join-Path -Path XDHyp:\HostingUnits -ChildPath $ClusterName

    Write-Verbose ('[{0}] Caching objects for lookups under {1}' -f $MyInvocation.MyCommand, $HypervisorConnectionPath)
    $CachedObjects = Get-ChildItem -Recurse $HypervisorConnectionPath -Verbose:$False

    $ClusterPath = $CachedObjects | Where-Object { $_.Name -like $ClusterName } | Select-Object FullPath
    Write-Verbose ('[{0}] Using cluster named {1} via path <{2}>' -f $MyInvocation.MyCommand, $ClusterName,$ClusterPath.FullPath)

    $NetworkPath = $CachedObjects | Where-Object { $NetworkName -icontains $_.Name } | Select-Object FullPath
    Write-Verbose ('[{0}] Using network named {1} via path <{2}>' -f $MyInvocation.MyCommand, [string]::Join(',', $NetworkName), [string]::Join(',', $NetworkPath.FullPath))

    $StoragePath = $CachedObjects | Where-Object { $StorageName -icontains $_.Name } | Select-Object FullPath
    Write-Verbose ('[{0}] Using storage named {1} via path <{2}>' -f $MyInvocation.MyCommand, [string]::Join(',', $StorageName), [string]::Join(',', $StoragePath.FullPath))

    New-Item -Verbose:$False -Path $BasePath -RootPath $ClusterPath.FullPath `
        -HypervisorConnectionName $HypervisorConnectionName `
        -NetworkPath $NetworkPath.FullPath `
        -PersonalvDiskStoragePath $StoragePath.FullPath `
        -StoragePath $StoragePath.FullPath | Out-Null
}
