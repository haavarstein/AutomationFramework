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

Function Get-VIARefTaskSequence
{
    Param(
    $RefTaskSequenceFolder
    )
    $RefTaskSequences = Get-ChildItem $RefTaskSequenceFolder
    Foreach($RefTaskSequence in $RefTaskSequences){
        New-Object PSObject -Property @{ 
        TaskSequenceID = $RefTaskSequence.ID
        Name = $RefTaskSequence.Name
        Comments = $RefTaskSequence.Comments
        Version = $RefTaskSequence.Version
        Enabled = $RefTaskSequence.enable
        LastModified = $RefTaskSequence.LastModifiedTime
        } 
    }
}

function ConvertFrom-MachineCatalog {
    <#
    .SYNOPSIS
    Convert a broker catalog to a hash
    .DESCRIPTION
    Only those fields are extracted from the catalog object that are required for creating the catalog
    .PARAMETER BrokerCatalog
    Collection of broker catalog to convert to a hash
    .PARAMETER ExcludeProvScheme
    Whether to exclude the provisioning scheme
    .PARAMETER ExcludeAcctIdentityPool
    Whether to exclude the account identity pool
    .PARAMETER ExcludeHostingUnit
    Whether to exclude the hosting unit
    .LINK
    ConvertTo-MachineCatalog
    New-MachineCatalog
    Export-MachineCatalog
    .EXAMPLE
    ConvertFrom-MachineCatalog -BrokerCatalog (Get-BrokerCatalog)
    .EXAMPLE
    Get-BrokerCatalog | ConvertFrom-MachineCatalog
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$True,HelpMessage='Collection of broker catalog to convert to a hash',ValueFromPipeline=$True,ValueFromPipelineByPropertyName=$True)]
        [ValidateNotNullOrEmpty()]
        [Citrix.Broker.Admin.SDK.Catalog[]]
        $BrokerCatalog
        ,
        [Parameter(Mandatory=$False,HelpMessage='Whether to exclude the provisioning scheme')]
        [switch]
        $ExcludeProvScheme
        ,
        [Parameter(Mandatory=$False,HelpMessage='Whether to exclude the account identity pool')]
        [switch]
        $ExcludeAcctIdentityPool
        ,
        [Parameter(Mandatory=$False,HelpMessage='Whether to exclude the hosting unit')]
        [switch]
        $ExcludeHostingUnit
    )

    Process {
        Write-Debug ('[{0}] Enumerating members of BrokerCatalog' -f $MyInvocation.MyCommand)

        foreach ($Catalog in $BrokerCatalog) {
            Write-Verbose ('[{0}] [{1}] Processing BrokerCatalog.Name={2}' -f $MyInvocation.MyCommand, $Catalog.UUID, $Catalog.Name)

            $CatalogParams = New-Object psobject -Property @{
                    Name               = $Catalog.Name
                    Description        = $Catalog.Description
                    AllocationType     = $Catalog.AllocationType
                    ProvisioningType   = $Catalog.ProvisioningType
                    PersistUserChanges = $Catalog.PersistUserChanges
                    SessionSupport     = $Catalog.SessionSupport
            }

            if (-Not $Catalog.ProvisioningSchemeId) {
                Write-Verbose ('[{0}] [{1}] No provisioning scheme specified' -f $MyInvocation.MyCommand, $Catalog.UUID)
                $CatalogParams
                continue
            }

            if (-Not $ExcludeProvScheme) {
                Write-Debug ('[{0}] [{1}] Accessing ProvisioningScheme' -f $MyInvocation.MyCommand, $Catalog.UUID)
                $ProvScheme = Get-ProvScheme -ProvisioningSchemeUid $Catalog.ProvisioningSchemeId -Verbose:$False
                Write-Verbose ('[{0}] [{1}] Retrieved ProvisioningScheme.Name={2}' -f $MyInvocation.MyCommand, $Catalog.UUID, $Catalog.Name)

                $CatalogParams | Add-Member -NotePropertyMembers @{
                        MasterImageVM           = $ProvScheme.MasterImageVM
                        CpuCount                = $ProvScheme.CpuCount
                        MemoryMB                = $ProvScheme.MemoryMB
                        CleanOnBoot             = $ProvScheme.CleanOnBoot
                }
            }

            if (-Not $ExcludeAcctIdentityPool) {
                Write-Debug ('[{0}] [{1}] Accessing AcctIdentityPool' -f $MyInvocation.MyCommand, $Catalog.UUID)
                $AcctIdentityPool = Get-AcctIdentityPool -IdentityPoolUid $ProvScheme.IdentityPoolUid -Verbose:$False
                Write-Verbose ('[{0}] [{1}] Retrieved AcctIdentityPool.IdentityPoolName={2}' -f $MyInvocation.MyCommand, $Catalog.UUID, $AcctIdentityPool.IdentityPoolName)

                $CatalogParams | Add-Member -NotePropertyMembers @{
                        NamingScheme       = $AcctIdentityPool.NamingScheme
                        NamingSchemeType   = $AcctIdentityPool.NamingSchemeType
                        OU                 = $AcctIdentityPool.OU
                        Domain             = $AcctIdentityPool.Domain
                }
            }

            if (-Not $ExcludeHostingUnit) {
                Write-Debug ('[{0}] [{1}] Accessing HostingUnit' -f $MyInvocation.MyCommand, $Catalog.UUID)
                $HostingUnit = Get-ChildItem XDHyp:\HostingUnits -Verbose:$False | Where-Object HostingUnitUid -eq $ProvScheme.HostingUnitUid -Verbose:$False
                Write-Verbose ('[{0}] [{1}] Retrieved HostingUnit.HostingUnitName={2}' -f $MyInvocation.MyCommand, $Catalog.UUID, $HostingUnit.HostingUnitName)

                $CatalogParams | Add-Member -NotePropertyMembers @{
                        HostingUnitName    = $HostingUnit.HostingUnitName
                }
            }

            Write-Debug ('[{0}] [{1}] Returning custom object with parameters for BrokerCatalog.Name={2}' -f $MyInvocation.MyCommand, $Catalog.UUID, $Catalog.Name)
            $CatalogParams
            Write-Debug ('[{0}] [{1}] Finished processing BrokerCatalog.Name={2}' -f $MyInvocation.MyCommand, $Catalog.UUID, $Catalog.Name)
        }
    }
}

function Set-Shortcut {
<#
    .SYNOPSIS
    Creates Shortcut Link with Source Link & DestinationPath

    .DESCRIPTION
    This function Creates Shortcut Link with Source Link & DestinationPat. The function has 4 parameters SourceLnk, DestinationPath, WorkingDirectory, IconLocation
    
    .LINK
    Set-Shortcut
    
    .EXAMPLE # 1
    Set-Shortcut -SourceLnk "%windir%\system32\notepad.exe" -DestinationPath "%systemdrive%\Users\%username%\Desktop" -WorkingDirectory "%systemdrive%\Users\%username%\Desktop" -IconLocation "%windir%\system32\notepad.exe,0"
    

    .EXAMPLE # 2
    Set-Shortcut -SourceLnk $SourceLnk -DestinationPath $DestinationPath -WorkingDirectory $WorkingDirectory -IconLocation $IconLocation
    
    #>
    
    [CmdletBinding()]

    param ( 
        [Parameter(Mandatory=$True,HelpMessage='SourceLnk')]
        [ValidateNotNullOrEmpty()]
        [string]$SourceLnk,
        
        [Parameter(Mandatory=$True,HelpMessage='DestinationPath')]
        [ValidateNotNullOrEmpty()] 
        [string]$DestinationPath, 

        [Parameter(Mandatory=$True,HelpMessage='WorkingDirectory')]
        [ValidateNotNullOrEmpty()]
        [string]$WorkingDirectory,
        
        [Parameter(Mandatory=$True,HelpMessage='IconLocation')]
        [ValidateNotNullOrEmpty()] 
        [string]$IconLocation
    )
    
    $WshShell = New-Object -comObject WScript.Shell
    
    $Shortcut = $WshShell.CreateShortcut($SourceLnk)
    
    $Shortcut.TargetPath = $DestinationPath
    
    if ($WorkingDirectory) { 
        $Shortcut.WorkingDirectory = $WorkingDirectory 
        }

    if ($IconLocation) { 
        $Shortcut.IconLocation = $IconLocation 
        }
    
    $Shortcut.Save()
}
