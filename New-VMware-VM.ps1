 function New-VMware-VM {
    <#
    .SYNOPSIS
    Create a new VMware VM
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
