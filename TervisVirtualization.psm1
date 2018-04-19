#Requires -Modules TervisEnvironment, TervisDHCP, TervisCluster, @{ModuleName="hyper-V";ModuleVersion=1.1}, StringPowerShell, TervisNetTCPIP, Get-SPN
#Requires -Version 5

function New-TervisVM {
    param(
        [Parameter(Mandatory, ParameterSetName = "ClusteredTemplatedVHD")]
        [Parameter(Mandatory, ParameterSetName = "NonClusteredTemplatedVHD")]
        [Parameter(Mandatory, ParameterSetName = "ClusteredNoVHD")]
        [Parameter(Mandatory, ParameterSetName = "NonClusteredNoVHD")]
        [Parameter(Mandatory, ParameterSetName = "ClusteredEmptyVHD")]
        [Parameter(Mandatory, ParameterSetName = "NonClusteredEmptyVHD")]
        [ValidateLength(1,11)]
        [ValidateScript({ Test-ShouldBeAlphaNumeric -Name VMNameWithoutEnvironmentPrefix -String $_ })]
        [String]$VMNameWithoutEnvironmentPrefix,
        
        [Parameter(Mandatory, ParameterSetName = "ClusteredTemplatedVHD")]
        [Parameter(Mandatory, ParameterSetName = "NonClusteredTemplatedVHD")]
        [Parameter(Mandatory, ParameterSetName = "ClusteredNoVHD")]
        [Parameter(Mandatory, ParameterSetName = "NonClusteredNoVHD")]
        [Parameter(Mandatory, ParameterSetName = "ClusteredEmptyVHD")]
        [Parameter(Mandatory, ParameterSetName = "NonClusteredEmptyVHD")]
        [ValidateSet(“Small”,”Medium”,"Large")]
        [String]$VMSizeName,

        [Parameter(Mandatory, ParameterSetName = "ClusteredTemplatedVHD")]
        [Parameter(Mandatory, ParameterSetName = "NonClusteredTemplatedVHD")]
        [Parameter(Mandatory, ParameterSetName = "ClusteredNoVHD")]
        [Parameter(Mandatory, ParameterSetName = "NonClusteredNoVHD")]
        [Parameter(Mandatory, ParameterSetName = "ClusteredEmptyVHD")]
        [Parameter(Mandatory, ParameterSetName = "NonClusteredEmptyVHD")]
        [ValidateSet(“Windows Server 2012 R2”,"Windows Server 2012","Windows Server 2008 R2", "PerfSonar", "CentOS 7","Windows 10","Windows Server 2016","VyOS","Arch Linux")]
        [String]$VMOperatingSystemTemplateName,

        [Parameter(Mandatory, ParameterSetName = "ClusteredTemplatedVHD")]
        [Parameter(Mandatory, ParameterSetName = "NonClusteredTemplatedVHD")]
        [Parameter(Mandatory, ParameterSetName = "ClusteredNoVHD")]
        [Parameter(Mandatory, ParameterSetName = "NonClusteredNoVHD")]
        [Parameter(Mandatory, ParameterSetName = "ClusteredEmptyVHD")]
        [Parameter(Mandatory, ParameterSetName = "NonClusteredEmptyVHD")]
        [ValidateSet(”Delta”,“Epsilon”,"Production","Infrastructure")]
        [ValidateScript({$_ -in $(Get-TervisEnvironmentName) })]
        [String]$EnvironmentName,

        [Parameter(Mandatory, ParameterSetName = "ClusteredTemplatedVHD")]
        [Parameter(Mandatory, ParameterSetName = "ClusteredNoVHD")]
        [Parameter(Mandatory, ParameterSetName = "ClusteredEmptyVHD")]
        [ValidateScript({ get-cluster -name $_ })]
        [String]$Cluster,

        [Parameter(Mandatory, ParameterSetName = "NonClusteredTemplatedVHD")]
        [Parameter(Mandatory, ParameterSetName = "NonClusteredNoVHD")]
        [Parameter(Mandatory, ParameterSetName = "NonClusteredEmptyVHD")]
        [String]$ComputerName,

        [Parameter(ParameterSetName = "ClusteredTemplatedVHD")]
        [Parameter(ParameterSetName = "NonClusteredTemplatedVHD")]
        [Parameter(ParameterSetName = "ClusteredNoVHD")]
        [Parameter(ParameterSetName = "NonClusteredNoVHD")]
        [Parameter(ParameterSetName = "ClusteredEmptyVHD")]
        [Parameter(ParameterSetName = "NonClusteredEmptyVHD")]
        [ValidateScript({ Get-DhcpServerv4Scope -ScopeId $_ -ComputerName $(Get-DhcpServerInDC | select -First 1 -ExpandProperty DNSName) })]
        [String]$DHCPScopeID,
        
        [Parameter(ParameterSetName = "ClusteredTemplatedVHD")]
        [Parameter(ParameterSetName = "NonClusteredTemplatedVHD")]
        [Parameter(ParameterSetName = "ClusteredNoVHD")]
        [Parameter(ParameterSetName = "NonClusteredNoVHD")]
        [Parameter(ParameterSetName = "ClusteredEmptyVHD")]
        [Parameter(ParameterSetName = "NonClusteredEmptyVHD")]
        [switch]$NeedsAccessToSAN,

        [Parameter(Mandatory, ParameterSetName = "ClusteredNoVHD")]
        [Parameter(Mandatory, ParameterSetName = "NonClusteredNoVHD")]
        [switch]$NoVHD,

        [Parameter(Mandatory, ParameterSetName = "ClusteredEmptyVHD")]
        [Parameter(Mandatory, ParameterSetName = "NonClusteredEmptyVHD")]
        [switch]$EmptyVHD
    )

    if ($ComputerName) {
        New-TervisNonClusterVM @PSBoundParameters
    } else {
        New-TervisClusterVM @PSBoundParameters
    }

}

function New-TervisClusterVM {
    param(
        [Parameter(Mandatory, ParameterSetName = "TemplatedVHD")]
        [Parameter(Mandatory, ParameterSetName = "NoVHD")]
        [Parameter(Mandatory, ParameterSetName = "EmptyVHD")]
        [ValidateLength(1,11)]
        [ValidateScript({ Test-ShouldBeAlphaNumeric -Name VMNameWithoutEnvironmentPrefix -String $_ })]
        [String]$VMNameWithoutEnvironmentPrefix,

        [Parameter(Mandatory, ParameterSetName = "TemplatedVHD")]
        [Parameter(Mandatory, ParameterSetName = "NoVHD")]
        [Parameter(Mandatory, ParameterSetName = "EmptyVHD")]
        [ValidateSet(“Small”,”Medium”,"Large")]
        [String]$VMSizeName,

        [Parameter(Mandatory, ParameterSetName = "TemplatedVHD")]
        [Parameter(Mandatory, ParameterSetName = "NoVHD")]
        [Parameter(Mandatory, ParameterSetName = "EmptyVHD")]
        [ValidateSet(“Windows Server 2012 R2”,"Windows Server 2012","Windows Server 2008 R2", "PerfSonar", "CentOS 7","Windows Server 2016","VyOS","Arch Linux")]
        [String]$VMOperatingSystemTemplateName,

        [Parameter(Mandatory, ParameterSetName = "TemplatedVHD")]
        [Parameter(Mandatory, ParameterSetName = "NoVHD")]
        [Parameter(Mandatory, ParameterSetName = "EmptyVHD")]
        [ValidateSet(”Delta”,“Epsilon”,"Production","Infrastructure")]
        [ValidateScript({$_ -in $(Get-TervisEnvironmentName) })]
        [String]$EnvironmentName,

        [Parameter(Mandatory, ParameterSetName = "TemplatedVHD")]
        [Parameter(Mandatory, ParameterSetName = "NoVHD")]
        [Parameter(Mandatory, ParameterSetName = "EmptyVHD")]
        [ValidateScript({ get-cluster -name $_ })]
        [String]$Cluster,

        [Parameter(ParameterSetName = "TemplatedVHD")]
        [Parameter(ParameterSetName = "NoVHD")]
        [Parameter(ParameterSetName = "EmptyVHD")]
        [ValidateScript({ Get-DhcpServerv4Scope -ScopeId $_ -ComputerName $(Get-DhcpServerInDC | select -First 1 -ExpandProperty DNSName) })]
        [String]$DHCPScopeID,
        
        [Parameter(ParameterSetName = "TemplatedVHD")]
        [Parameter(ParameterSetName = "NoVHD")]
        [Parameter(ParameterSetName = "EmptyVHD")]
        [switch]$NeedsAccessToSAN,

        [Parameter(Mandatory, ParameterSetName = "NoVHD")]
        [switch]$NoVHD,

        [Parameter(Mandatory, ParameterSetName = "EmptyVHD")]
        [switch]$EmptyVHD
    )
    $VMSize = Get-TervisVMSize -VMSizeName $VMSizeName
    $VMOperatingSystemTemplate = Get-VMOperatingSystemTemplate -VMOperatingSystemTemplateName $VMOperatingSystemTemplateName
    $VMName = Get-TervisVMName -VMNameWithoutEnvironmentPrefix $VMNameWithoutEnvironmentPrefix -EnvironmentName $EnvironmentName
    $CSVToStoreVMOS = Get-TervisClusterSharedVolumeToStoreVMOSOn -Cluster $Cluster
    $ClusterNodeToHostVM = Get-TervisClusterNodeToHostVM -VMSize $VMSize -Cluster $Cluster
    $VMSwitch = Get-TervisVMSwitch -ComputerName $ClusterNodeToHostVM.Name
    $DHCPScope = if ($DHCPScopeID) { 
        Get-TervisDhcpServerv4Scope -ScopeID $DHCPScopeID
    } else {
        Get-TervisDhcpServerv4Scope -Environment $EnvironmentName
    }

    Write-Verbose "$($VMSize.Name) $($VMOperatingSystemTemplate.Name) $VMName $($CSVToStoreVMOS.Name) $($ClusterNodeToHostVM.Name) $($VMSwitch.Name) $($DHCPScope.Name)"
    $ComputerName = $ClusterNodeToHostVM.Name

    $VM = New-VM -Name $VMName -MemoryStartupBytes $VMSize.MemoryBytes -NoVHD -Generation $VMOperatingSystemTemplate.Generation `
        -ComputerName $ClusterNodeToHostVM.Name -Path $CSVToStoreVMOS.SharedVolumeInfo.FriendlyVolumeName -SwitchName $VMSwitch.Name |
    Set-VM -ProcessorCount $VMSize.CPUs -Passthru |
    Set-TervisVMNetworkAdapter -DHCPScope $DHCPScope -UseVlanTagging -PassThru |
    Set-TervisDHCPForVM -DHCPScope $DHCPScope -PassThru |
    Add-ClusterVirtualMachineRole -Cluster $Cluster

    if ($NoVHD -eq $false) {
        Write-Verbose "$($ClusterNodeToHostVM.Name) $($VMOperatingSystemTemplate.VHDFile.FullName) $($CSVToStoreVMOS.SharedVolumeInfo.FriendlyVolumeName)\$VMName"
    
        Invoke-Command -ComputerName $ClusterNodeToHostVM.Name {
            param(
                $VMOperatingSystemTemplate,
                $CSVToStoreVMOS,
                $VMName
            )
            Copy-Item -Path $($VMOperatingSystemTemplate.VHDFile.FullName) -Destination "$($CSVToStoreVMOS.SharedVolumeInfo.FriendlyVolumeName)\$VMName"
        } -ArgumentList $VMOperatingSystemTemplate, $CSVToStoreVMOS, $VMName

        $PathOfVMVHDx = "$($CSVToStoreVMOS.SharedVolumeInfo.FriendlyVolumeName)\$VMName\$($VMOperatingSystemTemplate.VHDFile.Name)"

        Write-Verbose $PathOfVMVHDx
    
        $VM = get-vm -ComputerName $ClusterNodeToHostVM.Name -Name $VMName

        $VM | Add-VMHardDiskDrive -Path $PathOfVMVHDx
        $VM | Set-VMFirmware -BootOrder $($vm | Get-VMHardDiskDrive)
    }

    get-vm -ComputerName $ClusterNodeToHostVM.Name -Name $VMName | 
    Set-VMFirmware -EnableSecureBoot:$(if($VMOperatingSystemTemplateName.SecureBoot){"On"}else{"Off"})

    if ($NeedsAccessToSAN){
        Add-TervisFibreChannelFabrictoVM -VMName $VMName -Computername $ComputerName -Cluster $Cluster
    }

    get-vm -ComputerName $ClusterNodeToHostVM.Name -Name $VMName
}

function New-TervisNonClusterVM {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory, ParameterSetName = "TemplatedVHD")]
        [Parameter(Mandatory, ParameterSetName = "NoVHD")]
        [Parameter(Mandatory, ParameterSetName = "EmptyVHD")]
        [ValidateLength(1,11)]
        [ValidateScript({ Test-ShouldBeAlphaNumeric -Name VMNameWithoutEnvironmentPrefix -String $_ })]
        [String]$VMNameWithoutEnvironmentPrefix,

        [Parameter(Mandatory, ParameterSetName = "TemplatedVHD")]
        [Parameter(Mandatory, ParameterSetName = "NoVHD")]
        [Parameter(Mandatory, ParameterSetName = "EmptyVHD")]
        [ValidateSet(“Small”,”Medium”,"Large")]
        [String]$VMSizeName,

        [Parameter(Mandatory, ParameterSetName = "TemplatedVHD")]
        [Parameter(Mandatory, ParameterSetName = "NoVHD")]
        [Parameter(Mandatory, ParameterSetName = "EmptyVHD")]
        [ValidateSet(“Windows Server 2012 R2”,"Windows Server 2012","Windows Server 2008 R2", "PerfSonar", "CentOS 7","Windows 10","Windows Server 2016","VyOS","Arch Linux")]
        [String]$VMOperatingSystemTemplateName,

        [Parameter(Mandatory, ParameterSetName = "TemplatedVHD")]
        [Parameter(Mandatory, ParameterSetName = "NoVHD")]
        [Parameter(Mandatory, ParameterSetName = "EmptyVHD")]
        [ValidateSet(”Delta”,“Epsilon”,"Production","Infrastructure")]
        [ValidateScript({$_ -in $(Get-TervisEnvironmentName) })]
        [String]$EnvironmentName,

        [Parameter(Mandatory, ParameterSetName = "TemplatedVHD")]
        [Parameter(Mandatory, ParameterSetName = "NoVHD")]
        [Parameter(Mandatory, ParameterSetName = "EmptyVHD")]
        [String]$ComputerName,
        
        [Parameter(ParameterSetName = "TemplatedVHD")]
        [Parameter(ParameterSetName = "NoVHD")]
        [Parameter(ParameterSetName = "EmptyVHD")]
        [ValidateScript({ Get-DhcpServerv4Scope -ScopeId $_ -ComputerName $(Get-DhcpServerInDC | select -First 1 -ExpandProperty DNSName) })]
        [String]$DHCPScopeID,

        [Parameter(Mandatory, ParameterSetName = "NoVHD")]
        [switch]$NoVHD,

        [Parameter(Mandatory, ParameterSetName = "EmptyVHD")]
        [switch]$EmptyVHD
    )
    $VMSize = Get-TervisVMSize -VMSizeName $VMSizeName
    $VMOperatingSystemTemplate = Get-VMOperatingSystemTemplate -VMOperatingSystemTemplateName $VMOperatingSystemTemplateName
    $VMName = Get-TervisVMName -VMNameWithoutEnvironmentPrefix $VMNameWithoutEnvironmentPrefix
    $VMSwitch = Get-TervisVMSwitch -ComputerName $ComputerName
    $DHCPScope = if ($DHCPScopeID) { 
        Get-TervisDhcpServerv4Scope -ScopeID $DHCPScopeID
    } else {
        Get-TervisDhcpServerv4Scope -Environment $EnvironmentName
    }

    Write-Verbose "$($VMSize.Name) $($VMOperatingSystemTemplate.Name) $VMName $($VMSwitch.Name) $($DHCPScope.Name)"

    $VM = if ( -not $EmptyVHD ) {
        New-VM -Name $VMName -MemoryStartupBytes $VMSize.MemoryBytes -NoVHD -Generation $VMOperatingSystemTemplate.Generation `
            -ComputerName $ComputerName -SwitchName $VMSwitch.Name
    } else {
        New-VM -Name $VMName -MemoryStartupBytes $VMSize.MemoryBytes -NewVHDPath "$VMName.vhdx" -NewVHDSizeBytes 107374182400 -Generation $VMOperatingSystemTemplate.Generation `
            -ComputerName $ComputerName -SwitchName $VMSwitch.Name
    }

    $VM |
    Set-VM -ProcessorCount $VMSize.CPUs -Passthru |
    Set-TervisVMNetworkAdapter -DHCPScope $DHCPScope -PassThru |
    Set-TervisDHCPForVM -DHCPScope $DHCPScope

    if ($NoVHD -eq $false -and $EmptyVHD -eq $false) {
        Write-Verbose "$ComputerName $($VMOperatingSystemTemplate.VHDFile.FullName)"
        
        $ClusterNodeToPullTemplateFrom = Get-TervisVMClusterNodeToPullTemplateFrom -ComputerName $ComputerName
        $PathToStoreVHDIn = Get-VMHost -ComputerName $ComputerName | 
            select -ExpandProperty VirtualHardDiskPath

        Invoke-Command -ComputerName $ComputerName -ArgumentList $VMOperatingSystemTemplate, $ClusterNodeToPullTemplateFrom, $PathToStoreVHDIn, $VMName -ScriptBlock { 
            param(
                $VMOperatingSystemTemplate,
                $ClusterNodeToPullTemplateFrom,
                $PathToStoreVHDIn,
                $VMName
            )
            $Destination = "$PathToStoreVHDIn\$VMName$($VMOperatingSystemTemplate.VHDFile.FullName.Extension)"
            Copy-Item -Path "\\$($ClusterNodeToPullTemplateFrom.Name)\$($VMOperatingSystemTemplate.VHDFile.FullName -replace ":","`$")" -Destination $Destination
        }

        $PathOfVMVHDx = "$PathToStoreVHDIn\$VMName\$($VMOperatingSystemTemplate.VHDFile.Name)"

        Write-Verbose $PathOfVMVHDx
    
        $VM = get-vm -ComputerName $ComputerName -Name $VMName

        $VM | Add-VMHardDiskDrive -Path $PathOfVMVHDx
        $VM | Set-VMFirmware -BootOrder $($vm | Get-VMHardDiskDrive)
    }

    get-vm -ComputerName $ComputerName -Name $VMName | 
    Set-VMFirmware -EnableSecureBoot:$(if($VMOperatingSystemTemplateName.SecureBoot){"On"}else{"Off"})

    get-vm -ComputerName $ComputerName -Name $VMName
}

function Get-TervisVMClusterNodeToPullTemplateFrom {
    param (
        [Parameter(Mandatory)]$ComputerName
    )
    $Domain = Get-ADDomain |
        select -ExpandProperty forest
    $ADSiteOfHyperVHost = Get-ComputerSite -ComputerName $ComputerName
    $ClusterWithTemplates = Get-TervisCluster -Domain $Domain |
        where ADSite -EQ $ADSiteOfHyperVHost |
        select -First 1 -Wait
    $ClusterNodeToPullTemplateFrom = $ClusterWithTemplates |
        Get-ClusterNode | 
        where state -EQ "Up" | 
        select -First 1 -Wait
    
    $ClusterNodeToPullTemplateFrom
}

function Remove-TervisVM {
    [CmdletBinding()]
    param(
        [parameter(Mandatory, ValueFromPipeline)]$VM,
        [Switch]$DeleteVHDs
    )
    process {
        Invoke-Command -ComputerName $VM.ComputerName -ScriptBlock {
            $Using:VM.Name | Stop-VM -Force -TurnOff
        }

        Remove-TervisDHCPReservationAndLease -MacAddressWithDashes $VM.VMNetworkAdapter.MacAddressWithDashes
        Remove-TervisDNSRecord -ComputerName $VM.Name
        Remove-TervisADComputerObject -ComputerName $VM.Name

        if (Get-Cluster -Name $Vm.ComputerName -ErrorAction SilentlyContinue) {
            $VM | Remove-ClusterGroup -RemoveResources -Cluster $Vm.ComputerName
        }

        if ($DeleteVHDs) {
            Invoke-Command -ComputerName $VM.ComputerName -ScriptBlock {
                $Using:VM.Name | 
                Get-VMHardDiskDrive | 
                Remove-Item -Confirm
            }
        }
        if ($VM.FibreChannelHostBusAdapters) {
            $VM | Remove-BrocadeZoning
        }

        Invoke-Command -ComputerName $VM.ComputerName -ScriptBlock {
            $Using:VM.Name | Remove-VM
        }        
    }
}

function Set-TervisVMNetworkAdapter {
    param(
        [parameter(Mandatory, ValueFromPipeline)]$VM,
        [Parameter(Mandatory)]$DHCPScope,
        [Switch]$UseVlanTagging,
        [switch]$PassThru
    )
    if ($UseVlanTagging) { $VM | Set-VMNetworkAdapterVlan -VlanId $DHCPScope.VLan -Access }
    $VM | Start-VM -Passthru | Stop-VM -Force
    
    do {
        $VMWithMacAddressAssigned = Get-VM -ComputerName $VM.ComputerName -Name $VM.Name    
        $VMMacAddress = $VMWithMacAddressAssigned | Get-VMNetworkAdapter | select -ExpandProperty macaddress
    } while ($VMMacAddress -eq "000000000000") 

    $VMWithMacAddressAssigned | Set-VMNetworkAdapter -StaticMacAddress $VMMacAddress
    
    if ($PassThru) {$VMWithMacAddressAssigned}
}

function Get-TervisVMNetworkAdapter {
    param(
        [parameter(Mandatory, ValueFromPipeline)]$VM
    )
    process {
        $VMNetworkAdapter = $VM | Get-VMNetworkAdapter
        $VMNetworkAdapter | Add-VMNetworkAdapterCustomProperties
        $VMNetworkAdapter
    }   
}

filter Add-VMNetworkAdapterCustomProperties {
    $_ | Add-Member -MemberType ScriptProperty -Name MacAddressWithDashes -Value { ($This.macaddress -replace '(..)','$1-').Trim('-') }
}

function Get-TervisVMSwitch {
    param(
        [Parameter(Mandatory)][string]$ComputerName
    )
    Get-VMSwitch -ComputerName $ComputerName -Name "VSwitch"
}

$VMOperatingSystemTemplates = [pscustomobject][ordered]@{
    Name="Windows Server 2012 R2"
    VHDFile=[System.IO.FileInfo]"C:\ClusterStorage\Volume16\2012 R2 Template\2012R2Template.vhdx"
    Generation=2
    SecureBoot=$true
},
[pscustomobject][ordered]@{
    Name="Windows Server 2012"
    VHDFile=[System.IO.FileInfo]"C:\ClusterStorage\Volume8\2012 Template\2012 Template.vhdx"
    Generation=2
    SecureBoot=$true
},
[pscustomobject][ordered]@{
    Name="Windows Server 2008 R2"
    VHDFile=[System.IO.FileInfo]"C:\ClusterStorage\Volume16\2008R2 Template\2008r2template.vhdx"
    Generation=1
    SecureBoot=$False
},
[pscustomobject][ordered]@{
    Name="PerfSonar"
    VHDFile=[System.IO.FileInfo]"C:\ClusterStorage\Volume16\PerfSonar\PerfSonar.vhdx"
    Generation=1
    SecureBoot=$False
},
[pscustomobject][ordered]@{
    Name="CentOS 7"
    VHDFile=[System.IO.FileInfo]"C:\ClusterStorage\volume16\CentOS7\CentOS7.vhdx"
    Generation=2
    SecureBoot=$False
},
[pscustomobject][ordered]@{
    Name="Windows 10"
    Generation=2
    SecureBoot=$true
},
[pscustomobject][ordered]@{
    Name="Windows Server 2016"
    VHDFile=[System.IO.FileInfo]"C:\ClusterStorage\volume16\2016 Template\Virtual Hard Disks\2016 Template.vhdx"
    Generation=2
    SecureBoot=$true
},
[pscustomobject][ordered]@{
    Name="VyOS"
    VHDFile=[System.IO.FileInfo]"C:\ClusterStorage\Volume11\VyOS Template\Virtual Hard Disks\VyOS Template.vhdx"
    Generation=1
    SecureBoot=$False
},
[pscustomobject][ordered]@{
    Name="Arch Linux"
    VHDFile=[System.IO.FileInfo]"C:\ClusterStorage\Volume11\Arch Linux Template\Arch Linux Template.vhdx"
    Generation=2
    SecureBoot=$False
}

function Get-VMOperatingSystemTemplate {
    param(
        [Parameter(Mandatory)][String]$VMOperatingSystemTemplateName
    )
    process {
        $VMOperatingSystemTemplate = $VMOperatingSystemTemplates | Where name -EQ $VMOperatingSystemTemplateName
        $VMOperatingSystemTemplate
    }
}

Function Get-TervisVMName {
    param(
        [Parameter(Mandatory)][ValidateLength(1,11)][String]$VMNameWithoutEnvironmentPrefix,
        $EnvironmentName
    )
    $EnvironmentPrefix = get-TervisEnvironmentPrefix -EnvironmentName $EnvironmentName
    $VMName = "$EnvironmentPrefix-$VMNameWithoutEnvironmentPrefix"
    $VMName
}

$VMSizes = [pscustomobject][ordered]@{
    Name="Small"
    MemoryMiB=2048
    CPUs=2
},
[pscustomobject][ordered]@{
    Name="Medium"
    MemoryMiB=4096
    CPUs=4
},
[pscustomobject][ordered]@{
    Name="Large"
    MemoryMiB=8192
    CPUs=4
}

filter Add-VMSizesCustomProperties {
    $_ | Add-Member -MemberType ScriptProperty -Name MemoryGiB -Value { $this.MemoryMiB/1024 }
    $_ | Add-Member -MemberType ScriptProperty -Name MemoryKiB -Value { $this.MemoryMiB*1024 }
    $_ | Add-Member -MemberType ScriptProperty -Name MemoryBytes -Value { $this.MemoryKiB*1024 }
}

$VMSizes | Add-VMSizesCustomProperties

function Get-TervisVMSize {
    param(
        [Parameter(Mandatory)][ValidateSet(“Small”,”Medium”,"Large")][String]$VMSizeName
    )
    $VMSize = $VMSizes | Where name -EQ $VMSizeName
    $VMSize
}

function Get-TervisVM {
    param(
        [Parameter(ValueFromPipelineByPropertyName)]$Name,
        [Parameter(ValueFromPipelineByPropertyName)]$ComputerName
    )
    process {
        Get-VM @PSBoundParameters |
        Add-VMCustomProperties -PassThru
    }
}

function Add-VMCustomProperties {
    param(
        [Parameter(Mandatory,ValueFromPipeline)]$VM,
        [Switch]$PassThru
    )

    $VM | Add-Member -MemberType ScriptProperty -Name DhcpServerv4Lease -Value {
        $this | 
        Get-TervisVMNetworkAdapter |
        Find-DHCPServerv4Lease
    }

     $VM | Add-Member -MemberType ScriptProperty -Name IPAddress -Value {
        $this.DhcpServerv4Lease | 
        select -first 1 -Wait -ExpandProperty ipaddress | 
        select -ExpandProperty IPAddressToString
    }

    if ($PassThru) {$VM}
}

#http://www.yusufozturk.info/virtual-machine-manager/getting-virtual-machine-guest-information-from-hyper-v-server-2012r2.html
function Get-VMGuestInfo
{
<#
    .SYNOPSIS
 
        Gets virtual machine guest information
 
    .EXAMPLE
 
        Get-VMGuestInfo -VMName Test01
 
    .EXAMPLE
 
        Get-VMGuestInfo -VMName Test01 -HyperVHost Host01
 
    .NOTES
 
        Author: Yusuf Ozturk
        Website: http://www.yusufozturk.info
        Email: ysfozy[at]gmail.com
 
#>
 
[CmdletBinding(SupportsShouldProcess = $true)]
param (
 
    [Parameter(
        Mandatory = $true,
        HelpMessage = 'Virtual Machine Name')]
    $VMName,
 
    [Parameter(
        Mandatory = $false,
        HelpMessage = 'Hyper-V Host Name')]
    $HyperVHost = "localhost",
 
	[Parameter(
        Mandatory = $false,
        HelpMessage = 'Debug Mode')]
    [switch]$DebugMode = $false
)
	# Enable Debug Mode
	if ($DebugMode)
	{
		$DebugPreference = "Continue"
	}
	else
	{
		$ErrorActionPreference = "silentlycontinue"
	}
 
	$VMState = (Get-VM -ComputerName $HyperVHost -Name $VMName).State
 
	if ($VMState -eq "Running")
	{
		filter Import-CimXml
		{
			$CimXml = [Xml]$_
			$CimObj = New-Object -TypeName System.Object
			foreach ($CimProperty in $CimXml.SelectNodes("/INSTANCE/PROPERTY"))
			{
				if ($CimProperty.Name -eq "Name" -or $CimProperty.Name -eq "Data")
				{
					$CimObj | Add-Member -MemberType NoteProperty -Name $CimProperty.NAME -Value $CimProperty.VALUE
				}
			}
			$CimObj
		}
 
		$VMConf = Get-WmiObject -ComputerName $HyperVHost -Namespace "root\virtualization\v2" -Query "SELECT * FROM Msvm_ComputerSystem WHERE ElementName like '$VMName' AND caption like 'Virtual%' "
		$KVPData = Get-WmiObject -ComputerName $HyperVHost -Namespace "root\virtualization\v2" -Query "Associators of {$VMConf} Where AssocClass=Msvm_SystemDevice ResultClass=Msvm_KvpExchangeComponent"
		$KVPExport = $KVPData.GuestIntrinsicExchangeItems
 
		if ($KVPExport)
		{
			# Get KVP Data
			$KVPExport = $KVPExport | Import-CimXml
 
			# Get Guest Information
			$VMOSName = ($KVPExport | where {$_.Name -eq "OSName"}).Data
			$VMOSVersion = ($KVPExport | where {$_.Name -eq "OSVersion"}).Data
			$VMHostname = ($KVPExport | where {$_.Name -eq "FullyQualifiedDomainName"}).Data
		}
		else
		{
			$VMOSName = "Unknown"
			$VMOSVersion = "Unknown"
			$VMHostname = "Unknown"
		}
	}
	else
	{
		$VMOSName = "Unknown"
		$VMOSVersion = "Unknown"
		$VMHostname = "Unknown"
	}
 
	$Properties = New-Object Psobject
	$Properties | Add-Member Noteproperty VMName $VMName
	$Properties | Add-Member Noteproperty VMHost $HyperVHost
	$Properties | Add-Member Noteproperty VMState $VMState
	$Properties | Add-Member Noteproperty VMOSName $VMOSName
	$Properties | Add-Member Noteproperty VMOSVersion $VMOSVersion
	$Properties | Add-Member Noteproperty VMHostname $VMHostname
	Write-Output $Properties
}

function Start-TervisVMAndWaitForPort {
    Param (
        [Parameter(Mandatory)]
        $PortNumbertoMonitor,
        
        [Parameter(Mandatory, ValueFromPipeline)]
        $TervisVMObject
    )

    Start-VM -ComputerName $TervisVMObject.ComputerName -Name $TervisVMObject.Name
    Wait-ForPortAvailable -IPAddress $TervisVMObject.IPAddress -PortNumbertoMonitor $PortNumbertoMonitor
}

function Restart-TervisVMAndWaitForPort {
    Param(
        [Parameter(Mandatory)]
        $PortNumbertoMonitor,
        
        [Parameter(Mandatory, ValueFromPipeline)]
        $TervisVMObject
    )
    
    Restart-VM -ComputerName $TervisVMObject.ComputerName -Name $TervisVMObject.Name -force

    Wait-ForPortNotAvailable -IPAddress $TervisVMObject.IPAddress -PortNumbertoMonitor $PortNumbertoMonitor
    Wait-ForPortAvailable -IPAddress $TervisVMObject.IPAddress -PortNumbertoMonitor $PortNumbertoMonitor
}


function Find-TervisVM {
    [CmdletBinding()]
    param (
        [String[]]$Name = "*",
        $ClusterName
    )
    $HyperVHosts = Get-HyperVHosts

    $HyperVHostsToGetVMsFrom = if ($ClusterName) {
        $ClusterNodeNames = Get-Cluster -Name $ClusterName |
        Get-ClusterNode |
        Select-Object -ExpandProperty Name

        $HyperVHosts | 
        Where-Object {
            $_ -in $ClusterNodeNames
        }
    } else {
        $HyperVHosts
    }

    $VM = Start-ParallelWork -Parameters $HyperVHostsToGetVMsFrom -OptionalParameters $Name -ScriptBlock {
        param($HyperVHost, [String[]]$Name)
        Invoke-Command -ComputerName $HyperVHost -ArgumentList (,$Name) -ScriptBlock { 
            param ([String[]]$Name)
            $VM = get-vm -Name $Name -ErrorAction SilentlyContinue

            if ($VM) {
                $VM |
                foreach {
                    $_ | Add-Member -Name VMNetworkAdapter -MemberType NoteProperty -PassThru -Value $( 
                        $_ | Get-VMNetworkAdapter
                    )
                }
            }            
        }
    }

    if ($VM) {
        $VM.VMNetworkAdapter | Add-VMNetworkAdapterCustomProperties
        $VM | Add-VMCustomProperties
        $VM
    }
}

function Find-TervisVMByIP {
    [CmdletBinding()]
    param (
        [String[]]$VMIPAddress
    )
    $HyperVHosts = Get-HyperVHosts

    Start-ParallelWork -Parameters $HyperVHosts -OptionalParameters $VMIPAddress -ScriptBlock {
        param($HyperVHost, [String[]]$VMIPAddress)
        Invoke-Command -ComputerName $HyperVHost -ArgumentList (,$VMIPAddress) -ScriptBlock { 
            param ([String[]]$VMIPAddress)
            Get-VMNetworkAdapter -VMName * |
            where {$_.IPAddresses -eq $VMIPAddress}
        }
    }
}

function Find-TervisVMVLANID {
    [CmdletBinding()]
    param (
        [String[]]$VLANID
    )
    $HyperVHosts = Get-HyperVHosts

    Start-ParallelWork -Parameters $HyperVHosts -OptionalParameters $VLANID -ScriptBlock {
        param($HyperVHost, [String[]]$VLANID)
        Invoke-Command -ComputerName $HyperVHost -ArgumentList (,$VLANID) -ScriptBlock { 
            param ([String[]]$VLANID)
            Get-VMNetworkAdapter -VMName * |
            where {$_.VlanSetting.AccessVlanID -eq $VLANID} | 
            select -ExpandProperty vmname |
            get-vm | 
            foreach {
                $_ | Add-Member -Name VMNetworkAdapter -MemberType NoteProperty -PassThru -Value $( 
                    $_ | Get-VMNetworkAdapter
                )
            }
        }
    }
}

function Find-TervisVMUntaggedVlan {
    [CmdletBinding()]
    $HyperVHosts = Get-HyperVHosts

    Start-ParallelWork -Parameters $HyperVHosts -ScriptBlock {
        param($HyperVHost)
        Invoke-Command -ComputerName $HyperVHost -ScriptBlock { 
            Get-VMNetworkAdapter -VMName * |
            where {$_.VlanSetting.OperationMode -eq "Untagged"} | 
            select -ExpandProperty vmname |
            get-vm | 
            foreach {
                $_ | Add-Member -Name VMNetworkAdapter -MemberType NoteProperty -PassThru -Value $( 
                    $_ | Get-VMNetworkAdapter
                )
            }
        }
    }
}

function Find-TervisVMByMACAddress {
    [CmdletBinding()]
    param (
        [String[]]$MACAddress
    )
    $HyperVHosts = Get-HyperVHosts

    Start-ParallelWork -Parameters $HyperVHosts -OptionalParameters $MACAddress -ScriptBlock {
        param($HyperVHost, [String[]]$MACAddress)
        Invoke-Command -ComputerName $HyperVHost -ArgumentList (,$MACAddress) -ScriptBlock { 
            param ([String[]]$MACAddress)
            Get-VMNetworkAdapter -VMName * |
            where {$_.MacAddress -eq $MACAddress}
        }
    }
}

function Get-HyperVHosts {
    param (
        [switch]$UseServiceConnectionPoint
    )

    if ($UseServiceConnectionPoint) {
        $ComputerswithHyperVServices = Get-ADObject -Filter 'ObjectClass -eq "serviceConnectionPoint" -and Name -eq "Microsoft Hyper-V"' -ErrorAction Stop
        foreach($Computer in $ComputerswithHyperVServices) {            
            $ComputerObjectPath = ($Computer.DistinguishedName.split(",") | select -skip 1 ) -join ","
            $ObjectPathwithMSDPMSuffix = "CN=MSDPM,$ComputerObjectPath"
            if (-not(Get-ADObject -filter {distinguishedname -eq $ObjectPathwithMSDPMSuffix})){
                get-adcomputer -Identity $ComputerObjectPath | select -ExpandProperty Name
            }
        }
    } else {        
        Get-SPN -ServiceClass "Microsoft Virtual Console Service" | 
            Where-Object ComputerName -NotLike *DPM* |
            Where-Object ComputerName -NotLike *Mohl* |
            Select-Object -ExpandProperty ComputerName | 
            Sort-Object -Unique
    }    
}

$TervisVMFibreChannelFabric = [pscustomobject][ordered]@{
    Cluster = "HypervCluster5"
    FabricA = "FabricA"
    FabricB = "FabricB"
},
[pscustomobject][ordered]@{
    Cluster = "HypervCluster6"
    FabricA = "FabricA"
    FabricB = "FabricB"
}

function Get-TervisVMFibreChannelFabric {
    param ( 
        [Parameter(Mandatory)]
        [ValidateSet(“HypervCluster5","HypervCluster6")]
        $Cluster
    )
        $TervisVMFibreChannelFabric | Where Cluster -eq $Cluster
}

function Add-TervisFibreChannelFabrictoVM {
    param (
        [Parameter(Mandatory)] 
        [String] $VMName,

        [Parameter(Mandatory)] 
        [String] $Computername,

        [ValidateScript({ get-cluster -name $_ })]
        [Parameter(Mandatory)]
        [String] $Cluster
         
    )
    invoke-command -ComputerName $ComputerName -ScriptBlock {Set-VMSecurity -VirtualizationBasedSecurityOptOut $true -ComputerName $using:Computername -VMName $using:VMName}
    $ClusterFabric = Get-TervisVMFibreChannelFabric -Cluster $Cluster
        Add-VMFibreChannelHba -ComputerName $Computername -VMName $VMName -SanName $ClusterFabric.FabricA
        Add-VMFibreChannelHba -ComputerName $Computername -VMName $VMName -SanName $ClusterFabric.FabricB
}

function Move-TervisVMStorage {
    param (
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)] 
        [String] $VMName,

        [Parameter(Mandatory,ValueFromPipelineByPropertyName)] 
        [String] $Computername,

        [Parameter(Mandatory)] $VolumeNumber
    )
    process {
        $DestinationPathLocal = "C:\ClusterStorage\Volume$VolumeNumber\$VMName"
        $DestinationPathRemote = $DestinationPathLocal | ConvertTo-RemotePath -ComputerName $Computername
    
        New-Item -ItemType Directory -Path $DestinationPathRemote -Force -ErrorAction SilentlyContinue | Out-Null

        if (-not (Test-Path -Path $DestinationPathRemote)) {
            Throw "$DestinationPathRemote doesn't exist and failed to be created"
        }

        Invoke-Command -ComputerName $Computername -ScriptBlock {
            Get-VM -Name $Using:VMName |
            Move-VMStorage -DestinationStoragePath $Using:DestinationPathLocal
        }
    }
}

function Invoke-HyperVCluster6Provision {
    param (
        $EnvironmentName
    )
    Invoke-ApplicationProvision -ApplicationName HyperVCluster6 -EnvironmentName $EnvironmentName
    $Nodes = Get-TervisApplicationNode -ApplicationName HyperVCluster6 -EnvironmentName $EnvironmentName
    $Nodes | Update-TervisSNMPConfiguration
    $Nodes | Invoke-ClaimMPOI
    $Nodes | Add-NodeToTervisCluster -Cluster HyperVCluster6
}

function Invoke-HyperVCluster5Provision {
    param (
        $EnvironmentName
    )
    Invoke-ApplicationProvision -ApplicationName HyperVCluster5 -EnvironmentName $EnvironmentName
    $Nodes = Get-TervisApplicationNode -ApplicationName HyperVCluster5 -EnvironmentName $EnvironmentName
    $Nodes | Invoke-ClaimMPOI
    $Nodes | New-TervisNicTeam
    $Nodes | Add-NodeToTervisCluster -Cluster HyperVCluster5
}

function Invoke-VDICluster1Provision {
    param (
        $EnvironmentName
    )
    Invoke-ApplicationProvision -ApplicationName VDICluster1 -EnvironmentName $EnvironmentName
    $Nodes = Get-TervisApplicationNode -ApplicationName VDICluster1 -EnvironmentName $EnvironmentName
    $Nodes | Invoke-ClaimMPOI
    $Nodes | New-TervisNicTeam
}

function Invoke-StandaloneHyperVServerProvision {
    param (
        $EnvironmentName
    )
    Invoke-ApplicationProvision -ApplicationName StandaloneHyperVServer -EnvironmentName $EnvironmentName
    $Nodes = Get-TervisApplicationNode -ApplicationName StandaloneHyperVServer -EnvironmentName $EnvironmentName
    $Nodes | Invoke-ClaimMPOI
    $Nodes | New-TervisNicTeam
}

function Invoke-FindVHDsNotAttachedToVMs {
    param (
        [Parameter(Mandatory)]$ClusterName
    )
    $VMs = Find-TervisVM -ClusterName $ClusterName

    $VMHardDiskDrives = Start-ParallelWork -Parameters $VMs -ScriptBlock {
        param($VM)
        Get-VMHardDiskDrive -ComputerName $VM.ComputerName -VMName $VM.Name        
    }

    $VHDs = Get-ChildItem -Recurse -File -Path  "\\$ClusterName\ClusterStorage$" -Include *.avhd,*.vhd,*.vhdx

    $PathsToVHDAttachedToVMsRemote = $VMHardDiskDrives.path | ConvertTo-RemotePath -ComputerName $ClusterName
    $PathToVHDsOnClusterSharedVolumes = $VHDs.fullname | % { $_.replace("ClusterStorage$", "C$\ClusterStorage") }
    $Results = Compare-Object -ReferenceObject $PathsToVHDAttachedToVMsRemote -DifferenceObject $PathToVHDsOnClusterSharedVolumes

    $Results | fl *
}

function Get-IrmaReplicationStatus {
    $ReplicatedVMNames = @"
dhcp1
Disney-Old
passwordstate
prd-bartender01
prd-progis01
prd-wcsapp01
p-mesiis
customizer
ADFS02
DirSync
ADFSProxy01
RMSHQ01
2016 Template
RDBroker2012R2
RD2012R2-Lic
"@ -split "`r`n"
    $VMs = find-tervisvm -Name $ReplicatedVMNames
    $RunningVMs = $VMS | 
    where state -EQ Running
    
    $VMReplication = $RunningVMs|% { Measure-VMReplication -ComputerName $_.computername -VMName $_.Name }

    $VMReplication | % {
        $_.CurrentTask | 
        Select Name,PercentComplete |
        Add-Member -MemberType NoteProperty -Name VMName -PassThru -Value $_.VMName
    } | sort VMName | select -Property VMName, Name, PercentComplete
}

function Invoke-InstallandConfigureClusterAwareUpdating{
    param(
        [parameter(Mandatory)]$Cluster
    )

    Add-CauClusterRole -ClusterName $Cluster
        -Force 
        -CauPluginName Microsoft.WindowsUpdatePlugin 
        -CauPluginArguments @{ 'IncludeRecommendedUpdates' = 'True' } 
        -MaxFailedNodes 1 
        -MaxRetriesPerNode 3 
        -RequireAllNodesOnline 
        -StartDate (Get-Date) 
        -DaysOfWeek 1 
        -IntervalWeeks 1 
        -UseDefault 
        -EnableFirewallRules
    Enable-CauClusterRole -ClusterName HyperVCluster6 -Force;
    }

function Set-ClusterAwareUpdatingConfiguration{
    param(
        [parameter(mandatory)]$Cluster
    )
    Set-CauClusterRole -ClusterName $Cluster
        -Force 
        -CauPluginName Microsoft.WindowsUpdatePlugin 
        -CauPluginArguments @{ 'IncludeRecommendedUpdates' = 'True' } 
        -MaxFailedNodes 1 
        -MaxRetriesPerNode 3 
        -RequireAllNodesOnline 
        -StartDate (Get-Date) 
        -DaysOfWeek 1 
        -IntervalWeeks 1 
        -UseDefault 
        -EnableFirewallRules
    Enable-CauClusterRole -ClusterName HyperVCluster6 -Force;
    }

    Invoke-CauRun -