﻿#Requires -Modules TervisEnvironment, TervisDHCP, TervisCluster, @{ModuleName="hyper-V";ModuleVersion=1.1} 
#Requires -Version 5

function New-TervisVM {
    param(
        [Parameter(Mandatory)]
        [ValidateLength(1,11)]
        [ValidateScript({ Test-ShouldBeAlphaNumeric -Name VMNameWithoutEnvironmentPrefix -String $_ })]
        [String]$VMNameWithoutEnvironmentPrefix,

        [Parameter(Mandatory)]
        [ValidateSet(“Small”,”Medium”,"Large")]
        [String]$VMSizeName,

        [Parameter(Mandatory)]
        [ValidateSet(“Windows Server 2012 R2”,"Windows Server 2012","Windows Server 2008 R2", "PerfSonar", "CentOS 7")]
        [String]$VMOperatingSystemTemplateName,

        [Parameter(Mandatory)]
        [ValidateSet(”Delta”,“Epsilon”,"Production","Infrastructure")]
        [ValidateScript({$_ -in $(Get-TervisEnvironmentName) })]
        [String]$EnvironmentName,

        [Parameter(Mandatory)]
        [ValidateScript({ get-cluster -name $_ })]
        [String]$Cluster,

        [Parameter(Mandatory)]
        [ValidateScript({ Get-DhcpServerv4Scope -ScopeId $_ -ComputerName $(Get-DhcpServerInDC | select -First 1 -ExpandProperty DNSName) })]
        [String]$DHCPScopeID,

        [switch]$NeedsAccessToSAN,

        [switch]$NoVHD
    )
    $VMSize = Get-TervisVMSize -VMSizeName $VMSizeName
    $VMOperatingSystemTemplate = Get-VMOperatingSystemTemplate -VMOperatingSystemTemplateName $VMOperatingSystemTemplateName
    $VMName = Get-TervisVMName -VMNameWithoutEnvironmentPrefix $VMNameWithoutEnvironmentPrefix
    $CSVToStoreVMOS = Get-TervisClusterSharedVolumeToStoreVMOSOn -Cluster $Cluster
    $ClusterNodeToHostVM = Get-TervisClusterNodeToHostVM -VMSize $VMSize -Cluster $Cluster
    $VMSwitch = Get-TervisVMSwitch -ComputerName $ClusterNodeToHostVM.Name
    $DHCPScope = Get-TervisDhcpServerv4Scope -ScopeID $DHCPScopeID

    Write-Verbose "$($VMSize.Name) $($VMOperatingSystemTemplate.Name) $VMName $($CSVToStoreVMOS.Name) $($ClusterNodeToHostVM.Name) $($VMSwitch.Name) $($DHCPScope.Name)"

    $VM = New-VM -Name $VMName -MemoryStartupBytes $VMSize.MemoryBytes -NoVHD -Generation $VMOperatingSystemTemplate.Generation `
        -ComputerName $ClusterNodeToHostVM.Name -Path $CSVToStoreVMOS.SharedVolumeInfo.FriendlyVolumeName -SwitchName $VMSwitch.Name |
    Set-VM -ProcessorCount $VMSize.CPUs -Passthru |
    Set-TervisVMNetworkAdapter -DHCPScope $DHCPScope -PassThru |
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

    get-vm -ComputerName $ClusterNodeToHostVM.Name -Name $VMName
}

function Remove-TervisVM {
    [CmdletBinding()]
    param(
        [parameter(Mandatory, ValueFromPipeline)]$VM
    )
    $VM | Remove-TervisDHCPForVM -Verbose:($VerbosePreference -ne "SilentlyContinue")
    $VM | Remove-ClusterGroup -RemoveResources -Cluster $Vm.ComputerName
    $VM | Remove-VM
}

function Set-TervisVMNetworkAdapter {
    param(
        [parameter(Mandatory, ValueFromPipeline)]$VM,
        [Parameter(Mandatory)]$DHCPScope,
        [switch]$PassThru
    )
    $VM | Set-VMNetworkAdapterVlan -VlanId $DHCPScope.VLan -Access
    $VM | Start-VM -Passthru | Stop-VM -Force -Passthru
    
    $VMMacAddress = $VM | Get-VMNetworkAdapter | select -ExpandProperty macaddress

    $VM | Set-VMNetworkAdapter -StaticMacAddress $VMMacAddress
    
    if($PassThru) {$VM}
}

function Get-TervisVMNetworkAdapter {
    param(
        [parameter(Mandatory, ValueFromPipeline)]$VM
    )
    process {
        $VMNetworkAdapter = $VM | Get-VMNetworkAdapter
        $VMNetworkAdapter | Mixin-VMNetworkAdapter
        $VMNetworkAdapter
    }   
}

filter Mixin-VMNetworkAdapter {
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

function Test-ShouldBeAlphaNumeric {
    param(
        $Name, 
        $string
    )
    if ($string -notmatch "^[a-zA-Z0-9]+$") { 
        throw "The $name should only contain alphanumeric characters." 
    }
    $true
}

Function Get-TervisVMName {
    param(
        [Parameter(Mandatory)][ValidateLength(1,11)][String]$VMNameWithoutEnvironmentPrefix
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

filter Mixin-VMSizes {
    $_ | Add-Member -MemberType ScriptProperty -Name MemoryGiB -Value { $this.MemoryMiB/1024 }
    $_ | Add-Member -MemberType ScriptProperty -Name MemoryKiB -Value { $this.MemoryMiB*1024 }
    $_ | Add-Member -MemberType ScriptProperty -Name MemoryBytes -Value { $this.MemoryKiB*1024 }
}

$VMSizes | Mixin-VMSizes

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