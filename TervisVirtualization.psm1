#Requires -Modules TervisEnvironment, TervisDHCP, TervisCluster
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
        [ValidateSet(“Windows Server 2012 R2”,"Windows Server 2012","Windows Server 2008 R2")]
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

        [switch]$NeedsAccessToSAN
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

    $VM | 
    Add-VMHardDiskDrive -Path $PathOfVMVHDx -Passthru |
    Set-VMFirmware -BootOrder $($vm | Get-VMHardDiskDrive)
}

function Remove-TervisVM {
    param(
        [parameter(Mandatory, ValueFromPipeline)]$VM
    )
    $VM | Remove-TervisDHCPForVM
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
},
[pscustomobject][ordered]@{
    Name="Windows Server 2012"
    VHDFile=[System.IO.FileInfo]"C:\ClusterStorage\Volume8\2012 Template\2012 Template.vhdx"
    Generation=2
},
[pscustomobject][ordered]@{
    Name="Windows Server 2008 R2"
    VHDFile=[System.IO.FileInfo]"C:\ClusterStorage\Volume16\2008R2 Template\2008r2template.vhdx"
    Generation=1
}

function Get-VMOperatingSystemTemplate {
    param(
        [Parameter(Mandatory)][ValidateSet(“Windows Server 2012 R2”,"Windows Server 2012","Windows Server 2008 R2")][String]$VMOperatingSystemTemplateName
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