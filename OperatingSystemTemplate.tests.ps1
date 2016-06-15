Import-Module TervisVirtualization -Force

#Describe "VMOperatingSystemTemplates" {
#    it "Should all have a base set of properties" {
#        $VMOperatingSystemTemplates | % {
#            $_.Name | should exist
#            $_.Path | should exist
#            $_.VMGeneration | should exist
#        }
#    }
#}
#
#Describe "Get-VMOperatingSystemTemplate" {
#    it "Should return a number of operating system templates" {
#        $VMOperatingSystemTemplate = Get-VMOperatingSystemTemplate 
#        $True | should be "Basic Description"
#    }
#}
#

Describe "Get-TervisVMSize" {
    it "Should all have a base set of properties" {
        $VMOperatingSystemTemplates | % {
            $_.Name | should exist
            $_.Path | should exist
            $_.VMGeneration | should exist
        }
    }
}