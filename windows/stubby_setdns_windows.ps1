#Requires -RunAsAdministrator
#Requires -Version 2

#Set Stubby Address
$StubbyDNS = '127.0.0.1','1::0'

#Get enabled/connected adapters (same as 'Get-NetAdapter -Physical')
$NetworkAdapters = Get-WmiObject -Class 'Win32_NetworkAdapterConfiguration' -Filter {IPEnabled = 1}

#Verbose output so the user gets to know the current configuration
Write-Output -InputObject 'Found Adapters:'
Write-Output -InputObject $NetworkAdapters | Format-Table -Property IPAddress,DefaultIPGateway,DNSServerSearchOrder,Description

Write-Output -InputObject 'Setting DNS entries to use Stubby for the found Network Adapters...'

#Change the DNS entry for each found network adapter
foreach ($NetworkAdapter in $NetworkAdapters) {
  $null = $NetworkAdapter.SetDNSServerSearchOrder($StubbyDNS)
}
