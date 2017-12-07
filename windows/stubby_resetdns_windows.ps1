#Requires -RunAsAdministrator
#Requires -Version 2

#Get enabled/connected adapters (same as 'Get-NetAdapter -Physical')
$NetworkAdapters = Get-WmiObject -Class 'Win32_NetworkAdapterConfiguration' -Filter {IPEnabled = 1}

#Verbose output so the user gets to know the current configuration
Write-Output -InputObject 'Found Adapters:'
Write-Output -InputObject $NetworkAdapters | Format-Table -Property IPAddress,DefaultIPGateway,DNSServerSearchOrder,Description

Write-Output -InputObject 'Resetting DNS servers on found interfaces - the system will use default DNS service.'

#Change the DNS entry for each found network adapter
foreach ($NetworkAdapter in $NetworkAdapters) {
  $null = $NetworkAdapter.RenewDHCPLease()
}
