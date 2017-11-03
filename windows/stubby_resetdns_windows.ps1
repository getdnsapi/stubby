Get-NetAdapter -Physical | ForEach-Object {
   $ifname = $_.Name
   Write-Host "Resetting DNS servers on interface $ifname - the system will use default DNS service."
   set-dnsclientserveraddress $ifname -ResetServerAddresses
}