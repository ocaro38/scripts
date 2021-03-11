#Creates new VM, Defines Resource Group, Name, VirtualNetwork, Subnet, Image, Size
New-AzVm `
 -ResourceGroupName "vm-networks" `
 -Name "dataProcStage1" `
 -VirtualNetworkName "myVnet" `
 -SubnetName "vm-servers" `
 -image "Win2016Datacenter" `
 -Size "Standard_DS2_v2"
 
#Creates a variable called nic.
#Sets nic to the Vm Interface based on hostname of VM and Resource Group
#Select IpConfigurations.publicipaddress.id properties of $nic and set them to null
$nic = Get-AzNetworkInterface -Name dataProcStage2 -ResourceGroup vm-networks
$nic.IpConfigurations.publicipaddress.id = $null
Set-AzNetworkInterface -NetworkInterface $nic
