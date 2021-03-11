#Creates a resource group for our virtual network in a region
#Creates a virtual network called my-vnet witeh a 10.0.0.0/16 network.
#Creates a subnet in my-vnet called default with the network address of 10.0.0.24
$Location="EastUS2"
$vmNetRGName="vm-networks"
$subN1Name="default"
$subN2Name="vm-server"
$virtualNet1Name="myVnet"
New-AzResourceGroup -Name $vmNetRGName -Location $Location
$Subnet=New-AzVirtualNetworkSubnetConfig -Name $subN2Name -AddressPrefix 10.1.0.0/24
 New-AzVirtualNetwork -Name $virtualNet1Name -ResourceGroupName $vmNetRGName -Location $Location -AddressPrefix 10.0.0.0/16 -Subnet $Subnet
