New-AzVm `
 -ResourceGroupName "vm-networks" `
 -Name "dataProcStage1" `
 -VirtualNetworkName "myVnet" `
 -SubnetName "vm-servers" `
 -image "Win2016Datacenter" `
 -Size "Standard_DS2_v2"