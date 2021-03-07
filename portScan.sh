#! /bin/bash

#This script will ask the user what port they want to scan for then show them which devices onthe network have those ports open and those devices associated ip addresses

echo "Please enter the first ip address in the network range you want to scan"
read firstNetwork

echo "Please enter the last number in the last octet of the network you want to scan"
read lastIP

echo "Please enter the port you want to scan for"
read port
nmap -sT $firstNetwork-$lastIP -p $port  >/dev/null -oG portHostScan

cat portHostScan | grep open > portHostScan2

cat portHostScan2

