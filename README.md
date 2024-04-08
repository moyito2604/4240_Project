# IOTScan
### Containerized program that allows user to scan packets on a specific interface
The container can be customized with the given ```docker-compose.yml``` file provided. Once packets have been scanned, an easy to read report of where each packet went is generated. The following arguments are necessary for the program
```
INTERFACE=wlan0
```
The interface variable is a variable used to pick which wifi/ethernet interface to scan on, you can get this information by using ifconfig on Linux
```
SOURCEIP=192.168.0
```
SourceIP can be used to define a single IP or a range of IPs. To select a range, remove the last octet so that it scans all packets within the subnet
```
PACKETCNT=1000
```
PacketCNT is used to define the amount of packets you want to scan during your session
