import pyshark
import os
import socket

# Interface for packet capture
interface = os.environ.get("INTERFACE", False)

# IP of device for capture
sourceip = os.environ.get("SOURCEIP", False)

# Amount of packets to grab
packetcnt = os.environ.get("PACKETCNT", False)

# Amount of calls to domain

interface='wlx984827c0b944'
sourceip='10.42.0.130'
packetcnt=1000

if not interface or not sourceip or not packetcnt:
    print("INTERFACE, SOURCEIP, and PACKETCNT environment variables required.")
    exit(0)

capture = pyshark.LiveCapture(interface=interface, bpf_filter=f"ip host {sourceip}")
print("Retrieving Packets")

for packet in capture.sniff_continuously(packet_count=packetcnt):
    if packet.ip.src == sourceip:
        print(f"{packet.__dict__['number']}".ljust(7),
              f'{packet.ip.src} --> {socket.getnameinfo((packet.ip.dst, 0), 0)[0]}', f"{packet.__dict__['layers']}")
    else:
        print(f"{packet.__dict__['number']}".ljust(7),
              f'{socket.getnameinfo((packet.ip.src, 0), 0)[0]} --> {packet.ip.dst}', f"{packet.__dict__['layers']}")

