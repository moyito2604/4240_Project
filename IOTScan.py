import pyshark
import os
import socket
from socket import gaierror


# This class handles all color for any output requiring color
class Color:
    PURPLE = '\033[95m'
    CYAN = '\033[96m'
    DARKCYAN = '\033[36m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'


# Prints the final report for all the domains that were hit
def print_report(packetsrc, packetcnt, barsize):
    packetsrc = dict(sorted(packetsrc.items()))
    print(f"\n{Color.BLUE}{Color.BOLD}*************** PACKET REPORT ***************{Color.END}")
    for dest in packetsrc.keys():
        print(f"{Color.BLUE}{dest}{Color.END}\nRX: {packetsrc[dest]['RX']} | TX: {packetsrc[dest]['TX']}")
        packets = packetsrc[dest]['RX'] + packetsrc[dest]['TX']
        perc = packets / packetcnt
        barlen = round(barsize * perc)
        bar = ""
        for cnt in range(1, barsize + 1):
            if cnt <= barlen:
                bar += "█"
            else:
                bar += " "
        print(f"{Color.GREEN}{Color.BOLD}[{bar}]{Color.END}")


def main():
    barsize = 50

    # Interface for packet capture
    interface = os.environ.get("INTERFACE", False)

    # IP of device for capture
    sourceip = os.environ.get("SOURCEIP", False)

    # Amount of packets to grab
    packetcnt = os.environ.get("PACKETCNT", False)
    packetcnt = int(packetcnt)

    # Amount of calls to domain
    packetsrc = {}

    # interface = 'wlx984827c0b944'
    # sourceip = '10.42.0.130'
    # packetcnt = 1000

    # Ensures that all variables are accounted for
    if not interface or not sourceip or not packetcnt:
        print("INTERFACE, SOURCEIP, and PACKETCNT environment variables required.")
        exit(0)

    # Sets up the pyshark capture
    capture = pyshark.LiveCapture(interface=interface, bpf_filter=f"ip host {sourceip}")
    print("Retrieving Packets")

    # Sniffs for the amount of packets requested
    for packet in capture.sniff_continuously(packet_count=packetcnt):

        # If the source IP is identified to be part of the subnet or single IP we are looking for, then it makes sure
        # the packet is labeled as a transmitted packet
        if sourceip in packet.ip.src:

            try:
                nslookup = socket.getnameinfo((packet.ip.dst, 0), 0)[0]
            except gaierror:
                nslookup = packet.ip.dst

            print(f"{packet.__dict__['number']}".ljust(7),
                  f'{packet.ip.src} --> {nslookup}', f"{packet.__dict__['layers']}")
            if nslookup in packetsrc:
                packetsrc[nslookup]['TX'] += 1
            else:
                packetsrc[nslookup] = {}
                packetsrc[nslookup]['RX'] = 0
                packetsrc[nslookup]['TX'] = 1

        # If the destination IP is identified to be part of the subnet or single IP we are looking for, then it makes
        # sure the packet is labeled as a received packet
        else:

            try:
                nslookup = socket.getnameinfo((packet.ip.src, 0), 0)[0]
            except gaierror:
                nslookup = packet.ip.src

            print(f"{packet.__dict__['number']}".ljust(7),
                  f'{nslookup} --> {packet.ip.dst}', f"{packet.__dict__['layers']}")
            if nslookup in packetsrc:
                packetsrc[nslookup]['RX'] += 1
            else:
                packetsrc[nslookup] = {}
                packetsrc[nslookup]['RX'] = 1
                packetsrc[nslookup]['TX'] = 0

    print_report(packetsrc, packetcnt, barsize)


if __name__ == "__main__":
    main()
