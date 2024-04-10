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
        RXPacketper = round((packetsrc[dest]['RX'] / packetcnt) * 100, 2)
        TXPacketper = round((packetsrc[dest]['TX'] / packetcnt) * 100, 2)
        if 'nslookup' in packetsrc[dest]:
            print(f"{Color.BLUE}{packetsrc[dest]['nslookup']}\n{Color.CYAN}{Color.BOLD}RX: {packetsrc[dest]['RX']} "
                  f"({RXPacketper}%){Color.END} | {Color.PURPLE}{Color.BOLD}TX: {packetsrc[dest]['TX']} "
                  f"({TXPacketper}%){Color.END}")
        else:
            print(f"{Color.BLUE}{dest}\n{Color.CYAN}{Color.BOLD}RX: {packetsrc[dest]['RX']} ({RXPacketper}%){Color.END}"
                  f" | {Color.PURPLE}{Color.BOLD}TX: {packetsrc[dest]['TX']} ({TXPacketper}%){Color.END}")
        packets = packetsrc[dest]['RX'] + packetsrc[dest]['TX']
        perc = packets / packetcnt
        barlen = round(barsize * perc)
        bar = ""
        for cnt in range(1, barsize + 1):
            if cnt <= barlen:
                if cnt <= (packetsrc[dest]['RX'] / packetcnt) * barsize:
                    bar += f"{Color.CYAN}{Color.BOLD}"
                else:
                    bar += f"{Color.END}{Color.PURPLE}{Color.BOLD}"
                bar += "█"
            else:
                bar += " "
        print(f"{Color.GREEN}{Color.BOLD}[{bar}{Color.END}{Color.GREEN}{Color.BOLD}] {round(perc*100, 2)}%{Color.END}")


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

            ip = packet.ip.dst
            if ip in packetsrc:
                packetsrc[ip]['TX'] += 1
            else:
                packetsrc[ip] = {}
                packetsrc[ip]['RX'] = 0
                packetsrc[ip]['TX'] = 1

            if packetsrc[ip].get('nslookup') is None:
                try:
                    packetsrc[ip]['nslookup'] = socket.getnameinfo((ip, 0), 0)[0]
                    nslookup = packetsrc[ip]['nslookup']
                except gaierror:
                    nslookup = ip
            else:
                nslookup = packetsrc[ip]['nslookup']

            print(f"{packet.__dict__['number']}".ljust(7),
                  f'{packet.ip.src} {Color.PURPLE}{Color.BOLD}-->{Color.END} {nslookup}', f"{packet.__dict__['layers']}")

        # If the destination IP is identified to be part of the subnet or single IP we are looking for, then it makes
        # sure the packet is labeled as a received packet
        else:

            ip = packet.ip.src
            if ip in packetsrc:
                packetsrc[ip]['RX'] += 1
            else:
                packetsrc[ip] = {}
                packetsrc[ip]['RX'] = 1
                packetsrc[ip]['TX'] = 0

            if packetsrc[ip].get('nslookup') is None:
                try:
                    packetsrc[ip]['nslookup'] = socket.getnameinfo((ip, 0), 0)[0]
                    nslookup = packetsrc[ip]['nslookup']
                except gaierror:
                    nslookup = ip
            else:
                nslookup = packetsrc[ip]['nslookup']

            print(f"{packet.__dict__['number']}".ljust(7),
                  f'{packet.ip.dst} {Color.CYAN}{Color.BOLD}<--{Color.END} {nslookup}', f"{packet.__dict__['layers']}")

    for dest in packetsrc.keys():
        for cnt in range(0, 3):
            if dest == packetsrc[dest].get('nslookup'):
                try:
                    packetsrc[dest]['nslookup'] = socket.getnameinfo((dest, 0), 0)[0]
                except gaierror:
                    pass
            else:
                break

    print_report(packetsrc, packetcnt, barsize)


if __name__ == "__main__":
    main()
