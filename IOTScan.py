import pyshark
import os

interface = os.environ.get("tshark_int")
sourceip = os.environ.get("tshark_srcip", False)
#
# command = f"tshark -i {interface}"
# if sourceip:
#     command = command + f" -e ip.src -Y \"ip.src=={sourceip}"
# print(f"Tshark Command: {command}")
# os.system(command)

interface='wlx984827c0b944'
sourceip='198.21.252.164'

capture = pyshark.LiveCapture(interface=interface, bpf_filter=f"ip host {sourceip}")
print("Retrieving Packets")
#capture.sniff(timeout=5)
# capture.sniff_continuously(packet_count=5)

#print(capture[0])
for packet in capture.sniff_continuously(packet_count=1000):
    print(packet.ip)