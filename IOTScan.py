import os

interface = os.environ.get("tshark_int")

os.system(f"tshark -i {interface}")