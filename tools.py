from scapy.all import Ether
hex_data = "ffffffffffff48210b3131a108004500002a000100004001f91dc0a80032c0a800320900810b00000000437573746f6d205061796c6f616400000000"
packet = Ether(bytes.fromhex(hex_data))
packet.show()




icmp= '0900810b00000000437573746f6d205061796c6f616400000000'

print(len(hex_data) - len(icmp))