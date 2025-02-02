from helpers import parse_ip


# Parse ARP header
def parse_arp(hex_data):
    hardware_type = int(hex_data[:4], 16)
    protocol_type = int(hex_data[4:8], 16)
    hardware_size = int(hex_data[8:10], 10)
    protocol_size = int(hex_data[10:12], 10)
    operation = int(hex_data[12:16], 10)
    sender_mac = ':'.join(hex_data[i:i+2] for i in range (16, 28, 2))
    target_mac = ':'.join(hex_data[i:i+2] for i in range(36, 48, 2))
    
    target_IP = parse_ip(hex_data[28:36])
    sender_IP = parse_ip(hex_data[48:56])


    print(f"ARP Header:")
    print(f"  {'Hardware Type:':<25} {hex_data[:4]:<20} | {hardware_type}")
    print(f"  {'Protocol Type:':<25} {hex_data[4:8]:<20} | {protocol_type}")
    print(f"  {'Hardware Size:':<25} {hex_data[8:10]:<20} | {hardware_size}")
    print(f"  {'Protocol Size:':<25} {hex_data[10:12]:<20} | {protocol_size}")
    print(f"  {'Operation:':<25} {hex_data[12:16]:<20} | {operation}")
    print(f"  {'Sender MAC':<25} {hex_data[16:28]:<20} | {sender_mac}")
    print(f"  {'Sender IP':<25} {hex_data[28:36]:<20} | {sender_IP}")
    print(f"  {'Target MAC:':<25} {hex_data[36:48]:<20} | {target_mac}")
    print(f"  {'Target IP:':<25} {hex_data[48:56]:<20} | {target_IP}")
    