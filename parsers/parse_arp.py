from helpers import parse_ip


# Parse ARP header
def parse_arp_header(hex_data):
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
    



# def parse_arp_header(hex_data):
#     # Parsing the ARP header
#     hardware_type = int(hex_data[:4], 16)
#     protocol_type = int(hex_data[4:8], 16)
#     hardware_size = int(hex_data[8:10], 10)
#     protocol_size = int(hex_data[10:12], 10)
#     operation = int(hex_data[12:16], 10)
#     sender_mac = hex_data[16:28]
#     sender_ip = hex_data[28:36]
#     target_mac = hex_data[36:48]
#     target_ip = hex_data[48:56]
    
#     # Creating a list of field names and their corresponding values
#     fields = [
#         ("Hardware Type", hex_data[:4], hardware_type),
#         ("Protocol Type", hex_data[4:8], protocol_type),
#         ("Hardware Size", hex_data[8:10], hardware_size),
#         ("Protocol Size", hex_data[10:12], protocol_size),
#         ("Operation", hex_data[12:16], operation),
#         ("Sender MAC", sender_mac, sender_mac),
#         ("Sender IP", sender_ip, sender_ip),
#         ("Target MAC", target_mac, target_mac),
#         ("Target IP", target_ip, target_ip)
#     ]
    
#     # Printing the ARP header details
#     print(f"ARP Header:")
#     for field_name, hex_value, value in fields:
#         print(f"  {field_name:<25} {hex_value:<20} | {value}")