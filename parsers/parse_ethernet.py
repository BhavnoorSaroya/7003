from parsers.parse_arp import parse_arp
from parsers.parse_ipv4 import parse_ipv4

# Parse Ethernet header
def parse_ethernet(hex_data):
    # print("whole packet", hex_data)
    dest_mac = ':'.join(hex_data[i:i+2] for i in range(0, 12, 2))
    source_mac = ':'.join(hex_data[i:i+2] for i in range(12, 24, 2))
    ether_type = hex_data[24:28]

    print(f"Ethernet Header:")
    print(f"  {'Destination MAC:':<25} {hex_data[0:12]:<20} | {dest_mac}")
    print(f"  {'Source MAC:':<25} {hex_data[12:24]:<20} | {source_mac}")
    print(f"  {'EtherType:':<25} {ether_type:<20} | {int(ether_type, 16)}")

    payload = hex_data[28:]

    
    # Route payload based on EtherType
    if ether_type == "0806":  # ARP
        parse_arp(payload)
    elif ether_type == "0800":
        parse_ipv4(payload)
    else:    
        print(f"  {'Unknown EtherType:':<25} {ether_type:<20} | {int(ether_type, 16)}")
        print("  No parser available for this EtherType.")

    return ether_type, payload

    