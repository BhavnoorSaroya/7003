from helpers import parse_ip
from parsers.parse_tcp import parse_tcp
from parsers.parse_udp import parse_udp
from parsers.parse_icmp import parse_icmp

UDP_VALUE = 17
TCP_VALUE = 6
ICMP_VALUE = 1

def parse_ipv4(hex_data):     
    version = hex_data[0:1]
    i_header_length = hex_data[1:2]
    tos = hex_data[2:4]
    total_length = hex_data[4:8]
    identification = hex_data[8:12]
    flags_and_frag = hex_data[12:16]
    protocol = hex_data[18:20]
    source_ip = hex_data[24:32]
    dest_ip = hex_data[32:40]
    # payload = hex_data[40:]
    
    print("payload size", int(total_length, 16) - int(i_header_length, 16))
    
    payload_start = 40 + ((int(i_header_length, 16) - 5) * 8)
    print(payload_start)
    payload = hex_data[payload_start:]

    binFF = int(flags_and_frag, 16) #convert flags and frag to binary
    flagFF = (binFF & 0b1110000000000000) >> 13 #get fragment offset
    
    # Extract flags via bitshift operations
    shouldFragment = flagFF & 0b100 >> 2 
    moreFragments = flagFF & 0b010 >> 1
    reserved = flagFF & 0b001 >> 1 

    offsetFF = binFF & 0b0001111111111111

    print(f"IPv4 Header:")
    print(f"  {'Version:':<25} {hex_data[0:1]:<20} | {int(version, 16)}")
    print(f"  {'Header Length:':<25} {hex_data[1:2]:<20} | {int(i_header_length, 16)  * 4} bytes")
    print(f"  {'Total Length:':<25} {hex_data[4:8]:<20} | {int(total_length, 16)}")
    print(f"  {'Flags & Frag Offset:':<25} {hex_data[12:16]:<20} | {bin(int(flags_and_frag, 16))}")
    print(f"    {'Reserved:':<25} {reserved}")
    print(f"    {'DF (Do not Fragment):':<25} {shouldFragment}")
    print(f"    {'MF (More Fragments):':<25} {moreFragments}")
    print(f"    {'Fragment Offset:':<25} {hex(offsetFF)} | {offsetFF}")
    print(f"  {'Protocol:':<25} {hex_data[18:20]:<20} | {int(protocol, 16)}")
    print(f"  {'Source IP:':<25} {hex_data[24:32]:<20} | {parse_ip(source_ip)}")
    print(f"  {'Destination IP:':<25} {hex_data[32:40]:<20} | {parse_ip(dest_ip)}")



    protocol_int = int(protocol, 16)
    # Route payload based on EtherType
    if protocol_int == ICMP_VALUE:  # ARP
        print(parse_icmp(payload))
    elif protocol_int == UDP_VALUE:
        print(parse_udp(payload))
    elif protocol_int == TCP_VALUE:
        print(parse_tcp(payload))
    else:    
        print(f"  {'Unknown Protocol:':<25} {protocol:<20} | {protocol_int}")
        print("  No parser available for this Protocol.")