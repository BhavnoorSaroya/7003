from parsers.parse_dns import parse_dns 

DEFAULT_DNS_PORT = 53

def parse_udp(hex_data):
    source_port = hex_data[0:4]
    destination_port = hex_data[4:8]
    length = hex_data[8:12]
    checksum = hex_data[12:16]
    payload = hex_data[16:]

    
    print("UDP Header:")
    print(f"  {"Source Port":<25} {source_port:<20} | {int(source_port, 16)}")
    print(f"  {"Desitnation Port":<25} {destination_port:<20} | {int(destination_port, 16)}")
    print(f"  {"Length":<25} {length:<20} | {int(length, 16)}")
    print(f"  {"Checksum":<25} {checksum:<20} | {(checksum)}")

    if int(destination_port, 16) == DEFAULT_DNS_PORT:
        parse_dns(payload)


