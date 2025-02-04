
def parse_icmp(hex_data):
    message_type = hex_data[0:2]
    code = hex_data[2:4]
    checksum = hex_data[4:8]
    payload = hex_data[8:]
    print("ICMP Header:")
    print(f"  {"Type":<25} {message_type:<20} | {str(int(message_type, 16))}")
    print(f"  {"Code":<25} {code:<20} | {int(code, 16)}")
    print(f"  {"Checksum":<25} {checksum:<20} | {int(checksum, 16)}")
    print(f"  {'Payload (hex)':<25} {payload}")

