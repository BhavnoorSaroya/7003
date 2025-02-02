from parsers.parse_dns import parse_dns
def parse_tcp(hex_data):
    source = hex_data[0:4]
    destination = hex_data[4:8]
    seq = hex_data[8:16]
    ack = hex_data[16:24]
    offset = hex_data[24:25]
    reserved_flags = hex_data[25:28]
    window_size = hex_data[28:32]
    checksum = hex_data[32:36]
    urgent_pointer = hex_data[36:40]
    options = hex_data[40:(5 - (int(offset, 16)) * 8)]
    payload_start = int(offset, 16)* 8
    payload_start =  40 + (5 - (int(offset, 16)) * 8)

    payload = hex_data[payload_start:]


    reserved = (int(reserved_flags, 16) & 0b111000000000 >> 9)
    flags = (int(reserved_flags, 16) & 0b000111111111)
    reserved_str = format((int(reserved_flags, 16) & 0b111000000000 >> 9), '03b')
    flags_str = format((int(reserved_flags, 16) & 0b000111111111),  '09b')
    print("payload start", payload_start)
    print(flags)
    print(flags_str)
    print("payload", payload)
    # hex_data[39:40]
    
    print(f"TCP Header:")
    print(f"  {'Source Port:':<25} {source:<20} | {int(source, 16)}")
    print(f"  {'Destination Port:':<25} {destination:<20} | {int(destination, 16)}")
    print(f"  {'Sequence Number:':<25} {seq:<20} | {int(seq, 16)}")
    print(f"  {'Acknowledgment Number:':<25} {ack:<20} | {int(ack, 16)}")
    print(f"  {'Data Offset:':<25} {offset:<20} | {int(offset, 16)}")
    print(f"  {'Reserved':<25} {bin(reserved):<20} | {reserved}")
    print(f"  {'Flags:':<25} {bin(flags)}: | {flags}")
    print(f"    {'NS':<25} {flags_str[0:1]}")
    print(f"    {'CWR':<25} {flags_str[1:2]}")
    print(f"    {'ECE':<25} {flags_str[2:3]}")
    print(f"    {'URG':<25} {flags_str[3:4]}")
    print(f"    {'ACK':<25} {flags_str[4:5]}")
    print(f"    {'PSH':<25} {flags_str[5:6]}")
    print(f"    {'RST':<25} {flags_str[6:7]}")
    print(f"    {'SYN':<25} {flags_str[7:8]}")
    print(f"    {'FIN':<25} {flags_str[8:9]}")
    print(f"  {'Window Size:':<25} {window_size:<20} | {int(window_size, 16)}")
    print(f"  {'Checksum:':<25} {checksum:<20} | {int(checksum, 16)}")
    print(f"  {'Urgent Pointer:':<25} {urgent_pointer:<20} | {int(urgent_pointer, 16)}")


    if int(destination, 16) == 53:
        parse_dns(payload)
    
    return "HELLO TCP"