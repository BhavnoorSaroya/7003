def parse_ipv4(hex_data): 
    print("parsing ipv4 packet")
    
    version = hex_data[0:1]
    i_header_length = hex_data[1:2]
    tos = hex_data[2:4]
    total_length = hex_data[4:8]
    identification = hex_data[8:12]
    
    print("HELLO ")
    flags_and_frag = hex_data[12:16]
    ttl = hex_data[16:18]
    protocol = hex_data[18:20]
    header_checksum =  hex_data[20:24]
    source_addr = hex_data[24:32]
    dest_addr = hex_data[32:40]

    print("HELLO WORLD")
    print(i_header_length)
    option_len = 15 - int(i_header_length)
    print("option len was fine")
    options = hex_data[40:40+(option_len * 8)]
    print("options was fine")

    payload = hex_data[40+(option_len * 8):]

    print("hi tehre")

    
    print(f"IPv4 Header:")
    print(f"  {'Version:':<25} {hex_data[0:1]:<20} | {version}")
    print(f"  {'Header Length:':<25} {hex_data[1:2]:<20} | {i_header_length}")
    print(f"  {'Type of Service:':<25} {hex_data[2:4]:<20} | {tos}")
    print(f"  {'Total Length:':<25} {hex_data[4:8]:<20} | {total_length}")
    print(f"  {'Identification:':<25} {hex_data[8:12]:<20} | {identification}")
    print(f"  {'Flags & Frag Offset:':<25} {hex_data[12:16]:<20} | {flags_and_frag}")
    print(f"  {'TTL:':<25} {hex_data[16:18]:<20} | {ttl}")
    print(f"  {'Protocol:':<25} {hex_data[18:20]:<20} | {protocol}")
    print(f"  {'Header Checksum:':<25} {hex_data[20:24]:<20} | {header_checksum}")
    print(f"  {'Source Address:':<25} {hex_data[24:32]:<20} | {source_addr}")
    print(f"  {'Destination Address:':<25} {hex_data[32:40]:<20} | {dest_addr}")
    print(f"  {'Options:':<25} {options:<20} | {options}")
    print(f"  {'Payload:':<25} {payload:<20} | {payload}")

    return "HELLO WORLD"
