def parse_ip(hex_data):
    resulting_ip = []
    for i in range(0, len(hex_data), 2): 
        resulting_ip.append(str(int(hex_data[i: i+2], 16)))
        
    return '.'.join(resulting_ip)
