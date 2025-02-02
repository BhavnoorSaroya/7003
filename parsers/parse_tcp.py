
def parse_tcp(hex_data):
    source = hex_data[0:4]
    destination = hex_data[4:8]
    seq = hex_data[8:16]
    ack = hex_data[16:24]
    offset = hex_data[24:25]
    reserved_flags = hex_data[25:28]
    window_size = hex_data[28:32]
    checksum = hex_data[32:]

    return "HELLO TCP"