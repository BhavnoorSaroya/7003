from parsers.parse_ethernet import parse_ethernet
def parse_header(hex_data): 
    return parse_ethernet(hex_data)
