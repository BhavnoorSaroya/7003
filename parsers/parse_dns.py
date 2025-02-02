def parse_dns(hex_data):
    transaction_id = hex_data[0:4]
    flags = hex_data[4:8]
    questions = hex_data[8:12]
    answer_rrs = hex_data[12:16]
    authority_rr = hex_data[16:20]
    additional_rr = hex_data[20:24]

    payload = hex_data[24:]
    
    flags_int = int(flags, 16)
    
    qr = (flags_int & 0b1000000000000000) >> 15
    opcode = (flags_int & 0b0111100000000000) >> 11
    aa = (flags_int & 0b0000010000000000) >> 10
    tc = (flags_int & 0b0000001000000000) >> 9
    rd = (flags_int & 0b0000000100000000) >> 8
    ra = (flags_int & 0b0000000010000000) >> 7
    zero = (flags_int & 0b0000000001110000) >> 4
    rCode = flags_int & 0b0000000000001111

    print('DNS Header:')
    print(f"  {'Transaction Id':<25} {transaction_id:<20} | {int(transaction_id, 16)}")
    print(f"  {'Flags:':<25} {flags:<20} | {bin(flags_int)}")
    print(f"    {'Query Response (QR):':<30} {qr}")
    print(f"    {'Opcode :':<30} {opcode}")
    print(f"    {'Authoritative Answer (AA):':<30} {aa}")
    print(f"    {'TC:':<30} {tc}")
    print(f"    {'Recursion Desired (RD):':<30} {rd}")
    print(f"    {'Recursion Available (RA):':<30} {ra}")
    print(f"    {'Zero:':<30} {zero}")
    print(f"    {'Response Code (RS):':<30} {rCode}")
    print(f"  {'Questions':<25} {questions:<20} | {int(questions, 16)}")
    print(f"  {'Answer RRs':<25} {answer_rrs:<20} | {int(answer_rrs, 16)}")
    print(f"  {'Authority RRs':<25} {authority_rr:<20} | {int(authority_rr, 16)}")
    print(f"  {'Additional RRs':<25} {additional_rr:<20} | {int(additional_rr, 16)}")