
def read_tcp_text(filename):
    with open(filename, 'r') as file:
        content = file.read().strip()
        tcpIP, tcpPort = content.split(' ')
    return tcpIP, tcpPort


def read_tcp_dat(filename): #TODO
    with open(filename, 'rb') as file:
        content = file.read()    
    return content


def compute_checksum_and_length(content):
    checksum, TCP_length = int.from_bytes(content[16:18], 'big'), len(content)
    return checksum, TCP_length


def ip_dot_to_bytes(ip_string):
    ip_array = ip_string.split('.')
    byte_string  = b""
    for i in range(0,4):
        byte_string += int(ip_array[i]).to_bytes(1,'big')
    return(byte_string)


def assemble_IP_pseudo_header(source_IP, dest_IP, PTCL, tcp_length):
    IP_pseudo_header = b""
    IP_pseudo_header += source_IP + dest_IP + b'\x00' + PTCL + (tcp_length.to_bytes(2,'big')) 
    return IP_pseudo_header


def get_TCP_header_checksum(tcp_data, pseudoheader):
    

    tcp_zero_cksum = tcp_data[:16] + b'\x00\x00' + tcp_data[18:]

    if len(tcp_zero_cksum) % 2 == 1:
        tcp_zero_cksum += b'\x00'

    data = pseudoheader + tcp_zero_cksum

    total = 0
    offset = 0

    while(offset < len(data)):

        word = int.from_bytes(data[offset:offset + 2], "big")
        total += word

        total = (total & 0xffff) + (total >> 16)
        offset += 2
    
    return (~total) & 0xffff


def main():
    

    for i in range(0,10):
        text_filename = f'./tcp_data/tcp_addrs_{i}.txt'
        dat_filename = f'./tcp_data/tcp_data_{i}.dat'
        tcp_source_IP , tcp_dest_IP = read_tcp_text(text_filename)
        dat_content = read_tcp_dat(dat_filename)
        checksum, TCP_length = compute_checksum_and_length(dat_content)
        tcp_source_IP_bytes = ip_dot_to_bytes(tcp_source_IP)
        tcp_dest_IP_bytes = ip_dot_to_bytes(tcp_dest_IP)
        IP_pseudo_header = assemble_IP_pseudo_header(tcp_source_IP_bytes, tcp_dest_IP_bytes, b'\x06', TCP_length)
        TCP_header_checksum = get_TCP_header_checksum(dat_content, IP_pseudo_header )
        if checksum == TCP_header_checksum:
            print(f'PASS:\n{checksum}:{TCP_header_checksum}')
        else:
            print(f'FAIL:\n{checksum}:{TCP_header_checksum}')
    


main()