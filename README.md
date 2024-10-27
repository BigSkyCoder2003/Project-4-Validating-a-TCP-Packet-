# Project 4: Validating a TCP Packet  
# Daniel Lounsbury
# Brian Hall
# CS372

# TCP Functions Documentation

## `read_tcp_text(filename)`
* Reads TCP .txt files that contain source and destination IP addresses and returns each one in string form in a tuple. 

## `read_tcp_dat(filename)`
* Reads TCP .dat files that contain the tcp header and payload, and returns the binary.

## `compute_checksum_and_length(content)`
* Computes the checksum and TCP packet length from the .dat binary and returns the checksum and length in int form in a tuple.

## `ip_dot_to_bytes(ip_string)`
* Converts ip in string dot form to byte form and reutrns the byte form.

## `assemble_IP_pseudo_header(source_IP, dest_IP, PTCL, tcp_length)`
* Assembles an IP pseudo header from the source IP (byte form), destination IP (byte form), PTCL(byte form), and tcp length(int form).

## `get_TCP_header_checksum(tcp_data, pseudoheader)`
* Calculatues the TCP header checksum from the tcp_data(byte form) and the pseudo header(byte form).

## `main()`
* Runs checksum comparison(s) on provided .dat files(along with provided TCP IP .txt files).