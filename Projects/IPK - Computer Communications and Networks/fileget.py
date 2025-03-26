#!/usr/bin/env python3

import os
import socket
import argparse
import sys
from urllib.parse import urlparse

GET_ALL = False  # Default: stahujem jeden subor

parser = argparse.ArgumentParser("Trvivialni distribuovany souborovy system.")
parser.add_argument("-n", metavar="NAMESERVER", type=str, required=True)
parser.add_argument("-f", metavar="SURL", type=str, required=True)

arguments_parse = parser.parse_args()
surl_parse = urlparse(arguments_parse.f)
surl_filename = os.path.split(surl_parse.path)  # Rozdelenie cesty v nazve suboru
surl_filename_head = surl_filename[0]
surl_filename_tail = surl_filename[1]

if surl_filename_tail == "*":  # Stahujem vsetky polozky
    GET_ALL = True

if ':' in arguments_parse.n:
    ip, port = arguments_parse.n.split(":", 1)
    try:
        port = int(port)
    except ValueError:
        sys.stderr.write("Port ma nespravny format\n")
        sys.exit(1)

    if port > 65535 or port < 0:
        sys.stderr.write("Chybne zadany port\n")
        sys.exit(1)
else:
    sys.stderr.write("Chybne zadana IP adresa\n")
    sys.exit(1)

if surl_parse.scheme != "fsp":
    sys.stderr.write("SURL ma nespravny format\n")
    sys.exit(1)

# ******************************************************** UDP **************************
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # UDP spojenie
message1 = ("WHEREIS " + surl_parse.netloc).encode()
sock.settimeout(30)
try:
    sock.sendto(message1, (ip, port))
except socket.error:
    sys.stderr.write("IP adresa ma nespravny format\n")
    sys.exit(1)

try:
    whereis_data, whereis_address = sock.recvfrom(4096)
except socket.timeout:
    sys.stderr.write("Server neodpoveda \n")
    sys.exit(3)
except ConnectionError:
    sys.stderr.write("Chyba pripojenia na UDP server \n")
    sys.exit(3)

not_found_message = b"ERR Not Found"
if whereis_data == not_found_message:
    sys.stderr.write("Server neexistuje \n")
    sys.exit(3)

not_found_message = b"ERR Syntax"
if whereis_data == not_found_message:
    sys.stderr.write("Chybna syntax prikazu \n")
    sys.exit(3)

tcp_address = whereis_data.decode('utf-8')
sock.close()
tcp_address = tcp_address.replace("OK ", "")
tcp_ip, tcp_port = tcp_address.split(":", 1)  # Max 2 polozky
tcp_port = int(tcp_port)


# ******************************************************** TCP **************************
def tcp_get(get_index, surl_filename_tail):
    sock2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # TCP spojenie
    message2 = (
            "GET " + surl_filename_tail + " FSP/1.0\r\nHostname: " + surl_parse.netloc + "\r\nAgent: xbobol00\r\n\r\n")
    message2 = message2.encode('utf-8')
    sock2.settimeout(30)
    sock2.connect((tcp_ip, tcp_port))

    try:
        sock2.send(message2)
        received_data = sock2.recv(4096)

    except socket.timeout:
        sys.stderr.write("Server neodpoveda \n")
        sys.exit(4)

    except ConnectionError:
        sys.stderr.write("Chyba pripojenia na TCP server \n")
        sys.exit(4)

    received_data_splitted = received_data.split(b"\r\n\r\n")  # Oddelenie hlavicky od suboru
    received_status = received_data_splitted[0].decode('UTF-8')  # Dekodovanie hlavicky

    if received_status.find("FSP/1.0 Not Found") != -1:
        sys.stderr.write("Subor nebol najdeny \n")
        sys.exit(4)

    if received_status.find("FSP/1.0 Bad Request") != -1:
        sys.stderr.write("Server nerozumie zadanemu poziadavku\n")
        sys.exit(4)

    if received_status.find("FSP/1.0 Server Error") != -1:
        sys.stderr.write("Server error\n")
        sys.exit(4)

    if received_status.find("FSP/1.0 Success") == -1:
        sys.stderr.write("Ina chyba pri TCP spojeni\n")
        sys.exit(4)

    received_data = bytes()
    received_data_splitted = received_data_splitted[1:]  # Cast suboru z hlavicky je v liste
    for item2 in received_data_splitted:
        received_data += item2

    loop_receive_data = True  # Subor sa moze skladat z viacero socketov
    while loop_receive_data:
        received_data2 = sock2.recv(4096)
        if not received_data2:
            loop_receive_data = False
        else:
            received_data += received_data2
    sock2.close()

    if not get_index:  # Stahujem subor
        surl_filename_tail = os.path.split(surl_filename_tail)
        surl_filename_tail = surl_filename_tail[1]

        output_file = open(surl_filename_tail, "wb")
        output_file.write(received_data)
        output_file.close()
        return 0
    else:  # Stahujem iba index
        return received_data


if GET_ALL:
    get_index2 = True
    surl_filename_tail = "index"
    index_file = tcp_get(get_index2, surl_filename_tail)
    index_file = index_file.decode('utf-8')
    index_file = index_file.split("\r\n")

    index_file = index_file[:len(index_file) - 1]
    for item in index_file:  # Prechadzam cely index a vytvaram TCP spojenia pre kazdu polozku
        get_index2 = False
        surl_filename_tail = item
        index_file = tcp_get(get_index2, surl_filename_tail)

else:
    get_index2 = False
    index_file = tcp_get(get_index2, surl_filename_tail)
