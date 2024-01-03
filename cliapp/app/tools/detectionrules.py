import re
import pyshark
import pandas as pd
from scapy.all import *
from scapy.layers.inet import IP, TCP


def detect_ip(file_path):
    condition = False
    ips = []
    found_ips = []
    with open("../database/files/ip_blacklist.txt", 'r') as f:
        for line in f:
            ips.append(line.strip())

    if file_path.endswith('.txt') or file_path.endswith('.xml') or file_path.endswith('.json'):
        with open(file_path, "r") as file:
            for line in file:
                for ip in ips:
                    if re.search(ip, line):
                        condition = True
                        found_ips.append(ip)

    elif file_path.endswith('.pcap'):
        shark_cap = pyshark.FileCapture(file_path)
        output = ""
        for packet in shark_cap:
            output += str(packet)
        for ip in ips:
            if re.search(ip, output):
                condition = True
                found_ips.append(ip)
        print(found_ips)

    if condition:
        action_alert = "remote"
        action_block = True
        description = "Alert - suspicious ip"
    else:
        action_alert = None
        action_block = None
        description = None

    return action_alert, action_block, description, found_ips


def detect_words(file_path):
    condition = False
    words = []
    found_words = []
    with open("../../database/files/word_blacklist.txt", 'r') as f:
        for line in f:
            words.append(line.strip())

    if file_path.endswith('.txt') or file_path.endswith('.xml') or file_path.endswith('.json'):
        with open(file_path, "r") as file:
            for line in file:
                for word in words:
                    if re.search(word.lower(), line.lower()):
                        condition = True
                        found_words.append(word)

    elif file_path.endswith('.pcap'):
        shark_cap = pyshark.FileCapture(file_path)
        output = ""
        for packet in shark_cap:
            output += str(packet)
        for word in words:
            if re.search(word.lower(), output.lower()):
                condition = True
                found_words.append(word)

    if condition:
        action_alert = "remote"
        action_block = False
        description = "Alert - suspicious word"
    else:
        action_alert = None
        action_block = None
        description = None

    return action_alert, action_block, description, found_words


def detect_anomaly(file_path):
    scapy_cap = rdpcap(file_path)
    packet_tab = []
    for packet in scapy_cap:
        if TCP in packet:
            ip_src = ""
            ip_dst = ""
            if IP in packet:
                ip_src = packet[IP].src
                ip_dst = packet[IP].dst

            tcp_time = packet[TCP].time
            tcp_sport = packet[TCP].sport
            tcp_dport = packet[TCP].dport
            packet_tab.append([str(tcp_time), tcp_sport, tcp_dport, ip_src, ip_dst])

    df = pd.DataFrame(packet_tab, columns=['time', 'src_port', 'dst_port', 'ip_src', 'ip_dst'])

    connections = df.groupby(["dst_port"]).size().rename("amount").reset_index()
    connections.columns = ['port', 'amount']

    connections2 = df.groupby(["src_port"]).size().rename("amount").reset_index()
    connections2.columns = ['port', 'amount']

    ports_traffic = pd.concat([connections, connections2]).groupby('port').sum().reset_index()

    ports_traffic = ports_traffic[ports_traffic.amount > 100]
    ports_traffic.sort_values('amount', ascending=False)

    ports_traffic = ports_traffic[ports_traffic.port < 1024]

    trusted_ports = [80, 443]
    untrusted_ports = ports_traffic[~ports_traffic.port.isin(trusted_ports)]

    if len(untrusted_ports) > 0:
        action_alert = "remote"
        action_block = True
        description = "Alert - untrusted ports"
    else:
        action_alert = None
        action_block = None
        description = None

    return action_alert, action_block, description, untrusted_ports
