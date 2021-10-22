import math
import dpkt
import struct
import re

from typing import Dict, List
from pprint import pformat
from collections import OrderedDict
from datetime import datetime as dt

sender_ip = '172.24.16.132'
receiver_ip = '34.193.77.105'

def get_str_attr(data: bytes, sep: str, format:str, start: int, end: int):
    return sep.join(map(str, struct.unpack(format, data[start:end+1])))

def get_int_attr(data: bytes, format:str, start: int, end: int):
    return struct.unpack(format, data[start:end+1])[0]

class Packet:
    def __init__(self, data: bytes, timestamp:float):
        # Use formats as per https://docs.python.org/3/library/struct.html
        self.src_ip: str = get_str_attr(data, '.', 'BBBB', 26, 29)
        self.dest_ip: str = get_str_attr(data, '.', 'BBBB', 30, 33)
        self.src_port: str = get_str_attr(data, '', '>H', 34, 35)
        self.dest_port: str = get_str_attr(data, '', '>H', 36, 37)
        self.seq_num: int = get_int_attr(data, '>I', 38, 41)
        self.ack_num: int = get_int_attr(data, '>I', 42, 45)
        self.tcp_header_len: int = 8 * (get_int_attr(data, '>B', 46, 46) // 32)
        
        flags = '{0:08b}'.format(get_int_attr(data, '>B', 47, 47))
        self.ack: int = int(flags[3])
        self.psh: int = int(flags[4])
        self.syn: int = int(flags[6])
        self.fin: int = int(flags[7])

        self.window_size: int = get_int_attr(data, '>H', 48, 49)
        self.size: int = len(data)
        total_header_len = 14 + 20 + self.tcp_header_len
        self.payload: bytes = data[total_header_len:]
        self.payload_size: int = len(data[total_header_len:])
        self.timestamp: float = timestamp

        if self.syn == 1 and self.ack == 0:
            kind = get_int_attr(data, '>B', 54, 54)
            if kind == 2:
                self.mss: int = get_int_attr(data, '>H', 56, 57)
            self.scaling_window_size: int = int(math.pow(2, get_int_attr(data, '>B', 73, 73)))
    
    def __repr__(self):
        return pformat(vars(self), indent=4, width=1)

class Flow:
    def __init__(self, id: int, sender_port: str, receiver_port: str):
        self.id: int = id
        self.sender_port: str = sender_port
        self.receiver_port: str = receiver_port
        self.total_packets: int = 0
        self.total_sender_packets: int = 0
        self.total_receiver_packets: int = 0

        self.packets: List[Packet] = []
        self.sender_indices: List[int] = []
        self.receiver_indices: List[int] = []
    
    def __repr__(self):
        return pformat(vars(self), indent=4, width=1)
    
    def set_mss(self, mss: int):
        self.mss = mss
    
    def set_scaling_window(self, scaling_window_size: int):
        self.scaling_window_size = scaling_window_size

class HTTPAnalyzer:
    def __init__(self, pcap: dpkt.pcap.Reader):
        self.pcap = pcap
        self.flows: Dict[int, Flow] = OrderedDict()
    
    def update_sender_args(self, flow: Flow, packet: Packet):
        flow.packets.append(packet)
        flow.total_packets += 1
        flow.total_sender_packets += 1
        flow.sender_indices.append(flow.total_packets - 1)
    
    def update_receiver_args(self, flow: Flow, packet: Packet):
        flow.packets.append(packet)
        flow.total_packets += 1
        flow.total_receiver_packets += 1
        flow.receiver_indices.append(flow.total_packets - 1)
    
    def init_flow(self, flow_id: int, packet: Packet) -> Flow:
        flow = Flow(flow_id, packet.src_port, packet.dest_port)
        flow.set_mss(packet.mss)
        flow.set_scaling_window(packet.scaling_window_size)
        self.update_sender_args(flow, packet)
        return flow
    
    def init_flows(self):
        flow_id = 1
        port_to_flow_id_map = {}
        for timestamp, data in self.pcap:
            packet = Packet(data, timestamp)
            if packet.src_ip == sender_ip:
                flow_number = port_to_flow_id_map.get(packet.src_port)
                if flow_number:
                    flow = self.flows.get(flow_number)
                    self.update_sender_args(flow, packet)
                    self.flows[flow_number] = flow
                else:
                    flow = self.init_flow(flow_id, packet)
                    self.flows[flow_id] = flow
                    port_to_flow_id_map[packet.src_port] = flow_id
                    flow_id += 1
            else:
                flow_number = port_to_flow_id_map.get(packet.dest_port)
                flow = self.flows.get(flow_number)
                self.update_receiver_args(flow, packet)
                self.flows[flow_number] = flow
        
    def reassemble_http_c_1(self):
        print('-'*30 + 'PART C - 1)' + '-'*30)
        print("For better readability, the answer to this section can be found in part_c_1.txt\n")
        for flow_id, flow in self.flows.items():
            req_packets: List[Packet] = []
            resp_packets: List[Packet] = []
            seq_num_dict: Dict[int, Packet] = {}
            for packet in flow.packets:
                payload = str(packet.payload)
                # Request payloads start with 'GET'
                if payload.find('GET') != -1:
                    packet.payload = re.search(".*(GET.*1080)", payload).group()
                    req_packets.append(packet)
                # Response payloads start with 'HTTP'
                elif payload.find('HTTP') != -1:
                    packet.payload = re.search(".*(HTTP.*close)", payload).group()
                    resp_packets.append(packet)
                seq_num_dict[packet.seq_num] = packet
            
            tcp_segments = []
            for req_packet in req_packets:
                next_seq_num = req_packet.ack_num
                next_packet = seq_num_dict.get(next_seq_num)
                while not next_packet.fin:
                    tcp_segments.append(
                        (next_packet.src_port, next_packet.dest_port, next_packet.seq_num, next_packet.ack_num)
                    )
                    next_seq_num += next_packet.payload_size
                    next_packet = seq_num_dict.get(next_seq_num)
            
            # Uncomment below block, delete part_c_1.txt and then run this file if you want to test it yourself.
            """with open('part_c_1.txt', 'a') as f:
                f.write("Flow {}:\n".format(flow_id))
                for i, req_packet in enumerate(req_packets):
                    f.write("Request {}: {}\n\n".format(i+1, req_packet.payload))
                    f.write("TCP Segments associated with the request:\n")
                    f.write("{:<12} {:<10} {:<15} {:<15}\n".format('Source Port','Dest Port','Seq Num','Ack Num'))
                    for tcp_segment in tcp_segments:
                        f.write("{:<12} {:<10} {:<15} {:<15}\n".format(tcp_segment[0], tcp_segment[1], tcp_segment[2], tcp_segment[3]))
                    f.write("\nResponse {}: {}\n\n\n".format(i+1, resp_packets[i].payload))"""
        
    def stats_c_3(self, label: str):
        total_byte_size = 0
        total_packets = 0
        min_time = self.flows[1].packets[0].timestamp
        max_time = self.flows[1].packets[0].timestamp
        for flow_id, flow in self.flows.items():
            for packet in flow.packets:
                if packet.timestamp > max_time:
                    max_time = packet.timestamp
                if packet.timestamp < min_time:
                    min_time = packet.timestamp
                total_byte_size += packet.size
                total_packets += 1
        
        total_load_time = round((dt.fromtimestamp(max_time) - dt.fromtimestamp(min_time)).total_seconds(), 4)
        print("{} Connection Stats:".format(label))
        print("Total number of Connections = {}".format(len(self.flows)))
        print("Total Packets Transferred = {}".format(total_packets))
        print("Total Transfer Time = {}s".format(total_load_time))
        print("Total Transfer Bytes = {}\n".format(total_byte_size))

if __name__ == '__main__':
    #Part C - 1
    f = open('http_1080.pcap', 'rb')
    pcap = dpkt.pcap.Reader(f)
    http_analyzer_1080 = HTTPAnalyzer(pcap)
    http_analyzer_1080.init_flows()
    http_analyzer_1080.reassemble_http_c_1()

    #Part C - 2
    f = open('http_1081.pcap', 'rb')
    pcap = dpkt.pcap.Reader(f)
    http_analyzer_1081 = HTTPAnalyzer(pcap)
    http_analyzer_1081.init_flows()

    f = open('http_1082.pcap', 'rb')
    pcap = dpkt.pcap.Reader(f)
    http_analyzer_1082 = HTTPAnalyzer(pcap)
    http_analyzer_1082.init_flows()
    f.close()

    print('-'*30 + 'PART C - 2)' + '-'*30)
    print("Number of Flows/Connections established to the site on port 1080 = {}, which is equal to the number of GET requests made. " 
    "Hence, it must be using HTTP 1.0. Additionally, we can also confirm this with the Response section in part_c_1.txt file, where we "
    "can see HTTP/1.0 in the beginning of the response.".format(len(http_analyzer_1080.flows)))
    print("Number of Flows/Connections established to the site on port 1081 = {}, which has to imply that it must be using HTTP 1.1 "
    "which reduces the number of persistent connections through parallelization of requests (based on Browser settings, which is 6 by default).".format(len(http_analyzer_1081.flows)))
    print("Number of Flows/Connections established to the site on port 1082 = {}, implying that it must be using HTTP 2.0 which is known "
    "to make use of a single connection by making use of the pipelining technique to send all objects within one connection itself.".format(len(http_analyzer_1082.flows)))
    
    #Part C - 3
    print('\n' + '-'*30 + 'PART C - 3)' + '-'*30)
    http_analyzer_1080.stats_c_3("HTTP/1.0")
    http_analyzer_1081.stats_c_3("HTTP/1.1")
    http_analyzer_1082.stats_c_3("HTTP/2.0")